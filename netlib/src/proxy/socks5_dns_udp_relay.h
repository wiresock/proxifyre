#pragma once

// The DNS proxy's UDP path: one SOCKS5 control connection and one UDP ASSOCIATE relay shared by
// every UDP DNS query of one address family.
//
// The router redirects each UDP DNS query to this relay's local listener with a SOCKS5 UDP
// header already prepended (socks5_udp_local_redirect.h), naming the server to ask: the server
// the application queried, or the DNS server override. The relay replaces the query's message ID
// with a unique random relay ID and sends it through the shared association. The answer carrying
// that relay ID is returned to the client socket with its original ID and a SOCKS5 header naming
// the server the client queried, so the redirect presents it as an answer from that server.
// Bookkeeping and policy are in dns_udp_multiplexer.h.
//
// The association is opened on the first query and reopened, with backoff, after its control
// connection closes, its relay socket fails, or it stops answering. While none is open, queries
// that cannot wait are dropped: DNS is never sent directly in Proxy mode.
//
// DNS traffic is light, so the relay uses blocking sockets on three threads instead of the I/O
// completion port: the listener, the reader of the current relay socket, and maintenance (opens
// associations, expires queries, checks health). Socket receives have short timeouts so every
// thread notices stop() and a retired association; sockets are closed only after the threads
// using them have been joined.

#include <condition_variable>
#include <deque>
#include <random>
#include <thread>

#include "dns_udp_multiplexer.h"
#include "socks5_udp_association.h"

namespace proxy
{
    template <typename AddressT>
    class socks5_dns_udp_relay : public netlib::log::logger<socks5_dns_udp_relay<AddressT>>  // NOLINT(clang-diagnostic-padded)
    {
    public:
        using log_level = netlib::log::log_level;
        using logger = netlib::log::logger<socks5_dns_udp_relay>;
        using address_type_t = AddressT;
        using endpoint_t = net::ip_endpoint<AddressT>;
        using negotiate_context_t = socks5_negotiate_context<AddressT>;

        /// Whether the router recently redirected a UDP DNS query from this local source port.
        using authorize_client_t = bool(uint16_t);

        /// Observes each UDP relay endpoint the SOCKS5 server returns, before it is used.
        using relay_endpoint_observed_t = void(const endpoint_t&);

        /// Queries in flight are forgotten after this long; Windows gives up on a query sooner.
        static constexpr std::chrono::seconds query_ttl{ 10 };

        /// Bound on queries in flight through one association.
        static constexpr std::size_t max_queries_in_flight = 4096;

        /// Bound on queries held while an association is being opened.
        static constexpr std::size_t max_waiting_queries = 64;

        /// Unanswered queries in a row (with no datagram from the relay) that retire an association.
        static constexpr std::size_t unanswered_limit = 3;

        /// An association younger than this is not retired for unanswered queries.
        static constexpr std::chrono::seconds minimum_association_age{ 30 };

        /**
         * @param upstream SOCKS5 server (for the IPv6 instance, an IPv4-mapped address reaches an
         *        IPv4 server).
         * @param credentials Optional SOCKS5 username/password.
         * @param upstream_options Transport and TLS settings for the control connection.
         * @param authorize_client Required. The relay refuses datagrams from any other source port,
         *        so its listener cannot be used to send arbitrary UDP through the proxy.
         * @param relay_endpoint_observed Optional; see relay_endpoint_observed_t.
         */
        socks5_dns_udp_relay(const endpoint_t& upstream,
            std::optional<std::pair<std::string, std::string>> credentials,
            socks5_upstream_options upstream_options,
            std::function<authorize_client_t> authorize_client,
            std::function<relay_endpoint_observed_t> relay_endpoint_observed = {},
            const log_level log_level = log_level::error,
            std::shared_ptr<std::ostream> log_stream = nullptr)
            : logger(log_level, std::move(log_stream)),
            upstream_(upstream),
            credentials_(std::move(credentials)),
            upstream_options_(std::move(upstream_options)),
            authorize_client_(std::move(authorize_client)),
            relay_endpoint_observed_(std::move(relay_endpoint_observed)),
            association_client_(log_level, logger::log_stream_)
        {
        }

        ~socks5_dns_udp_relay()
        {
            stop();
        }

        socks5_dns_udp_relay(const socks5_dns_udp_relay&) = delete;
        socks5_dns_udp_relay(socks5_dns_udp_relay&&) = delete;
        socks5_dns_udp_relay& operator=(const socks5_dns_udp_relay&) = delete;
        socks5_dns_udp_relay& operator=(socks5_dns_udp_relay&&) = delete;

        /// Local listener port the router redirects UDP DNS queries to (0 until started).
        [[nodiscard]] uint16_t listener_port() const noexcept { return listener_port_; }

        /**
         * @brief Creates the listener and starts the threads. No association is opened until the
         *        first query arrives.
         * @return false if the listener socket could not be created.
         */
        bool start()
        {
            if (running_)
                return true;

            if (!create_listener_socket())
                return false;

            stopping_.store(false, std::memory_order_release);
            running_ = true;
            listener_thread_ = std::thread(&socks5_dns_udp_relay::listener_loop, this);
            maintenance_thread_ = std::thread(&socks5_dns_udp_relay::maintenance_loop, this);
            NETLIB_INFO("DNS relay: listening on UDP port {} for {} DNS queries via SOCKS5 server {}",
                listener_port_, address_type_t::af_type == AF_INET ? "IPv4" : "IPv6", upstream_.to_string());
            return true;
        }

        /// Stops the threads, closes the association and the listener. Idempotent.
        void stop()
        {
            if (!running_)
                return;

            stopping_.store(true, std::memory_order_release);
            {
                std::scoped_lock lock(lock_);
                maintenance_cv_.notify_all();
            }

            if (listener_thread_.joinable())
                listener_thread_.join();
            if (maintenance_thread_.joinable())
                maintenance_thread_.join();

            std::unique_ptr<association> current;
            {
                std::scoped_lock lock(lock_);
                current = std::move(association_);
                waiting_.clear();
                queries_.clear();
            }
            close_association(std::move(current));

            closesocket(listener_socket_);
            listener_socket_ = INVALID_SOCKET;
            running_ = false;
        }

    private:
        /// Client socket identity: the listener's sender (the queried server and the client
        /// port), plus the IPv6 scope so an answer to a link-local server can be sent back.
        struct client_t
        {
            endpoint_t endpoint;
            uint32_t scope_id{};

            bool operator==(const client_t& rhs) const noexcept
            {
                return endpoint == rhs.endpoint && scope_id == rhs.scope_id;
            }
        };

        struct client_hash
        {
            std::size_t operator()(const client_t& client) const noexcept
            {
                return std::hash<endpoint_t>{}(client.endpoint) ^ static_cast<std::size_t>(client.scope_id);
            }
        };

        /// One SOCKS5 control connection with its UDP relay socket and reader thread.
        struct association
        {
            SOCKET control{ INVALID_SOCKET };
            SOCKET relay{ INVALID_SOCKET };
            std::thread reader;
            std::atomic_bool retiring{ false };
            std::atomic_bool failed{ false };
        };

        struct waiting_query
        {
            client_t client;
            std::vector<uint8_t> datagram;
        };

        static constexpr uint8_t own_address_type = address_type_t::af_type == AF_INET ? 1 : 4;
        static constexpr std::size_t own_address_size = address_type_t::af_type == AF_INET ? 4 : 16;
        static constexpr DWORD receive_timeout_ms = 500;
        static constexpr std::size_t max_datagram_size = 65535;

        // --- Configuration -------------------------------------------------------------------

        endpoint_t upstream_;
        std::optional<std::pair<std::string, std::string>> credentials_;
        socks5_upstream_options upstream_options_;
        std::function<authorize_client_t> authorize_client_;
        std::function<relay_endpoint_observed_t> relay_endpoint_observed_;
        socks5_udp_association_client<address_type_t> association_client_;

        // --- State (lock_ protects everything below except the atomics and the listener) -----

        std::mutex lock_;
        std::condition_variable maintenance_cv_;
        std::unique_ptr<association> association_;
        std::deque<waiting_query> waiting_;
        dns_query_table<client_t, client_hash> queries_{ query_ttl, max_queries_in_flight };
        dns_association_health<> health_{ unanswered_limit, minimum_association_age };
        std::random_device random_;

        SOCKET listener_socket_{ INVALID_SOCKET };
        uint16_t listener_port_{ 0 };
        bool running_{ false };
        std::atomic_bool stopping_{ true };
        std::thread listener_thread_;
        std::thread maintenance_thread_;

        // --- Statistics, reported by the maintenance thread at a throttled rate ---------------

        std::atomic<uint64_t> dropped_unauthorized_{ 0 };
        std::atomic<uint64_t> dropped_malformed_{ 0 };
        std::atomic<uint64_t> dropped_unavailable_{ 0 };
        std::atomic<uint64_t> dropped_unmatched_answers_{ 0 };
        std::atomic<uint64_t> dropped_send_failures_{ 0 };
        uint64_t reported_drops_{ 0 };
        std::chrono::steady_clock::time_point last_report_{};

        // --- Helpers --------------------------------------------------------------------------

        uint16_t random_id()
        {
            return static_cast<uint16_t>(std::uniform_int_distribution<unsigned>{ 0, 0xFFFF }(random_));
        }

        static void set_receive_timeout(const SOCKET socket) noexcept
        {
            const DWORD timeout = receive_timeout_ms;
            setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        }

        static void disable_connection_reset(const SOCKET socket) noexcept
        {
            BOOL new_behavior = FALSE;
            DWORD bytes_returned = 0;
            WSAIoctl(socket, SIO_UDP_CONNRESET, &new_behavior, sizeof(new_behavior),
                nullptr, 0, &bytes_returned, nullptr, nullptr);
        }

        [[nodiscard]] static std::optional<client_t> client_from(const SOCKADDR_STORAGE& sender) noexcept
        {
            if constexpr (address_type_t::af_type == AF_INET)
            {
                if (sender.ss_family != AF_INET)
                    return std::nullopt;
                const auto* address = reinterpret_cast<const sockaddr_in*>(&sender);
                return client_t{ endpoint_t{ address_type_t{ address->sin_addr }, ntohs(address->sin_port) }, 0 };
            }
            else
            {
                if (sender.ss_family != AF_INET6)
                    return std::nullopt;
                const auto* address = reinterpret_cast<const sockaddr_in6*>(&sender);
                return client_t{ endpoint_t{ address_type_t{ address->sin6_addr }, ntohs(address->sin6_port) },
                    address->sin6_scope_id };
            }
        }

        [[nodiscard]] static std::pair<SOCKADDR_STORAGE, int> sockaddr_from(const client_t& client) noexcept
        {
            SOCKADDR_STORAGE storage{};
            if constexpr (address_type_t::af_type == AF_INET)
            {
                auto* address = reinterpret_cast<sockaddr_in*>(&storage);
                address->sin_family = AF_INET;
                address->sin_addr = client.endpoint.ip;
                address->sin_port = htons(client.endpoint.port);
                return { storage, static_cast<int>(sizeof(sockaddr_in)) };
            }
            else
            {
                auto* address = reinterpret_cast<sockaddr_in6*>(&storage);
                address->sin6_family = AF_INET6;
                address->sin6_addr = client.endpoint.ip;
                address->sin6_port = htons(client.endpoint.port);
                address->sin6_scope_id = client.scope_id;
                return { storage, static_cast<int>(sizeof(sockaddr_in6)) };
            }
        }

        bool create_listener_socket()
        {
            // SO_RCVTIMEO only takes effect on sockets created with WSA_FLAG_OVERLAPPED.
            listener_socket_ = WSASocket(address_type_t::af_type, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                WSA_FLAG_OVERLAPPED);
            if (listener_socket_ == INVALID_SOCKET)
            {
                NETLIB_ERROR("DNS relay: failed to create the listener socket: {}", WSAGetLastError());
                return false;
            }

            disable_connection_reset(listener_socket_);
            set_receive_timeout(listener_socket_);

            SOCKADDR_STORAGE local{};
            int local_size;
            if constexpr (address_type_t::af_type == AF_INET)
            {
                auto* address = reinterpret_cast<sockaddr_in*>(&local);
                address->sin_family = AF_INET;
                address->sin_addr.s_addr = htonl(INADDR_ANY);
                local_size = static_cast<int>(sizeof(sockaddr_in));
            }
            else
            {
                auto* address = reinterpret_cast<sockaddr_in6*>(&local);
                address->sin6_family = AF_INET6;
                address->sin6_addr = in6addr_any;
                local_size = static_cast<int>(sizeof(sockaddr_in6));
            }

            if (bind(listener_socket_, reinterpret_cast<sockaddr*>(&local), local_size) == SOCKET_ERROR ||
                getsockname(listener_socket_, reinterpret_cast<sockaddr*>(&local), &local_size) == SOCKET_ERROR)
            {
                NETLIB_ERROR("DNS relay: failed to bind the listener socket: {}", WSAGetLastError());
                closesocket(listener_socket_);
                listener_socket_ = INVALID_SOCKET;
                return false;
            }

            listener_port_ = address_type_t::af_type == AF_INET
                ? ntohs(reinterpret_cast<sockaddr_in*>(&local)->sin_port)
                : ntohs(reinterpret_cast<sockaddr_in6*>(&local)->sin6_port);
            return true;
        }

        /// Sends one query through the open association. Caller holds lock_.
        void send_query_locked(const client_t& client, std::vector<uint8_t>& datagram, const std::size_t dns_offset)
        {
            const auto original_id = *dns_message_id(datagram.data() + dns_offset, datagram.size() - dns_offset);
            const auto relay_id = queries_.insert(client, original_id, std::chrono::steady_clock::now(),
                [this] { return random_id(); });
            if (!relay_id)
            {
                ++dropped_unavailable_;
                return;
            }

            set_dns_message_id(datagram.data() + dns_offset, *relay_id);
            if (send(association_->relay, reinterpret_cast<const char*>(datagram.data()),
                static_cast<int>(datagram.size()), 0) == SOCKET_ERROR)
            {
                ++dropped_send_failures_;
                association_->failed.store(true, std::memory_order_release);
                maintenance_cv_.notify_all();
            }
        }

        // --- Threads ----------------------------------------------------------------------------

        void listener_loop()
        {
            std::vector<uint8_t> buffer(max_datagram_size);

            while (!stopping_.load(std::memory_order_acquire))
            {
                SOCKADDR_STORAGE sender{};
                int sender_size = static_cast<int>(sizeof(sender));
                const auto received = recvfrom(listener_socket_, reinterpret_cast<char*>(buffer.data()),
                    static_cast<int>(buffer.size()), 0, reinterpret_cast<sockaddr*>(&sender), &sender_size);
                if (received == SOCKET_ERROR || received <= 0)
                    continue; // timeout (checks stopping_), or a spurious error on a UDP socket

                const auto size = static_cast<std::size_t>(received);
                const auto client = client_from(sender);
                if (!client || client->endpoint.port == 0 || !authorize_client_ ||
                    !authorize_client_(client->endpoint.port))
                {
                    ++dropped_unauthorized_;
                    continue;
                }

                const auto dns_offset = socks5_dns_query_offset(buffer.data(), size, own_address_type);
                if (!dns_offset)
                {
                    ++dropped_malformed_;
                    continue;
                }

                std::vector<uint8_t> datagram(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(size));

                std::scoped_lock lock(lock_);
                if (association_ && !association_->failed.load(std::memory_order_acquire))
                {
                    send_query_locked(*client, datagram, *dns_offset);
                    continue;
                }

                // No usable association: hold the query while one is opened, unless opening is
                // backing off after a failure or too many queries are already waiting.
                if (!health_.may_open(std::chrono::steady_clock::now()) || waiting_.size() >= max_waiting_queries)
                {
                    ++dropped_unavailable_;
                    continue;
                }

                waiting_.push_back(waiting_query{ *client, std::move(datagram) });
                maintenance_cv_.notify_all();
            }
        }

        void reader_loop(association* const owner)
        {
            std::vector<uint8_t> buffer(max_datagram_size);
            std::vector<uint8_t> answer(max_datagram_size + 32);

            while (!stopping_.load(std::memory_order_acquire) && !owner->retiring.load(std::memory_order_acquire))
            {
                const auto received = recv(owner->relay, reinterpret_cast<char*>(buffer.data()),
                    static_cast<int>(buffer.size()), 0);
                if (received == SOCKET_ERROR)
                {
                    if (WSAGetLastError() == WSAETIMEDOUT)
                        continue;
                    owner->failed.store(true, std::memory_order_release);
                    {
                        std::scoped_lock lock(lock_);
                        maintenance_cv_.notify_all();
                    }
                    return;
                }

                const auto relayed = parse_socks5_udp_datagram(buffer.data(), static_cast<std::size_t>(received));
                const auto relay_id = relayed ? dns_message_id(relayed->data, relayed->data_size) : std::nullopt;
                if (!relay_id)
                {
                    ++dropped_unmatched_answers_;
                    continue;
                }

                std::optional<typename decltype(queries_)::pending> query;
                {
                    std::scoped_lock lock(lock_);
                    health_.on_relay_datagram();
                    query = queries_.take(*relay_id, std::chrono::steady_clock::now());
                }

                if (!query)
                {
                    ++dropped_unmatched_answers_;
                    continue;
                }

                const auto answer_size = build_dns_client_answer(*relayed,
                    reinterpret_cast<const uint8_t*>(&query->client.endpoint.ip), own_address_size, dns_port,
                    query->original_id, answer.data(), answer.size());
                if (answer_size == 0)
                {
                    ++dropped_unmatched_answers_;
                    continue;
                }

                const auto [to, to_size] = sockaddr_from(query->client);
                if (sendto(listener_socket_, reinterpret_cast<const char*>(answer.data()), static_cast<int>(answer_size),
                    0, reinterpret_cast<const sockaddr*>(&to), to_size) == SOCKET_ERROR)
                {
                    ++dropped_send_failures_;
                }
            }
        }

        void maintenance_loop()
        {
            using namespace std::chrono_literals;

            std::unique_lock lock(lock_);
            while (!stopping_.load(std::memory_order_acquire))
            {
                maintenance_cv_.wait_for(lock, 1s, [this]
                {
                    return stopping_.load(std::memory_order_acquire) ||
                        (association_ && association_->failed.load(std::memory_order_acquire)) ||
                        (!association_ && !waiting_.empty() && health_.may_open(std::chrono::steady_clock::now()));
                });
                if (stopping_.load(std::memory_order_acquire))
                    break;

                const auto now = std::chrono::steady_clock::now();

                // Retire an association whose relay or control connection failed, or that has
                // stopped answering.
                if (association_)
                {
                    const auto unanswered = queries_.expire(now);
                    const char* reason = nullptr;
                    if (association_->failed.load(std::memory_order_acquire))
                        reason = "the UDP relay socket failed";
                    else if (control_channel_closed(association_->control))
                        reason = "the SOCKS5 control connection closed";
                    else if (health_.on_unanswered(unanswered, now))
                        reason = "queries stopped being answered";

                    if (reason)
                    {
                        NETLIB_INFO("DNS relay: closing the SOCKS5 UDP association because {}; it is reopened "
                            "on the next query", reason);
                        auto retired = std::move(association_);
                        queries_.clear();
                        lock.unlock();
                        close_association(std::move(retired));
                        lock.lock();
                        continue;
                    }
                }
                else
                {
                    (void)queries_.expire(now);
                }

                if (!association_ && !waiting_.empty() && health_.may_open(now))
                    open_association(lock);

                report_drops(now);
            }
        }

        /// Opens an association for the waiting queries. Called with lock_ held; releases it
        /// for the blocking SOCKS5 exchange.
        void open_association(std::unique_lock<std::mutex>& lock)
        {
            lock.unlock();

            auto opened = connect_association();

            lock.lock();
            const auto now = std::chrono::steady_clock::now();

            if (!opened || stopping_.load(std::memory_order_acquire))
            {
                const bool failed = !opened;
                if (opened)
                {
                    lock.unlock();
                    close_association(std::move(opened));
                    lock.lock();
                }
                if (failed)
                {
                    health_.on_open_failed(now);
                    dropped_unavailable_ += waiting_.size();
                    waiting_.clear();
                    const auto retry = std::chrono::duration_cast<std::chrono::seconds>(health_.next_attempt() - now);
                    if (health_.consecutive_failures() == 1)
                    {
                        NETLIB_WARNING("DNS relay: could not open a SOCKS5 UDP association with {}; UDP DNS is "
                            "dropped until one opens (next attempt in {} s)", upstream_.to_string(), retry.count());
                    }
                    else
                    {
                        NETLIB_DEBUG("DNS relay: SOCKS5 UDP association attempt {} failed; next attempt in {} s",
                            health_.consecutive_failures(), retry.count());
                    }
                }
                return;
            }

            if (health_.consecutive_failures() > 0)
                NETLIB_INFO("DNS relay: SOCKS5 UDP association with {} opened", upstream_.to_string());
            else
                NETLIB_DEBUG("DNS relay: SOCKS5 UDP association with {} opened", upstream_.to_string());

            health_.on_opened(now);
            association_ = std::move(opened);
            association_->reader = std::thread(&socks5_dns_udp_relay::reader_loop, this, association_.get());

            auto waiting = std::move(waiting_);
            waiting_.clear();
            for (auto& query : waiting)
            {
                if (const auto offset = socks5_dns_query_offset(query.datagram.data(), query.datagram.size(),
                    own_address_type))
                {
                    send_query_locked(query.client, query.datagram, *offset);
                }
            }
        }

        /// Blocking: SOCKS5 connect, authentication, UDP ASSOCIATE and relay socket. Lock not held.
        std::unique_ptr<association> connect_association()
        {
            auto control = association_client_.connect_to_socks5_proxy(upstream_.ip, upstream_.port);
            if (control == INVALID_SOCKET)
                return nullptr;

            auto negotiate_ctx = std::make_unique<negotiate_context_t>(address_type_t{}, 0,
                credentials_ ? std::optional(credentials_->first) : std::nullopt,
                credentials_ ? std::optional(credentials_->second) : std::nullopt,
                upstream_options_);

            std::optional<endpoint_t> relay_endpoint;
            try
            {
                relay_endpoint = association_client_.associate_to_socks5_proxy(control, upstream_.ip, negotiate_ctx);
            }
            catch (...)
            {
                relay_endpoint.reset();
            }

            if (!relay_endpoint)
            {
                closesocket(control);
                return nullptr;
            }

            // Report the relay endpoint before the relay socket exists (recursion guard).
            if (relay_endpoint_observed_)
                relay_endpoint_observed_(*relay_endpoint);

            const auto relay = association_client_.create_relay_socket(*relay_endpoint);
            if (relay == INVALID_SOCKET)
            {
                closesocket(control);
                return nullptr;
            }
            set_receive_timeout(relay);

            auto result = std::make_unique<association>();
            result->control = control;
            result->relay = relay;
            return result;
        }

        /// Stops the association's reader and closes its sockets. Lock not held.
        static void close_association(std::unique_ptr<association> retired)
        {
            if (!retired)
                return;

            retired->retiring.store(true, std::memory_order_release);
            if (retired->reader.joinable())
                retired->reader.join();
            if (retired->relay != INVALID_SOCKET)
                closesocket(retired->relay);
            if (retired->control != INVALID_SOCKET)
                closesocket(retired->control);
        }

        /// Whether the SOCKS5 control connection has closed. After the UDP ASSOCIATE reply no data
        /// is expected on it, so readable data (for example a TLS close_notify) or EOF both mean
        /// the association has ended. Zero-timeout select: never blocks.
        [[nodiscard]] static bool control_channel_closed(const SOCKET control) noexcept
        {
            fd_set read_set;
            FD_ZERO(&read_set);
            FD_SET(control, &read_set);
            timeval timeout{};

            const auto select_result = select(0, &read_set, nullptr, nullptr, &timeout);
            if (select_result == 0)
                return false;
            if (select_result == SOCKET_ERROR)
                return WSAGetLastError() != WSAEINTR;

            char pending_byte{};
            const auto recv_result = recv(control, &pending_byte, 1, MSG_PEEK);
            if (recv_result == SOCKET_ERROR)
            {
                const auto error = WSAGetLastError();
                return error != WSAEWOULDBLOCK && error != WSAEINTR && error != WSAETIMEDOUT;
            }
            return true;
        }

        /// Logs what was dropped since the last report, at most every 30 seconds.
        void report_drops(const std::chrono::steady_clock::time_point now)
        {
            using namespace std::chrono_literals;

            const auto unauthorized = dropped_unauthorized_.load(std::memory_order_relaxed);
            const auto malformed = dropped_malformed_.load(std::memory_order_relaxed);
            const auto unavailable = dropped_unavailable_.load(std::memory_order_relaxed);
            const auto unmatched = dropped_unmatched_answers_.load(std::memory_order_relaxed);
            const auto send_failures = dropped_send_failures_.load(std::memory_order_relaxed);
            const auto total = unauthorized + malformed + unavailable + unmatched + send_failures;

            if (total == reported_drops_ || now - last_report_ < 30s)
                return;

            NETLIB_INFO("DNS relay: dropped so far: {} queries while no SOCKS5 UDP association was available, "
                "{} not from a redirected DNS client, {} without a DNS header, {} answers matching no query, "
                "{} send failures", unavailable, unauthorized, malformed, unmatched, send_failures);
            reported_drops_ = total;
            last_report_ = now;
        }
    };
}
