#pragma once

// Bookkeeping for the DNS proxy's shared SOCKS5 UDP association (socks5_dns_udp_relay.h).
//
// All UDP DNS queries of one address family travel through a single SOCKS5 UDP ASSOCIATE
// relay. Answers then no longer arrive per client socket, so each query's DNS message ID is
// replaced by a unique, randomly chosen relay ID on the way out, and the answer carrying that
// ID is mapped back to the client socket, its original ID and the server it queried.
//
// Like dns_routing_policy.h, this header is free of Windows, driver and socket types so it can
// be unit tested on any platform. The relay supplies time, randomness and raw datagrams.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

#include "dns_routing_policy.h"

namespace proxy
{
    /// Writes a DNS message ID (network byte order) into the first two bytes of @p payload.
    constexpr void set_dns_message_id(uint8_t* payload, const uint16_t id) noexcept
    {
        payload[0] = static_cast<uint8_t>(id >> 8);
        payload[1] = static_cast<uint8_t>(id & 0xff);
    }

    /// SOCKS5 UDP header size for an IPv4 (ATYP 1) or IPv6 (ATYP 4) address.
    [[nodiscard]] constexpr std::size_t socks5_udp_header_size(const uint8_t address_type) noexcept
    {
        return address_type == 1 ? 4 + 4 + 2 : address_type == 4 ? 4 + 16 + 2 : 0;
    }

    /**
     * @brief Validates a query the local redirect delivered to the DNS relay's listener and
     *        returns the offset of its DNS message.
     *
     * The redirect prepends a SOCKS5 UDP header of the listener's family (@p address_type)
     * naming the server to ask (the queried server or the server override). A datagram without
     * that header, or too short to carry a DNS header after it, cannot be multiplexed and is
     * dropped by the relay.
     */
    [[nodiscard]] constexpr std::optional<std::size_t> socks5_dns_query_offset(const uint8_t* datagram,
        const std::size_t size, const uint8_t address_type) noexcept
    {
        const auto view = parse_socks5_udp_datagram(datagram, size);
        if (!view || view->address_type != address_type || view->data_size < dns_header_size)
            return std::nullopt;
        return static_cast<std::size_t>(view->data - datagram);
    }

    /// Whether @p address (network byte order, 4 or 16 bytes) is a loopback address, including
    /// an IPv4-mapped IPv6 loopback address.
    [[nodiscard]] constexpr bool is_loopback_address(const uint8_t* address, const std::size_t size) noexcept
    {
        if (address == nullptr)
            return false;
        if (size == 4)
            return address[0] == 127;
        if (size != 16)
            return false;

        bool zero_prefix = true;
        for (std::size_t i = 0; i < 10; ++i)
            zero_prefix = zero_prefix && address[i] == 0;
        if (zero_prefix && address[10] == 0xff && address[11] == 0xff)
            return address[12] == 127; // ::ffff:127.x.y.z
        if (!zero_prefix || address[10] != 0 || address[11] != 0)
            return false;
        for (std::size_t i = 12; i < 15; ++i)
        {
            if (address[i] != 0)
                return false;
        }
        return address[15] == 1; // ::1
    }

    /**
     * @brief Whether the DNS relay may send a query its listener received.
     *
     * Redirected queries reach the listener from the address of the server the client queried,
     * with a SOCKS5 header the redirect wrote: port 53 of that same address, or the DNS server
     * override when one is configured. Anything else, and anything from a loopback address
     * (loopback traffic is never redirected), was sent to the listener directly by a local
     * process and is refused, so the listener cannot be used to reach other destinations
     * through the proxy.
     *
     * @param query The listener datagram's SOCKS5 header (parse_socks5_udp_datagram()).
     * @param sender_address The listener's sender address (network byte order).
     * @param override_address The override address for this family, or nullptr when none is
     *        configured; @p override_size and @p override_port are then ignored.
     */
    [[nodiscard]] constexpr bool dns_relay_destination_allowed(const socks5_udp_datagram_view& query,
        const uint8_t* sender_address, const std::size_t sender_size, const uint8_t* override_address,
        const std::size_t override_size, const uint16_t override_port) noexcept
    {
        if (sender_address == nullptr || is_loopback_address(sender_address, sender_size))
            return false;

        const auto same_address = [&query](const uint8_t* address, const std::size_t size) noexcept
        {
            if (query.address == nullptr || query.address_size != size)
                return false;
            for (std::size_t i = 0; i < size; ++i)
            {
                if (query.address[i] != address[i])
                    return false;
            }
            return true;
        };

        if (override_address != nullptr)
            return query.port == override_port && same_address(override_address, override_size);
        return query.port == dns_port && same_address(sender_address, sender_size);
    }

    /**
     * @brief Largest DNS answer the relay returns over UDP: the size that keeps the listener's
     *        reply (IP + UDP + SOCKS5 header + answer) within a 1280-byte packet, the IPv6
     *        minimum MTU, so it is never fragmented. A fragmented listener reply cannot be
     *        delivered: its first fragment is dropped.
     * @param address_type SOCKS5 ATYP of the listener's family: 1 (IPv4) or 4 (IPv6).
     */
    [[nodiscard]] constexpr std::size_t dns_udp_answer_limit(const uint8_t address_type) noexcept
    {
        constexpr std::size_t minimum_mtu = 1280;
        constexpr std::size_t udp_header = 8;
        const std::size_t ip_header = address_type == 1 ? 20 : 40;
        return minimum_mtu - ip_header - udp_header - socks5_udp_header_size(address_type);
    }

    /**
     * @brief Walks the question section of a DNS message (RFC 1035 section 4.1.2).
     *
     * @p visit is called, in order, for every byte range of the section: each QNAME label's
     * length byte, its content (with @p is_label_text true), the terminating zero byte or
     * two-byte compression pointer, and each question's QTYPE and QCLASS.
     *
     * @param limit The section must end at or before this offset.
     * @return The offset just past the section, or std::nullopt when it is malformed, truncated,
     *         or ends after @p limit.
     */
    template <typename Visitor>
    [[nodiscard]] constexpr std::optional<std::size_t> walk_dns_questions(const uint8_t* message,
        const std::size_t size, const std::size_t limit, Visitor&& visit)
    {
        if (message == nullptr || size < dns_header_size)
            return std::nullopt;

        const auto question_count = static_cast<std::size_t>((message[4] << 8) | message[5]);
        std::size_t end = dns_header_size;
        for (std::size_t question = 0; question < question_count; ++question)
        {
            // QNAME: labels ending with a zero byte, or a two-byte compression pointer.
            while (true)
            {
                if (end >= size)
                    return std::nullopt;
                const auto length = static_cast<std::size_t>(message[end]);
                if (length == 0)
                {
                    visit(message + end, 1, false);
                    ++end;
                    break;
                }
                if ((length & 0xC0) == 0xC0)
                {
                    if (size - end < 2)
                        return std::nullopt;
                    visit(message + end, 2, false);
                    end += 2;
                    break;
                }
                if ((length & 0xC0) != 0 || size - end < 1 + length)
                    return std::nullopt;
                visit(message + end, 1, false);
                visit(message + end + 1, length, true);
                end += 1 + length;
            }
            if (size - end < 4)
                return std::nullopt;
            visit(message + end, 4, false); // QTYPE, QCLASS
            end += 4;
            if (end > limit)
                return std::nullopt;
        }
        return end;
    }

    /**
     * @brief A 64-bit fingerprint of a DNS message's question section (count, names ignoring
     *        ASCII case, types and classes), used to check that an answer belongs to the query
     *        it claims to answer.
     * @return std::nullopt when the message has no question or its question section is malformed.
     */
    [[nodiscard]] inline std::optional<uint64_t> dns_question_fingerprint(const uint8_t* message,
        const std::size_t size) noexcept
    {
        if (message == nullptr || size < dns_header_size || ((message[4] << 8) | message[5]) == 0)
            return std::nullopt;

        uint64_t hash = 14695981039346656037ull; // FNV-1a
        const auto mix = [&hash](const uint8_t byte) noexcept
        {
            hash ^= byte;
            hash *= 1099511628211ull;
        };
        mix(message[4]);
        mix(message[5]);
        const auto end = walk_dns_questions(message, size, size,
            [&mix](const uint8_t* bytes, const std::size_t count, const bool is_label_text) noexcept
            {
                for (std::size_t i = 0; i < count; ++i)
                {
                    const auto byte = bytes[i];
                    mix(is_label_text && byte >= 'A' && byte <= 'Z' ? static_cast<uint8_t>(byte + ('a' - 'A')) : byte);
                }
            });
        if (!end)
            return std::nullopt;
        return hash;
    }

    /**
     * @brief Whether a DNS answer belongs to a query with question fingerprint @p question.
     *
     * The answer must carry the same question section (RFC 1035 servers copy it). An error
     * response without a question section (QR set, non-zero RCODE, QDCOUNT 0), which some
     * servers send for queries they cannot parse or do not implement, is also accepted.
     */
    [[nodiscard]] inline bool dns_answer_matches_question(const uint8_t* answer, const std::size_t size,
        const uint64_t question) noexcept
    {
        if (answer == nullptr || size < dns_header_size)
            return false;
        if (const auto fingerprint = dns_question_fingerprint(answer, size))
            return *fingerprint == question;

        const bool is_response = (answer[2] & 0x80) != 0;
        const bool is_error = (answer[3] & 0x0F) != 0;
        const bool no_question = answer[4] == 0 && answer[5] == 0;
        return is_response && is_error && no_question;
    }

    /**
     * @brief Truncates a DNS answer larger than @p limit the way a server does when an answer
     *        does not fit (RFC 1035 section 4.2.1, RFC 7766): the TC bit is set, and only the
     *        header and question section are kept, so the resolver repeats the query over TCP.
     *
     * The answer, authority and additional counts are zeroed. If the question section cannot be
     * parsed, only the header is kept, with a zero question count.
     *
     * @return The new size (unchanged when @p size <= @p limit or the message has no header).
     */
    [[nodiscard]] constexpr std::size_t truncate_dns_answer(uint8_t* message, const std::size_t size,
        const std::size_t limit) noexcept
    {
        if (message == nullptr || size <= limit || size < dns_header_size)
            return size;

        auto end = walk_dns_questions(message, size, limit, [](const uint8_t*, std::size_t, bool) noexcept {});
        if (!end)
        {
            end = dns_header_size;
            message[4] = 0;
            message[5] = 0;
        }

        message[2] = static_cast<uint8_t>(message[2] | 0x02); // TC
        for (std::size_t field = 6; field < dns_header_size; ++field)
            message[field] = 0; // ANCOUNT, NSCOUNT, ARCOUNT
        return *end;
    }

    /**
     * @brief Builds the datagram the DNS relay returns to a local client from an answer the
     *        SOCKS5 relay delivered.
     *
     * The output is a SOCKS5 UDP header of the listener's family naming the server the client
     * queried (@p server_address, @p server_port), followed by the DNS answer with the client's
     * original message ID. The local redirect presents the answer with that header's address as
     * its source, so the client sees an answer from the server it asked, whatever source and
     * address family the relay reported (always the override with a server override; for some
     * relays their own address).
     *
     * @param relayed The relay's datagram, already parsed (parse_socks5_udp_datagram()).
     * @param server_address Queried server address bytes (network byte order): 4 or 16 bytes.
     * An answer larger than dns_udp_answer_limit() is truncated (truncate_dns_answer()), so the
     * resolver retries over TCP instead of receiving a fragmented reply it would never get.
     *
     * @param original_id The client's DNS message ID.
     * @param out Output buffer.
     * @return Bytes written, or 0 when the answer does not fit, carries no DNS header, or
     *         @p address_size is not 4 or 16.
     */
    [[nodiscard]] inline std::size_t build_dns_client_answer(const socks5_udp_datagram_view& relayed,
        const uint8_t* server_address, const std::size_t address_size, const uint16_t server_port,
        const uint16_t original_id, uint8_t* out, const std::size_t out_capacity) noexcept
    {
        if (relayed.data == nullptr || relayed.data_size < dns_header_size || server_address == nullptr ||
            out == nullptr || (address_size != 4 && address_size != 16))
            return 0;

        const uint8_t address_type = address_size == 4 ? 1 : 4;
        const auto header_size = socks5_udp_header_size(address_type);
        if (out_capacity < header_size || out_capacity - header_size < relayed.data_size)
            return 0;

        out[0] = 0; // RSV
        out[1] = 0;
        out[2] = 0; // FRAG
        out[3] = address_type;
        std::memcpy(out + 4, server_address, address_size);
        out[4 + address_size] = static_cast<uint8_t>(server_port >> 8);
        out[4 + address_size + 1] = static_cast<uint8_t>(server_port & 0xff);
        std::memmove(out + header_size, relayed.data, relayed.data_size);
        set_dns_message_id(out + header_size, original_id);
        return header_size + truncate_dns_answer(out + header_size, relayed.data_size,
            dns_udp_answer_limit(address_type));
    }


    /**
     * @brief Queries in flight through the shared association, keyed by relay ID.
     *
     * insert() replaces a query's message ID with a relay ID that is unique among the queries in
     * flight and chosen by the caller's random source, so the 16-bit ID keeps its full entropy
     * against forged answers. A retransmission (same client socket and original ID) reuses its
     * relay ID, so duplicate answers map to it and it counts once as unanswered. Each entry also
     * keeps the query's question fingerprint (dns_question_fingerprint()) so an answer can be
     * checked against it. Entries expire after the TTL; the table is bounded, and when full the
     * oldest query is evicted.
     *
     * Not thread-safe: the caller serializes access.
     *
     * @tparam Client Client socket identity (equality-comparable, hashed by @p Hash). The relay
     *         uses the listener's sender endpoint: the queried server address and the client port.
     */
    template <typename Client, typename Hash = std::hash<Client>, typename Clock = std::chrono::steady_clock>
    class dns_query_table
    {
    public:
        using time_point = typename Clock::time_point;

        struct pending
        {
            Client client;
            uint16_t original_id{};
            uint64_t question{};
        };

        dns_query_table(const std::chrono::seconds ttl, const std::size_t capacity)
            : ttl_(ttl), capacity_(std::max<std::size_t>(capacity, 1))
        {
        }

        /**
         * @brief Records a query and returns its relay ID.
         * @param question The query's question fingerprint.
         * @param random Callable returning a uniformly distributed uint16_t.
         * @return The relay ID, or std::nullopt only if no ID could be found (cannot happen while
         *         the capacity is below 65536).
         */
        template <typename Random>
        std::optional<uint16_t> insert(const Client& client, const uint16_t original_id, const uint64_t question,
            const time_point now, Random&& random)
        {
            const key k{ client, original_id };
            if (const auto existing = by_client_.find(k); existing != by_client_.end())
            {
                auto& entry = entries_.at(existing->second);
                entry.sent_at = now;
                entry.question = question;
                return existing->second;
            }

            // Expiry is left to expire(), which reports the unanswered count; a full table only
            // evicts its oldest query.
            if (entries_.size() >= capacity_)
                evict_oldest();

            // Random probing; the table holds at most capacity_ of 65536 IDs, so a free ID is
            // found within a few draws. Fall back to a linear scan from a random start.
            std::optional<uint16_t> relay_id;
            for (int attempt = 0; attempt < 16 && !relay_id; ++attempt)
            {
                const auto candidate = static_cast<uint16_t>(random());
                if (!entries_.contains(candidate))
                    relay_id = candidate;
            }
            if (!relay_id)
            {
                const auto start = static_cast<uint16_t>(random());
                for (uint32_t step = 0; step < 0x10000 && !relay_id; ++step)
                {
                    const auto candidate = static_cast<uint16_t>(start + step);
                    if (!entries_.contains(candidate))
                        relay_id = candidate;
                }
            }
            if (!relay_id)
                return std::nullopt;

            entries_.emplace(*relay_id, entry{ client, original_id, question, now });
            by_client_.emplace(k, *relay_id);
            return relay_id;
        }

        /// insert() for a query without a question fingerprint (fingerprint 0).
        template <typename Random>
        std::optional<uint16_t> insert(const Client& client, const uint16_t original_id, const time_point now,
            Random&& random)
        {
            return insert(client, original_id, uint64_t{ 0 }, now, std::forward<Random>(random));
        }

        /// The live query with @p relay_id, without removing it.
        [[nodiscard]] std::optional<pending> find(const uint16_t relay_id, const time_point now) const
        {
            const auto it = entries_.find(relay_id);
            if (it == entries_.end() || now - it->second.sent_at > ttl_)
                return std::nullopt;
            return pending{ it->second.client, it->second.original_id, it->second.question };
        }

        /**
         * @brief Removes and returns the query an answer with @p relay_id belongs to.
         * @return std::nullopt for an unknown or expired relay ID.
         */
        std::optional<pending> take(const uint16_t relay_id, const time_point now)
        {
            const auto it = entries_.find(relay_id);
            if (it == entries_.end())
                return std::nullopt;

            const bool expired = now - it->second.sent_at > ttl_;
            pending result{ it->second.client, it->second.original_id, it->second.question };
            erase(it);
            if (expired)
                return std::nullopt;
            return result;
        }

        /**
         * @brief Removes queries older than the TTL.
         * @param counted_after When set, only expired queries sent after this time are counted.
         * @return How many expired queries were counted.
         */
        std::size_t expire(const time_point now, const std::optional<time_point> counted_after = std::nullopt)
        {
            std::size_t counted = 0;
            for (auto it = entries_.begin(); it != entries_.end();)
            {
                if (now - it->second.sent_at > ttl_)
                {
                    if (!counted_after || it->second.sent_at > *counted_after)
                        ++counted;
                    it = erase(it);
                }
                else
                {
                    ++it;
                }
            }
            return counted;
        }

        void clear() noexcept
        {
            entries_.clear();
            by_client_.clear();
        }

        [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
        [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }

    private:
        struct entry
        {
            Client client;
            uint16_t original_id{};
            uint64_t question{};
            time_point sent_at{};
        };

        struct key
        {
            Client client;
            uint16_t original_id{};
            bool operator==(const key& rhs) const { return client == rhs.client && original_id == rhs.original_id; }
        };

        struct key_hash
        {
            std::size_t operator()(const key& k) const noexcept
            {
                return Hash{}(k.client) ^ (static_cast<std::size_t>(k.original_id) * 0x9E3779B1u);
            }
        };

        using entries_t = std::unordered_map<uint16_t, entry>;

        typename entries_t::iterator erase(typename entries_t::iterator it)
        {
            by_client_.erase(key{ it->second.client, it->second.original_id });
            return entries_.erase(it);
        }

        void evict_oldest()
        {
            const auto oldest = std::min_element(entries_.begin(), entries_.end(),
                [](const auto& a, const auto& b) { return a.second.sent_at < b.second.sent_at; });
            if (oldest != entries_.end())
                erase(oldest);
        }

        entries_t entries_;
        std::unordered_map<key, uint16_t, key_hash> by_client_;
        std::chrono::seconds ttl_;
        std::size_t capacity_;
    };

    /**
     * @brief Decides when the shared association is reopened and when a new one may be tried.
     *
     * - A failed open is retried after a backoff that doubles from 1 s up to 30 s; queries
     *   arriving meanwhile are dropped (Proxy mode never sends DNS directly). An association that
     *   closes less than @p minimum_age after opening counts as a failed open, so a server that
     *   accepts UDP ASSOCIATE and then drops the connection is not reconnected in a tight loop,
     *   and so does one retired because it stopped answering. The backoff resets only when an
     *   association proves itself: a datagram arrives from the relay once it is at least
     *   @p minimum_age old, or it closes normally at that age.
     * - An open association is reopened when its SOCKS5 control connection closes or its relay
     *   socket fails (reported by the relay), or when it looks silently dead: at least
     *   @p unanswered_limit queries expired unanswered that were sent after the last datagram
     *   from the relay, and the association is at least @p minimum_age old. A query sent before
     *   a datagram that did arrive is not counted, so a resolver that never answers cannot
     *   retire an association that keeps delivering other answers.
     *
     * Not thread-safe: the caller serializes access.
     */
    template <typename Clock = std::chrono::steady_clock>
    class dns_association_health
    {
    public:
        using time_point = typename Clock::time_point;

        explicit dns_association_health(const std::size_t unanswered_limit = 3,
            const std::chrono::seconds minimum_age = std::chrono::seconds{ 30 })
            : unanswered_limit_(std::max<std::size_t>(unanswered_limit, 1)), minimum_age_(minimum_age)
        {
        }

        /// Whether opening an association may be attempted at @p now.
        [[nodiscard]] bool may_open(const time_point now) const noexcept
        {
            return failures_ == 0 || now >= next_attempt_;
        }

        /**
         * @brief Records a failed attempt to open an association and backs off.
         * @return true for the first failed attempt since the last successful open (or since
         *         the relay started), which the relay reports as a warning.
         */
        bool on_open_failed(const time_point now) noexcept
        {
            back_off(now);
            const bool first = !open_failure_reported_;
            open_failure_reported_ = true;
            return first;
        }

        void on_opened(const time_point now) noexcept
        {
            unanswered_ = 0;
            opened_at_ = now;
            last_datagram_.reset();
            open_failure_reported_ = false;
        }

        /**
         * @brief The association was closed at @p now.
         * @param failed The association stopped working (for example it was retired for
         *        unanswered queries): back off before the next attempt whatever its age. An
         *        association younger than the minimum age always counts as a failed open.
         */
        void on_closed(const time_point now, const bool failed = false) noexcept
        {
            if (failed || now - opened_at_ < minimum_age_)
                back_off(now);
            else
                failures_ = 0;
        }

        /// Any datagram from the relay shows the association is alive; once it is also at least
        /// the minimum age, it has proved itself and the backoff resets.
        void on_relay_datagram(const time_point now) noexcept
        {
            unanswered_ = 0;
            last_datagram_ = now;
            if (now - opened_at_ >= minimum_age_)
                failures_ = 0;
        }

        /// Time of the last datagram from the relay since the association opened, if any.
        [[nodiscard]] std::optional<time_point> last_datagram() const noexcept { return last_datagram_; }

        /**
         * @brief Records @p count queries that expired unanswered (counted as expire() does with
         *        last_datagram()); true when the association should be reopened.
         */
        [[nodiscard]] bool on_unanswered(const std::size_t count, const time_point now) noexcept
        {
            unanswered_ += count;
            return unanswered_ >= unanswered_limit_ && now - opened_at_ >= minimum_age_;
        }

        [[nodiscard]] std::size_t consecutive_failures() const noexcept { return failures_; }
        [[nodiscard]] time_point next_attempt() const noexcept { return next_attempt_; }

        static constexpr std::chrono::seconds max_backoff{ 30 };

    private:
        void back_off(const time_point now) noexcept
        {
            ++failures_;
            const auto shift = std::min<std::size_t>(failures_ - 1, 5); // 1, 2, 4, 8, 16, 32 s
            next_attempt_ = now + (std::min)(std::chrono::seconds{ 1 } * (1u << shift), max_backoff);
        }

        bool open_failure_reported_{ false };
        std::size_t unanswered_limit_;
        std::chrono::seconds minimum_age_;
        std::size_t failures_{};
        std::size_t unanswered_{};
        time_point next_attempt_{};
        time_point opened_at_{};
        std::optional<time_point> last_datagram_;
    };

    /// What happens to a query the DNS relay's listener received.
    enum class dns_relay_query : uint8_t
    {
        send,      ///< rewritten with its relay ID: send it through the association
        malformed, ///< no SOCKS5 header of the listener's family, or no parsable DNS question
        no_id      ///< no free relay ID (cannot happen below 65536 queries in flight)
    };

    /// What happens to a datagram the SOCKS5 relay delivered.
    enum class dns_relay_answer : uint8_t
    {
        deliver,           ///< return it to the client
        malformed,         ///< no SOCKS5 UDP header, no DNS header, or does not fit the output
        unmatched,         ///< matches no query in flight (late, duplicate or unsolicited)
        question_mismatch  ///< its relay ID is in flight but its question is another query's
    };

    /**
     * @brief The DNS relay's per-datagram logic for one shared association, free of sockets so
     *        it is unit tested on any platform (socks5_dns_udp_relay.h does the I/O).
     *
     * Combines the table of queries in flight, the association health, the question check and
     * the answer returned to the client. Not thread-safe: the relay serializes access.
     */
    template <typename Client, typename Hash = std::hash<Client>, typename Clock = std::chrono::steady_clock>
    class dns_relay_session
    {
    public:
        using time_point = typename Clock::time_point;
        using table_t = dns_query_table<Client, Hash, Clock>;

        struct answer
        {
            dns_relay_answer outcome{ dns_relay_answer::malformed };
            std::optional<Client> client;
            std::size_t size{}; ///< bytes written to the output buffer when delivered
        };

        dns_relay_session(const std::chrono::seconds query_ttl, const std::size_t max_queries,
            const std::size_t unanswered_limit, const std::chrono::seconds minimum_association_age)
            : queries_(query_ttl, max_queries), health_(unanswered_limit, minimum_association_age)
        {
        }

        /**
         * @brief Prepares a query from the listener for the association: validates it, records
         *        it, and replaces its DNS message ID with the relay ID in place.
         * @param datagram SOCKS5 UDP header of the listener's family (@p address_type) followed
         *        by the DNS query, as the local redirect delivered it.
         */
        template <typename Random>
        dns_relay_query prepare_query(const Client& client, uint8_t* datagram, const std::size_t size,
            const uint8_t address_type, const time_point now, Random&& random)
        {
            const auto offset = socks5_dns_query_offset(datagram, size, address_type);
            if (!offset)
                return dns_relay_query::malformed;

            auto* const message = datagram + *offset;
            const auto message_size = size - *offset;
            const auto question = dns_question_fingerprint(message, message_size);
            if (!question)
                return dns_relay_query::malformed;

            const auto original_id = *dns_message_id(message, message_size);
            const auto relay_id = queries_.insert(client, original_id, *question, now, std::forward<Random>(random));
            if (!relay_id)
                return dns_relay_query::no_id;

            set_dns_message_id(message, *relay_id);
            return dns_relay_query::send;
        }

        /**
         * @brief Maps a datagram from the SOCKS5 relay back to its client.
         *
         * Every datagram from the relay counts as a sign of life. An answer is delivered only if
         * its relay ID is in flight and its question section matches that query's
         * (dns_answer_matches_question()); a mismatch does not consume the query.
         *
         * @param address_of (const Client&) -> std::pair<const uint8_t*, std::size_t>: the
         *        address bytes of the server the client queried.
         * @param out Output buffer for the datagram returned to the client
         *        (build_dns_client_answer()).
         */
        template <typename AddressOf>
        answer prepare_answer(const uint8_t* relayed, const std::size_t size, AddressOf&& address_of,
            uint8_t* out, const std::size_t out_capacity, const time_point now)
        {
            health_.on_relay_datagram(now);

            const auto view = parse_socks5_udp_datagram(relayed, size);
            const auto relay_id = view ? dns_message_id(view->data, view->data_size) : std::nullopt;
            if (!relay_id)
                return { dns_relay_answer::malformed, std::nullopt, 0 };

            const auto query = queries_.find(*relay_id, now);
            if (!query)
                return { dns_relay_answer::unmatched, std::nullopt, 0 };
            if (!dns_answer_matches_question(view->data, view->data_size, query->question))
                return { dns_relay_answer::question_mismatch, std::nullopt, 0 };

            (void)queries_.take(*relay_id, now);
            const auto [address, address_size] = address_of(query->client);
            const auto written = build_dns_client_answer(*view, address, address_size, dns_port,
                query->original_id, out, out_capacity);
            if (written == 0)
                return { dns_relay_answer::malformed, std::nullopt, 0 };
            return { dns_relay_answer::deliver, query->client, written };
        }

        /// Expires queries; true when the association looks silently dead and should be reopened.
        [[nodiscard]] bool expire(const time_point now)
        {
            return health_.on_unanswered(queries_.expire(now, health_.last_datagram()), now);
        }

        /// Expires queries while no association is open (nothing is counted).
        void expire_closed(const time_point now) { (void)queries_.expire(now); }

        [[nodiscard]] bool may_open(const time_point now) const noexcept { return health_.may_open(now); }
        /// See dns_association_health::on_open_failed().
        bool on_open_failed(const time_point now) noexcept { return health_.on_open_failed(now); }
        void on_opened(const time_point now) noexcept { health_.on_opened(now); }

        /// The association closed: its queries in flight can no longer be answered. See
        /// dns_association_health::on_closed() for @p failed.
        void on_closed(const time_point now, const bool failed = false) noexcept
        {
            queries_.clear();
            health_.on_closed(now, failed);
        }

        void clear() noexcept { queries_.clear(); }

        [[nodiscard]] std::size_t queries_in_flight() const noexcept { return queries_.size(); }
        [[nodiscard]] std::size_t consecutive_failures() const noexcept { return health_.consecutive_failures(); }
        [[nodiscard]] time_point next_attempt() const noexcept { return health_.next_attempt(); }

    private:
        table_t queries_;
        dns_association_health<Clock> health_;
    };

    /**
     * @brief Queries held while the shared association is being opened: bounded in number, and
     *        each held at most @p max_wait, so nothing is sent long after the client gave up.
     *        Items stay in arrival order. Not thread-safe: the relay serializes access.
     */
    template <typename Item, typename Clock = std::chrono::steady_clock>
    class dns_waiting_queue
    {
    public:
        using time_point = typename Clock::time_point;

        dns_waiting_queue(const std::size_t capacity, const std::chrono::milliseconds max_wait)
            : capacity_(capacity), max_wait_(max_wait)
        {
        }

        /// Queues @p item; false (and @p item is not queued) when the queue is full.
        bool push(Item item, const time_point now)
        {
            if (items_.size() >= capacity_)
                return false;
            items_.emplace_back(now, std::move(item));
            return true;
        }

        /// Drops items held longer than max_wait; returns how many.
        std::size_t drop_stale(const time_point now)
        {
            std::size_t stale = 0;
            while (!items_.empty() && now - items_.front().first > max_wait_)
            {
                items_.pop_front();
                ++stale;
            }
            return stale;
        }

        /// Drops everything; returns how many.
        std::size_t drop_all() noexcept
        {
            const auto dropped = items_.size();
            items_.clear();
            return dropped;
        }

        /// Removes and returns every item, oldest first.
        std::vector<Item> take_all()
        {
            std::vector<Item> taken;
            taken.reserve(items_.size());
            for (auto& [queued_at, item] : items_)
                taken.push_back(std::move(item));
            items_.clear();
            return taken;
        }

        [[nodiscard]] bool empty() const noexcept { return items_.empty(); }
        [[nodiscard]] std::size_t size() const noexcept { return items_.size(); }

    private:
        std::deque<std::pair<time_point, Item>> items_;
        std::size_t capacity_;
        std::chrono::milliseconds max_wait_;
    };
}
