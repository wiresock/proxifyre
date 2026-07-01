#pragma once

namespace proxy
{
    /**
     * @brief SOCKS5 UDP proxy server implementation.
     *
     * This class implements a local UDP proxy server that relays UDP packets through a SOCKS5 proxy.
     * It manages the lifecycle of proxy sockets, handles client connections, and coordinates
     * asynchronous I/O operations using Windows I/O completion ports.
     *
     * @tparam T Proxy socket implementation type.
     */
    template <typename T>
    class socks5_local_udp_proxy_server : public netlib::log::logger<socks5_local_udp_proxy_server<T>>
    {
    public:
        /**
         * @brief Logging level type alias.
         *
         * Alias for the logging level enumeration used by the proxy server.
         */
        using log_level = netlib::log::log_level;

        /**
         * @brief Logger type alias.
         *
         * Alias for the logger base class used for logging within the proxy server.
         */
        using logger = netlib::log::logger<socks5_local_udp_proxy_server>;

        /**
         * @brief Negotiation context type alias.
         *
         * Alias for the negotiation context type defined by the proxy socket implementation (T).
         * Used to store authentication and session information for SOCKS5 negotiation.
         */
        using negotiate_context_t = typename T::negotiate_context_t;

        /**
         * @brief Address type alias.
         *
         * Alias for the address type defined by the proxy socket implementation (T).
         * Represents an IPv4 or IPv6 address, depending on the template parameter.
         */
        using address_type_t = typename T::address_type_t;

        /**
         * @brief Per-I/O context type alias.
         *
         * Alias for the per-I/O context type defined by the proxy socket implementation (T).
         * Used for managing asynchronous I/O operations.
         */
        using per_io_context_t = typename T::per_io_context_t;

        /**
         * @brief Query remote peer function signature.
         *
         * Function type that takes a local address and port, and returns a tuple containing:
         * - The remote address to connect to,
         * - The remote port,
         * - A unique pointer to a negotiation context (for authentication/session).
         */
        using query_remote_peer_t = std::tuple<address_type_t, uint16_t, std::unique_ptr<negotiate_context_t>>(
            address_type_t, uint16_t);

    private:
        /**
         * @brief Maximum number of simultaneous proxy connections.
         *
         * This constant defines the maximum number of concurrent connections
         * the proxy server will track in its internal connection array.
         */
        constexpr static size_t connections_array_size = 64;

        /**
         * @brief Mutex for synchronizing access to internal data structures.
         *
         * Used to protect shared resources such as the proxy_sockets_ map
         * from concurrent access by multiple threads.
         */
        std::mutex lock_;

        /**
         * @brief Thread object for the main proxy server loop.
         *
         * Handles the main server operations, such as accepting and processing client requests.
         */
        std::thread proxy_server_;

        /**
         * @brief Thread object for client cleanup operations.
         *
         * Periodically checks and removes inactive or closed client connections.
         */
        std::thread check_clients_thread_;

        /**
         * @brief Map of active proxy sockets indexed by local UDP port.
         *
         * Uses shared_ptr to enable safe concurrent access from IOCP threads.
         * Each entry represents a client session managed by the proxy server.
         * The last reference may be held by a pending I/O operation.
         */
        std::map<uint16_t, std::shared_ptr<T>> proxy_sockets_;

        /**
         * @brief Indicates whether the server is terminating.
         *
         * Set to true when the server is stopping or has stopped.
         */
        std::atomic_bool end_server_{ true }; // set to true on proxy termination

        /**
         * @brief Counts the number of IOCP operations currently executing in the lambda.
         *
         * Incremented when entering the lambda, decremented when exiting.
         * Used during shutdown to ensure no operations are in-flight before destroying the object.
         */
        std::atomic<int32_t> active_iocp_operations_{ 0 };

        /**
         * @brief UDP server socket handle.
         *
         * The main socket used to receive and send UDP packets for the proxy server.
         */
        SOCKET server_socket_{ INVALID_SOCKET };

        /**
         * @brief Memory pool for efficient allocation and reuse of packet buffers.
         */
        std::shared_ptr<packet_pool> packet_pool_{};

        /**
         * @brief Buffer for receiving UDP packets from clients.
         */
        std::array<char, T::send_receive_buffer_size> server_receive_buffer_{};

        /**
         * @brief WSABUF structure for overlapped I/O operations on the server socket.
         */
        WSABUF server_recv_buf_{ static_cast<ULONG>(server_receive_buffer_.size()), server_receive_buffer_.data() };

        /**
         * @brief Per-I/O context for the server socket's read operations.
         */
        per_io_context_t server_io_context_{ proxy_io_operation::relay_io_read, nullptr, true };

        /**
         * @brief Storage for the address of the sender of the last received UDP packet.
         */
        SOCKADDR_STORAGE recv_from_sa_{};

        /**
         * @brief Size of the sender address structure.
         */
        INT recv_from_sa_size_{ sizeof(SOCKADDR_STORAGE) };

        /**
         * @brief Local UDP port number the proxy server is bound to.
         */
        uint16_t proxy_port_;

        /**
         * @brief Reference to the I/O completion port used for asynchronous operations.
         */
        netlib::winsys::io_completion_port& completion_port_;

        /**
         * @brief Completion key associated with the server socket in the I/O completion port.
         */
        ULONG_PTR completion_key_{ 0 };

        /**
         * @brief Function to query remote peer information for a given local address and port.
         */
        std::function<query_remote_peer_t> query_remote_peer_;

    public:
        /**
         * @brief Constructs a SOCKS5 local UDP proxy server.
         *
         * Initializes the proxy server with the specified UDP port, I/O completion port,
         * remote peer query function, logging level, and optional log stream.
         *
         * @param proxy_port The local UDP port to bind the proxy server to.
         * @param completion_port Reference to the I/O completion port for asynchronous operations.
         * @param query_remote_peer_fn Function to resolve the remote peer for a given local address/port.
         * @param log_level The logging level for the server (default: error).
         * @param log_stream Optional output stream for logging (default: std::nullopt).
         *
         * @throws std::runtime_error if the server socket cannot be created or bound.
         */
        socks5_local_udp_proxy_server(const uint16_t proxy_port, netlib::winsys::io_completion_port& completion_port,
            const std::function<query_remote_peer_t>& query_remote_peer_fn,
            const log_level log_level = log_level::error,
            std::shared_ptr<std::ostream> log_stream = nullptr)
            : logger(log_level, std::move(log_stream)),
            proxy_port_(proxy_port),
            completion_port_(completion_port),
            query_remote_peer_(query_remote_peer_fn)
        {
            if (!create_server_socket())
            {
                throw std::runtime_error("socks5_local_udp_proxy_server: failed to create server socket.");
            }

            packet_pool_ = std::make_shared<packet_pool>();
        }

        /**
         * @brief Destructor. Cleans up resources and stops the server if running.
         *
         * Closes the server socket and calls stop() if the server is still running.
         */
        ~socks5_local_udp_proxy_server()
        {
            if (server_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
            {
                closesocket(server_socket_);
                server_socket_ = INVALID_SOCKET;
            }

            if (end_server_ == false)
                stop();
        }

        // Deleted copy constructor to prevent copying.
        socks5_local_udp_proxy_server(const socks5_local_udp_proxy_server& other) = delete;

        // Deleted move constructor to prevent moving.
        socks5_local_udp_proxy_server(socks5_local_udp_proxy_server&& other) noexcept = delete;

        // Deleted copy assignment operator to prevent copying.
        socks5_local_udp_proxy_server& operator=(const socks5_local_udp_proxy_server& other) = delete;

        // Deleted move assignment operator to prevent moving.
        socks5_local_udp_proxy_server& operator=(socks5_local_udp_proxy_server&& other) noexcept = delete;

        /**
         * @brief Gets the local UDP port the proxy server is bound to.
         *
         * @return The UDP port number.
         */
        [[nodiscard]] uint16_t proxy_port() const
        {
            return proxy_port_;
        }

        /**
         * @brief Starts the SOCKS5 local UDP proxy server.
         *
         * Associates the server socket with the I/O completion port and begins listening for UDP packets.
         * If the server is already running, this function is a no-op and returns true.
         * On failure, the server socket is closed and the server is marked as stopped.
         *
         * @return True if the server started successfully or was already running, false otherwise.
         */
        bool start()
        {
            if (end_server_ == false)
            {
                // already running
                return true;
            }

            end_server_ = false;

            if (server_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
            {
                if (auto [associate_status, io_key] = completion_port_.associate_socket(
                    server_socket_,
                    [this](const DWORD num_bytes, OVERLAPPED* povlp, const BOOL status)
                    {
                        // Count this completion for the entire duration of the callback so
                        // stop() waits for it. EVERY completion the IOCP delivers on this
                        // shared key -- the server read AND every per-session proxy
                        // relay/negotiate/inject completion -- is balanced exactly once:
                        // +1 here, -1 in the guard below. (Previously only the server-read
                        // re-post incremented, so proxy completions drove the counter
                        // negative and stop() could stop waiting while a callback still ran.)
                        active_iocp_operations_.fetch_add(1, std::memory_order_acquire);

                        // RAII guard to ensure we decrement on all exit paths (including exceptions)
                        struct operation_guard {
                            std::atomic<int32_t>& counter;
                            
                            explicit operation_guard(std::atomic<int32_t>& c) : counter(c) {}
                            
                            ~operation_guard() {
                                counter.fetch_sub(1, std::memory_order_release);
                            }
                            
                            // Delete copy and move to satisfy Rule of 5
                            operation_guard(const operation_guard&) = delete;
                            operation_guard(operation_guard&&) = delete;
                            operation_guard& operator=(const operation_guard&) = delete;
                            operation_guard& operator=(operation_guard&&) = delete;
                        } guard{ active_iocp_operations_ };

                        auto result = true;
                        auto server_read = false;

                        std::lock_guard lock(lock_);

                        auto io_context = static_cast<per_io_context_t*>(povlp);

                        // While the server is shutting down we must still fully process each
                        // delivered completion -- decrement its outstanding-I/O count (via io_dec
                        // below) and release any heap per-I/O context it owns -- but must start no
                        // NEW work (no connect, no data-relay dispatch, no recv/send re-arm). Read
                        // this once and gate the new-work paths on it. The unconditional io_dec
                        // guard keeps outstanding_io_ balanced without a special early return.
                        const bool shutting_down = end_server_.load(std::memory_order_acquire);

                        // If this is the server socket's read operation
                        if (io_context == &server_io_context_)
                        {
                            // Server socket read operation complete
                            server_read = true;

                            if (status && num_bytes && !shutting_down)
                            {
                                do
                                {
                                    if (false == connect_to_remote_host(io_context))
                                    {
                                        result = false;
                                        break;
                                    }

                                    io_context->wsa_buf = packet_pool_->allocate(num_bytes);

                                    if (!io_context->wsa_buf)
                                    {
                                        result = false;
                                        break;
                                    }

                                    io_context->wsa_buf->len = num_bytes;
                                    memmove(io_context->wsa_buf->buf, server_receive_buffer_.data(), num_bytes);
                                } while (false);
                            }
                        }

                        // Balance the io_posted() done when a per-session overlapped op was
                        // posted. This completion is a real delivery -- success OR failure: an
                        // aborted recv/send flushed by close_client()'s CancelIoEx during teardown
                        // arrives here with status == false. It must therefore decrement the owning
                        // proxy socket's outstanding-I/O count exactly once on every exit path,
                        // independent of status/result and of whether we dispatch below; trapping
                        // the decrement inside "if (status && result)" would leak the count on every
                        // torn-down session and the socket would never become removable. Server-read
                        // completions ride server_io_context_, which no proxy socket ever counted, so
                        // they are excluded. The strong ref keeps the socket alive until decrement.
                        std::shared_ptr<T> completing_socket = server_read ? nullptr : io_context->proxy_socket_ptr;
                        struct io_dec_guard {
                            T* s;
                            explicit io_dec_guard(T* sock) : s(sock) {}
                            ~io_dec_guard() { if (s) s->io_completed(); }
                            io_dec_guard(const io_dec_guard&) = delete;
                            io_dec_guard(io_dec_guard&&) = delete;
                            io_dec_guard& operator=(const io_dec_guard&) = delete;
                            io_dec_guard& operator=(io_dec_guard&&) = delete;
                        } io_dec{ completing_socket.get() };

                        // The proxy socket may have released its self-reference during teardown; a
                        // late completion then finds null and is safely ignored.
                        if (auto proxy_socket = io_context->proxy_socket_ptr)
                        {
                            switch (io_context->io_operation)
                            {
                            // Reads (and the no-op negotiate handlers) run a handler that posts NEW
                            // overlapped I/O, so only dispatch them on a successful, non-teardown
                            // completion. On an aborted read (status == false) or during shutdown
                            // there is nothing to free -- the recv uses a member io_context -- so we
                            // just fall through to the io_dec decrement.
                            case proxy_io_operation::relay_io_read:
                                if (status && result && !shutting_down)
                                    proxy_socket->process_receive_buffer_complete(num_bytes, io_context);
                                break;

                            case proxy_io_operation::negotiate_io_read:
                                if (status && result && !shutting_down)
                                    proxy_socket->process_receive_negotiate_complete(num_bytes, io_context);
                                break;

                            case proxy_io_operation::negotiate_io_write:
                                if (status && result && !shutting_down)
                                    proxy_socket->process_send_negotiate_complete(num_bytes, io_context);
                                break;

                            // Writes and injects own a HEAP io_context (allocated per datagram via
                            // allocate_io_context / new). Their handler only releases that context
                            // (and its pooled packet) and posts no new I/O, so it MUST run on EVERY
                            // completion -- including an aborted one (status == false) flushed by
                            // close_client()'s CancelIoEx during runtime teardown or shutdown.
                            // Skipping it leaks the context and its buffer and keeps this socket
                            // pinned alive via the context's strong proxy_socket_ptr.
                            case proxy_io_operation::relay_io_write:
                                proxy_socket->process_send_buffer_complete(num_bytes, io_context);
                                break;

                            case proxy_io_operation::inject_io_write:
                                T::process_inject_buffer_complete(packet_pool_, io_context);
                                break;

                            default: break; // NOLINT(clang-diagnostic-covered-switch-default)
                            }
                        }

                        if (server_read)
                        {
                            // The server read context does not own a session; drop the strong
                            // reference taken in connect_to_remote_host so a finished session
                            // is not pinned alive until the next inbound datagram replaces it.
                            io_context->proxy_socket_ptr.reset();

                            DWORD flags = 0;

                            // Re-arm the server read. The completion this generates will be
                            // counted when it is dispatched (the fetch_add at the top of this
                            // lambda), so there is no separate counter bump here.
                            if (!end_server_)
                            {
                                if ((::WSARecvFrom(
                                    server_socket_,
                                    &server_recv_buf_,
                                    1,
                                    nullptr,
                                    &flags,
                                    reinterpret_cast<sockaddr*>(&recv_from_sa_),
                                    &recv_from_sa_size_,
                                    &server_io_context_,
                                    nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                                {
                                    result = false;
                                }
                            }
                        }

                        return result;
                   }); associate_status == true)
                {
                    completion_key_ = io_key;
                    DWORD flags = 0;

                    // Post the initial server read. Its completion is counted when dispatched
                    // (the fetch_add at the top of the completion lambda), so no bump here.
                    if ((::WSARecvFrom(
                        server_socket_,
                        &server_recv_buf_,
                        1,
                        nullptr,
                        &flags,
                        reinterpret_cast<sockaddr*>(&recv_from_sa_),
                        &recv_from_sa_size_,
                        &server_io_context_,
                        nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                   {
                        closesocket(server_socket_);
                        end_server_ = true;
                        return false;
                    }
                }
                else
                {
                    if (server_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
                    {
                        closesocket(server_socket_);
                    }

                    end_server_ = true;
                    return false;
                }
            }

            check_clients_thread_ = std::thread(&socks5_local_udp_proxy_server<T>::clear_thread, this);

            return true;
        }

        /**
         * @brief Stops the SOCKS5 local UDP proxy server and releases all resources.
         *
         * This method performs a graceful shutdown by:
         * 1. Setting the end_server_ flag to signal shutdown
         * 2. Closing the server socket, which causes the pending WSARecvFrom to complete with error
         * 3. Cancelling each proxy socket's pending I/O (close_client) so its posted operations abort
         * 4. Waiting for every proxy socket's overlapped I/O to drain (per-socket outstanding count)
         *    and for all IOCP callbacks to finish
         * 5. Releasing each socket's self-reference and clearing the map so the sockets destruct
         * 6. Joining background threads
         *
         * The IOCP thread pool itself is managed by io_completion_port and will be
         * properly shut down when the completion port is destroyed.
         */
        void stop()
        {
            if (end_server_ == true)
            {
                // already stopped
                return;
            }

            // Step 1: Signal shutdown - IOCP lambda will check this and exit
            end_server_ = true;

            // Step 2: Close server socket
            // This causes any pending WSARecvFrom to complete immediately with an error.
            // When IOCP threads wake up, they'll see end_server_ == true and return false.
            if (server_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
            {
                closesocket(server_socket_);
                server_socket_ = INVALID_SOCKET;
            }

            // NOTE: the IOCP handler stays registered until AFTER the drain below. The aborted
            // completions produced by close_client()'s CancelIoEx must still dispatch through it so
            // they release their heap contexts and decrement each socket's outstanding_io_;
            // unregistering here would drop those completions and the drain would never complete.

            // Step 3: Cancel every proxy socket's pending I/O so its posted operations complete
            // promptly (aborted) and stop pinning the socket. Keep the sockets in the map for now --
            // they must stay alive until their in-flight completions have drained. Simply clearing
            // the map does NOT destroy them: each socket's recv io_context holds a self-reference,
            // so the destructor would never run and the handle/armed recv would leak.
            {
                std::lock_guard lock(lock_);
                if (!proxy_sockets_.empty())
                {
                    NETLIB_INFO("Cancelling I/O on {} proxy sockets before draining", proxy_sockets_.size());
                    for (auto& entry : proxy_sockets_)
                    {
                        if (entry.second)
                            entry.second->close_client(); // idempotent: CancelIoEx + closesocket
                    }
                }
            }

            // Step 4: Wait until every proxy socket has drained all posted overlapped I/O (its
            // per-socket outstanding count reaches zero) AND no IOCP callback is still running.
            // The handler is still registered, so close_client()'s aborted completions dispatch,
            // release their heap contexts, and the io_dec guard decrements the count. Gate on the
            // per-socket count -- not just active_iocp_operations_ -- because a cancelled completion
            // may still be queued (not yet dispatched) while active_iocp_operations_ momentarily
            // reads zero; releasing a socket's self-reference before that completion is processed
            // would free the io_context out from under it. Re-issue close_client() on any not-yet-
            // drained socket each pass so a session armed concurrently with shutdown (e.g. a
            // blocking connect that finished after end_server_ was set) is cancelled too.
            // Exponential backoff to avoid busy-waiting.
            using namespace std::chrono_literals;
            int wait_iterations = 0;
            bool drained_ok = false;

            while (true)
            {
                bool drained = true;
                {
                    std::lock_guard lock(lock_);
                    for (auto& entry : proxy_sockets_)
                    {
                        if (entry.second && entry.second->outstanding_io() != 0)
                        {
                            drained = false;
                            entry.second->close_client(); // idempotent; cancels late-armed sessions
                        }
                    }
                }

                if (drained && active_iocp_operations_.load(std::memory_order_acquire) == 0)
                {
                    drained_ok = true;
                    break;
                }

                if (constexpr int max_wait_iterations = 100; ++wait_iterations > max_wait_iterations)
                {
                    NETLIB_ERROR("Timeout waiting for proxy socket I/O to drain (active operations: {}); "
                        "leaving sessions pinned to avoid freeing in-flight io_contexts",
                        active_iocp_operations_.load(std::memory_order_relaxed));
                    break;
                }

                // Exponential backoff: 1ms, 2ms, 4ms, 8ms, ... up to 100ms
                const auto wait_time = std::min(1ms * (1 << std::min(wait_iterations / 10, 6)), 100ms);
                std::this_thread::sleep_for(wait_time);
            }

            // Step 4b: Regardless of how the drain loop exited, make sure no IOCP callback is still
            // executing before we proceed. A worker inside the completion lambda has captured `this`
            // (it touches lock_, end_server_, packet_pool_, server_io_context_ and decrements
            // active_iocp_operations_ on the way out), so unregistering the handler and returning
            // from stop() while active_iocp_operations_ > 0 risks a use-after-free of the server if
            // the object is then destroyed. On the happy path this is already zero (it is part of
            // the break condition above); on the timeout path we still wait here. Lambdas are
            // bounded work, so this reliably reaches zero; bound it as a last resort.
            for (int active_wait = 0;
                 active_iocp_operations_.load(std::memory_order_acquire) != 0;
                 ++active_wait)
            {
                if (active_wait > 200)
                {
                    NETLIB_ERROR("IOCP callbacks still active ({}) after drain; proceeding may be unsafe",
                        active_iocp_operations_.load(std::memory_order_relaxed));
                    break;
                }
                std::this_thread::sleep_for(std::min(1ms * (1 << std::min(active_wait / 10, 6)), 100ms));
            }

            // Step 5: All completions have now been processed (or we timed out), so unregister the
            // IOCP handler -- no further completion will dispatch into this server.
            if (completion_key_ != 0)
            {
                (void)completion_port_.unregister_handler(completion_key_);
                completion_key_ = 0;
            }

            // Step 6: Only if the drain completed do we break each socket's self-reference and clear
            // the map so the sockets (and their already-released heap I/O contexts) destruct. If the
            // drain timed out, some overlapped op is still outstanding; releasing/clearing now would
            // free an io_context that a still-queued completion could dereference, so we deliberately
            // leak those sessions instead (a bounded, shutdown-only leak) rather than risk a UAF.
            if (drained_ok)
            {
                std::lock_guard lock(lock_);
                for (auto& entry : proxy_sockets_)
                {
                    if (entry.second)
                        entry.second->release_self_reference();
                }
                proxy_sockets_.clear();
            }

            // Step 7: Join background threads
            if (proxy_server_.joinable())
            {
                proxy_server_.join();
            }

            if (check_clients_thread_.joinable())
            {
                check_clients_thread_.join();
            }
        }

    private:
        /**
         * @brief Queries remote host information for outgoing connection by local peer IP address and port.
         *
         * This method uses the configured query_remote_peer_ function to determine the remote peer
         * (address, port, and negotiation context) for a given local peer address and UDP port.
         * If no query function is set, it returns a default-constructed tuple with empty address,
         * port 0, and nullptr negotiation context.
         *
         * @param accepted_peer_address The local peer's IP address.
         * @param accepted_peer_port The local peer's UDP port.
         * @return Tuple containing the remote address, remote port, and a unique pointer to the negotiation context.
         */
        std::tuple<address_type_t, uint16_t, std::unique_ptr<negotiate_context_t>> get_remote_peer(
            address_type_t accepted_peer_address, unsigned short accepted_peer_port) const
        {
            if (query_remote_peer_)
            {
                return query_remote_peer_(accepted_peer_address, accepted_peer_port);
            }

            return std::make_tuple(address_type_t{}, 0, nullptr);
        }

        /**
         * @brief Creates and binds the UDP server socket for the proxy server.
         *
         * This method creates a UDP socket (IPv4 or IPv6 depending on address_type_t::af_type),
         * binds it to the specified proxy_port_, and updates proxy_port_ if it was initially zero.
         * On failure, the socket is closed and INVALID_SOCKET is set.
         *
         * @return True if the socket was successfully created and bound, false otherwise.
         */
        bool create_server_socket()
        {
            server_socket_ = WSASocket(address_type_t::af_type, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                WSA_FLAG_OVERLAPPED);

            if (server_socket_ == static_cast<SOCKET>(INVALID_SOCKET))
            {
                return false;
            }

            if constexpr (address_type_t::af_type == AF_INET)
            {
                sockaddr_in service{};
                service.sin_family = address_type_t::af_type;
                service.sin_port = htons(proxy_port_);
                service.sin_addr.s_addr = htonl(INADDR_ANY);

                if (const auto status = bind(server_socket_, reinterpret_cast<SOCKADDR*>(&service), sizeof(service));
                    status == SOCKET_ERROR)
                {
                    closesocket(server_socket_);
                    server_socket_ = INVALID_SOCKET;
                    return false;
                }

                if (proxy_port_ == 0)
                {
                    int name_length = sizeof(service);
                    if (0 == getsockname(server_socket_, reinterpret_cast<SOCKADDR*>(&service), &name_length))
                    {
                        proxy_port_ = ntohs(service.sin_port);
                    }
                    else
                    {
                        closesocket(server_socket_);
                        server_socket_ = INVALID_SOCKET;
                        return false;
                    }
                }
            }
            else
            {
                sockaddr_in6 service;
                service.sin6_family = address_type_t::af_type;
                service.sin6_port = htons(proxy_port_);
                service.sin6_flowinfo = 0;
                service.sin6_addr = in6addr_any;
                service.sin6_scope_id = 0;

                if (const auto status = bind(server_socket_, reinterpret_cast<SOCKADDR*>(&service), sizeof(service));
                    status == SOCKET_ERROR)
                {
                    closesocket(server_socket_);
                    server_socket_ = INVALID_SOCKET;
                    return false;
                }

                if (proxy_port_ == 0)
                {
                    int name_length = sizeof(service);
                    if (0 == getsockname(server_socket_, reinterpret_cast<SOCKADDR*>(&service), &name_length))
                    {
                        proxy_port_ = ntohs(service.sin6_port);
                    }
                    else
                    {
                        closesocket(server_socket_);
                        server_socket_ = INVALID_SOCKET;
                        return false;
                    }
                }
            }

            return true;
        }

        /**
         * @brief Establishes a TCP connection to the specified SOCKS5 proxy server.
         *
         * This method creates a non-blocking TCP socket (IPv4 or IPv6 depending on address_type_t::af_type),
         * binds it to a local ephemeral port, and connects it to the given SOCKS5 proxy server address and port.
         * On failure, the socket is closed and INVALID_SOCKET is returned.
         *
         * @param socks_server_address The address of the SOCKS5 proxy server to connect to.
         * @param socks_server_port The port of the SOCKS5 proxy server.
         * @return A connected TCP SOCKET handle, or INVALID_SOCKET on failure.
         */
        SOCKET connect_to_socks5_proxy(address_type_t socks_server_address, const uint16_t socks_server_port)
        {
            auto socks_tcp_socket = WSASocket(address_type_t::af_type, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                WSA_FLAG_OVERLAPPED);

            if (socks_tcp_socket == INVALID_SOCKET)
            {
                return INVALID_SOCKET;
            }

            // Set socket timeouts to prevent indefinite blocking in recv/send calls
            // This prevents deadlock where IOCP worker holds lock_ while blocked on network I/O
            constexpr DWORD timeout_ms = 5000; // 5 second timeout
            if (setsockopt(socks_tcp_socket, SOL_SOCKET, SO_RCVTIMEO, 
                          reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms)) == SOCKET_ERROR)
            {
                NETLIB_WARNING("Failed to set socket receive timeout: {}", WSAGetLastError());
            }
            
            if (setsockopt(socks_tcp_socket, SOL_SOCKET, SO_SNDTIMEO, 
                          reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms)) == SOCKET_ERROR)
            {
                NETLIB_WARNING("Failed to set socket send timeout: {}", WSAGetLastError());
            }

            if constexpr (address_type_t::af_type == AF_INET)
            {
                sockaddr_in sa_local{};
                sa_local.sin_family = address_type_t::af_type;
                sa_local.sin_port = htons(0);
                sa_local.sin_addr.s_addr = htonl(INADDR_ANY);

                if (const auto status = bind(socks_tcp_socket, reinterpret_cast<sockaddr*>(&sa_local), sizeof(sa_local))
                    ; status == SOCKET_ERROR)
                {
                    closesocket(socks_tcp_socket);
                    return INVALID_SOCKET;
                }
            }
            else
            {
                // Allow this AF_INET6 upstream control socket to reach IPv4 SOCKS5
                // servers via IPv4-mapped addresses (e.g. ::ffff:127.0.0.1) by
                // clearing IPV6_V6ONLY so the dual-stack socket accepts both families.
                DWORD v6_only = 0;
                if (setsockopt(socks_tcp_socket, IPPROTO_IPV6, IPV6_V6ONLY,
                    reinterpret_cast<const char*>(&v6_only), sizeof(v6_only)) == SOCKET_ERROR)
                {
                    NETLIB_WARNING("Failed to clear IPV6_V6ONLY on SOCKS5 control socket: {}", WSAGetLastError());
                }

                sockaddr_in6 sa_local{};
                sa_local.sin6_family = address_type_t::af_type;
                sa_local.sin6_port = htons(0);
                sa_local.sin6_addr = in6addr_any;

                if (const auto status = bind(socks_tcp_socket, reinterpret_cast<sockaddr*>(&sa_local), sizeof(sa_local))
                    ; status == SOCKET_ERROR)
                {
                    closesocket(socks_tcp_socket);
                    return INVALID_SOCKET;
                }
            }

            // connect to server
            if constexpr (address_type_t::af_type == AF_INET)
            {
                sockaddr_in sa_service{};
                sa_service.sin_family = address_type_t::af_type;
                sa_service.sin_addr = socks_server_address;
                sa_service.sin_port = htons(socks_server_port);

                if (!connect_with_timeout(socks_tcp_socket, reinterpret_cast<SOCKADDR*>(&sa_service),
                    sizeof(sa_service), 5000))
                {
                    closesocket(socks_tcp_socket);
                    return INVALID_SOCKET;
                }
            }
            else
            {
                sockaddr_in6 sa_service{};
                sa_service.sin6_family = address_type_t::af_type;
                sa_service.sin6_addr = socks_server_address;
                sa_service.sin6_port = htons(socks_server_port);

                if (!connect_with_timeout(socks_tcp_socket, reinterpret_cast<SOCKADDR*>(&sa_service),
                    sizeof(sa_service), 5000))
                {
                    closesocket(socks_tcp_socket);
                    return INVALID_SOCKET;
                }
            }

            return socks_tcp_socket;
        }

        /**
         * @brief Connects a socket with a bounded timeout.
         *
         * A plain blocking connect() is not bounded by SO_*TIMEO and can hang for the OS
         * default TCP connect timeout (~21s) on a black-holed SOCKS5 server while this thread
         * holds the server lock, stalling all UDP relay. This switches the socket to
         * non-blocking, issues the connect, and waits with select() up to timeout_ms, then
         * restores blocking mode for the subsequent SO_*TIMEO-bounded send/recv.
         *
         * @return true if the connection completed within the timeout, false otherwise.
         */
        static bool connect_with_timeout(const SOCKET s, const sockaddr* const addr, const int addr_len,
                                         const DWORD timeout_ms) noexcept
        {
            u_long non_blocking = 1;
            if (ioctlsocket(s, FIONBIO, &non_blocking) == SOCKET_ERROR)
                return false;

            auto succeeded = false;
            if (connect(s, addr, addr_len) == 0)
            {
                succeeded = true;
            }
            else if (WSAGetLastError() == WSAEWOULDBLOCK)
            {
                fd_set write_set;
                FD_ZERO(&write_set);
                FD_SET(s, &write_set);
                fd_set error_set;
                FD_ZERO(&error_set);
                FD_SET(s, &error_set);

                timeval tv{};
                tv.tv_sec = static_cast<long>(timeout_ms / 1000);
                tv.tv_usec = static_cast<long>((timeout_ms % 1000) * 1000);

                if (const auto sel = select(0, nullptr, &write_set, &error_set, &tv);
                    sel > 0 && FD_ISSET(s, &write_set))
                {
                    auto so_error = 0;
                    auto len = static_cast<int>(sizeof(so_error));
                    if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &len) == 0 &&
                        so_error == 0)
                    {
                        succeeded = true;
                    }
                }
            }

            // Restore blocking mode for the subsequent SO_*TIMEO-bounded send/recv. If the
            // socket connected but cannot be put back into blocking mode, fail the connect so
            // the caller closes it rather than issuing blocking send/recv on a still-non-blocking
            // socket (which would spuriously return WSAEWOULDBLOCK and break negotiation).
            u_long blocking = 0;
            if (ioctlsocket(s, FIONBIO, &blocking) == SOCKET_ERROR)
                return false;
            return succeeded;
        }

        /**
         * @brief Performs SOCKS5 negotiation and sends the UDP ASSOCIATE command.
         *
         * This method negotiates authentication with the SOCKS5 proxy server over the provided TCP socket,
         * using either "NO AUTHENTICATION REQUIRED" or "USERNAME/PASSWORD" (RFC 1929) as needed.
         * If authentication succeeds, it sends a UDP ASSOCIATE command to the proxy and retrieves the
         * UDP relay endpoint assigned by the proxy for relaying UDP packets.
         *
         * @param socks_tcp_socket The connected TCP socket to the SOCKS5 proxy server.
         * @param negotiate_ctx Unique pointer to the negotiation context, containing optional credentials.
         * @return The UDP relay endpoint assigned by the SOCKS5 proxy, or std::nullopt on failure.
         */
        [[nodiscard]] std::optional<net::ip_endpoint<address_type_t>> associate_to_socks5_proxy(
            const SOCKET socks_tcp_socket,
            const address_type_t socks_server_address,
            std::unique_ptr<negotiate_context_t>&
            negotiate_ctx) const noexcept
        {
            using namespace std::string_literals;

            socks5_ident_req<2> ident_req{};
            socks5_ident_resp ident_resp{};

            auto socks5_ident_req_size = sizeof(ident_req);

            ident_req.methods[0] = 0x0; // RFC 1928: X'00' NO AUTHENTICATION REQUIRED
            ident_req.methods[1] = 0x2; // RFC 1928: X'02' USERNAME/PASSWORD

            // Don't suggest username/password option if not provided
            if (!negotiate_ctx->socks5_username.has_value())
            {
                ident_req.number_of_methods = 1;
                socks5_ident_req_size = sizeof(socks5_ident_req<1>);
            }

            auto result = send(socks_tcp_socket, reinterpret_cast<const char*>(&ident_req),
                static_cast<int>(socks5_ident_req_size), 0);
            if (result == SOCKET_ERROR)
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: Failed to send socks5_ident_req: {}",
                    WSAGetLastError());
                return {};
            }

            result = recv(socks_tcp_socket, reinterpret_cast<char*>(&ident_resp), sizeof(ident_resp), 0);
            if (result == SOCKET_ERROR)
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: Failed to receive socks5_ident_resp: {}",
                    WSAGetLastError());
                return {};
            }

            if ((ident_resp.version != 5) ||
                (ident_resp.method == 0xFF))
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: SOCKS5 authentication has failed");
                return {};
            }

            if (ident_resp.method == 0x2)
            {
                if (!negotiate_ctx->socks5_username.has_value())
                {
                    NETLIB_INFO(
                        "[SOCKS5]: associate_to_socks5_proxy: RFC 1928: X'02' USERNAME/PASSWORD is chosen but USERNAME is not provided");
                    return {};
                }

                if (negotiate_ctx->socks5_username.value().length() > socks5_username_max_length || 
                    negotiate_ctx->socks5_username.value().length() < 1)
                {
                    NETLIB_INFO(
                        "[SOCKS5]: associate_to_socks5_proxy: RFC 1928: X'02' USERNAME/PASSWORD is chosen but USERNAME exceeds maximum possible length");
                    return {};
                }

                if (!negotiate_ctx->socks5_password.has_value())
                {
                    NETLIB_INFO(
                        "[SOCKS5]: associate_to_socks5_proxy: RFC 1928: X'02' USERNAME/PASSWORD is chosen but PASSWORD is not provided");
                    return {};
                }

                if (negotiate_ctx->socks5_password.value().length() > socks5_username_max_length || 
                    negotiate_ctx->socks5_password.value().length() < 1)
                {
                    NETLIB_INFO(
                        "[SOCKS5]: associate_to_socks5_proxy: RFC 1928: X'02' USERNAME/PASSWORD is chosen but PASSWORD exceeds maximum possible length");
                    return {};
                }

                const socks5_username_auth auth_req(
                    negotiate_ctx->socks5_username.value(),
                    negotiate_ctx->socks5_password.value()
                );

                result = send(socks_tcp_socket, reinterpret_cast<const char*>(&auth_req),
                    3 + static_cast<int>(negotiate_ctx->socks5_username.value().length()) + 
                    static_cast<int>(negotiate_ctx->socks5_password.value().length()), 0);
                if (result == SOCKET_ERROR)
                {
                    NETLIB_INFO(
                        "[SOCKS5]: associate_to_socks5_proxy: Failed to send socks5_username_auth: {}",
                        WSAGetLastError());
                    return {};
                }

                result = recv(socks_tcp_socket, reinterpret_cast<char*>(&ident_resp), sizeof(ident_resp), 0);
                if (result == SOCKET_ERROR)
                {
                    NETLIB_INFO(
                        "[SOCKS5]: associate_to_socks5_proxy: Failed to receive socks5_ident_resp: {}",
                        WSAGetLastError());
                    return {};
                }

                if (ident_resp.method != 0x0)
                {
                    NETLIB_INFO(
                        "[SOCKS5]: associate_to_socks5_proxy: USERNAME/PASSWORD authentication has failed!");
                    return {};
                }

                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: USERNAME/PASSWORD authentication SUCCESS");
            }

            // Build the UDP ASSOCIATE request. DST.ADDR/DST.PORT only advertise the
            // address the client expects to send datagrams from; we advertise the
            // unspecified address. The ATYP must match the family actually used on the
            // wire: the IPv6 proxy instance reaches the (IPv4) SOCKS5 server through an
            // IPv4-mapped upstream, so an IPv4-only server would reject an ATYP=4 request.
            // Send ATYP=1 with a zero IPv4 address whenever the upstream is IPv4 or
            // IPv4-mapped, and ATYP=4 only for a genuine IPv6 upstream.
            unsigned char associate_req_buf[4 + sizeof(in6_addr) + sizeof(unsigned short)]{};
            associate_req_buf[0] = 5; // VER
            associate_req_buf[1] = 3; // CMD = UDP ASSOCIATE
            associate_req_buf[2] = 0; // RSV
            int associate_req_len;
            if constexpr (address_type_t::af_type == AF_INET)
            {
                associate_req_buf[3] = 1; // ATYP = IPv4
                associate_req_len = 4 + 4 + static_cast<int>(sizeof(unsigned short));
            }
            else
            {
                if (IN6_IS_ADDR_V4MAPPED(static_cast<const in6_addr*>(&socks_server_address)))
                {
                    associate_req_buf[3] = 1; // ATYP = IPv4 (IPv4-mapped upstream)
                    associate_req_len = 4 + 4 + static_cast<int>(sizeof(unsigned short));
                }
                else
                {
                    associate_req_buf[3] = 4; // ATYP = IPv6 (genuine IPv6 upstream)
                    associate_req_len = 4 + static_cast<int>(sizeof(in6_addr)) + static_cast<int>(sizeof(unsigned short));
                }
            }
            result = send(socks_tcp_socket, reinterpret_cast<const char*>(associate_req_buf), associate_req_len, 0);
            if (result == SOCKET_ERROR)
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: Failed to send SOCKS5 ASSOCIATE request: {}",
                    WSAGetLastError());
                return {};
            }

            // Read and validate the SOCKS5 UDP ASSOCIATE reply. The reply's BND.ADDR
            // family (ATYP) is selected by the SERVER and is independent of the address
            // family this proxy instance uses: an IPv6 proxy instance reaches the
            // configured (IPv4) SOCKS5 server through an IPv4-mapped upstream, so the
            // server typically replies with ATYP=1 and a 4-byte BND.ADDR. Parsing the
            // reply as a fixed-size socks5_resp<address_type_t> (which has a 16-byte
            // BND.ADDR for IPv6) would then read BND.PORT from the wrong offset and
            // hand back a bogus relay port. Parse the 4-byte reply prefix, then read
            // exactly the bytes implied by the returned ATYP and take BND.PORT from the
            // correct position so the relay port is family-agnostic and correct.

            // Blocking read of exactly 'len' bytes (recv() may return short reads on a
            // stream socket); returns false on error or premature close.
            const auto recv_exact = [](const SOCKET s, void* const buffer, const int len) -> bool
            {
                // Bound the TOTAL time spent assembling these bytes, not just each recv().
                // SO_RCVTIMEO is a per-call timeout, so a server that drips one byte just
                // under it could otherwise keep this loop (and the IOCP worker that holds
                // the server lock) alive for timeout * byte-count. Hold a single absolute
                // deadline, shrink the receive timeout toward it on every iteration, and
                // restore the socket's default timeout before returning.
                constexpr DWORD total_timeout_ms = 5000;

                // Save the socket's configured receive timeout and restore exactly that on
                // every exit path, since the loop below temporarily shrinks SO_RCVTIMEO
                // toward the deadline (leaving a tiny/stale value on the shared control
                // socket would otherwise affect any later read on it).
                DWORD original_timeout = total_timeout_ms;
                int original_timeout_size = static_cast<int>(sizeof(original_timeout));
                getsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                    reinterpret_cast<char*>(&original_timeout), &original_timeout_size);

                const auto restore_timeout = [s, original_timeout]
                {
                    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                        reinterpret_cast<const char*>(&original_timeout), sizeof(original_timeout));
                };

                auto* const bytes = static_cast<char*>(buffer);
                const auto deadline = GetTickCount64() + total_timeout_ms;
                int received = 0;
                while (received < len)
                {
                    const auto now = GetTickCount64();
                    if (now >= deadline)
                    {
                        restore_timeout();
                        return false;
                    }

                    auto remaining_ms = static_cast<DWORD>(deadline - now);
                    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                        reinterpret_cast<const char*>(&remaining_ms), sizeof(remaining_ms)) == SOCKET_ERROR)
                    {
                        restore_timeout();
                        return false;
                    }

                    const auto n = recv(s, bytes + received, len - received, 0);
                    if (n == SOCKET_ERROR || n == 0)
                    {
                        restore_timeout();
                        return false;
                    }
                    received += n;
                }

                restore_timeout();
                return true;
            };

            // Fixed 4-byte reply prefix: VER, REP, RSV, ATYP.
            struct socks5_resp_prefix
            {
                unsigned char version;
                unsigned char reply;
                unsigned char reserved;
                unsigned char address_type;
            } resp_prefix{};

            if (!recv_exact(socks_tcp_socket, &resp_prefix, sizeof(resp_prefix)))
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: Failed to receive SOCKS5 ASSOCIATE reply header");
                return {};
            }

            if ((resp_prefix.version != 5) ||
                (resp_prefix.reply != 0))
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: SOCKS5 ASSOCIATE has failed");
                return {};
            }

            // Determine BND.ADDR length from the server-selected ATYP. For ATYP=3
            // (domain) the first byte carries the name length.
            int bnd_addr_len;
            switch (resp_prefix.address_type)
            {
            case 1: // IPv4
                bnd_addr_len = 4;
                break;
            case 4: // IPv6
                bnd_addr_len = 16;
                break;
            case 3: // domain name
                {
                    unsigned char domain_len = 0;
                    if (!recv_exact(socks_tcp_socket, &domain_len, sizeof(domain_len)))
                    {
                        NETLIB_INFO(
                            "[SOCKS5]: associate_to_socks5_proxy: Failed to receive BND.ADDR domain length");
                        return {};
                    }
                    bnd_addr_len = domain_len;
                }
                break;
            default:
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: Unexpected BND.ADDR type {} in ASSOCIATE reply",
                    resp_prefix.address_type);
                return {};
            }

            // Read BND.ADDR followed by the 2-byte BND.PORT. The buffer is sized for the
            // largest possible BND.ADDR (a 255-byte domain) plus the port.
            unsigned char bnd_addr_and_port[255 + sizeof(unsigned short)]{};
            if (!recv_exact(socks_tcp_socket, bnd_addr_and_port,
                bnd_addr_len + static_cast<int>(sizeof(unsigned short))))
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: Failed to receive BND.ADDR/BND.PORT");
                return {};
            }

            // BND.PORT immediately follows BND.ADDR, in network byte order. Assembling
            // the two big-endian bytes directly yields the host-order port value.
            const auto bind_port = static_cast<uint16_t>(
                (static_cast<uint16_t>(bnd_addr_and_port[bnd_addr_len]) << 8) |
                static_cast<uint16_t>(bnd_addr_and_port[bnd_addr_len + 1]));

            // The UDP relay endpoint is, in every deployment ProxiFyre supports, the same
            // host as the SOCKS5 server we connected the control socket to. Servers
            // frequently report a BND.ADDR that is only meaningful from their own vantage
            // point (0.0.0.0, 127.0.0.1, or an internal/NAT address), so honoring it
            // verbatim can aim the relay at an address the client cannot reach -- and it
            // would also turn a server-supplied address into a connect() target. We
            // therefore relay to the address we already reached over the control
            // connection (socks_server_address -- the IPv4-mapped upstream for the IPv6
            // instance) and take only BND.PORT from the reply. BND.PORT was parsed at the
            // family-correct offset above, so the relay port is correct regardless of the
            // ATYP the server selected, and no blocking DNS lookup is needed for an
            // ATYP=3 (domain) reply.
            NETLIB_INFO(
                "[SOCKS5]: associate_to_socks5_proxy: SOCKS5 ASSOCIATE SUCCESS endpoint: {}:{}",
                socks_server_address,
                bind_port);

            return net::ip_endpoint<address_type_t>{ socks_server_address, bind_port };
        }

        /**
         * @brief Establishes a UDP relay session to a remote host through a SOCKS5 proxy.
         *
         * This method is responsible for setting up a UDP relay for a new client connection.
         * It determines the local peer's address and port from the last received UDP packet,
         * checks if a proxy socket for this client already exists, and if not:
         *   - Resolves the remote SOCKS5 proxy address, port, and negotiation context.
         *   - Establishes a TCP connection to the SOCKS5 proxy and performs authentication/negotiation.
         *   - Issues a UDP ASSOCIATE command to the proxy and retrieves the assigned UDP port.
         *   - Creates and binds a UDP socket for relaying packets to the proxy.
         *   - Connects the UDP socket to the proxy and stores the session in the proxy_sockets_ map.
         *   - Associates the new proxy socket with the I/O completion port and starts it.
         *
         * If any step fails, all resources are cleaned up and the method returns false.
         *
         * @param io_context Pointer to the per-I/O context structure for the current operation.
         *                   On success, its proxy_socket_ptr is set to the active proxy socket.
         * @return True if the relay session was established or already exists, false on failure.
         */
        bool connect_to_remote_host(per_io_context_t* io_context)
        {
            uint16_t local_peer_port = 0;
            address_type_t local_peer_address{};

            if constexpr (address_type_t::af_type == AF_INET)
            {
                local_peer_port = ntohs(reinterpret_cast<sockaddr_in*>(&recv_from_sa_)->sin_port);
                local_peer_address = address_type_t(reinterpret_cast<sockaddr_in*>(&recv_from_sa_)->sin_addr);
            }
            else if constexpr (address_type_t::af_type == AF_INET6)
            {
                local_peer_port = ntohs(reinterpret_cast<sockaddr_in6*>(&recv_from_sa_)->sin6_port);
                local_peer_address = address_type_t(reinterpret_cast<sockaddr_in6*>(&recv_from_sa_)->sin6_addr);
            }
            else
            {
                static_assert(false_v<T>, "Unsupported address family used as a template parameter!");
            }

            // Lookup an existing proxy socket
            if (auto it = proxy_sockets_.find(local_peer_port); it != proxy_sockets_.end())
            {
                // Set to shared_ptr instead of raw pointer
                io_context->proxy_socket_ptr = it->second;
                return true;
            }

            auto [remote_address, remote_port, negotiate_ctx] =
                get_remote_peer(local_peer_address, local_peer_port);

            NETLIB_DEBUG(
                "connect_to_remote_host: Connect to SOCKS5 proxy and send ASSOCIATE command: {}:{}",
                remote_address,
                remote_port);

            auto socks5_tcp_socket = connect_to_socks5_proxy(remote_address, remote_port);
            if (socks5_tcp_socket == INVALID_SOCKET)
            {
                NETLIB_DEBUG(
                    "connect_to_remote_host: Failed to connect to SOCKS5 proxy: {}:{}",
                    remote_address,
                    remote_port);
                return false;
            }

            auto udp_endpoint = associate_to_socks5_proxy(socks5_tcp_socket, remote_address, negotiate_ctx);
            if (!udp_endpoint.has_value())
            {
                NETLIB_DEBUG(
                    "connect_to_remote_host: ASSOCIATE command has failed: {}:{}",
                    remote_address,
                    remote_port);

                closesocket(socks5_tcp_socket);
                return false;
            }

            NETLIB_DEBUG(
                "connect_to_remote_host: UDP connect: {}:{}",
                udp_endpoint->ip,
                udp_endpoint->port);

            auto remote_socket = WSASocket(address_type_t::af_type, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                WSA_FLAG_OVERLAPPED);

            if (remote_socket == INVALID_SOCKET)
            {
                NETLIB_DEBUG(
                    "connect_to_remote_host: Failed to create UDP socket: {}",
                    WSAGetLastError());
                closesocket(socks5_tcp_socket);
                return false;
            }

            if constexpr (address_type_t::af_type == AF_INET)
            {
                sockaddr_in sa_local{};
                sa_local.sin_family = address_type_t::af_type;
                sa_local.sin_port = htons(0);
                sa_local.sin_addr.s_addr = htonl(INADDR_ANY);

                if (const auto status = bind(remote_socket, reinterpret_cast<sockaddr*>(&sa_local), sizeof(sa_local));
                    status == SOCKET_ERROR)
                {
                    closesocket(remote_socket);
                    closesocket(socks5_tcp_socket);
                    NETLIB_DEBUG(
                        "connect_to_remote_host: Failed to bind UDP socket: {}",
                        WSAGetLastError());
                    return false;
                }
            }
            else
            {
                // Dual-stack the AF_INET6 UDP relay socket so it can reach an IPv4
                // SOCKS5 server's UDP relay endpoint via its IPv4-mapped address
                // (the relay address mirrors the configured control address).
                DWORD v6_only = 0;
                if (setsockopt(remote_socket, IPPROTO_IPV6, IPV6_V6ONLY,
                    reinterpret_cast<const char*>(&v6_only), sizeof(v6_only)) == SOCKET_ERROR)
                {
                    NETLIB_WARNING("connect_to_remote_host: Failed to clear IPV6_V6ONLY on UDP relay socket: {}",
                        WSAGetLastError());
                }

                sockaddr_in6 sa_local{};
                sa_local.sin6_family = address_type_t::af_type;
                sa_local.sin6_port = htons(0);
                sa_local.sin6_addr = in6addr_any;

                if (const auto status = bind(remote_socket, reinterpret_cast<sockaddr*>(&sa_local), sizeof(sa_local));
                    status == SOCKET_ERROR)
                {
                    closesocket(remote_socket);
                    closesocket(socks5_tcp_socket);
                    NETLIB_DEBUG(
                        "connect_to_remote_host: Failed to bind UDP socket: {}",
                        WSAGetLastError());
                    return false;
                }
            }

            // connect to server
            if constexpr (address_type_t::af_type == AF_INET)
            {
                sockaddr_in sa_service{};
                sa_service.sin_family = address_type_t::af_type;
                sa_service.sin_addr = udp_endpoint->ip;
                sa_service.sin_port = htons(udp_endpoint->port);

                if (connect(remote_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) ==
                    SOCKET_ERROR)
                {
                    closesocket(remote_socket);
                    closesocket(socks5_tcp_socket);
                    NETLIB_DEBUG(
                        "connect_to_remote_host: Failed to connect UDP socket: {}",
                        WSAGetLastError());
                    return false;
                }
            }
            else
            {
                sockaddr_in6 sa_service{};
                sa_service.sin6_family = address_type_t::af_type;
                sa_service.sin6_addr = udp_endpoint->ip;
                sa_service.sin6_port = htons(udp_endpoint->port);

                if (connect(remote_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) ==
                    SOCKET_ERROR)
                {
                    closesocket(remote_socket);
                    closesocket(socks5_tcp_socket);
                    NETLIB_DEBUG(
                        "connect_to_remote_host: Failed to connect UDP socket: {}",
                        WSAGetLastError());
                    return false;
                }
            }

            auto [it, result] = proxy_sockets_.emplace(local_peer_port,
                std::make_shared<T>(
                    socks5_tcp_socket, packet_pool_, server_socket_,
                    recv_from_sa_, remote_socket, udp_endpoint->ip,
                    udp_endpoint->port, std::move(negotiate_ctx),
                    logger::log_level_, logger::log_stream_));

            if (result)
            {
                try
                {
                    // Initialize I/O contexts with shared_ptr
                    it->second->initialize_io_contexts();

                    // Now safe to associate and start
                    it->second->associate_to_completion_port(completion_key_, completion_port_);
                    it->second->start();

                    // Set the context pointer to the shared_ptr
                    io_context->proxy_socket_ptr = it->second;
                }
                catch (const std::exception& e)
                {
                    NETLIB_DEBUG(
                        "connect_to_remote_host: Failed to initialize proxy socket for: {}:{} ({})",
                        udp_endpoint->ip,
                        udp_endpoint->port,
                        e.what());
                    // Remove from map - the shared_ptr destructor will close the sockets
                    // that were transferred to T's constructor
                    proxy_sockets_.erase(it);
                    return false;
                }
                catch (...)
                {
                    NETLIB_DEBUG(
                        "connect_to_remote_host: Failed to initialize proxy socket for: {}:{} (unknown exception)",
                        udp_endpoint->ip,
                        udp_endpoint->port);
                    // Remove from map - the shared_ptr destructor will close the sockets
                    proxy_sockets_.erase(it);
                    return false;
                }
            }
            else
            {
                closesocket(remote_socket);
                closesocket(socks5_tcp_socket);
                NETLIB_DEBUG(
                    "connect_to_remote_host: Failed to create proxy socket for: {}:{}",
                    udp_endpoint->ip,
                    udp_endpoint->port);
                return false;
            }

            return result;
        }

        /**
         * @brief Periodically cleans up inactive or closed proxy socket sessions.
         *
         * This thread routine runs in the background while the server is active. It acquires a lock
         * on the proxy_sockets_ map, iterates through all active proxy socket sessions, and removes
         * any that are ready for removal (e.g., due to client disconnect or error). The cleanup
         * operation is performed once per second to minimize resource usage and ensure timely
         * release of unused sockets.
         *
         * The thread exits automatically when the server is stopped (end_server_ is set to true).
         */
        void clear_thread()
        {
            while (end_server_ == false)
            {
                {
                    std::lock_guard lock(lock_);

                    for (auto it = proxy_sockets_.begin(); it != proxy_sockets_.end();)
                    {
                        if (it->second->is_ready_for_removal())
                        {
                            proxy_sockets_.erase(it++);
                        }
                        else
                        {
                            ++it;
                        }
                    }
                }

                using namespace std::chrono_literals;
                std::this_thread::sleep_for(1000ms);
            }
        }
    };
}
