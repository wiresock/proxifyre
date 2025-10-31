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
        using negotiate_context_t = T::negotiate_context_t;

        /**
         * @brief Address type alias.
         *
         * Alias for the address type defined by the proxy socket implementation (T).
         * Represents an IPv4 or IPv6 address, depending on the template parameter.
         */
        using address_type_t = T::address_type_t;

        /**
         * @brief Per-I/O context type alias.
         *
         * Alias for the per-I/O context type defined by the proxy socket implementation (T).
         * Used for managing asynchronous I/O operations.
         */
        using per_io_context_t = T::per_io_context_t;

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
         * Each entry represents a client session managed by the proxy server.
         */
        std::map<uint16_t, std::unique_ptr<T>> proxy_sockets_;

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
        winsys::io_completion_port& completion_port_;

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
        socks5_local_udp_proxy_server(const uint16_t proxy_port, winsys::io_completion_port& completion_port,
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
                        // RAII guard to ensure we decrement on all exit paths (including exceptions)
                        // Note: Counter was already incremented BEFORE the I/O operation was posted
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

                        // Check if server is shutting down
                        if (end_server_)
                            return false;

                        std::lock_guard lock(lock_);

                        auto io_context = static_cast<per_io_context_t*>(povlp);

                        // If this is the server socket's read operation
                        if (io_context == &server_io_context_)
                        {
                            // Server socket read operation complete
                            server_read = true;

                            if (status && num_bytes)
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

                        if (status && result)
                        {
                            switch (io_context->io_operation)
                            {
                            case proxy_io_operation::relay_io_read:
                                io_context->proxy_socket_ptr->process_receive_buffer_complete(num_bytes, io_context);
                                break;

                            case proxy_io_operation::relay_io_write:
                                io_context->proxy_socket_ptr->process_send_buffer_complete(num_bytes, io_context);
                                break;

                            case proxy_io_operation::negotiate_io_read:
                                io_context->proxy_socket_ptr->process_receive_negotiate_complete(num_bytes, io_context);
                                break;

                            case proxy_io_operation::negotiate_io_write:
                                io_context->proxy_socket_ptr->process_send_negotiate_complete(num_bytes, io_context);
                                break;

                            case proxy_io_operation::inject_io_write:
                                T::process_inject_buffer_complete(packet_pool_, io_context);
                                break;

                            default: break; // NOLINT(clang-diagnostic-covered-switch-default)
                            }
                        }

                        if (server_read)
                        {
                            DWORD flags = 0;

                            // Increment counter BEFORE posting the I/O operation
                            // This ensures stop() will wait for this operation to complete
                            if (!end_server_)
                            {
                                active_iocp_operations_.fetch_add(1, std::memory_order_acquire);

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
                                    // Failed to post I/O, decrement counter
                                    active_iocp_operations_.fetch_sub(1, std::memory_order_release);
                                    result = false;
                                }
                            }
                        }

                        return result;
                   }); associate_status == true)
                {
                    completion_key_ = io_key;
                    DWORD flags = 0;

                    // Increment counter BEFORE posting the initial I/O operation
                    active_iocp_operations_.fetch_add(1, std::memory_order_acquire);

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
                        // Failed to post initial I/O, decrement counter
                        active_iocp_operations_.fetch_sub(1, std::memory_order_release);
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
         * 2. Closing the server socket, which causes pending I/O to complete with error
         * 3. Waiting for all active IOCP operations to complete (tracked by atomic counter)
         * 4. Joining background threads
         * 5. Clearing resources
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

            // Step 3: Close all proxy sockets FIRST to cancel their I/O operations
            // This is CRITICAL: proxy sockets post their own I/O operations that will
            // call back into this server's lambda, potentially after the server is destroyed.
            // We must ensure all proxy socket I/O is cancelled before we proceed.
            {
                std::lock_guard lock(lock_);
                if (!proxy_sockets_.empty())
                {
                    NETLIB_INFO("Closing {} proxy sockets before waiting for I/O completion", proxy_sockets_.size());
                    // Closing the map entries will destroy the proxy sockets,
                    // which will close their sockets and cancel any pending I/O
                    proxy_sockets_.clear();
                }
            }

            // Step 4: Wait for all active IOCP operations to complete
            // The socket closure ensures pending operations complete quickly.
            // The atomic counter ensures we wait until all in-flight operations finish.
            // Use exponential backoff to avoid busy-waiting
            using namespace std::chrono_literals;
            int wait_iterations = 0;

            while (active_iocp_operations_.load(std::memory_order_acquire) > 0)
            {
                if (constexpr int max_wait_iterations = 100; ++wait_iterations > max_wait_iterations)
                {
                    // Log warning if we're taking too long
                    NETLIB_WARNING("Timeout waiting for IOCP operations to complete. Active operations: {}",
                    active_iocp_operations_.load(std::memory_order_relaxed));
                    break;
                }
             
                // Exponential backoff: 1ms, 2ms, 4ms, 8ms, ... up to 100ms
                const auto wait_time = std::min(1ms * (1 << std::min(wait_iterations / 10, 6)), 100ms);
                std::this_thread::sleep_for(wait_time);
            }

            // Step 5: Join background threads
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

                if (connect(socks_tcp_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) ==
                    SOCKET_ERROR)
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

                if (connect(socks_tcp_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) ==
                    SOCKET_ERROR)
                {
                    closesocket(socks_tcp_socket);
                    return INVALID_SOCKET;
                }
            }

            return socks_tcp_socket;
        }

        /**
         * @brief Performs SOCKS5 negotiation and sends the UDP ASSOCIATE command.
         *
         * This method negotiates authentication with the SOCKS5 proxy server over the provided TCP socket,
         * using either "NO AUTHENTICATION REQUIRED" or "USERNAME/PASSWORD" (RFC 1929) as needed.
         * If authentication succeeds, it sends a UDP ASSOCIATE command to the proxy and retrieves the
         * UDP port assigned by the proxy for relaying UDP packets.
         *
         * @param socks_tcp_socket The connected TCP socket to the SOCKS5 proxy server.
         * @param negotiate_ctx Unique pointer to the negotiation context, containing optional credentials.
         * @return The UDP port assigned by the SOCKS5 proxy for UDP relay, or std::nullopt on failure.
         */
        [[nodiscard]] std::optional<uint16_t> associate_to_socks5_proxy(const SOCKET socks_tcp_socket,
            std::unique_ptr<negotiate_context_t>&
            negotiate_ctx) const noexcept
        {
            using namespace std::string_literals;

            socks5_ident_req<2> ident_req{};
            socks5_ident_resp ident_resp{};
            socks5_req<address_type_t> associate_req;
            socks5_resp<address_type_t> associate_resp;

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

            associate_req.version = 5;
            associate_req.cmd = 3;
            associate_req.reserved = 0;
            if constexpr (address_type_t::af_type == AF_INET)
            {
                associate_req.address_type = 1;
            }
            else
            {
                associate_req.address_type = 4;
            }
            associate_req.dest_address = address_type_t{};
            associate_req.dest_port = 0;
            result = send(socks_tcp_socket, reinterpret_cast<const char*>(&associate_req), sizeof(associate_req), 0);
            if (result == SOCKET_ERROR)
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: Failed to send SOCKS5 ASSOCIATE request: {}",
                    WSAGetLastError());
                return {};
            }

            result = recv(socks_tcp_socket, reinterpret_cast<char*>(&associate_resp), sizeof(associate_resp), 0);
            if (result == SOCKET_ERROR)
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: Failed to receive SOCKS5 ASSOCIATE response: {}",
                    WSAGetLastError());
                return {};
            }

            if ((associate_resp.version != 5) ||
                (associate_resp.reply != 0))
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: SOCKS5 ASSOCIATE has failed");
                return {};
            }

            NETLIB_INFO(
                "[SOCKS5]: associate_to_socks5_proxy: SOCKS5 ASSOCIATE SUCCESS port: {}",
                ntohs(associate_resp.bind_port));

            return ntohs(associate_resp.bind_port);
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
                io_context->proxy_socket_ptr = it->second.get();
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

            auto udp_port = associate_to_socks5_proxy(socks5_tcp_socket, negotiate_ctx);
            if (!udp_port.has_value())
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
                remote_address,
                udp_port.value());

            auto remote_socket = WSASocket(address_type_t::af_type, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                WSA_FLAG_OVERLAPPED);

            if (remote_socket == INVALID_SOCKET)
            {
                NETLIB_DEBUG(
                    "connect_to_remote_host: Failed to create UDP socket: {}",
                    WSAGetLastError());
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
                sa_service.sin_addr = remote_address;
                sa_service.sin_port = htons(udp_port.value());

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
                sa_service.sin6_addr = remote_address;
                sa_service.sin6_port = htons(udp_port.value());

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
                std::make_unique<T>(
                    socks5_tcp_socket, packet_pool_, server_socket_,
                    recv_from_sa_, remote_socket, remote_address,
                    udp_port.value(), std::move(negotiate_ctx),
                    logger::log_level_, logger::log_stream_));

            if (result)
            {
                io_context->proxy_socket_ptr = it->second.get();
                io_context->proxy_socket_ptr->associate_to_completion_port(completion_key_, completion_port_);
                io_context->proxy_socket_ptr->start();
            }
            else
            {
                closesocket(remote_socket);
                closesocket(socks5_tcp_socket);
                NETLIB_DEBUG(
                    "connect_to_remote_host: Failed to create proxy socket for: {}:{}",
                    remote_address,
                    udp_port.value());
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
