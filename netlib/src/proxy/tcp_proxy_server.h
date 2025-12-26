#pragma once
namespace proxy
{
    /**
     * @class tcp_proxy_server
     * @brief Implements a generic asynchronous TCP proxy server using I/O completion ports.
     *
     * This class manages the lifecycle and I/O operations of a TCP proxy server that relays connections
     * between local clients and remote peers. It is designed to be highly scalable and efficient by leveraging
     * Windows overlapped I/O and completion ports, and supports both IPv4 and IPv6 through its template parameter.
     *
     * Key features:
     * - Listens for incoming TCP connections on a configurable port.
     * - For each accepted connection, queries the remote peer endpoint and negotiation context using a user-supplied callback.
     * - Establishes a connection to the remote peer and relays data between the local client and remote server.
     * - Manages all sockets and I/O operations asynchronously using a thread pool and completion port.
     * - Provides thread-safe management of active proxy sessions and supports dynamic cleanup of idle or closed sessions.
     * - Integrates with a logging framework for diagnostics and debugging.
     *
     * Template parameter:
     * @tparam T The proxy socket type to use for each proxied connection. Must provide:
     *   - negotiate_context_t: Type holding negotiation context (e.g., credentials, target address).
     *   - address_type_t: Address type (e.g., IPv4 or IPv6).
     *   - per_io_context_t: Per-I/O context type for managing asynchronous operations.
     *
     * Public interface:
     * - tcp_proxy_server(uint16_t proxy_port, winsys::io_completion_port&, std::function<query_remote_peer_t>, ...)
     *      Constructs and initializes the proxy server, binding to the specified port.
     * - ~tcp_proxy_server()
     *      Cleans up all resources and stops the server.
     * - bool start()
     *      Starts the proxy server, accepting connections and relaying data.
     * - void stop()
     *      Stops the proxy server and all active sessions.
     * - uint16_t proxy_port() const
     *      Returns the local listening port.
     * - std::vector<negotiate_context_t> query_current_sessions_ctx()
     *      Returns the negotiation contexts for all active sessions.
     *
     * Not copyable or movable.
     *
     * Internal details:
     * - Uses a vector of socket/event/context tuples to track pending and active connections.
     * - Uses multiple threads for accepting connections, connecting to remote hosts, and cleaning up idle sessions.
     * - Associates sockets with the I/O completion port for efficient asynchronous I/O.
     * - Thread safety is ensured via shared_mutex and atomic flags.
     */
    template <typename T>
    class tcp_proxy_server : public netlib::log::logger<tcp_proxy_server<T>>  // NOLINT(clang-diagnostic-padded)
    {
    public:
        /**
         * @brief Type alias for the logging level enumeration used by the proxy server.
         */
        using log_level = netlib::log::log_level;

        /**
         * @brief Type alias for the logger base class used for logging within the proxy server.
         */
        using logger = netlib::log::logger<tcp_proxy_server>;

        /**
         * @brief Type alias for the negotiation context type used by the proxy socket.
         *
         * This type holds information required for session negotiation, such as credentials or
         * target addresses, and is defined by the proxy socket type T.
         */
        using negotiate_context_t = T::negotiate_context_t;

        /**
         * @brief Type alias for the address type (e.g., IPv4 or IPv6) used by the proxy socket.
         */
        using address_type_t = T::address_type_t;

        /**
         * @brief Type alias for the per-I/O context type used for managing asynchronous operations.
         */
        using per_io_context_t = T::per_io_context_t;

        /**
         * @brief Type alias for the callback function used to query remote peer information.
         *
         * The callback takes an address and port and returns a tuple containing the remote address,
         * remote port, and a unique pointer to the negotiation context for the session.
         */
        using query_remote_peer_t = std::tuple<address_type_t, uint16_t, std::unique_ptr<negotiate_context_t>>(
            address_type_t, uint16_t);

    private:
        /**
         * @brief Maximum number of simultaneous connections/events the server can track.
         *
         * This constant defines the reserved size for the internal connection/event arrays.
         */
        constexpr static size_t connections_array_size = 64;

        /**
         * @brief Reference to the I/O completion port used for asynchronous socket operations.
         *
         * This enables scalable, efficient handling of multiple concurrent I/O operations.
         */
        netlib::winsys::io_completion_port& completion_port_;

        /**
         * @brief Callback function to query remote peer information for each new connection.
         *
         * This function is invoked with the local peer's address and port, and returns a tuple
         * containing the remote address, remote port, and a unique pointer to the negotiation context.
         */
        std::function<query_remote_peer_t> query_remote_peer_;

        /**
         * @brief Shared mutex for synchronizing access to internal data structures.
         *
         * Used to protect concurrent access to the proxy socket and event arrays.
         */
        std::shared_mutex lock_;

        /**
         * @brief Thread for accepting incoming client connections and dispatching them.
         */
        std::thread proxy_server_;

        /**
         * @brief Thread for periodically checking and cleaning up closed or idle client sessions.
         */
        std::thread check_clients_thread_;

        /**
         * @brief Thread for handling asynchronous connections to remote hosts.
         */
        std::thread connect_to_remote_host_thread_;

        /**
         * @brief Vector of active proxy socket instances, one per client session.
         *
         * Uses shared_ptr to enable safe concurrent access from IOCP threads.
         * The last reference may be held by a pending I/O operation.
         */
        std::vector<std::shared_ptr<T>> proxy_sockets_;

        /**
         * @brief Array of tuples tracking events, sockets, and negotiation contexts for pending connections.
         *
         * Each tuple contains:
         * - WSAEVENT: Event handle for overlapped I/O notification.
         * - SOCKET:   Local client socket.
         * - SOCKET:   Remote server socket.
         * - std::unique_ptr<negotiate_context_t>: Negotiation context for the session.
         */
        std::vector<std::tuple<WSAEVENT, SOCKET, SOCKET, std::unique_ptr<negotiate_context_t>>> sock_array_events_;

        /**
         * @brief The main listening socket for incoming client connections.
         */
        SOCKET server_socket_{ INVALID_SOCKET };

        /**
         * @brief Completion key associated with the I/O completion port for this server.
         */
        ULONG_PTR completion_key_{ 0 };

        /**
         * @brief Counts the number of IOCP operations currently executing in the lambda.
         *
         * Incremented when entering the lambda, decremented when exiting.
         * Used during shutdown to ensure no operations are in-flight before destroying the object.
         */
        std::atomic<int32_t> active_iocp_operations_{ 0 };

        /**
         * @brief The TCP port number on which the proxy server listens for incoming connections.
         */
        uint16_t proxy_port_;

        /**
        * @brief Atomic flag indicating whether the server is shutting down or has terminated.
        */
        std::atomic_bool end_server_{ true };

    public:
        /**
         * @brief Constructs a tcp_proxy_server instance and binds it to the specified port.
         *
         * Initializes the TCP proxy server, sets up the I/O completion port, and prepares the
         * callback for remote peer queries. Throws a std::runtime_error if the server socket
         * cannot be created or bound.
         *
         * @param proxy_port         The TCP port number to listen on for incoming client connections.
         * @param completion_port    Reference to the I/O completion port for asynchronous operations.
         * @param query_remote_peer_fn
         *        Callback function to determine the remote peer address, port, and negotiation context
         *        for each new client connection.
         * @param log_level          Logging level for this server instance (default: error).
         * @param log_stream         Optional output stream for logging (default: std::nullopt).
         *
         * @throws std::runtime_error if the server socket cannot be created or bound.
         */
        tcp_proxy_server(const uint16_t proxy_port, netlib::winsys::io_completion_port& completion_port,
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
                throw std::runtime_error("tcp_proxy_server: failed to create server socket.");
            }
        }

        /**
         * @brief Destructor for the tcp_proxy_server class.
         *
         * Cleans up resources by shutting down and closing the server socket if it is still open.
         * If the server is still running, calls stop() to ensure all threads and sessions are properly terminated.
         */
        ~tcp_proxy_server()
        {
            if (server_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
            {
                shutdown(server_socket_, SD_BOTH);
                closesocket(server_socket_);
                server_socket_ = INVALID_SOCKET;
            }

            if (end_server_ == false)
                stop();
        }

        /**
         * @brief Deleted copy constructor to prevent copying of tcp_proxy_server instances.
         */
        tcp_proxy_server(const tcp_proxy_server& other) = delete;

        /**
         * @brief Deleted move constructor to prevent moving of tcp_proxy_server instances.
         */
        tcp_proxy_server(tcp_proxy_server&& other) noexcept = delete;

        /**
         * @brief Deleted copy assignment operator to prevent copying of tcp_proxy_server instances.
         */
        tcp_proxy_server& operator=(const tcp_proxy_server& other) = delete;

        /**
         * @brief Deleted move assignment operator to prevent moving of tcp_proxy_server instances.
         */
        tcp_proxy_server& operator=(tcp_proxy_server&& other) noexcept = delete;

        /**
         * @brief Returns the TCP port number on which the proxy server is listening.
         * @return The local proxy port number.
         */
        [[nodiscard]] uint16_t proxy_port() const
        {
            return proxy_port_;
        }

        /**
         * @brief Starts the TCP proxy server and its worker threads.
         *
         * This method initializes the server for accepting new client connections and relaying data.
         * It performs the following steps:
         * - Checks if the server is already running; if so, returns true immediately.
         * - Reserves space for connection events and sockets.
         * - Creates the initial event and socket tuple for accepting connections.
         * - Associates the listening socket with the I/O completion port and sets up the callback handler.
         * - If association fails, cleans up resources and returns false.
         * - Launches the main proxy server thread, client cleanup thread, and remote host connection thread.
         *
         * @return true if the server was started successfully or is already running; false if initialization failed.
         */
        bool start()
        {
            if (end_server_ == false)
            {
                // already running
                return true;
            }

            end_server_ = false;

            sock_array_events_.reserve(connections_array_size);

            sock_array_events_.push_back(std::make_tuple(WSACreateEvent(),
                                                         WSASocket(address_type_t::af_type, SOCK_STREAM,
                                                                   IPPROTO_TCP, nullptr, 0,
                                                                   WSA_FLAG_OVERLAPPED), INVALID_SOCKET, nullptr));

            if (std::get<1>(sock_array_events_[0]) != INVALID_SOCKET)
            {
                auto [success, io_key] = completion_port_.associate_socket(
                    std::get<1>(sock_array_events_[0]),
                    [this](const DWORD num_bytes, OVERLAPPED* povlp, const BOOL status)
                    {
                        // Increment active operations counter on entry
                        active_iocp_operations_.fetch_add(1, std::memory_order_acquire);
                        
                        // RAII guard to ensure we decrement on all exit paths (including exceptions)
                        // Non-copyable/non-moveable to prevent double-decrement bugs
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

                        // Check if server is shutting down
                        if (end_server_.load(std::memory_order_acquire))
                            return false;

                        auto io_context = static_cast<per_io_context_t*>(povlp);

                        if (!status || (status && (num_bytes == 0)))
                        {
                            if ((io_context->io_operation == proxy_io_operation::relay_io_read) ||
                                (io_context->io_operation == proxy_io_operation::negotiate_io_read))
                            {
                                io_context->proxy_socket_ptr->close_client(true, io_context->is_local);
                                return false;
                            }

                            if (!status)
                            {
                                io_context->proxy_socket_ptr->close_client(false, io_context->is_local);
                                return false;
                            }
                        }

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
                            T::process_inject_buffer_complete(io_context);
                            break;
                        default: break; // NOLINT(clang-diagnostic-covered-switch-default)
                        }

                        return true;
                    });

                if (success == true)
                {
                    completion_key_ = io_key;
                }
                else
                {
                    if (std::get<0>(sock_array_events_[0]) != INVALID_HANDLE_VALUE)
                    {
                        WSACloseEvent(std::get<0>(sock_array_events_[0]));
                    }

                    if (std::get<1>(sock_array_events_[0]) != INVALID_SOCKET)
                    {
                        closesocket(std::get<1>(sock_array_events_[0]));
                    }

                    sock_array_events_.clear();
                    end_server_ = true;
                    return false;
                }
            }

            proxy_server_ = std::thread(&tcp_proxy_server::start_proxy_thread, this);
            check_clients_thread_ = std::thread(&tcp_proxy_server::clear_thread, this);
            connect_to_remote_host_thread_ = std::thread(&tcp_proxy_server::connect_to_remote_host_thread, this);

            return true;
        }

        /**
         * @brief Stops the TCP proxy server and cleans up all resources.
         *
         * This method performs a graceful shutdown of the proxy server by:
         * 1. Setting the end_server_ flag to signal shutdown
         * 2. Closing the server socket, which causes pending I/O to complete with error
         * 3. Waiting for all active IOCP operations to complete (tracked by atomic counter)
         * 4. Joining background threads
         * 5. Clearing resources
         *
         * The IOCP thread pool itself is managed by io_completion_port and will be 
         * properly shut down when the completion port is destroyed.
         *
         * If the server is already stopped, this method returns immediately.
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
            // This causes any pending accept/I/O operations to complete immediately with an error.
            // When IOCP threads wake up, they'll see end_server_ == true and return false.
            closesocket(server_socket_);
            server_socket_ = INVALID_SOCKET;

            {
                std::unique_lock lock(lock_);
                ::WSASetEvent(std::get<0>(sock_array_events_[0]));
            }

            // Step 2.5: Unregister the IOCP handler BEFORE waiting
            if (completion_key_ != 0) {
                (void)completion_port_.unregister_handler(completion_key_);
                completion_key_ = 0;
            }

            // Step 3: Wait for all active IOCP operations to complete
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

            // Step 4: Join background threads
            if (proxy_server_.joinable())
            {
                proxy_server_.join();
            }

            if (check_clients_thread_.joinable())
            {
                check_clients_thread_.join();
            }

            if (connect_to_remote_host_thread_.joinable())
            {
                connect_to_remote_host_thread_.join();
            }

            // Step 5: Clear resources
            // Now safe because:
            // - end_server_ is true, so IOCP lambda won't process new completions
            // - Socket is closed, so no new I/O can be initiated
            // - We waited for all active operations to complete
            if (!sock_array_events_.empty())
            {
                sock_array_events_.clear();
            }

            if (!proxy_sockets_.empty())
            {
                proxy_sockets_.clear();
            }

            // Note: The IOCP thread pool itself is managed by completion_port_ and will be
            // properly shut down when io_completion_port's destructor is called.
        }

        /**
         * @brief Retrieves the negotiation contexts for all active proxy sessions.
         *
         * This method acquires a shared lock to ensure thread-safe access to the internal
         * proxy socket list. It then iterates over all active proxy socket instances and
         * extracts their negotiation context, returning a vector of these contexts.
         *
         * @return std::vector<negotiate_context_t> containing the negotiation context for each active session.
         */
        std::vector<negotiate_context_t> query_current_sessions_ctx()
        {
            std::shared_lock lock(lock_);
            std::vector<negotiate_context_t> result;
            result.reserve(proxy_sockets_.size());

            std::transform(proxy_sockets_.cbegin(), proxy_sockets_.cend(), std::back_inserter(result), [](auto&& e)
                {
                    return *reinterpret_cast<negotiate_context_t*>(e->get_negotiate_ctx());
                });

            return result;
        }

    private:
        // ********************************************************************************
        /// <summary>
        /// Queries remote host information for an outgoing connection by a locally accepted socket.
        /// </summary>
        /// <param name="accepted">The locally accepted TCP socket for which to query remote peer information.</param>
        /// <returns>
        /// A tuple containing:
        ///   - The remote peer address (address_type_t)
        ///   - The remote peer port (uint16_t)
        ///   - A unique pointer to the negotiation context (std::unique_ptr<negotiate_context_t>)
        /// If the query fails, returns a tuple with default-constructed values.
        /// </returns>
        // ********************************************************************************
        std::tuple<address_type_t, uint16_t, std::unique_ptr<negotiate_context_t>> get_remote_peer(
            const SOCKET accepted) const
        {
            SOCKADDR_STORAGE name;
            int len = sizeof(SOCKADDR_STORAGE);

            if (!getpeername(accepted, reinterpret_cast<sockaddr*>(&name), &len))
            {
                uint16_t accepted_peer_port = 0;
                address_type_t accepted_peer_address{};

                if constexpr (address_type_t::af_type == AF_INET)
                {
                    accepted_peer_port = ntohs(reinterpret_cast<sockaddr_in*>(&name)->sin_port);
                    accepted_peer_address = address_type_t(reinterpret_cast<sockaddr_in*>(&name)->sin_addr);
                }
                else if constexpr (address_type_t::af_type == AF_INET6)
                {
                    accepted_peer_port = ntohs(reinterpret_cast<sockaddr_in6*>(&name)->sin6_port);
                    accepted_peer_address = address_type_t(reinterpret_cast<sockaddr_in6*>(&name)->sin6_addr);
                }
                else
                {
                    static_assert(false_v<T>, "Unsupported address family used as a template parameter!");
                }

                if (query_remote_peer_)
                {
                    return query_remote_peer_(accepted_peer_address, accepted_peer_port);
                }
            }
            else
            {
                return std::make_tuple(address_type_t{}, 0, nullptr);
            }

            return std::make_tuple(address_type_t{}, 0, nullptr);
        }

        /**
         * @brief Creates and binds the server's listening socket.
         *
         * This method creates a new overlapped TCP socket using the address family specified by
         * address_type_t. It then binds the socket to the configured proxy port and any local address
         * (IPv4 or IPv6, depending on the template parameter). If the port is set to 0, the method
         * retrieves the actual port assigned by the system after binding. Finally, it puts the socket
         * into listening mode for incoming connections.
         *
         * If any step fails, the socket is closed and the method returns false.
         *
         * @return true if the server socket was successfully created, bound, and set to listen; false otherwise.
         */
        bool create_server_socket()
        {
            server_socket_ = WSASocket(address_type_t::af_type, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                WSA_FLAG_OVERLAPPED);

            if (server_socket_ == static_cast<SOCKET>(INVALID_SOCKET))
            {
                return false;
            }

            if constexpr (address_type_t::af_type == AF_INET)
            {
                sockaddr_in service{};
                service.sin_family = address_type_t::af_type;
                service.sin_addr.s_addr = INADDR_ANY;
                service.sin_port = htons(proxy_port_);

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
                sockaddr_in6 service{};
                service.sin6_family = address_type_t::af_type;
                service.sin6_addr = in6addr_any;
                service.sin6_port = htons(proxy_port_);

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

            if (const auto status = listen(server_socket_, SOMAXCONN); status == SOCKET_ERROR)
            {
                closesocket(server_socket_);
                server_socket_ = INVALID_SOCKET;
                return false;
            }

            return true;
        }

        /**
         * @brief Establishes an asynchronous connection to a remote host for a given accepted client socket.
         *
         * This method performs the following steps:
         * - Queries the remote peer address, port, and negotiation context using get_remote_peer().
         * - If the remote port is invalid, returns false.
         * - Creates a new overlapped socket for the remote connection.
         * - Binds the remote socket to an ephemeral local port and any local address (IPv4 or IPv6).
         * - Sets the remote socket to non-blocking mode.
         * - Registers the remote socket and associated event/context in the internal tracking array.
         * - Initiates a non-blocking connect() to the remote peer.
         * - If the connection fails immediately (other than WSAEWOULDBLOCK), cleans up and returns false.
         *
         * @param accepted The accepted client SOCKET for which to establish a remote connection.
         * @return true if the connection initiation was successful; false otherwise.
         */
        bool connect_to_remote_host(SOCKET accepted)
        {
            auto [remote_ip, remote_port, negotiate_ctx] = get_remote_peer(accepted);

            if (!remote_port)
            {
                NETLIB_WARNING("connect_to_remote_host: Invalid remote port (0) - rejecting connection");
                return false;
            }

            NETLIB_DEBUG("connect_to_remote_host: Connecting to {}:{}", remote_ip, remote_port);

            auto remote_socket = WSASocket(address_type_t::af_type, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                WSA_FLAG_OVERLAPPED);

            if (remote_socket == INVALID_SOCKET)
            {
                NETLIB_ERROR("connect_to_remote_host: Failed to create remote socket: {}", WSAGetLastError());
                return false;
            }

            if constexpr (address_type_t::af_type == AF_INET)
            {
                sockaddr_in sa_local{};
                sa_local.sin_family = address_type_t::af_type;
                sa_local.sin_port = htons(0);
                sa_local.sin_addr.s_addr = htonl(INADDR_ANY);

                // bind socket's name
                const auto status = bind(remote_socket, reinterpret_cast<sockaddr*>(&sa_local), sizeof(sa_local));

                if (status == SOCKET_ERROR)
                {
                    const auto error = WSAGetLastError();
                    NETLIB_ERROR("connect_to_remote_host: Failed to bind IPv4 remote socket: {}", error);
                    shutdown(remote_socket, SD_BOTH);
                    closesocket(remote_socket);
                    return false;
                }
            }
            else
            {
                sockaddr_in6 sa_local{};
                sa_local.sin6_family = address_type_t::af_type;
                sa_local.sin6_port = htons(0);
                sa_local.sin6_addr = in6addr_any;

                // bind socket's name
                const auto status = bind(remote_socket, reinterpret_cast<sockaddr*>(&sa_local), sizeof(sa_local));

                if (status == SOCKET_ERROR)
                {
                    const auto error = WSAGetLastError();
                    NETLIB_ERROR("connect_to_remote_host: Failed to bind IPv6 remote socket: {}", error);
                    shutdown(remote_socket, SD_BOTH);
                    closesocket(remote_socket);
                    return false;
                }
            }

            // enable non-blocking mode
            u_long mode = 1;
            auto ret = ioctlsocket(remote_socket, FIONBIO, &mode);
            if (ret != 0)
            {
                const auto error = WSAGetLastError();
                NETLIB_WARNING("connect_to_remote_host: Failed to set non-blocking mode: {}", error);
                // Continue anyway, as this might not be critical
            }

            // The client_service structure specifies the address family,
            // IP address, and port of the server to be connected to.
            {
                std::scoped_lock lock(lock_);

                if (sock_array_events_.size() >= connections_array_size - 1)
                {
                    NETLIB_WARNING("connect_to_remote_host: Socket array full, cannot add new connection");
                    shutdown(remote_socket, SD_BOTH);
                    closesocket(remote_socket);
                    return false;
                }

                sock_array_events_.push_back(
                    std::make_tuple(WSACreateEvent(), accepted, remote_socket, std::move(negotiate_ctx)));

                if (std::get<0>(sock_array_events_.back()) == WSA_INVALID_EVENT)
                {
                    NETLIB_ERROR("connect_to_remote_host: Failed to create WSA event: {}", WSAGetLastError());
                    sock_array_events_.pop_back();
                    shutdown(remote_socket, SD_BOTH);
                    closesocket(remote_socket);
                    return false;
                }

                if (WSAEventSelect(remote_socket, std::get<0>(sock_array_events_.back()), FD_CONNECT) == SOCKET_ERROR)
                {
                    const auto error = WSAGetLastError();
                    NETLIB_WARNING("connect_to_remote_host: WSAEventSelect failed: {}", error);
                    WSACloseEvent(std::get<0>(sock_array_events_.back()));
                    sock_array_events_.pop_back();
                    shutdown(remote_socket, SD_BOTH);
                    closesocket(remote_socket);
                    return false;
                }

                WSASetEvent(std::get<0>(sock_array_events_[0]));
            }

            NETLIB_DEBUG("connect_to_remote_host: Initiating connection to {}:{}", remote_ip, remote_port);

            // connect to server
            if constexpr (address_type_t::af_type == AF_INET)
            {
                sockaddr_in sa_service{};
                sa_service.sin_family = address_type_t::af_type;
                sa_service.sin_addr = remote_ip;
                sa_service.sin_port = htons(remote_port);

                if (connect(remote_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) ==
                    SOCKET_ERROR)
                {
                    if (const auto error = WSAGetLastError(); error != WSAEWOULDBLOCK)
                    {
                        NETLIB_WARNING("connect_to_remote_host: IPv4 connect failed: {}", error);
                        shutdown(remote_socket, SD_BOTH);
                        closesocket(remote_socket);
                        return false;
                    }
                    NETLIB_DEBUG("connect_to_remote_host: IPv4 connection in progress (WSAEWOULDBLOCK)");
                }
                else
                {
                    NETLIB_DEBUG("connect_to_remote_host: IPv4 connection completed immediately");
                }
            }
            else
            {
                sockaddr_in6 sa_service{};
                sa_service.sin6_family = address_type_t::af_type;
                sa_service.sin6_addr = remote_ip;
                sa_service.sin6_port = htons(remote_port);

                if (connect(remote_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) ==
                    SOCKET_ERROR)
                {
                    if (const auto error = WSAGetLastError(); error != WSAEWOULDBLOCK)
                    {
                        NETLIB_WARNING("connect_to_remote_host: IPv6 connect failed: {}", error);
                        shutdown(remote_socket, SD_BOTH);
                        closesocket(remote_socket);
                        return false;
                    }
                    else
                    {
                        NETLIB_DEBUG("connect_to_remote_host: IPv6 connection in progress (WSAEWOULDBLOCK)");
                    }
                }
                else
                {
                    NETLIB_DEBUG("connect_to_remote_host: IPv6 connection completed immediately");
                }
            }

            NETLIB_DEBUG("connect_to_remote_host: Successfully initiated connection to {}:{}", remote_ip, remote_port);
            return true;
        }

        /**
         * @brief Main thread routine for accepting and dispatching incoming client connections.
         *
         * This method runs in a dedicated thread and continuously accepts new TCP client connections
         * on the server's listening socket as long as the server is running. For each accepted connection:
         * - If the server is shutting down or the accept fails, the loop exits.
         * - Attempts to establish a connection to the corresponding remote host using connect_to_remote_host().
         * - If the remote connection setup fails, the accepted client socket is closed immediately.
         *
         * The thread terminates when the server is stopped or a fatal error occurs on accept.
         */
        void start_proxy_thread()
        {
            while (end_server_ == false)
            {
                //
                // loop accepting connections from clients until proxy shuts down
                //
                const auto accepted = WSAAccept(server_socket_, nullptr, nullptr, nullptr, 0);

                if (accepted == static_cast<SOCKET>(INVALID_SOCKET) || end_server_)
                {
                    break;
                }

                if (sock_array_events_.size() >= connections_array_size) {
                    NETLIB_WARNING("Too many pending connections, rejecting new client.");
                    closesocket(accepted);
                    continue;
                }

                if (const auto connected = connect_to_remote_host(accepted); !connected)
                {
                    closesocket(accepted);
                }
            }
        }

        /**
         * @brief Thread routine for handling asynchronous connections to remote hosts.
         *
         * This method runs in a dedicated thread and manages the completion of non-blocking connect operations
         * for remote sockets. It operates as follows:
         * - Continuously builds a list of WSAEVENT handles corresponding to pending remote connection attempts.
         * - Waits for any of these events to be signaled, indicating a completed connection attempt.
         * - If a connection event (other than the first) is signaled, finalizes the session:
         *   - Closes the event handle.
         *   - Constructs a new proxy socket instance for the completed connection, associates it with the I/O completion port,
         *     and starts the proxy session.
         *   - Removes the processed entry from the tracking array.
         * - If the first event is signaled, resets it and continues.
         * - On server shutdown, cleans up all remaining events and sockets in the tracking array.
         *
         * Thread safety is ensured via shared and exclusive locks as needed.
         * The thread exits when the server is stopped.
         */
        void connect_to_remote_host_thread()
        {
            std::vector<WSAEVENT> wait_events;
            wait_events.reserve(connections_array_size);

            while (end_server_ == false)
            {
                // initialize wait events array
                wait_events.clear();

                {
                    std::shared_lock lock(lock_);

                    std::transform(sock_array_events_.cbegin(), sock_array_events_.cend(),
                        std::back_inserter(wait_events), [](auto&& e)
                        {
                            return std::get<0>(e);
                        });
                }

                const auto event_index = wait_for_multiple_objects(static_cast<DWORD>(wait_events.size()),
                    wait_events.data(), INFINITE);

                if (end_server_ == true)
                    break;

                if (event_index != 0)
                {
                    std::scoped_lock lock(lock_);

                    WSACloseEvent(wait_events[event_index]);

                    // Extract socket handles before creating the shared_ptr
                    // so we can clean them up if initialization fails
                    auto local_socket = std::get<1>(sock_array_events_[event_index]);
                    auto remote_socket = std::get<2>(sock_array_events_[event_index]);
                    auto negotiate_ctx = std::move(std::get<3>(sock_array_events_[event_index]));

                    // Remove from tracking array first - we own the resources now
                    sock_array_events_.erase(sock_array_events_.begin() + event_index);

                    try
                    {
                        // Create socket as shared_ptr
                        auto socket = std::make_shared<T>(
                            local_socket,
                            remote_socket,
                            std::move(negotiate_ctx),
                            logger::log_level_, logger::log_stream_);

                        // Initialize I/O contexts - can throw std::bad_weak_ptr or std::runtime_error
                        socket->initialize_io_contexts();

                        // Associate with completion port
                        socket->associate_to_completion_port(completion_key_, completion_port_);

                        // Start the socket
                        socket->start();

                        // Store in vector - socket is now fully initialized
                        proxy_sockets_.push_back(std::move(socket));
                    }
                    catch (const std::exception& e)
                    {
                        // Initialization failed - clean up sockets manually since they weren't
                        // transferred to a successfully initialized proxy socket
                        NETLIB_ERROR("connect_to_remote_host_thread: Failed to initialize proxy socket: {}", e.what());

                        if (local_socket != INVALID_SOCKET)
                        {
                            shutdown(local_socket, SD_BOTH);
                            closesocket(local_socket);
                        }

                        if (remote_socket != INVALID_SOCKET)
                        {
                            shutdown(remote_socket, SD_BOTH);
                            closesocket(remote_socket);
                        }
                        // Continue processing other connections
                    }
                    catch (...)
                    {
                        NETLIB_ERROR("connect_to_remote_host_thread: Unknown exception during proxy socket initialization");

                        if (local_socket != INVALID_SOCKET)
                        {
                            shutdown(local_socket, SD_BOTH);
                            closesocket(local_socket);
                        }

                        if (remote_socket != INVALID_SOCKET)
                        {
                            shutdown(remote_socket, SD_BOTH);
                            closesocket(remote_socket);
                        }
                        // Continue processing other connections
                    }
                }
                else
                {
                    WSAResetEvent(wait_events[event_index]);
                }
            }

            // cleanup on exit
            std::shared_lock lock(lock_);

            for (auto&& a : sock_array_events_)
            {
                if (std::get<0>(a) != INVALID_HANDLE_VALUE)
                {
                    WSACloseEvent(std::get<0>(a));
                }

                if (std::get<1>(a) != INVALID_SOCKET)
                {
                    shutdown(std::get<1>(a), SD_BOTH);
                    closesocket(std::get<1>(a));
                    std::get<1>(a) = INVALID_SOCKET;
                }

                if (std::get<2>(a) != INVALID_SOCKET)
                {
                    shutdown(std::get<2>(a), SD_BOTH);
                    closesocket(std::get<2>(a));
                    std::get<2>(a) = INVALID_SOCKET;
                }
            }
        }

        /**
         * @brief Thread routine for cleaning up closed or idle proxy sessions.
         *
         * This method runs in a dedicated thread and periodically scans the list of active proxy socket
         * instances. It removes any sockets that are ready for removal (e.g., closed or idle sessions)
         * from the internal proxy_sockets_ vector. The cleanup operation is protected by a lock to ensure
         * thread safety. The thread sleeps for 1 second between cleanup cycles and exits when the server
         * is stopped.
         */
        void clear_thread()
        {
            while (end_server_ == false)
            {
                {
                    std::scoped_lock lock(lock_);

                    proxy_sockets_.erase(std::remove_if(proxy_sockets_.begin(), proxy_sockets_.end(), [](auto&& a)
                        {
                            return a->is_ready_for_removal();
                        }), proxy_sockets_.end());
                }

                using namespace std::chrono_literals;
                std::this_thread::sleep_for(1000ms);
            }
        }

        /**
         * @brief Waits for one or more objects (such as threads or events) to become signaled.
         *
         * This static utility function provides a scalable way to wait for multiple synchronization objects,
         * such as thread or event handles, to become signaled. If the number of handles exceeds the platform's
         * MAXIMUM_WAIT_OBJECTS, the function recursively splits the array and waits on subsets, using a randomized
         * order to avoid starvation. For a manageable number of handles, it delegates to the native
         * ::WaitForMultipleObjects API.
         *
         * @param count   The number of handles in the array.
         * @param handles Pointer to an array of HANDLEs to wait on.
         * @param ms      The maximum time to wait, in milliseconds. Use INFINITE for no timeout.
         * @return WAIT_OBJECT_0 + index of the signaled handle if successful, WAIT_TIMEOUT if the wait timed out.
         */
        static DWORD wait_for_multiple_objects(const DWORD count, const HANDLE* handles, const DWORD ms)
        {
            // Thread local seed for rand_r
            thread_local auto seed = static_cast<uint32_t>(time(nullptr));

            // Initial result set to timeout
            DWORD result = WAIT_TIMEOUT;

            // If the number of objects is greater than the maximum allowed...
            if (count >= MAXIMUM_WAIT_OBJECTS)
            {
                // Loop until a handle is signaled or until the timeout is reached if timeout is infinite
                do
                {
                    // Divide the number of handles in half
                    const DWORD split = count / 2;

                    // Divide the wait time in half, if timeout is infinite, use a default wait time of 2000ms
                    const DWORD wait = (ms == INFINITE ? 2000 : ms) / 2;
                    const int random = rand_s(&seed);

                    // Recurse on both halves in a random order until a handle is signaled or all handles are checked
                    for (short branch = 0; branch < 2 && result == WAIT_TIMEOUT; branch++)
                    {
                        if (random % 2 == branch)
                        {
                            // Wait for the lower half of handles
                            result = wait_for_multiple_objects(split, handles, wait);
                        }
                        else
                        {
                            // Wait for the upper half of handles, adjust result if a handle is signaled
                            result = wait_for_multiple_objects(count - split, handles + split, wait);
                            if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + split) result += split;
                        }
                    }
                } while (ms == INFINITE && result == WAIT_TIMEOUT);
            }
            else
            {
                // If the number of handles is within limit, use the native win32 function
                result = ::WaitForMultipleObjects(count, handles, FALSE, ms);
            }

            // Return the result
            return result;
        }
    };
}
