#pragma once

namespace proxy
{
    template <net::ip_address T>
    class socks5_udp_proxy_socket;

    template <net::ip_address T>
    struct socks5_udp_per_io_context : WSAOVERLAPPED  // NOLINT(clang-diagnostic-padded)
    {
        /**
         * @brief Constructs a per-I/O context for SOCKS5 UDP proxy operations.
         *
         * @param io_operation The type of proxy I/O operation (read, write, etc).
         * @param socket Shared pointer to the associated socks5_udp_proxy_socket instance.
         * @param is_local True if the operation is for the local socket, false for the remote socket.
         */
        socks5_udp_per_io_context(const proxy_io_operation io_operation,
            std::shared_ptr<socks5_udp_proxy_socket<T>> socket,
            const bool is_local)
            : WSAOVERLAPPED{ 0, 0, {{.Offset = 0, .OffsetHigh = 0}}, nullptr },
              proxy_socket_ptr(std::move(socket)),
              io_operation(io_operation),
              is_local(is_local)
        {
        }

        /**
         * @brief Allocates and initializes a new per-I/O context for a UDP proxy operation.
         *
         * Optionally allocates a packet buffer of the specified size using the socket's packet pool.
         *
         * @param io_operation The type of proxy I/O operation.
         * @param socket Shared pointer to the associated socks5_udp_proxy_socket instance.
         * @param is_local True if the operation is for the local socket, false for the remote socket.
         * @param size Optional size of the packet buffer to allocate (default: 0, no buffer).
         * @return Pointer to the allocated context, or nullptr on failure.
         */
        static socks5_udp_per_io_context* allocate_io_context(
            const proxy_io_operation io_operation,
            const std::shared_ptr<socks5_udp_proxy_socket<T>>& socket,
            const bool is_local,
            const uint32_t size = 0)
        {
            auto* context = new(std::nothrow) socks5_udp_per_io_context(io_operation, socket, is_local);
            if (!context)
                return nullptr;

            if (size)
            {
                context->wsa_buf = socket->allocate_packet(size);

                if (!context->wsa_buf)
                {
                    delete context;
                    return nullptr;
                }
            }

            return context;
        }

        /**
        * @brief Releases a per-I/O context and its associated packet buffer.
        *
        * Frees the packet buffer (if any) using the socket's packet pool, then deletes the context.
        *
        * @param context Pointer to the context to release.
        */
        static void release_io_context(socks5_udp_per_io_context* context)
        {
            if (!context)
                return;

            if (context->proxy_socket_ptr && context->wsa_buf)
            {
                context->proxy_socket_ptr->release_packet(std::move(context->wsa_buf));
            }

            delete context;
        }
        
        /// Shared pointer to the associated SOCKS5 UDP proxy socket.
        std::shared_ptr<socks5_udp_proxy_socket<T>> proxy_socket_ptr;
        /// Unique pointer to the packet buffer for this I/O operation.
        std::unique_ptr<net_packet_t> wsa_buf{ nullptr };
        /// The type of proxy I/O operation (read, write, etc).
        proxy_io_operation io_operation;
        /// True if the operation is for the local socket, false for the remote socket.
        bool is_local;
    };

    /**
    * @class socks5_udp_proxy_socket
    * @brief Implements a UDP proxy socket that relays UDP packets through a SOCKS5 proxy server.
    *
    * This class manages the lifecycle and I/O operations of a UDP relay session via a SOCKS5 proxy.
    * It handles asynchronous packet forwarding between a local UDP socket and a remote UDP endpoint
    * provided by the SOCKS5 proxy, using Windows overlapped I/O and completion ports for scalability.
    *
    * Key features:
    * - Manages local and remote UDP sockets, and the associated SOCKS5 TCP control connection.
    * - Uses a shared packet pool for efficient buffer management.
    * - Supports asynchronous send/receive operations with per-I/O context structures.
    * - Tracks session state and provides cleanup when a session is idle or closed.
    * - Integrates with a logging framework for diagnostics and debugging.
    *
    * @tparam T Address type (e.g., IPv4 or IPv6) used for remote peer addressing.
    */
    template <net::ip_address T>
    class socks5_udp_proxy_socket final : public netlib::log::logger<socks5_udp_proxy_socket<T>>,  // NOLINT(clang-diagnostic-padded)
        public std::enable_shared_from_this<socks5_udp_proxy_socket<T>>
    {
    public:
        /**
         * @brief Size of the send/receive buffer for UDP packets (64 KiB).
         *
         * This constant defines the maximum buffer size for UDP packet transmission and reception.
         */
        constexpr static size_t send_receive_buffer_size = 256ull * 256ull;

        /**
         * @brief Type aliases for logging, address, negotiation context, and per-I/O context.
         *
         * - log_level: Logging level enumeration used for this proxy socket.
         * - logger: Logger base class for logging within the proxy socket.
         * - address_type_t: Address type (e.g., IPv4 or IPv6) used by the proxy socket.
         * - negotiate_context_t: Type holding SOCKS5 negotiation context (credentials, target address, etc.).
         * - per_io_context_t: Per-I/O context type for managing asynchronous operations.
         */
        using log_level = netlib::log::log_level;
        using logger = netlib::log::logger<socks5_udp_proxy_socket>;
        using address_type_t = T;
        using negotiate_context_t = socks5_negotiate_context<T>;
        using per_io_context_t = socks5_udp_per_io_context<T>;

    private:
        /// <summary>
        /// Timestamp of the last processed packet for this session.
        /// Used to determine session activity and for idle timeout checks.
        /// </summary>
        std::chrono::steady_clock::time_point timestamp_;

        /// <summary>
        /// SOCKS5 TCP control connection socket used for UDP association with the proxy server.
        /// </summary>
        SOCKET socks_socket_;

        /// <summary>
        /// Shared pointer to the packet pool for efficient allocation and reuse of network packet buffers.
        /// </summary>
        std::shared_ptr<packet_pool> packet_pool_;

        /// <summary>
        /// Local UDP socket used to receive and send packets from/to the client application.
        /// </summary>
        SOCKET local_socket_;

        /// <summary>
        /// Remote UDP socket used to relay packets to and from the SOCKS5 proxy server.
        /// </summary>
        SOCKET remote_socket_;

        /// <summary>
        /// Address structure representing the local socket's destination address for outgoing packets.
        /// </summary>
        SOCKADDR_STORAGE local_address_sa_{};

        /// <summary>
        /// Unique pointer to the negotiation context containing authentication and session information.
        /// </summary>
        std::unique_ptr<negotiate_context_t> negotiate_ctx_;

        /// <summary>
        /// Buffer for receiving data from the remote UDP socket (SOCKS5 proxy).
        /// </summary>
        std::array<char, send_receive_buffer_size> from_remote_to_local_buffer_{};

        /// <summary>
        /// WSABUF structure for overlapped I/O operations on the remote UDP socket.
        /// </summary>
        WSABUF remote_recv_buf_{
            static_cast<ULONG>(from_remote_to_local_buffer_.size()), from_remote_to_local_buffer_.data()
        };

        /// <summary>
        /// Per-I/O context for receiving data from the remote UDP socket.
        /// Initialized with nullptr, set later via initialize_io_contexts().
        /// </summary>
        per_io_context_t io_context_recv_from_remote_{ proxy_io_operation::relay_io_read, nullptr, false };

        /// <summary>
        /// Remote peer's address (IPv4 or IPv6) as assigned by the SOCKS5 proxy.
        /// </summary>
        address_type_t remote_peer_address_;

        /// <summary>
        /// Remote peer's UDP port number as assigned by the SOCKS5 proxy.
        /// </summary>
        uint16_t remote_peer_port_;

        /// <summary>
        /// Atomic flag indicating whether the session is ready for removal and cleanup.
        /// </summary>
        std::atomic_bool ready_for_removal_{ false };

    public:
        /**
         * @brief Constructs a SOCKS5 UDP proxy socket instance.
         *
         * Initializes all internal state for a UDP relay session through a SOCKS5 proxy.
         * Sets up the local and remote sockets, packet pool, addressing, negotiation context,
         * and logging configuration. The timestamp is initialized to the current time.
         *
         * @param socks_socket      SOCKS5 TCP control connection socket (for UDP association).
         * @param packet_pool       Shared pointer to the packet pool for buffer management.
         * @param local_socket      Local UDP socket for client communication.
         * @param local_address_sa  Local socket's destination address for outgoing packets.
         * @param remote_socket     Remote UDP socket for communication with the SOCKS5 proxy.
         * @param remote_address    Remote peer address (IPv4 or IPv6) assigned by the proxy.
         * @param remote_port       Remote peer UDP port assigned by the proxy.
         * @param negotiate_ctx     Unique pointer to the negotiation context (auth/session info).
         * @param log_level         Logging level for this socket (default: error).
         * @param log_stream        Optional output stream for logging (default: std::nullopt).
         */
        socks5_udp_proxy_socket(const SOCKET socks_socket, const std::shared_ptr<packet_pool>& packet_pool, const SOCKET& local_socket,
            const SOCKADDR_STORAGE& local_address_sa, const SOCKET remote_socket,
            address_type_t remote_address, const uint16_t remote_port,
            std::unique_ptr<negotiate_context_t> negotiate_ctx,
            const log_level log_level = log_level::error,
            std::shared_ptr<std::ostream> log_stream = nullptr)
            : logger(log_level, std::move(log_stream)),
            timestamp_{ std::chrono::steady_clock::now() },
            socks_socket_(socks_socket),
            packet_pool_(packet_pool),
            local_socket_(local_socket),
            remote_socket_(remote_socket),
            local_address_sa_(local_address_sa),
            negotiate_ctx_(std::move(negotiate_ctx)),
            remote_peer_address_(remote_address),
            remote_peer_port_(remote_port)
        {
        }

        /**
         * @brief Initializes the per-I/O contexts with shared_ptr to this socket.
         *
         * Must be called after the socket is managed by a shared_ptr.
         * Uses shared_from_this() to obtain a shared_ptr to this instance.
         */
        void initialize_io_contexts()
        {
            auto self = this->shared_from_this();
            io_context_recv_from_remote_.proxy_socket_ptr = self;
        }

        /**
         * @brief Destructor. Cleans up sockets and releases resources.
         *
         * Explicitly cancels all pending I/O operations on the sockets before closing them.
         * This ensures that no completion callbacks will be invoked after the socket is destroyed,
         * preventing use-after-free errors. After canceling I/O, closes the remote UDP socket
         * and the SOCKS5 TCP control socket if they are valid.
         */
        ~socks5_udp_proxy_socket()
        {
            if (remote_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
            {
                // Cancel all pending I/O operations on the remote socket before closing
                // This prevents completion callbacks from being invoked after destruction
                CancelIoEx(reinterpret_cast<HANDLE>(remote_socket_), nullptr);  // NOLINT(performance-no-int-to-ptr)
                closesocket(remote_socket_);
                remote_socket_ = INVALID_SOCKET;
            }

            if (socks_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
            {
                // Cancel all pending I/O operations on the SOCKS TCP socket before closing
                CancelIoEx(reinterpret_cast<HANDLE>(socks_socket_), nullptr);  // NOLINT(performance-no-int-to-ptr)
                closesocket(socks_socket_);
                socks_socket_ = INVALID_SOCKET;
            }
        }

        /**
         * @brief Move constructor (deleted).
         *
         * Moving socks5_udp_proxy_socket instances is not safe because:
         * - WSAOVERLAPPED structures cannot be relocated while I/O operations are pending
         * - Per-I/O contexts contain pointers that would become invalid after a move
         * - The class is designed to be used via shared_ptr and managed by the proxy server
         *
         * @param other The socks5_udp_proxy_socket instance to move from (not allowed).
         */
        socks5_udp_proxy_socket(socks5_udp_proxy_socket&& other) = delete;

        /**
         * @brief Move assignment operator (deleted).
         *
         * Moving socks5_udp_proxy_socket instances is not safe because:
         * - WSAOVERLAPPED structures cannot be relocated while I/O operations are pending
         * - Per-I/O contexts contain pointers that would become invalid after a move
         * - The class is designed to be used via shared_ptr and managed by the proxy server
         *
         * @param other The socks5_udp_proxy_socket instance to move from (not allowed).
         * @return Reference to this instance.
         */
        socks5_udp_proxy_socket& operator=(socks5_udp_proxy_socket&& other) = delete;

        /**
         * @brief Deleted copy constructor.
         *
         * Copying is not allowed for socks5_udp_proxy_socket instances as they manage
         * unique resources like sockets and negotiation contexts that cannot be safely copied.
         */
        socks5_udp_proxy_socket(const socks5_udp_proxy_socket&) = delete;

        /**
         * @brief Deleted copy assignment operator.
         *
         * Copy assignment is not allowed for socks5_udp_proxy_socket instances as they manage
         * unique resources like sockets and negotiation contexts that cannot be safely copied.
         */
        socks5_udp_proxy_socket& operator=(const socks5_udp_proxy_socket&) = delete;

        /**
         * @brief Allocates a network packet buffer of the specified size from the packet pool.
         *
         * @param size The minimum required buffer size in bytes.
         * @return Unique pointer to a net_packet_t, or nullptr on failure.
         */
        std::unique_ptr<net_packet_t> allocate_packet(const uint32_t size) const
        {
            return packet_pool_->allocate(size);
        }

        /**
         * @brief Returns a packet buffer to the pool for reuse.
         *
         * The buffer is placed in the appropriate internal pool based on its size.
         * If the pool for that size is full, the buffer is destroyed.
         *
         * @param packet Unique pointer to the packet buffer to free.
         */
        void release_packet(std::unique_ptr<net_packet_t> packet) const
        {
            packet_pool_->free(std::move(packet));
        }

        /**
         * @brief Associates the remote socket with an I/O completion port.
         *
         * @param completion_key The completion key to associate with the socket.
         * @param completion_port Reference to the I/O completion port.
         * @return True if the association succeeded, false otherwise.
         */
        bool associate_to_completion_port(const ULONG_PTR completion_key,
            const netlib::winsys::io_completion_port& completion_port) const
        {
            if (remote_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
                return completion_port.associate_socket(remote_socket_, completion_key);

            return false;
        }

        /**
         * @brief Marks the proxy socket as ready for removal and cleanup.
         *
         * This is typically called when a connection is closed or an error occurs.
         */
        void close_client()
        {
            ready_for_removal_.store(true);
        }

        /**
         * @brief Checks if the proxy socket is ready to be removed.
         *
         * The socket is considered ready for removal if it has been marked as such,
         * or if no packets have been processed for more than 5 minutes.
         *
         * @return True if the socket should be removed, false otherwise.
         */
        bool is_ready_for_removal() const
        {
            using namespace std::chrono_literals;

            if (ready_for_removal_.load() || (std::chrono::steady_clock::now() - timestamp_ > 5min))
                return true;

            return false;
        }

        /**
         * @brief Starts the SOCKS5 UDP proxy session, including negotiation and data relay.
         *
         * Attempts to negotiate credentials for both local and remote sockets. If both negotiations
         * complete immediately (or are not required), the method starts the data relay between the
         * local and remote sockets. If negotiation is asynchronous, data relay will be started
         * later from the negotiation completion handlers.
         *
         * @return true if the data relay was started immediately, false otherwise.
         */
        bool start()
        {
            if (local_negotiate() && (remote_negotiate()))
            {
                // if negotiate phase can be complete immediately (or not needed at all)
                // start data relay here
                return start_data_relay();
            }

            // otherwise start_data_relay should be called from 
            // process_receive_negotiate_complete/process_send_negotiate_complete
            return false;
        }

        /**
         * @brief Handler for completion of a receive operation during negotiation.
         *
         * This static method is intended to be overridden in derived classes to handle
         * protocol-specific negotiation steps when a receive operation completes.
         *
         * @param io_size   Number of bytes received.
         * @param io_context Pointer to the per-I/O context structure for the operation.
         */
        static void process_receive_negotiate_complete(const uint32_t io_size, per_io_context_t* io_context)
        {
        }

        /**
         * @brief Handler for completion of a send operation during negotiation.
         *
         * This static method is intended to be overridden in derived classes to handle
         * protocol-specific negotiation steps when a send operation completes.
         *
         * @param io_size   Number of bytes sent.
         * @param io_context Pointer to the per-I/O context structure for the operation.
         */
        static void process_send_negotiate_complete(const uint32_t io_size, per_io_context_t* io_context)
        {
        }

        /**
         * @brief Handles completion of a receive operation on the data relay path.
         *
         * Updates the session timestamp and relays received data between local and remote sockets.
         * If the data was received from the local socket, it is forwarded to the remote peer via the proxy.
         * If the data was received from the remote socket, it is forwarded to the local client.
         * Handles buffer management and error conditions.
         *
         * @param io_size   Number of bytes received.
         * @param io_context Pointer to the per-I/O context structure for the operation.
         */
        void process_receive_buffer_complete(const uint32_t io_size, per_io_context_t* io_context)
        {
            timestamp_ = std::chrono::steady_clock::now();

            NETLIB_DEBUG("process_receive_buffer_complete: Processing {} bytes from {} socket ({}:{})",
                io_size, io_context->is_local ? "local" : "remote",
                remote_peer_address_, remote_peer_port_);

            if (io_context->is_local == true)
            {
                NETLIB_DEBUG("process_receive_buffer_complete: {}:{} received data from local socket: {} bytes",
                    remote_peer_address_, remote_peer_port_, io_size);

                NETLIB_DEBUG("process_receive_buffer_complete: Allocating I/O context for remote send operation");

                // Use shared_from_this() to get shared_ptr
                if (auto* io_context_send_to_remote = socks5_udp_per_io_context<T>::allocate_io_context(
                    proxy_io_operation::relay_io_write, this->shared_from_this(), false); io_context_send_to_remote)
                {
                    NETLIB_DEBUG("process_receive_buffer_complete: I/O context allocated, forwarding data to remote host");

                    // forward the received data to remote host
                    io_context_send_to_remote->wsa_buf = std::move(io_context->wsa_buf);

                    NETLIB_DEBUG("process_receive_buffer_complete: {}:{} sending {} bytes to remote socket",
                        remote_peer_address_, remote_peer_port_, io_size);

                    if ((::WSASend(
                        remote_socket_,
                        io_context_send_to_remote->wsa_buf.get(),
                        1,
                        nullptr,
                        0,
                        io_context_send_to_remote,
                        nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                    {
                        const auto error = WSAGetLastError();
                        NETLIB_WARNING("process_receive_buffer_complete: WSASend to remote failed with error: {}", error);
                        // Close connection to remote peer in case of error
                        close_client();
                    }
                    else
                    {
                        NETLIB_DEBUG("process_receive_buffer_complete: WSASend to remote initiated successfully");
                    }
                }
                else
                {
                    NETLIB_ERROR("process_receive_buffer_complete: Failed to allocate I/O context for remote send, freeing packet");
                    packet_pool_->free(std::move(io_context->wsa_buf));
                }
            }
            else
            {
                NETLIB_DEBUG("process_receive_buffer_complete: {}:{} received data from remote socket: {} bytes",
                    remote_peer_address_, remote_peer_port_, io_size);

                NETLIB_DEBUG("process_receive_buffer_complete: Allocating I/O context for local send operation");

                // Use shared_from_this() to get shared_ptr
                if (auto* io_context_send_to_local = socks5_udp_per_io_context<T>::allocate_io_context(
                    proxy_io_operation::relay_io_write, this->shared_from_this(), true, io_size);
                    io_context_send_to_local)
                {
                    NETLIB_DEBUG("process_receive_buffer_complete: I/O context allocated, preparing data for local send");

                    io_context_send_to_local->wsa_buf->len = io_size;
                    memmove(io_context_send_to_local->wsa_buf->buf, from_remote_to_local_buffer_.data(), io_size);

                    NETLIB_DEBUG("process_receive_buffer_complete: {}:{} sending {} bytes to local socket",
                        remote_peer_address_, remote_peer_port_, io_size);

                    if ((::WSASendTo(
                        local_socket_,
                        io_context_send_to_local->wsa_buf.get(),
                        1,
                        nullptr,
                        0,
                        reinterpret_cast<sockaddr*>(&local_address_sa_),
                        (address_type_t::af_type == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
                        io_context_send_to_local,
                        nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                    {
                        const auto error = WSAGetLastError();
                        NETLIB_WARNING("process_receive_buffer_complete: WSASendTo to local failed with error: {}", error);
                        // Close connection to remote peer in case of error
                        close_client();
                    }
                    else
                    {
                        NETLIB_DEBUG("process_receive_buffer_complete: WSASendTo to local initiated successfully");
                    }
                }
                else
                {
                    NETLIB_ERROR("process_receive_buffer_complete: Failed to allocate I/O context for local send");
                }

                NETLIB_DEBUG("process_receive_buffer_complete: Initiating new receive operation on remote socket");

                DWORD flags = 0;

                auto ret = WSARecv(remote_socket_, &remote_recv_buf_, 1,
                    nullptr, &flags, &io_context_recv_from_remote_, nullptr);

                if (const auto wsa_error = WSAGetLastError(); ret == SOCKET_ERROR && (ERROR_IO_PENDING != wsa_error))
                {
                    NETLIB_WARNING("process_receive_buffer_complete: WSARecv on remote socket failed with error: {}", wsa_error);
                    close_client();
                }
                else if (ret == SOCKET_ERROR && wsa_error == ERROR_IO_PENDING)
                {
                    NETLIB_DEBUG("process_receive_buffer_complete: WSARecv on remote socket initiated successfully (pending)");
                }
                else
                {
                    NETLIB_DEBUG("process_receive_buffer_complete: WSARecv on remote socket completed immediately");
                }
            }

            NETLIB_DEBUG("process_receive_buffer_complete: Completed processing {} bytes from {} socket",
                io_size, io_context->is_local ? "local" : "remote");
        }

        /**
         * @brief Handles completion of a send operation on the data relay path.
         *
         * This method is called when an asynchronous send operation to either the local or remote socket completes.
         * It logs the completion event (including the direction and number of bytes sent) at debug level.
         * After logging, it releases the per-I/O context and any associated packet buffer to the pool.
         *
         * @param io_size   Number of bytes sent.
         * @param io_context Pointer to the per-I/O context structure for the operation.
         */
        void process_send_buffer_complete(const uint32_t io_size, per_io_context_t* io_context)
        {
            if (io_context->is_local == true)
            {
                // Send to local complete
                NETLIB_DEBUG(
                    "process_send_buffer_complete: {}:{} :send data to locally connected socket complete: {}",
                    remote_peer_address_,
                    remote_peer_port_,
                    io_size);
            }
            else
            {
                // Send to remote complete
                NETLIB_DEBUG(
                    "process_send_buffer_complete: {}:{} :send data to remotely connected socket complete: {}",
                    remote_peer_address_,
                    remote_peer_port_,
                    io_size);
            }

            // free completed packet resource
            socks5_udp_per_io_context<T>::release_io_context(io_context);
        }

        /**
         * @brief Handles completion of an injected buffer operation.
         *
         * This static method is called when a buffer injected into the local or remote socket
         * (for testing or special control flows) has completed its send operation.
         * It releases the associated packet buffer back to the pool and deletes the I/O context.
         *
         * @param packet_pool Shared pointer to the packet pool for buffer management.
         * @param context     Pointer to the per-I/O context structure for the operation.
         */
        static void process_inject_buffer_complete(const std::shared_ptr<packet_pool>& packet_pool, per_io_context_t* context)
        {
            if (context->wsa_buf != nullptr)
                packet_pool->free(std::move(context->wsa_buf));

            delete context;
        }

        /**
         * @brief Sends a block of data into the local UDP socket.
         *
         * Allocates a per-I/O context and a packet buffer from the pool, copies the provided data
         * into the buffer, and initiates an asynchronous send operation to the local socket.
         * If allocation or send fails, resources are released and the method returns false.
         *
         * @param data   Pointer to the data buffer to send.
         * @param length Length of the data to send, in bytes.
         * @param type   Type of proxy I/O operation (default: inject_io_write).
         * @return true if the send operation was successfully initiated, false otherwise.
         */
        bool inject_to_local(const char* data, const uint32_t length,
            proxy_io_operation type = proxy_io_operation::inject_io_write)
        {
            NETLIB_DEBUG("inject_to_local: Starting injection of {} bytes (operation type: {}) to {}:{}",
                length, static_cast<int>(type), remote_peer_address_, remote_peer_port_);

            // Validate input parameters
            if (data == nullptr)
            {
                NETLIB_ERROR("inject_to_local: Data pointer is null, cannot inject to {}:{}",
                    remote_peer_address_, remote_peer_port_);
                return false;
            }

            if (length == 0)
            {
                NETLIB_WARNING("inject_to_local: Injection length is 0, skipping operation for {}:{}",
                    remote_peer_address_, remote_peer_port_);
                return true; // Consider this a successful no-op
            }

            if (local_socket_ == static_cast<SOCKET>(INVALID_SOCKET))
            {
                NETLIB_ERROR("inject_to_local: Local socket is invalid (INVALID_SOCKET) for {}:{}",
                    remote_peer_address_, remote_peer_port_);
                return false;
            }

            NETLIB_DEBUG("inject_to_local: Allocating per-I/O context for local socket injection ({}:{})",
                remote_peer_address_, remote_peer_port_);

            auto context = new(std::nothrow) per_io_context_t{ type, this->shared_from_this(), true };

            if (context == nullptr)
            {
                NETLIB_ERROR("inject_to_local: Failed to allocate per-I/O context for {}:{}",
                    remote_peer_address_, remote_peer_port_);
                return false;
            }

            NETLIB_DEBUG("inject_to_local: Allocating packet buffer of {} bytes from pool for {}:{}",
                length, remote_peer_address_, remote_peer_port_);

            context->wsa_buf = packet_pool_->allocate(length);

            if (!context->wsa_buf)
            {
                NETLIB_ERROR("inject_to_local: Failed to allocate packet buffer of {} bytes for {}:{}",
                    length, remote_peer_address_, remote_peer_port_);
                delete context;
                return false;
            }

            NETLIB_DEBUG("inject_to_local: Packet buffer allocated successfully, copying {} bytes for {}:{}",
                length, remote_peer_address_, remote_peer_port_);

            context->wsa_buf->buf->len = length;
            memmove(context->wsa_buf->buf, data, length);
            context->wsa_buf->len = length;

            NETLIB_DEBUG("inject_to_local: Initiating WSASend to local socket {} with {} bytes for {}:{}",
                static_cast<int>(local_socket_), length, remote_peer_address_, remote_peer_port_);

            if ((::WSASend(
                local_socket_,
                &context->wsa_buf,
                1,
                nullptr,
                0,
                context,
                nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
            {
                const auto error = WSAGetLastError();
                NETLIB_WARNING("inject_to_local: WSASend failed with error: {} for {}:{}",
                    error, remote_peer_address_, remote_peer_port_);

                // Clean up allocated resources
                packet_pool_->free(std::move(context->wsa_buf));
                delete context;
                return false;
            }

            NETLIB_DEBUG("inject_to_local: WSASend initiated successfully for {} bytes to {}:{}",
                length, remote_peer_address_, remote_peer_port_);
            NETLIB_DEBUG("inject_to_local: Injection completed, context and buffer will be cleaned up on completion for {}:{}",
                remote_peer_address_, remote_peer_port_);

            return true;
        }

        /**
         * @brief Sends a block of data into the remote UDP socket (SOCKS5 proxy).
         *
         * Allocates a per-I/O context and a packet buffer from the pool, copies the provided data
         * into the buffer, and initiates an asynchronous send operation to the remote socket.
         * If allocation or send fails, resources are released and the method returns false.
         * If the send fails, the client connection is closed.
         *
         * @param data   Pointer to the data buffer to send.
         * @param length Length of the data to send, in bytes.
         * @param type   Type of proxy I/O operation (default: inject_io_write).
         * @return true if the send operation was successfully initiated, false otherwise.
         */
        bool inject_to_remote(const char* data, const uint32_t length,
            proxy_io_operation type = proxy_io_operation::inject_io_write)
        {
            NETLIB_DEBUG("inject_to_remote: Starting injection of {} bytes (operation type: {}) to {}:{}",
                length, static_cast<int>(type), remote_peer_address_, remote_peer_port_);

            // Validate input parameters
            if (data == nullptr)
            {
                NETLIB_ERROR("inject_to_remote: Data pointer is null, cannot inject to {}:{}",
                    remote_peer_address_, remote_peer_port_);
                return false;
            }

            if (length == 0)
            {
                NETLIB_WARNING("inject_to_remote: Injection length is 0, skipping operation for {}:{}",
                    remote_peer_address_, remote_peer_port_);
                return true; // Consider this a successful no-op
            }

            if (remote_socket_ == static_cast<SOCKET>(INVALID_SOCKET))
            {
                NETLIB_ERROR("inject_to_remote: Remote socket is invalid (INVALID_SOCKET) for {}:{}",
                    remote_peer_address_, remote_peer_port_);
                return false;
            }

            NETLIB_DEBUG("inject_to_remote: Allocating per-I/O context for remote socket injection ({}:{})",
                remote_peer_address_, remote_peer_port_);

            auto context = new(std::nothrow) per_io_context_t{ type, this->shared_from_this(), false };

            if (context == nullptr)
            {
                NETLIB_ERROR("inject_to_remote: Failed to allocate per-I/O context for {}:{}",
                    remote_peer_address_, remote_peer_port_);
                return false;
            }

            NETLIB_DEBUG("inject_to_remote: Allocating packet buffer of {} bytes from pool for {}:{}",
                length, remote_peer_address_, remote_peer_port_);

            context->wsa_buf = packet_pool_->allocate(length);

            if (!context->wsa_buf)
            {
                NETLIB_ERROR("inject_to_remote: Failed to allocate packet buffer of {} bytes for {}:{}",
                    length, remote_peer_address_, remote_peer_port_);
                delete context;
                return false;
            }

            NETLIB_DEBUG("inject_to_remote: Packet buffer allocated successfully, copying {} bytes for {}:{}",
                length, remote_peer_address_, remote_peer_port_);

            context->wsa_buf->buf->len = length;
            memmove(context->wsa_buf->buf, data, length);
            context->wsa_buf->len = length;

            NETLIB_DEBUG("inject_to_remote: Initiating WSASend to remote socket {} with {} bytes for {}:{}",
                static_cast<int>(remote_socket_), length, remote_peer_address_, remote_peer_port_);

            if ((::WSASend(
                remote_socket_,
                &context->wsa_buf,
                1,
                nullptr,
                0,
                context,
                nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
            {
                const auto error = WSAGetLastError();
                NETLIB_WARNING("inject_to_remote: WSASend failed with error: {} for {}:{}",
                    error, remote_peer_address_, remote_peer_port_);

                // Clean up allocated resources
                packet_pool_->free(std::move(context->wsa_buf));
                delete context;

                NETLIB_DEBUG("inject_to_remote: Closing client due to WSASend failure for {}:{}",
                    remote_peer_address_, remote_peer_port_);
                close_client();
                return false;
            }

            NETLIB_DEBUG("inject_to_remote: WSASend initiated successfully for {} bytes to {}:{}",
                length, remote_peer_address_, remote_peer_port_);
            NETLIB_DEBUG("inject_to_remote: Injection completed, context and buffer will be cleaned up on completion for {}:{}",
                remote_peer_address_, remote_peer_port_);

            return true;
        }

    protected:
        /**
          * @brief Performs local-side negotiation for the SOCKS5 UDP proxy session.
          *
          * This method is intended to be overridden in derived classes to implement
          * protocol-specific negotiation logic for the local socket. By default, it
          * returns true, indicating that no negotiation is required or that negotiation
          * completes immediately.
          *
          * @return true if local negotiation is complete or not required, false otherwise.
          */
        static bool local_negotiate()
        {
            return true;
        }

        /**
         * @brief Performs remote-side negotiation for the SOCKS5 UDP proxy session.
         *
         * This method is intended to be overridden in derived classes to implement
         * protocol-specific negotiation logic for the remote socket. By default, it
         * returns true, indicating that no negotiation is required or that negotiation
         * completes immediately.
         *
         * @return true if remote negotiation is complete or not required, false otherwise.
         */
        static bool remote_negotiate()
        {
            return true;
        }

        /**
         * @brief Starts the asynchronous data relay from the remote UDP socket.
         *
         * Initiates an asynchronous receive operation on the remote socket to begin
         * relaying data between the local and remote endpoints. If the operation
         * cannot be started, the client is closed and the method returns false.
         *
         * @return true if the data relay was successfully started, false otherwise.
         */
        bool start_data_relay()
        {
            NETLIB_DEBUG("start_data_relay: Starting UDP data relay initialization for {}:{}",
                remote_peer_address_, remote_peer_port_);

            if (remote_socket_ == static_cast<SOCKET>(INVALID_SOCKET))
            {
                NETLIB_ERROR("start_data_relay: Remote socket is invalid (INVALID_SOCKET) for {}:{}",
                    remote_peer_address_, remote_peer_port_);
                close_client();
                return false;
            }

            NETLIB_DEBUG("start_data_relay: Initiating WSARecv on remote socket {} for {}:{}",
                static_cast<int>(remote_socket_), remote_peer_address_, remote_peer_port_);

            DWORD flags = 0;

            auto ret = WSARecv(remote_socket_, &remote_recv_buf_, 1,
                nullptr, &flags, &io_context_recv_from_remote_, nullptr);

            if (const auto wsa_error = WSAGetLastError(); ret == SOCKET_ERROR && (ERROR_IO_PENDING != wsa_error))
            {
                NETLIB_WARNING("start_data_relay: WSARecv on remote socket failed with error: {} for {}:{}",
                    wsa_error, remote_peer_address_, remote_peer_port_);

                NETLIB_DEBUG("start_data_relay: Closing client due to WSARecv failure for {}:{}",
                    remote_peer_address_, remote_peer_port_);
                close_client();
                return false;
            }
            else if (ret == SOCKET_ERROR && wsa_error == ERROR_IO_PENDING)
            {
                NETLIB_DEBUG("start_data_relay: Remote WSARecv initiated successfully (pending) for {}:{}",
                    remote_peer_address_, remote_peer_port_);
            }
            else
            {
                NETLIB_DEBUG("start_data_relay: Remote WSARecv completed immediately for {}:{}",
                    remote_peer_address_, remote_peer_port_);
            }

            NETLIB_INFO("start_data_relay: UDP data relay successfully initialized for {}:{}",
                remote_peer_address_, remote_peer_port_);

            return true;
        }
    };
}