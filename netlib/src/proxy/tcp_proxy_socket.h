// ReSharper disable CppClangTidyPerformanceNoIntToPtr
#pragma once

namespace proxy
{
    /**
     * @enum connection_status
     * @brief Represents the current state of a proxied client connection.
     *
     * Used to track the lifecycle of a client session within the proxy, from initial connection
     * through establishment and completion.
     *
     * - client_no_change:    No state change (default/initial state).
     * - client_connected:    Client socket has connected but not yet established.
     * - client_established:  Connection between client and remote peer is established.
     * - client_completed:    Session is complete; resources can be cleaned up.
     */
    enum class connection_status : uint8_t
    {
        client_no_change = 0,
        client_connected,
        client_established,
        client_completed,
    };

    /**
     * @class tcp_proxy_socket
     * @brief Forward declaration of the TCP proxy socket class template.
     *
     * This class manages a proxied TCP connection between a local client and a remote server,
     * handling asynchronous I/O and session state.
     *
     * @tparam T Address type (e.g., IPv4 or IPv6).
     */
    template <net::ip_address T>
    class tcp_proxy_socket;

    /**
     * @struct tcp_per_io_context
     * @brief Per-I/O context structure for asynchronous socket operations in the proxy.
     *
     * Inherits from WSAOVERLAPPED and is used to track the state and metadata for each
     * asynchronous I/O operation (read/write) on a socket. Associates the operation with
     * a specific proxy socket instance and indicates whether the operation is for the local
     * or remote endpoint.
     *
     * @tparam T Address type (e.g., IPv4 or IPv6).
     */
    template <net::ip_address T>
    struct tcp_per_io_context : WSAOVERLAPPED
    {
        /**
         * @brief Constructs a per-I/O context for a specific operation and socket.
         * @param io_operation   The type of proxy I/O operation (e.g., read, write).
         * @param socket         Pointer to the associated tcp_proxy_socket instance.
         * @param is_local       True if the operation is for the local socket; false for remote.
         */
        tcp_per_io_context(const proxy_io_operation io_operation, tcp_proxy_socket<T>* socket, const bool is_local)
            : WSAOVERLAPPED{ 0, 0, {{.Offset = 0, .OffsetHigh = 0}}, nullptr },
            io_operation(io_operation),
            proxy_socket_ptr(socket),
            is_local(is_local)
        {
        }

        proxy_io_operation io_operation;      ///< The type of I/O operation (read/write/negotiate/inject).
        tcp_proxy_socket<T>* proxy_socket_ptr;///< Pointer to the associated proxy socket.
        WSABUF wsa_buf{ 0, nullptr };           ///< Buffer for the I/O operation.
        bool is_local;                        ///< True if for local socket, false if for remote.
    };

    /**
     * @class tcp_proxy_server
     * @brief Forward declaration of the TCP proxy server class template.
     *
     * Manages the lifecycle and coordination of multiple tcp_proxy_socket instances.
     *
     * @tparam T Proxy socket type.
     */
    template <typename T>
    class tcp_proxy_server;

    /**
     * @class tcp_proxy_socket
     * @brief Implements a proxied TCP connection between a local client and a remote server.
     *
     * This class manages the lifecycle, state, and asynchronous I/O operations for a single proxied TCP session.
     * It handles data relay, negotiation, and resource cleanup for both the local and remote sockets.
     * The class is designed to be used with Windows overlapped I/O and integrates with an I/O completion port.
     *
     * Key features:
     * - Manages both local and remote sockets for a proxied session.
     * - Handles asynchronous read/write operations using per-I/O context structures.
     * - Provides thread-safe state management and resource cleanup.
     * - Supports negotiation phases before starting data relay.
     * - Integrates with a logging framework for diagnostics.
     * - Supports disabling Nagle's algorithm for low-latency scenarios.
     *
     * Template parameter:
     * @tparam T The address type (e.g., IPv4 or IPv6) used for the proxied connection.
     *
     * Not copyable, but movable.
     */
    template <net::ip_address T>
    class tcp_proxy_socket : public netlib::log::logger<tcp_proxy_socket<T>>
    {
        friend tcp_proxy_server<tcp_proxy_socket>;

    public:
        /**
         * @brief Type alias for the logging level enumeration used by the proxy socket.
         *
         * This alias provides convenient access to the logging level type defined in the logging framework.
         */
        using log_level = netlib::log::log_level;

        /**
         * @brief Type alias for the logger base class used for logging within the proxy socket.
         *
         * This alias allows the proxy socket to use the logging facilities provided by the logger base class.
         */
        using logger = netlib::log::logger<tcp_proxy_socket>;

        /**
         * @brief Type alias for the address type used by the proxy socket (e.g., IPv4 or IPv6).
         *
         * The address type is determined by the template parameter T.
         */
        using address_type_t = T;

        /**
         * @brief Type alias for the negotiation context type used by the proxy socket.
         *
         * This type holds information required for session negotiation, such as credentials or
         * target addresses, and is defined by the address type T.
         */
        using negotiate_context_t = negotiate_context<T>;

        /**
         * @brief Type alias for the per-I/O context structure used for asynchronous operations.
         *
         * This structure encapsulates the state and metadata for each overlapped I/O operation
         * performed by the proxy socket.
         */
        using per_io_context_t = tcp_per_io_context<T>;

    protected:
        /**
         * @brief Size (in bytes) of the internal send/receive buffers for relaying data.
         *
         * This constant defines the buffer size used for both directions of data transfer
         * between the local and remote sockets.
         */
        constexpr static size_t send_receive_buffer_size = 65536;

        /**
         * @brief Socket handle for the locally connected client.
         *
         * Represents the endpoint for the client-side of the proxied connection.
         */
        SOCKET local_socket_;

        /**
         * @brief Socket handle for the remotely connected server.
         *
         * Represents the endpoint for the remote-side of the proxied connection.
         */
        SOCKET remote_socket_;

        /**
         * @brief Negotiation context for this session.
         *
         * Holds session-specific information such as credentials or target addresses,
         * used during the negotiation phase of the proxy connection.
         */
        std::unique_ptr<negotiate_context_t> negotiate_ctx_;

        /**
         * @brief Indicates whether Nagle's algorithm is disabled for the remote socket.
         *
         * When true, disables Nagle's algorithm (TCP_NODELAY) to reduce latency for small packets.
         */
        bool is_disable_nagle_;

        /**
         * @brief Mutex for synchronizing access to I/O operations and state.
         *
         * Ensures thread-safe access to socket state and buffers.
         */
        std::mutex lock_;

        /**
         * @brief Current connection status for this proxy session.
         *
         * Tracks the state of the proxied connection (e.g., connected, established, completed).
         */
        connection_status connection_status_{ connection_status::client_connected };

        /**
         * @brief Buffer for data relayed from the local client to the remote server.
         */
        std::array<char, send_receive_buffer_size> from_local_to_remote_buffer_{};

        /**
         * @brief Buffer for data relayed from the remote server to the local client.
         */
        std::array<char, send_receive_buffer_size> from_remote_to_local_buffer_{};

        /**
         * @brief WSABUF structure for receiving data from the local client.
         */
        WSABUF local_recv_buf_{
            static_cast<ULONG>(from_local_to_remote_buffer_.size()), from_local_to_remote_buffer_.data()
        };

        /**
         * @brief WSABUF structure for sending data to the local client.
         */
        WSABUF local_send_buf_{ 0, nullptr };

        /**
         * @brief WSABUF structure for receiving data from the remote server.
         */
        WSABUF remote_recv_buf_{
            static_cast<ULONG>(from_remote_to_local_buffer_.size()), from_remote_to_local_buffer_.data()
        };

        /**
         * @brief WSABUF structure for sending data to the remote server.
         */
        WSABUF remote_send_buf_{ 0, nullptr };

        /**
         * @brief Timestamp of the last activity on this session.
         *
         * Used for idle timeout and session cleanup logic.
         */
        std::chrono::steady_clock::time_point timestamp_{ std::chrono::steady_clock::now() };

        /**
         * @brief Per-I/O context for receiving data from the local client.
         */
        per_io_context_t io_context_recv_from_local_{ proxy_io_operation::relay_io_read, this, true };

        /**
         * @brief Per-I/O context for receiving data from the remote server.
         */
        per_io_context_t io_context_recv_from_remote_{ proxy_io_operation::relay_io_read, this, false };

        /**
         * @brief Per-I/O context for sending data to the local client.
         */
        per_io_context_t io_context_send_to_local_{ proxy_io_operation::relay_io_write, this, true };

        /**
         * @brief Per-I/O context for sending data to the remote server.
         */
        per_io_context_t io_context_send_to_remote_{ proxy_io_operation::relay_io_write, this, false };

    public:
        /**
         * @brief Constructs a tcp_proxy_socket instance for a proxied TCP session.
         *
         * Initializes the proxy socket with the provided local and remote socket handles,
         * negotiation context, logging configuration, and Nagle's algorithm setting.
         *
         * @param local_socket   The socket handle for the locally connected client.
         * @param remote_socket  The socket handle for the remotely connected server.
         * @param negotiate_ctx  Unique pointer to the negotiation context for this session (e.g., credentials, target address).
         * @param log_level      Logging level for this socket instance (default: error).
         * @param log_stream     Optional output stream for logging (default: std::nullopt).
         * @param disable_nagle  If true, disables Nagle's algorithm (TCP_NODELAY) on the remote socket (default: false).
         */
        tcp_proxy_socket(const SOCKET local_socket, const SOCKET remote_socket,
            std::unique_ptr<negotiate_context_t> negotiate_ctx,
            const log_level log_level = log_level::error,
            std::shared_ptr<std::ostream> log_stream = nullptr,
            const bool disable_nagle = false)
            : logger(log_level, std::move(log_stream)),
            local_socket_(local_socket),
            remote_socket_(remote_socket),
            negotiate_ctx_(std::move(negotiate_ctx)),
            is_disable_nagle_(disable_nagle)
        {
        }

        /**
         * @brief Destructor for the tcp_proxy_socket class.
         *
         * Ensures proper cleanup of resources associated with the proxied TCP session.
         * Acquires a lock to guarantee thread safety during destruction. If the local or remote
         * socket is still valid, it performs a shutdown on both send and receive operations,
         * closes the socket, and marks it as invalid. This prevents resource leaks and ensures
         * that all network resources are released when the proxy socket is destroyed.
         */
        virtual ~tcp_proxy_socket()
        {
            std::lock_guard lock(lock_);

            NETLIB_DEBUG("~tcp_proxy_socket: Starting destructor cleanup");

            if (local_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
            {
                NETLIB_DEBUG("~tcp_proxy_socket: Cleaning up local socket {}", static_cast<int>(local_socket_));

                if (shutdown(local_socket_, SD_BOTH) == SOCKET_ERROR) {
                    const auto error = WSAGetLastError();
                    NETLIB_WARNING("~tcp_proxy_socket: shutdown(local_socket_) failed: {}", error);
                }
                else {
                    NETLIB_DEBUG("~tcp_proxy_socket: Local socket shutdown successful");
                }

                // Cancel all pending I/O before closing
                if (CancelIoEx(reinterpret_cast<HANDLE>(local_socket_), nullptr) == FALSE) {
                    const auto error = GetLastError();
                    if (error != ERROR_NOT_FOUND) {  // ERROR_NOT_FOUND means no pending operations
                        NETLIB_DEBUG("~tcp_proxy_socket: CancelIoEx(local_socket_) returned error: {}", error);
                    }
                }

                if (closesocket(local_socket_) == SOCKET_ERROR) {
                    const auto error = WSAGetLastError();
                    NETLIB_WARNING("~tcp_proxy_socket: closesocket(local_socket_) failed: {}", error);
                }
                else {
                    NETLIB_DEBUG("~tcp_proxy_socket: Local socket closed successfully");
                }

                local_socket_ = INVALID_SOCKET;
            }

            if (remote_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
            {
                NETLIB_DEBUG("~tcp_proxy_socket: Cleaning up remote socket {}", static_cast<int>(remote_socket_));

                if (shutdown(remote_socket_, SD_BOTH) == SOCKET_ERROR) {
                    const auto error = WSAGetLastError();
                    NETLIB_WARNING("~tcp_proxy_socket: shutdown(remote_socket_) failed: {}", error);
                }
                else {
                    NETLIB_DEBUG("~tcp_proxy_socket: Remote socket shutdown successful");
                }

                // Cancel all pending I/O before closing
                if (CancelIoEx(reinterpret_cast<HANDLE>(remote_socket_), nullptr) == FALSE) {
                    const auto error = GetLastError();
                    if (error != ERROR_NOT_FOUND) {  // ERROR_NOT_FOUND means no pending operations
                        NETLIB_DEBUG("~tcp_proxy_socket: CancelIoEx(remote_socket_) returned error: {}", error);
                    }
                }

                if (closesocket(remote_socket_) == SOCKET_ERROR) {
                    const auto error = WSAGetLastError();
                    NETLIB_WARNING("~tcp_proxy_socket: closesocket(remote_socket_) failed: {}", error);
                }
                else {
                    NETLIB_DEBUG("~tcp_proxy_socket: Remote socket closed successfully");
                }

                remote_socket_ = INVALID_SOCKET;
            }

            NETLIB_DEBUG("~tcp_proxy_socket: Destructor cleanup completed");
        }

        /**
         * @brief Copy constructor (deleted).
         *
         * The tcp_proxy_socket class is non-copyable to prevent accidental copying of socket handles,
         * buffers, and other resources. Copying could lead to double-free errors, resource leaks,
         * or undefined behavior in asynchronous I/O operations.
         *
         * @param other The tcp_proxy_socket instance to copy from (not allowed).
         */
        tcp_proxy_socket(const tcp_proxy_socket& other) = delete;

        /**
         * @brief Copy assignment operator (deleted).
         *
         * The tcp_proxy_socket class is non-copyable to ensure unique ownership of sockets and
         * associated resources. Assignment is disabled to prevent resource management issues.
         *
         * @param other The tcp_proxy_socket instance to assign from (not allowed).
         * @return Reference to this tcp_proxy_socket instance.
         */
        tcp_proxy_socket& operator=(const tcp_proxy_socket& other) = delete;

        /**
         * @brief Move constructor for tcp_proxy_socket.
         *
         * Transfers ownership of all resources and state from another tcp_proxy_socket instance to this one.
         * This includes socket handles, negotiation context, buffers, I/O contexts, and connection state.
         * After the move, the source object's socket handles are set to INVALID_SOCKET to prevent double closure.
         *
         * @param other The tcp_proxy_socket instance to move from.
         */
        tcp_proxy_socket(tcp_proxy_socket&& other) noexcept
            : logger(std::move(other)), // Initialize the base class
            local_socket_(other.local_socket_),
            remote_socket_(other.remote_socket_),
            negotiate_ctx_(std::move(other.negotiate_ctx_)),
            is_disable_nagle_(other.is_disable_nagle_),
            connection_status_(other.connection_status_),
            from_local_to_remote_buffer_(other.from_local_to_remote_buffer_),
            from_remote_to_local_buffer_(other.from_remote_to_local_buffer_),
            local_recv_buf_(other.local_recv_buf_),
            local_send_buf_(other.local_send_buf_),
            remote_recv_buf_(other.remote_recv_buf_),
            remote_send_buf_(other.remote_send_buf_),
            timestamp_(other.timestamp_),
            io_context_recv_from_local_(std::move(other.io_context_recv_from_local_)),
            io_context_recv_from_remote_(std::move(other.io_context_recv_from_remote_)),
            io_context_send_to_local_(std::move(other.io_context_send_to_local_)),
            io_context_send_to_remote_(std::move(other.io_context_send_to_remote_))
        {
            other.local_socket_ = INVALID_SOCKET;
            other.remote_socket_ = INVALID_SOCKET;
        }

        /**
         * @brief Move assignment operator for tcp_proxy_socket.
         *
         * Transfers ownership of all resources and state from another tcp_proxy_socket instance to this one,
         * after releasing any resources currently held by this instance. Ensures thread safety by locking
         * both instances during the operation. After the move, the source object's socket handles are set
         * to INVALID_SOCKET to prevent double closure.
         *
         * @param other The tcp_proxy_socket instance to move from.
         * @return Reference to this tcp_proxy_socket instance.
         */
        tcp_proxy_socket& operator=(tcp_proxy_socket&& other) noexcept
        {
            if (this != &other)
            {
                std::scoped_lock lock(lock_, other.lock_);

                logger::operator=(std::move(other)); // Assign the base class

                local_socket_ = other.local_socket_;
                other.local_socket_ = INVALID_SOCKET;
                remote_socket_ = other.remote_socket_;
                other.remote_socket_ = INVALID_SOCKET;
                negotiate_ctx_ = std::move(other.negotiate_ctx_);
                is_disable_nagle_ = other.is_disable_nagle_;
                connection_status_ = other.connection_status_;
                from_local_to_remote_buffer_ = other.from_local_to_remote_buffer_;
                from_remote_to_local_buffer_ = other.from_remote_to_local_buffer_;
                local_recv_buf_ = other.local_recv_buf_;
                local_send_buf_ = other.local_send_buf_;
                remote_recv_buf_ = other.remote_recv_buf_;
                remote_send_buf_ = other.remote_send_buf_;
                timestamp_ = other.timestamp_;
                io_context_recv_from_local_ = std::move(other.io_context_recv_from_local_);
                io_context_recv_from_remote_ = std::move(other.io_context_recv_from_remote_);
                io_context_send_to_local_ = std::move(other.io_context_send_to_local_);
                io_context_send_to_remote_ = std::move(other.io_context_send_to_remote_);
            }
            return *this;
        }

        /**
         * @brief Associates both the local and remote sockets with a Windows I/O completion port.
         *
         * This method registers the local and remote sockets of the proxied session with the provided
         * I/O completion port, using the specified completion key. This enables asynchronous I/O operations
         * on both sockets to be managed and dispatched by the completion port's thread pool.
         *
         * On success, the connection status is set to @ref connection_status::client_established.
         *
         * @param completion_key   The key value to associate with both sockets for I/O completion events.
         * @param completion_port  Reference to the I/O completion port wrapper managing asynchronous operations.
         * @return true if both sockets were successfully associated with the completion port; false otherwise.
         *
         * @note Both sockets must be valid (not INVALID_SOCKET) for association to succeed.
         *       If either association fails, the method returns false and the session is not fully established.
         */
        bool associate_to_completion_port(const ULONG_PTR completion_key, winsys::io_completion_port& completion_port)
        {
            NETLIB_DEBUG("associate_to_completion_port: Starting association with completion key {}", completion_key);

            connection_status_ = connection_status::client_established;
            NETLIB_DEBUG("associate_to_completion_port: Connection status set to client_established");

            if (local_socket_ == static_cast<SOCKET>(INVALID_SOCKET))
            {
                NETLIB_ERROR("associate_to_completion_port: Local socket is invalid (INVALID_SOCKET)");
                return false;
            }

            if (remote_socket_ == static_cast<SOCKET>(INVALID_SOCKET))
            {
                NETLIB_ERROR("associate_to_completion_port: Remote socket is invalid (INVALID_SOCKET)");
                return false;
            }

            NETLIB_DEBUG("associate_to_completion_port: Associating local socket {} with completion port",
                static_cast<int>(local_socket_));

            const bool local_result = completion_port.associate_socket(local_socket_, completion_key);
            if (!local_result)
            {
                NETLIB_ERROR("associate_to_completion_port: Failed to associate local socket {} with completion port",
                    static_cast<int>(local_socket_));
                return false;
            }

            NETLIB_DEBUG("associate_to_completion_port: Local socket {} associated successfully",
                static_cast<int>(local_socket_));

            NETLIB_DEBUG("associate_to_completion_port: Associating remote socket {} with completion port",
                static_cast<int>(remote_socket_));

            const bool remote_result = completion_port.associate_socket(remote_socket_, completion_key);
            if (!remote_result)
            {
                NETLIB_ERROR("associate_to_completion_port: Failed to associate remote socket {} with completion port",
                    static_cast<int>(remote_socket_));
                return false;
            }

            NETLIB_DEBUG("associate_to_completion_port: Remote socket {} associated successfully",
                static_cast<int>(remote_socket_));

            NETLIB_DEBUG("associate_to_completion_port: Successfully associated both sockets (local: {}, remote: {}) with completion key {}",
                static_cast<int>(local_socket_),
                static_cast<int>(remote_socket_),
                completion_key);

            return true;
        }

        /**
         * @brief Closes the local or remote client socket and updates session state.
         *
         * This method safely shuts down and closes either the local or remote socket, depending on the
         * is_local parameter. It also updates the connection status and resets the appropriate I/O buffer
         * length to zero, based on whether the operation is for a receive or send path. If both sockets
         * are closed, the session is considered complete and ready for cleanup.
         *
         * Thread safety is ensured by acquiring a lock, unless AlreadyLocked is set to true, in which case
         * the caller is responsible for holding the lock.
         *
         * @tparam AlreadyLocked  If true, assumes the caller already holds the lock; otherwise, acquires it internally.
         * @param is_receive      If true, resets the receive buffer length; otherwise, resets the send buffer length.
         * @param is_local        If true, closes the local socket; otherwise, closes the remote socket.
         */
        template <bool AlreadyLocked = false>
        void close_client(const bool is_receive, const bool is_local)
        {
            std::unique_lock lock(lock_, std::defer_lock);

            if constexpr (!AlreadyLocked)
            {
                lock.lock();
            }

            NETLIB_DEBUG("close_client: Starting cleanup (is_receive: {}, is_local: {})",
                is_receive, is_local);

            if (is_local)
            {
                NETLIB_DEBUG("close_client: Processing local socket closure");

                if (local_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
                {
                    NETLIB_DEBUG("close_client: Closing local socket {}",
                        static_cast<int>(local_socket_));

                    if (shutdown(local_socket_, SD_BOTH) == SOCKET_ERROR) {
                        const auto error = WSAGetLastError();
                        NETLIB_WARNING("close_client: shutdown(local_socket_) failed: {}", error);
                    }
                    else {
                        NETLIB_DEBUG("close_client: Local socket shutdown successful");
                    }

                    // Cancel all pending I/O before closing
                    if (CancelIoEx(reinterpret_cast<HANDLE>(local_socket_), nullptr) == FALSE) {
                        const auto error = GetLastError();
                        if (error != ERROR_NOT_FOUND) {  // ERROR_NOT_FOUND means no pending operations
                            NETLIB_DEBUG("close_client: CancelIoEx(local_socket_) returned error: {}", error);
                        }
                    }
                    else {
                        NETLIB_DEBUG("close_client: Local socket I/O cancellation successful");
                    }

                    if (closesocket(local_socket_) == SOCKET_ERROR) {
                        const auto error = WSAGetLastError();
                        NETLIB_WARNING("close_client: closesocket(local_socket_) failed: {}", error);
                    }
                    else {
                        NETLIB_DEBUG("close_client: Local socket closed successfully");
                    }

                    local_socket_ = INVALID_SOCKET;
                    connection_status_ = connection_status::client_completed;
                    NETLIB_DEBUG("close_client: Connection status set to client_completed");
                }
                else {
                    NETLIB_DEBUG("close_client: Local socket already invalid, skipping closure");
                }

                if (is_receive)
                {
                    local_recv_buf_.len = 0;
                    NETLIB_DEBUG("close_client: Reset local receive buffer length");
                }
                else
                {
                    local_send_buf_.len = 0;
                    NETLIB_DEBUG("close_client: Reset local send buffer length");
                }

                if (remote_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
                {
                    NETLIB_DEBUG("close_client: Also closing remote socket {} due to local closure",
                        static_cast<int>(remote_socket_));

                    if (shutdown(remote_socket_, SD_BOTH) == SOCKET_ERROR) {
                        const auto error = WSAGetLastError();
                        NETLIB_WARNING("close_client: shutdown(remote_socket_) failed: {}", error);
                    }
                    else {
                        NETLIB_DEBUG("close_client: Remote socket shutdown successful");
                    }

                    // Cancel all pending I/O before closing
                    if (CancelIoEx(reinterpret_cast<HANDLE>(remote_socket_), nullptr) == FALSE) {
                        const auto error = GetLastError();
                        if (error != ERROR_NOT_FOUND) {  // ERROR_NOT_FOUND means no pending operations
                            NETLIB_DEBUG("close_client: CancelIoEx(remote_socket_) returned error: {}", error);
                        }
                    }
                    else {
                        NETLIB_DEBUG("close_client: Remote socket I/O cancellation successful");
                    }

                    if (closesocket(remote_socket_) == SOCKET_ERROR) {
                        const auto error = WSAGetLastError();
                        NETLIB_WARNING("close_client: closesocket(remote_socket_) failed: {}", error);
                    }
                    else {
                        NETLIB_DEBUG("close_client: Remote socket closed successfully");
                    }

                    remote_socket_ = INVALID_SOCKET;
                }
                else {
                    NETLIB_DEBUG("close_client: Remote socket already invalid, skipping closure");
                }
            }
            else
            {
                NETLIB_DEBUG("close_client: Processing remote socket closure");

                if (remote_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
                {
                    NETLIB_DEBUG("close_client: Closing remote socket {}",
                        static_cast<int>(remote_socket_));

                    if (shutdown(remote_socket_, SD_BOTH) == SOCKET_ERROR) {
                        const auto error = WSAGetLastError();
                        NETLIB_WARNING("close_client: shutdown(remote_socket_) failed: {}", error);
                    }
                    else {
                        NETLIB_DEBUG("close_client: Remote socket shutdown successful");
                    }

                    // Cancel all pending I/O before closing
                    if (CancelIoEx(reinterpret_cast<HANDLE>(remote_socket_), nullptr) == FALSE) {
                        const auto error = GetLastError();
                        if (error != ERROR_NOT_FOUND) {  // ERROR_NOT_FOUND means no pending operations
                            NETLIB_DEBUG("close_client: CancelIoEx(remote_socket_) returned error: {}", error);
                        }
                    }
                    else {
                        NETLIB_DEBUG("close_client: Remote socket I/O cancellation successful");
                    }

                    if (closesocket(remote_socket_) == SOCKET_ERROR) {
                        const auto error = WSAGetLastError();
                        NETLIB_WARNING("close_client: closesocket(remote_socket_) failed: {}", error);
                    }
                    else {
                        NETLIB_DEBUG("close_client: Remote socket closed successfully");
                    }

                    remote_socket_ = INVALID_SOCKET;
                    connection_status_ = connection_status::client_completed;
                    NETLIB_DEBUG("close_client: Connection status set to client_completed");
                }
                else {
                    NETLIB_DEBUG("close_client: Remote socket already invalid, skipping closure");
                }

                if (is_receive)
                {
                    remote_recv_buf_.len = 0;
                    NETLIB_DEBUG("close_client: Reset remote receive buffer length");
                }
                else
                {
                    remote_send_buf_.len = 0;
                    NETLIB_DEBUG("close_client: Reset remote send buffer length");
                }

                if (local_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
                {
                    NETLIB_DEBUG("close_client: Also closing local socket {} due to remote closure",
                        static_cast<int>(local_socket_));

                    if (shutdown(local_socket_, SD_BOTH) == SOCKET_ERROR) {
                        const auto error = WSAGetLastError();
                        NETLIB_WARNING("close_client: shutdown(local_socket_) failed: {}", error);
                    }
                    else {
                        NETLIB_DEBUG("close_client: Local socket shutdown successful");
                    }

                    // Cancel all pending I/O before closing
                    if (CancelIoEx(reinterpret_cast<HANDLE>(local_socket_), nullptr) == FALSE) {
                        const auto error = GetLastError();
                        if (error != ERROR_NOT_FOUND) {  // ERROR_NOT_FOUND means no pending operations
                            NETLIB_DEBUG("close_client: CancelIoEx(local_socket_) returned error: {}", error);
                        }
                    }
                    else {
                        NETLIB_DEBUG("close_client: Local socket I/O cancellation successful");
                    }

                    if (closesocket(local_socket_) == SOCKET_ERROR) {
                        const auto error = WSAGetLastError();
                        NETLIB_WARNING("close_client: closesocket(local_socket_) failed: {}", error);
                    }
                    else {
                        NETLIB_DEBUG("close_client: Local socket closed successfully");
                    }

                    local_socket_ = INVALID_SOCKET;
                }
                else {
                    NETLIB_DEBUG("close_client: Local socket already invalid, skipping closure");
                }
            }

            NETLIB_DEBUG("close_client: Cleanup completed (is_receive: {}, is_local: {})",
                is_receive, is_local);
        }

        /**
         * @brief Determines if the proxy session is ready for removal and performs idle cleanup.
         *
         * This method checks whether both the local and remote sockets are closed and all I/O buffers
         * are empty, indicating that the session can be safely removed and its resources reclaimed.
         * If the session is not yet ready for removal, it also checks for an extreme idle timeout (1 hour)
         * as a safety measure to handle truly abandoned connections that somehow didn't get closed properly.
         *
         * The method prioritizes natural connection lifecycle management over timeout-based forced closure.
         * Modern web applications (WebSockets, Server-Sent Events, long-polling) can legitimately remain
         * idle for extended periods, so the timeout serves only as a safety net for abandoned connections.
         *
         * Thread safety is ensured by acquiring a lock on the session state.
         *
         * @return true if the session is fully closed and all buffers are empty (ready for removal),
         *         false otherwise.
         *
         * @note This method may be called periodically by a cleanup thread to manage session lifetimes.
         *       It is safe to call concurrently with other session operations.
         *       The 1-hour safety timeout prevents memory leaks from truly abandoned connections while
         *       allowing legitimate long-lived connections to function normally.
         */
        bool is_ready_for_removal()
        {
            using namespace std::chrono_literals;

            std::lock_guard lock(lock_);

            NETLIB_DEBUG("is_ready_for_removal: Checking session readiness for removal");

            // Check if both sockets are closed
            const bool sockets_closed = (remote_socket_ == static_cast<SOCKET>(INVALID_SOCKET)) &&
                (local_socket_ == static_cast<SOCKET>(INVALID_SOCKET));

            if (sockets_closed)
            {
                NETLIB_DEBUG("is_ready_for_removal: Both sockets are closed, checking buffer states");
                NETLIB_DEBUG("is_ready_for_removal: Buffer lengths - remote_send: {}, local_send: {}, remote_recv: {}, local_recv: {}",
                    remote_send_buf_.len, local_send_buf_.len, remote_recv_buf_.len, local_recv_buf_.len);

                // If both sockets are closed, force-reset all buffer lengths
                // The connection is dead, so any remaining data cannot be transmitted
                if (remote_send_buf_.len != 0 || local_send_buf_.len != 0 || 
                    remote_recv_buf_.len != 0 || local_recv_buf_.len != 0)
                {
                    NETLIB_WARNING("is_ready_for_removal: Sockets closed with non-empty buffers, forcing buffer reset (data lost: remote_send={}, local_send={}, remote_recv={}, local_recv={})",
                        remote_send_buf_.len, local_send_buf_.len, remote_recv_buf_.len, local_recv_buf_.len);
                    
                    remote_send_buf_.len = 0;
                    local_send_buf_.len = 0;
                    remote_recv_buf_.len = 0;
                    local_recv_buf_.len = 0;
                }

                NETLIB_INFO("is_ready_for_removal: Session is ready for removal - all sockets closed and buffers cleared");
                return true;
            }
            else
            {
                NETLIB_DEBUG("is_ready_for_removal: Sockets still open - local: {}, remote: {}",
                    local_socket_ == static_cast<SOCKET>(INVALID_SOCKET) ? "closed" : "open",
                    remote_socket_ == static_cast<SOCKET>(INVALID_SOCKET) ? "closed" : "open");
            }

            // Only check for extreme timeout as a safety measure (1 hour instead of 2 minutes)
            // This handles truly abandoned connections that somehow didn't get closed properly
            const auto current_time = std::chrono::steady_clock::now();
            const auto idle_duration = current_time - timestamp_;
            const auto idle_seconds = std::chrono::duration_cast<std::chrono::seconds>(idle_duration).count();

            NETLIB_DEBUG("is_ready_for_removal: Session idle time: {} seconds (safety timeout: 3600 seconds)",
                idle_seconds);

            if (idle_duration > 1h)  // Changed from 120s to 1 hour as safety measure
            {
                NETLIB_WARNING("is_ready_for_removal: Session has been idle for {} seconds (1 hour), performing safety cleanup", idle_seconds);

                if (sockets_closed)
                {
                    NETLIB_DEBUG("is_ready_for_removal: Sockets already closed, performing buffer cleanup");

                    // Force reset all buffers
                    remote_send_buf_.len = 0;
                    local_send_buf_.len = 0;
                    remote_recv_buf_.len = 0;
                    local_recv_buf_.len = 0;

                    NETLIB_DEBUG("is_ready_for_removal: Buffer cleanup completed for abandoned session");
                }
                else
                {
                    NETLIB_WARNING("is_ready_for_removal: Sockets still open after 1 hour idle - likely abandoned connection, performing safety closure");

                    if (local_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
                    {
                        NETLIB_WARNING("is_ready_for_removal: Closing abandoned local socket {}",
                            static_cast<int>(local_socket_));
                    }

                    if (remote_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
                    {
                        NETLIB_WARNING("is_ready_for_removal: Closing abandoned remote socket {}",
                            static_cast<int>(remote_socket_));
                    }

                    close_client<true>(false, true);
                    close_client<true>(false, false);

                    // Extend timestamp by 1 minute to avoid immediate re-cleanup attempts
                    timestamp_ += 1min;

                    NETLIB_DEBUG("is_ready_for_removal: Safety closure completed, timestamp extended by 1 minute");
                }
            }
            else
            {
                NETLIB_DEBUG("is_ready_for_removal: Session within safety timeout, {} seconds remaining",
                    3600 - idle_seconds);
            }

            NETLIB_DEBUG("is_ready_for_removal: Session not ready for removal");
            return false;
        }

        /**
         * @brief Starts the proxied TCP session, performing negotiation and initiating data relay.
         *
         * This method attempts to negotiate credentials or session parameters for both the local and remote sockets.
         * If Nagle's algorithm is to be disabled for the remote socket, it sets the TCP_NODELAY option.
         *
         * The negotiation is performed by calling the virtual methods @ref local_negotiate and @ref remote_negotiate.
         * If both negotiations succeed (or are not required), the method immediately starts the data relay between
         * the local and remote endpoints by calling @ref start_data_relay.
         *
         * If negotiation is asynchronous or requires additional steps, the data relay should be started later
         * from @ref process_receive_negotiate_complete or @ref process_send_negotiate_complete.
         *
         * @return true if the data relay was started immediately (negotiation succeeded or not needed),
         *         false otherwise (negotiation is pending or failed).
         *
         * @note This method is typically called after the sockets are associated with the I/O completion port
         *       and the session is ready to begin.
         */
        virtual bool start()
        {
            NETLIB_DEBUG("start: Starting proxy session initialization");
            NETLIB_DEBUG("start: Local socket: {}, Remote socket: {}",
                static_cast<int>(local_socket_), static_cast<int>(remote_socket_));

            if (is_disable_nagle_)
            {
                NETLIB_DEBUG("start: Nagle's algorithm disabled, setting TCP_NODELAY on remote socket");

                auto i = 1;
                const int result = setsockopt(remote_socket_, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char*>(&i), sizeof(i));

                if (result == SOCKET_ERROR)
                {
                    const auto error = WSAGetLastError();
                    NETLIB_WARNING("start: Failed to set TCP_NODELAY on remote socket: {}", error);
                }
                else
                {
                    NETLIB_DEBUG("start: TCP_NODELAY successfully set on remote socket");
                }
            }
            else
            {
                NETLIB_DEBUG("start: Nagle's algorithm enabled, TCP_NODELAY not set");
            }

            NETLIB_DEBUG("start: Beginning negotiation phase");

            NETLIB_DEBUG("start: Initiating local negotiation");
            const bool local_negotiate_result = local_negotiate();

            if (local_negotiate_result)
            {
                NETLIB_DEBUG("start: Local negotiation completed successfully");
            }
            else
            {
                NETLIB_DEBUG("start: Local negotiation is pending or failed");
            }

            NETLIB_DEBUG("start: Initiating remote negotiation");
            const bool remote_negotiate_result = remote_negotiate();

            if (remote_negotiate_result)
            {
                NETLIB_DEBUG("start: Remote negotiation completed successfully");
            }
            else
            {
                NETLIB_DEBUG("start: Remote negotiation is pending or failed");
            }

            if (local_negotiate_result && remote_negotiate_result)
            {
                NETLIB_DEBUG("start: Both negotiations completed successfully, starting data relay immediately");

                // if negotiate phase can be complete immediately (or not needed at all)
                // start data relay here
                const bool data_relay_result = start_data_relay();

                if (data_relay_result)
                {
                    NETLIB_INFO("start: Proxy session started successfully with immediate data relay");
                }
                else
                {
                    NETLIB_WARNING("start: Failed to start data relay after successful negotiations");
                }

                return data_relay_result;
            }

            NETLIB_DEBUG("start: Negotiation is pending or incomplete, data relay will be started later");
            NETLIB_DEBUG("start: Data relay will be initiated from process_receive_negotiate_complete or process_send_negotiate_complete");

            // otherwise start_data_relay should be called from 
            // process_receive_negotiate_complete/process_send_negotiate_complete
            return false;
        }

        /**
         * @brief Called when a receive or send negotiation operation completes.
         *
         * These virtual methods are invoked upon completion of the negotiation phase for either
         * receiving or sending on the local or remote socket. They are typically used in protocols
         * that require a handshake or authentication step before data relay can begin (e.g., SOCKS5).
         *
         * The default implementation simply updates the session's activity timestamp and is thread-safe.
         * Derived classes can override these methods to implement protocol-specific negotiation logic,
         * such as processing authentication responses or advancing the negotiation state machine.
         *
         * @param io_size     The number of bytes transferred during the negotiation operation.
         * @param io_context  Pointer to the per-I/O context structure associated with the operation.
         */
        virtual void process_receive_negotiate_complete(const uint32_t io_size, per_io_context_t* io_context)
        {
            std::lock_guard lock(lock_);
            timestamp_ = std::chrono::steady_clock::now();
        }

        /**
         * @brief Called when a send negotiation operation completes.
         *
         * See @ref process_receive_negotiate_complete for details. The default implementation
         * updates the session's activity timestamp. Override in derived classes to handle
         * protocol-specific negotiation completion for send operations.
         *
         * @param io_size     The number of bytes transferred during the negotiation operation.
         * @param io_context  Pointer to the per-I/O context structure associated with the operation.
         */
        virtual void process_send_negotiate_complete(const uint32_t io_size, per_io_context_t* io_context)
        {
            std::lock_guard lock(lock_);
            timestamp_ = std::chrono::steady_clock::now();
        }

        /**
         * @brief Handles completion of an asynchronous receive operation for the proxy session.
         *
         * This method is called when a receive operation on either the local or remote socket completes.
         * It updates the session's activity timestamp and processes the received data according to the
         * current connection status:
         *
         * - If the session is completed, it resets the appropriate receive buffer length to zero.
         * - If the session is established, it relays the received data to the opposite endpoint,
         *   manages cyclic buffer pointers, and initiates further asynchronous receive operations as needed.
         *   If an error occurs during forwarding, the corresponding socket is closed.
         *
         * The method ensures thread safety by acquiring a lock on the session state.
         * It also logs debug information about data transfer events.
         *
         * @param io_size     The number of bytes received in the operation.
         * @param io_context  Pointer to the per-I/O context structure associated with this operation.
         *
         * @note This method is typically invoked by the I/O completion port thread when a receive
         *       operation completes. It is safe to override in derived classes for protocol-specific
         *       data handling.
         */
        virtual void process_receive_buffer_complete(const uint32_t io_size, per_io_context_t* io_context)
        {
            std::lock_guard lock(lock_);

            timestamp_ = std::chrono::steady_clock::now();

            NETLIB_DEBUG("process_receive_buffer_complete: Processing {} bytes from {} socket",
                io_size, io_context->is_local ? "local" : "remote");

            switch (connection_status_)
            {
            case connection_status::client_completed:
            {
                NETLIB_DEBUG("process_receive_buffer_complete: Connection already completed, resetting buffer");

                if (io_context->is_local)
                {
                    local_recv_buf_.len = 0;
                    NETLIB_DEBUG("process_receive_buffer_complete: Reset local receive buffer length");
                }
                else
                {
                    remote_recv_buf_.len = 0;
                    NETLIB_DEBUG("process_receive_buffer_complete: Reset remote receive buffer length");
                }

                break;
            }
            case connection_status::client_established:
            {
                NETLIB_DEBUG("process_receive_buffer_complete: Connection established, processing data relay");

                if (io_context->is_local)
                {
                    NETLIB_DEBUG("process_receive_buffer_complete: Data received from local socket: {} bytes", io_size);

                    // data received from locally connected socket
                    if (remote_send_buf_.len == 0)
                    {
                        NETLIB_DEBUG("process_receive_buffer_complete: No remote send in progress, forwarding to remote");

                        // if there is no "send to remotely connected socket" in progress
                        // then forward the received data to remote host
                        remote_send_buf_.buf = local_recv_buf_.buf;
                        remote_send_buf_.len = io_size;

                        NETLIB_DEBUG("process_receive_buffer_complete: Sending {} bytes to remote socket", io_size);

                        if ((::WSASend(
                            remote_socket_,
                            &remote_send_buf_,
                            1,
                            nullptr,
                            0,
                            &io_context_send_to_remote_,
                            nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                        {
                            const auto error = WSAGetLastError();
                            NETLIB_WARNING("process_receive_buffer_complete: WSASend to remote failed: {}", error);
                            // Close connection to remote peer in case of error
                            close_client<true>(false, false);
                        }
                        else
                        {
                            NETLIB_DEBUG("process_receive_buffer_complete: WSASend to remote initiated successfully");
                        }
                    }
                    else
                    {
                        NETLIB_DEBUG("process_receive_buffer_complete: Remote send already in progress (len={}), buffering data", remote_send_buf_.len);
                    }

                    // shift the receive buffer for the amount of received data
                    // buffer is cyclic, adjust the available buffer size
                    // if end of the buffer is reached then go from the start
                    local_recv_buf_.buf += io_size;
                    NETLIB_DEBUG("process_receive_buffer_complete: Advanced local receive buffer by {} bytes", io_size);

                    if (local_recv_buf_.buf > remote_send_buf_.buf)
                    {
                        if (local_recv_buf_.buf < from_local_to_remote_buffer_.data() + from_local_to_remote_buffer_.size())
                        {
                            local_recv_buf_.len = static_cast<ULONG>(from_local_to_remote_buffer_.data() +
                                from_local_to_remote_buffer_.size() - local_recv_buf_.buf);
                            NETLIB_DEBUG("process_receive_buffer_complete: Set local recv buffer len to {} (within buffer)", local_recv_buf_.len);
                        }
                        else
                        {
                            local_recv_buf_.buf = from_local_to_remote_buffer_.data();
                            local_recv_buf_.len = static_cast<ULONG>(remote_send_buf_.buf -
                                from_local_to_remote_buffer_.data());
                            NETLIB_DEBUG("process_receive_buffer_complete: Wrapped local recv buffer, len set to {}", local_recv_buf_.len);
                        }
                    }
                    else
                    {
                        local_recv_buf_.len = static_cast<ULONG>(remote_send_buf_.buf - local_recv_buf_.buf);
                        NETLIB_DEBUG("process_receive_buffer_complete: Set local recv buffer len to {} (normal case)", local_recv_buf_.len);
                    }

                    // Initiate the new receive if we have space in the receive buffer
                    if (local_recv_buf_.len)
                    {
                        NETLIB_DEBUG("process_receive_buffer_complete: Initiating new local receive with buffer size {}", local_recv_buf_.len);

                        DWORD flags = 0;

                        if ((::WSARecv(
                            local_socket_,
                            &local_recv_buf_,
                            1,
                            nullptr,
                            &flags,
                            &io_context_recv_from_local_,
                            nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                        {
                            const auto error = WSAGetLastError();
                            NETLIB_WARNING("process_receive_buffer_complete: WSARecv from local failed: {}", error);
                            // Close connection to local peer in case of error
                            close_client<true>(true, true);
                        }
                        else
                        {
                            NETLIB_DEBUG("process_receive_buffer_complete: New local WSARecv initiated successfully");
                        }
                    }
                    else
                    {
                        NETLIB_DEBUG("process_receive_buffer_complete: No space in local receive buffer, skipping new receive");
                    }
                }
                else
                {
                    NETLIB_DEBUG("process_receive_buffer_complete: Data received from remote socket: {} bytes", io_size);

                    // data received from remotely connected socket
                    if (local_send_buf_.len == 0)
                    {
                        NETLIB_DEBUG("process_receive_buffer_complete: No local send in progress, forwarding to local");

                        // if there is no "send to locally connected socket" in progress
                        // then forward the received data to local host
                        local_send_buf_.buf = remote_recv_buf_.buf;
                        local_send_buf_.len = io_size;

                        NETLIB_DEBUG("process_receive_buffer_complete: Sending {} bytes to local socket", io_size);

                        if ((::WSASend(
                            local_socket_,
                            &local_send_buf_,
                            1,
                            nullptr,
                            0,
                            &io_context_send_to_local_,
                            nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                        {
                            const auto error = WSAGetLastError();
                            NETLIB_WARNING("process_receive_buffer_complete: WSASend to local failed: {}", error);
                            // Close connection to local peer in case of error
                            close_client<true>(false, true);
                        }
                        else
                        {
                            NETLIB_DEBUG("process_receive_buffer_complete: WSASend to local initiated successfully");
                        }
                    }
                    else
                    {
                        NETLIB_DEBUG("process_receive_buffer_complete: Local send already in progress (len={}), buffering data", local_send_buf_.len);
                    }

                    // shift the receive buffer for the amount of received data
                    // buffer is cyclic, adjust the available buffer size
                    // if end of the buffer is reached then go from the start
                    remote_recv_buf_.buf += io_size;
                    NETLIB_DEBUG("process_receive_buffer_complete: Advanced remote receive buffer by {} bytes", io_size);

                    if (remote_recv_buf_.buf > local_send_buf_.buf)
                    {
                        if (remote_recv_buf_.buf < from_remote_to_local_buffer_.data() +
                            from_remote_to_local_buffer_.size())
                        {
                            remote_recv_buf_.len = static_cast<DWORD>(from_remote_to_local_buffer_.data() +
                                from_remote_to_local_buffer_.size() - remote_recv_buf_.buf);
                            NETLIB_DEBUG("process_receive_buffer_complete: Set remote recv buffer len to {} (within buffer)", remote_recv_buf_.len);
                        }
                        else
                        {
                            remote_recv_buf_.buf = from_remote_to_local_buffer_.data();
                            remote_recv_buf_.len = static_cast<DWORD>(local_send_buf_.buf -
                                from_remote_to_local_buffer_.data());
                            NETLIB_DEBUG("process_receive_buffer_complete: Wrapped remote recv buffer, len set to {}", remote_recv_buf_.len);
                        }
                    }
                    else
                    {
                        remote_recv_buf_.len = static_cast<DWORD>(local_send_buf_.buf - remote_recv_buf_.buf);
                        NETLIB_DEBUG("process_receive_buffer_complete: Set remote recv buffer len to {} (normal case)", remote_recv_buf_.len);
                    }

                    // initiate the new receive if we have space in receive buffer
                    if (remote_recv_buf_.len)
                    {
                        NETLIB_DEBUG("process_receive_buffer_complete: Initiating new remote receive with buffer size {}", remote_recv_buf_.len);

                        DWORD flags = 0;

                        if ((::WSARecv(
                            remote_socket_,
                            &remote_recv_buf_,
                            1,
                            nullptr,
                            &flags,
                            &io_context_recv_from_remote_,
                            nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                        {
                            const auto error = WSAGetLastError();
                            NETLIB_WARNING("process_receive_buffer_complete: WSARecv from remote failed: {}", error);
                            // Close connection to remote peer in case of error
                            close_client<true>(true, false);
                        }
                        else
                        {
                            NETLIB_DEBUG("process_receive_buffer_complete: New remote WSARecv initiated successfully");
                        }
                    }
                    else
                    {
                        NETLIB_DEBUG("process_receive_buffer_complete: No space in remote receive buffer, skipping new receive");
                    }
                }

                break;
            }
            case connection_status::client_no_change:
            case connection_status::client_connected:
                NETLIB_DEBUG("process_receive_buffer_complete: Connection not established yet, ignoring received data");
                break;
            }

            NETLIB_DEBUG("process_receive_buffer_complete: Completed processing {} bytes from {} socket",
                io_size, io_context->is_local ? "local" : "remote");
        }

        /**
         * @brief Handles completion of an asynchronous send operation for the proxy session.
         *
         * This method is called when a send operation on either the local or remote socket completes.
         * It updates the session's activity timestamp and manages the cyclic buffer pointers and lengths
         * for the send/receive buffers. Depending on which endpoint (local or remote) completed the send,
         * it may initiate a new receive operation on the opposite endpoint if needed, or continue sending
         * remaining buffered data.
         *
         * - For the local socket: If the remote receive buffer is empty, it initiates a new receive on the remote socket.
         *   It also advances the local send buffer pointer and length, and continues sending if more data is available.
         *   If all data has been sent and the session is completed, it closes the remote socket.
         *
         * - For the remote socket: If the local receive buffer is empty, it initiates a new receive on the local socket.
         *   It also advances the remote send buffer pointer and length, and continues sending if more data is available.
         *   If all data has been sent and the session is completed, it closes the local socket.
         *
         * The method ensures thread safety by acquiring a lock on the session state and logs debug information
         * about send completions and subsequent actions.
         *
         * @param io_size     The number of bytes sent in the operation.
         * @param io_context  Pointer to the per-I/O context structure associated with this operation.
         *
         * @note This method is typically invoked by the I/O completion port thread when a send
         *       operation completes. It is safe to override in derived classes for protocol-specific
         *       data handling or custom relay logic.
         */
        virtual void process_send_buffer_complete(const uint32_t io_size, per_io_context_t* io_context)
        {
            std::lock_guard lock(lock_);

            timestamp_ = std::chrono::steady_clock::now();

            NETLIB_DEBUG("process_send_buffer_complete: Processing {} bytes sent to {} socket",
                io_size, io_context->is_local ? "local" : "remote");

            if (io_context->is_local)
            {
                NETLIB_DEBUG("process_send_buffer_complete: Send completed to local socket: {} bytes", io_size);

                if (connection_status_ != connection_status::client_completed)
                {
                    NETLIB_DEBUG("process_send_buffer_complete: Connection still active, checking for receive buffer restart");

                    if (remote_recv_buf_.len == 0)
                    {
                        NETLIB_DEBUG("process_send_buffer_complete: Remote receive buffer empty, setting up new receive");

                        DWORD flags = 0;

                        remote_recv_buf_.buf = local_send_buf_.buf;
                        remote_recv_buf_.len = io_size;

                        if (remote_recv_buf_.len > 0)
                        {
                            NETLIB_DEBUG("process_send_buffer_complete: Initiating remote receive with buffer size {}", remote_recv_buf_.len);

                            if ((::WSARecv(
                                remote_socket_,
                                &remote_recv_buf_,
                                1,
                                nullptr,
                                &flags,
                                &io_context_recv_from_remote_,
                                nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                            {
                                const auto error = WSAGetLastError();
                                NETLIB_WARNING("process_send_buffer_complete: WSARecv on remote failed: {}", error);
                                close_client<true>(true, false);
                            }
                            else
                            {
                                NETLIB_DEBUG("process_send_buffer_complete: Remote WSARecv initiated successfully");
                            }
                        }
                        else
                        {
                            NETLIB_DEBUG("process_send_buffer_complete: Remote receive buffer length is 0, skipping receive");
                        }
                    }
                    else
                    {
                        NETLIB_DEBUG("process_send_buffer_complete: Remote receive buffer already active (len={})", remote_recv_buf_.len);
                    }
                }
                else
                {
                    NETLIB_DEBUG("process_send_buffer_complete: Connection completed, skipping receive restart");
                }

                // Advance the send buffer pointer
                local_send_buf_.buf += io_size;
                NETLIB_DEBUG("process_send_buffer_complete: Advanced local send buffer by {} bytes", io_size);

                // Handle buffer wrap-around
                if (local_send_buf_.buf == from_remote_to_local_buffer_.data() + from_remote_to_local_buffer_.size())
                {
                    local_send_buf_.buf = from_remote_to_local_buffer_.data();
                    NETLIB_DEBUG("process_send_buffer_complete: Local send buffer wrapped to beginning");
                }

                // Check if we've caught up with the receive buffer
                if (local_send_buf_.buf == remote_recv_buf_.buf)
                {
                    NETLIB_DEBUG("process_send_buffer_complete: Local send buffer caught up with remote receive buffer");

                    if (connection_status_ == connection_status::client_completed)
                    {
                        NETLIB_DEBUG("process_send_buffer_complete: Connection completed, closing remote client");
                        close_client<true>(false, false);
                    }

                    local_send_buf_.len = 0;
                    NETLIB_DEBUG("process_send_buffer_complete: Reset local send buffer length to 0");
                }
                else
                {
                    // Calculate remaining data to send
                    if (local_send_buf_.buf < remote_recv_buf_.buf)
                    {
                        local_send_buf_.len = static_cast<ULONG>(remote_recv_buf_.buf - local_send_buf_.buf);
                        NETLIB_DEBUG("process_send_buffer_complete: Set local send buffer len to {} (normal case)", local_send_buf_.len);
                    }
                    else
                    {
                        local_send_buf_.len = static_cast<ULONG>(from_remote_to_local_buffer_.data() +
                            from_remote_to_local_buffer_.size() - local_send_buf_.buf);
                        NETLIB_DEBUG("process_send_buffer_complete: Set local send buffer len to {} (wrapped case)", local_send_buf_.len);
                    }

                    // Continue sending if there's more data
                    if (local_send_buf_.len)
                    {
                        NETLIB_DEBUG("process_send_buffer_complete: Continuing send to local socket with {} bytes", local_send_buf_.len);

                        if ((::WSASend(
                            local_socket_,
                            &local_send_buf_,
                            1,
                            nullptr,
                            0,
                            &io_context_send_to_local_,
                            nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                        {
                            const auto error = WSAGetLastError();
                            NETLIB_WARNING("process_send_buffer_complete: WSASend to local failed: {}", error);
                            close_client<true>(false, true);
                        }
                        else
                        {
                            NETLIB_DEBUG("process_send_buffer_complete: Continued local send initiated successfully");
                        }
                    }
                    else
                    {
                        NETLIB_DEBUG("process_send_buffer_complete: No more data to send to local socket");
                    }
                }
            }
            else
            {
                NETLIB_DEBUG("process_send_buffer_complete: Send completed to remote socket: {} bytes", io_size);

                if (connection_status_ != connection_status::client_completed)
                {
                    NETLIB_DEBUG("process_send_buffer_complete: Connection still active, checking for receive buffer restart");

                    if (local_recv_buf_.len == 0)
                    {
                        NETLIB_DEBUG("process_send_buffer_complete: Local receive buffer empty, setting up new receive");

                        DWORD flags = 0;

                        local_recv_buf_.buf = remote_send_buf_.buf;
                        local_recv_buf_.len = io_size;

                        if (local_recv_buf_.len)
                        {
                            NETLIB_DEBUG("process_send_buffer_complete: Initiating local receive with buffer size {}", local_recv_buf_.len);

                            if ((::WSARecv(
                                local_socket_,
                                &local_recv_buf_,
                                1,
                                nullptr,
                                &flags,
                                &io_context_recv_from_local_,
                                nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                            {
                                const auto error = WSAGetLastError();
                                NETLIB_WARNING("process_send_buffer_complete: WSARecv on local failed: {}", error);
                                close_client<true>(true, true);
                            }
                            else
                            {
                                NETLIB_DEBUG("process_send_buffer_complete: Local WSARecv initiated successfully");
                            }
                        }
                        else
                        {
                            NETLIB_DEBUG("process_send_buffer_complete: Local receive buffer length is 0, skipping receive");
                        }
                    }
                    else
                    {
                        NETLIB_DEBUG("process_send_buffer_complete: Local receive buffer already active (len={})", local_recv_buf_.len);
                    }
                }
                else
                {
                    NETLIB_DEBUG("process_send_buffer_complete: Connection completed, skipping receive restart");
                }

                // Advance the send buffer pointer
                remote_send_buf_.buf += io_size;
                NETLIB_DEBUG("process_send_buffer_complete: Advanced remote send buffer by {} bytes", io_size);

                // Handle buffer wrap-around
                if (remote_send_buf_.buf == from_local_to_remote_buffer_.data() + from_local_to_remote_buffer_.size())
                {
                    remote_send_buf_.buf = from_local_to_remote_buffer_.data();
                    NETLIB_DEBUG("process_send_buffer_complete: Remote send buffer wrapped to beginning");
                }

                // Check if we've caught up with the receive buffer
                if (remote_send_buf_.buf == local_recv_buf_.buf)
                {
                    NETLIB_DEBUG("process_send_buffer_complete: Remote send buffer caught up with local receive buffer");

                    if (connection_status_ == connection_status::client_completed)
                    {
                        NETLIB_DEBUG("process_send_buffer_complete: Connection completed, closing local client");
                        close_client<true>(false, false);
                    }

                    remote_send_buf_.len = 0;
                    NETLIB_DEBUG("process_send_buffer_complete: Reset remote send buffer length to 0");
                }
                else
                {
                    // Calculate remaining data to send
                    if (remote_send_buf_.buf < local_recv_buf_.buf)
                    {
                        remote_send_buf_.len = static_cast<ULONG>(local_recv_buf_.buf - remote_send_buf_.buf);
                        NETLIB_DEBUG("process_send_buffer_complete: Set remote send buffer len to {} (normal case)", remote_send_buf_.len);
                    }
                    else
                    {
                        remote_send_buf_.len = static_cast<ULONG>(from_local_to_remote_buffer_.data() +
                            from_local_to_remote_buffer_.size() - remote_send_buf_.buf);
                        NETLIB_DEBUG("process_send_buffer_complete: Set remote send buffer len to {} (wrapped case)", remote_send_buf_.len);
                    }

                    // Continue sending if there's more data
                    if (remote_send_buf_.len)
                    {
                        NETLIB_DEBUG("process_send_buffer_complete: Continuing send to remote socket with {} bytes", remote_send_buf_.len);

                        if ((::WSASend(
                            remote_socket_,
                            &remote_send_buf_,
                            1,
                            nullptr,
                            0,
                            &io_context_send_to_remote_,
                            nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                        {
                            const auto error = WSAGetLastError();
                            NETLIB_WARNING("process_send_buffer_complete: WSASend to remote failed: {}", error);
                            close_client<true>(false, false);
                        }
                        else
                        {
                            NETLIB_DEBUG("process_send_buffer_complete: Continued remote send initiated successfully");
                        }
                    }
                    else
                    {
                        NETLIB_DEBUG("process_send_buffer_complete: No more data to send to remote socket");
                    }
                }
            }

            NETLIB_DEBUG("process_send_buffer_complete: Completed processing {} bytes sent to {} socket",
                io_size, io_context->is_local ? "local" : "remote");
        }

        /**
         * @brief Cleans up resources after an injected buffer operation completes.
         *
         * This static method is called when an asynchronous inject operation (such as
         * `inject_to_local` or `inject_to_remote`) has finished processing. It is responsible
         * for releasing any dynamically allocated memory associated with the per-I/O context,
         * including the buffer used for the operation and the context object itself.
         *
         * @param context Pointer to the per_io_context_t structure associated with the completed inject operation.
         *
         * @note This method must be called to avoid memory leaks after each inject operation.
         *       It safely deletes both the buffer and the context, regardless of success or failure.
         */
        static void process_inject_buffer_complete(per_io_context_t* context)
        {
            if (context->wsa_buf.buf != nullptr)
                delete[] context->wsa_buf.buf;

            delete context;
        }

        /**
         * @brief Injects a block of data into the local socket as an asynchronous operation.
         *
         * This method allocates a new per-I/O context and buffer, copies the provided data into the buffer,
         * and initiates an asynchronous WSASend operation to transmit the data to the local socket.
         * The operation type can be specified (default is inject_io_write).
         *
         * If allocation of the context or buffer fails, the method returns false.
         * If WSASend fails to start and the error is not ERROR_IO_PENDING, the local socket is closed and false is returned.
         * On success, the method returns true, and the buffer/context will be cleaned up by process_inject_buffer_complete
         * after the operation completes.
         *
         * @param data   Pointer to the data buffer to send.
         * @param length Length of the data to send, in bytes.
         * @param type   Type of proxy I/O operation (default: inject_io_write).
         * @return true if the send operation was successfully initiated, false otherwise.
         *
         * @note The caller is responsible for ensuring the lifetime of the data buffer until the operation is started.
         *       The buffer is copied internally, so the original data can be released after this call returns.
         *       This method is thread-safe.
         */
        bool inject_to_local(const char* data, const uint32_t length,
            proxy_io_operation type = proxy_io_operation::inject_io_write)
        {
            NETLIB_DEBUG("inject_to_local: Starting injection of {} bytes (operation type: {})",
                length, static_cast<int>(type));

            // Validate input parameters
            if (data == nullptr)
            {
                NETLIB_ERROR("inject_to_local: Data pointer is null, cannot inject");
                return false;
            }

            if (length == 0)
            {
                NETLIB_WARNING("inject_to_local: Injection length is 0, skipping operation");
                return true; // Consider this a successful no-op
            }

            if (local_socket_ == static_cast<SOCKET>(INVALID_SOCKET))
            {
                NETLIB_ERROR("inject_to_local: Local socket is invalid (INVALID_SOCKET)");
                return false;
            }

            NETLIB_DEBUG("inject_to_local: Allocating per-I/O context for local socket {}",
                static_cast<int>(local_socket_));

            auto context = new(std::nothrow) per_io_context_t{ type, this, true };

            if (context == nullptr)
            {
                NETLIB_ERROR("inject_to_local: Failed to allocate per-I/O context");
                return false;
            }

            NETLIB_DEBUG("inject_to_local: Allocating buffer for {} bytes", length);

            context->wsa_buf.buf = new(std::nothrow) char[length];

            if (context->wsa_buf.buf == nullptr)
            {
                NETLIB_ERROR("inject_to_local: Failed to allocate buffer of {} bytes", length);
                delete context;
                return false;
            }

            NETLIB_DEBUG("inject_to_local: Copying {} bytes of data to buffer", length);

            memmove(context->wsa_buf.buf, data, length);
            context->wsa_buf.len = length;

            NETLIB_DEBUG("inject_to_local: Initiating WSASend to local socket {} with {} bytes",
                static_cast<int>(local_socket_), length);

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
                NETLIB_WARNING("inject_to_local: WSASend failed with error: {}", error);

                // Clean up allocated resources
                delete[] context->wsa_buf.buf;
                delete context;

                NETLIB_DEBUG("inject_to_local: Closing local client due to WSASend failure");
                close_client(false, true);
                return false;
            }

            NETLIB_DEBUG("inject_to_local: WSASend initiated successfully for {} bytes", length);
            NETLIB_DEBUG("inject_to_local: Injection completed, context and buffer will be cleaned up on completion");

            return true;
        }

        /**
         * @brief Injects a block of data into the remote socket as an asynchronous operation.
         *
         * This method allocates a new per-I/O context and buffer, copies the provided data into the buffer,
         * and initiates an asynchronous WSASend operation to transmit the data to the remote socket.
         * The operation type can be specified (default is inject_io_write).
         *
         * If allocation of the context or buffer fails, the method returns false.
         * If WSASend fails to start and the error is not ERROR_IO_PENDING, the remote socket is closed and false is returned.
         * On success, the method returns true, and the buffer/context will be cleaned up by process_inject_buffer_complete
         * after the operation completes.
         *
         * @param data   Pointer to the data buffer to send.
         * @param length Length of the data to send, in bytes.
         * @param type   Type of proxy I/O operation (default: inject_io_write).
         * @return true if the send operation was successfully initiated, false otherwise.
         *
         * @note The caller is responsible for ensuring the lifetime of the data buffer until the operation is started.
         *       The buffer is copied internally, so the original data can be released after this call returns.
         *       This method is thread-safe.
         */
        bool inject_to_remote(const char* data, const uint32_t length,
            proxy_io_operation type = proxy_io_operation::inject_io_write)
        {
            NETLIB_DEBUG("inject_to_remote: Starting injection of {} bytes (operation type: {})",
                length, static_cast<int>(type));

            // Validate input parameters
            if (data == nullptr)
            {
                NETLIB_ERROR("inject_to_remote: Data pointer is null, cannot inject");
                return false;
            }

            if (length == 0)
            {
                NETLIB_WARNING("inject_to_remote: Injection length is 0, skipping operation");
                return true; // Consider this a successful no-op
            }

            if (remote_socket_ == static_cast<SOCKET>(INVALID_SOCKET))
            {
                NETLIB_ERROR("inject_to_remote: Remote socket is invalid (INVALID_SOCKET)");
                return false;
            }

            NETLIB_DEBUG("inject_to_remote: Allocating per-I/O context for remote socket {}",
                static_cast<int>(remote_socket_));

            auto context = new(std::nothrow) per_io_context_t{ type, this, false };

            if (context == nullptr)
            {
                NETLIB_ERROR("inject_to_remote: Failed to allocate per-I/O context");
                return false;
            }

            NETLIB_DEBUG("inject_to_remote: Allocating buffer for {} bytes", length);

            context->wsa_buf.buf = new(std::nothrow) char[length];

            if (context->wsa_buf.buf == nullptr)
            {
                NETLIB_ERROR("inject_to_remote: Failed to allocate buffer of {} bytes", length);
                delete context;
                return false;
            }

            NETLIB_DEBUG("inject_to_remote: Copying {} bytes of data to buffer", length);

            memmove(context->wsa_buf.buf, data, length);
            context->wsa_buf.len = length;

            NETLIB_DEBUG("inject_to_remote: Initiating WSASend to remote socket {} with {} bytes",
                static_cast<int>(remote_socket_), length);

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
                NETLIB_WARNING("inject_to_remote: WSASend failed with error: {}", error);

                // Clean up allocated resources
                delete[] context->wsa_buf.buf;
                delete context;

                NETLIB_DEBUG("inject_to_remote: Closing remote client due to WSASend failure");
                close_client(false, false);
                return false;
            }

            NETLIB_DEBUG("inject_to_remote: WSASend initiated successfully for {} bytes", length);
            NETLIB_DEBUG("inject_to_remote: Injection completed, context and buffer will be cleaned up on completion");

            return true;
        }

    protected:
        /**
         * @brief Returns a raw pointer to the current negotiation context.
         *
         * This accessor provides direct, read-only access to the internal negotiation context
         * associated with the proxy session. The negotiation context typically contains
         * session-specific information such as authentication credentials, target addresses,
         * or protocol state required during the negotiation phase of the connection.
         *
         * @return Raw pointer to the negotiate_context_t instance, or nullptr if not set.
         *
         * @note The returned pointer is owned by the tcp_proxy_socket instance and must not be deleted
         *       or modified by the caller. The pointer remains valid for the lifetime of the session
         *       or until the context is reset.
         */
        [[nodiscard]] negotiate_context_t* get_negotiate_ctx() const
        {
            return negotiate_ctx_.get();
        }

        /**
         * @brief Performs protocol-specific negotiation on the local socket.
         *
         * This virtual method is called during the session startup to perform any required
         * negotiation or handshake with the locally connected client (e.g., authentication,
         * protocol version negotiation). The default implementation returns true, indicating
         * that no negotiation is required.
         *
         * Derived classes can override this method to implement custom negotiation logic.
         * If the negotiation is asynchronous, return false and invoke data relay startup
         * from the appropriate completion handler.
         *
         * @return true if negotiation is complete or not required, false if negotiation is pending.
         */
        virtual bool local_negotiate()
        {
            return true;
        }

        /**
         * @brief Performs protocol-specific negotiation on the remote socket.
         *
         * This virtual method is called during the session startup to perform any required
         * negotiation or handshake with the remote server (e.g., authentication, protocol
         * version negotiation). The default implementation returns true, indicating that
         * no negotiation is required.
         *
         * Derived classes can override this method to implement custom negotiation logic.
         * If the negotiation is asynchronous, return false and invoke data relay startup
         * from the appropriate completion handler.
         *
         * @return true if negotiation is complete or not required, false if negotiation is pending.
         */
        virtual bool remote_negotiate()
        {
            return true;
        }

        /**
         * @brief Initiates asynchronous data relay between the local and remote sockets.
         *
         * This method starts the data relay phase of the proxy session by posting asynchronous
         * WSARecv operations on both the local and remote sockets. It prepares the session to
         * receive data from both endpoints and relay it as needed.
         *
         * If the initial WSARecv call on the local socket fails (other than ERROR_IO_PENDING),
         * the local socket is closed, the remote receive buffer is reset, and the method returns false.
         * If the WSARecv call on the remote socket fails (other than ERROR_IO_PENDING), the local socket
         * is closed, the remote socket is closed, and the method returns false.
         *
         * On success, both sockets are set up for asynchronous receive operations and the method returns true.
         *
         * @return true if both receive operations were successfully initiated; false otherwise.
         *
         * @note This method is typically called after successful negotiation and completion port association.
         *       It is thread-safe and ensures proper cleanup on failure.
         */
        bool start_data_relay()
        {
            NETLIB_DEBUG("start_data_relay: Starting data relay initialization");

            DWORD flags = 0;

            NETLIB_DEBUG("start_data_relay: Initiating WSARecv on local socket {}",
                static_cast<int>(local_socket_));

            auto ret = WSARecv(local_socket_, &local_recv_buf_, 1,
                nullptr, &flags, &io_context_recv_from_local_, nullptr);

            if (const auto wsa_error = WSAGetLastError(); ret == SOCKET_ERROR && (ERROR_IO_PENDING != wsa_error))
            {
                NETLIB_WARNING("start_data_relay: WSARecv on local socket failed with error: {}", wsa_error);
                NETLIB_DEBUG("start_data_relay: Closing local client due to WSARecv failure");

                close_client(true, true);
                remote_recv_buf_.len = 0;

                NETLIB_DEBUG("start_data_relay: Data relay initialization failed on local socket");
                return false;
            }
            else if (ret == SOCKET_ERROR && wsa_error == ERROR_IO_PENDING)
            {
                NETLIB_DEBUG("start_data_relay: Local WSARecv initiated successfully (pending)");
            }
            else
            {
                NETLIB_DEBUG("start_data_relay: Local WSARecv completed immediately");
            }

            NETLIB_DEBUG("start_data_relay: Initiating WSARecv on remote socket {}",
                static_cast<int>(remote_socket_));

            ret = WSARecv(remote_socket_, &remote_recv_buf_, 1,
                nullptr, &flags, &io_context_recv_from_remote_, nullptr);

            if (const auto wsa_error = WSAGetLastError(); ret == SOCKET_ERROR && (ERROR_IO_PENDING != wsa_error))
            {
                NETLIB_WARNING("start_data_relay: WSARecv on remote socket failed with error: {}", wsa_error);
                NETLIB_DEBUG("start_data_relay: Cleaning up local socket due to remote WSARecv failure");

                if (shutdown(local_socket_, SD_BOTH) == SOCKET_ERROR) {
                    const auto shutdown_error = WSAGetLastError();
                    NETLIB_WARNING("start_data_relay: shutdown(local_socket_) failed: {}", shutdown_error);
                }
                else {
                    NETLIB_DEBUG("start_data_relay: Local socket shutdown successful");
                }

                // Cancel all pending I/O before closing
                if (CancelIoEx(reinterpret_cast<HANDLE>(local_socket_), nullptr) == FALSE) {
                    const auto cancel_error = GetLastError();
                    if (cancel_error != ERROR_NOT_FOUND) {  // ERROR_NOT_FOUND means no pending operations
                        NETLIB_DEBUG("start_data_relay: CancelIoEx(local_socket_) returned error: {}", cancel_error);
                    }
                }
                else {
                    NETLIB_DEBUG("start_data_relay: Local socket I/O cancellation successful");
                }

                if (closesocket(local_socket_) == SOCKET_ERROR) {
                    const auto close_error = WSAGetLastError();
                    NETLIB_WARNING("start_data_relay: closesocket(local_socket_) failed: {}", close_error);
                }
                else {
                    NETLIB_DEBUG("start_data_relay: Local socket closed successfully");
                }

                NETLIB_DEBUG("start_data_relay: Closing remote client due to WSARecv failure");
                close_client(true, false);

                NETLIB_DEBUG("start_data_relay: Data relay initialization failed on remote socket");
                return false;
            }
            else if (ret == SOCKET_ERROR && wsa_error == ERROR_IO_PENDING)
            {
                NETLIB_DEBUG("start_data_relay: Remote WSARecv initiated successfully (pending)");
            }
            else
            {
                NETLIB_DEBUG("start_data_relay: Remote WSARecv completed immediately");
            }

            NETLIB_DEBUG("start_data_relay: Data relay successfully initialized for both sockets (local: {}, remote: {})",
                static_cast<int>(local_socket_), static_cast<int>(remote_socket_));

            return true;
        }
    };
}