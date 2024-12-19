#pragma once

namespace proxy
{
    template <typename T>
    class socks5_udp_proxy_socket;

    template <typename T>
    struct socks5_udp_per_io_context : WSAOVERLAPPED
    {
        socks5_udp_per_io_context(const proxy_io_operation io_operation, socks5_udp_proxy_socket<T>* socket,
                                  const bool is_local)
            : WSAOVERLAPPED{0, 0, {{0, 0}}, nullptr},
              io_operation(io_operation),
              proxy_socket_ptr(socket),
              is_local(is_local)
        {
        }

        static socks5_udp_per_io_context* allocate_io_context(const proxy_io_operation io_operation,
                                                              socks5_udp_proxy_socket<T>* socket, const bool is_local,
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

        proxy_io_operation io_operation;
        socks5_udp_proxy_socket<T>* proxy_socket_ptr;
        std::unique_ptr<net_packet_t> wsa_buf{nullptr};
        bool is_local;
    };

    template <typename T>
    // ReSharper disable once CppClassCanBeFinal
    class socks5_udp_proxy_socket : public netlib::log::logger<socks5_udp_proxy_socket<T>>
    {
    public:
        constexpr static size_t send_receive_buffer_size = 256 * 256;

        using log_level = netlib::log::log_level;
        using logger = netlib::log::logger<socks5_udp_proxy_socket>;
        using address_type_t = T;
        using negotiate_context_t = socks5_negotiate_context<T>;
        using per_io_context_t = socks5_udp_per_io_context<T>;

    private:
        /// <summary> last processed packet timestamp </summary>
        std::chrono::steady_clock::time_point timestamp_;
        /// <summary> SOCKS5 TCP connection </summary>
        SOCKET socks_socket_;
        /// <summary> packet pool reference </summary>
        packet_pool& packet_pool_;
        /// <summary>local connection socket reference</summary>
        const SOCKET& local_socket_;
        /// <summary>remote connection socket</summary>
        SOCKET remote_socket_;
        /// <summary>local socket sent_to address</summary>
        SOCKADDR_STORAGE local_address_sa_{};

        /// <summary> remote peer address and port</summary>
        uint16_t remote_peer_port_;
        address_type_t remote_peer_address_;

        /// <summary> negotiate context pointer </summary>
        std::unique_ptr<negotiate_context_t> negotiate_ctx_;

        /// <summary>provides synchronization for the I/O operations</summary>
        std::atomic_bool ready_for_removal_{false};

        std::array<char, send_receive_buffer_size> from_remote_to_local_buffer_{};
        WSABUF remote_recv_buf_{
            static_cast<ULONG>(from_remote_to_local_buffer_.size()), from_remote_to_local_buffer_.data()
        };

        per_io_context_t io_context_recv_from_remote_{proxy_io_operation::relay_io_read, this, false};

    public:
        socks5_udp_proxy_socket(const SOCKET socks_socket, packet_pool& packet_pool, const SOCKET& local_socket,
                                const SOCKADDR_STORAGE& local_address_sa, const SOCKET remote_socket,
                                address_type_t remote_address, const uint16_t remote_port,
                                std::unique_ptr<negotiate_context_t> negotiate_ctx,
                                const log_level log_level = log_level::error,
                                const std::optional<std::reference_wrapper<std::ostream>> log_stream = std::nullopt)
            : logger(log_level, log_stream),
              timestamp_{std::chrono::steady_clock::now()},
              socks_socket_(socks_socket),
              packet_pool_(packet_pool),
              local_socket_(local_socket),
              remote_socket_(remote_socket),
              local_address_sa_(local_address_sa),
              remote_peer_port_(remote_port),
              remote_peer_address_(remote_address),
              negotiate_ctx_(std::move(negotiate_ctx))
        {
        }

        virtual ~socks5_udp_proxy_socket()
        {
            if (remote_socket_ != INVALID_SOCKET)
            {
                closesocket(remote_socket_);
                remote_socket_ = INVALID_SOCKET;
                closesocket(socks_socket_);
                socks_socket_ = INVALID_SOCKET;
            }
        }

        socks5_udp_proxy_socket(const socks5_udp_proxy_socket& other) = delete;

        socks5_udp_proxy_socket& operator=(const socks5_udp_proxy_socket& other) = delete;

        socks5_udp_proxy_socket(socks5_udp_proxy_socket&& other) noexcept
            : logger(std::move(other)), // Initialize the base class
              timestamp_(other.timestamp_),
              packet_pool_(other.packet_pool_),
              local_socket_(other.local_socket_),
              local_address_sa_(other.local_address_sa_),
              remote_peer_port_(other.remote_peer_port_),
              remote_peer_address_(std::move(other.remote_peer_address_)),
              negotiate_ctx_(std::move(other.negotiate_ctx_)),
              ready_for_removal_(std::move(other.ready_for_removal_)),
              from_remote_to_local_buffer_(other.from_remote_to_local_buffer_),
              remote_recv_buf_(other.remote_recv_buf_),
              io_context_recv_from_remote_(std::move(other.io_context_recv_from_remote_))
        {
            socks_socket_ = other.socks_socket_;
            other.socks_socket_ = INVALID_SOCKET;
            remote_socket_ = other.remote_socket_;
            other.remote_socket_ = INVALID_SOCKET;
        }

        socks5_udp_proxy_socket& operator=(socks5_udp_proxy_socket&& other) noexcept
        {
            if (this != &other)
            {
                logger::operator=(std::move(other)); // Assign the base class

                timestamp_ = other.timestamp_;
                packet_pool_ = other.packet_pool_;
                local_socket_ = other.local_socket_;
                local_address_sa_ = other.local_address_sa_;
                remote_peer_port_ = other.remote_peer_port_;
                remote_peer_address_ = std::move(other.remote_peer_address_);
                negotiate_ctx_ = std::move(other.negotiate_ctx_);
                ready_for_removal_ = std::move(other.ready_for_removal_);
                from_remote_to_local_buffer_ = other.from_remote_to_local_buffer_;
                remote_recv_buf_ = other.remote_recv_buf_;
                io_context_recv_from_remote_ = std::move(other.io_context_recv_from_remote_);

                socks_socket_ = other.socks_socket_;
                other.socks_socket_ = INVALID_SOCKET;
                remote_socket_ = other.remote_socket_;
                other.remote_socket_ = INVALID_SOCKET;
            }
            return *this;
        }

        std::unique_ptr<net_packet_t> allocate_packet(const uint32_t size) const
        {
            return packet_pool_.allocate(size);
        }

        void release_packet(std::unique_ptr<net_packet_t> packet) const
        {
            packet_pool_.free(std::move(packet));
        }

        bool associate_to_completion_port(const ULONG_PTR completion_key,
                                          winsys::io_completion_port& completion_port) const
        {
            if (remote_socket_ != INVALID_SOCKET)
                return completion_port.associate_socket(remote_socket_, completion_key);

            return false;
        }

        void close_client()
        {
            ready_for_removal_.store(true);
        }

        bool is_ready_for_removal() const
        {
            using namespace std::chrono_literals;

            if (ready_for_removal_.load() || (std::chrono::steady_clock::now() - timestamp_ > 5min))
                return true;

            return false;
        }

        // ********************************************************************************
        /// <summary>
        /// Attempts to negotiate credentials for local and remote sockets and starts 
        /// data relay between them
        /// </summary>
        /// <returns>true is relay was started, false otherwise</returns>
        // ********************************************************************************
        virtual bool start()
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

        virtual void process_receive_negotiate_complete(const uint32_t io_size, per_io_context_t* io_context)
        {
        }

        virtual void process_send_negotiate_complete(const uint32_t io_size, per_io_context_t* io_context)
        {
        }

        void process_receive_buffer_complete(const uint32_t io_size, per_io_context_t* io_context)
        {
            timestamp_ = std::chrono::steady_clock::now();

            if (io_context->is_local == true)
            {
                if (log_level_ > netlib::log::log_level::debug)
                    print_log(log_level::debug, std::string("process_receive_buffer_complete: ") +
                              std::string{remote_peer_address_} + " : " +
                              std::to_string(remote_peer_port_) + std::string(" :received data from local socket: ") +
                              std::to_string(io_size));

                if (auto* io_context_send_to_remote = socks5_udp_per_io_context<T>::allocate_io_context(
                    proxy_io_operation::relay_io_write, this, false); io_context_send_to_remote)
                {
                    // forward the received data to remote host
                    io_context_send_to_remote->wsa_buf = std::move(io_context->wsa_buf);

                    print_log(log_level::debug, std::string("process_receive_buffer_complete: ") +
                              std::string{remote_peer_address_} + " : " +
                              std::to_string(remote_peer_port_) + std::string(" :sending data to remote socket: ") +
                              std::to_string(io_size));

                    if ((::WSASend(
                        remote_socket_,
                        io_context_send_to_remote->wsa_buf.get(),
                        1,
                        nullptr,
                        0,
                        io_context_send_to_remote,
                        nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                    {
                        // Close connection to remote peer in case of error
                        close_client();
                    }
                }
                else
                {
                    packet_pool_.free(std::move(io_context->wsa_buf));
                }
            }
            else
            {
                print_log(log_level::debug, std::string("process_receive_buffer_complete: ") +
                          std::string{remote_peer_address_} + " : " +
                          std::to_string(remote_peer_port_) + std::string(" :received data from remote socket: ") +
                          std::to_string(io_size));

                if (auto* io_context_send_to_local = socks5_udp_per_io_context<T>::allocate_io_context(
                        proxy_io_operation::relay_io_write, this, true, io_size);
                    io_context_send_to_local)
                {
                    io_context_send_to_local->wsa_buf->len = io_size;
                    memmove(io_context_send_to_local->wsa_buf->buf, from_remote_to_local_buffer_.data(), io_size);

                    print_log(log_level::debug, std::string("process_receive_buffer_complete: ") +
                              std::string{remote_peer_address_} + " : " +
                              std::to_string(remote_peer_port_) + std::string(" :sending data to local socket: ") +
                              std::to_string(io_size));

                    if ((::WSASendTo(
                        local_socket_,
                        io_context_send_to_local->wsa_buf.get(),
                        1,
                        nullptr,
                        0,
                        reinterpret_cast<sockaddr*>(&local_address_sa_),
                        sizeof(sockaddr),
                        io_context_send_to_local,
                        nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                    {
                        // Close connection to remote peer in case of error
                        close_client();
                    }
                }

                DWORD flags = 0;

                auto ret = WSARecv(remote_socket_, &remote_recv_buf_, 1,
                                   nullptr, &flags, &io_context_recv_from_remote_, nullptr);

                if (const auto wsa_error = WSAGetLastError(); ret == SOCKET_ERROR && (ERROR_IO_PENDING != wsa_error))
                {
                    close_client();
                }
            }
        }

        void process_send_buffer_complete(const uint32_t io_size, per_io_context_t* io_context)
        {
            if (io_context->is_local == true)
            {
                // Send to local complete
                print_log(log_level::debug, std::string("process_send_buffer_complete: ") +
                          std::string{remote_peer_address_} + " : " +
                          std::to_string(remote_peer_port_) + std::string(
                              " :send data to locally connected socket complete: ") + std::to_string(io_size));
            }
            else
            {
                // Send to remote complete
                print_log(log_level::debug, std::string("process_send_buffer_complete: ") +
                          std::string{remote_peer_address_} + " : " +
                          std::to_string(remote_peer_port_) + std::string(
                              " :send data to remotely connected socket complete: ") + std::to_string(io_size));
            }

            // free completed packet resource
            socks5_udp_per_io_context<T>::release_io_context(io_context);
        }

        static void process_inject_buffer_complete(packet_pool& packet_pool, per_io_context_t* context)
        {
            if (context->wsa_buf != nullptr)
                packet_pool.free(std::move(context->wsa_buf));

            delete context;
        }

        // ********************************************************************************
        /// <summary>
        /// Sends block of data into local socket
        /// </summary>
        /// <param name="data">data buffer</param>
        /// <param name="length">length of the data to send</param>
        /// <param name="type">type of operation</param>
        /// <returns>pre-status of the operation</returns>
        // ********************************************************************************
        bool inject_to_local(const char* data, const uint32_t length,
                             proxy_io_operation type = proxy_io_operation::inject_io_write)
        {
            auto context = new(std::nothrow) per_io_context_t{type, this, true};

            if (context == nullptr)
                return false;

            context->wsa_buf = packet_pool_.allocate(length);

            if (!context->wsa_buf)
            {
                return false;
            }

            context->wsa_buf->buf->len = length;

            memmove(context->wsa_buf->buf, data, length);

            context->wsa_buf->len = length;

            if ((::WSASend(
                local_socket_,
                &context->wsa_buf,
                1,
                nullptr,
                0,
                context,
                nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
            {
                return false;
            }

            return true;
        }

        // ********************************************************************************
        /// <summary>
        /// Sends block of data into remote socket
        /// </summary>
        /// <param name="data">data buffer</param>
        /// <param name="length">length of the data to send</param>
        /// <param name="type">type of operation</param>
        /// <returns>pre-status of the operation</returns>
        // ********************************************************************************
        bool inject_to_remote(const char* data, const uint32_t length,
                              proxy_io_operation type = proxy_io_operation::inject_io_write)
        {
            auto context = new(std::nothrow) per_io_context_t{type, this, false};

            if (context == nullptr)
                return false;

            context->wsa_buf = packet_pool_.allocate(length);

            if (!context->wsa_buf)
            {
                return false;
            }

            context->wsa_buf->buf->len = length;

            memmove(context->wsa_buf->buf, data, length);

            context->wsa_buf->len = length;

            if ((::WSASend(
                remote_socket_,
                &context->wsa_buf,
                1,
                nullptr,
                0,
                context,
                nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
            {
                close_client();
                return false;
            }

            return true;
        }

    protected:
        virtual bool local_negotiate()
        {
            return true;
        }

        virtual bool remote_negotiate()
        {
            return true;
        }

        bool start_data_relay()
        {
            DWORD flags = 0;

            auto ret = WSARecv(remote_socket_, &remote_recv_buf_, 1,
                               nullptr, &flags, &io_context_recv_from_remote_, nullptr);

            if (const auto wsa_error = WSAGetLastError(); ret == SOCKET_ERROR && (ERROR_IO_PENDING != wsa_error))
            {
                close_client();
                return false;
            }

            return true;
        }
    };
}
