#pragma once

namespace proxy
{
    /**
     * @class socks5_tcp_proxy_socket
     * @brief Implements a SOCKS5 TCP proxy socket with authentication and negotiation logic.
     *
     * This class extends tcp_proxy_socket to provide SOCKS5 protocol support, including
     * username/password authentication (RFC 1929) and connection negotiation. It manages
     * the SOCKS5 handshake, authentication, and connection establishment with the remote
     * SOCKS5 proxy server, and transitions to data relay once negotiation is complete.
     *
     * @tparam T Address type (e.g., IPv4 or IPv6).
     */
    template <net::ip_address T>
    class socks5_tcp_proxy_socket final : public tcp_proxy_socket<T>  // NOLINT(clang-diagnostic-padded)
    {
        /**
        * @enum socks5_state
        * @brief Internal state machine for SOCKS5 negotiation.
        *
        * - pre_login: Initial state before negotiation begins.
        * - login_sent: Identification request sent to the proxy.
        * - login_responded: Identification response received.
        * - password_sent: Username/password authentication sent.
        * - password_responded: Authentication response received.
         * - connect_reply_header: Waiting for the 4-byte CONNECT reply header.
         * - connect_reply_domain_length: Waiting for the domain-name BND.ADDR length byte.
         * - connect_reply_tail: Waiting for BND.ADDR/BND.PORT bytes.
        */
        enum class socks5_state : uint8_t
        {
            pre_login,
            login_sent,
            login_responded,
            password_sent,
            password_responded,
            connect_reply_header,
            connect_reply_domain_length,
            connect_reply_tail
        };

    public:
        /**
         * @brief Type aliases for logging, address, negotiation context, and per-I/O context.
         *
         * - log_level: Logging level enumeration used for this proxy socket.
         * - address_type_t: Address type (e.g., IPv4 or IPv6) used by the proxy socket.
         * - negotiate_context_t: Type holding SOCKS5 negotiation context (credentials, target address, etc.).
         * - per_io_context_t: Per-I/O context type for managing asynchronous operations.
         */
        using log_level = netlib::log::log_level;
        using address_type_t = T;
        using negotiate_context_t = socks5_negotiate_context<T>;
        using per_io_context_t = tcp_per_io_context<T>;

        /**
         * @brief Constructs a SOCKS5 TCP proxy socket.
         *
         * Initializes the proxy socket with the given local and remote sockets, negotiation context,
         * logging level, and optional log stream. The negotiation context typically contains
         * authentication credentials and the target address/port for the SOCKS5 connection.
         *
         * @param local_socket The local client socket handle.
         * @param remote_socket The remote SOCKS5 proxy server socket handle.
         * @param negotiate_ctx Unique pointer to the negotiation context (credentials, target, etc.).
         * @param log_level Logging level for this socket (default: error).
         * @param log_stream Optional output stream for logging (default: std::nullopt).
         */
        socks5_tcp_proxy_socket(const SOCKET local_socket, const SOCKET remote_socket,
            std::unique_ptr<negotiate_context_t> negotiate_ctx,
            const log_level log_level = log_level::error,
            std::shared_ptr<std::ostream> log_stream = nullptr)
            : tcp_proxy_socket<T>(local_socket, remote_socket, std::move(negotiate_ctx), log_level,
                std::move(log_stream))
        {
        }

        /**
         * @brief Initializes the per-I/O contexts with shared_ptr to this socket.
         *
         * Overrides the base class method to also initialize SOCKS5-specific negotiation contexts.
         * Uses shared_from_this() to obtain a shared_ptr to the derived type.
         *
         * @throws std::runtime_error if the dynamic_pointer_cast fails, indicating type mismatch.
         */
        void initialize_io_contexts() override
        {
            // Call base class to initialize relay I/O contexts
            tcp_proxy_socket<T>::initialize_io_contexts();

            // Now initialize our SOCKS5-specific negotiation contexts
            // Use dynamic_pointer_cast for type-safe down-casting with runtime verification
            auto base_ptr = this->shared_from_this();
            auto self = std::dynamic_pointer_cast<socks5_tcp_proxy_socket>(base_ptr);

            if (!self)
            {
                // This should never happen if the class hierarchy is correct and the object
                // was created as socks5_tcp_proxy_socket, but we check defensively
                NETLIB_ERROR("initialize_io_contexts: dynamic_pointer_cast to socks5_tcp_proxy_socket failed - type mismatch");
                throw std::runtime_error(
                    "socks5_tcp_proxy_socket::initialize_io_contexts(): dynamic_pointer_cast failed. "
                    "Object is not of type socks5_tcp_proxy_socket or RTTI is disabled.");
            }

            io_context_recv_negotiate_.proxy_socket_ptr = self;
            io_context_send_negotiate_.proxy_socket_ptr = self;

            NETLIB_DEBUG("initialize_io_contexts: SOCKS5 negotiation contexts initialized successfully");
        }

        /**
         * @brief Handles completion of a SOCKS5 negotiation receive operation.
         *
         * This method is invoked when a negotiation-related receive operation completes on the remote socket.
         * It advances the SOCKS5 handshake state machine, processes authentication and connection responses,
         * and issues further requests as needed. If any step fails, the client connection is closed.
         *
         * The negotiation proceeds as follows:
         * - On receiving the identification response (login_sent state), checks the SOCKS5 version and method.
         *   - If username/password authentication is required, validates credentials and sends the authentication request.
         *   - If no authentication is required, sends the CONNECT command to the proxy.
         * - On receiving the authentication response (password_sent state), checks for success and sends the CONNECT command.
         * - On receiving the CONNECT response header, checks for success, drains the variable-length
         *   BND.ADDR/BND.PORT fields, and starts data relay if successful.
         *
         * @param io_size Number of bytes received by the completed negotiation read.
         * @param io_context Pointer to the per-I/O context structure for the operation.
         */
        void process_receive_negotiate_complete(const uint32_t io_size, per_io_context_t* io_context) override
        {
            if (io_context->is_local == false)
            {
                if (current_state_ == socks5_state::login_sent)
                {
                    current_state_ = socks5_state::login_responded;

                    if ((ident_resp_.version != 5) ||
                        (ident_resp_.method == 0xFF))
                    {
                        // SOCKS v5 identification or authentication failed
                        tcp_proxy_socket<T>::close_client(true, false);
                    }
                    else
                    {
                        // USERNAME/PASSWORD is chosen
                        if (ident_resp_.method == 0x2)
                        {
                            if (auto* negotiate_context_ptr = dynamic_cast<negotiate_context_t*>(tcp_proxy_socket<
                                T>::negotiate_ctx_.get()); !negotiate_context_ptr->socks5_username.has_value() ||
                                // [SOCKS5]: associate_to_socks5_proxy: RFC 1928: X'02' USERNAME/PASSWORD is chosen but USERNAME is not provided
                                (negotiate_context_ptr->socks5_username.value().length() > socks5_username_max_length ||
                                    negotiate_context_ptr->socks5_username.value().length() < 1) ||
                                // [SOCKS5]: associate_to_socks5_proxy: RFC 1928: X'02' USERNAME/PASSWORD is chosen but USERNAME exceeds maximum possible length
                                !negotiate_context_ptr->socks5_password.has_value() ||
                                // [SOCKS5]: associate_to_socks5_proxy: RFC 1928: X'02' USERNAME/PASSWORD is chosen but PASSWORD is not provided
                                (negotiate_context_ptr->socks5_password.value().length() > socks5_username_max_length ||
                                    negotiate_context_ptr->socks5_password.value().length() < 1)
                                // [SOCKS5]: associate_to_socks5_proxy: RFC 1928: X'02' USERNAME/PASSWORD is chosen but USERNAME exceeds maximum possible length
                                )
                            {
                                tcp_proxy_socket<T>::close_client(true, false);
                            }
                            else
                            {
                                if (auto auth_size = username_auth_.init(
                                    negotiate_context_ptr->socks5_username.value(),
                                    negotiate_context_ptr->socks5_password.value()); auth_size != 0)
                                {
                                    io_context_send_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&username_auth_);
                                    io_context_send_negotiate_.wsa_buf.len = auth_size;
                                    io_context_recv_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&ident_resp_);
                                    io_context_recv_negotiate_.wsa_buf.len = sizeof(socks5_ident_resp);

                                    if (this->post_send(
                                        tcp_proxy_socket<T>::remote_socket_,
                                        &io_context_send_negotiate_.wsa_buf,
                                        &io_context_send_negotiate_) == SOCKET_ERROR)
                                    {
                                        tcp_proxy_socket<T>::close_client(false, false);
                                        return;
                                    }

                                    current_state_ = socks5_state::password_sent;

                                    if (this->post_recv(
                                        tcp_proxy_socket<T>::remote_socket_,
                                        &io_context_recv_negotiate_.wsa_buf,
                                        &io_context_recv_negotiate_) == SOCKET_ERROR)
                                    {
                                        tcp_proxy_socket<T>::close_client(true, false);
                                    }
                                }
                            }
                        }
                        else // NO AUTHENTICATION REQUIRED is chosen
                        {
                            send_connect_request();
                        }
                    }
                }
                else if (current_state_ == socks5_state::password_sent)
                {
                    current_state_ = socks5_state::password_responded;

                    if (ident_resp_.method != 0)
                    {
                        // SOCKS v5 identification or authentication failed
                        tcp_proxy_socket<T>::close_client(true, false);
                    }
                    else
                    {
                        send_connect_request();
                    }
                }
                else if (current_state_ == socks5_state::connect_reply_header)
                {
                    if (!accumulate_connect_reply(io_size, &connect_response_header_, sizeof(connect_response_header_)))
                    {
                        return;
                    }

                    if ((connect_response_header_.version != socks5_protocol_version) ||
                        (connect_response_header_.reply != 0))
                    {
                        // SOCKS v5 connect failed
                        tcp_proxy_socket<T>::close_client(true, false);
                        return;
                    }

                    switch (connect_response_header_.address_type)
                    {
                    case 1: // IPv4
                        if (!start_connect_reply_receive(
                            socks5_state::connect_reply_tail,
                            connect_response_tail_.data(),
                            4 + sizeof(unsigned short)))
                        {
                            return;
                        }
                        break;

                    case 4: // IPv6
                        if (!start_connect_reply_receive(
                            socks5_state::connect_reply_tail,
                            connect_response_tail_.data(),
                            16 + sizeof(unsigned short)))
                        {
                            return;
                        }
                        break;

                    case 3: // domain name: read the one-byte length first.
                        if (!start_connect_reply_receive(
                            socks5_state::connect_reply_domain_length,
                            connect_response_tail_.data(),
                            1))
                        {
                            return;
                        }
                        break;

                    default:
                        tcp_proxy_socket<T>::close_client(true, false);
                        break;
                    }
                }
                else if (current_state_ == socks5_state::connect_reply_domain_length)
                {
                    if (!accumulate_connect_reply(io_size, connect_response_tail_.data(), 1))
                    {
                        return;
                    }

                    const auto domain_length = connect_response_tail_[0];
                    if (!start_connect_reply_receive(
                        socks5_state::connect_reply_tail,
                        connect_response_tail_.data() + 1,
                        static_cast<ULONG>(domain_length + sizeof(unsigned short))))
                    {
                        return;
                    }
                }
                else if (current_state_ == socks5_state::connect_reply_tail)
                {
                    if (!accumulate_connect_reply(io_size, connect_reply_buffer_, connect_reply_expected_))
                    {
                        return;
                    }

                    tcp_proxy_socket<T>::start_data_relay();
                }
            }
        }

    private:
        struct socks5_resp_header
        {
            unsigned char version = socks5_protocol_version;
            unsigned char reply{};
            unsigned char reserved{};
            unsigned char address_type{};
        };

        void reset_overlapped(per_io_context_t& io_context) noexcept
        {
            io_context.Internal = 0;
            io_context.InternalHigh = 0;
            io_context.Offset = 0;
            io_context.OffsetHigh = 0;
            io_context.hEvent = nullptr;
        }

        [[nodiscard]] bool start_negotiate_receive(void* const buffer, const ULONG length)
        {
            reset_overlapped(io_context_recv_negotiate_);
            io_context_recv_negotiate_.wsa_buf.buf = static_cast<char*>(buffer);
            io_context_recv_negotiate_.wsa_buf.len = length;

            if (this->post_recv(
                tcp_proxy_socket<T>::remote_socket_,
                &io_context_recv_negotiate_.wsa_buf,
                &io_context_recv_negotiate_) == SOCKET_ERROR)
            {
                tcp_proxy_socket<T>::close_client(true, false);
                return false;
            }

            return true;
        }

        [[nodiscard]] bool start_connect_reply_receive(const socks5_state state, void* const buffer, const ULONG length)
        {
            current_state_ = state;
            connect_reply_buffer_ = static_cast<unsigned char*>(buffer);
            connect_reply_expected_ = length;
            connect_reply_received_ = 0;
            return start_negotiate_receive(buffer, length);
        }

        [[nodiscard]] bool accumulate_connect_reply(const uint32_t io_size, void* const buffer, const ULONG length)
        {
            connect_reply_received_ += io_size;
            if (connect_reply_received_ >= length)
            {
                return true;
            }

            if (!start_negotiate_receive(
                static_cast<unsigned char*>(buffer) + connect_reply_received_,
                length - connect_reply_received_))
            {
                return false;
            }

            return false;
        }

        void send_connect_request()
        {
            connect_request_.cmd = 1;
            connect_request_.reserved = 0;
            if constexpr (address_type_t::af_type == AF_INET)
            {
                connect_request_.address_type = 1; // IPv4
            }
            else
            {
                connect_request_.address_type = 4; // IPv6
            }
            connect_request_.dest_address = tcp_proxy_socket<T>::negotiate_ctx_->remote_address;
            connect_request_.dest_port = htons(tcp_proxy_socket<T>::negotiate_ctx_->remote_port);

            reset_overlapped(io_context_send_negotiate_);
            io_context_send_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&connect_request_);
            io_context_send_negotiate_.wsa_buf.len = sizeof(socks5_req<T>);

            if (this->post_send(
                tcp_proxy_socket<T>::remote_socket_,
                &io_context_send_negotiate_.wsa_buf,
                &io_context_send_negotiate_) == SOCKET_ERROR)
            {
                tcp_proxy_socket<T>::close_client(false, false);
                return;
            }

            if (!start_connect_reply_receive(
                socks5_state::connect_reply_header,
                &connect_response_header_,
                sizeof(connect_response_header_)))
            {
                return;
            }
        }

        /**
         * @brief Internal state and buffers for SOCKS5 negotiation and connection.
         *
         * - io_context_recv_negotiate_: Per-I/O context for receiving negotiation data from the remote proxy.
         * - io_context_send_negotiate_: Per-I/O context for sending negotiation data to the remote proxy.
         * - current_state_: Tracks the current state of the SOCKS5 handshake and authentication process.
         * - ident_req_: Buffer for the SOCKS5 identification request (supports up to 2 methods).
         * - ident_resp_: Buffer for the SOCKS5 identification response from the proxy.
         * - connect_request_: Buffer for the SOCKS5 CONNECT command request.
         * - connect_response_header_/tail: Buffers for the variable-length SOCKS5 CONNECT response.
         * - username_auth_: Buffer for username/password authentication as per RFC 1929.
         *
         * These members are used to manage the asynchronous negotiation and authentication
         * sequence with the SOCKS5 proxy server, including method selection, credential exchange,
         * and connection establishment.
         */
        per_io_context_t io_context_recv_negotiate_{ proxy_io_operation::negotiate_io_read, nullptr, false };
        per_io_context_t io_context_send_negotiate_{ proxy_io_operation::negotiate_io_write, nullptr, false };

        // Also release this class's two negotiation contexts when breaking the cycle.
        void release_self_references() noexcept override
        {
            tcp_proxy_socket<T>::release_self_references();
            io_context_recv_negotiate_.proxy_socket_ptr.reset();
            io_context_send_negotiate_.proxy_socket_ptr.reset();
        }

        socks5_state current_state_{ socks5_state::pre_login };
        socks5_ident_req<2> ident_req_{};
        socks5_ident_resp ident_resp_{};
        socks5_req<address_type_t> connect_request_;
        socks5_resp_header connect_response_header_{};
        std::array<unsigned char, 1 + socks5_username_max_length + sizeof(unsigned short)> connect_response_tail_{};
        unsigned char* connect_reply_buffer_{ nullptr };
        ULONG connect_reply_expected_{ 0 };
        ULONG connect_reply_received_{ 0 };
        socks5_username_auth username_auth_{};

    protected:
        /**
         * @brief Indicates that no local-side negotiation is required for SOCKS5.
         *
         * This method is called to perform any protocol-specific negotiation on the local (client) side
         * before establishing a connection to the remote SOCKS5 proxy. For SOCKS5, no such negotiation
         * is needed, so this method always returns true.
         *
         * @return Always returns true.
         */
        bool local_negotiate() override
        {
            return true;
        }

        /**
         * @brief Initiates the SOCKS5 negotiation sequence with the remote proxy.
         *
         * This method starts the SOCKS5 handshake by sending an identification request to the remote proxy.
         * If username/password credentials are provided in the negotiation context, the request will include
         * the USERNAME/PASSWORD method; otherwise, only "NO AUTHENTICATION REQUIRED" is offered.
         * The method sets up the necessary buffers and asynchronous send/receive operations for the handshake.
         *
         * @return False if negotiation is in progress, true if negotiation is already complete or not required.
         */
        bool remote_negotiate() override
        {
            if (tcp_proxy_socket<T>::negotiate_ctx_)
            {
                if (current_state_ == socks5_state::pre_login)
                {
                    NETLIB_DEBUG("Starting SOCKS5 negotiation with remote proxy");

                    auto socks5_ident_req_size = sizeof(ident_req_);

                    ident_req_.methods[0] = 0x0; // RFC 1928: X'00' NO AUTHENTICATION REQUIRED
                    ident_req_.methods[1] = 0x2; // RFC 1928: X'02' USERNAME/PASSWORD

                    // Don't suggest username/password option if not provided
                    if (auto* negotiate_context_ptr = dynamic_cast<negotiate_context_t*>(tcp_proxy_socket<
                        T>::negotiate_ctx_.get()); !negotiate_context_ptr->socks5_username.has_value())
                    {
                        ident_req_.number_of_methods = 1;
                        socks5_ident_req_size = sizeof(socks5_ident_req<1>);
                        NETLIB_DEBUG("SOCKS5 authentication methods: NO_AUTH only (no credentials provided)");
                    }
                    else
                    {
                        NETLIB_DEBUG("SOCKS5 authentication methods: NO_AUTH and USERNAME/PASSWORD");
                    }

                    io_context_send_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&ident_req_);
                    io_context_send_negotiate_.wsa_buf.len = static_cast<ULONG>(socks5_ident_req_size);
                    io_context_recv_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&ident_resp_);
                    io_context_recv_negotiate_.wsa_buf.len = sizeof(socks5_ident_resp);

                    NETLIB_DEBUG("Sending SOCKS5 identification request ({} bytes)", socks5_ident_req_size);

                    if (this->post_send(
                        tcp_proxy_socket<T>::remote_socket_,
                        &io_context_send_negotiate_.wsa_buf,
                        &io_context_send_negotiate_) == SOCKET_ERROR)
                    {
                        const auto error = WSAGetLastError();
                        NETLIB_ERROR("Failed to send SOCKS5 identification request: WSA error {}", error);
                        tcp_proxy_socket<T>::close_client(false, false);
                        return false;
                    }

                    current_state_ = socks5_state::login_sent;
                    NETLIB_DEBUG("SOCKS5 identification request sent, waiting for response");

                    if (this->post_recv(
                        tcp_proxy_socket<T>::remote_socket_,
                        &io_context_recv_negotiate_.wsa_buf,
                        &io_context_recv_negotiate_) == SOCKET_ERROR)
                    {
                        const auto error = WSAGetLastError();
                        NETLIB_ERROR("Failed to receive SOCKS5 identification response: WSA error {}", error);
                        tcp_proxy_socket<T>::close_client(true, false);
                        return false;
                    }
                }

                return false;
            }

            NETLIB_DEBUG("SOCKS5 negotiation skipped - no negotiation context available");
            return true;
        }
    };
}
