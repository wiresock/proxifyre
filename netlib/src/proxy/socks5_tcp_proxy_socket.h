// ReSharper disable CppClangTidyClangDiagnosticComma
// ReSharper disable CppExpressionWithoutSideEffects
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
         * @brief Starts plain SOCKS5 negotiation or the native SOCKS5-over-TLS path.
         */
        bool start() override
        {
            auto* const negotiate_context_ptr = dynamic_cast<negotiate_context_t*>(
                tcp_proxy_socket<T>::negotiate_ctx_.get());
            if (negotiate_context_ptr == nullptr || !negotiate_context_ptr->upstream_options.is_tls())
            {
                return tcp_proxy_socket<T>::start();
            }

            return start_tls_transport(*negotiate_context_ptr);
        }

        void process_receive_buffer_complete(const uint32_t io_size, per_io_context_t* io_context) override
        {
            if (!tls_relay_active_.load(std::memory_order_acquire))
            {
                tcp_proxy_socket<T>::process_receive_buffer_complete(io_size, io_context);
                return;
            }

            NETLIB_DEBUG(
                "SOCKS5Tls relay received {} bytes from the {} socket",
                io_size,
                io_context->is_local ? "local" : "upstream");

            std::scoped_lock lock(tcp_proxy_socket<T>::lock_);
            tcp_proxy_socket<T>::timestamp_ = std::chrono::steady_clock::now();

            if (tcp_proxy_socket<T>::connection_status_ == connection_status::client_completed)
            {
                if (io_context->is_local)
                {
                    tcp_proxy_socket<T>::local_recv_buf_.len = 0;
                }
                else
                {
                    tcp_proxy_socket<T>::remote_recv_buf_.len = 0;
                }
                return;
            }

            if (io_context->is_local)
            {
                tcp_proxy_socket<T>::local_recv_buf_.len = 0;
                if (tcp_proxy_socket<T>::remote_send_buf_.len != 0)
                {
                    NETLIB_ERROR("SOCKS5Tls relay invariant failed: overlapping sends to the upstream proxy");
                    tcp_proxy_socket<T>::close_client<true>(true, true);
                    return;
                }

                if (!tls_stream_->encrypt(
                    tcp_proxy_socket<T>::from_local_to_remote_buffer_.data(),
                    io_size,
                    tls_encrypted_send_buffer_))
                {
                    NETLIB_WARNING("SOCKS5Tls relay encryption failed: {}", tls_stream_->last_error());
                    tcp_proxy_socket<T>::close_client<true>(true, true);
                    return;
                }

                if (!post_tls_remote_send_locked())
                {
                    tcp_proxy_socket<T>::close_client<true>(false, false);
                }
                return;
            }

            tcp_proxy_socket<T>::remote_recv_buf_.len = 0;
            if (tcp_proxy_socket<T>::local_send_buf_.len != 0)
            {
                NETLIB_ERROR("SOCKS5Tls relay invariant failed: overlapping sends to the local client");
                tcp_proxy_socket<T>::close_client<true>(true, false);
                return;
            }

            const auto decrypt_result = tls_stream_->decrypt_available(
                tcp_proxy_socket<T>::from_remote_to_local_buffer_.data(),
                io_size,
                tls_plaintext_send_buffer_);
            if (decrypt_result == schannel_tls_stream::decrypt_status::failed)
            {
                NETLIB_WARNING("SOCKS5Tls relay decryption failed: {}", tls_stream_->last_error());
                tcp_proxy_socket<T>::close_client<true>(true, false);
                return;
            }

            if (decrypt_result == schannel_tls_stream::decrypt_status::closed)
            {
                tls_remote_closed_ = true;
                tcp_proxy_socket<T>::connection_status_ = connection_status::client_completed;
            }

            if (!tls_plaintext_send_buffer_.empty())
            {
                if (!post_tls_local_send_locked())
                {
                    tcp_proxy_socket<T>::close_client<true>(false, true);
                }
                return;
            }

            if (tls_remote_closed_)
            {
                close_tls_after_drain_locked();
                return;
            }

            if (!post_tls_remote_receive_locked())
            {
                tcp_proxy_socket<T>::close_client<true>(true, false);
            }
        }

        void process_send_buffer_complete(const uint32_t io_size, per_io_context_t* io_context) override
        {
            if (!tls_relay_active_.load(std::memory_order_acquire))
            {
                tcp_proxy_socket<T>::process_send_buffer_complete(io_size, io_context);
                return;
            }

            NETLIB_DEBUG(
                "SOCKS5Tls relay sent {} bytes to the {} socket",
                io_size,
                io_context->is_local ? "local" : "upstream");

            std::scoped_lock lock(tcp_proxy_socket<T>::lock_);
            tcp_proxy_socket<T>::timestamp_ = std::chrono::steady_clock::now();

            auto& send_buffer = io_context->is_local
                ? tcp_proxy_socket<T>::local_send_buf_
                : tcp_proxy_socket<T>::remote_send_buf_;
            if (io_size == 0 || io_size > send_buffer.len)
            {
                NETLIB_WARNING(
                    "SOCKS5Tls relay received an invalid send completion ({} of {} bytes)",
                    io_size,
                    send_buffer.len);
                tcp_proxy_socket<T>::close_client<true>(false, io_context->is_local);
                return;
            }

            send_buffer.buf += io_size;
            send_buffer.len -= io_size;
            if (send_buffer.len != 0)
            {
                reset_overlapped(io_context->is_local
                    ? tcp_proxy_socket<T>::io_context_send_to_local_
                    : tcp_proxy_socket<T>::io_context_send_to_remote_);
                const auto socket = io_context->is_local
                    ? tcp_proxy_socket<T>::local_socket_
                    : tcp_proxy_socket<T>::remote_socket_;
                if (this->post_send(socket, &send_buffer, io_context) == SOCKET_ERROR)
                {
                    tcp_proxy_socket<T>::close_client<true>(false, io_context->is_local);
                }
                return;
            }

            send_buffer.buf = nullptr;
            if (io_context->is_local)
            {
                tls_plaintext_send_buffer_.clear();
            }
            else
            {
                tls_encrypted_send_buffer_.clear();
            }

            if (tcp_proxy_socket<T>::connection_status_ == connection_status::client_completed)
            {
                close_tls_after_drain_locked();
                return;
            }

            const auto receive_posted = io_context->is_local
                ? post_tls_remote_receive_locked()
                : post_tls_local_receive_locked();
            if (!receive_posted)
            {
                tcp_proxy_socket<T>::close_client<true>(true, !io_context->is_local);
            }
        }

        void on_peer_read_shutdown(const bool is_local) override
        {
            if (!tls_relay_active_.load(std::memory_order_acquire))
            {
                tcp_proxy_socket<T>::on_peer_read_shutdown(is_local);
                return;
            }

            std::scoped_lock lock(tcp_proxy_socket<T>::lock_);
            if (tcp_proxy_socket<T>::connection_status_ == connection_status::client_completed)
            {
                return;
            }

            tcp_proxy_socket<T>::timestamp_ = std::chrono::steady_clock::now();
            tcp_proxy_socket<T>::connection_status_ = connection_status::client_completed;
            if (is_local)
            {
                tcp_proxy_socket<T>::local_recv_buf_.len = 0;
            }
            else
            {
                tcp_proxy_socket<T>::remote_recv_buf_.len = 0;
            }

            const auto socket = is_local
                ? tcp_proxy_socket<T>::local_socket_
                : tcp_proxy_socket<T>::remote_socket_;
            if (socket != static_cast<SOCKET>(INVALID_SOCKET) && shutdown(socket, SD_RECEIVE) == SOCKET_ERROR)
            {
                NETLIB_DEBUG("SOCKS5Tls relay shutdown(SD_RECEIVE) failed: {}", WSAGetLastError());
            }

            close_tls_after_drain_locked();
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
                // Unlike the base handler and the relay completion handlers, this SOCKS5 override
                // must guard the negotiation state (current_state_, ident_resp_, the negotiate
                // io-contexts, remote_socket_) against a concurrent close_client()/stop() running
                // on another IOCP thread. The IOCP dispatcher calls this handler WITHOUT holding
                // lock_, so acquire it here. Every close_client() reachable from this handler uses
                // the AlreadyLocked (<true>) form to avoid re-locking the non-recursive mutex; the
                // lock is released before start_data_relay() (which locks internally).
                std::unique_lock<std::mutex> lock(tcp_proxy_socket<T>::lock_);

                if (current_state_ == socks5_state::login_sent)
                {
                    // The method-selection reply is 2 bytes but TCP may deliver it across multiple
                    // completions. Accumulate before parsing; a short read otherwise reads a stale
                    // ident_resp_.method (0 -> mis-parsed as NO-AUTH) and desyncs the handshake.
                    ident_resp_received_ += io_size;
                    if (ident_resp_received_ < sizeof(socks5_ident_resp))
                    {
                        static_cast<void>(start_negotiate_receive(
                            reinterpret_cast<char*>(&ident_resp_) + ident_resp_received_,
                            static_cast<ULONG>(sizeof(socks5_ident_resp)) - ident_resp_received_));
                        return;
                    }

                    current_state_ = socks5_state::login_responded;

                    if ((ident_resp_.version != socks5_protocol_version) ||
                        (ident_resp_.method != 0x00 && ident_resp_.method != 0x02))
                    {
                        // SOCKS v5 identification or authentication failed
                        tcp_proxy_socket<T>::close_client<true>(true, false);  // NOLINT(bugprone-chained-comparison)
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
                                tcp_proxy_socket<T>::close_client<true>(true, false);  // NOLINT(bugprone-chained-comparison)
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
                                        tcp_proxy_socket<T>::close_client<true>(false, false);  // NOLINT(bugprone-chained-comparison)
                                        return;
                                    }

                                    current_state_ = socks5_state::password_sent;
                                    ident_resp_received_ = 0; // reset for the 2-byte auth reply

                                    if (this->post_recv(
                                        tcp_proxy_socket<T>::remote_socket_,
                                        &io_context_recv_negotiate_.wsa_buf,
                                        &io_context_recv_negotiate_) == SOCKET_ERROR)
                                    {
                                        tcp_proxy_socket<T>::close_client<true>(true, false);  // NOLINT(bugprone-chained-comparison)
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
                    // Accumulate the 2-byte auth reply the same way (see login_sent).
                    ident_resp_received_ += io_size;
                    if (ident_resp_received_ < sizeof(socks5_ident_resp))
                    {
                        static_cast<void>(start_negotiate_receive(
                            reinterpret_cast<char*>(&ident_resp_) + ident_resp_received_,
                            static_cast<ULONG>(sizeof(socks5_ident_resp)) - ident_resp_received_));
                        return;
                    }

                    current_state_ = socks5_state::password_responded;

                    if (ident_resp_.version != socks5_username_auth_version || ident_resp_.method != 0)
                    {
                        // SOCKS v5 identification or authentication failed
                        tcp_proxy_socket<T>::close_client<true>(true, false);  // NOLINT(bugprone-chained-comparison)
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
                        (connect_response_header_.reserved != 0) ||
                        (connect_response_header_.reply != 0))
                    {
                        // SOCKS v5 connect failed
                        tcp_proxy_socket<T>::close_client<true>(true, false);  // NOLINT(bugprone-chained-comparison)
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
                        tcp_proxy_socket<T>::close_client<true>(true, false); // NOLINT(bugprone-chained-comparison)
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
                    if (domain_length == 0)
                    {
                        tcp_proxy_socket<T>::close_client<true>(true, false);
                        return;
                    }
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

                    // start_data_relay() locks lock_ internally (via close_client on its error
                    // paths), so release our lock first to avoid re-locking the non-recursive
                    // mutex. This is the terminal action of the handler; no shared negotiation
                    // state is touched afterwards.
                    lock.unlock();
                    tcp_proxy_socket<T>::start_data_relay();
                }
            }
        }

    private:
        class socket_send_timeout_guard
        {
        public:
            explicit socket_send_timeout_guard(const SOCKET socket) noexcept
                : socket_(socket)
            {
                int option_size = static_cast<int>(sizeof(original_timeout_));
                if (getsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO,
                    reinterpret_cast<char*>(&original_timeout_), &option_size) == SOCKET_ERROR)
                {
                    error_ = WSAGetLastError();
                    return;
                }

                constexpr DWORD timeout_ms = 5000;
                if (setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO,
                    reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms)) == SOCKET_ERROR)
                {
                    error_ = WSAGetLastError();
                    return;
                }

                configured_ = true;
            }

            socket_send_timeout_guard(const socket_send_timeout_guard&) = delete;
            socket_send_timeout_guard& operator=(const socket_send_timeout_guard&) = delete;

            ~socket_send_timeout_guard()
            {
                if (configured_)
                {
                    setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO,
                        reinterpret_cast<const char*>(&original_timeout_), sizeof(original_timeout_));
                }
            }

            [[nodiscard]] bool configured() const noexcept
            {
                return configured_;
            }

            [[nodiscard]] int error() const noexcept
            {
                return error_;
            }

        private:
            SOCKET socket_{ INVALID_SOCKET };
            DWORD original_timeout_ = 0;
            int error_ = 0;
            bool configured_ = false;
        };

        struct socks5_resp_header
        {
            unsigned char version = socks5_protocol_version;
            unsigned char reply{};
            unsigned char reserved{};
            unsigned char address_type{};
        };

        [[nodiscard]] bool start_tls_transport(negotiate_context_t& negotiate_context)
        {
            if (tcp_proxy_socket<T>::is_disable_nagle_)
            {
                const int enabled = 1;
                if (setsockopt(tcp_proxy_socket<T>::remote_socket_, IPPROTO_TCP, TCP_NODELAY,
                    reinterpret_cast<const char*>(&enabled), sizeof(enabled)) == SOCKET_ERROR)
                {
                    NETLIB_WARNING("SOCKS5Tls failed to set TCP_NODELAY: {}", WSAGetLastError());
                }
            }

            // WSAEventSelect makes the connect socket non-blocking. TLS setup is deliberately
            // synchronous and bounded, after which the socket returns to overlapped IOCP I/O.
            if (WSAEventSelect(tcp_proxy_socket<T>::remote_socket_, nullptr, 0) == SOCKET_ERROR)
            {
                NETLIB_WARNING("SOCKS5Tls failed to detach the connect event: {}", WSAGetLastError());
                tcp_proxy_socket<T>::close_client(false, false);
                return false;
            }

            u_long blocking_mode = 0;
            if (ioctlsocket(tcp_proxy_socket<T>::remote_socket_, FIONBIO, &blocking_mode) == SOCKET_ERROR)
            {
                NETLIB_WARNING("SOCKS5Tls failed to restore blocking setup mode: {}", WSAGetLastError());
                tcp_proxy_socket<T>::close_client(false, false);
                return false;
            }

            socket_send_timeout_guard send_timeout{ tcp_proxy_socket<T>::remote_socket_ };
            if (!send_timeout.configured())
            {
                NETLIB_WARNING("SOCKS5Tls failed to configure the setup send timeout: {}", send_timeout.error());
                tcp_proxy_socket<T>::close_client(false, false);
                return false;
            }

            tls_stream_ = std::make_unique<schannel_tls_stream>(
                tcp_proxy_socket<T>::remote_socket_,
                negotiate_context.upstream_options.tls);
            if (!tls_stream_->handshake())
            {
                NETLIB_WARNING("SOCKS5Tls handshake failed: {}", tls_stream_->last_error());
                tcp_proxy_socket<T>::close_client(false, false);
                return false;
            }

            if (!perform_tls_socks5_connect(negotiate_context))
            {
                NETLIB_WARNING("SOCKS5Tls CONNECT negotiation failed: {}", tls_negotiation_error_);
                tcp_proxy_socket<T>::close_client(false, false);
                return false;
            }

            return start_tls_data_relay();
        }

        [[nodiscard]] bool perform_tls_socks5_connect(const negotiate_context_t& negotiate_context)
        {
            const auto fail = [this](std::string error)
            {
                tls_negotiation_error_ = std::move(error);
                return false;
            };
            const auto send_tls = [this, &fail](const void* const data, const int length)
            {
                return tls_stream_->send_all(data, length)
                    ? true
                    : fail(tls_stream_->last_error());
            };
            const auto recv_tls = [this, &fail](void* const data, const int length)
            {
                return tls_stream_->recv_exact(data, length)
                    ? true
                    : fail(tls_stream_->last_error());
            };

            const auto has_username = negotiate_context.socks5_username.has_value();
            const auto has_password = negotiate_context.socks5_password.has_value();
            if (has_username != has_password)
            {
                return fail("SOCKS5 username and password must be configured together.");
            }
            if (has_username && (negotiate_context.socks5_username->empty() ||
                negotiate_context.socks5_username->size() > socks5_username_max_length ||
                negotiate_context.socks5_password->empty() ||
                negotiate_context.socks5_password->size() > socks5_username_max_length))
            {
                return fail("SOCKS5 username and password must each contain between 1 and 255 bytes.");
            }

            socks5_ident_req<2> ident_request{};
            ident_request.methods[0] = 0x00;
            auto ident_request_size = sizeof(socks5_ident_req<1>);
            if (has_username)
            {
                ident_request.number_of_methods = 2;
                ident_request.methods[1] = 0x02;
                ident_request_size = sizeof(ident_request);
            }
            else
            {
                ident_request.number_of_methods = 1;
            }

            socks5_ident_resp ident_response{};
            if (!send_tls(&ident_request, static_cast<int>(ident_request_size)) ||
                !recv_tls(&ident_response, sizeof(ident_response)))
            {
                return false;
            }
            if (ident_response.version != socks5_protocol_version)
            {
                return fail("The upstream returned an invalid SOCKS5 method-selection version.");
            }
            if (ident_response.method != 0x00 && ident_response.method != 0x02)
            {
                return fail("The upstream selected an unsupported SOCKS5 authentication method.");
            }

            if (ident_response.method == 0x02)
            {
                if (!has_username)
                {
                    return fail("The upstream requires SOCKS5 username/password authentication.");
                }

                socks5_username_auth username_auth{};
                const auto auth_size = username_auth.init(
                    *negotiate_context.socks5_username,
                    *negotiate_context.socks5_password);
                socks5_ident_resp auth_response{};
                if (auth_size == 0 ||
                    !send_tls(&username_auth, static_cast<int>(auth_size)) ||
                    !recv_tls(&auth_response, sizeof(auth_response)))
                {
                    return false;
                }
                if (auth_response.version != socks5_username_auth_version || auth_response.method != 0)
                {
                    return fail("The upstream rejected SOCKS5 username/password authentication.");
                }
            }

            socks5_req<address_type_t> connect_request{
                socks5_protocol_version,
                1,
                0,
                address_type_t::af_type == AF_INET ? static_cast<unsigned char>(1) : static_cast<unsigned char>(4),
                negotiate_context.remote_address,
                htons(negotiate_context.remote_port)
            };

            socks5_resp_header response_header{};
            if (!send_tls(&connect_request, sizeof(connect_request)) ||
                !recv_tls(&response_header, sizeof(response_header)))
            {
                return false;
            }
            if (response_header.version != socks5_protocol_version || response_header.reserved != 0)
            {
                return fail("The upstream returned an invalid SOCKS5 CONNECT response header.");
            }
            if (response_header.reply != 0)
            {
                return fail("The upstream rejected SOCKS5 CONNECT with reply code " +
                    std::to_string(response_header.reply) + ".");
            }

            std::array<unsigned char, socks5_username_max_length + sizeof(unsigned short)> response_tail{};
            switch (response_header.address_type)
            {
            case 1:
                return recv_tls(response_tail.data(), 4 + sizeof(unsigned short));
            case 4:
                return recv_tls(response_tail.data(), 16 + sizeof(unsigned short));
            case 3:
            {
                unsigned char domain_length = 0;
                if (!recv_tls(&domain_length, sizeof(domain_length)))
                {
                    return false;
                }
                if (domain_length == 0)
                {
                    return fail("The upstream returned an empty SOCKS5 bound domain name.");
                }
                return recv_tls(
                    response_tail.data(),
                    static_cast<int>(domain_length + sizeof(unsigned short)));
            }
            default:
                return fail("The upstream returned an unsupported SOCKS5 bound address type.");
            }
        }

        [[nodiscard]] bool start_tls_data_relay()
        {
            std::scoped_lock lock(tcp_proxy_socket<T>::lock_);
            tls_relay_active_.store(true, std::memory_order_release);

            const auto decrypt_result = tls_stream_->decrypt_available(
                nullptr,
                0,
                tls_plaintext_send_buffer_);
            if (decrypt_result == schannel_tls_stream::decrypt_status::failed)
            {
                NETLIB_WARNING("SOCKS5Tls failed to process buffered data: {}", tls_stream_->last_error());
                tcp_proxy_socket<T>::close_client<true>(true, false);
                return false;
            }
            if (decrypt_result == schannel_tls_stream::decrypt_status::closed)
            {
                tls_remote_closed_ = true;
                tcp_proxy_socket<T>::connection_status_ = connection_status::client_completed;
            }

            if (tcp_proxy_socket<T>::connection_status_ != connection_status::client_completed &&
                !post_tls_local_receive_locked())
            {
                tcp_proxy_socket<T>::close_client<true>(true, true);
                return false;
            }

            if (!tls_plaintext_send_buffer_.empty())
            {
                NETLIB_DEBUG(
                    "SOCKS5Tls relay has {} bytes of setup read-ahead",
                    tls_plaintext_send_buffer_.size());
                if (!post_tls_local_send_locked())
                {
                    tcp_proxy_socket<T>::close_client<true>(false, true);
                    return false;
                }
                return true;
            }

            if (tls_remote_closed_)
            {
                close_tls_after_drain_locked();
                return false;
            }

            if (!post_tls_remote_receive_locked())
            {
                tcp_proxy_socket<T>::close_client<true>(true, false);
                return false;
            }

            NETLIB_INFO("SOCKS5Tls TCP CONNECT relay established");
            return true;
        }

        [[nodiscard]] bool post_tls_local_receive_locked()
        {
            reset_overlapped(tcp_proxy_socket<T>::io_context_recv_from_local_);
            tcp_proxy_socket<T>::local_recv_buf_.buf =
                tcp_proxy_socket<T>::from_local_to_remote_buffer_.data();
            tcp_proxy_socket<T>::local_recv_buf_.len = static_cast<ULONG>(
                tcp_proxy_socket<T>::from_local_to_remote_buffer_.size());
            if (this->post_recv(
                tcp_proxy_socket<T>::local_socket_,
                &this->local_recv_buf_,
                &this->io_context_recv_from_local_) == SOCKET_ERROR)
            {
                tcp_proxy_socket<T>::local_recv_buf_.len = 0;
                NETLIB_WARNING("SOCKS5Tls failed to post a local receive: {}", WSAGetLastError());
                return false;
            }
            NETLIB_DEBUG("SOCKS5Tls relay posted a local receive");
            return true;
        }

        [[nodiscard]] bool post_tls_remote_receive_locked()
        {
            reset_overlapped(tcp_proxy_socket<T>::io_context_recv_from_remote_);
            tcp_proxy_socket<T>::remote_recv_buf_.buf =
                tcp_proxy_socket<T>::from_remote_to_local_buffer_.data();
            tcp_proxy_socket<T>::remote_recv_buf_.len = static_cast<ULONG>(
                tcp_proxy_socket<T>::from_remote_to_local_buffer_.size());
            if (this->post_recv(
                tcp_proxy_socket<T>::remote_socket_,
                &this->remote_recv_buf_,
                &this->io_context_recv_from_remote_) == SOCKET_ERROR)
            {
                tcp_proxy_socket<T>::remote_recv_buf_.len = 0;
                NETLIB_WARNING("SOCKS5Tls failed to post an upstream receive: {}", WSAGetLastError());
                return false;
            }
            NETLIB_DEBUG("SOCKS5Tls relay posted an upstream receive");
            return true;
        }

        [[nodiscard]] bool post_tls_local_send_locked()
        {
            if (tls_plaintext_send_buffer_.empty())
            {
                return false;
            }

            reset_overlapped(tcp_proxy_socket<T>::io_context_send_to_local_);
            tcp_proxy_socket<T>::local_send_buf_.buf = tls_plaintext_send_buffer_.data();
            tcp_proxy_socket<T>::local_send_buf_.len = static_cast<ULONG>(tls_plaintext_send_buffer_.size());
            if (this->post_send(
                tcp_proxy_socket<T>::local_socket_,
                &this->local_send_buf_,
                &this->io_context_send_to_local_) == SOCKET_ERROR)
            {
                tcp_proxy_socket<T>::local_send_buf_.len = 0;
                NETLIB_WARNING("SOCKS5Tls failed to post a local send: {}", WSAGetLastError());
                return false;
            }
            NETLIB_DEBUG(
                "SOCKS5Tls relay posted {} plaintext bytes to the local socket",
                tcp_proxy_socket<T>::local_send_buf_.len);
            return true;
        }

        [[nodiscard]] bool post_tls_remote_send_locked()
        {
            if (tls_encrypted_send_buffer_.empty())
            {
                return false;
            }

            reset_overlapped(tcp_proxy_socket<T>::io_context_send_to_remote_);
            tcp_proxy_socket<T>::remote_send_buf_.buf = tls_encrypted_send_buffer_.data();
            tcp_proxy_socket<T>::remote_send_buf_.len = static_cast<ULONG>(tls_encrypted_send_buffer_.size());
            if (this->post_send(
                tcp_proxy_socket<T>::remote_socket_,
                &this->remote_send_buf_,
                &this->io_context_send_to_remote_) == SOCKET_ERROR)
            {
                tcp_proxy_socket<T>::remote_send_buf_.len = 0;
                NETLIB_WARNING("SOCKS5Tls failed to post an upstream send: {}", WSAGetLastError());
                return false;
            }
            NETLIB_DEBUG(
                "SOCKS5Tls relay posted {} encrypted bytes to the upstream socket",
                tcp_proxy_socket<T>::remote_send_buf_.len);
            return true;
        }

        void close_tls_after_drain_locked()
        {
            if (tcp_proxy_socket<T>::local_send_buf_.len != 0 ||
                tcp_proxy_socket<T>::remote_send_buf_.len != 0)
            {
                return;
            }

            if (!tls_shutdown_started_ &&
                tcp_proxy_socket<T>::remote_socket_ != static_cast<SOCKET>(INVALID_SOCKET))
            {
                tls_shutdown_started_ = true;
                std::vector<char> shutdown_token;
                if (tls_stream_->create_shutdown_token(shutdown_token))
                {
                    tls_encrypted_send_buffer_ = std::move(shutdown_token);
                    if (post_tls_remote_send_locked())
                    {
                        return;
                    }
                    NETLIB_WARNING("SOCKS5Tls failed to send close_notify: {}", WSAGetLastError());
                }
                else
                {
                    NETLIB_WARNING("SOCKS5Tls failed to create close_notify: {}", tls_stream_->last_error());
                }
            }

            tcp_proxy_socket<T>::local_recv_buf_.len = 0;
            tcp_proxy_socket<T>::remote_recv_buf_.len = 0;
            tcp_proxy_socket<T>::close_client<true>(true, true);
        }

        static void reset_overlapped(per_io_context_t& io_context) noexcept
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
                // Called only from process_receive_negotiate_complete while lock_ is held.
                tcp_proxy_socket<T>::close_client<true>(true, false);  // NOLINT(bugprone-chained-comparison)
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
                // Called only from process_receive_negotiate_complete while lock_ is held.
                tcp_proxy_socket<T>::close_client<true>(false, false); // NOLINT(bugprone-chained-comparison)
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

    public:
        // Also release this class's two negotiation contexts when breaking the cycle. Public (like
        // the base override) so the owning server's stop() can break the reference cycle at shutdown.
        void release_self_references() noexcept override
        {
            tcp_proxy_socket<T>::release_self_references();
            io_context_recv_negotiate_.proxy_socket_ptr.reset();
            io_context_send_negotiate_.proxy_socket_ptr.reset();
        }

    private:
        unsigned char* connect_reply_buffer_{ nullptr };
        ULONG connect_reply_expected_{ 0 };
        ULONG connect_reply_received_{ 0 };
        // Bytes accumulated so far for a fixed 2-byte reply (method-selection / auth). TCP may
        // split the 2 bytes across completions; without accumulating, a 1-byte read would be
        // parsed as a complete reply against stale ident_resp_ contents.
        ULONG ident_resp_received_{ 0 };
        socks5_state current_state_{ socks5_state::pre_login };
        socks5_ident_req<2> ident_req_{};
        socks5_ident_resp ident_resp_{};
        socks5_req<address_type_t> connect_request_;
        socks5_resp_header connect_response_header_{};
        socks5_username_auth username_auth_{};
        std::array<unsigned char, 1 + socks5_username_max_length + sizeof(unsigned short)> connect_response_tail_{};
        std::unique_ptr<schannel_tls_stream> tls_stream_;
        std::vector<char> tls_encrypted_send_buffer_;
        std::vector<char> tls_plaintext_send_buffer_;
        std::string tls_negotiation_error_;
        std::atomic_bool tls_relay_active_{ false };
        bool tls_remote_closed_ = false;
        bool tls_shutdown_started_ = false;

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
                    ident_resp_received_ = 0; // reset for the 2-byte method-selection reply
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
