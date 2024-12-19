// ReSharper disable CppExpressionWithoutSideEffects
// ReSharper disable CppClangTidyClangDiagnosticUnusedValue
#pragma once

namespace proxy
{
    template <typename T>
    class socks5_tcp_proxy_socket final : public tcp_proxy_socket<T>
    {
        enum class socks5_state : uint8_t
        {
            pre_login,
            login_sent,
            login_responded,
            password_sent,
            password_responded,
            connect_sent
        };

    public:
        using log_level = netlib::log::log_level;
        using address_type_t = T;
        using negotiate_context_t = socks5_negotiate_context<T>;
        using per_io_context_t = tcp_per_io_context<T>;

        socks5_tcp_proxy_socket(const SOCKET local_socket, const SOCKET remote_socket,
                                std::unique_ptr<negotiate_context_t> negotiate_ctx,
                                const log_level log_level = log_level::error,
                                const std::optional<std::reference_wrapper<std::ostream>> log_stream = std::nullopt)
            : tcp_proxy_socket<T>(local_socket, remote_socket, std::move(negotiate_ctx), log_level,
                                  log_stream)
        {
        }

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

                                    DWORD flags = 0;

                                    if ((::WSASend(
                                        tcp_proxy_socket<T>::remote_socket_,
                                        &io_context_send_negotiate_.wsa_buf,
                                        1,
                                        nullptr,
                                        0,
                                        &io_context_send_negotiate_,
                                        nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                                    {
                                        tcp_proxy_socket<T>::close_client(false, false);
                                    }

                                    current_state_ = socks5_state::password_sent;

                                    if ((::WSARecv(
                                        tcp_proxy_socket<T>::remote_socket_,
                                        &io_context_recv_negotiate_.wsa_buf,
                                        1,
                                        nullptr,
                                        &flags,
                                        &io_context_recv_negotiate_,
                                        nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                                    {
                                        tcp_proxy_socket<T>::close_client(true, false);
                                    }
                                }
                            }
                        }
                        else // NO AUTHENTICATION REQUIRED is chosen
                        {
                            connect_request_.cmd = 1;
                            connect_request_.reserved = 0;
                            connect_request_.address_type = 1;
                            connect_request_.dest_address = tcp_proxy_socket<T>::negotiate_ctx_->remote_address;
                            connect_request_.dest_port = htons(tcp_proxy_socket<T>::negotiate_ctx_->remote_port);

                            io_context_send_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&connect_request_);
                            io_context_send_negotiate_.wsa_buf.len = sizeof(socks5_req<T>);
                            io_context_recv_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&connect_response_);
                            io_context_recv_negotiate_.wsa_buf.len = sizeof(socks5_resp<T>);

                            DWORD flags = 0;

                            if ((::WSASend(
                                tcp_proxy_socket<T>::remote_socket_,
                                &io_context_send_negotiate_.wsa_buf,
                                1,
                                nullptr,
                                0,
                                &io_context_send_negotiate_,
                                nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                            {
                                tcp_proxy_socket<T>::close_client(false, false);
                            }

                            current_state_ = socks5_state::connect_sent;

                            if ((::WSARecv(
                                tcp_proxy_socket<T>::remote_socket_,
                                &io_context_recv_negotiate_.wsa_buf,
                                1,
                                nullptr,
                                &flags,
                                &io_context_recv_negotiate_,
                                nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                            {
                                tcp_proxy_socket<T>::close_client(true, false);
                            }
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
                        connect_request_.cmd = 1;
                        connect_request_.reserved = 0;
                        connect_request_.address_type = 1;
                        connect_request_.dest_address = tcp_proxy_socket<T>::negotiate_ctx_->remote_address;
                        connect_request_.dest_port = htons(tcp_proxy_socket<T>::negotiate_ctx_->remote_port);

                        io_context_send_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&connect_request_);
                        io_context_send_negotiate_.wsa_buf.len = sizeof(socks5_req<T>);
                        io_context_recv_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&connect_response_);
                        io_context_recv_negotiate_.wsa_buf.len = sizeof(socks5_resp<T>);

                        DWORD flags = 0;

                        if ((::WSASend(
                            tcp_proxy_socket<T>::remote_socket_,
                            &io_context_send_negotiate_.wsa_buf,
                            1,
                            nullptr,
                            0,
                            &io_context_send_negotiate_,
                            nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                        {
                            tcp_proxy_socket<T>::close_client(false, false);
                        }

                        current_state_ = socks5_state::connect_sent;

                        if ((::WSARecv(
                            tcp_proxy_socket<T>::remote_socket_,
                            &io_context_recv_negotiate_.wsa_buf,
                            1,
                            nullptr,
                            &flags,
                            &io_context_recv_negotiate_,
                            nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                        {
                            tcp_proxy_socket<T>::close_client(true, false);
                        }
                    }
                }
                else if (current_state_ == socks5_state::connect_sent)
                {
                    if (connect_response_.reply != 0)
                    {
                        // SOCKS v5 connect failed
                        tcp_proxy_socket<T>::close_client(true, false);
                    }
                    else
                    {
                        tcp_proxy_socket<T>::start_data_relay();
                    }
                }
            }
        }

    private:
        per_io_context_t io_context_recv_negotiate_{proxy_io_operation::negotiate_io_read, this, false};
        per_io_context_t io_context_send_negotiate_{proxy_io_operation::negotiate_io_write, this, false};

        socks5_state current_state_{socks5_state::pre_login};
        socks5_ident_req<2> ident_req_{};
        socks5_ident_resp ident_resp_{};
        socks5_req<address_type_t> connect_request_;
        socks5_resp<address_type_t> connect_response_;
        socks5_username_auth username_auth_{};

    protected:
        bool local_negotiate() override
        {
            return true;
        }

        bool remote_negotiate() override
        {
            if (tcp_proxy_socket<T>::negotiate_ctx_)
            {
                if (current_state_ == socks5_state::pre_login)
                {
                    auto socks5_ident_req_size = sizeof(ident_req_);

                    ident_req_.methods[0] = 0x0; // RFC 1928: X'00' NO AUTHENTICATION REQUIRED
                    ident_req_.methods[1] = 0x2; // RFC 1928: X'02' USERNAME/PASSWORD

                    // Don't suggest username/password option if not provided
                    if (auto* negotiate_context_ptr = dynamic_cast<negotiate_context_t*>(tcp_proxy_socket<
                        T>::negotiate_ctx_.get()); !negotiate_context_ptr->socks5_username.has_value())
                    {
                        ident_req_.number_of_methods = 1;
                        socks5_ident_req_size = sizeof(socks5_ident_req<1>);
                    }

                    io_context_send_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&ident_req_);
                    io_context_send_negotiate_.wsa_buf.len = static_cast<ULONG>(socks5_ident_req_size);
                    io_context_recv_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&ident_resp_);
                    io_context_recv_negotiate_.wsa_buf.len = sizeof(socks5_ident_resp);

                    DWORD flags = 0;

                    if ((::WSASend(
                        tcp_proxy_socket<T>::remote_socket_,
                        &io_context_send_negotiate_.wsa_buf,
                        1,
                        nullptr,
                        0,
                        &io_context_send_negotiate_,
                        nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                    {
                        tcp_proxy_socket<T>::close_client(false, false);
                    }

                    current_state_ = socks5_state::login_sent;

                    if ((::WSARecv(
                        tcp_proxy_socket<T>::remote_socket_,
                        &io_context_recv_negotiate_.wsa_buf,
                        1,
                        nullptr,
                        &flags,
                        &io_context_recv_negotiate_,
                        nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
                    {
                        tcp_proxy_socket<T>::close_client(true, false);
                    }
                }

                return false;
            }

            return true;
        }
    };
}
