#pragma once

// SOCKS5 UDP ASSOCIATE client steps shared by the per-source-port UDP proxy server
// (socks5_local_udp_proxy_server.h) and the DNS proxy's shared association
// (socks5_dns_udp_relay.h): connecting the control connection, negotiating authentication and
// UDP ASSOCIATE (optionally over TLS), and creating the UDP socket connected to the relay.

// SIO_UDP_CONNRESET normally comes from <mstcpip.h>, but this header-only file relies on the
// project's master include order and the macro is not reliably visible here across SDKs. Provide
// the standard fallback definition; _WSAIOW/IOC_VENDOR are from <winsock2.h>, which is always
// included ahead of this file.
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

namespace proxy
{
    /**
     * @brief Blocking SOCKS5 UDP ASSOCIATE client.
     *
     * Every step is bounded by timeouts (connect, per-call SO_*TIMEO and an overall receive
     * deadline), so callers run it on a worker thread without holding locks.
     *
     * @tparam AddressT net::ip_address_v4 or net::ip_address_v6: the family of the control and
     *         relay sockets. The IPv6 instance reaches an IPv4 SOCKS5 server through IPv4-mapped
     *         addresses.
     */
    template <typename AddressT>
    class socks5_udp_association_client : public netlib::log::logger<socks5_udp_association_client<AddressT>>
    {
    public:
        using log_level = netlib::log::log_level;
        using logger = netlib::log::logger<socks5_udp_association_client>;
        using address_type_t = AddressT;
        using negotiate_context_t = socks5_negotiate_context<AddressT>;

        /**
         * @brief Requested UDP socket buffer size for QUIC-sized bursts.
         *
         * Browser QUIC can emit many ~1200 byte datagrams immediately. The first
         * datagram for a local UDP source port may need to establish a SOCKS5 TCP
         * control connection and complete UDP ASSOCIATE before it can be forwarded;
         * while that happens, the local UDP proxy socket relies on the kernel
         * receive buffer to hold the rest of the burst.
         */
        constexpr static int udp_socket_buffer_size = 4 * 1024 * 1024;

        explicit socks5_udp_association_client(const log_level log_level = log_level::error,
            std::shared_ptr<std::ostream> log_stream = nullptr)
            : logger(log_level, std::move(log_stream))
        {
        }

        void tune_udp_socket_buffers(const SOCKET socket, const char* const socket_name) const noexcept
        {
            const auto set_buffer = [this, socket, socket_name](const int option, const char* const option_name)
            {
                int requested_size = udp_socket_buffer_size;
                if (setsockopt(socket, SOL_SOCKET, option,
                    reinterpret_cast<const char*>(&requested_size), sizeof(requested_size)) == SOCKET_ERROR)
                {
                    NETLIB_WARNING("{}: failed to set {} to {} bytes: {}",
                        socket_name, option_name, requested_size, WSAGetLastError());
                    return;
                }

                int actual_size = 0;
                int actual_size_len = static_cast<int>(sizeof(actual_size));
                if (getsockopt(socket, SOL_SOCKET, option,
                    reinterpret_cast<char*>(&actual_size), &actual_size_len) == 0)
                {
                    NETLIB_DEBUG("{}: {} is {} bytes", socket_name, option_name, actual_size);
                }
            };

            set_buffer(SO_RCVBUF, "SO_RCVBUF");
            set_buffer(SO_SNDBUF, "SO_SNDBUF");
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
                closesocket(socks_tcp_socket);
                return INVALID_SOCKET;
            }
            
            if (setsockopt(socks_tcp_socket, SOL_SOCKET, SO_SNDTIMEO, 
                          reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms)) == SOCKET_ERROR)
            {
                NETLIB_WARNING("Failed to set socket send timeout: {}", WSAGetLastError());
                closesocket(socks_tcp_socket);
                return INVALID_SOCKET;
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

                timeval tv;
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
            negotiate_ctx) const
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

            std::unique_ptr<schannel_tls_stream> tls_stream;
            if (negotiate_ctx->upstream_options.is_tls())
            {
                tls_stream = std::make_unique<schannel_tls_stream>(
                    socks_tcp_socket,
                    negotiate_ctx->upstream_options.tls);
                if (!tls_stream->handshake())
                {
                    NETLIB_INFO(
                        "[SOCKS5TLS]: associate_to_socks5_proxy: TLS handshake failed: {}",
                        tls_stream->last_error());
                    return {};
                }
            }

            auto control_socket_error = 0;
            const auto send_all_raw = [socks_tcp_socket, &control_socket_error](
                const void* const buffer, const int len) -> bool
            {
                control_socket_error = 0;
                auto* bytes = static_cast<const char*>(buffer);
                int sent_total = 0;
                while (sent_total < len)
                {
                    const auto sent = send(socks_tcp_socket, bytes + sent_total, len - sent_total, 0);
                    if (sent == SOCKET_ERROR)
                    {
                        control_socket_error = WSAGetLastError();
                        return false;
                    }
                    if (sent == 0)
                    {
                        control_socket_error = WSAECONNRESET;
                        return false;
                    }
                    sent_total += sent;
                }
                return true;
            };

            // Blocking read of exactly 'len' bytes (recv() may return short reads on a
            // stream socket); returns false on error or premature close.
            const auto recv_exact_raw = [&control_socket_error](
                const SOCKET s, void* const buffer, const int len) -> bool
            {
                control_socket_error = 0;
                // Bound the TOTAL time spent assembling these bytes, not just each recv().
                // SO_RCVTIMEO is a per-call timeout, so a server that drips one byte just
                // under it could otherwise keep this loop alive for timeout * byte-count.
                constexpr DWORD total_timeout_ms = 5000;

                DWORD original_timeout = total_timeout_ms;
                int original_timeout_size = static_cast<int>(sizeof(original_timeout));
                getsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                    reinterpret_cast<char*>(&original_timeout), &original_timeout_size);

                const auto restore_timeout = [s, original_timeout]  // NOLINT(clang-diagnostic-padded)
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
                        control_socket_error = WSAETIMEDOUT;
                        restore_timeout();
                        return false;
                    }

                    auto remaining_ms = static_cast<DWORD>(deadline - now);
                    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                        reinterpret_cast<const char*>(&remaining_ms), sizeof(remaining_ms)) == SOCKET_ERROR)
                    {
                        control_socket_error = WSAGetLastError();
                        restore_timeout();
                        return false;
                    }

                    const auto n = recv(s, bytes + received, len - received, 0);
                    if (n == SOCKET_ERROR)
                    {
                        control_socket_error = WSAGetLastError();
                        restore_timeout();
                        return false;
                    }
                    if (n == 0)
                    {
                        control_socket_error = WSAECONNRESET;
                        restore_timeout();
                        return false;
                    }
                    received += n;
                }

                restore_timeout();
                return true;
            };

            const auto send_control = [&tls_stream, &send_all_raw](const void* const buffer, const int len) -> bool
            {
                return tls_stream ? tls_stream->send_all(buffer, len) : send_all_raw(buffer, len);
            };

            const auto recv_control = [&tls_stream, socks_tcp_socket, &recv_exact_raw](void* const buffer, const int len) -> bool
            {
                return tls_stream ? tls_stream->recv_exact(buffer, len) : recv_exact_raw(socks_tcp_socket, buffer, len);
            };

            const auto control_error = [&tls_stream, &control_socket_error]
            {
                return tls_stream
                    ? tls_stream->last_error()
                    : std::to_string(control_socket_error);
            };

            if (!send_control(reinterpret_cast<const char*>(&ident_req),
                static_cast<int>(socks5_ident_req_size)))
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: Failed to send socks5_ident_req: {}",
                    control_error());
                return {};
            }

            if (!recv_control(reinterpret_cast<char*>(&ident_resp), sizeof(ident_resp)))
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: Failed to receive socks5_ident_resp: {}",
                    control_error());
                return {};
            }

            if ((ident_resp.version != socks5_protocol_version) ||
                (ident_resp.method != 0x00 && ident_resp.method != 0x02))
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: SOCKS5 selected an unsupported authentication method");
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

                if (!send_control(reinterpret_cast<const char*>(&auth_req),
                    3 + static_cast<int>(negotiate_ctx->socks5_username.value().length()) + 
                    static_cast<int>(negotiate_ctx->socks5_password.value().length())))
                {
                    NETLIB_INFO(
                        "[SOCKS5]: associate_to_socks5_proxy: Failed to send socks5_username_auth: {}",
                        control_error());
                    return {};
                }

                if (!recv_control(reinterpret_cast<char*>(&ident_resp), sizeof(ident_resp)))
                {
                    NETLIB_INFO(
                        "[SOCKS5]: associate_to_socks5_proxy: Failed to receive socks5_ident_resp: {}",
                        control_error());
                    return {};
                }

                if (ident_resp.version != socks5_username_auth_version || ident_resp.method != 0x00)
                {
                    NETLIB_INFO(
                        "[SOCKS5]: associate_to_socks5_proxy: USERNAME/PASSWORD authentication has failed!");
                    return {};
                }

                NETLIB_DEBUG(
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
            if (!send_control(reinterpret_cast<const char*>(associate_req_buf), associate_req_len))
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: Failed to send SOCKS5 ASSOCIATE request: {}",
                    control_error());
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

            // Fixed 4-byte reply prefix: VER, REP, RSV, ATYP.
            struct socks5_resp_prefix
            {
                unsigned char version;
                unsigned char reply;
                unsigned char reserved;
                unsigned char address_type;
            } resp_prefix{};

            if (!recv_control(&resp_prefix, sizeof(resp_prefix)))
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: Failed to receive SOCKS5 ASSOCIATE reply header: {}",
                    control_error());
                return {};
            }

            if ((resp_prefix.version != socks5_protocol_version) ||
                (resp_prefix.reply != 0) ||
                (resp_prefix.reserved != 0))
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
                    if (!recv_control(&domain_len, sizeof(domain_len)))
                    {
                        NETLIB_INFO(
                            "[SOCKS5]: associate_to_socks5_proxy: Failed to receive BND.ADDR domain length: {}",
                            control_error());
                        return {};
                    }
                    if (domain_len == 0)
                    {
                        NETLIB_INFO(
                            "[SOCKS5]: associate_to_socks5_proxy: Empty BND.ADDR domain in ASSOCIATE reply");
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
            if (!recv_control(bnd_addr_and_port,
                bnd_addr_len + static_cast<int>(sizeof(unsigned short))))
            {
                NETLIB_INFO(
                    "[SOCKS5]: associate_to_socks5_proxy: Failed to receive BND.ADDR/BND.PORT: {}",
                    control_error());
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
            NETLIB_DEBUG(
                "[SOCKS5]: associate_to_socks5_proxy: SOCKS5 ASSOCIATE SUCCESS endpoint: {}:{}",
                socks_server_address,
                bind_port);

            return net::ip_endpoint<address_type_t>{ socks_server_address, bind_port };
        }

        /**
         * @brief Creates a UDP socket connected to the SOCKS5 UDP relay endpoint @p udp_endpoint.
         *
         * The socket is bound to an ephemeral port, has SIO_UDP_CONNRESET disabled so an ICMP
         * port-unreachable cannot break its reads, and (for the IPv6 instance) is dual-stack so
         * it can reach an IPv4 relay through its IPv4-mapped address.
         *
         * @return The connected socket, or INVALID_SOCKET on failure.
         */
        SOCKET create_relay_socket(const net::ip_endpoint<address_type_t>& udp_endpoint)
        {
            auto remote_socket = WSASocket(address_type_t::af_type, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                WSA_FLAG_OVERLAPPED);

            if (remote_socket == INVALID_SOCKET)
            {
                NETLIB_DEBUG(
                    "create_relay_socket: Failed to create UDP socket: {}",
                    WSAGetLastError());
                return INVALID_SOCKET;
            }

            tune_udp_socket_buffers(remote_socket, "SOCKS5 UDP relay socket");

            // Suppress spurious WSAECONNRESET on the relay socket:
            // an ICMP port-unreachable from the SOCKS5 UDP relay must not kill this relay's reads.
            {
                BOOL new_behavior = FALSE;
                DWORD bytes_returned = 0;
                if (WSAIoctl(remote_socket, SIO_UDP_CONNRESET, &new_behavior, sizeof(new_behavior),
                    nullptr, 0, &bytes_returned, nullptr, nullptr) == SOCKET_ERROR)
                {
                    NETLIB_WARNING("create_relay_socket: failed to disable SIO_UDP_CONNRESET on relay socket: {}",
                        WSAGetLastError());
                }
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
                    NETLIB_DEBUG(
                        "create_relay_socket: Failed to bind UDP socket: {}",
                        WSAGetLastError());
                    return INVALID_SOCKET;
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
                    NETLIB_WARNING("create_relay_socket: Failed to clear IPV6_V6ONLY on UDP relay socket: {}",
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
                    NETLIB_DEBUG(
                        "create_relay_socket: Failed to bind UDP socket: {}",
                        WSAGetLastError());
                    return INVALID_SOCKET;
                }
            }

            // connect to server
            if constexpr (address_type_t::af_type == AF_INET)
            {
                sockaddr_in sa_service{};
                sa_service.sin_family = address_type_t::af_type;
                sa_service.sin_addr = udp_endpoint.ip;
                sa_service.sin_port = htons(udp_endpoint.port);

                if (connect(remote_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) ==
                    SOCKET_ERROR)
                {
                    closesocket(remote_socket);
                    NETLIB_DEBUG(
                        "create_relay_socket: Failed to connect UDP socket: {}",
                        WSAGetLastError());
                    return INVALID_SOCKET;
                }
            }
            else
            {
                sockaddr_in6 sa_service{};
                sa_service.sin6_family = address_type_t::af_type;
                sa_service.sin6_addr = udp_endpoint.ip;
                sa_service.sin6_port = htons(udp_endpoint.port);

                if (connect(remote_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) ==
                    SOCKET_ERROR)
                {
                    closesocket(remote_socket);
                    NETLIB_DEBUG(
                        "create_relay_socket: Failed to connect UDP socket: {}",
                        WSAGetLastError());
                    return INVALID_SOCKET;
                }
            }

            return remote_socket;
        }
    };
}
