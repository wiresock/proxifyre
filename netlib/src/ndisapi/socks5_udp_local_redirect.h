#pragma once

namespace ndisapi
{
    /**
    * @class socks5_udp_local_redirect
    * @brief Implements local UDP redirection for SOCKS5 proxying.
    *
    * This class manages UDP endpoint tracking and packet translation for redirecting
    * client UDP traffic to a local SOCKS5 proxy. It supports both IPv4 and IPv6 and
    * provides NAT functionality for UDP source ports. Timed-out endpoints are cleaned
    * up automatically in a background thread.
    *
    * @tparam T IP address type (net::ip_address_v4 or net::ip_address_v6).
    */
    template <net::ip_address T>
    class socks5_udp_local_redirect : public netlib::log::logger<socks5_udp_local_redirect<T>>  // NOLINT(clang-diagnostic-padded)
    {
        /// <summary>
        /// NOTE: All ports are in the network byte order
        /// </summary>
        ///
        using log_level = netlib::log::log_level;
        using logger = netlib::log::logger<socks5_udp_local_redirect>;

        /// <summary>
        /// Maps client UDP endpoint (port or endpoint) to the timestamp of last activity.
        /// Used for tracking active UDP sessions.
        /// </summary>
        std::unordered_map<uint16_t, std::chrono::steady_clock::time_point> endpoints_;
        /// <summary>
        /// Mutex for synchronizing access to endpoints_.
        /// </summary>
        std::mutex lock_;
        /// <summary>
        /// Thread for cleaning up timed-out UDP endpoints.
        /// </summary>
        std::thread cleanup_thread_;
        /// <summary>
        /// Proxy port in network byte order.
        /// </summary>
        u_short proxy_port_{};
        /// <summary>
        /// Termination flag for the cleanup_thread_.
        /// </summary>
        std::atomic_bool terminate_{ false };

        /**
         * @brief Starts the background cleanup thread.
         *
         * The thread periodically scans the endpoints_ map and removes entries
         * that have been inactive for more than 15 minutes.
         */
        void start_cleanup_thread()
        {
            cleanup_thread_ = std::thread([this]()
                {
                    while (!terminate_)
                    {
                        {
                            auto current_time = std::chrono::steady_clock::now();
                            std::scoped_lock lock(lock_);

                            tools::generic::erase_if(endpoints_, endpoints_.begin(), endpoints_.end(),
                                [&current_time, this](auto&& a)
                                {
                                    using namespace std::chrono_literals;
                                    if (current_time - a.second > 15min)
                                    {
                                        NETLIB_INFO(
                                            "DELETE UDP client endpoint (timeout): : {}",
                                            ntohs(a.first));

                                        return true;
                                    }
                                    return false;
                                });
                        }

                        // Check terminate_ more frequently during sleep to allow faster shutdown
                        using namespace std::chrono_literals;
                        for (int i = 0; i < 50 && !terminate_; ++i)
                        {
                            std::this_thread::sleep_for(100ms);
                        }
                    }
                });
        }

    public:
        /**
         * @brief Constructs the redirector with optional log level and stream.
         * @param log_level Logging level.
         * @param log_stream Optional output stream for logging.
         */
        explicit socks5_udp_local_redirect(
            const log_level log_level = log_level::error,
            std::shared_ptr<std::ostream> log_stream = nullptr)
            : logger(log_level, std::move(log_stream))
        {
            start_cleanup_thread();
        }

        /**
         * @brief Constructs the redirector with a specific proxy port, log level, and stream.
         * @param proxy_port UDP port for the local proxy (host byte order).
         * @param log_level Logging level.
         * @param log_stream Optional output stream for logging.
         */
        explicit socks5_udp_local_redirect(
            const u_short proxy_port,
            const log_level log_level = log_level::error,
            std::shared_ptr<std::ostream> log_stream = nullptr)
            : logger(log_level, std::move(log_stream)),
              proxy_port_(htons(proxy_port))
        {
            start_cleanup_thread();
        }

        /**
          * @brief Deleted copy constructor.
          */
        socks5_udp_local_redirect(const socks5_udp_local_redirect& other) = delete;

        /**
         * @brief Deleted move constructor.
         */
        socks5_udp_local_redirect(socks5_udp_local_redirect&& other) noexcept = delete;

        /**
         * @brief Deleted copy assignment operator.
         */
        socks5_udp_local_redirect& operator=(const socks5_udp_local_redirect& other) = delete;

        /**
         * @brief Deleted move assignment operator.
         */
        socks5_udp_local_redirect& operator=(socks5_udp_local_redirect&& other) noexcept = delete;

        /**
         * @brief Destructor. Stops the cleanup thread and releases resources.
         */
        ~socks5_udp_local_redirect() noexcept
        {
            try
            {
                stop();
            }
            catch (const std::exception& e)
            {
                // Log but don't throw from destructor
                NETLIB_ERROR("Exception in ~socks5_udp_local_redirect: {}", e.what());
            }
            catch (...)
            {
                // Catch any other exceptions to prevent abort
                NETLIB_ERROR("Unknown exception in ~socks5_udp_local_redirect");
            }
        }

        /**
         * @brief Gets the proxy port in host byte order.
         * @return Proxy port.
         */
        [[nodiscard]] u_short get_proxy_port() const
        {
            return ntohs(proxy_port_);
        }

        /**
         * @brief Sets the proxy port (host byte order).
         * @param proxy_port Proxy port.
         */
        void set_proxy_port(const u_short proxy_port)
        {
            proxy_port_ = htons(proxy_port);
        }

        /**
         * @brief Checks if the UDP session for the given packet is new.
         *
         * If the session is new, it is recorded and true is returned.
         * Otherwise, returns false.
         *
         * @param packet C2S network packet.
         * @return True if the session is new, false otherwise.
         */
        bool is_new_endpoint(INTERMEDIATE_BUFFER& packet)
        {
            if constexpr (auto* const eth_header = reinterpret_cast<ether_header_ptr>(packet.m_IBuffer); std::is_same_v<
                net::ip_address_v4, std::decay_t<T>>)
            {
                if (ntohs(eth_header->h_proto) != ETH_P_IP)
                    return false;

                const auto* ip_header = reinterpret_cast<iphdr_ptr>(packet.m_IBuffer + ETHER_HEADER_LENGTH);

                if (ip_header->ip_p != IPPROTO_UDP)
                    return false;

                // This is UDP packet, get UDP header pointer
                const auto* udp_header = reinterpret_cast<const udphdr*>(reinterpret_cast<const unsigned char*>(
                    ip_header) +
                    sizeof(DWORD) * ip_header->ip_hl);

                std::scoped_lock lock(lock_);

                if (const auto it = endpoints_.find(udp_header->th_sport); it
                    == endpoints_.cend())
                {
                    endpoints_[udp_header->th_sport] =
                        std::chrono::steady_clock::now();

                    NETLIB_INFO(
                        "NEW client UDP endpoint: : {}",
                        ntohs(udp_header->th_sport));

                    return true;
                }

                return false;
            }
            else if constexpr (std::is_same_v<net::ip_address_v6, std::decay_t<T>>)
            {
                if (ntohs(eth_header->h_proto) != ETH_P_IPV6)
                    return false;

                const auto* const ip_header = reinterpret_cast<ipv6hdr_ptr>(eth_header + 1);
                auto [p_header, proto] =
                    net::ipv6_helper::find_transport_header(ip_header, packet.m_Length - ETHER_HEADER_LENGTH);

                if (p_header == nullptr || proto != IPPROTO_UDP)
                    return false;

                const auto* udp_header = static_cast<udphdr_ptr>(p_header);

                std::scoped_lock lock(lock_);

                if (const auto it = endpoints_.find(udp_header->th_sport); it == endpoints_.cend())
                {
                    endpoints_[udp_header->th_sport] =
                        std::chrono::steady_clock::now();

                    NETLIB_INFO(
                        "NEW client UDP endpoint: : {}",
                        ntohs(udp_header->th_sport));

                    return true;
                }

                return false;
            }

            return false;
        }

        /**
         * @brief Redirects a C2S UDP packet to the local proxy and applies NAT to the source port.
         *
         * Modifies the packet in-place, attaches a SOCKS5 UDP header, and updates the source/destination
         * addresses and ports as needed.
         *
         * @param packet C2S network packet.
         * @param port Destination port to forward the packet to (network byte order). If 0, uses proxy_port_.
         * @return True if the packet was translated, false otherwise.
         */
        bool process_client_to_server_packet(INTERMEDIATE_BUFFER& packet, uint16_t port = 0)
        {
            if (port == 0)
                port = proxy_port_;

            if constexpr (auto* const eth_header = reinterpret_cast<ether_header_ptr>(packet.m_IBuffer); std::is_same_v<
                net::ip_address_v4, std::decay_t<T>>)
            {
                if (ntohs(eth_header->h_proto) != ETH_P_IP)
                    return false;

                auto* ip_header = reinterpret_cast<iphdr_ptr>(packet.m_IBuffer + ETHER_HEADER_LENGTH);

                if (ip_header->ip_p != IPPROTO_UDP)
                    return false;

                // We don't support fragmented packets
                if ((ntohs(ip_header->ip_off) & ~IP_DF) != 0)
                    return false;

                // This is UDP packet, get UDP header pointer
                auto* udp_header = reinterpret_cast<udphdr*>(reinterpret_cast<unsigned char*>(ip_header) +
                    sizeof(DWORD) * ip_header->ip_hl);

                std::scoped_lock lock(lock_);

                // existing connection
                const auto it = endpoints_.find(udp_header->th_sport);

                if (it == endpoints_.cend())
                {
                    return false;
                }

                NETLIB_DEBUG(
                    "C2S: {}:{} -> {}:{}",
                    std::string{ T{ip_header->ip_src} },
                    ntohs(udp_header->th_sport),
                    std::string{ T{ip_header->ip_dst} },
                    ntohs(udp_header->th_dport));

                // Validate lengths before inserting the SOCKS5 UDP header: the UDP header
                // must be fully captured, and the packet must have room to grow by
                // socks5_header_size. Without the MAX_ETHER_FRAME guard a near-MTU datagram
                // makes the memmove (and the m_Length increment below) write past m_IBuffer;
                // the captured-size check prevents the payload-size underflow on a truncated
                // frame. Mirrors the IPv6 attach guards.
                {
                    constexpr auto socks5_header_size = sizeof(proxy::socks5_udp_header<T>);
                    const auto* const packet_end = packet.m_IBuffer + packet.m_Length;
                    const auto* const udp_header_bytes = reinterpret_cast<const uint8_t*>(udp_header);
                    if (udp_header_bytes > packet_end ||
                        static_cast<size_t>(packet_end - udp_header_bytes) < sizeof(udphdr) ||
                        packet.m_Length + socks5_header_size > MAX_ETHER_FRAME)
                    {
                        return false;
                    }
                }

                auto* udp_payload = reinterpret_cast<uint8_t*>(udp_header + 1);
                const auto udp_payload_size = static_cast<uint16_t>(packet.m_Length - sizeof(ether_header) - sizeof(
                    DWORD) * ip_header->ip_hl - sizeof(udphdr));
                const auto udp_max_payload_size = static_cast<uint16_t>(MAX_ETHER_FRAME - sizeof(ether_header) - sizeof(
                    DWORD) * ip_header->ip_hl - sizeof(udphdr));
                memmove(udp_payload + sizeof(proxy::socks5_udp_header<T>), udp_payload,
                    std::min(udp_payload_size, udp_max_payload_size));

                packet.m_Length += sizeof(proxy::socks5_udp_header<T>);
                ip_header->ip_len = htons(ntohs(ip_header->ip_len) + sizeof(proxy::socks5_udp_header<T>));
                udp_header->length = htons(ntohs(udp_header->length) + sizeof(proxy::socks5_udp_header<T>));
                auto* socks5_udp_header_ptr = reinterpret_cast<proxy::socks5_udp_header<T>*>(udp_payload);

                socks5_udp_header_ptr->reserved = 0;
                socks5_udp_header_ptr->fragment = 0;
                socks5_udp_header_ptr->address_type = 1;
                socks5_udp_header_ptr->dest_address = ip_header->ip_dst;
                socks5_udp_header_ptr->dest_port = udp_header->th_dport;

                // Swap Ethernet addresses
                std::swap(eth_header->h_dest, eth_header->h_source);

                // Swap IP addresses
                std::swap(ip_header->ip_dst, ip_header->ip_src);

                udp_header->th_dport = port;

                CNdisApi::RecalculateUDPChecksum(&packet);
                CNdisApi::RecalculateIPChecksum(&packet);

                it->second = std::chrono::steady_clock::now();

                NETLIB_DEBUG(
                    "C2S: {}:{} -> {}:{}",
                    std::string{ T{ip_header->ip_src} },
                    ntohs(udp_header->th_sport),
                    std::string{ T{ip_header->ip_dst} },
                    ntohs(udp_header->th_dport));

                return true;
            }
            else if constexpr (std::is_same_v<net::ip_address_v6, std::decay_t<T>>)
            {
                if (ntohs(eth_header->h_proto) != ETH_P_IPV6)
                    return false;

                auto* const ip_header = reinterpret_cast<ipv6hdr_ptr>(eth_header + 1);
                auto [p_header, proto] =
                    net::ipv6_helper::find_transport_header(ip_header, packet.m_Length - ETHER_HEADER_LENGTH);

                if (p_header == nullptr || proto != IPPROTO_UDP)
                    return false;

                auto* udp_header = static_cast<udphdr_ptr>(p_header);

                std::scoped_lock lock(lock_);

                const auto it = endpoints_.find(udp_header->th_sport);

                if (it == endpoints_.cend())
                {
                    return false;
                }

                NETLIB_DEBUG(
                    "C2S: {}:{} -> {}:{}",
                    std::string{ T{ip_header->ip6_src} },
                    ntohs(udp_header->th_sport),
                    std::string{ T{ip_header->ip6_dst} },
                    ntohs(udp_header->th_dport));

                constexpr auto socks5_header_size = sizeof(proxy::socks5_udp_header<T>);
                const auto* const packet_end = packet.m_IBuffer + packet.m_Length;
                const auto* const udp_header_bytes = reinterpret_cast<const uint8_t*>(udp_header);
                if (udp_header_bytes > packet_end ||
                    static_cast<size_t>(packet_end - udp_header_bytes) < sizeof(udphdr))
                {
                    return false;
                }

                const auto udp_length = ntohs(udp_header->length);
                const auto captured_udp_size = static_cast<size_t>(packet_end - udp_header_bytes);
                if (udp_length < sizeof(udphdr) ||
                    udp_length > captured_udp_size ||
                    packet.m_Length + socks5_header_size > MAX_ETHER_FRAME)
                {
                    return false;
                }

                // Attach SOCK5 UDP header here
                auto* udp_payload = reinterpret_cast<uint8_t*>(udp_header + 1);
                const auto udp_payload_size = static_cast<size_t>(udp_length - sizeof(udphdr));
                memmove(udp_payload + socks5_header_size, udp_payload, udp_payload_size);

                packet.m_Length += socks5_header_size;
                ip_header->ip6_len = htons(ntohs(ip_header->ip6_len) + socks5_header_size);
                udp_header->length = htons(ntohs(udp_header->length) + socks5_header_size);
                auto* socks5_udp_header_ptr = reinterpret_cast<proxy::socks5_udp_header<T>*>(udp_payload);

                socks5_udp_header_ptr->reserved = 0;
                socks5_udp_header_ptr->fragment = 0;
                socks5_udp_header_ptr->address_type = 4; // For IPv6 address type is 4
                socks5_udp_header_ptr->dest_address = ip_header->ip6_dst;
                socks5_udp_header_ptr->dest_port = udp_header->th_dport;

                // Swap Ethernet addresses
                std::swap(eth_header->h_dest, eth_header->h_source);

                // Swap IP addresses
                std::swap(ip_header->ip6_dst, ip_header->ip6_src);

                udp_header->th_dport = port;

                // Recalculate checksum
                net::ipv6_helper::recalculate_tcp_udp_checksum(&packet);

                it->second = std::chrono::steady_clock::now();

                NETLIB_DEBUG(
                    "C2S: {}:{} -> {}:{}",
                    std::string{ T{ip_header->ip6_src} },
                    ntohs(udp_header->th_sport),
                    std::string{ T{ip_header->ip6_dst} },
                    ntohs(udp_header->th_dport));

                return true;
            }

            return false;
        }

        /**
         * @brief Processes an S2C packet, restoring the original client source port and remote peer.
         *
         * Modifies the packet in-place, removes the SOCKS5 UDP header, and updates the source/destination
         * addresses and ports as needed.
         *
         * @param packet S2C network packet.
         * @return True if the packet was translated, false otherwise.
         */
        bool process_server_to_client_packet(INTERMEDIATE_BUFFER& packet)
        {
            if constexpr (auto* const eth_header = reinterpret_cast<ether_header_ptr>(packet.m_IBuffer); std::is_same_v<
                net::ip_address_v4, std::decay_t<T>>)
            {
                if (ntohs(eth_header->h_proto) != ETH_P_IP)
                    return false;

                auto* ip_header = reinterpret_cast<iphdr_ptr>(packet.m_IBuffer + ETHER_HEADER_LENGTH);

                if (ip_header->ip_p != IPPROTO_UDP)
                    return false;

                // We don't support fragmented packets
                if ((ntohs(ip_header->ip_off) & ~IP_DF) != 0)
                    return false;

                // This is UDP packet, get UDP header pointer
                auto* udp_header = reinterpret_cast<udphdr*>(reinterpret_cast<unsigned char*>(ip_header) +
                    sizeof(DWORD) * ip_header->ip_hl);

                std::scoped_lock lock(lock_);

                const auto it = endpoints_.find(udp_header->th_dport);

                if (it == endpoints_.cend())
                    return false;

                // Validate lengths before mutating anything: udp_header->length comes from
                // the received datagram. Without these guards a short/forged length makes
                // udp_payload_size - socks5_header_size underflow into a huge value and the
                // memmove writes far out of bounds. Mirrors the IPv6 detach guards.
                constexpr auto socks5_header_size = sizeof(proxy::socks5_udp_header<T>);
                const auto* const packet_end = packet.m_IBuffer + packet.m_Length;
                const auto* const udp_header_bytes = reinterpret_cast<const uint8_t*>(udp_header);
                const auto udp_length = ntohs(udp_header->length);
                if (udp_header_bytes > packet_end ||
                    static_cast<size_t>(packet_end - udp_header_bytes) < sizeof(udphdr) ||
                    udp_length < sizeof(udphdr) + socks5_header_size ||
                    udp_length > static_cast<size_t>(packet_end - udp_header_bytes) ||
                    packet.m_Length < socks5_header_size ||
                    ntohs(ip_header->ip_len) < socks5_header_size)
                {
                    return false;
                }

                // Reject a reply whose SOCKS5 UDP header ATYP doesn't match this relay's family
                // (IPv4 = 1): parsing a mismatched layout (e.g. a 16-byte IPv6 address as IPv4)
                // would hand the client a spoofed/garbage source endpoint. The bounds check above
                // guarantees the SOCKS5 header is fully captured. Done before any mutation.
                if (reinterpret_cast<const proxy::socks5_udp_header<T>*>(udp_header + 1)->address_type != 1)
                    return false;

                NETLIB_DEBUG(
                    "S2C: {}:{} -> {}:{}",
                    std::string{ T{ip_header->ip_src} },
                    ntohs(udp_header->th_sport),
                    std::string{ T{ip_header->ip_dst} },
                    ntohs(udp_header->th_dport));

                // Swap Ethernet addresses
                std::swap(eth_header->h_dest, eth_header->h_source);

                // Swap IP addresses
                std::swap(ip_header->ip_dst, ip_header->ip_src);

                auto* udp_payload = reinterpret_cast<uint8_t*>(udp_header + 1);
                auto* socks5_udp_header_ptr = reinterpret_cast<proxy::socks5_udp_header<T>*>(udp_payload);

                ip_header->ip_src = socks5_udp_header_ptr->dest_address;
                udp_header->th_sport = socks5_udp_header_ptr->dest_port;

                const auto udp_payload_size = static_cast<size_t>(udp_length - sizeof(udphdr));
                memmove(udp_payload, udp_payload + socks5_header_size,
                    udp_payload_size - socks5_header_size);

                packet.m_Length -= sizeof(proxy::socks5_udp_header<T>);
                ip_header->ip_len = htons(ntohs(ip_header->ip_len) - sizeof(proxy::socks5_udp_header<T>));
                udp_header->length = htons(ntohs(udp_header->length) - sizeof(proxy::socks5_udp_header<T>));

                CNdisApi::RecalculateUDPChecksum(&packet);
                CNdisApi::RecalculateIPChecksum(&packet);

                it->second = std::chrono::steady_clock::now();

                NETLIB_DEBUG(
                    "S2C: {}:{} -> {}:{}",
                    std::string{ T{ip_header->ip_src} },
                    ntohs(udp_header->th_sport),
                    std::string{ T{ip_header->ip_dst} },
                    ntohs(udp_header->th_dport));

                return true;
            }
            else if constexpr (std::is_same_v<net::ip_address_v6, std::decay_t<T>>)
            {
                if (ntohs(eth_header->h_proto) != ETH_P_IPV6)
                    return false;

                auto* const ip_header = reinterpret_cast<ipv6hdr_ptr>(eth_header + 1);
                auto [p_header, proto] =
                    net::ipv6_helper::find_transport_header(ip_header, packet.m_Length - ETHER_HEADER_LENGTH);

                if (p_header == nullptr || proto != IPPROTO_UDP)
                    return false;

                auto* udp_header = static_cast<udphdr_ptr>(p_header);

                std::scoped_lock lock(lock_);

                const auto it = endpoints_.find(udp_header->th_dport);

                if (it == endpoints_.cend())
                    return false;

                NETLIB_DEBUG(
                    "S2C: {}:{} -> {}:{}",
                    std::string{ T{ip_header->ip6_src} },
                    ntohs(udp_header->th_sport),
                    std::string{ T{ip_header->ip6_dst} },
                    ntohs(udp_header->th_dport));

                // Remove SOCK5 UDP header here
                constexpr auto socks5_header_size = sizeof(proxy::socks5_udp_header<T>);
                const auto* const packet_end = packet.m_IBuffer + packet.m_Length;
                const auto* const udp_header_bytes = reinterpret_cast<const uint8_t*>(udp_header);
                if (udp_header_bytes > packet_end ||
                    static_cast<size_t>(packet_end - udp_header_bytes) < sizeof(udphdr))
                {
                    return false;
                }

                const auto udp_length = ntohs(udp_header->length);
                const auto captured_udp_size = static_cast<size_t>(packet_end - udp_header_bytes);
                if (udp_length < sizeof(udphdr) + socks5_header_size ||
                    udp_length > captured_udp_size ||
                    packet.m_Length < socks5_header_size ||
                    ntohs(ip_header->ip6_len) < socks5_header_size)
                {
                    return false;
                }

                auto* udp_payload = reinterpret_cast<uint8_t*>(udp_header + 1);
                auto* socks5_udp_header_ptr = reinterpret_cast<proxy::socks5_udp_header<T>*>(udp_payload);

                // Reject a reply whose SOCKS5 UDP header ATYP doesn't match this relay's family
                // (IPv6 = 4); see the IPv4 path. The bounds check above guarantees the header is
                // fully captured. Done before any mutation.
                if (socks5_udp_header_ptr->address_type != 4)
                    return false;

                // Swap Ethernet addresses
                std::swap(eth_header->h_dest, eth_header->h_source);

                // Swap IP addresses
                std::swap(ip_header->ip6_dst, ip_header->ip6_src);

                ip_header->ip6_src = socks5_udp_header_ptr->dest_address;
                udp_header->th_sport = socks5_udp_header_ptr->dest_port;

                const auto udp_payload_size = static_cast<size_t>(udp_length - sizeof(udphdr));
                memmove(udp_payload, udp_payload + socks5_header_size,
                    udp_payload_size - socks5_header_size);

                packet.m_Length -= socks5_header_size;
                ip_header->ip6_len = htons(ntohs(ip_header->ip6_len) - socks5_header_size);
                udp_header->length = htons(ntohs(udp_header->length) - socks5_header_size);

                // Recalculate checksum
                net::ipv6_helper::recalculate_tcp_udp_checksum(&packet);

                it->second = std::chrono::steady_clock::now();

                NETLIB_DEBUG(
                    "S2C: {}:{} -> {}:{}",
                    std::string{ T{ip_header->ip6_src} },
                    ntohs(udp_header->th_sport),
                    std::string{ T{ip_header->ip6_dst} },
                    ntohs(udp_header->th_dport));

                return true;
            }

            return false;
        }

        /**
         * @brief Stops the cleanup thread and releases resources.
         *
         * This method gracefully terminates the background cleanup thread by setting
         * the termination flag and waiting for the thread to complete. It's safe to
         * call this method multiple times - subsequent calls will have no effect if
         * the thread has already been stopped.
         *
         * The method uses memory_order_release for the atomic flag to ensure proper
         * synchronization of the termination signal with the cleanup thread's loop.
         *
         * @note This method blocks until the cleanup thread completes execution.
         * @note Thread-safe: Can be called concurrently with other methods.
         * @note Idempotent: Multiple calls are safe and have no additional effect.
         * @note The destructor automatically calls this method, so explicit calls
         *       are only needed if early shutdown is required.
         *
         * @see ~socks5_udp_local_redirect() for automatic cleanup on destruction.
         */
        void stop()
        {
            if (bool expected = false; terminate_.compare_exchange_strong(expected, true, std::memory_order_release))
            {
                if (cleanup_thread_.joinable())
                {
                    cleanup_thread_.join();
                }
            }
        }
    };
}
