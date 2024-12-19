#pragma once

namespace ndisapi
{
    template <typename T>
    class tcp_local_redirect : public netlib::log::logger<tcp_local_redirect<T>>
    {
        using log_level = netlib::log::log_level;
        using logger = netlib::log::logger<tcp_local_redirect>;
        using timestamp_endpoint = std::pair<uint16_t, std::chrono::steady_clock::time_point>;

        std::unordered_map<net::ip_endpoint<T>, timestamp_endpoint> redirected_connections_;

        /// <summary>proxy port in network byte order</summary>
        u_short proxy_port_{};
        /// <summary>lock for redirected_connections_ </summary>
        std::mutex lock_;
        /// <summary>thread to drop timed out connections </summary>
        std::thread cleanup_thread_;
        /// <summary>termination flag for the cleanup_thread </summary>
        std::atomic_bool terminate_{false};

        void start_cleanup_thread()
        {
            cleanup_thread_ = std::thread([this]()
            {
                while (!terminate_)
                {
                    {
                        auto current_time = std::chrono::steady_clock::now();
                        std::lock_guard lock(lock_);

                        tools::generic::erase_if(redirected_connections_, redirected_connections_.begin(),
                                                 redirected_connections_.end(),
                                                 [&current_time, this](auto&& a)
                                                 {
                                                     using namespace std::chrono_literals;
                                                     if (current_time - a.second.second > 5min)
                                                     {
                                                         this->print_log(log_level::info,
                                                                         std::string("DELETE TCP (timeout): ") +
                                                                         std::to_string(ntohs(a.first.port)) + " -> " +
                                                                         std::string{a.first.ip} + " : "
                                                                         +
                                                                         std::to_string(ntohs(a.second.first)));
                                                         return true;
                                                     }
                                                     return false;
                                                 });
                    }

                    using namespace std::chrono_literals;
                    std::this_thread::sleep_for(1s);
                }
            });
        }

    public:
        explicit tcp_local_redirect(const log_level log_level = log_level::error,
                                    const std::optional<std::reference_wrapper<std::ostream>> log_stream = std::nullopt)
            : logger(log_level, log_stream)
        {
            start_cleanup_thread();
        }

        explicit tcp_local_redirect(const u_short proxy_port, const log_level log_level = log_level::error,
                                    const std::optional<std::reference_wrapper<std::ostream>> log_stream = std::nullopt)
            : logger(log_level, log_stream),
              proxy_port_(htons(proxy_port))
        {
            start_cleanup_thread();
        }

        ~tcp_local_redirect()
        {
            terminate_ = true;

            if (cleanup_thread_.joinable())
                cleanup_thread_.join();
        }

        tcp_local_redirect(const tcp_local_redirect& other) = delete;

        tcp_local_redirect(tcp_local_redirect&& other) noexcept = delete;

        tcp_local_redirect& operator=(const tcp_local_redirect& other) = delete;

        tcp_local_redirect& operator=(tcp_local_redirect&& other) noexcept = delete;

        [[nodiscard]] u_short get_proxy_port() const
        {
            return ntohs(proxy_port_);
        }

        void set_proxy_port(const u_short proxy_port)
        {
            proxy_port_ = htons(proxy_port);
        }

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

                if (ip_header->ip_p != IPPROTO_TCP)
                    return false;

                // This is TCP packet, get TCP header pointer
                auto* tcp_header = reinterpret_cast<tcphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) +
                    sizeof(DWORD) * ip_header->ip_hl);

                std::lock_guard lock(lock_);

                if ((tcp_header->th_flags & (TH_SYN | TH_ACK)) == TH_SYN)
                {
                    if (const auto [it, result] = redirected_connections_.emplace(
                        net::ip_endpoint<T>{T{ip_header->ip_dst}, tcp_header->th_sport},
                        timestamp_endpoint{
                            tcp_header->th_dport,
                            std::chrono::steady_clock::now()
                        }); !result)
                        return false;

                    print_log(log_level::info,
                              std::string("NEW TCP: ") + std::string{T{ip_header->ip_src}} + " : " +
                              std::to_string(ntohs(tcp_header->th_sport)) + " -> " + std::string{T{ip_header->ip_dst}} +
                              " : " + std::to_string(ntohs(tcp_header->th_dport)));
                }
                else
                {
                    // existing connection
                    const auto it = redirected_connections_.find(net::ip_endpoint<T>{
                        T{ip_header->ip_dst}, tcp_header->th_sport
                    });
                    if (it == redirected_connections_.cend())
                        return false;

                    if (tcp_header->th_flags & TH_RST || tcp_header->th_flags & TH_FIN)
                    {
                        // pass through but erase the corresponding entry
                        print_log(log_level::info,
                                  std::string("DELETE TCP: ") + std::to_string(ntohs(it->first.port)) + " -> " +
                                  std::string{it->first.ip} + " : "
                                  +
                                  std::to_string(ntohs(it->second.first)));

                        redirected_connections_.erase(it);
                    }
                    else
                    {
                        it->second.second = std::chrono::steady_clock::now();
                    }
                }

                // Swap Ethernet addresses
                std::swap(eth_header->h_dest, eth_header->h_source);

                // Swap IP addresses
                std::swap(ip_header->ip_dst, ip_header->ip_src);

                tcp_header->th_dport = port;

                CNdisApi::RecalculateTCPChecksum(&packet);
                CNdisApi::RecalculateIPChecksum(&packet);

                return true;
            }
            else if constexpr (std::is_same_v<net::ip_address_v6, std::decay_t<T>>)
            {
                if (ntohs(eth_header->h_proto) != ETH_P_IPV6)
                    return false;

                auto* const ip_header = reinterpret_cast<ipv6hdr_ptr>(eth_header + 1);
                auto [p_header, proto] =
                    net::ipv6_helper::find_transport_header(ip_header, packet.m_Length - ETHER_HEADER_LENGTH);

                if (p_header == nullptr || proto != IPPROTO_TCP)
                    return false;

                auto* tcp_header = static_cast<tcphdr_ptr>(p_header);

                std::lock_guard lock(lock_);

                if ((tcp_header->th_flags & (TH_SYN | TH_ACK)) == TH_SYN)
                {
                    if (const auto [it, result] = redirected_connections_.emplace(
                        net::ip_endpoint<T>{T{ip_header->ip6_dst}, tcp_header->th_sport},
                        timestamp_endpoint{
                            tcp_header->th_dport,
                            std::chrono::steady_clock::now()
                        }); !result)
                        return false;

                    print_log(log_level::info, std::string("NEW TCP: ") + std::string{T{ip_header->ip6_src}} + " : " +
                              std::to_string(ntohs(tcp_header->th_sport)) + " -> " + std::string{T{ip_header->ip6_dst}}
                              +
                              " : " + std::to_string(ntohs(tcp_header->th_dport)));
                }
                else
                {
                    // existing connection
                    const auto it = redirected_connections_.find(net::ip_endpoint<T>{
                        T{ip_header->ip6_dst}, tcp_header->th_sport
                    });
                    if (it == redirected_connections_.cend())
                        return false;

                    if (tcp_header->th_flags & TH_RST || tcp_header->th_flags & TH_FIN)
                    {
                        // pass thru but erase the corresponding entry
                        print_log(log_level::info, std::string("DELETE TCP: ") + std::string{it->first.ip} + " : " +
                                  std::to_string(ntohs(it->first.port)) + " -> " + std::string{T{it->second.ip}} +
                                  " : " + std::to_string(ntohs(it->second.port)));

                        redirected_connections_.erase(it);
                    }
                    else
                    {
                        it->second.timestamp = std::chrono::steady_clock::now();
                    }
                }

                //Swap Ethernet addresses
                std::swap(eth_header->h_dest, eth_header->h_source);

                // Swap IP addresses
                std::swap(ip_header->ip6_dst, ip_header->ip6_src);

                tcp_header->th_dport = port;

                // Recalculate checksum
                net::ipv6_helper::recalculate_tcp_udp_checksum(&packet);

                return true;
            }

            return false;
        }

        bool process_server_to_client_packet(INTERMEDIATE_BUFFER& packet)
        {
            if constexpr (auto* const eth_header = reinterpret_cast<ether_header_ptr>(packet.m_IBuffer); std::is_same_v<
                net::ip_address_v4, std::decay_t<T>>)
            {
                if (ntohs(eth_header->h_proto) != ETH_P_IP)
                    return false;

                auto* ip_header = reinterpret_cast<iphdr_ptr>(packet.m_IBuffer + ETHER_HEADER_LENGTH);

                if (ip_header->ip_p != IPPROTO_TCP)
                    return false;

                // This is TCP packet, get TCP header pointer
                auto* tcp_header = reinterpret_cast<tcphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) +
                    sizeof(DWORD) * ip_header->ip_hl);

                std::lock_guard lock(lock_);

                const auto it = redirected_connections_.find(net::ip_endpoint<T>{
                    T{ip_header->ip_dst}, tcp_header->th_dport
                });
                if (it == redirected_connections_.cend())
                    return false;

                tcp_header->th_sport = it->second.first;

                if (tcp_header->th_flags & TH_RST || tcp_header->th_flags & TH_FIN)
                {
                    // pass thru but erase the corresponding entry
                    print_log(log_level::info,
                              std::string("DELETE TCP: ") + std::to_string(ntohs(it->first.port)) + " -> " +
                              std::string{it->first.ip} + " : "
                              +
                              std::to_string(ntohs(it->second.first)));

                    redirected_connections_.erase(it);
                }
                else
                {
                    it->second.second = std::chrono::steady_clock::now();
                }

                // Swap Ethernet addresses
                std::swap(eth_header->h_dest, eth_header->h_source);

                // Swap IP addresses
                std::swap(ip_header->ip_dst, ip_header->ip_src);

                CNdisApi::RecalculateTCPChecksum(&packet);
                CNdisApi::RecalculateIPChecksum(&packet);

                return true;
            }
            else if constexpr (std::is_same_v<net::ip_address_v6, std::decay_t<T>>)
            {
                if (ntohs(eth_header->h_proto) != ETH_P_IPV6)
                    return false;

                auto* const ip_header = reinterpret_cast<ipv6hdr_ptr>(eth_header + 1);
                auto [p_header, proto] =
                    net::ipv6_helper::find_transport_header(ip_header, packet.m_Length - ETHER_HEADER_LENGTH);

                if (p_header == nullptr || proto != IPPROTO_TCP)
                    return false;

                auto* tcp_header = static_cast<tcphdr_ptr>(p_header);

                std::lock_guard lock(lock_);

                const auto it = redirected_connections_.find(net::ip_endpoint<T>{
                    T{ip_header->ip6_dst}, tcp_header->th_dport
                });
                if (it == redirected_connections_.cend())
                    return false;

                tcp_header->th_sport = it->second.first;

                if (tcp_header->th_flags & TH_RST || tcp_header->th_flags & TH_FIN)
                {
                    // pass thru but erase the corresponding entry
                    print_log(log_level::info,
                              std::string("DELETE TCP: ") + std::to_string(ntohs(it->first.port)) + " -> " +
                              std::string{it->first.ip} + " : "
                              +
                              std::to_string(ntohs(it->second.first)));

                    redirected_connections_.erase(it);
                }
                else
                {
                    it->second.timestamp = std::chrono::steady_clock::now();
                }

                // Swap Ethernet addresses
                std::swap(eth_header->h_dest, eth_header->h_source);

                // Swap IP addresses
                std::swap(ip_header->ip6_dst, ip_header->ip6_src);

                // Recalculate checksum
                net::ipv6_helper::recalculate_tcp_udp_checksum(&packet);

                return true;
            }

            return false;
        }
    };
}
