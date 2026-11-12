#pragma once

namespace ndisapi
{
    /**
     * @class tcp_local_redirect
     * @brief Implements local TCP redirection for transparent proxying.
     *
     * This class manages TCP endpoint tracking and packet translation for redirecting
     * client TCP traffic to a local proxy. It supports both IPv4 and IPv6 and
     * provides NAT functionality for TCP source ports. Timed-out connections are cleaned
     * up automatically in a background thread.
     *
     * @tparam T IP address type (net::ip_address_v4 or net::ip_address_v6).
     */
    template <net::ip_address T>
    class tcp_local_redirect : public netlib::log::logger<tcp_local_redirect<T>>  // NOLINT(clang-diagnostic-padded)
    {
        using log_level = netlib::log::log_level;
        using logger = netlib::log::logger<tcp_local_redirect>;

    public:
        using clock = std::chrono::steady_clock;

        /// Idle lifetime of a redirected connection that has not started closing.
        static constexpr std::chrono::seconds open_timeout{ 5 * 60 };

        /// Idle lifetime once one side has sent FIN (half-closed). Data may still flow the other way.
        static constexpr std::chrono::seconds half_closed_timeout{ 2 * 60 };

        /// Lifetime once both sides have sent FIN, so the final ACK and FIN retransmissions of
        /// either side are still translated instead of reaching the real server.
        static constexpr std::chrono::seconds closed_linger{ 10 };

        /**
         * @brief Tracking state of one redirected connection.
         *
         * The entry is kept through the whole close: removing it on the first FIN (as earlier
         * versions did) left the rest of the close untranslated, so the peer's ACK/FIN and FIN
         * retransmissions were passed toward the real server. An RST removes the entry at once.
         */
        struct connection_state
        {
            u_short original_port{};         ///< original destination port (network byte order)
            clock::time_point last_activity;
            bool client_fin{};               ///< the client sent FIN
            bool server_fin{};               ///< the local proxy sent FIN

            /// The time after which the entry may be removed.
            [[nodiscard]] clock::time_point expires_at() const noexcept
            {
                if (client_fin && server_fin)
                    return last_activity + closed_linger;
                if (client_fin || server_fin)
                    return last_activity + half_closed_timeout;
                return last_activity + open_timeout;
            }
        };

    private:
        /**
         * @brief Maps the client TCP endpoint (original destination address, client source port)
         *        to its tracking state.
         */
        std::unordered_map<net::ip_endpoint<T>, connection_state> redirected_connections_;

        /**
         * @brief Mutex for synchronizing access to redirected_connections_.
         */
        std::mutex lock_;

        /**
         * @brief Thread for cleaning up timed-out TCP connections.
         */
        std::thread cleanup_thread_;

        /**
         * @brief Proxy port in network byte order.
         */
        u_short proxy_port_{};

        /**
         * @brief Termination flag for the cleanup_thread_.
         */
        std::atomic_bool terminate_{ false };

        /**
         * @brief Starts the background cleanup thread.
         *
         * The thread periodically removes entries whose lifetime has elapsed (see
         * connection_state::expires_at()).
         */
        void start_cleanup_thread()
        {
            cleanup_thread_ = std::thread([this]()
                {
                    while (!terminate_)
                    {
                        remove_expired(clock::now());

                        // Check terminate_ more frequently during sleep to allow faster shutdown
                        using namespace std::chrono_literals;
                        for (int i = 0; i < 10 && !terminate_; ++i)
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
        explicit tcp_local_redirect(const log_level log_level = log_level::error,
                                    std::shared_ptr<std::ostream> log_stream = nullptr)
            : logger(log_level, std::move(log_stream))
        {
            start_cleanup_thread();
        }

        /**
         * @brief Constructs the redirector with a specific proxy port, log level, and stream.
         * @param proxy_port TCP port for the local proxy (host byte order).
         * @param log_level Logging level.
         * @param log_stream Optional output stream for logging.
         */
        explicit tcp_local_redirect(const u_short proxy_port, const log_level log_level = log_level::error,
                                    std::shared_ptr<std::ostream> log_stream = nullptr)
            : logger(log_level, std::move(log_stream)),
              proxy_port_(htons(proxy_port))
        {
            start_cleanup_thread();
        }

        /**
        * @brief Destructor. Stops the cleanup thread and releases resources.
        */
        ~tcp_local_redirect() noexcept
        {
            try
            {
                stop();
            }
            catch (const std::exception& e)
            {
                // Log but don't throw from destructor
                NETLIB_ERROR("Exception in ~tcp_local_redirect: {}", e.what());
            }
            catch (...)
            {
                // Catch any other exceptions to prevent abort
                NETLIB_ERROR("Unknown exception in ~tcp_local_redirect");
            }
        }

        /**
         * @brief Deleted copy constructor.
         */
        tcp_local_redirect(const tcp_local_redirect& other) = delete;

        /**
         * @brief Deleted move constructor.
         */
        tcp_local_redirect(tcp_local_redirect&& other) noexcept = delete;

        /**
         * @brief Deleted copy assignment operator.
         */
        tcp_local_redirect& operator=(const tcp_local_redirect& other) = delete;

        /**
         * @brief Deleted move assignment operator.
         */
        tcp_local_redirect& operator=(tcp_local_redirect&& other) noexcept = delete;

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
         * @brief Removes connection entries whose lifetime has elapsed at @p now.
         *
         * Called periodically by the cleanup thread; public so the timeouts can be exercised
         * deterministically.
         */
        void remove_expired(const clock::time_point now)
        {
            std::lock_guard lock(lock_);

            tools::generic::erase_if(redirected_connections_, redirected_connections_.begin(),
                redirected_connections_.end(),
                [&now, this](auto&& a)
                {
                    if (now < a.second.expires_at())
                        return false;

                    NETLIB_DEBUG(
                        "DELETE TCP (timeout): {} -> {} : {}",
                        ntohs(a.first.port),
                        std::string{ a.first.ip },
                        ntohs(a.second.original_port));
                    return true;
                });
        }

        /**
         * @brief Returns a copy of the tracking state for client endpoint
         *        (@p original_destination, @p client_port), where @p client_port is in network
         *        byte order. For diagnostics and tests.
         */
        [[nodiscard]] std::optional<connection_state> find_connection(const T& original_destination,
            const u_short client_port)
        {
            std::lock_guard lock(lock_);
            const auto it = redirected_connections_.find(net::ip_endpoint<T>{ original_destination, client_port });
            if (it == redirected_connections_.cend())
                return std::nullopt;
            return it->second;
        }

    private:
        /**
         * @brief Updates the tracking state for a client-to-server segment. The caller holds lock_.
         *
         * A SYN (without ACK) starts or restarts tracking: a retransmitted SYN refreshes the entry,
         * and a SYN on a key whose previous connection is closing starts a new connection. Any
         * other segment must belong to a tracked connection.
         *
         * @return false when the segment belongs to no tracked connection and must not be rewritten.
         */
        bool track_client_segment(const net::ip_endpoint<T>& key, const u_char flags, const u_short destination_port,
            const T& source, const T& destination)
        {
            const auto now = clock::now();

            if ((flags & (TH_SYN | TH_ACK)) == TH_SYN)
            {
                const auto [it, inserted] = redirected_connections_.try_emplace(key);
                if (inserted)
                {
                    NETLIB_DEBUG(
                        "NEW TCP: {}:{} -> {}:{}",
                        std::string{ source },
                        ntohs(key.port),
                        std::string{ destination },
                        ntohs(destination_port));
                }

                // A SYN whose key already exists is either a retransmission for a connection that
                // is still being set up (the local listener has not completed the handshake) or a
                // new connection reusing the key after the previous one closed. Both are rewritten
                // to the local proxy: returning false would pass the SYN to the real destination,
                // an unproxied leak of a connection we own.
                it->second = connection_state{ destination_port, now, false, false };
                return true;
            }

            const auto it = redirected_connections_.find(key);
            if (it == redirected_connections_.cend())
                return false;

            if (flags & TH_RST)
            {
                NETLIB_DEBUG("DELETE TCP (client RST): {} -> {} : {}",
                    ntohs(it->first.port), std::string{ it->first.ip }, ntohs(it->second.original_port));
                redirected_connections_.erase(it);
                return true;
            }

            if (flags & TH_FIN)
                it->second.client_fin = true;

            it->second.last_activity = now;
            return true;
        }

        /**
         * @brief Updates the tracking state for a segment from the local proxy to the client.
         *        The caller holds lock_.
         * @return the original destination port (network byte order) to present as the source
         *         port, or std::nullopt when the segment belongs to no tracked connection.
         */
        std::optional<u_short> track_server_segment(const net::ip_endpoint<T>& key, const u_char flags)
        {
            const auto it = redirected_connections_.find(key);
            if (it == redirected_connections_.cend())
                return std::nullopt;

            const auto original_port = it->second.original_port;

            if (flags & TH_RST)
            {
                NETLIB_DEBUG("DELETE TCP (proxy RST): {} -> {} : {}",
                    ntohs(it->first.port), std::string{ it->first.ip }, ntohs(original_port));
                redirected_connections_.erase(it);
                return original_port;
            }

            if (flags & TH_FIN)
                it->second.server_fin = true;

            it->second.last_activity = clock::now();
            return original_port;
        }

    public:
        /**
        * @brief Redirects a C2S TCP packet to the local proxy and applies NAT to the source port.
        *
        * Modifies the packet in-place, updates the source/destination addresses and ports as needed,
        * and manages the connection tracking table.
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

                if (ip_header->ip_p != IPPROTO_TCP)
                    return false;

                // This is TCP packet, get TCP header pointer
                auto* tcp_header = reinterpret_cast<tcphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) +
                    sizeof(DWORD) * ip_header->ip_hl);

                // Ensure the full TCP header lies within the captured frame before reading
                // tcp_header fields (th_flags is at offset 13); avoids keying state on stale
                // bytes for a short/forged IPv4 frame.
                if (ip_header->ip_hl < 5 ||
                    ETHER_HEADER_LENGTH + sizeof(DWORD) * ip_header->ip_hl + sizeof(tcphdr) > packet.m_Length)
                    return false;

                std::lock_guard lock(lock_);

                if (!track_client_segment(net::ip_endpoint<T>{ T{ ip_header->ip_dst }, tcp_header->th_sport },
                        tcp_header->th_flags, tcp_header->th_dport, T{ ip_header->ip_src }, T{ ip_header->ip_dst }))
                    return false;

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

                if (!track_client_segment(net::ip_endpoint<T>{ T{ ip_header->ip6_dst }, tcp_header->th_sport },
                        tcp_header->th_flags, tcp_header->th_dport, T{ ip_header->ip6_src }, T{ ip_header->ip6_dst }))
                    return false;

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

        /**
         * @brief Processes an S2C packet, restoring the original client source port and remote peer.
         *
         * Modifies the packet in-place and updates the source/destination addresses and ports as needed.
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

                if (ip_header->ip_p != IPPROTO_TCP)
                    return false;

                // This is TCP packet, get TCP header pointer
                auto* tcp_header = reinterpret_cast<tcphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) +
                    sizeof(DWORD) * ip_header->ip_hl);

                // Ensure the full TCP header lies within the captured frame before reading
                // tcp_header fields (th_flags is at offset 13); avoids keying state on stale
                // bytes for a short/forged IPv4 frame.
                if (ip_header->ip_hl < 5 ||
                    ETHER_HEADER_LENGTH + sizeof(DWORD) * ip_header->ip_hl + sizeof(tcphdr) > packet.m_Length)
                    return false;

                std::lock_guard lock(lock_);

                const auto original_port = track_server_segment(
                    net::ip_endpoint<T>{ T{ ip_header->ip_dst }, tcp_header->th_dport }, tcp_header->th_flags);
                if (!original_port)
                    return false;

                tcp_header->th_sport = *original_port;

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

                const auto original_port = track_server_segment(
                    net::ip_endpoint<T>{ T{ ip_header->ip6_dst }, tcp_header->th_dport }, tcp_header->th_flags);
                if (!original_port)
                    return false;

                tcp_header->th_sport = *original_port;

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
         * @see ~tcp_local_redirect() for automatic cleanup on destruction.
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
