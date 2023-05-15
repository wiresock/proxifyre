#pragma once

namespace ndisapi
{
	template <typename T>
	class socks5_udp_local_redirect
	{
		/// <summary>
		/// NOTE: All ports are in the network byte order
		/// </summary>

		/// <summary>maps client UDP endpoint to the timestamp</summary>
		std::unordered_map<uint16_t, std::chrono::steady_clock::time_point> endpoints_;
		/// <summary>proxy port in network byte order</summary>
		u_short proxy_port_;
		/// <summary>message logging function</summary>
		std::function<void(const char*)> log_printer_;
		/// <summary>logging level</summary>
		netlib::log::log_level log_level_;
		/// <summary>lock for redirected_connections_ </summary>
		std::mutex lock_;
		/// <summary>thread to drop timed out connections </summary>
		std::thread cleanup_thread_;
		/// <summary>termination flag for the cleanup_thread </summary>
		std::atomic_bool terminate_{false};

	public:
		explicit socks5_udp_local_redirect(std::function<void(const char*)> log_printer,
		                                   const netlib::log::log_level log_level)
			: socks5_udp_local_redirect(0, log_printer, log_level)
		{
		}

		explicit socks5_udp_local_redirect(const u_short proxy_port, std::function<void(const char*)> log_printer,
		                                   const netlib::log::log_level log_level):
			proxy_port_(htons(proxy_port)), log_printer_(std::move(log_printer)), log_level_(log_level)
		{
			cleanup_thread_ = std::thread([this]()
			{
				while (!terminate_)
				{
					{
						auto current_time = std::chrono::steady_clock::now();
						std::lock_guard lock(lock_);

						tools::generic::erase_if(endpoints_, endpoints_.begin(), endpoints_.end(),
						                         [&current_time, this](auto&& a)
						                         {
							                         using namespace std::chrono_literals;
							                         if (current_time - a.second > 15min)
							                         {
								                         print_log(netlib::log::log_level::info,
								                                   std::string("DELETE UDP client endpoint (timeout): ")
								                                   + " : " +
								                                   std::to_string(ntohs(a.first)));

								                         return true;
							                         }
							                         return false;
						                         });
					}

					using namespace std::chrono_literals;
					std::this_thread::sleep_for(5s);
				}
			});
		}

		socks5_udp_local_redirect(const socks5_udp_local_redirect& other) = delete;

		socks5_udp_local_redirect(socks5_udp_local_redirect&& other) noexcept = delete;

		socks5_udp_local_redirect& operator=(const socks5_udp_local_redirect& other) = delete;

		socks5_udp_local_redirect& operator=(socks5_udp_local_redirect&& other) noexcept = delete;

		~socks5_udp_local_redirect()
		{
			terminate_ = true;

			if (cleanup_thread_.joinable())
				cleanup_thread_.join();
		}

		[[nodiscard]] u_short get_proxy_port() const
		{
			return ntohs(proxy_port_);
		}

		void set_proxy_port(const u_short proxy_port)
		{
			proxy_port_ = htons(proxy_port);
		}

		/// <summary>
		/// Check if the associated UDP session already recorded for the C2S packet
		/// </summary>
		/// <param name="packet">C2S network packet</param>
		/// <returns>if the session is new then true is returned</returns>
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

				std::lock_guard lock(lock_);

				if (const auto it = endpoints_.find(udp_header->th_sport); it
					== endpoints_.cend())
				{
					endpoints_[udp_header->th_sport] =
						std::chrono::steady_clock::now();

					print_log(netlib::log::log_level::info, std::string("NEW client UDP endpoint: ") +
					          " : " + std::to_string(ntohs(udp_header->th_sport)));

					return true;
				}

				return false;
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

				std::lock_guard lock(lock_);

				if (const auto it = endpoints_.find(net::ip_endpoint<T>{T{ip_header->ip6_src}, udp_header->th_sport});
					it == endpoints_.cend())
				{
					endpoints_[udp_header->th_sport] =
						std::chrono::steady_clock::now();

					print_log(netlib::log::log_level::info, std::string("NEW client UDP endpoint: ") +
					          " : " + std::to_string(ntohs(udp_header->th_sport)));

					return true;
				}

				return false;
			}

			return false;
		}

		/// <summary>
		/// Process C2S packet redirecting it to local UDP proxy and applying NAT to source UDP port
		/// </summary>
		/// <param name="packet">C2S network packet</param>
		/// <param name="port">destination port to forward packet to</param>
		/// <returns>true if corresponding entry was found in local_redirected_connections_ and packet
		/// was translated</returns>
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

				std::lock_guard lock(lock_);

				// existing connection
				const auto it = endpoints_.find(udp_header->th_sport);

				if (it == endpoints_.cend())
				{
					return false;
				}

				print_log(netlib::log::log_level::debug,
				          std::string("C2S: ") + std::string{T{ip_header->ip_src}} + " : " +
				          std::to_string(ntohs(udp_header->th_sport)) + " -> " +
				          std::string{T{ip_header->ip_dst}} + " : " + std::to_string(ntohs(udp_header->th_dport)));

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

				print_log(netlib::log::log_level::debug,
				          std::string("C2S: ") + std::string{T{ip_header->ip_src}} + " : " +
				          std::to_string(ntohs(udp_header->th_sport)) + " -> " + std::string{T{ip_header->ip_dst}} +
				          " : "
				          +
				          std::to_string(ntohs(udp_header->th_dport)));

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

				std::lock_guard lock(lock_);

				const auto it = endpoints_.find(net::ip_endpoint<T>{T{ip_header->ip6_src}, udp_header->th_sport});

				if (it == endpoints_.cend())
				{
					return false;
				}

				print_log(netlib::log::log_level::debug,
				          std::string("C2S: ") + std::string{T{ip_header->ip6_src}} + " : " +
				          std::to_string(ntohs(udp_header->th_sport)) + " -> " +
				          std::string{T{ip_header->ip6_dst}} + " : " + std::to_string(ntohs(udp_header->th_dport)));

				//
				// TODO: attach SOCK5 UDP header here
				//

				// Swap Ethernet addresses
				std::swap(eth_header->h_dest, eth_header->h_source);

				// Swap IP addresses
				std::swap(ip_header->ip6_dst, ip_header->ip6_src);

				udp_header->th_dport = port;

				// Recalculate checksum
				net::ipv6_helper::recalculate_tcp_udp_checksum(&packet);

				it->second = std::chrono::steady_clock::now();

				print_log(netlib::log::log_level::debug,
				          std::string("C2S: ") + std::string{T{ip_header->ip6_src}} + " : " +
				          std::to_string(ntohs(udp_header->th_sport)) + " -> " + std::string{T{ip_header->ip6_dst}} +
				          " : " +
				          std::to_string(ntohs(udp_header->th_dport)));

				return true;
			}

			return false;
		}

		/// <summary>
		/// Processes S2C packet restoring the original client source port and remote peer
		/// </summary>
		/// <param name="packet">S2C network packet</param>
		/// <returns>true if corresponding entry was found in remote_redirected_connections_
		/// and packet was translated</returns>
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

				std::lock_guard lock(lock_);

				const auto it = endpoints_.find(udp_header->th_dport);

				if (it == endpoints_.cend())
					return false;

				print_log(netlib::log::log_level::debug,
				          std::string("S2C: ") + std::string{T{ip_header->ip_src}} + " : " +
				          std::to_string(ntohs(udp_header->th_sport)) + " -> " + std::string{T{ip_header->ip_dst}} +
				          " : "
				          +
				          std::to_string(ntohs(udp_header->th_dport)));

				// Swap Ethernet addresses
				std::swap(eth_header->h_dest, eth_header->h_source);

				// Swap IP addresses
				std::swap(ip_header->ip_dst, ip_header->ip_src);

				auto* udp_payload = reinterpret_cast<uint8_t*>(udp_header + 1);
				auto* socks5_udp_header_ptr = reinterpret_cast<proxy::socks5_udp_header<T>*>(udp_payload);

				ip_header->ip_src = socks5_udp_header_ptr->dest_address;
				udp_header->th_sport = socks5_udp_header_ptr->dest_port;

				const auto udp_payload_size = static_cast<uint16_t>(ntohs(udp_header->length) - sizeof(udphdr));
				memmove(udp_payload, udp_payload + sizeof(proxy::socks5_udp_header<T>),
				        udp_payload_size - sizeof(proxy::socks5_udp_header<T>));

				packet.m_Length -= sizeof(proxy::socks5_udp_header<T>);
				ip_header->ip_len = htons(ntohs(ip_header->ip_len) - sizeof(proxy::socks5_udp_header<T>));
				udp_header->length = htons(ntohs(udp_header->length) - sizeof(proxy::socks5_udp_header<T>));

				CNdisApi::RecalculateUDPChecksum(&packet);
				CNdisApi::RecalculateIPChecksum(&packet);

				it->second = std::chrono::steady_clock::now();

				print_log(netlib::log::log_level::debug,
				          std::string("S2C: ") + std::string{T{ip_header->ip_src}} + " : " +
				          std::to_string(ntohs(udp_header->th_sport)) + " -> " + std::string{T{ip_header->ip_dst}} +
				          " : "
				          +
				          std::to_string(ntohs(udp_header->th_dport)));

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

				std::lock_guard lock(lock_);

				const auto it = endpoints_.find(net::ip_endpoint<T>{
					T{ip_header->ip6_dst}, udp_header->th_dport
				});

				if (it == endpoints_.cend())
					return false;

				// Swap Ethernet addresses
				std::swap(eth_header->h_dest, eth_header->h_source);

				// Swap IP addresses
				std::swap(ip_header->ip6_dst, ip_header->ip6_src);

				//
				// TODO: remove SOCK5 UDP header here
				//

				// Recalculate checksum
				net::ipv6_helper::recalculate_tcp_udp_checksum(&packet);

				it->second = std::chrono::steady_clock::now();

				return true;
			}

			return false;
		}

	private:
		/**
		 * \brief Prints the specified string into the log
		 * \param level - message severity
		 * \param message - string message
		 */
		void print_log(const netlib::log::log_level level, const std::string& message) const noexcept
		{
			if ((level <= log_level_) && log_printer_)
			{
				log_printer_(message.c_str());
			}
		}
	};
}
