#pragma once
namespace proxy
{
	class socks_local_router : public iphelper::network_config_info<socks_local_router>
	{
		/// <summary>
		/// Make the base class a friend to allow access to the private CRTP callback
		/// </summary>
		friend network_config_info;

		using s5_tcp_proxy_server = tcp_proxy_server<socks5_tcp_proxy_socket<net::ip_address_v4>>;
		using s5_udp_proxy_server = socks5_local_udp_proxy_server<socks5_udp_proxy_socket<net::ip_address_v4>>;

		std::unordered_map<uint16_t, net::ip_endpoint<net::ip_address_v4>> tcp_mapper_;
		std::unordered_set<uint16_t> udp_mapper_;
		std::mutex tcp_mapper_lock_;
		std::mutex udp_mapper_lock_;
		winsys::io_completion_port io_port_;

		/// <summary>message logging function</summary>
		std::function<void(const char*)> log_printer_;
		/// <summary>logging level</summary>
		netlib::log::log_level log_level_;

		std::shared_ptr<pcap::pcap_file_storage> pcap_{nullptr};

		std::vector<std::pair<std::unique_ptr<s5_tcp_proxy_server>, std::unique_ptr<s5_udp_proxy_server>>>
		proxy_servers_;
		std::unordered_map<std::wstring, size_t> name_to_proxy_;
		std::shared_mutex lock_;
		std::optional<iphelper::network_adapter_info> default_adapter_;
		std::size_t if_index_{};

		std::unique_ptr<ndisapi::tcp_local_redirect<net::ip_address_v4>> tcp_redirect_{nullptr};
		std::unique_ptr<ndisapi::socks5_udp_local_redirect<net::ip_address_v4>> udp_redirect_{nullptr};
		std::unique_ptr<ndisapi::queued_packet_filter> filter_{nullptr};

		std::atomic_bool is_active_{false};

	public:
		socks_local_router(std::function<void(const char*)> log_printer, const netlib::log::log_level log_level) :
			log_printer_(std::move(log_printer)), log_level_(log_level)
		{
			using namespace std::string_literals;

			if (log_level_ > netlib::log::log_level::debug)
				pcap_ = std::make_shared<pcap::pcap_file_storage>("socks_local_router.pcap"s);

			tcp_redirect_ = std::make_unique<ndisapi::tcp_local_redirect<net::ip_address_v4>>(
				log_printer_, log_level_);

			udp_redirect_ = std::make_unique<ndisapi::socks5_udp_local_redirect<net::ip_address_v4>>(
				log_printer_, log_level_);

			filter_ = std::make_unique<ndisapi::queued_packet_filter>(
				nullptr,
				[this](HANDLE, INTERMEDIATE_BUFFER& buffer)
				{
					auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);
					const auto destination_mac = net::mac_address(ethernet_header->h_dest);

					if (ntohs(ethernet_header->h_proto) != ETH_P_IP)
						return ndisapi::queued_packet_filter::packet_action::pass;

					auto* const ip_header = reinterpret_cast<iphdr_ptr>(ethernet_header + 1);

					if (pcap_)
						*pcap_ << buffer;

					if (ip_header->ip_p == IPPROTO_UDP)
					{
						const auto* const udp_header = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header)
							+ sizeof(DWORD) * ip_header->ip_hl);

						// skip broadcast and multicast UDP packets
						if (destination_mac.is_broadcast() || destination_mac.is_multicast())
							return ndisapi::queued_packet_filter::packet_action::pass;

						auto process = iphelper::process_lookup<net::ip_address_v4>::get_process_helper().
							lookup_process_for_udp<false>(net::ip_endpoint<net::ip_address_v4>{
								ip_header->ip_src, ntohs(udp_header->th_sport)
							});

						if (!process)
						{
							iphelper::process_lookup<net::ip_address_v4>::get_process_helper().actualize(false, true);
							process = iphelper::process_lookup<net::ip_address_v4>::get_process_helper().
								lookup_process_for_udp<true>(net::ip_endpoint<net::ip_address_v4>{
									ip_header->ip_src, ntohs(udp_header->th_sport)
								});
						}

						if (const auto port = get_proxy_port_udp(process->name); port.has_value())
						{
							if (udp_redirect_->is_new_endpoint(buffer))
							{
								std::lock_guard lock(udp_mapper_lock_);
								udp_mapper_.insert(ntohs(udp_header->th_sport));

								print_log(netlib::log::log_level::info,
								          std::string("Redirecting UDP ") + std::string(
									          net::ip_address_v4(ip_header->ip_src)) +
								          " : " + std::to_string(ntohs(udp_header->th_sport)) + " -> " +
								          std::string(net::ip_address_v4(ip_header->ip_dst)) + " : " + std::to_string(
									          ntohs(udp_header->th_dport)));
							}

							if (udp_redirect_->process_client_to_server_packet(buffer, htons(port.value())))
								return ndisapi::queued_packet_filter::packet_action::revert;
						}
						else if (is_udp_proxy_port(ntohs(udp_header->th_sport)))
						{
							if (udp_redirect_->process_server_to_client_packet(buffer))
								return ndisapi::queued_packet_filter::packet_action::revert;
						}
					}
					else if (ip_header->ip_p == IPPROTO_TCP)
					{
						const auto* const tcp_header = reinterpret_cast<tcphdr_ptr>(reinterpret_cast<PUCHAR>(
								ip_header) +
							sizeof(DWORD) * ip_header->ip_hl);

						auto process = iphelper::process_lookup<net::ip_address_v4>::get_process_helper().
							lookup_process_for_tcp<false>(net::ip_session<net::ip_address_v4>{
								ip_header->ip_src, ip_header->ip_dst, ntohs(tcp_header->th_sport),
								ntohs(tcp_header->th_dport)
							});

						if (!process)
						{
							iphelper::process_lookup<net::ip_address_v4>::get_process_helper().actualize(true, false);
							process = iphelper::process_lookup<net::ip_address_v4>::get_process_helper().
								lookup_process_for_tcp<true>(net::ip_session<net::ip_address_v4>{
									ip_header->ip_src, ip_header->ip_dst, ntohs(tcp_header->th_sport),
									ntohs(tcp_header->th_dport)
								});
						}

						if (const auto port = get_proxy_port_tcp(process->name); port.has_value())
						{
							if ((tcp_header->th_flags & (TH_SYN | TH_ACK)) == TH_SYN)
							{
								std::lock_guard lock(tcp_mapper_lock_);
								tcp_mapper_[ntohs(tcp_header->th_sport)] =
									net::ip_endpoint(net::ip_address_v4(ip_header->ip_dst),
									                 ntohs(tcp_header->th_dport));

								print_log(netlib::log::log_level::info,
								          std::string("Redirecting TCP: ") + std::string(
									          net::ip_address_v4(ip_header->ip_src)) +
								          " : " + std::to_string(ntohs(tcp_header->th_sport)) + " -> " + std::string(
									          net::ip_address_v4(ip_header->ip_dst)) +
								          " : " + std::to_string(ntohs(tcp_header->th_dport)));
							}

							if (tcp_redirect_->process_client_to_server_packet(buffer, htons(port.value())))
								return ndisapi::queued_packet_filter::packet_action::revert;
						}
						else if (is_tcp_proxy_port(ntohs(tcp_header->th_sport)))
						{
							if (tcp_redirect_->process_server_to_client_packet(buffer))
								return ndisapi::queued_packet_filter::packet_action::revert;
						}
					}

					return ndisapi::queued_packet_filter::packet_action::pass;
				});

			ndisapi::filter<net::ip_address_v4> icmp_filter;
			icmp_filter
				.set_action(ndisapi::action_t::pass)
				.set_direction(ndisapi::direction_t::both)
				.set_protocol(IPPROTO_ICMP);

			ndisapi::static_filters::get_instance()
				.add_filter(icmp_filter)
				.apply();
		}

		~socks_local_router()
		{
			stop();
		}

		socks_local_router(const socks_local_router& other) = delete;

		socks_local_router(socks_local_router&& other) = delete;

		socks_local_router& operator=(const socks_local_router& other) = delete;

		socks_local_router& operator=(socks_local_router&& other) = delete;

		bool start()
		{
			if (auto expected = false; !is_active_.compare_exchange_strong(expected, true))
				return false;

			std::shared_lock lock(lock_);

			// Start thread pool
			io_port_.start_thread_pool();

			// Start proxies
			for (auto& [tcp, udp] : proxy_servers_)
			{
				tcp->start();
				udp->start();
			}

			// Update network configuration and start filter
			if (update_network_configuration())
				filter_->start_filter(if_index_);

			if (!this->set_notify_ip_interface_change())
			{
				print_log(
					netlib::log::log_level::error,
					"set_notify_ip_interface_change has failed, lasterror: " + std::to_string(
						GetLastError()));
			}

			return is_active_;
		}

		bool stop()
		{
			if (auto expected = true; !is_active_.compare_exchange_strong(expected, false))
				return false;

			std::shared_lock lock(lock_);

			if (!this->cancel_notify_ip_interface_change())
			{
				print_log(
					netlib::log::log_level::error, "cancel_notify_ip_interface_change has failed, lasterror: " +
					std::to_string(
						GetLastError()));
			}

			// Stop filter
			filter_->stop_filter();

			// Stop proxies
			for (auto& [tcp, udp] : proxy_servers_)
			{
				tcp->stop();
				udp->stop();
			}

			// Stop thread pool
			io_port_.stop_thread_pool();

			return is_active_;
		}

		bool is_driver_loaded() const
		{
			return filter_->IsDriverLoaded() ? true : false;
		}

		std::optional<size_t> add_socks5_proxy(
			const std::string& endpoint,
			const std::optional<std::pair<std::string, std::string>>& cred_pair,
			const bool start = false
		)
		{
			using namespace std::string_literals;

			auto proxy_endpoint = parse_endpoint(endpoint);

			if (!proxy_endpoint)
			{
				print_log(netlib::log::log_level::error, "Failed to parse the proxy endpoint "s + endpoint);
				return {};
			}

			ndisapi::filter<net::ip_address_v4> sock5_tcp_proxy_filter_out, sock5_tcp_proxy_filter_in,
			                                    sock5_udp_proxy_filter_out, sock5_udp_proxy_filter_in;
			sock5_tcp_proxy_filter_out
				.set_dest_address(net::ip_subnet{proxy_endpoint.value().ip, net::ip_address_v4{"255.255.255.255"}})
				.set_dest_port(std::make_pair(proxy_endpoint.value().port, proxy_endpoint.value().port))
				.set_action(ndisapi::action_t::pass)
				.set_direction(ndisapi::direction_t::out)
				.set_protocol(IPPROTO_TCP);
			sock5_tcp_proxy_filter_in
				.set_source_address(net::ip_subnet{proxy_endpoint.value().ip, net::ip_address_v4{"255.255.255.255"}})
				.set_source_port(std::make_pair(proxy_endpoint.value().port, proxy_endpoint.value().port))
				.set_action(ndisapi::action_t::pass)
				.set_direction(ndisapi::direction_t::in)
				.set_protocol(IPPROTO_TCP);
			sock5_udp_proxy_filter_out
				.set_dest_address(net::ip_subnet{proxy_endpoint.value().ip, net::ip_address_v4{"255.255.255.255"}})
				.set_action(ndisapi::action_t::pass)
				.set_direction(ndisapi::direction_t::out)
				.set_protocol(IPPROTO_UDP);
			sock5_udp_proxy_filter_in
				.set_source_address(net::ip_subnet{proxy_endpoint.value().ip, net::ip_address_v4{"255.255.255.255"}})
				.set_action(ndisapi::action_t::pass)
				.set_direction(ndisapi::direction_t::in)
				.set_protocol(IPPROTO_UDP);
			ndisapi::static_filters::get_instance()
				.add_filter(sock5_tcp_proxy_filter_out)
				.add_filter(sock5_tcp_proxy_filter_in)
				.add_filter(sock5_udp_proxy_filter_out)
				.add_filter(sock5_udp_proxy_filter_in)
				.apply();

			try
			{
				auto socks_tcp_proxy_server = std::make_unique<s5_tcp_proxy_server>(
					0, io_port_, [this, endpoint = proxy_endpoint.value(), cred_pair](
					const net::ip_address_v4 address, const uint16_t port)->
					std::tuple<net::ip_address_v4, uint16_t, std::unique_ptr<s5_tcp_proxy_server::negotiate_context_t>>
					{
						std::lock_guard lock(tcp_mapper_lock_);

						if (const auto it = tcp_mapper_.find(port); it != tcp_mapper_.end())
						{
							print_log(netlib::log::log_level::info,
							          "TCP Redirect entry was found for the "s + std::string{address} + " : " +
							          std::to_string(port) + " is " + std::string{net::ip_address_v4{it->second.ip}} +
							          " : " + std::to_string(it->second.port));

							auto remote_address = it->second.ip;
							auto remote_port = it->second.port;

							tcp_mapper_.erase(it);

							return std::make_tuple(endpoint.ip, endpoint.port,
							                       std::make_unique<s5_tcp_proxy_server::negotiate_context_t>(
								                       remote_address, remote_port,
								                       cred_pair
									                       ? std::optional(cred_pair.value().first)
									                       : std::nullopt,
								                       cred_pair
									                       ? std::optional(cred_pair.value().second)
									                       : std::nullopt));
						}

						return std::make_tuple(net::ip_address_v4{}, 0, nullptr);
					}, log_printer_, log_level_);

				auto socks_udp_proxy_server = std::make_unique<s5_udp_proxy_server>(
					0, io_port_, [this, endpoint = proxy_endpoint.value(), cred_pair](
					const net::ip_address_v4 address, const uint16_t port)->
					std::tuple<net::ip_address_v4, uint16_t, std::unique_ptr<s5_udp_proxy_server::negotiate_context_t>>
					{
						std::lock_guard lock(udp_mapper_lock_);

						if (const auto it = udp_mapper_.find(port); it != udp_mapper_.end())
						{
							print_log(netlib::log::log_level::info, "UDP Redirect entry was found for the "s +
							          std::string{address} + " : " + std::to_string(port));

							udp_mapper_.erase(it);

							return std::make_tuple(endpoint.ip, endpoint.port,
							                       std::make_unique<s5_udp_proxy_server::negotiate_context_t>(
								                       net::ip_address_v4{}, 0,
								                       cred_pair
									                       ? std::optional(cred_pair.value().first)
									                       : std::nullopt,
								                       cred_pair
									                       ? std::optional(cred_pair.value().second)
									                       : std::nullopt));
						}

						return std::make_tuple(net::ip_address_v4{}, 0, nullptr);
					}, log_printer_, log_level_);

				if (start) // optionally start proxies
				{
					if (!socks_tcp_proxy_server->start())
					{
						print_log(netlib::log::log_level::error, "Failed to start TCP SOCKS5 proxy "s + endpoint);
						return {};
					}

					print_log(netlib::log::log_level::info,
					          "Local TCP proxy for "s + endpoint + " is listening port: " + std::to_string(
						          socks_tcp_proxy_server->proxy_port()));

					if (!socks_udp_proxy_server->start())
					{
						print_log(netlib::log::log_level::error, "Failed to start UDP SOCKS5 proxy "s + endpoint);
						return {};
					}

					print_log(netlib::log::log_level::info,
					          "Local UDP proxy for "s + endpoint + " is listening port: " + std::to_string(
						          socks_udp_proxy_server->proxy_port()));
				}

				std::lock_guard lock(lock_);

				proxy_servers_.emplace_back(
					std::move(socks_tcp_proxy_server), std::move(socks_udp_proxy_server));

				return proxy_servers_.size() - 1;
			}
			catch (const std::exception& e)
			{
				print_log(netlib::log::log_level::error, "An exception was thrown while adding SOCKS5 proxy "s +
				          endpoint + " : " + e.what());
			}

			return {};
		}

		bool associate_process_name_to_proxy(const std::wstring& process_name, const size_t proxy_id)
		{
			using namespace std::string_literals;

			std::lock_guard lock(lock_);

			if (proxy_id >= proxy_servers_.size())
			{
				print_log(netlib::log::log_level::error,
				          "associate_process_name_to_proxy: proxy index is out of range!");
				return false;
			}

			name_to_proxy_[process_name] = proxy_id;

			return true;
		}

		static std::optional<net::ip_endpoint<net::ip_address_v4>> parse_endpoint(const std::string& endpoint)
		{
			net::ip_endpoint<net::ip_address_v4> result_endpoint;

			if (const auto pos = endpoint.find(':'); pos != std::string::npos)
			{
				auto [result_v4, address_v4] = net::ip_address_v4::from_string(endpoint.substr(0, pos));
				if (auto [p, ec] = std::from_chars(endpoint.data() + pos + 1, endpoint.data() + endpoint.size(),
				                                   result_endpoint.port); ec == std::errc())
				{
					if (result_v4)
					{
						result_endpoint.ip = address_v4;
					}
					else
					{
						addrinfo* resulted_address_info = nullptr;
						addrinfo hints{};

						// Setup the hints address info structure
						// which is passed to the getaddrinfo() function
						ZeroMemory(&hints, sizeof(hints));
						hints.ai_family = AF_INET;
						hints.ai_socktype = SOCK_STREAM;
						hints.ai_protocol = IPPROTO_TCP;

						if (const auto ret_val = getaddrinfo(endpoint.substr(0, pos).c_str(),
						                                     std::to_string(result_endpoint.port).c_str(), &hints,
						                                     &resulted_address_info); ret_val == 0)
						{
							// Retrieve each address and print out the hex bytes
							for (const auto* ptr = resulted_address_info; ptr != nullptr; ptr = ptr->ai_next)
							{
								switch (ptr->ai_family)
								{
								case AF_INET:
									{
										const auto* const ipv4 = reinterpret_cast<sockaddr_in*>(ptr->ai_addr);
										result_endpoint.ip = net::ip_address_v4(ipv4->sin_addr);
										break;
									}
								default:
									break;
								}
							}
							freeaddrinfo(resulted_address_info);
						}
					}
				}
			}

			if (result_endpoint.ip != net::ip_address_v4{})
				return result_endpoint;

			return {};
		}

	private:
		std::optional<uint16_t> get_proxy_port_tcp(const std::wstring& process_name)
		{
			std::shared_lock lock(lock_);

			for (auto& [name, proxy_id] : name_to_proxy_)
			{
				if (process_name.find(name) != std::wstring::npos)
					return proxy_servers_[proxy_id].first->proxy_port();
			}

			return {};
		}

		std::optional<uint16_t> get_proxy_port_udp(const std::wstring& process_name)
		{
			std::shared_lock lock(lock_);

			for (auto& [name, proxy_id] : name_to_proxy_)
			{
				if (process_name.find(name) != std::wstring::npos)
					return proxy_servers_[proxy_id].second->proxy_port();
			}

			return {};
		}

		bool is_tcp_proxy_port(const uint16_t port)
		{
			std::shared_lock lock(lock_);

			return std::any_of(proxy_servers_.cbegin(), proxy_servers_.cend(), [port](auto& proxy)
			{
				if (proxy.first->proxy_port() == port)
					return true;
				return false;
			});
		}

		bool is_udp_proxy_port(const uint16_t port)
		{
			std::shared_lock lock(lock_);

			return std::any_of(proxy_servers_.cbegin(), proxy_servers_.cend(), [port](auto& proxy)
			{
				if (proxy.second->proxy_port() == port)
					return true;
				return false;
			});
		}

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

		bool update_network_configuration()
		{
			if (!filter_->reconfigure())
			{
				print_log(netlib::log::log_level::error,
				          "socks5_local_router: Failed to update WinpkFilter network interfaces \n");
			}

			const auto& ndis_adapters = filter_->get_interface_list();

			default_adapter_ = get_best_interface(net::ip_address_v4("1.1.1.1"));

			if (!default_adapter_)
			{
				print_log(netlib::log::log_level::error,
				          "socks5_local_router:: Failed to figure out the route to the 1.1.1.1 \n");
				return false;
			}

			print_log(netlib::log::log_level::info,
			          "socks5_local_router:: Detected default interface " + default_adapter_->get_adapter_name());

			if (default_adapter_->get_if_type() != IF_TYPE_PPP)
			{
				if (const auto it = std::find_if(ndis_adapters.begin(), ndis_adapters.end(),
				                                 [this](const auto& ndis_adapter)
				                                 {
					                                 return (std::string::npos != ndis_adapter->get_internal_name().
						                                 find(default_adapter_->get_adapter_name()));
				                                 }); it != ndis_adapters.cend())
				{
					if_index_ = it - ndis_adapters.begin();
					return true;
				}
			}
			else
			{
				if (const auto it = std::find_if(ndis_adapters.begin(), ndis_adapters.end(),
				                                 [this](const auto& ndis_adapter)
				                                 {
					                                 if (auto wan_info = ndis_adapter->get_ras_links(); wan_info)
					                                 {
						                                 if (auto ras_it = std::find_if(
							                                 wan_info->cbegin(), wan_info->cend(),
							                                 [this](auto& ras_link)
							                                 {
								                                 return default_adapter_->has_address(
									                                 ras_link.ip_address);
							                                 }); ras_it != wan_info->cend())
						                                 {
							                                 return true;
						                                 }
					                                 }

					                                 return false;
				                                 }); it != ndis_adapters.cend())
				{
					if_index_ = it - ndis_adapters.begin();
					return true;
				}
			}

			if (netlib::log::log_level::info < log_level_)
			{
				print_log(
					netlib::log::log_level::info,
					"socks5_local_router: Failed to find a matching WinpkFilter interface for the " +
					default_adapter_->
					get_adapter_name());
			}
			return false;
		}

		void ip_interface_changed_callback(PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE notification_type)
		{
			const std::optional<iphelper::network_adapter_info> adapter = get_best_interface(
				net::ip_address_v4("1.1.1.1"));

			if (!adapter)
			{
				print_log(
					netlib::log::log_level::error,
					"socks5_local_router: ip_interface_changed_callback: No Internet available.");

				return;
			}

			if (default_adapter_.has_value() && *adapter == *default_adapter_ && adapter->is_same_address_info<false>(
				*default_adapter_))
			{
				// nothing has changed, no reaction needed
				return;
			}

			print_log(
				netlib::log::log_level::info,
				"socks5_local_router: ip_interface_changed_callback: default network adapter has changed. Restart the filter engine.");

			std::thread restart_async([this]()
			{
				bool update_result;
				filter_->stop_filter();
				{
					std::lock_guard internal_lock(lock_);
					update_result = update_network_configuration();
				}
				if (update_result)
					filter_->start_filter(if_index_);
			});

			restart_async.detach();
		}
	};
}
