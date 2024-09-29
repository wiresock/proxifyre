#pragma once
namespace proxy
{
	class socks_local_router : public iphelper::network_config_info<socks_local_router>
	{
		// Allows the base class 'network_config_info' to access the private CRTP callback
		friend network_config_info;

		// Definitions of TCP and UDP proxy server types, specialized for IPv4 and SOCKS5
		using s5_tcp_proxy_server = tcp_proxy_server<socks5_tcp_proxy_socket<net::ip_address_v4>>;
		using s5_udp_proxy_server = socks5_local_udp_proxy_server<socks5_udp_proxy_socket<net::ip_address_v4>>;

		// Stores a mapping of TCP ports to their corresponding IP endpoints
		std::unordered_map<uint16_t, net::ip_endpoint<net::ip_address_v4>> tcp_mapper_;
		// Stores the set of UDP ports being mapped
		std::unordered_set<uint16_t> udp_mapper_;
		// Mutexes to synchronize access to the TCP and UDP maps
		std::mutex tcp_mapper_lock_;
		std::mutex udp_mapper_lock_;
		// I/O completion port for async operations
		winsys::io_completion_port io_port_;

		// Callback for logging messages
		std::function<void(const char*)> log_printer_;
		// Logging level (determines severity of messages to be logged)
		netlib::log::log_level log_level_;

		// Optional pointer to a pcap file storage, used for packet capturing
		std::shared_ptr<pcap::pcap_file_storage> pcap_{ nullptr };

		// Vector storing pairs of unique pointers to TCP and UDP proxy servers
		std::vector<std::pair<std::unique_ptr<s5_tcp_proxy_server>, std::unique_ptr<s5_udp_proxy_server>>>
			proxy_servers_;
		// Maps process names to their corresponding proxy indexes
		std::unordered_map<std::wstring, size_t> name_to_proxy_;
		// Maps process names to their parent process names which in @name_to_proxy_
		std::unordered_map<std::wstring, std::wstring> name_to_parent_name_;
		// Save the process names that should be passed through
		std::unordered_set<std::wstring> passthrough_names_;
		// Shared mutex to protect concurrent access to shared resources
		std::shared_mutex lock_;
		// Information of the default network adapter
		std::optional<iphelper::network_adapter_info> default_adapter_;
		// Index of the network interface used
		std::size_t if_index_{};

		// Unique pointers to TCP and UDP redirect objects
		std::unique_ptr<ndisapi::tcp_local_redirect<net::ip_address_v4>> tcp_redirect_{ nullptr };
		std::unique_ptr<ndisapi::socks5_udp_local_redirect<net::ip_address_v4>> udp_redirect_{ nullptr };
		// Unique pointer to the packet filter object
		std::unique_ptr<ndisapi::queued_packet_filter> filter_{ nullptr };

		// Atomic boolean to track the active status of the router
		std::atomic_bool is_active_{ false };

	public:
		enum supported_protocols
		{
			tcp,
			udp,
			both
		};

		/**
		 * The socks_local_router class constructor, used to set up a local router to handle SOCKS traffic.
		 * It creates instances of `tcp_local_redirect`, `socks5_udp_local_redirect` and `queued_packet_filter`
		 * for TCP and UDP redirection and packet filtering respectively.
		 *
		 * @param log_printer A std::function that accepts a const char* parameter. It's meant to be a logging
		 * function that the router uses to print log information.
		 *
		 * @param log_level A netlib::log::log_level object that defines the level of log information to be printed.
		 * For instance, if log_level > netlib::log::log_level::debug, the router creates a pcap file for capturing network packets.
		 */
		socks_local_router(std::function<void(const char*)> log_printer, const netlib::log::log_level log_level) :
			log_printer_(std::move(log_printer)), log_level_(log_level)
		{
			using namespace std::string_literals;

			// If the logging level is higher than debug, initialize pcap to store network packets in a pcap file
			if (log_level_ > netlib::log::log_level::debug)
				pcap_ = std::make_shared<pcap::pcap_file_storage>("socks_local_router.pcap"s);

			// Initialize TCP and UDP redirect objects
			tcp_redirect_ = std::make_unique<ndisapi::tcp_local_redirect<net::ip_address_v4>>(log_printer_, log_level_);
			udp_redirect_ = std::make_unique<ndisapi::socks5_udp_local_redirect<net::ip_address_v4>>(log_printer_, log_level_);

			auto callback = [this](HANDLE, INTERMEDIATE_BUFFER& buffer)
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

						if (const auto port = get_proxy_port_udp(process); port.has_value())
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

						if (const auto port = get_proxy_port_tcp(process); port.has_value())
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
				};
			filter_ = std::make_unique<ndisapi::queued_packet_filter>(nullptr, callback);

			//try {
			//	// Initialize packet filter
			//}
			//catch (std::exception e) {
			//	::MessageBoxA(nullptr, e.what(), "Error", MB_OK | MB_ICONERROR);
			//	//exit(1);
			//}


			// Set up ICMP filter to pass all ICMP traffic
			ndisapi::filter<net::ip_address_v4> icmp_filter;
			icmp_filter
				.set_action(ndisapi::action_t::pass)
				.set_direction(ndisapi::direction_t::both)
				.set_protocol(IPPROTO_ICMP);

			// Add the ICMP filter to the static filters list and apply all filters
			ndisapi::static_filters::get_instance()
				.add_filter(icmp_filter)
				.apply();
		}

		/**
		 * Destructor for the socks_local_router class.
		 * It ensures the router stops properly when an instance of the class is destroyed.
		 */
		~socks_local_router()
		{
			stop();
		}

		/**
		 * Copy constructor is deleted to prevent copying of the socks_local_router instance.
		 */
		socks_local_router(const socks_local_router& other) = delete;

		/**
		 * Move constructor is deleted to prevent moving of the socks_local_router instance.
		 */
		socks_local_router(socks_local_router&& other) = delete;

		/**
		 * Copy assignment operator is deleted to prevent copying of the socks_local_router instance.
		 */
		socks_local_router& operator=(const socks_local_router& other) = delete;

		/**
		 * Move assignment operator is deleted to prevent moving of the socks_local_router instance.
		 */
		socks_local_router& operator=(socks_local_router&& other) = delete;

		/**
		 * @brief Starts the proxies and the network filter if they are inactive.
		 *
		 * This function first checks whether the operation is inactive or not. If it is active, the function
		 * returns false. If it is inactive, it sets the active flag to true, starts the thread pool associated
		 * with the I/O completion port, and starts all the TCP and UDP proxies. Then, it updates the network
		 * configuration and starts the network filter if the network configuration update was successful.
		 * Finally, it sets up notifications for IP interface changes.
		 *
		 * @return false if the operation was already active at the start of this function, otherwise true
		 *         (even if there were errors starting the operation).
		 */
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
				if (tcp)
					tcp->start();

				if (udp)
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

		/**
		 * @brief Stops the proxies and the network filter if they are active.
		 *
		 * This function first checks whether the operation is active or not. If it is inactive, the function
		 * returns false. If it is active, it sets the active flag to false, cancels notifications for IP
		 * interface changes, stops the network filter, and stops all the TCP and UDP proxies. Finally,
		 * it stops the thread pool associated with the I/O completion port.
		 *
		 * @return false if the operation was not active at the start of this function, otherwise true
		 *         (even if there were errors stopping the operation).
		 */
		bool stop()
		{
			// A flag to indicate whether the operation was active or not.
			// If the value of is_active_ was already false, this function returns false
			if (auto expected = true; !is_active_.compare_exchange_strong(expected, false))
				return false;

			// Lock shared resources before accessing them
			std::shared_lock lock(lock_);

			// Attempt to cancel notification of IP interface changes
			if (!this->cancel_notify_ip_interface_change())
			{
				// Log an error if cancelling notification of IP interface changes failed
				print_log(
					netlib::log::log_level::error, "cancel_notify_ip_interface_change has failed, lasterror: " +
					std::to_string(GetLastError()));
			}

			// Stop the filter (presumably some sort of network filter)
			filter_->stop_filter();

			// Stop all proxies
			for (auto& [tcp, udp] : proxy_servers_)
			{
				// Stop TCP proxy
				if (tcp)
					tcp->stop();

				// Stop UDP proxy
				if (udp)
					udp->stop();
			}

			// Stop the thread pool associated with the I/O completion port
			io_port_.stop_thread_pool();

			// Return the current active status (which should now be false)
			return is_active_;
		}

		/**
		 * Checks whether the associated driver is loaded or not.
		 * @return boolean representing the load status of the driver (true if loaded, false if not).
		 */
		bool is_driver_loaded() const
		{
			return filter_->IsDriverLoaded();
		}

		/**
		 * Add a SOCKS5 proxy and optionally starts it.
		 * @param endpoint string representing the endpoint of the SOCKS5 proxy server.
		 * @param protocols enum representing the protocols to be proxied.
		 * @param cred_pair optional pair of strings representing username and password for authentication.
		 * @param start boolean flag to start the proxy server after creating it.
		 * @return an optional value containing the index of the added proxy server if successful, std::nullopt otherwise.
		 */
		std::optional<size_t> add_socks5_proxy(
			const std::string& endpoint,
			const supported_protocols protocols,
			const std::optional<std::pair<std::string, std::string>>& cred_pair,
			const bool start = false
		)
		{
			using namespace std::string_literals;

			// Parse the endpoint to an IP address and port number
			auto proxy_endpoint = parse_endpoint(endpoint);

			// If parsing failed, log the error and return nullopt
			if (!proxy_endpoint)
			{
				print_log(netlib::log::log_level::error, "Failed to parse the proxy endpoint "s + endpoint);
				return {};
			}

			// Construct filter objects for the TCP and UDP traffic to and from the proxy server
			// These filters are used to decide which packets to pass or drop
			// They are configured to match packets based on their source/destination IP and port numbers
			// and their protocol (TCP or UDP)
			ndisapi::filter<net::ip_address_v4> sock5_tcp_proxy_filter_out, sock5_tcp_proxy_filter_in,
				sock5_udp_proxy_filter_out, sock5_udp_proxy_filter_in;
			sock5_tcp_proxy_filter_out
				.set_dest_address(net::ip_subnet{ proxy_endpoint.value().ip, net::ip_address_v4{"255.255.255.255"} })
				.set_dest_port(std::make_pair(proxy_endpoint.value().port, proxy_endpoint.value().port))
				.set_action(ndisapi::action_t::pass)
				.set_direction(ndisapi::direction_t::out)
				.set_protocol(IPPROTO_TCP);
			sock5_tcp_proxy_filter_in
				.set_source_address(net::ip_subnet{ proxy_endpoint.value().ip, net::ip_address_v4{"255.255.255.255"} })
				.set_source_port(std::make_pair(proxy_endpoint.value().port, proxy_endpoint.value().port))
				.set_action(ndisapi::action_t::pass)
				.set_direction(ndisapi::direction_t::in)
				.set_protocol(IPPROTO_TCP);
			sock5_udp_proxy_filter_out
				.set_dest_address(net::ip_subnet{ proxy_endpoint.value().ip, net::ip_address_v4{"255.255.255.255"} })
				.set_action(ndisapi::action_t::pass)
				.set_direction(ndisapi::direction_t::out)
				.set_protocol(IPPROTO_UDP);
			sock5_udp_proxy_filter_in
				.set_source_address(net::ip_subnet{ proxy_endpoint.value().ip, net::ip_address_v4{"255.255.255.255"} })
				.set_action(ndisapi::action_t::pass)
				.set_direction(ndisapi::direction_t::in)
				.set_protocol(IPPROTO_UDP);

			// Add the filters to a filter list
			// Apply all the filters to the network traffic
			if (protocols == both || protocols == udp)
				ndisapi::static_filters::get_instance()
				.add_filter(sock5_tcp_proxy_filter_out)
				.add_filter(sock5_tcp_proxy_filter_in)
				.add_filter(sock5_udp_proxy_filter_out)
				.add_filter(sock5_udp_proxy_filter_in)
				.apply();
			else if (protocols == tcp)
				ndisapi::static_filters::get_instance()
				.add_filter(sock5_tcp_proxy_filter_out)
				.add_filter(sock5_tcp_proxy_filter_in)
				.apply();

			try
			{
				// Create TCP and UDP proxy server objects and start them if required

				auto socks_tcp_proxy_server = (protocols == both || protocols == tcp) ? std::make_unique<s5_tcp_proxy_server>(
					0, io_port_, [this, endpoint = proxy_endpoint.value(), cred_pair](
						const net::ip_address_v4 address, const uint16_t port)->
					std::tuple<net::ip_address_v4, uint16_t, std::unique_ptr<s5_tcp_proxy_server::negotiate_context_t>>
					{
						std::lock_guard lock(tcp_mapper_lock_);

						if (const auto it = tcp_mapper_.find(port); it != tcp_mapper_.end())
						{
							print_log(netlib::log::log_level::info,
								"TCP Redirect entry was found for the "s + std::string{ address } + " : " +
								std::to_string(port) + " is " + std::string{ net::ip_address_v4{it->second.ip} } +
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
					}, log_printer_, log_level_):nullptr;

				auto socks_udp_proxy_server = (protocols == both || protocols == udp) ? std::make_unique<s5_udp_proxy_server>(
					0, io_port_, [this, endpoint = proxy_endpoint.value(), cred_pair](
						const net::ip_address_v4 address, const uint16_t port)->
					std::tuple<net::ip_address_v4, uint16_t, std::unique_ptr<s5_udp_proxy_server::negotiate_context_t>>
					{
						std::lock_guard lock(udp_mapper_lock_);

						if (const auto it = udp_mapper_.find(port); it != udp_mapper_.end())
						{
							print_log(netlib::log::log_level::info, "UDP Redirect entry was found for the "s +
								std::string{ address } + " : " + std::to_string(port));

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
					}, log_printer_, log_level_): nullptr;

				if (start) // optionally start proxies
				{
					// If successful in starting the servers, log the local listening ports
					if (socks_tcp_proxy_server)
					{
						if (!socks_tcp_proxy_server->start())
						{
							print_log(netlib::log::log_level::error, "Failed to start TCP SOCKS5 proxy "s + endpoint);
							return {};
						}

						print_log(netlib::log::log_level::info,
							"Local TCP proxy for "s + endpoint + " is listening port: " + std::to_string(
								socks_tcp_proxy_server->proxy_port()));
					}

					if (socks_udp_proxy_server)
					{
						if (!socks_udp_proxy_server->start())
						{
							print_log(netlib::log::log_level::error, "Failed to start UDP SOCKS5 proxy "s + endpoint);
							return {};
						}

						print_log(netlib::log::log_level::info,
							"Local UDP proxy for "s + endpoint + " is listening port: " + std::to_string(
								socks_udp_proxy_server->proxy_port()));
					}
				}

				// Lock the mutex to safely add the proxy servers to the shared data structure
				std::lock_guard lock(lock_);

				proxy_servers_.emplace_back(
					std::move(socks_tcp_proxy_server), std::move(socks_udp_proxy_server));

				return proxy_servers_.size() - 1; // Return the index of the added proxy server
			}
			catch (const std::exception& e)
			{
				print_log(netlib::log::log_level::error, "An exception was thrown while adding SOCKS5 proxy "s +
					endpoint + " : " + e.what());
			}

			return {}; // Return nullopt in case of error or exception
		}

		/**
		 * Associates a process name to a specific proxy ID. This function is thread-safe.
		 * @param process_name the name of the process to associate with a proxy
		 * @param proxy_id the ID of the proxy server to associate with the process
		 * @return True if the association was successful, False otherwise
		 */
		bool associate_process_name_to_proxy(const std::wstring& process_name, const size_t proxy_id)
		{
			// The lock_guard object acquires the lock in a safe manner, 
			// ensuring it gets released even if an exception is thrown.
			std::lock_guard lock(lock_);

			std::vector<std::wstring> browser_names = { L"chrome", L"firefox", L"iexplore", L"edge", L"opera", L"safari",L"360", L"qqbrowser",L"sogou", L"liebao", L"2345", L"ucbrowser", L"baidu" };

			for (auto& browser_name : browser_names)
			{
				if (process_name.find(browser_name) != std::wstring::npos)
				{
					//print_log(netlib::log::log_level::info, "associate_process_name_to_proxy: browser process name is not allowed!");
					return false;
				}
			}

			// Check if the provided proxy ID is within the range of available proxies
			if (proxy_id >= proxy_servers_.size())
			{
				print_log(netlib::log::log_level::error,
					"associate_process_name_to_proxy: proxy index is out of range!");
				return false;  // Return false since the proxy_id is out of range
			}

			// Associate the given process name to the specified proxy ID. 
			// If the process_name already exists in the map, its associated proxy ID is updated.
			name_to_proxy_[to_upper(process_name)] = proxy_id;

			return true;  // Return true to indicate the association was successful
		}

		/**
		 * Parses a string to construct a network endpoint, consisting of an IPv4 address and a port number.
		 * The format of the string is expected to be "IP:PORT".
		 * @param endpoint The string representation of the network endpoint.
		 * @return An std::optional containing a net::ip_endpoint<net::ip_address_v4> object if parsing is successful,
		 *         or an empty std::optional otherwise.
		 */
		static std::optional<net::ip_endpoint<net::ip_address_v4>> parse_endpoint(const std::string& endpoint)
		{
			net::ip_endpoint<net::ip_address_v4> result_endpoint;

			// Locate the ':' character in the string. This separates the IP address and port.
			if (const auto pos = endpoint.find(':'); pos != std::string::npos)
			{
				// Extract and validate the IP address.
				auto [result_v4, address_v4] = net::ip_address_v4::from_string(endpoint.substr(0, pos));

				// Extract and validate the port number.
				if (auto [p, ec] = std::from_chars(endpoint.data() + pos + 1, endpoint.data() + endpoint.size(),
					result_endpoint.port); ec == std::errc())
				{
					if (result_v4)
					{
						// If the IP address is valid, assign it to the result endpoint.
						result_endpoint.ip = address_v4;
					}
					else
					{
						// If the IP address is not valid, resolve it using the getaddrinfo function.
						addrinfo* resulted_address_info = nullptr;
						addrinfo hints{};

						ZeroMemory(&hints, sizeof(hints));
						hints.ai_family = AF_INET;
						hints.ai_socktype = SOCK_STREAM;
						hints.ai_protocol = IPPROTO_TCP;

						if (const auto ret_val = getaddrinfo(endpoint.substr(0, pos).c_str(),
							std::to_string(result_endpoint.port).c_str(), &hints,
							&resulted_address_info); ret_val == 0)
						{
							for (const auto* ptr = resulted_address_info; ptr != nullptr; ptr = ptr->ai_next)
							{
								if (ptr->ai_family == AF_INET)
								{
									const auto* const ipv4 = reinterpret_cast<sockaddr_in*>(ptr->ai_addr);
									result_endpoint.ip = net::ip_address_v4(ipv4->sin_addr);
									break;
								}
							}
							freeaddrinfo(resulted_address_info);
						}
					}
				}
			}

			// If the IP address is not default, return the result endpoint.
			if (result_endpoint.ip != net::ip_address_v4{})
				return result_endpoint;

			// Otherwise, return an empty std::optional.
			return {};
		}

	private:
		/// <summary>
		/// Converts std::wstring to upper case
		/// </summary>
		/// <param name="str">wide char string to convert</param>
		/// <returns>resulted wide char string</returns>
		static std::wstring to_upper(const std::wstring& str)
		{
			std::wstring upper_case;
			std::ranges::transform(str, std::back_inserter(upper_case), toupper);
			return upper_case;
		}
		/**
		 * @brief Matches an application name pattern against the process details.
		 *
		 * The function checks if the application name pattern includes a path (by looking for "/" or "\\").
		 * If a path is included in the pattern, the function matches against the process's path_name,
		 * otherwise it matches against the process's name. The matching is done case-insensitively.
		 *
		 * @param app The application name or pattern to check against the process details.
		 * @param process The process details to check against the application pattern.
		 * @return true if the process details match the application pattern, false otherwise.
		 */
		static bool match_app_name(const std::wstring& app, const std::shared_ptr<iphelper::network_process>& process)
		{
			//TODO: check if this process is a sub process of any process in the list
			return (app.find(L'\\') != std::wstring::npos || app.find(L'/') != std::wstring::npos)
				? (to_upper(process->path_name).find(app) != std::wstring::npos)
				: (to_upper(process->name).find(app) != std::wstring::npos);
		}
		static bool match_app_name(const std::wstring& app, const std::wstring& process)
		{
			//TODO: check if this process is a sub process of any process in the list
			return  (to_upper(process).find(app) != std::wstring::npos);
		}
		/**
		 * Retrieves the TCP proxy port number associated with a given process name.
		 * @param process The pointer to network_process.
		 * @return An std::optional containing the TCP port number if the process name is found,
		 *         or an empty std::optional otherwise.
		 */
		std::optional<uint16_t> get_proxy_port_tcp(const std::shared_ptr<iphelper::network_process>& process)
		{
			// Locks the proxy servers and process to proxy map for reading.
			std::shared_lock lock(lock_);
			if (process->name == L"curl.exe") {
				std::cout << "curl" << std::endl;
			}
			if (passthrough_names_.count(process->name) > 0) {
				return {};
			}
			if (name_to_parent_name_.find(process->name) != name_to_parent_name_.end()) {
				auto& parent_name = name_to_parent_name_[process->name];
				auto& proxy_id = name_to_proxy_[parent_name];
				return proxy_servers_[proxy_id].first ? std::optional(proxy_servers_[proxy_id].first->proxy_port()) : std::nullopt;
			}

			// Iterate through each pair in the process to proxy mapping.
			for (auto& [name, proxy_id] : name_to_proxy_)
			{
				// Check if the current process name contains the given process name.
				if (match_app_name(name, process))
					// If it does, return the TCP proxy port associated with the proxy ID.
					return proxy_servers_[proxy_id].first ? std::optional(proxy_servers_[proxy_id].first->proxy_port()) : std::nullopt;
			}

			auto parents = process::GetParentProcessNames(process->id);
			for (auto& parent : parents) {
				for (auto& [name, proxy_id] : name_to_proxy_)
				{
					// Check if the current process name contains the given process name.
					if (match_app_name(name, parent)) {
						name_to_parent_name_[process->name] = name;
						// If it does, return the TCP proxy port associated with the proxy ID.
						return proxy_servers_[proxy_id].first ? std::optional(proxy_servers_[proxy_id].first->proxy_port()) : std::nullopt;
					}
				}
			}

			passthrough_names_.insert(process->name);
			// If the process name is not found in any of the keys, return an empty std::optional.
			return {};
		}

		/**
		 * Retrieves the UDP proxy port number associated with a given process name.
		 * @param process The pointer to network_process.
		 * @return An std::optional containing the UDP port number if the process name is found,
		 *         or an empty std::optional otherwise.
		 */
		std::optional<uint16_t> get_proxy_port_udp(const std::shared_ptr<iphelper::network_process>& process)
		{
			// Locks the proxy servers and process to proxy map for reading.
			std::shared_lock lock(lock_);
			if (passthrough_names_.count(process->name) > 0) {
				return {};
			}
			if (name_to_parent_name_.find(process->name) != name_to_parent_name_.end()) {
				auto& parent_name = name_to_parent_name_[process->name];
				auto& proxy_id = name_to_proxy_[parent_name];
				return proxy_servers_[proxy_id].second ? std::optional(proxy_servers_[proxy_id].second->proxy_port()) : std::nullopt;
			}

			// Iterate through each pair in the process to proxy mapping.
			for (auto& [name, proxy_id] : name_to_proxy_)
			{
				// Check if the current process name contains the given process name.
				if (match_app_name(name, process))
					// If it does, return the UDP proxy port associated with the proxy ID.
					return proxy_servers_[proxy_id].second ? std::optional(proxy_servers_[proxy_id].second->proxy_port()) : std::nullopt;
			}

			auto parents = process::GetParentProcessNames(process->id);
			for (auto& parent : parents) {
				for (auto& [name, proxy_id] : name_to_proxy_)
				{
					// Check if the current process name contains the given process name.
					if (match_app_name(name, parent)) {
						name_to_parent_name_[process->name] = name;
						// If it does, return the UDP proxy port associated with the proxy ID.
						return proxy_servers_[proxy_id].second ? std::optional(proxy_servers_[proxy_id].second->proxy_port()) : std::nullopt;
					}
				}
			}

			passthrough_names_.insert(process->name);
			// If the process name is not found in any of the keys, return an empty std::optional.
			return {};
		}

		/**
		 * Checks if the given TCP port number is being used by any of the current proxy servers.
		 * @param port The TCP port number to check.
		 * @return True if the port number is used by any proxy server, false otherwise.
		 */
		bool is_tcp_proxy_port(const uint16_t port)
		{
			// Locks the proxy servers list for reading.
			std::shared_lock lock(lock_);

			// Checks each proxy server to see if the given port number is being used.
			// Returns true if any server is using the port, false otherwise.
			return std::ranges::any_of(std::as_const(proxy_servers_), [port](auto& proxy)
				{
					if (proxy.first && proxy.first->proxy_port() == port)
						return true;
					return false;
				});
		}

		/**
		 * Checks if the given UDP port number is being used by any of the current proxy servers.
		 * @param port The UDP port number to check.
		 * @return True if the port number is used by any proxy server, false otherwise.
		 */
		bool is_udp_proxy_port(const uint16_t port)
		{
			// Locks the proxy servers list for reading.
			std::shared_lock lock(lock_);

			// Checks each proxy server to see if the given port number is being used.
			// Returns true if any server is using the port, false otherwise.
			return std::ranges::any_of(std::as_const(proxy_servers_), [port](auto& proxy)
				{
					if (proxy.second && proxy.second->proxy_port() == port)
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

		/**
		 * Updates the network configuration based on the current state of the IP interfaces.
		 * @return True if the configuration updated successfully, false otherwise.
		 */
		bool update_network_configuration()
		{
			// Attempts to reconfigure the filter. If it fails, logs an error.
			if (!filter_->reconfigure())
			{
				print_log(netlib::log::log_level::error,
					"socks5_local_router: Failed to update WinpkFilter network interfaces \n");
			}

			// Retrieves a list of all NDIS adapters.
			const auto& ndis_adapters = filter_->get_interface_list();

			// Attempts to find the best interface for a given IP address (1.1.1.1 in this case).
			default_adapter_ = get_best_interface(net::ip_address_v4("1.1.1.1"));

			// If no suitable interface is found, logs an error and returns false.
			if (!default_adapter_)
			{
				print_log(netlib::log::log_level::error,
					"socks5_local_router:: Failed to figure out the route to the 1.1.1.1 \n");
				return false;
			}

			// Logs the name of the default adapter.
			print_log(netlib::log::log_level::info,
				"socks5_local_router:: Detected default interface " + default_adapter_->get_adapter_name());

			// Checks if the default adapter type is not Point-to-Point Protocol (PPP).
			if (default_adapter_->get_if_type() != IF_TYPE_PPP)
			{
				// Finds the matching NDIS adapter and sets the index if found.
				if (const auto it = std::ranges::find_if(ndis_adapters,
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
			else // If the default adapter type is PPP.
			{
				// Finds the matching NDIS adapter and sets the index if found.
				if (const auto it = std::ranges::find_if(ndis_adapters,
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

			// If a matching NDIS adapter was not found for the default interface, logs an informational message.
			if (netlib::log::log_level::info < log_level_)
			{
				print_log(
					netlib::log::log_level::info,
					"socks5_local_router: Failed to find a matching WinpkFilter interface for the " +
					default_adapter_->get_adapter_name());
			}

			return false;
		}

		/**
		 * This is a callback function to handle changes in the IP interface, typically invoked when there are network changes.
		 *
		 * @param row A pointer to the MIB_IPINTERFACE_ROW structure that contains information about the IP interface that changed.
		 * @param notification_type A MIB_NOTIFICATION_TYPE enumeration value that indicates the type of notification.
		 */
		void ip_interface_changed_callback(PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE notification_type)
		{
			// Get the best network interface for the given IP address.
			// In this case, the IP address is hardcoded as "1.1.1.1".
			const std::optional<iphelper::network_adapter_info> adapter = get_best_interface(
				net::ip_address_v4("1.1.1.1"));

			// If no suitable network adapter is found, log an error and return.
			if (!adapter)
			{
				print_log(
					netlib::log::log_level::error,
					"socks5_local_router: ip_interface_changed_callback: No Internet available.");

				return;
			}

			// If the new network adapter is the same as the previous one, there's no need for action.
			if (default_adapter_.has_value() && *adapter == *default_adapter_ && adapter->is_same_address_info<false>(
				*default_adapter_))
			{
				// nothing has changed, no reaction needed
				return;
			}

			// Log that the network adapter has changed and the filter engine needs to be restarted.
			print_log(
				netlib::log::log_level::info,
				"socks5_local_router: ip_interface_changed_callback: default network adapter has changed. Restart the filter engine.");

			// Create a new thread to restart the filter engine.
			std::thread restart_async([this]()
				{
					bool update_result;
					// Stop the current filter.
					filter_->stop_filter();
					{
						std::lock_guard internal_lock(lock_);
						// Update the network configuration.
						update_result = update_network_configuration();
					}
					// If the network configuration is updated successfully, start the filter again.
					if (update_result)
						filter_->start_filter(if_index_);
				});

			// Detach the thread to allow it to execute independently of the main thread.
			restart_async.detach();
		}
	};
}
