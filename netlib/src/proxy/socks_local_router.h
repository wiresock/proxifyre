#pragma once
namespace proxy
{
    /**
     * @class socks_local_router
     * @brief Implements a local router for handling SOCKS proxy traffic.
     *
     * The socks_local_router class manages TCP and UDP redirection, process-to-proxy mapping,
     * and dynamic network adapter filtering for transparent proxying. It integrates with
     * the system's network configuration and logging facilities, and provides mechanisms
     * for deferred process resolution, packet filtering, and proxy server management.
     *
     * Inherits from:
     * - iphelper::network_config_info<socks_local_router>: For network configuration monitoring and callbacks.
     * - netlib::log::logger<socks_local_router>: For logging router events and diagnostics.
     */
    class socks_local_router :  // NOLINT(clang-diagnostic-padded)
        public iphelper::network_config_info<socks_local_router>,
        public netlib::log::logger<socks_local_router>
    {
        // Type alias for the log level used by the logger base class.
        using log_level = netlib::log::log_level;

        /**
         * @brief Alias for the packet filter type from the ndisapi library.
         */
        using packet_filter = ndisapi::queued_multi_interface_packet_filter;

        // Allows the base class 'network_config_info' to access the private CRTP callback.
        friend network_config_info;

        /**
         * @brief Type alias for the SOCKS5 TCP proxy server specialized for IPv4.
         */
        using s5_tcp_proxy_server = tcp_proxy_server<socks5_tcp_proxy_socket<net::ip_address_v4>>;

        /**
         * @brief Type alias for the SOCKS5 UDP proxy server specialized for IPv4.
         */
        using s5_udp_proxy_server = socks5_local_udp_proxy_server<socks5_udp_proxy_socket<net::ip_address_v4>>;

        /**
         * @brief Stores a mapping of TCP ports to their corresponding IP endpoints.
         */
        std::unordered_map<uint16_t, net::ip_endpoint<net::ip_address_v4>> tcp_mapper_;

        /**
         * @brief Stores the set of UDP ports being mapped.
         */
        std::unordered_set<uint16_t> udp_mapper_;

        /**
         * @brief Mutex to synchronize access to the TCP port mapping.
         */
        std::mutex tcp_mapper_lock_;

        /**
         * @brief Mutex to synchronize access to the UDP port mapping.
         */
        std::mutex udp_mapper_lock_;

        /**
         * @brief I/O completion port for asynchronous operations.
         */
        netlib::winsys::io_completion_port io_port_;

        /**
         * @brief Optional pcap stream logger for packet capture logging.
         */
        std::optional<pcap::pcap_stream_logger> pcap_logger_;

        /**
         * @brief Vector storing pairs of unique pointers to TCP and UDP proxy servers.
         */
        std::vector<std::pair<std::unique_ptr<s5_tcp_proxy_server>, std::unique_ptr<s5_udp_proxy_server>>> proxy_servers_;

        /**
         * @brief Maps proxy indexes to their corresponding process names (sorted by proxy ID).
         */
        std::multimap<size_t, std::wstring> proxy_to_names_;

        /**
         * @brief A list of excluded process names.
         */
        std::vector<std::wstring> excluded_list_;

        /**
         * @brief Shared mutex to protect concurrent access to shared resources.
         */
        std::shared_mutex lock_;

        /**
         * @brief Unique pointer to the TCP redirect object.
         */
        std::unique_ptr<ndisapi::tcp_local_redirect<net::ip_address_v4>> tcp_redirect_{ nullptr };

        /**
         * @brief Unique pointer to the UDP redirect object.
         */
        std::unique_ptr<ndisapi::socks5_udp_local_redirect<net::ip_address_v4>> udp_redirect_{ nullptr };

        /**
         * @brief Unique pointer to the packet filter object.
         */
        std::unique_ptr<packet_filter> packet_filter_{ nullptr };

        /**
         * @brief Static filters for packet filtering.
         */
        ndisapi::static_filters static_filters_;

        /**
         * @brief Process lookup for IPv4 addresses.
         */
        iphelper::process_lookup<net::ip_address_v4> process_lookup_v4_;

        /**
         * @brief Process lookup for IPv6 addresses.
         */
        iphelper::process_lookup<net::ip_address_v6> process_lookup_v6_;

        /**
         * @brief Mutex to protect the set of adapter names that need to be filtered.
         */
        std::shared_mutex adapters_to_filter_lock_;

        /**
         * @brief Set of adapter names that need to be filtered.
         */
        std::unordered_set<std::string> adapters_to_filter_;

        /**
         * @brief Thread for lazy process resolution.
         */
        std::thread process_resolve_thread_;

        /**
         * @brief Queue for holding pointers to intermediate_buffer objects that require process resolution.
         *
         * This queue is used to store buffers that need to be processed by the process resolution thread.
         * Access to this queue is synchronized using process_resolve_buffer_mutex_ and process_resolve_buffer_queue_cv_.
         */
        std::queue<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr> process_resolve_buffer_queue_;

        /**
         * @brief Mutex to guard access to the process_resolve_buffer_queue_.
         *
         * This mutex ensures thread-safe access to the buffer queue, preventing data races
         * when multiple threads are adding to or removing from the queue.
         */
        mutable std::mutex process_resolve_buffer_mutex_;

        /**
         * @brief Condition variable for synchronizing access to the process_resolve_buffer_queue_.
         *
         * This condition variable is used to notify waiting threads when new buffers are added to the queue,
         * allowing the process resolution thread to efficiently wait for work.
         */
        std::condition_variable process_resolve_buffer_queue_cv_;

        /**
         * @brief Shared pointer to an output stream for PCAP (packet capture) logging.
         *
         * This stream is used to write packet capture data when PCAP logging is enabled.
         * The stream is passed to the constructor and if valid, is used to initialize
         * the pcap_logger_ for packet logging functionality. The shared ownership allows
         * the stream to be safely shared across different components of the router.
         *
         * @see pcap_logger_
         * @see log_packet_to_pcap()
         */
        std::shared_ptr<std::ostream> pcap_log_stream_;

        /**
        * @brief Atomic boolean to track the active status of the router.
        */
        std::atomic_bool is_active_{ false };

    public:
        enum supported_protocols : uint8_t
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
         * @param log_level A netlib::log::log_level object that defines the level of log information to be printed.
         *                  For instance, if log_level > netlib::log::log_level::debug, the router creates a pcap file for capturing network packets.
         * @param log_stream Optional reference to an output stream for logging.
         * @param pcap_log_stream Optional reference to an output stream for pcap logging.
         */
        explicit socks_local_router(const log_level log_level = log_level::error,
                                    std::shared_ptr<std::ostream> log_stream = nullptr,
                                    std::shared_ptr<std::ostream> pcap_log_stream = nullptr) :
                                    logger(log_level, std::move(log_stream)),
                                    static_filters_{ true, true, log_level_, log_stream_ },
                                    process_lookup_v4_{ log_level_, log_stream_ },
                                    process_lookup_v6_{ log_level_, log_stream_ },
                                    pcap_log_stream_(std::move(pcap_log_stream))
        {
            using namespace std::string_literals;

            if (pcap_log_stream) {
                pcap_logger_.emplace(*pcap_log_stream_);
            }

            // Initialize TCP and UDP redirect objects
            tcp_redirect_ = std::make_unique<ndisapi::tcp_local_redirect<net::ip_address_v4>>(log_level_, log_stream);
            udp_redirect_ = std::make_unique<ndisapi::socks5_udp_local_redirect<net::ip_address_v4>>(
                log_level_, log_stream);

            // Initialize packet filter
            packet_filter_ = std::make_unique<packet_filter>(
                nullptr,
                [this](HANDLE, ndisapi::intermediate_buffer& buffer)
                {
                    auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);
                    const auto destination_mac = net::mac_address(ethernet_header->h_dest);

                    if (ntohs(ethernet_header->h_proto) != ETH_P_IP)
                    {
                        return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
                    }

                    log_packet_to_pcap(buffer);

                    const auto* const ip_header = reinterpret_cast<iphdr_ptr>(ethernet_header + 1);

                    if (ip_header->ip_p == IPPROTO_UDP)
                    {
                        // skip broadcast and multicast UDP packets
                        if (destination_mac.is_broadcast() || destination_mac.is_multicast())
                        {
                            return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
                        }

                        if (const auto result = process_udp_packet(buffer, false))
                        {
                            return result.value();
                        }
                        // Queue for the later processing
                        if (auto allocated_buffer = ndisapi::intermediate_buffer_pool::instance().allocate(buffer))
                        {
                            {
                                std::scoped_lock lock(process_resolve_buffer_mutex_);
                                process_resolve_buffer_queue_.push(std::move(allocated_buffer));
                            }
                            process_resolve_buffer_queue_cv_.notify_one();
                        }
                        else
                        {
                            // Handle the error, e.g., log it or take corrective action
                            NETLIB_LOG(log_level::error, "Failed to allocate buffer.");
                        }
                        return packet_filter::packet_action{ packet_filter::packet_action::action_type::drop };
                    }

                    if (ip_header->ip_p == IPPROTO_TCP)
                    {
                        if (const auto result = process_tcp_packet(buffer, false))
                        {
                            return result.value();
                        }
                        // Queue for the later processing
                        if (auto allocated_buffer = ndisapi::intermediate_buffer_pool::instance().allocate(buffer))
                        {
                            {
                                std::scoped_lock lock(process_resolve_buffer_mutex_);
                                process_resolve_buffer_queue_.push(std::move(allocated_buffer));
                            }
                            process_resolve_buffer_queue_cv_.notify_one();
                        }
                        else
                        {
                            // Handle the error, e.g., log it or take corrective action
                            NETLIB_LOG(log_level::error, "Failed to allocate buffer.");
                        }
                        return packet_filter::packet_action{ packet_filter::packet_action::action_type::drop };
                    }

                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
                });

            // Set up ICMP filter to pass all ICMP traffic
            ndisapi::filter<net::ip_address_v4> icmp_filter;
            icmp_filter
                .set_action(ndisapi::action_t::pass)
                .set_direction(ndisapi::direction_t::both)
                .set_protocol(IPPROTO_ICMP);

            // Add the ICMP filter to the static filters list
            static_filters_.add_filter_back(icmp_filter);
        }

        /**
         * Destructor for the socks_local_router class.
         * It ensures the router stops properly when an instance of the class is destroyed.
         */
        ~socks_local_router() override
        {
            try
            {
                if (is_active_.load(std::memory_order_acquire))
                {
                    NETLIB_DEBUG("Destructor calling stop()");
                    stop();
                }
            }
            catch (const std::exception& e)
            {
                // Log but don't throw from destructor
                // Throwing from destructor causes std::terminate/abort
                NETLIB_ERROR("Exception in ~socks_local_router::stop(): {}", e.what());
            }
            catch (...)
            {
                // Catch any other exceptions to prevent abort
                NETLIB_ERROR("Unknown exception in ~socks_local_router::stop()");
            }
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
            {
                NETLIB_LOG(log_level::error, "Filter is already active!");
                return false;
            }

            if (!packet_filter_)
            {
                NETLIB_LOG(log_level::error, "Packet filter is not initialized!");
                return false;
            }

            if (!this->set_notify_ip_interface_change())
            {
                NETLIB_LOG(
                    log_level::error,
                    "set_notify_ip_interface_change has failed, lasterror: {}",
                    GetLastError());
            }

            {
                std::shared_lock lock(lock_);

                // Start thread pool
                io_port_.start_thread_pool();

                // Start proxies
                for (auto& [tcp, udp] : proxy_servers_)
                {
                    if (tcp)
                    {
                        if (!tcp->start())
                        {
                            NETLIB_LOG(log_level::error, "Failed to start TCP proxy on port: {}", tcp->proxy_port());
                        }
                    }

                    if (udp)
                    {
                        if (!udp->start())
                        {
                            NETLIB_LOG(log_level::error, "Failed to start UDP proxy on port: {}", udp->proxy_port());
                        }
                    }
                }
            }

            process_resolve_thread_ = std::thread(&socks_local_router::process_resolve_thread_proc, this);

            // Update network configuration and start filter
            update_network_configuration();
            if (!packet_filter_->start_filter())
            {
                NETLIB_LOG(log_level::error, "Failed to start NDIS packet filter");

                // Attempt to cancel notification of IP interface changes
                if (!this->cancel_notify_ip_interface_change())
                {
                    // Log an error if cancelling notification of IP interface changes failed
                    NETLIB_LOG(
                        log_level::error, "cancel_notify_ip_interface_change has failed, lasterror: {}",
                        GetLastError());

                    std::shared_lock lock(lock_);

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

                    is_active_.store(false);

                    process_resolve_buffer_queue_cv_.notify_all();

                    if (process_resolve_thread_.joinable())
                        process_resolve_thread_.join();
                }
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

            // Step 1: Stop the packet filter FIRST
            // This prevents new packets from being processed and queued
            NETLIB_DEBUG("Stopping packet filter");
            packet_filter_->stop_filter();

            // Step 2: Signal and join the process resolve thread
            // This ensures no more packets are being queued for processing
            NETLIB_DEBUG("Stopping process resolve thread");
            process_resolve_buffer_queue_cv_.notify_all();

            if (process_resolve_thread_.joinable())
                process_resolve_thread_.join();

            // Step 3: Stop all redirect objects FIRST to stop their cleanup threads
            // CRITICAL: Stop redirects before stopping proxies to ensure cleanup threads finish
            NETLIB_DEBUG("Stopping redirect objects");

            if (tcp_redirect_)
            {
                tcp_redirect_->stop();  // This should join the cleanup thread
            }

            if (udp_redirect_)
            {
                udp_redirect_->stop();  // This should join the cleanup thread
            }

            // Step 4: Stop all proxy servers WITHOUT holding lock_
            // CRITICAL: We must NOT hold lock_ while calling stop() or during destruction
            // because the cleanup threads inside the proxies need to acquire the same lock

            NETLIB_DEBUG("Stopping {} IPv4 proxy pairs", proxy_servers_.size());

            // Stop all IPv4 proxies without holding lock_
            for (size_t i = 0; i < proxy_servers_.size(); ++i)
            {
                if (proxy_servers_[i].first)
                {
                    NETLIB_DEBUG("Stopping IPv4 TCP proxy #{} on port {}", i, proxy_servers_[i].first->proxy_port());
                    proxy_servers_[i].first->stop();
                }

                if (proxy_servers_[i].second)
                {
                    NETLIB_DEBUG("Stopping IPv4 UDP proxy #{} on port {}", i, proxy_servers_[i].second->proxy_port());
                    proxy_servers_[i].second->stop();
                }
            }

            // Step 5: Stop the IOCP thread pool
            // At this point, all handlers registered by the proxy servers have been
            // unregistered by their respective stop() methods, so no new completions
            // will invoke callbacks that access destroyed objects.
            NETLIB_DEBUG("Stopping IOCP thread pool");
            io_port_.stop_thread_pool();

            // Step 6: Cancel IP interface change notifications
            // Attempt to cancel notification of IP interface changes
            if (!this->cancel_notify_ip_interface_change())
            {
                // Log an error if cancelling notification of IP interface changes failed
                NETLIB_ERROR("cancel_notify_ip_interface_change has failed, lasterror: {}",
                    GetLastError());
            }

            // Step 7: Wait for any in-flight callbacks to complete
            // The callback increments notify_ip_interface_ref_ on entry and decrements on exit.
            // We wait with timeout to prevent indefinite hangs if something goes wrong.
            NETLIB_DEBUG("Waiting for network interface callbacks to complete");

            using namespace std::chrono_literals;
            constexpr auto max_wait_duration = 5s;  // Maximum time to wait for callbacks
            constexpr auto initial_sleep = 1ms;
            constexpr auto max_sleep = 100ms;

            const auto start_time = std::chrono::steady_clock::now();
            auto current_sleep = initial_sleep;

            while (!this->notify_ip_interface_can_unload())
            {
                if (const auto elapsed = std::chrono::steady_clock::now() - start_time; elapsed >= max_wait_duration)
                {
                    NETLIB_WARNING("Timeout waiting for network interface callbacks to complete after {} seconds. "
                        "Proceeding with shutdown - potential resource leak or callback still in-flight.",
                        std::chrono::duration_cast<std::chrono::seconds>(elapsed).count());
                    break;
                }

                // Exponential backoff to reduce CPU usage while waiting
                std::this_thread::sleep_for(current_sleep);
                current_sleep = std::min(current_sleep * 2, max_sleep);
            }

            if (this->notify_ip_interface_can_unload())
            {
                NETLIB_DEBUG("All network interface callbacks completed");
            }

            NETLIB_INFO("socks_local_router stopped successfully");

            // Return the current active status (which should now be false)
            return !is_active_;
        }

        /**
         * @brief Enables LAN traffic bypass by adding pass-through filters.
         *
         * When called, traffic to/from local network ranges (10.x.x.x, 172.16.x.x-172.31.x.x,
         * 192.168.x.x, 224.0.0.x, 169.254.x.x) will pass through without being proxied.
         *
         * @note This must be called before start() to take effect.
         */
        void set_bypass_lan() noexcept
        {
            add_lan_passover_filters_v4();
        }

        /**
         * Checks whether the associated driver is loaded or not.
         * @return boolean representing the load status of the driver (true if loaded, false if not).
         */
        bool is_driver_loaded() const
        {
            return packet_filter_->IsDriverLoaded();
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
                NETLIB_LOG(log_level::error, "Failed to parse the proxy endpoint {}", endpoint);
                return {};
            }

            // Construct filter objects for the TCP and UDP traffic to and from the proxy server
            // These filters are used to decide which packets to pass or drop
            // They are configured to match packets based on their source/destination IP and port numbers
            // and their protocol (TCP or UDP)
            auto create_filter = [](const uint8_t protocol, const ndisapi::direction_t direction,
                const net::ip_address_v4& address, const uint16_t port)
            {
                ndisapi::filter<net::ip_address_v4> filter;
                filter.set_protocol(protocol)
                    .set_direction(direction)
                    .set_action(ndisapi::action_t::pass)
                    .set_dest_address(net::ip_subnet{ address, net::ip_address_v4{"255.255.255.255"} })
                    .set_dest_port(std::make_pair(port, port));
                return filter;
            };

            const auto tcp_out_filter = create_filter(IPPROTO_TCP, ndisapi::direction_t::out, proxy_endpoint.value().ip,
                                                      proxy_endpoint.value().port);
            const auto tcp_in_filter = create_filter(IPPROTO_TCP, ndisapi::direction_t::in, proxy_endpoint.value().ip,
                                                     proxy_endpoint.value().port);
            const auto udp_out_filter = create_filter(IPPROTO_UDP, ndisapi::direction_t::out, proxy_endpoint.value().ip,
                                                      proxy_endpoint.value().port);
            const auto udp_in_filter = create_filter(IPPROTO_UDP, ndisapi::direction_t::in, proxy_endpoint.value().ip,
                                                     proxy_endpoint.value().port);

            // Add the filters to a filter list
            // Apply all the filters to the network traffic
            if (protocols == both || protocols == udp)
            {
                static_filters_.add_filter_back(tcp_out_filter);
                static_filters_.add_filter_back(tcp_in_filter);
                static_filters_.add_filter_back(udp_out_filter);
                static_filters_.add_filter_back(udp_in_filter);
            }
            else if (protocols == tcp)
            {
                static_filters_.add_filter_back(tcp_out_filter);
                static_filters_.add_filter_back(tcp_in_filter);
            }

            try
            {
                // Create TCP and UDP proxy server objects and start them if required

                auto socks_tcp_proxy_server = (protocols == both || protocols == tcp)
                                                  ? std::make_unique<s5_tcp_proxy_server>(
                                                      0, io_port_, [this, endpoint = proxy_endpoint.value(), cred_pair](
                                                      const net::ip_address_v4 address, const uint16_t port)->
                                                      std::tuple<net::ip_address_v4, uint16_t, std::unique_ptr<
                                                                     s5_tcp_proxy_server::negotiate_context_t>>
                                                      {
                                                          std::scoped_lock lock(tcp_mapper_lock_);

                                                          if (const auto it = tcp_mapper_.find(port); it != tcp_mapper_.
                                                              end())
                                                          {
                                                              NETLIB_LOG(log_level::info,
                                                                        "TCP Redirect entry was found for the {} : {} is {} : {}",
                                                                        address, port, net::ip_address_v4{it->second.ip}, it->second.port);

                                                              auto remote_address = it->second.ip;
                                                              auto remote_port = it->second.port;

                                                              tcp_mapper_.erase(it);

                                                              return std::make_tuple(endpoint.ip, endpoint.port,
                                                                  std::make_unique<
                                                                      s5_tcp_proxy_server::negotiate_context_t>(
                                                                      remote_address, remote_port,
                                                                      cred_pair
                                                                          ? std::optional(cred_pair.value().first)
                                                                          : std::nullopt,
                                                                      cred_pair
                                                                          ? std::optional(cred_pair.value().second)
                                                                          : std::nullopt));
                                                          }

                                                          return std::make_tuple(net::ip_address_v4{}, 0, nullptr);
                                                      }, log_level_, log_stream_)
                                                  : nullptr;

                auto socks_udp_proxy_server = (protocols == both || protocols == udp)
                                                  ? std::make_unique<s5_udp_proxy_server>(
                                                      0, io_port_, [this, endpoint = proxy_endpoint.value(), cred_pair](
                                                      const net::ip_address_v4 address, const uint16_t port)->
                                                      std::tuple<net::ip_address_v4, uint16_t, std::unique_ptr<
                                                                     s5_udp_proxy_server::negotiate_context_t>>
                                                      {
                                                          std::scoped_lock lock(udp_mapper_lock_);

                                                          if (const auto it = udp_mapper_.find(port); it != udp_mapper_.
                                                              end())
                                                          {
                                                              NETLIB_LOG(log_level::info,
                                                                        "UDP Redirect entry was found for the {} : {}",
                                                                        address, port);

                                                              udp_mapper_.erase(it);

                                                              return std::make_tuple(endpoint.ip, endpoint.port,
                                                                  std::make_unique<
                                                                      s5_udp_proxy_server::negotiate_context_t>(
                                                                      net::ip_address_v4{}, 0,
                                                                      cred_pair
                                                                          ? std::optional(cred_pair.value().first)
                                                                          : std::nullopt,
                                                                      cred_pair
                                                                          ? std::optional(cred_pair.value().second)
                                                                          : std::nullopt));
                                                          }

                                                          return std::make_tuple(net::ip_address_v4{}, 0, nullptr);
                                                      }, log_level_, log_stream_)
                                                  : nullptr;

                if (start) // optionally start proxies
                {
                    // If successful in starting the servers, log the local listening ports
                    if (socks_tcp_proxy_server)
                    {
                        if (!socks_tcp_proxy_server->start())
                        {
                            NETLIB_LOG(log_level::error, "Failed to start TCP SOCKS5 proxy {}", endpoint);
                            return {};
                        }

                        NETLIB_LOG(log_level::info,
                                  "Local TCP proxy for {} is listening port: {}", endpoint, socks_tcp_proxy_server->proxy_port());
                    }

                    if (socks_udp_proxy_server)
                    {
                        if (!socks_udp_proxy_server->start())
                        {
                            NETLIB_LOG(log_level::error, "Failed to start UDP SOCKS5 proxy {}", endpoint);
                            return {};
                        }

                        NETLIB_LOG(log_level::info,
                                  "Local UDP proxy for {} is listening port: {}", endpoint, socks_udp_proxy_server->proxy_port());
                    }
                }

                // Lock the mutex to safely add the proxy servers to the shared data structure
                std::scoped_lock lock(lock_);

                proxy_servers_.emplace_back(
                    std::move(socks_tcp_proxy_server), std::move(socks_udp_proxy_server));

                return proxy_servers_.size() - 1; // Return the index of the added proxy server
            }
            catch (const std::exception& e)
            {
                NETLIB_LOG(log_level::error, "An exception was thrown while adding SOCKS5 proxy {} : {}",
                          endpoint, e.what());
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
            std::scoped_lock lock(lock_);

            // Check if the provided proxy ID is within the range of available proxies
            if (proxy_id >= proxy_servers_.size())
            {
                NETLIB_LOG(log_level::error,
                    "associate_process_name_to_proxy: proxy index is out of range!");
                return false; // Return false since the proxy_id is out of range
            }

            try
            {
                // Associate the given process name to the specified proxy ID.
                proxy_to_names_.emplace(proxy_id, to_upper(process_name));
            }
            catch (const std::exception& e) {
                NETLIB_LOG(log_level::error, "Exception associating process name to proxy: {}", e.what());
                return false; // Return false if any exception occurs during the association
            }
            catch (...) {
                NETLIB_LOG(log_level::error, "Unknown exception associating process name to proxy.");
                return false;
            }

            return true; // Return true to indicate the association was successful
        }

        /**
         * @brief Adds a process name to the exclusion list. This function is thread-safe.
         * @param excluded_entry the name of the process to exclude
         * @return True if exclusion was successful, otherwise false
         */
        bool exclude_process_name(const std::wstring& excluded_entry) noexcept
        {
            // The lock_guard makes this function thread-safe against other operations using `lock_`.
            std::scoped_lock lock(lock_);

            try
            {
                // Append the excluded entry
                excluded_list_.push_back(to_upper(excluded_entry));
            }
            catch (const std::exception& e) {
                NETLIB_LOG(log_level::error, "Exception excluding process name: {}", e.what());
                return false;
            }
            catch (...) {
                NETLIB_LOG(log_level::error, "Unknown exception excluding process name.");
                return false;
            }

            return true;
        }

        /**
         * Parses a string to construct a network endpoint, consisting of an IPv4 address and a port number.
         * The format of the string is expected to be "IP:PORT".
         * @param endpoint The string representation of the network endpoint.
         * @return A std::optional containing a net::ip_endpoint<net::ip_address_v4> object if parsing is successful,
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
         * @brief Matches an application name pattern against the process details with exclusion support.
         *
         * This function performs a two-stage matching process:
         * 1. First, it checks if the process should be excluded based on the exclusion list
         * 2. Then, it performs pattern matching if the process is not excluded
         *
         * For both exclusion checking and pattern matching, the function uses intelligent field selection:
         * - If the pattern/exclusion entry contains path separators ("/" or "\\"), it matches against the process's full path_name
         * - If the pattern/exclusion entry contains no path separators, it matches against the process's name only
         *
         * The pattern matching is performed case-insensitively using substring matching.
         * The function automatically excludes the current process (by process ID) to prevent self-matching.
         *
         * @param app The application name or pattern to check against the process details.
         *            Can be either a simple process name (e.g., "notepad.exe") or a path-based pattern (e.g., "C:\\Windows\\System32\\notepad.exe").
         * @param process The process details to check against the application pattern.
         *                Must contain valid name and path_name fields for comparison.
         * @return true if the process details match the application pattern and are not in the exclusion list,
         *              and are not the current process; false otherwise.
         *
         * @note This function does not perform caching. Caching is handled at a higher level by the
         *       get_proxy_port_tcp() and get_proxy_port_udp() functions using process_to_proxy_cache_.
         *
         * @note The function performs direct string matching without regex support. All comparisons
         *       are case-sensitive as input is already converted to uppercase by calling functions.
         */
        bool match_app_name(const std::wstring& app, const std::shared_ptr<iphelper::network_process>& process) const
        {
            if (!process) return false;

            // Exclude the current process by process ID (not cached since it's a quick check)
            if (process->id == ::GetCurrentProcessId())
                return false;

            // Check exclusion list
            for (const auto& excluded_entry : excluded_list_) {
                if ((excluded_entry.find(L'\\') != std::wstring::npos || excluded_entry.find(L'/') != std::wstring::npos)
                    ? (process->path_name.find(excluded_entry) != std::wstring::npos)
                    : (process->name.find(excluded_entry) != std::wstring::npos)
                    ) {
                    process->excluded = true;
                    return false; // Excluded
                }
            }

            return (app.find(L'\\') != std::wstring::npos || app.find(L'/') != std::wstring::npos)
                    ? (process->path_name.find(app) != std::wstring::npos)
                    : (process->name.find(app) != std::wstring::npos);
        }

        /**
         * Retrieves the TCP proxy port number associated with a given process name.
         * @param process The pointer to network_process.
         * @return A std::optional containing the TCP port number if the process name is found,
         *         or an empty std::optional otherwise.
         */
        std::optional<uint16_t> get_proxy_port_tcp(const std::shared_ptr<iphelper::network_process>& process)
        {
            if (!process) return {};

            std::shared_lock lock(lock_);

            for (const auto& [proxy_id, process_pattern] : proxy_to_names_)
            {
                if (match_app_name(process_pattern, process))
                {
                    return proxy_servers_[proxy_id].first
                        ? std::optional(proxy_servers_[proxy_id].first->proxy_port())
                        : std::nullopt;
                }
            }

            return {};
        }

        /**
         * Retrieves the UDP proxy port number associated with a given process name.
         * @param process The pointer to network_process.
         * @return A std::optional containing the UDP port number if the process name is found,
         *         or an empty std::optional otherwise.
         */
        std::optional<uint16_t> get_proxy_port_udp(const std::shared_ptr<iphelper::network_process>& process)
        {
            if (!process) return {};

            std::shared_lock lock(lock_);

            // Search for a matching process pattern
            for (const auto& [proxy_id, process_pattern] : proxy_to_names_)
            {
                if (match_app_name(process_pattern, process))
                {
                    return proxy_servers_[proxy_id].second
                        ? std::optional(proxy_servers_[proxy_id].second->proxy_port())
                        : std::nullopt;
                }
            }

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
         * @brief Processes a UDP packet for possible redirection through a proxy.
         *
         * This function inspects the provided intermediate_buffer, attempts to resolve the associated process,
         * and determines if the UDP packet should be redirected to a proxy port, passed through, or reverted.
         * If the process cannot be resolved and @p postponed is false, the function returns std::nullopt,
         * indicating that the packet should be queued for later processing. If @p postponed is true, a
         * second attempt is made to resolve the process using an updated process table.
         *
         * If the process is associated with a UDP proxy, and the packet is from a new endpoint, the source
         * port is recorded and a redirection is logged. The function then attempts to process the packet for
         * client-to-server redirection. If the packet is from a known proxy port, it attempts to process it
         * for server-to-client redirection.
         *
         * @param buffer Reference to the intermediate_buffer containing the packet data.
         * @param postponed If false, only the current process table is used for lookup. If true, the process
         *        table is refreshed and a second lookup is attempted.
         * @return std::optional<packet_filter::packet_action> indicating the action to take:
         *         - std::nullopt: process could not be resolved (should be queued for later)
         *         - packet_action::revert: packet should be reverted (redirected)
         *         - packet_action::pass: packet should be passed through
         */
        std::optional<packet_filter::packet_action> process_udp_packet(ndisapi::intermediate_buffer& buffer, const bool postponed)
        {
            auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);
            auto* const ip_header = reinterpret_cast<iphdr_ptr>(ethernet_header + 1);
            const auto* const udp_header = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header)
                + sizeof(DWORD) * ip_header->ip_hl);

            // If the destination port is 53 (DNS), allow the packet to pass through without redirection
            // TODO: We might consider adding a DNS proxy in the future
            if (ntohs(udp_header->th_dport) == 53)
            {
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
            }

            // If the packet is from a known proxy port, process for server-to-client redirection
            if (is_udp_proxy_port(ntohs(udp_header->th_sport)))
            {
                if (udp_redirect_->process_server_to_client_packet(buffer))
                {
                    log_packet_to_pcap(buffer);
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::revert };
                }
            }

            auto process = process_lookup_v4_.
                lookup_process_for_udp<false>(net::ip_endpoint<net::ip_address_v4>{
                ip_header->ip_src, ntohs(udp_header->th_sport)
            });

            if (!process)
            {
                if (postponed)
                {
                    process = process_lookup_v4_.
                        lookup_process_for_udp<true>(net::ip_endpoint<net::ip_address_v4>{
                        ip_header->ip_src, ntohs(udp_header->th_sport)
                    });
                }
                else
                {
                    return std::nullopt;
                }
            }

            if (process->excluded || process->bypass_udp)
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };

            if (const auto port = process->udp_proxy_port ? process->udp_proxy_port : get_proxy_port_udp(process); port.has_value())
            {
                if (udp_redirect_->is_new_endpoint(buffer))
                {
                    std::scoped_lock lock(udp_mapper_lock_);
                    udp_mapper_.insert(ntohs(udp_header->th_sport));

                    NETLIB_LOG(log_level::info,
                        "Redirecting UDP {} : {} -> {} : {}",
                        net::ip_address_v4(ip_header->ip_src), ntohs(udp_header->th_sport),
                        net::ip_address_v4(ip_header->ip_dst), ntohs(udp_header->th_dport));
                }

                if (udp_redirect_->process_client_to_server_packet(buffer, htons(port.value())))
                {
                    log_packet_to_pcap(buffer);
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::revert };
                }

            }
            else
            {
                process->bypass_udp = true;
            }

            return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
        }

        /**
         * @brief Processes a TCP packet for possible redirection through a proxy.
         *
         * This function inspects the provided intermediate_buffer, attempts to resolve the associated process,
         * and determines if the TCP packet should be redirected to a proxy port, passed through, or reverted.
         * If the process cannot be resolved and @p postponed is false, the function returns std::nullopt,
         * indicating that the packet should be queued for later processing. If @p postponed is true, a
         * second attempt is made to resolve the process using an updated process table.
         *
         * If the process is associated with a TCP proxy, and the packet is a SYN (connection initiation),
         * the source port is mapped to the destination endpoint and a redirection is logged. The function
         * then attempts to process the packet for client-to-server redirection. If the packet is from a
         * known proxy port, it attempts to process it for server-to-client redirection.
         *
         * @param buffer Reference to the intermediate_buffer containing the packet data.
         * @param postponed If false, only the current process table is used for lookup. If true, the process
         *        table is refreshed and a second lookup is attempted.
         * @return std::optional<packet_filter::packet_action> indicating the action to take:
         *         - std::nullopt: process could not be resolved (should be queued for later)
         *         - packet_action::revert: packet should be reverted (redirected)
         *         - packet_action::pass: packet should be passed through
         */
        std::optional<packet_filter::packet_action> process_tcp_packet(ndisapi::intermediate_buffer& buffer, const bool postponed)
        {
            auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);
            auto* const ip_header = reinterpret_cast<iphdr_ptr>(ethernet_header + 1);
            const auto* const tcp_header = reinterpret_cast<tcphdr_ptr>(reinterpret_cast<PUCHAR>(
                ip_header) +
                sizeof(DWORD) * ip_header->ip_hl);

            // If the packet is from a known proxy port, process for server-to-client redirection
            if (is_tcp_proxy_port(ntohs(tcp_header->th_sport)))
            {
                if (tcp_redirect_->process_server_to_client_packet(buffer))
                {
                    log_packet_to_pcap(buffer);
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::revert };
                }
            }

            auto process = process_lookup_v4_.
                lookup_process_for_tcp<false>(net::ip_session<net::ip_address_v4>{
                ip_header->ip_src, ip_header->ip_dst, ntohs(tcp_header->th_sport),
                    ntohs(tcp_header->th_dport)
            });

            if (!process)
            {
                if (postponed)
                {
                    process = process_lookup_v4_.
                        lookup_process_for_tcp<true>(net::ip_session<net::ip_address_v4>{
                        ip_header->ip_src, ip_header->ip_dst, ntohs(tcp_header->th_sport),
                            ntohs(tcp_header->th_dport)
                    });
                }
                else
                {
                    return std::nullopt;
                }
            }

            if (process->excluded || process->bypass_tcp)
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };

            if (const auto port = process->tcp_proxy_port ? process->tcp_proxy_port : get_proxy_port_tcp(process); port.has_value())
            {
                // If this is a SYN packet (connection initiation), map the source port to the destination endpoint
                if ((tcp_header->th_flags & (TH_SYN | TH_ACK)) == TH_SYN)
                {
                    std::scoped_lock lock(tcp_mapper_lock_);
                    tcp_mapper_[ntohs(tcp_header->th_sport)] =
                        net::ip_endpoint(net::ip_address_v4(ip_header->ip_dst),
                            ntohs(tcp_header->th_dport));

                    NETLIB_LOG(log_level::info,
                        "Redirecting TCP: {} : {} -> {} : {}",
                        net::ip_address_v4(ip_header->ip_src), ntohs(tcp_header->th_sport),
                        net::ip_address_v4(ip_header->ip_dst), ntohs(tcp_header->th_dport));
                }

                // Attempt to process the packet for client-to-server redirection
                if (tcp_redirect_->process_client_to_server_packet(buffer, htons(port.value())))
                {
                    log_packet_to_pcap(buffer);
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::revert };
                }
            }
            else
            {
                process->bypass_tcp = true;
            }

            // Otherwise, pass the packet through
            return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
        }

        /**
         * @brief Logs a single packet to the pcap logger.
         *
         * This function logs a single packet to the pcap logger if it is available.
         *
         * @param packet The packet to be logged.
         */
        void log_packet_to_pcap(const INTERMEDIATE_BUFFER& packet) {
            if (pcap_logger_) {
                pcap_logger_.value() << packet;
            }
        }

        /**
         * @brief Sends a queue of packets to the network adapters.
         *
         * This method takes a vector of intermediate_buffer pointers and sends them to the network adapters
         * using the underlying packet filter. The packets are sent unsorted, and the number of successfully
         * sent packets is tracked internally.
         *
         * @param packet_queue Reference to a vector of intermediate_buffer pointers to be sent.
         * @return true if the packets were successfully sent to the adapters, false otherwise.
         */
        bool send_packets_to_adapters(std::vector<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr>& packet_queue) const
        {
            DWORD packets_success = 0;
            return packet_filter_->SendPacketsToAdaptersUnsorted(
                reinterpret_cast<PINTERMEDIATE_BUFFER*>(packet_queue.data()),
                static_cast<DWORD>(packet_queue.size()),
                &packets_success
            );
        }

        /**
         * @brief Sends a queue of packets to the Microsoft TCP/IP stack (MSTCP).
         *
         * This method takes a vector of intermediate_buffer pointers and sends them to the MSTCP stack
         * using the underlying packet filter. The packets are sent unsorted, and the number of successfully
         * sent packets is tracked internally.
         *
         * @param packet_queue Reference to a vector of intermediate_buffer pointers to be sent.
         * @return true if the packets were successfully sent to MSTCP, false otherwise.
         */
        bool send_packets_to_mstcp(std::vector<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr>& packet_queue) const
        {
            DWORD packets_success = 0;
            return packet_filter_->SendPacketsToMstcpUnsorted(
                reinterpret_cast<PINTERMEDIATE_BUFFER*>(packet_queue.data()),
                static_cast<DWORD>(packet_queue.size()),
                &packets_success
            );
        }

        /**
        * @brief Thread procedure for deferred process resolution and packet forwarding.
        *
        * This method runs in a dedicated thread and is responsible for processing packets
        * that could not be immediately associated with a process. It waits for packets to
        * appear in the process_resolve_buffer_queue_, then attempts to resolve the process
        * information using an updated process table. Based on the result of the resolution
        * and packet inspection, packets are either sent to network adapters, sent to the
        * Microsoft TCP/IP stack, or dropped. The method ensures thread safety and efficient
        * processing by using local queues and minimizing lock contention.
        *
        * The main steps are:
        * 1. Wait for packets to be queued or for the router to become inactive.
        * 2. Swap the shared queue with a local queue for processing.
        * 3. Refresh the process lookup table.
        * 4. For each packet, attempt to resolve the process and determine the appropriate
        *    action (pass to adapter, revert to MSTCP, or assert on unexpected cases).
        * 5. Send processed packets to their respective destinations and clear local queues.
        *
        * The thread exits when the router is deactivated and the queue is empty.
        */
        void process_resolve_thread_proc()
        {
            // Use local (non-static) containers to avoid static initialization order issues and data races
            std::queue<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr> local_queue;
            std::vector<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr> to_adapters;
            std::vector<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr> to_mstcp;

            while (is_active_.load())
            {
                {
                    std::unique_lock lock(process_resolve_buffer_mutex_);
                    process_resolve_buffer_queue_cv_.wait(lock, [this] {
                        return !process_resolve_buffer_queue_.empty() || !is_active_.load();
                        });

                    if (!is_active_.load() && process_resolve_buffer_queue_.empty())
                        break;

                    // Swap the contents of the shared queue with the local queue
                    std::swap(process_resolve_buffer_queue_, local_queue);
                }

                // Actualize process lookup before processing
                process_lookup_v4_.actualize(true, true);

                while (!local_queue.empty())
                {
                    auto buffer_ptr = std::move(local_queue.front());
                    local_queue.pop();

                    auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer_ptr->m_IBuffer);

                    if (const auto* const ip_header = reinterpret_cast<iphdr_ptr>(ethernet_header + 1);
                        ip_header->ip_p == IPPROTO_UDP)
                    {
                        if (const auto result = process_udp_packet(*buffer_ptr, true);
                            result && result->action == packet_filter::packet_action::action_type::pass)
                        {
                            to_adapters.push_back(std::move(buffer_ptr));
                        }
                        else if (result && result->action == packet_filter::packet_action::action_type::revert)
                        {
                            to_mstcp.push_back(std::move(buffer_ptr));
                        }
                        else
                        {
                            // Should always have a result for postponed packets
                            assert(false && "process_udp_packet should always return a result for postponed packets");
                        }
                    }
                    else if (ip_header->ip_p == IPPROTO_TCP)
                    {
                        if (const auto result = process_tcp_packet(*buffer_ptr, true);
                            result && result->action == packet_filter::packet_action::action_type::pass)
                        {
                            to_adapters.push_back(std::move(buffer_ptr));
                        }
                        else if (result && result->action == packet_filter::packet_action::action_type::revert)
                        {
                            to_mstcp.push_back(std::move(buffer_ptr));
                        }
                        else
                        {
                            // Should always have a result for postponed packets
                            assert(false && "process_tcp_packet should always return a result for postponed packets");
                        }
                    }
                    else
                    {
                        // Only TCP/UDP packets should be queued for deferred processing
                        assert(false && "Only TCP/UDP packets should be queued for deferred processing");
                    }
                }

                if (!to_adapters.empty())
                {
                    send_packets_to_adapters(to_adapters);
                    to_adapters.clear();
                }

                if (!to_mstcp.empty())
                {
                    send_packets_to_mstcp(to_mstcp);
                    to_mstcp.clear();
                }
            }
        }

        /**
         * @brief Callback function that is called when the IP interface changes.
         *
         * This function is triggered by changes in the network configuration and
         * updates the network configuration accordingly.
         *
         * @param row Pointer to the MIB_IPINTERFACE_ROW structure that contains
         *            information about the IP interface that changed.
         * @param notification_type The type of notification that triggered the callback.
         */
        void ip_interface_changed_callback([[maybe_unused]] PMIB_IPINTERFACE_ROW row, [[maybe_unused]] MIB_NOTIFICATION_TYPE notification_type)
        {
            NETLIB_LOG(log_level::debug, "Network configuration has changed.");
            update_network_configuration();
        }

        /**
         * @brief Updates the network configuration by filtering or unfiltering network adapters.
         *
         * This function retrieves the list of network adapters and external network connections,
         * determines which adapters need to be filtered, and applies the appropriate filters.
         */
        void update_network_configuration()
        {
            const auto ndis_adapters = packet_filter_->get_interface_list();
            const auto configured_interfaces = iphelper::network_adapter_info::get_external_network_connections();
            std::unordered_set<std::string> adapters_to_filter;

            for (const auto& adapter : configured_interfaces)
            {
                if (adapter.get_if_type() != IF_TYPE_PPP)
                {
                    if (const auto it = std::ranges::find_if(ndis_adapters,
                        [&adapter](const auto& ndis_adapter)
                        {
                            return ndis_adapter.get_internal_name().find(adapter.get_adapter_name()) != std::string::npos;
                        }); it != ndis_adapters.end())
                    {
                        adapters_to_filter.insert(it->get_internal_name());
                    }
                }
                else
                {
                    if (const auto it = std::ranges::find_if(ndis_adapters,
                        [&adapter](const auto& ndis_adapter)
                        {
                            if (const auto wan_info = ndis_adapter.get_ras_links(); wan_info)
                            {
                                return std::any_of(wan_info->begin(), wan_info->end(),
                                    [&adapter](const auto& ras_link)
                                    {
                                        return adapter.has_address(ras_link.ip_address);
                                    });
                            }
                            return false;
                        }); it != ndis_adapters.end())
                    {
                        adapters_to_filter.insert(it->get_internal_name());
                    }
                }
            }

            {
                std::shared_lock lock(adapters_to_filter_lock_);
                if (adapters_to_filter_ == adapters_to_filter)
                    return;
            }

            for (const auto& adapter : ndis_adapters)
            {
                if (const auto& internal_name = adapter.get_internal_name(); adapters_to_filter.contains(internal_name))
                {
                    packet_filter_->filter_network_adapter(internal_name);
                    NETLIB_LOG(log_level::debug, "Filtering network interface: {}", adapter.get_friendly_name());
                }
                else
                {
                    packet_filter_->unfilter_network_adapter(internal_name);
                    NETLIB_LOG(log_level::debug, "Unfiltering network interface: {}", adapter.get_friendly_name());
                }
            }

            {
                std::unique_lock lock(adapters_to_filter_lock_);
                adapters_to_filter_ = std::move(adapters_to_filter);
            }
        }
        
        /**
        * @brief Builds and adds IPv4 pass-through filters for common local network ranges.
        *
        * The function generates inbound and outbound filters that allow traffic
        * for a predefined set of local and special-purpose IPv4 subnets and adds
        * them to the static filters list.
        *
        * Bypassed ranges:
        * - 10.0.0.0/8      (Private Class A)
        * - 172.16.0.0/12   (Private Class B)
        * - 192.168.0.0/16  (Private Class C)
        * - 224.0.0.0/4     (Multicast)
        * - 169.254.0.0/16  (Link-local / APIPA)
        */
        void add_lan_passover_filters_v4()
        {
            // List of local IPv4 address ranges (address + subnet mask)
            static constexpr std::array<std::pair<const char*, const char*>, 5> local_ranges{ {
                {"10.0.0.0",    "255.0.0.0"},      // 10.0.0.0/8 - Private Class A
                {"172.16.0.0",  "255.240.0.0"},    // 172.16.0.0/12 - Private Class B
                {"192.168.0.0", "255.255.0.0"},    // 192.168.0.0/16 - Private Class C
                {"224.0.0.0",   "240.0.0.0"},      // 224.0.0.0/4 - Multicast (224.0.0.0 - 239.255.255.255)
                {"169.254.0.0", "255.255.0.0"}     // 169.254.0.0/16 - Link-local (APIPA)
            } };

            // Helper to construct an IPv4 subnet object from string literals
            const auto to_subnet = [](const char* address, const char* mask) {
                return net::ip_subnet{
                    net::ip_address_v4{address},
                    net::ip_address_v4{mask}
                };
                };

            for (const auto& [address, mask] : local_ranges) {
                const auto subnet = to_subnet(address, mask);

                // Allow inbound traffic originating from the local subnet
                ndisapi::filter<net::ip_address_v4> in_filter;
                in_filter
                    .set_direction(ndisapi::direction_t::in)
                    .set_action(ndisapi::action_t::pass)
                    .set_source_address(subnet);
                static_filters_.add_filter_front(in_filter);

                // Allow outbound traffic destined to the local subnet
                ndisapi::filter<net::ip_address_v4> out_filter;
                out_filter
                    .set_direction(ndisapi::direction_t::out)
                    .set_action(ndisapi::action_t::pass)
                    .set_dest_address(subnet);
                static_filters_.add_filter_front(out_filter);
            }

            NETLIB_LOG(log_level::info, "LAN bypass enabled - local network traffic will not be proxied");
        }
    };
}
