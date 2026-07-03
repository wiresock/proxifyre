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
         * @brief Type alias for the SOCKS5 TCP proxy server specialized for IPv6.
         */
        using s5_tcp_proxy_server_v6 = tcp_proxy_server<socks5_tcp_proxy_socket<net::ip_address_v6>>;

        /**
         * @brief Type alias for the SOCKS5 UDP proxy server specialized for IPv6.
         */
        using s5_udp_proxy_server_v6 = socks5_local_udp_proxy_server<socks5_udp_proxy_socket<net::ip_address_v6>>;

        /**
         * @brief Entry stored in the TCP source-port mappers: redirected destination
         *        endpoint and the steady-clock timestamp at which the mapping was
         *        created. The timestamp is used by process_resolve_thread_proc to evict
         *        stale entries whose SYN never produced a local proxy connection
         *        (e.g. RST/timeout). Templated on the address family so the IPv4 and
         *        IPv6 mappers share a single definition.
         */
        template <typename AddrT>
        struct tcp_mapper_entry_t
        {
            net::ip_endpoint<AddrT> endpoint;
            std::chrono::steady_clock::time_point created_at;
        };

        using tcp_mapper_entry = tcp_mapper_entry_t<net::ip_address_v4>;
        using tcp_mapper_entry_v6 = tcp_mapper_entry_t<net::ip_address_v6>;

        /**
         * @brief Stores a mapping of TCP source ports to their original destination
         *        endpoints, stamped with the time the entry was created so stale
         *        entries can be aged out. Separate maps are kept per address family
         *        because IPv4 and IPv6 connections may reuse the same source port
         *        value independently.
         */
        std::unordered_map<uint16_t, tcp_mapper_entry> tcp_mapper_;
        std::unordered_map<uint16_t, tcp_mapper_entry_v6> tcp_mapper_v6_;

        /**
         * @brief Maximum age for a tcp_mapper_ entry before it is considered stale and
         *        evicted by the resolve thread. SYN packets that never reach the local
         *        SOCKS5 server (e.g. RST'd, dropped, app gave up) would otherwise leak
         *        entries indefinitely.
         */
        static constexpr std::chrono::seconds tcp_mapper_entry_ttl_{ 30 };

        /**
         * @brief Maximum number of packets that may be queued for deferred process
         *        resolution before new packets are dropped. Bounds memory growth of
         *        process_resolve_buffer_queue_ (and therefore the intermediate buffer
         *        pool) when the single-threaded resolver cannot keep up with the
         *        incoming packet rate.
         */
        static constexpr std::size_t max_resolve_queue_depth_ = 2048;

        /**
         * @brief Minimum interval between consecutive drop-counter warning logs from
         *        the resolver thread. The cumulative dropped count is preserved
         *        between emissions, so no information is lost — only the log rate
         *        is throttled to avoid flooding under sustained overload where
         *        resolver drain cycles can fire many times per second.
         */
        static constexpr std::chrono::seconds drop_log_throttle_interval_{ 5 };

        /**
         * @brief Cumulative count of TCP/UDP packets dropped because
         *        process_resolve_buffer_queue_ was full. Sampled and logged at a
         *        coarse rate from the resolver thread to avoid log floods under
         *        sustained overload.
         */
        std::atomic<std::uint64_t> resolve_queue_dropped_packets_{ 0 };

        /**
         * @brief Cumulative count of TCP/UDP packets dropped because the intermediate
         *        buffer pool failed to allocate. Reported alongside
         *        resolve_queue_dropped_packets_ via the same time-throttled log path
         *        in the resolver thread, avoiding a per-failure log line under
         *        memory pressure.
         */
        std::atomic<std::uint64_t> resolve_queue_alloc_failures_{ 0 };

        /**
         * @brief Stores the set of UDP ports being mapped.
         */
        std::unordered_set<uint16_t> udp_mapper_;
        std::unordered_set<uint16_t> udp_mapper_v6_;

        /**
         * @brief Mutex to synchronize access to the TCP port mapping.
         */
        std::mutex tcp_mapper_lock_;
        std::mutex tcp_mapper_v6_lock_;

        /**
         * @brief Mutex to synchronize access to the UDP port mapping.
         */
        std::mutex udp_mapper_lock_;
        std::mutex udp_mapper_v6_lock_;

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
         * @brief IPv6 counterpart of proxy_servers_. Kept index-aligned with
         *        proxy_servers_ (add_socks5_proxy() always appends to both), so a
         *        proxy index resolved from proxy_to_names_ selects the matching
         *        IPv4 and IPv6 proxy pair.
         */
        std::vector<std::pair<std::unique_ptr<s5_tcp_proxy_server_v6>, std::unique_ptr<s5_udp_proxy_server_v6>>> proxy_servers_v6_;

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
         * @brief Serializes lifecycle operations (start(), stop(), and
         * add_socks5_proxy()) so that proxies cannot be created/started
         * concurrently with start()/stop() bookkeeping. Without this guard,
         * a proxy added via add_socks5_proxy() could slip into proxy_servers_
         * after a start() failure-cleanup snapshot is captured but before the
         * stop loop runs, leaving a started proxy that the cleanup misses.
         * This mutex is intentionally NOT held by the resolver thread or by
         * proxy cleanup threads, so it does not introduce new deadlock paths
         * with the existing lock_ ordering.
         */
        std::mutex lifecycle_mutex_;

        /**
         * @brief Unique pointer to the TCP redirect object.
         */
        std::unique_ptr<ndisapi::tcp_local_redirect<net::ip_address_v4>> tcp_redirect_{ nullptr };

        /**
         * @brief Unique pointer to the IPv6 TCP redirect object.
         */
        std::unique_ptr<ndisapi::tcp_local_redirect<net::ip_address_v6>> tcp_redirect_v6_{ nullptr };

        /**
         * @brief Unique pointer to the UDP redirect object.
         */
        std::unique_ptr<ndisapi::socks5_udp_local_redirect<net::ip_address_v4>> udp_redirect_{ nullptr };

        /**
         * @brief Unique pointer to the IPv6 UDP redirect object.
         */
        std::unique_ptr<ndisapi::socks5_udp_local_redirect<net::ip_address_v6>> udp_redirect_v6_{ nullptr };

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

        /**
         * @brief Atomic flag that signals the deferred-resolve thread to exit.
         *
         * Set to true only after the packet filter has been fully stopped (so no
         * more enqueue_for_deferred_resolve calls can race the resolver thread's
         * exit decision). Kept distinct from is_active_ because stop() clears
         * is_active_ before stopping the packet filter, and the packet handler
         * thread can therefore still produce queued buffers while is_active_ is
         * already false. Gating the resolver's shutdown break on this flag (and
         * not on is_active_) ensures any buffers enqueued before stop_filter()
         * returns are still drained.
         */
        std::atomic_bool resolver_should_exit_{ false };

        /**
         * @brief Enqueues a TCP/UDP packet for deferred process resolution, dropping
         *        it if process_resolve_buffer_queue_ is already at capacity.
         *
         * Bounding the queue is what keeps the intermediate buffer pool's high-water
         * mark finite when the resolver thread cannot keep up with the incoming
         * packet rate. The capacity check is performed under
         * process_resolve_buffer_mutex_ before allocating from the pool so an
         * overload condition does not produce unnecessary buffer-pool churn.
         * The queued_multi_interface_packet_filter callback path drives this
         * function from a single packet processing thread, so the size check
         * and subsequent push are not racing other filter callbacks; the
         * implementation does not rely on exceeding max_resolve_queue_depth_
         * to remain bounded under concurrency.
         *
         * Defined in the private section above the constructor so its declaration
         * is in scope for the packet_filter callback lambda constructed in the
         * constructor body, regardless of compiler treatment of complete-class
         * context for member name lookup inside lambdas.
         *
         * @param buffer The intermediate buffer describing the packet to enqueue.
         * @return Always returns a 'drop' action: the packet is either queued for
         *         later re-injection (and therefore dropped from the current pass)
         *         or dropped outright due to overload / allocation failure.
         */
        packet_filter::packet_action enqueue_for_deferred_resolve(ndisapi::intermediate_buffer& buffer)
        {
            {
                std::scoped_lock lock(process_resolve_buffer_mutex_);
                if (process_resolve_buffer_queue_.size() >= max_resolve_queue_depth_)
                {
                    // The increment occurs while holding process_resolve_buffer_mutex_
                    // so this full-queue drop path is not expected to undercount due
                    // to contention. Treat the counter as a coarse overload signal
                    // rather than precise end-to-end accounting; if the
                    // single-callback-thread assumption changes in the future, the
                    // more likely concurrency artifact would be temporary queue
                    // overshoot from the unlocked allocation window below, not
                    // missed increments in this branch.
                    resolve_queue_dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::drop };
                }
            }

            if (auto allocated_buffer = ndisapi::intermediate_buffer_pool::instance().allocate(buffer))
            {
                bool pushed = false;
                {
                    std::scoped_lock lock(process_resolve_buffer_mutex_);
                    // Re-check capacity under the lock so the depth bound is
                    // enforced strictly even if multiple producers ever drive
                    // this path concurrently in the future. The allocation
                    // window above is unlocked, so without this re-check the
                    // queue could transiently exceed max_resolve_queue_depth_.
                    if (process_resolve_buffer_queue_.size() < max_resolve_queue_depth_)
                    {
                        process_resolve_buffer_queue_.push(std::move(allocated_buffer));
                        pushed = true;
                    }
                    else
                    {
                        resolve_queue_dropped_packets_.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                if (pushed)
                    process_resolve_buffer_queue_cv_.notify_one();
                // allocated_buffer falls out of scope here and is returned to the
                // pool automatically when not pushed.
            }
            else
            {
                // Treat allocation failure as a drop and account for it via a
                // dedicated counter so it is surfaced through the resolver
                // thread's time-throttled log path. Avoids emitting a log line
                // per failure under memory pressure, which could itself flood.
                resolve_queue_alloc_failures_.fetch_add(1, std::memory_order_relaxed);

                // Wake the resolver thread even when the queue remains empty
                // so allocation-failure diagnostics are not delayed until the
                // next timed maintenance wakeup. The drop-log path itself is
                // still throttled by drop_log_throttle_interval_, so a flood
                // of failures cannot translate into a flood of log lines.
                process_resolve_buffer_queue_cv_.notify_one();
            }
            return packet_filter::packet_action{ packet_filter::packet_action::action_type::drop };
        }

        /**
         * @brief Compile-time selectors that return the TCP/UDP source-port mapper
         *        (and its lock) for the requested address family. They let the
         *        family-generic helpers (build_proxy_pair, process_*_packet_v6)
         *        reference the correct member without duplicating their bodies.
         */
        template <typename AddrT>
        auto& tcp_mapper_for() noexcept
        {
            if constexpr (std::is_same_v<AddrT, net::ip_address_v4>)
                return tcp_mapper_;
            else
                return tcp_mapper_v6_;
        }

        template <typename AddrT>
        std::mutex& tcp_mapper_lock_for() noexcept
        {
            if constexpr (std::is_same_v<AddrT, net::ip_address_v4>)
                return tcp_mapper_lock_;
            else
                return tcp_mapper_v6_lock_;
        }

        template <typename AddrT>
        auto& udp_mapper_for() noexcept
        {
            if constexpr (std::is_same_v<AddrT, net::ip_address_v4>)
                return udp_mapper_;
            else
                return udp_mapper_v6_;
        }

        template <typename AddrT>
        std::mutex& udp_mapper_lock_for() noexcept
        {
            if constexpr (std::is_same_v<AddrT, net::ip_address_v4>)
                return udp_mapper_lock_;
            else
                return udp_mapper_v6_lock_;
        }

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

            // Test the MEMBER, not the constructor parameter: pcap_log_stream was moved-from into
            // pcap_log_stream_ on the initializer list above, so `if (pcap_log_stream)` was always
            // false and pcap logging was silently never enabled.
            if (pcap_log_stream_) {
                pcap_logger_.emplace(*pcap_log_stream_);
            }

            // Initialize TCP and UDP redirect objects
            tcp_redirect_ = std::make_unique<ndisapi::tcp_local_redirect<net::ip_address_v4>>(log_level_, log_stream);
            udp_redirect_ = std::make_unique<ndisapi::socks5_udp_local_redirect<net::ip_address_v4>>(
                log_level_, log_stream);

            // Initialize the IPv6 redirect objects. The lower redirect/proxy stack is
            // fully dual-stack (templated + if constexpr), so the IPv6 path mirrors the
            // IPv4 one: redirected IPv6 TCP/UDP egress is NAT'd to the local IPv6 proxy
            // listeners instead of leaking out unproxied.
            tcp_redirect_v6_ = std::make_unique<ndisapi::tcp_local_redirect<net::ip_address_v6>>(log_level_, log_stream);
            udp_redirect_v6_ = std::make_unique<ndisapi::socks5_udp_local_redirect<net::ip_address_v6>>(
                log_level_, log_stream);

            // Initialize packet filter
            packet_filter_ = std::make_unique<packet_filter>(
                nullptr,
                [this](HANDLE, ndisapi::intermediate_buffer& buffer)
                {
                    auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);
                    const auto destination_mac = net::mac_address(ethernet_header->h_dest);
                    const auto ether_type = ntohs(ethernet_header->h_proto);

                    // IPv6 traffic from proxied apps would otherwise leave the machine
                    // unproxied; route it through the parallel IPv6 path.
                    if (ether_type == ETH_P_IPV6)
                    {
                        return handle_ipv6_filter(buffer, destination_mac);
                    }

                    if (ether_type != ETH_P_IP)
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
                        return enqueue_for_deferred_resolve(buffer);
                    }

                    if (ip_header->ip_p == IPPROTO_TCP)
                    {
                        if (const auto result = process_tcp_packet(buffer, false))
                        {
                            return result.value();
                        }
                        return enqueue_for_deferred_resolve(buffer);
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
        /**
         * @brief Rolls back a partially- or fully-started router. Used by both the packet-filter
         *        start-failure path and start()'s exception handler. Safe on partial state: proxy
         *        stop() and stop_thread_pool() are idempotent and the resolver join is guarded by
         *        joinable(). Proxies are stopped OUTSIDE lock_ (proxy cleanup threads may contend
         *        for the same mutex, so holding lock_ across a stop() can deadlock).
         */
        void start_failure_cleanup()
        {
            if (!this->cancel_notify_ip_interface_change())
            {
                NETLIB_LOG(
                    log_level::error, "cancel_notify_ip_interface_change has failed, lasterror: {}",
                    GetLastError());
            }

            std::vector<std::pair<s5_tcp_proxy_server*, s5_udp_proxy_server*>> proxies_to_stop;
            std::vector<std::pair<s5_tcp_proxy_server_v6*, s5_udp_proxy_server_v6*>> proxies_to_stop_v6;
            {
                std::shared_lock lock(lock_);
                proxies_to_stop.reserve(proxy_servers_.size());
                for (auto& [tcp, udp] : proxy_servers_)
                    proxies_to_stop.emplace_back(tcp.get(), udp.get());

                proxies_to_stop_v6.reserve(proxy_servers_v6_.size());
                for (auto& [tcp, udp] : proxy_servers_v6_)
                    proxies_to_stop_v6.emplace_back(tcp.get(), udp.get());
            }

            for (auto& [tcp, udp] : proxies_to_stop)
            {
                if (tcp) tcp->stop();
                if (udp) udp->stop();
            }

            for (auto& [tcp, udp] : proxies_to_stop_v6)
            {
                if (tcp) tcp->stop();
                if (udp) udp->stop();
            }

            io_port_.stop_thread_pool();

            is_active_.store(false);

            resolver_should_exit_.store(true);
            process_resolve_buffer_queue_cv_.notify_all();

            if (process_resolve_thread_.joinable())
                process_resolve_thread_.join();
        }

        bool start()
        {
            // Serialize lifecycle operations (start/stop/add_socks5_proxy) so
            // that a concurrent add_socks5_proxy() cannot register a started
            // proxy after the failure-cleanup snapshot has been captured.
            std::scoped_lock lifecycle_lock(lifecycle_mutex_);

            if (auto expected = false; !is_active_.compare_exchange_strong(expected, true))
            {
                NETLIB_LOG(log_level::error, "Filter is already active!");
                return false;
            }

            // Reset resolver-exit signal on every start so a previous
            // stop()/start() cycle does not leave the new resolver thread
            // pre-armed to exit. Also reset the drop/alloc-failure counters
            // so they reflect this run rather than leaking stale counts from
            // a prior stop()/start() cycle.
            resolver_should_exit_.store(false);
            resolve_queue_dropped_packets_.store(0, std::memory_order_relaxed);
            resolve_queue_alloc_failures_.store(0, std::memory_order_relaxed);

            // Exception safety: any throw after the is_active_ CAS above must not escape with
            // is_active_ still true (a half-started router that stop()/the destructor would then
            // mishandle). Wrap the whole bring-up; the catch at the end rolls back via
            // start_failure_cleanup(). Body indentation is left unchanged to keep the diff focused.
            try
            {

            if (!packet_filter_)
            {
                NETLIB_LOG(log_level::error, "Packet filter is not initialized!");
                // Roll back is_active_ so subsequent stop()/start() cycles see
                // a consistent inactive router state. The resolver thread has
                // not been started yet on this path, so resolver_should_exit_
                // does not need to be touched (it was just reset above).
                is_active_.store(false);
                return false;
            }

            if (!this->set_notify_ip_interface_change())
            {
                NETLIB_LOG(
                    log_level::error,
                    "set_notify_ip_interface_change has failed, lasterror: {}",
                    GetLastError());
            }

            // IPv6 listeners that started but whose pair partner failed are stopped AFTER
            // releasing lock_, mirroring stop()'s "never hold lock_ across a proxy stop()"
            // discipline (a proxy's teardown path may contend for shared state).
            std::vector<std::unique_ptr<s5_tcp_proxy_server_v6>> ipv6_disabled_tcp;
            std::vector<std::unique_ptr<s5_udp_proxy_server_v6>> ipv6_disabled_udp;

            {
                std::unique_lock lock(lock_);

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

                // Start the IPv6 proxies (index-aligned with proxy_servers_). IPv6
                // listeners are optional: if the OS/socket stack rejects either half
                // of the pair, disable that IPv6 slot so later packet handling falls
                // back to pass-through instead of redirecting to a dead local port.
                for (auto& [tcp, udp] : proxy_servers_v6_)
                {
                    // Disable this IPv6 slot by moving its servers out of the shared
                    // vector (which nulls the slot) so they can be stopped and destroyed
                    // after lock_ is released rather than under it.
                    const auto disable_ipv6_pair = [&]
                    {
                        if (tcp)
                            ipv6_disabled_tcp.push_back(std::move(tcp));
                        if (udp)
                            ipv6_disabled_udp.push_back(std::move(udp));
                    };

                    if (tcp)
                    {
                        if (!tcp->start())
                        {
                            NETLIB_LOG(
                                log_level::warning,
                                "IPv6 TCP proxy on port {} is disabled because it failed to start.",
                                tcp->proxy_port());
                            disable_ipv6_pair();
                            continue;
                        }
                    }

                    if (udp)
                    {
                        if (!udp->start())
                        {
                            NETLIB_LOG(
                                log_level::warning,
                                "IPv6 UDP proxy on port {} is disabled because it failed to start.",
                                udp->proxy_port());
                            disable_ipv6_pair();
                        }
                    }
                }
            }

            // Stop any disabled IPv6 listeners without holding lock_.
            for (auto& tcp : ipv6_disabled_tcp)
                if (tcp)
                    tcp->stop();
            for (auto& udp : ipv6_disabled_udp)
                if (udp)
                    udp->stop();

            process_resolve_thread_ = std::thread(&socks_local_router::process_resolve_thread_proc, this);

            // Update network configuration and start filter
            update_network_configuration();
            if (!packet_filter_->start_filter())
            {
                NETLIB_LOG(log_level::error, "Failed to start NDIS packet filter");

                // Everything this start() brought up must be torn down (the packet filter never
                // started). Shared with the exception handler below.
                start_failure_cleanup();
            }
            }
            catch (const std::exception& e)
            {
                // Any throw after the is_active_ CAS (e.g. io_port_.start_thread_pool() ->
                // std::system_error on thread-create failure, update_network_configuration() ->
                // std::bad_alloc, or std::thread construction failing) would otherwise unwind with
                // is_active_ still true, leaving a half-started router that a later stop()/destructor
                // acts on incorrectly. Roll back to a clean inactive state, then report failure.
                NETLIB_LOG(log_level::error, "Exception while starting the router: {}; rolled back", e.what());
                start_failure_cleanup();
                return false;
            }
            catch (...)
            {
                NETLIB_LOG(log_level::error, "Unknown exception while starting the router; rolled back");
                start_failure_cleanup();
                return false;
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
            // Serialize lifecycle operations (start/stop/add_socks5_proxy) so
            // that an add_socks5_proxy() cannot interleave with the teardown
            // sequence below and leave a started proxy outside the stop loop.
            std::scoped_lock lifecycle_lock(lifecycle_mutex_);

            // A flag to indicate whether the operation was active or not.
            // If the value of is_active_ was already false, this function returns false
            if (auto expected = true; !is_active_.compare_exchange_strong(expected, false))
                return false;

            // Step 1: Stop the packet filter FIRST
            // This prevents new packets from being processed and queued
            NETLIB_DEBUG("Stopping packet filter");
            packet_filter_->stop_filter();

            // Step 2: Signal and join the process resolve thread
            // This ensures no more packets are being queued for processing.
            // resolver_should_exit_ is set only AFTER stop_filter() returns
            // so the resolver thread cannot observe an exit signal while the
            // packet handler thread is still potentially enqueuing buffers,
            // which would otherwise leave them stranded in
            // process_resolve_buffer_queue_.
            NETLIB_DEBUG("Stopping process resolve thread");
            resolver_should_exit_.store(true);
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

            if (tcp_redirect_v6_)
            {
                tcp_redirect_v6_->stop();  // This should join the cleanup thread
            }

            if (udp_redirect_v6_)
            {
                udp_redirect_v6_->stop();  // This should join the cleanup thread
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

            NETLIB_DEBUG("Stopping {} IPv6 proxy pairs", proxy_servers_v6_.size());

            // Stop all IPv6 proxies without holding lock_
            for (size_t i = 0; i < proxy_servers_v6_.size(); ++i)
            {
                if (proxy_servers_v6_[i].first)
                {
                    NETLIB_DEBUG("Stopping IPv6 TCP proxy #{} on port {}", i, proxy_servers_v6_[i].first->proxy_port());
                    proxy_servers_v6_[i].first->stop();
                }

                if (proxy_servers_v6_[i].second)
                {
                    NETLIB_DEBUG("Stopping IPv6 UDP proxy #{} on port {}", i, proxy_servers_v6_[i].second->proxy_port());
                    proxy_servers_v6_[i].second->stop();
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
            add_lan_passover_filters_v6();
        }

        /**
         * Checks whether the associated driver is loaded or not.
         * @return boolean representing the load status of the driver (true if loaded, false if not).
         */
        bool is_driver_loaded() const
        {
            return packet_filter_->IsDriverLoaded();
        }

    private:
        /**
         * @brief Builds a (TCP, UDP) SOCKS5 proxy-server pair for a single address
         *        family, without starting them.
         *
         * Both the IPv4 and IPv6 paths in add_socks5_proxy() go through this single
         * templated helper so the accept-callback logic (source-port mapper lookup,
         * TTL eviction, negotiate-context construction) lives in one place. The correct
         * per-family source-port mapper is selected at compile time via the
         * *_mapper_for<AddrT>() helpers.
         *
         * @tparam AddrT net::ip_address_v4 or net::ip_address_v6.
         * @param upstream The upstream SOCKS5 server endpoint the proxy connects to.
         *        For the IPv6 instantiation this is the IPv4-mapped form of the
         *        configured endpoint, so an IPv4 SOCKS5 server keeps working over the
         *        proxy's dual-stack upstream socket.
         * @param protocols Which of TCP/UDP to create.
         * @param cred_pair Optional SOCKS5 username/password.
         * @return Pair of unique_ptrs; either element is null when its protocol is not requested.
         */
        template <typename AddrT>
        std::pair<std::unique_ptr<tcp_proxy_server<socks5_tcp_proxy_socket<AddrT>>>,
                  std::unique_ptr<socks5_local_udp_proxy_server<socks5_udp_proxy_socket<AddrT>>>>
        build_proxy_pair(const net::ip_endpoint<AddrT>& upstream,
                         const supported_protocols protocols,
                         const std::optional<std::pair<std::string, std::string>>& cred_pair)
        {
            using tcp_server_t = tcp_proxy_server<socks5_tcp_proxy_socket<AddrT>>;
            using udp_server_t = socks5_local_udp_proxy_server<socks5_udp_proxy_socket<AddrT>>;
            using tcp_negotiate_t = typename tcp_server_t::negotiate_context_t;
            using udp_negotiate_t = typename udp_server_t::negotiate_context_t;

            auto tcp_server = (protocols == both || protocols == tcp)
                ? std::make_unique<tcp_server_t>(
                    0, io_port_,
                    [this, upstream, cred_pair](const AddrT address, const uint16_t port)
                        -> std::tuple<AddrT, uint16_t, std::unique_ptr<tcp_negotiate_t>>
                    {
                        auto& mapper = tcp_mapper_for<AddrT>();
                        std::scoped_lock lock(tcp_mapper_lock_for<AddrT>());

                        if (const auto it = mapper.find(port); it != mapper.end())
                        {
                            // Discard stale entries whose age has exceeded the TTL.
                            // Eviction is performed asynchronously by the resolver
                            // thread and may be delayed, so validate age at lookup
                            // time to avoid misrouting a new connection on a reused
                            // source port.
                            if (std::chrono::steady_clock::now() - it->second.created_at > tcp_mapper_entry_ttl_)
                            {
                                NETLIB_LOG(log_level::warning,
                                    "TCP Redirect entry for port {} was stale (age exceeded TTL); discarding.",
                                    port);
                                mapper.erase(it);
                                return std::make_tuple(AddrT{}, 0, nullptr);
                            }

                            NETLIB_LOG(log_level::info,
                                "TCP Redirect entry was found for the {} : {} is {}",
                                std::string{ address }, port, it->second.endpoint.to_string());

                            auto remote_address = it->second.endpoint.ip;
                            auto remote_port = it->second.endpoint.port;

                            mapper.erase(it);

                            return std::make_tuple(upstream.ip, upstream.port,
                                std::make_unique<tcp_negotiate_t>(
                                    remote_address, remote_port,
                                    cred_pair ? std::optional(cred_pair.value().first) : std::nullopt,
                                    cred_pair ? std::optional(cred_pair.value().second) : std::nullopt));
                        }

                        return std::make_tuple(AddrT{}, 0, nullptr);
                    }, log_level_, log_stream_)
                : nullptr;

            auto udp_server = (protocols == both || protocols == udp)
                ? std::make_unique<udp_server_t>(
                    0, io_port_,
                    [this, upstream, cred_pair](const AddrT address, const uint16_t port)
                        -> std::tuple<AddrT, uint16_t, std::unique_ptr<udp_negotiate_t>>
                    {
                        auto& mapper = udp_mapper_for<AddrT>();
                        std::scoped_lock lock(udp_mapper_lock_for<AddrT>());

                        if (const auto it = mapper.find(port); it != mapper.end())
                        {
                            NETLIB_LOG(log_level::info,
                                "UDP Redirect entry was found for the {} : {}",
                                std::string{ address }, port);

                            mapper.erase(it);

                            return std::make_tuple(upstream.ip, upstream.port,
                                std::make_unique<udp_negotiate_t>(
                                    AddrT{}, 0,
                                    cred_pair ? std::optional(cred_pair.value().first) : std::nullopt,
                                    cred_pair ? std::optional(cred_pair.value().second) : std::nullopt));
                        }

                        return std::make_tuple(AddrT{}, 0, nullptr);
                    }, log_level_, log_stream_)
                : nullptr;

            return { std::move(tcp_server), std::move(udp_server) };
        }

    public:
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

            // Parse the endpoint to an IP address and port number. This may
            // perform a blocking DNS lookup via getaddrinfo, so it is
            // intentionally done OUTSIDE lifecycle_mutex_ so that a concurrent
            // start()/stop() cannot be stalled by name resolution.
            auto proxy_endpoint = parse_endpoint(endpoint);

            // If parsing failed, log the error and return nullopt
            if (!proxy_endpoint)
            {
                NETLIB_LOG(log_level::error, "Failed to parse the proxy endpoint {}", endpoint);
                return {};
            }

            // Serialize the lifecycle-state mutations (filter list, proxy
            // construction/start, and proxy_servers_ insertion) against
            // start()/stop() so that this function cannot register/start a
            // proxy concurrently with start() failure cleanup (which would
            // otherwise leave a running proxy that the cleanup snapshot of
            // proxy_servers_ has already missed) or with stop().
            std::scoped_lock lifecycle_lock(lifecycle_mutex_);

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

            // NOTE: the static PASS filters for the upstream endpoint are installed only AFTER
            // the proxy pair is successfully built and (optionally) started -- see below, just
            // before proxy_servers_ is updated. Installing them here (before build/start) leaked
            // orphaned driver filters on every failure path.

            try
            {
                // Create the IPv4 proxy-server pair first; this is the historical,
                // required path. The IPv6 pair is best-effort below so IPv4 proxy
                // registration still works on hosts where IPv6 sockets are disabled.
                auto [socks_tcp_proxy_server, socks_udp_proxy_server] =
                    build_proxy_pair<net::ip_address_v4>(proxy_endpoint.value(), protocols, cred_pair);

                std::unique_ptr<s5_tcp_proxy_server_v6> socks_tcp_proxy_server_v6;
                std::unique_ptr<s5_udp_proxy_server_v6> socks_udp_proxy_server_v6;

                try
                {
                    // The IPv6 path connects to the IPv4-mapped form of the configured
                    // upstream over a dual-stack socket, so existing IPv4 SOCKS5
                    // endpoints (e.g. 127.0.0.1:1080) keep working while IPv6
                    // destinations are proxied instead of leaking.
                    // Build the IPv4-mapped IPv6 form of the configured (IPv4) upstream
                    // directly from its octets rather than via "::ffff:" + string parsing,
                    // which would silently yield :: on a parse failure under NDEBUG.
                    in6_addr mapped_upstream{};
                    mapped_upstream.u.Byte[10] = 0xff;
                    mapped_upstream.u.Byte[11] = 0xff;
                    const in_addr upstream_v4 = proxy_endpoint.value().ip;
                    memcpy(&mapped_upstream.u.Byte[12], &upstream_v4, sizeof(upstream_v4));
                    const net::ip_endpoint<net::ip_address_v6> upstream_v6{
                        net::ip_address_v6{ mapped_upstream },
                        proxy_endpoint.value().port
                    };

                    auto proxy_pair_v6 = build_proxy_pair<net::ip_address_v6>(upstream_v6, protocols, cred_pair);
                    socks_tcp_proxy_server_v6 = std::move(proxy_pair_v6.first);
                    socks_udp_proxy_server_v6 = std::move(proxy_pair_v6.second);
                }
                catch (const std::exception& e)
                {
                    NETLIB_LOG(log_level::warning,
                        "IPv6 SOCKS5 proxy listeners for {} are disabled: {}",
                        endpoint, e.what());
                }
                catch (...)
                {
                    NETLIB_LOG(log_level::warning,
                        "IPv6 SOCKS5 proxy listeners for {} are disabled: unknown error",
                        endpoint);
                }

                if (start) // optionally start proxies
                {
                    // IPv4 listeners are required: on failure return nullopt and let
                    // the local unique_ptrs tear down (their destructors stop any listener
                    // that already started), so the add fails atomically.
                    const auto start_listener = [&endpoint, this](auto& server, const char* family,
                                                                  const char* proto) -> bool
                    {
                        if (!server)
                            return true;

                        if (!server->start())
                        {
                            NETLIB_LOG(log_level::error, "Failed to start {} {} SOCKS5 proxy {}", family, proto, endpoint);
                            return false;
                        }

                        NETLIB_LOG(log_level::info,
                            "Local {} {} proxy for {} is listening port: {}", family, proto, endpoint, server->proxy_port());
                        return true;
                    };

                    if (!start_listener(socks_tcp_proxy_server, "IPv4", "TCP")) return {};
                    if (!start_listener(socks_udp_proxy_server, "IPv4", "UDP")) return {};

                    const auto disable_ipv6_listeners = [&]
                    {
                        if (socks_tcp_proxy_server_v6)
                            socks_tcp_proxy_server_v6->stop();
                        if (socks_udp_proxy_server_v6)
                            socks_udp_proxy_server_v6->stop();

                        socks_tcp_proxy_server_v6.reset();
                        socks_udp_proxy_server_v6.reset();
                    };

                    if (!start_listener(socks_tcp_proxy_server_v6, "IPv6", "TCP"))
                    {
                        disable_ipv6_listeners();
                    }
                    else if (!start_listener(socks_udp_proxy_server_v6, "IPv6", "UDP"))
                    {
                        disable_ipv6_listeners();
                    }
                }

                // Install the static PASS filters for the upstream endpoint only NOW that the
                // proxy pair has been successfully built and (if requested) started. add_filter_back
                // commits immediately to the driver, so installing earlier leaked orphaned filters
                // on every failure path (build_proxy_pair throwing, or a required listener failing
                // to start and returning {}). Kept under lifecycle_lock and outside lock_, mirroring
                // the original lock scope.
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

                // Lock the mutex to safely add the proxy servers to the shared data
                // structures. proxy_servers_ and proxy_servers_v6_ are appended together
                // so they stay index-aligned (the returned index addresses both).
                std::scoped_lock lock(lock_);

                // Reserve capacity on BOTH vectors up front so the two appends below
                // are exception-atomic: reserve() is the only step here that can throw
                // (std::bad_alloc on reallocation), while the subsequent emplace_back of
                // moved unique_ptrs is noexcept once capacity is guaranteed. If either
                // reserve throws, neither vector has grown, preserving the index-alignment
                // invariant (a half-completed append would otherwise permanently skew the
                // vectors and silently leave IPv6 unproxied for later proxies).
                proxy_servers_.reserve(proxy_servers_.size() + 1);
                proxy_servers_v6_.reserve(proxy_servers_v6_.size() + 1);

                proxy_servers_.emplace_back(
                    std::move(socks_tcp_proxy_server), std::move(socks_udp_proxy_server));
                proxy_servers_v6_.emplace_back(
                    std::move(socks_tcp_proxy_server_v6), std::move(socks_udp_proxy_server_v6));

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
            upper_case.reserve(str.size());
            // Use the wide-character towupper. The narrow toupper(int) has
            // undefined behaviour for wchar_t values outside the unsigned char
            // range and does not upper-case non-ASCII characters, which made
            // process-name/exclusion matching diverge from network_process,
            // whose names are upper-cased with towupper. Wrap it in a lambda so
            // the wchar_t -> wint_t -> wchar_t conversion is explicit and the
            // call does not depend on towupper being a non-overloaded function.
            std::ranges::transform(str, std::back_inserter(upper_case),
                                   [](const wchar_t c) { return static_cast<wchar_t>(::towupper(c)); });
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

            // Matches a configured executable name (one without a path separator) against the
            // process's bare name. Anchored to the whole filename -- an exact match, or the
            // entry as the filename stem immediately followed by an extension -- so a short
            // pattern can't match an unrelated process (e.g. "NOTE" matching "EVILNOTE.EXE").
            // Inputs are already uppercased by the caller. Path-form entries (containing a
            // separator) still use substring matching against the full path.
            const auto name_matches = [](const std::wstring& name, const std::wstring& entry)
            {
                if (entry.empty())
                    return false;
                if (name == entry)
                    return true;
                return name.size() > entry.size()
                    && name.compare(0, entry.size(), entry) == 0
                    && name[entry.size()] == L'.';
            };

            // Check exclusion list
            for (const auto& excluded_entry : excluded_list_) {
                if ((excluded_entry.find(L'\\') != std::wstring::npos || excluded_entry.find(L'/') != std::wstring::npos)
                    ? (process->path_name.find(excluded_entry) != std::wstring::npos)
                    : name_matches(process->name, excluded_entry)
                    ) {
                    process->excluded = true;
                    return false; // Excluded
                }
            }

            // An empty app pattern is the catch-all: match ANY process not excluded above. This
            // restores the long-standing behavior (before matching was anchored) where a substring
            // find("") matched every process, letting an appNames entry of "" act as a default /
            // fallback proxy for all remaining traffic. Non-empty names keep the anchored matching
            // above (so a short pattern still can't match an unrelated process).
            if (app.empty())
                return true;

            return (app.find(L'\\') != std::wstring::npos || app.find(L'/') != std::wstring::npos)
                    ? (process->path_name.find(app) != std::wstring::npos)
                    : name_matches(process->name, app);
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
                    return proxy_id < proxy_servers_.size() && proxy_servers_[proxy_id].first
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
                    return proxy_id < proxy_servers_.size() && proxy_servers_[proxy_id].second
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
         * IPv6 counterpart of get_proxy_port_tcp(). Indexes proxy_servers_v6_, which is
         * kept index-aligned with proxy_servers_, so the same proxy_to_names_ mapping
         * selects the matching IPv6 proxy.
         */
        std::optional<uint16_t> get_proxy_port_tcp_v6(const std::shared_ptr<iphelper::network_process>& process)
        {
            if (!process) return {};

            std::shared_lock lock(lock_);

            for (const auto& [proxy_id, process_pattern] : proxy_to_names_)
            {
                if (match_app_name(process_pattern, process))
                {
                    return proxy_id < proxy_servers_v6_.size() && proxy_servers_v6_[proxy_id].first
                        ? std::optional(proxy_servers_v6_[proxy_id].first->proxy_port())
                        : std::nullopt;
                }
            }

            return {};
        }

        /**
         * IPv6 counterpart of get_proxy_port_udp(). See get_proxy_port_tcp_v6().
         */
        std::optional<uint16_t> get_proxy_port_udp_v6(const std::shared_ptr<iphelper::network_process>& process)
        {
            if (!process) return {};

            std::shared_lock lock(lock_);

            for (const auto& [proxy_id, process_pattern] : proxy_to_names_)
            {
                if (match_app_name(process_pattern, process))
                {
                    return proxy_id < proxy_servers_v6_.size() && proxy_servers_v6_[proxy_id].second
                        ? std::optional(proxy_servers_v6_[proxy_id].second->proxy_port())
                        : std::nullopt;
                }
            }

            return {};
        }

        /**
         * IPv6 counterpart of is_tcp_proxy_port(): checks the IPv6 TCP proxy listeners.
         */
        bool is_tcp_proxy_port_v6(const uint16_t port)
        {
            std::shared_lock lock(lock_);

            return std::ranges::any_of(std::as_const(proxy_servers_v6_), [port](auto& proxy)
            {
                if (proxy.first && proxy.first->proxy_port() == port)
                    return true;
                return false;
            });
        }

        /**
         * IPv6 counterpart of is_udp_proxy_port(): checks the IPv6 UDP proxy listeners.
         */
        bool is_udp_proxy_port_v6(const uint16_t port)
        {
            std::shared_lock lock(lock_);

            return std::ranges::any_of(std::as_const(proxy_servers_v6_), [port](auto& proxy)
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
                        tcp_mapper_entry{
                            net::ip_endpoint(net::ip_address_v4(ip_header->ip_dst),
                                ntohs(tcp_header->th_dport)),
                            std::chrono::steady_clock::now()
                        };

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
         * @brief Dispatches an IPv6 frame from the packet-filter callback.
         *
         * Mirrors the IPv4 dispatch in the constructor's filter callback: locates the
         * transport header (skipping IPv6 extension headers), passes broadcast/multicast
         * UDP through untouched, and routes TCP/UDP to the IPv6 process handlers. When a
         * handler cannot resolve the owning process inline, the frame is queued for
         * deferred resolution.
         *
         * @param buffer The intermediate buffer describing the IPv6 frame.
         * @param destination_mac Destination MAC, used to skip broadcast/multicast UDP.
         * @return The packet action to apply.
         */
        packet_filter::packet_action handle_ipv6_filter(ndisapi::intermediate_buffer& buffer,
                                                        const net::mac_address& destination_mac)
        {
            log_packet_to_pcap(buffer);

            auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);
            auto* const ip_header = reinterpret_cast<ipv6hdr_ptr>(ethernet_header + 1);

            const auto [transport, protocol] =
                net::ipv6_helper::find_transport_header(ip_header, buffer.m_Length - ETHER_HEADER_LENGTH);

            if (transport == nullptr)
            {
                // No usable transport header: either a fragmented IPv6 datagram (which
                // this build deliberately does not rewrite, to avoid corrupting a
                // partially-rewritten datagram) or an unsupported extension chain. Such
                // traffic is passed through UNPROXIED, so a proxied app's fragmented IPv6
                // egress leaks its real source address. Warn once so the limitation is
                // visible at runtime (see README, IPv6 fragmentation note).
                static std::atomic_flag fragment_passthrough_warned;
                if (!fragment_passthrough_warned.test_and_set(std::memory_order_relaxed))
                {
                    NETLIB_LOG(log_level::warning,
                        "Fragmented or unsupported IPv6 packet passed through unproxied; "
                        "fragmented IPv6 traffic is not redirected to the SOCKS5 proxy.");
                }
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
            }

            if (protocol == IPPROTO_UDP)
            {
                // skip broadcast and multicast UDP packets
                if (destination_mac.is_broadcast() || destination_mac.is_multicast())
                {
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
                }

                if (const auto result = process_udp_packet_v6(buffer, false))
                {
                    return result.value();
                }
                return enqueue_for_deferred_resolve(buffer);
            }

            if (protocol == IPPROTO_TCP)
            {
                if (const auto result = process_tcp_packet_v6(buffer, false))
                {
                    return result.value();
                }
                return enqueue_for_deferred_resolve(buffer);
            }

            return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
        }

        /**
         * @brief IPv6 counterpart of process_udp_packet().
         *
         * Behaves identically to the IPv4 handler but parses an IPv6 header (skipping
         * extension headers via ipv6_helper), and uses the IPv6 process lookup, mapper,
         * proxy-port lookup, and redirect objects. See process_udp_packet() for the
         * postponed/return-value contract.
         */
        std::optional<packet_filter::packet_action> process_udp_packet_v6(ndisapi::intermediate_buffer& buffer, const bool postponed)
        {
            auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);
            auto* const ip_header = reinterpret_cast<ipv6hdr_ptr>(ethernet_header + 1);

            const auto [transport, protocol] =
                net::ipv6_helper::find_transport_header(ip_header, buffer.m_Length - ETHER_HEADER_LENGTH);

            if (transport == nullptr || protocol != IPPROTO_UDP)
            {
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
            }

            const auto* const udp_header = static_cast<udphdr_ptr>(transport);

            // If the destination port is 53 (DNS), allow the packet to pass through
            // without redirection (mirrors the IPv4 path).
            if (ntohs(udp_header->th_dport) == 53)
            {
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
            }

            // If the packet is from a known proxy port, process for server-to-client redirection
            if (is_udp_proxy_port_v6(ntohs(udp_header->th_sport)))
            {
                if (udp_redirect_v6_->process_server_to_client_packet(buffer))
                {
                    log_packet_to_pcap(buffer);
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::revert };
                }
            }

            auto process = process_lookup_v6_.
                lookup_process_for_udp<false>(net::ip_endpoint<net::ip_address_v6>{
                ip_header->ip6_src, ntohs(udp_header->th_sport)
            });

            if (!process)
            {
                if (postponed)
                {
                    process = process_lookup_v6_.
                        lookup_process_for_udp<true>(net::ip_endpoint<net::ip_address_v6>{
                        ip_header->ip6_src, ntohs(udp_header->th_sport)
                    });
                }
                else
                {
                    return std::nullopt;
                }
            }

            if (process->excluded || process->bypass_udp)
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };

            if (const auto port = process->udp_proxy_port ? process->udp_proxy_port : get_proxy_port_udp_v6(process); port.has_value())
            {
                if (udp_redirect_v6_->is_new_endpoint(buffer))
                {
                    std::scoped_lock lock(udp_mapper_v6_lock_);
                    udp_mapper_v6_.insert(ntohs(udp_header->th_sport));

                    NETLIB_LOG(log_level::info,
                        "Redirecting UDP6 {} : {} -> {} : {}",
                        std::string{ net::ip_address_v6{ip_header->ip6_src} }, ntohs(udp_header->th_sport),
                        std::string{ net::ip_address_v6{ip_header->ip6_dst} }, ntohs(udp_header->th_dport));
                }

                if (udp_redirect_v6_->process_client_to_server_packet(buffer, htons(port.value())))
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
         * @brief IPv6 counterpart of process_tcp_packet().
         *
         * Behaves identically to the IPv4 handler but parses an IPv6 header (skipping
         * extension headers via ipv6_helper), and uses the IPv6 process lookup, mapper,
         * proxy-port lookup, and redirect objects. See process_tcp_packet() for the
         * postponed/return-value contract.
         */
        std::optional<packet_filter::packet_action> process_tcp_packet_v6(ndisapi::intermediate_buffer& buffer, const bool postponed)
        {
            auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);
            auto* const ip_header = reinterpret_cast<ipv6hdr_ptr>(ethernet_header + 1);

            const auto [transport, protocol] =
                net::ipv6_helper::find_transport_header(ip_header, buffer.m_Length - ETHER_HEADER_LENGTH);

            if (transport == nullptr || protocol != IPPROTO_TCP)
            {
                return packet_filter::packet_action{ packet_filter::packet_action::action_type::pass };
            }

            const auto* const tcp_header = static_cast<tcphdr_ptr>(transport);

            // If the packet is from a known proxy port, process for server-to-client redirection
            if (is_tcp_proxy_port_v6(ntohs(tcp_header->th_sport)))
            {
                if (tcp_redirect_v6_->process_server_to_client_packet(buffer))
                {
                    log_packet_to_pcap(buffer);
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::revert };
                }
            }

            auto process = process_lookup_v6_.
                lookup_process_for_tcp<false>(net::ip_session<net::ip_address_v6>{
                ip_header->ip6_src, ip_header->ip6_dst, ntohs(tcp_header->th_sport),
                    ntohs(tcp_header->th_dport)
            });

            if (!process)
            {
                if (postponed)
                {
                    process = process_lookup_v6_.
                        lookup_process_for_tcp<true>(net::ip_session<net::ip_address_v6>{
                        ip_header->ip6_src, ip_header->ip6_dst, ntohs(tcp_header->th_sport),
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

            if (const auto port = process->tcp_proxy_port ? process->tcp_proxy_port : get_proxy_port_tcp_v6(process); port.has_value())
            {
                // If this is a SYN packet (connection initiation), map the source port to the destination endpoint
                if ((tcp_header->th_flags & (TH_SYN | TH_ACK)) == TH_SYN)
                {
                    std::scoped_lock lock(tcp_mapper_v6_lock_);
                    tcp_mapper_v6_[ntohs(tcp_header->th_sport)] =
                        tcp_mapper_entry_v6{
                            net::ip_endpoint(net::ip_address_v6(ip_header->ip6_dst),
                                ntohs(tcp_header->th_dport)),
                            std::chrono::steady_clock::now()
                        };

                    NETLIB_LOG(log_level::info,
                        "Redirecting TCP6: {} : {} -> {} : {}",
                        std::string{ net::ip_address_v6{ip_header->ip6_src} }, ntohs(tcp_header->th_sport),
                        std::string{ net::ip_address_v6{ip_header->ip6_dst} }, ntohs(tcp_header->th_dport));
                }

                // Attempt to process the packet for client-to-server redirection
                if (tcp_redirect_v6_->process_client_to_server_packet(buffer, htons(port.value())))
                {
                    log_packet_to_pcap(buffer);
                    return packet_filter::packet_action{ packet_filter::packet_action::action_type::revert };
                }
            }
            else
            {
                process->bypass_tcp = true;
            }

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
        * 1. Wait for packets to be queued or for resolver_should_exit_ to be set.
        * 2. Swap the shared queue with a local queue for processing.
        * 3. Refresh the process lookup table.
        * 4. For each packet, attempt to resolve the process and determine the appropriate
        *    action (pass to adapter, revert to MSTCP, or assert on unexpected cases).
        * 5. Send processed packets to their respective destinations and clear local queues.
        *
        * The thread exits only after resolver_should_exit_ has been set (which stop()
        * does after packet_filter_->stop_filter() returns) and the shared queue has
        * fully drained, so any buffers enqueued by the packet-handler thread before
        * stop_filter() completes are still processed before the resolver thread exits.
        */
        void process_resolve_thread_proc()
        {
            // Use local (non-static) containers to avoid static initialization order issues and data races
            std::queue<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr> local_queue;
            std::vector<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr> to_adapters;
            std::vector<ndisapi::intermediate_buffer_pool::intermediate_buffer_ptr> to_mstcp;

            // Run the tcp_mapper_ sweep at most once per maintenance interval, even
            // under heavy resolver activity. The interval is half the TTL so an
            // entry is evicted within at most 1.5 * TTL of becoming stale, and the
            // condition variable below uses the same period as its wait timeout so
            // the sweep still runs when the deferred-resolve queue stays empty.
            constexpr auto maintenance_interval = tcp_mapper_entry_ttl_ / 2;
            auto last_sweep = std::chrono::steady_clock::now();
            auto last_drop_log = last_sweep;

            while (true)
            {
                {
                    std::unique_lock lock(process_resolve_buffer_mutex_);
                    // Timed wait so we still run periodic maintenance (tcp_mapper_
                    // TTL eviction) when no packets are being deferred. Also wake
                    // early for maintenance-only notifications so throttled
                    // alloc-failure/drop diagnostics are not delayed until the next
                    // timeout when no packet was actually queued, but only once
                    // the throttle window has elapsed to avoid a tight spin on
                    // empty queues under sustained overload (the counters stay
                    // non-zero until the throttled log path runs and exchanges
                    // them, so waking unconditionally on non-zero counters would
                    // re-fire every iteration until the throttle elapses).
                    process_resolve_buffer_queue_cv_.wait_for(lock, maintenance_interval, [this, &last_drop_log] {
                        if (!process_resolve_buffer_queue_.empty() || resolver_should_exit_.load())
                            return true;

                        const auto has_pending_drop_diagnostics =
                            resolve_queue_alloc_failures_.load(std::memory_order_relaxed) != 0 ||
                            resolve_queue_dropped_packets_.load(std::memory_order_relaxed) != 0;

                        if (!has_pending_drop_diagnostics)
                            return false;

                        return std::chrono::steady_clock::now() - last_drop_log >= drop_log_throttle_interval_;
                        });

                    if (resolver_should_exit_.load() && process_resolve_buffer_queue_.empty())
                        break;

                    // Swap the contents of the shared queue with the local queue
                    std::swap(process_resolve_buffer_queue_, local_queue);
                }

                // Evict stale tcp_mapper_ entries whose SYN was redirected but never
                // produced a local proxy connection (e.g. peer RST, timeout, app gave
                // up). Without this sweep such entries would leak indefinitely since
                // the only other removal site is the SOCKS5 negotiate callback. The
                // sweep is rate-limited to maintenance_interval to bound CPU cost
                // when the resolver loop runs frequently under sustained load.
                if (const auto now = std::chrono::steady_clock::now();
                    now - last_sweep >= maintenance_interval)
                {
                    last_sweep = now;
                    {
                        std::scoped_lock lock(tcp_mapper_lock_);
                        for (auto it = tcp_mapper_.begin(); it != tcp_mapper_.end();)
                        {
                            if (now - it->second.created_at > tcp_mapper_entry_ttl_)
                            {
                                it = tcp_mapper_.erase(it);
                            }
                            else
                            {
                                ++it;
                            }
                        }
                    }

                    // Same TTL sweep for the IPv6 TCP mapper.
                    {
                        std::scoped_lock lock(tcp_mapper_v6_lock_);
                        for (auto it = tcp_mapper_v6_.begin(); it != tcp_mapper_v6_.end();)
                        {
                            if (now - it->second.created_at > tcp_mapper_entry_ttl_)
                            {
                                it = tcp_mapper_v6_.erase(it);
                            }
                            else
                            {
                                ++it;
                            }
                        }
                    }
                }

                // Periodically surface the counts of packets dropped due to a
                // full resolve queue or buffer-pool allocation failure so
                // operators can correlate connectivity issues with resolver
                // overload / memory pressure. The emission is throttled to at
                // most once per drop_log_throttle_interval_ — between
                // emissions the cumulative counts keep accumulating in the
                // atomic counters, so no drops are lost; only the log rate is
                // bounded. Performed before the local_queue.empty() early-
                // continue so the signal is still surfaced when the queue
                // stays empty (e.g. resolver succeeds inline but allocations
                // are failing). Relaxed ordering is sufficient because the
                // counters are coarse overload indicators.
                if (const auto now = std::chrono::steady_clock::now();
                    now - last_drop_log >= drop_log_throttle_interval_)
                {
                    // Relaxed load fast-path: once the throttle interval has
                    // elapsed, avoid performing atomic RMWs (exchange) on the
                    // hot path when both counters are already zero. Only fall
                    // through to the exchange/log path when at least one
                    // counter has observed activity.
                    const auto dropped_snapshot =
                        resolve_queue_dropped_packets_.load(std::memory_order_relaxed);
                    const auto alloc_failures_snapshot =
                        resolve_queue_alloc_failures_.load(std::memory_order_relaxed);

                    if ((dropped_snapshot != 0) || (alloc_failures_snapshot != 0))
                    {
                        bool emitted = false;
                        if (dropped_snapshot != 0)
                        {
                            if (const auto dropped =
                                    resolve_queue_dropped_packets_.exchange(0, std::memory_order_relaxed);
                                dropped != 0)
                            {
                                NETLIB_LOG(log_level::warning,
                                    "Dropped {} packet(s) because process_resolve_buffer_queue_ reached capacity at {} entries.",
                                    dropped, max_resolve_queue_depth_);
                                emitted = true;
                            }
                        }
                        if (alloc_failures_snapshot != 0)
                        {
                            if (const auto alloc_failures =
                                    resolve_queue_alloc_failures_.exchange(0, std::memory_order_relaxed);
                                alloc_failures != 0)
                            {
                                NETLIB_LOG(log_level::error,
                                    "Dropped {} packet(s) because the intermediate buffer pool failed to allocate.",
                                    alloc_failures);
                                emitted = true;
                            }
                        }
                        // Only advance the throttle timestamp when something
                        // was actually logged so that the throttle interval
                        // bounds the minimum gap between *emitted* logs
                        // rather than between throttle checks.
                        if (emitted)
                        {
                            last_drop_log = now;
                        }
                    }
                    else
                    {
                        // Both counters are zero: advance the throttle
                        // timestamp so the throttle check (now() + atomic
                        // loads) only runs at most once per
                        // drop_log_throttle_interval_, instead of on every
                        // resolver loop iteration once the interval has
                        // elapsed. A subsequent counter increment is still
                        // surfaced within at most one drop_log_throttle_interval_.
                        last_drop_log = now;
                    }
                }

                // Nothing else to do on a maintenance-only wakeup (timer fired with
                // an empty queue) — skip process-lookup refresh until there is
                // real packet work.
                if (local_queue.empty())
                {
                    continue;
                }

                // Actualize process lookup before processing
                process_lookup_v4_.actualize(true, true);
                process_lookup_v6_.actualize(true, true);

                while (!local_queue.empty())
                {
                    auto buffer_ptr = std::move(local_queue.front());
                    local_queue.pop();

                    auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer_ptr->m_IBuffer);

                    // Dispatch on EtherType first: IPv6 packets carry an IPv6
                    // header (with optional extension headers) rather than an
                    // iphdr, so reading iphdr::ip_p for them would misparse.
                    if (const auto ether_type = ntohs(ethernet_header->h_proto);
                        ether_type == ETH_P_IPV6)
                    {
                        const auto* const ip_header =
                            reinterpret_cast<ipv6hdr_ptr>(ethernet_header + 1);
                        const auto [transport_header, protocol] =
                            net::ipv6_helper::find_transport_header(
                                ip_header, buffer_ptr->m_Length - ETHER_HEADER_LENGTH);

                        if (transport_header == nullptr)
                        {
                            // Non-initial fragment or malformed/unsupported chain:
                            // nothing actionable was deferred, so pass it through.
                            to_adapters.push_back(std::move(buffer_ptr));
                            continue;
                        }

                        if (protocol == IPPROTO_UDP)
                        {
                            if (const auto result = process_udp_packet_v6(*buffer_ptr, true);
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
                                // Invariant: a postponed packet always yields a result. If a
                                // future change ever breaks it, fail safe by passing the packet
                                // through rather than silently dropping it in a release build.
                                assert(false && "process_udp_packet_v6 should always return a result for postponed packets");
                                to_adapters.push_back(std::move(buffer_ptr));
                            }
                        }
                        else if (protocol == IPPROTO_TCP)
                        {
                            if (const auto result = process_tcp_packet_v6(*buffer_ptr, true);
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
                                // Fail safe (see above): pass through instead of dropping.
                                assert(false && "process_tcp_packet_v6 should always return a result for postponed packets");
                                to_adapters.push_back(std::move(buffer_ptr));
                            }
                        }
                        else
                        {
                            // Unexpected (only TCP/UDP are queued): pass through, don't drop.
                            assert(false && "Only TCP/UDP packets should be queued for deferred processing");
                            to_adapters.push_back(std::move(buffer_ptr));
                        }

                        continue;
                    }

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
                            // Should always have a result for postponed packets; if not,
                            // fail safe by passing it through rather than dropping it.
                            assert(false && "process_udp_packet should always return a result for postponed packets");
                            to_adapters.push_back(std::move(buffer_ptr));
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
                            // Should always have a result for postponed packets; if not,
                            // fail safe by passing it through rather than dropping it.
                            assert(false && "process_tcp_packet should always return a result for postponed packets");
                            to_adapters.push_back(std::move(buffer_ptr));
                        }
                    }
                    else
                    {
                        // Only TCP/UDP packets should be queued for deferred processing;
                        // pass anything unexpected through rather than dropping it.
                        assert(false && "Only TCP/UDP packets should be queued for deferred processing");
                        to_adapters.push_back(std::move(buffer_ptr));
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
            bool enumeration_succeeded = false;
            const auto configured_interfaces =
                iphelper::network_adapter_info::get_external_network_connections(&enumeration_succeeded);

            // Fail SAFE, not open. An empty result is ambiguous: it can mean "no external
            // adapters" OR that enumeration failed (transient API/allocation error, e.g. under
            // memory pressure during a network-change storm). If we cannot trust the list, do
            // NOT rebuild the filter set from it: an empty set would unfilter every interface
            // and send all matched applications' traffic direct, bypassing the proxy. Keep the
            // current filter state and let the next change notification retry.
            if (!enumeration_succeeded)
            {
                NETLIB_LOG(log_level::warning,
                    "update_network_configuration: network adapter enumeration failed; "
                    "preserving current filter state to avoid a proxy-bypass.");
                return;
            }

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

            // Serialize compare -> reprogram driver -> store as ONE atomic critical section.
            // This function is reentrant: it runs from start() and from the NotifyIpInterfaceChange
            // system-thread callback. Splitting the "did it change?" check from the driver
            // reprogramming and the stored-set update lets two concurrent runs both pass the check,
            // both drive filter/unfilter, and race their stores -- leaving adapters_to_filter_ out
            // of sync with the actual NDIS filter state. Hold the exclusive lock across the whole
            // decision so the stored set always reflects the last programming applied to the driver.
            std::unique_lock lock(adapters_to_filter_lock_);

            if (adapters_to_filter_ == adapters_to_filter)
                return;

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

            adapters_to_filter_ = std::move(adapters_to_filter);
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

        /**
        * @brief Builds and adds IPv6 pass-through filters for common local network ranges.
        *
        * IPv6 counterpart of add_lan_passover_filters_v4(). Because IPv6 destinations
        * are now proxied, LAN bypass must also exempt the IPv6 local/special-purpose
        * ranges; otherwise a matched application's link-local / ULA / multicast IPv6
        * traffic would be redirected to the SOCKS5 proxy (which generally cannot reach
        * those scopes) even with bypassLan enabled.
        *
        * Bypassed ranges:
        * - fe80::/10  (Link-local unicast)
        * - fc00::/7   (Unique local addresses, ULA)
        * - ff00::/8   (Multicast)
        */
        void add_lan_passover_filters_v6()
        {
            // Local / special-purpose IPv6 ranges, in CIDR notation. Because the IPv6
            // redirect also captures IPv4-mapped destinations (::ffff:a.b.c.d) that a
            // dual-stack app opens to a v4 LAN host, the IPv4 private/link-local/multicast
            // ranges are also exempted in their v4-mapped form so bypassLan covers them.
            static constexpr std::array<const char*, 9> local_ranges{ {
                "::1/128",                  // Loopback
                "fe80::/10",                // Link-local unicast
                "fc00::/7",                 // Unique local addresses (ULA)
                "ff00::/8",                 // Multicast
                "::ffff:10.0.0.0/104",      // IPv4-mapped 10.0.0.0/8 (private)
                "::ffff:172.16.0.0/108",    // IPv4-mapped 172.16.0.0/12 (private)
                "::ffff:192.168.0.0/112",   // IPv4-mapped 192.168.0.0/16 (private)
                "::ffff:169.254.0.0/112",   // IPv4-mapped 169.254.0.0/16 (link-local)
                "::ffff:127.0.0.0/104"      // IPv4-mapped loopback
            } };

            for (const auto* const cidr : local_ranges)
            {
                const auto subnet = net::ip_subnet<net::ip_address_v6>::from_cidr(cidr);
                if (!subnet)
                {
                    // The ranges above are compile-time constants, so this should
                    // never trigger; guard defensively rather than dereference a
                    // nullopt if one is ever mistyped.
                    NETLIB_LOG(log_level::warning, "Failed to parse IPv6 LAN bypass range '{}'; skipping.", cidr);
                    continue;
                }

                // Allow inbound traffic originating from the local subnet
                ndisapi::filter<net::ip_address_v6> in_filter;
                in_filter
                    .set_direction(ndisapi::direction_t::in)
                    .set_action(ndisapi::action_t::pass)
                    .set_source_address(subnet.value());
                static_filters_.add_filter_front(in_filter);

                // Allow outbound traffic destined to the local subnet
                ndisapi::filter<net::ip_address_v6> out_filter;
                out_filter
                    .set_direction(ndisapi::direction_t::out)
                    .set_action(ndisapi::action_t::pass)
                    .set_dest_address(subnet.value());
                static_filters_.add_filter_front(out_filter);
            }

            NETLIB_LOG(log_level::info, "IPv6 LAN bypass enabled - local IPv6 network traffic will not be proxied");
        }
    };
}
