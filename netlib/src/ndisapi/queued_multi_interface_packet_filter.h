// --------------------------------------------------------------------------------
/**
 * @file queued_multi_interface_packet_filter.h
 * @brief Declaration of a multi-interface, queued packet filter for WinpkFilter-based prototyping.
 *
 * This header defines the @ref ndisapi::queued_multi_interface_packet_filter class, which provides
 * a thread-safe, multi-queue, multi-adapter packet filtering mechanism using the Windows Packet Filter (WinpkFilter) driver.
 * The filter supports user-defined functors for incoming and outgoing packet processing, dynamic adapter management,
 * and efficient batch processing of packets for high-performance network applications.
 */
 // --------------------------------------------------------------------------------
#pragma once

namespace ndisapi
{
    /**
     * @class unsorted_packet_block
     * @brief Represents a fixed-size block of packet buffers for batch processing.
     *
     * This template class manages a group of @ref intermediate_buffer objects and provides
     * pointer arrays and vectors for efficient batch read/write operations in a packet
     * filtering pipeline. It is designed for use with the queued, multithreaded
     * packet filter, enabling high-throughput processing of network packets.
     *
     * @tparam Size The number of packets in the block.
     *
     * @details
     * - Each block contains an array of @ref intermediate_buffer objects, which hold the actual packet data.
     * - The @c read_request_ array provides pointers to each buffer for use in batch read operations.
     * - The @c write_adapter_request_ and @c write_mstcp_request_ vectors collect pointers to buffers
     *   that should be written to the network adapter or up to the protocol stack, respectively.
     * - The @c packets_success_ member tracks the number of packets successfully read into the block.
     */
    template <uint32_t Size>
    class unsorted_packet_block
    {
        /// Number of successfully read packets in this block.
        uint32_t packets_success_{ 0 };
        /// Array of packet buffers.
        std::array<intermediate_buffer, Size> packet_buffer_;
        /// Array of pointers for batch reading packets.
        std::array<intermediate_buffer*, Size> read_request_;
        /// Vector of pointers to packets to be written to the adapter.
        std::vector<intermediate_buffer*> write_adapter_request_;
        /// Vector of pointers to packets to be written up to the protocol stack.
        std::vector<intermediate_buffer*> write_mstcp_request_;

    public:
        /**
         * @brief Constructs and initializes the packet block.
         *
         * Reserves space in the write vectors and sets up the read pointer array
         * to point to each buffer in @c packet_buffer_.
         */
        explicit unsorted_packet_block()
        {
            write_adapter_request_.reserve(Size);
            write_mstcp_request_.reserve(Size);

            for (unsigned i = 0; i < Size; ++i)
            {
                read_request_[i] = &packet_buffer_[i];
            }
        }

        /**
         * @brief Returns the array of pointers for batch reading packets.
         * @return Const reference to the read pointer array.
         */
        [[nodiscard]] const std::array<intermediate_buffer*, Size>& get_read_request() const
        {
            return read_request_;
        }

        /**
         * @brief Returns the vector of pointers for writing packets to the adapter.
         * @return Reference to the write_adapter_request_ vector.
         */
        [[nodiscard]] std::vector<intermediate_buffer*>& get_write_adapter_request()
        {
            return write_adapter_request_;
        }

        /**
         * @brief Returns the vector of pointers for writing packets up to the protocol stack.
         * @return Reference to the write_mstcp_request_ vector.
         */
        [[nodiscard]] std::vector<intermediate_buffer*>& get_write_mstcp_request()
        {
            return write_mstcp_request_;
        }

        /**
         * @brief Accesses a packet buffer by index.
         * @param idx Index of the buffer.
         * @return Reference to the buffer at the specified index.
         */
        intermediate_buffer& operator[](const std::size_t idx)
        {
            return packet_buffer_[idx];
        }

        /**
         * @brief Const access to a packet buffer by index.
         * @param idx Index of the buffer.
         * @return Const reference to the buffer at the specified index.
         */
        const intermediate_buffer& operator[](const std::size_t idx) const
        {
            return packet_buffer_[idx];
        }

        /**
         * @brief Returns a reference to the number of successfully read packets.
         * @return Reference to the packets_success_ member.
         */
        [[nodiscard]] uint32_t& get_packets_success()
        {
            return packets_success_;
        }
    };

    // --------------------------------------------------------------------------------
    /**
     * @class queued_multi_interface_packet_filter
     * @brief WinpkFilter-based multi-interface packet filter for rapid prototyping.
     *
     * This class provides a high-level, thread-safe, multi-queue packet filtering engine
     * for Windows using the WinpkFilter driver. It supports dynamic management of multiple
     * network adapters and enables user-defined logic for both incoming and outgoing packet
     * processing via functors. The filter is designed for high-throughput, low-latency
     * scenarios and is suitable for advanced network applications, monitoring, and research.
     *
     * Key features:
     * - Multi-threaded, lock-protected queues for each stage of packet processing.
     * - Batch processing of packets using @ref unsorted_packet_block for efficiency.
     * - Dynamic adapter filtering and runtime reconfiguration.
     * - User-supplied functors for custom packet handling logic.
     * - Automatic resource management and graceful shutdown.
     *
     * Usage:
     *   1. Instantiate with functors for incoming and outgoing packet handling.
     *   2. Start the filter with start_filter().
     *   3. Optionally, filter or unfilter specific adapters at runtime.
     *   4. Stop the filter with stop_filter() before destruction.
     */
     // --------------------------------------------------------------------------------
    class queued_multi_interface_packet_filter final : public CNdisApi
    {
    public:
        /**
         * @struct packet_action
         * @brief Describes the action to take for a packet during filtering.
         *
         * This structure is used as the return type for packet filter functors. It specifies
         * whether a packet should be passed, dropped, or reverted, and optionally allows
         * redirection to a specific network interface.
         *
         * Example usage in a filter functor:
         * @code
         * return packet_action(packet_action::action_type::drop);
         * // or to redirect:
         * return packet_action(packet_action::action_type::pass, target_handle);
         * @endcode
         */
        struct packet_action
        {
            /**
             * @enum action_type
             * @brief Enumerates possible actions for a packet.
             */
            enum class action_type : uint8_t
            {
                pass,   ///< Pass the packet to the next layer (default).
                drop,   ///< Drop the packet.
                revert  ///< Revert the packet to the original direction (e.g., send back to MSTCP).
            };

            action_type action{ action_type::pass };      ///< The action to perform on the packet.
            std::optional<HANDLE> interface_handle;       ///< Optional: redirect to a specific interface.

            /**
             * @brief Default constructor. Initializes to 'pass' action.
             */
            packet_action() = default;

            /**
             * @brief Constructs a packet_action with the specified action.
             * @param action_type The action to perform.
             */
            explicit packet_action(const action_type action_type)
                : action(action_type)
            {
            }

            /**
             * @brief Constructs a packet_action with the specified action and target interface.
             * @param action_type The action to perform.
             * @param if_handle The handle of the target interface for redirection.
             */
            packet_action(const action_type action_type, HANDLE if_handle)
                : action(action_type), interface_handle(if_handle)
            {
            }
        };

    private:
        /**
         * @brief Maximum number of packets in a single processing block.
         *
         * This constant defines the size of each @ref unsorted_packet_block used for batch
         * packet processing. Increasing this value may improve throughput at the cost of
         * higher memory usage and latency.
         */
        static constexpr uint32_t maximum_packet_block = 512;

        /**
         * @brief Maximum number of packet blocks in the processing queues.
         *
         * This constant determines the number of @ref unsorted_packet_block instances
         * allocated for the internal queues. It controls the maximum number of batches
         * that can be in-flight at any stage of the pipeline.
         */
        static constexpr uint32_t maximum_block_num = 16;

        /**
         * @brief Constructs the filter and initializes internal resources.
         *
         * Checks for the presence of the Windows Packet Filter driver and throws
         * a std::runtime_error if unavailable. Sets up the adapter event thread to
         * monitor network adapter changes and initializes the list of available
         * network interfaces for filtering.
         *
         * @throws std::runtime_error if the WinpkFilter driver is not loaded.
         */
        queued_multi_interface_packet_filter()
        {
            // Check if the Windows Packet Filter driver is loaded. If not, throw an exception.
            if (!IsDriverLoaded())
                throw std::runtime_error("Windows Packet Filter driver is not available!");

            // Create a thread to handle adapter events. This thread waits for an adapter event,
            // resets the event, and then calls on_network_adapter_change() if the thread should not exit.
            adapter_event_thread_ = std::thread([this]()
                {
                    do {
                        std::ignore = adapter_event_.wait(INFINITE);
                        std::ignore = adapter_event_.reset_event();
                        if (!exit_adapter_event_thread_)
                            on_network_adapter_change();
                    } while (!exit_adapter_event_thread_);
                });

            // Set the event that triggers when the list of network adapters changes.
            SetAdapterListChangeEvent(adapter_event_.get());

            // Initialize the list of network interfaces available for packet filtering.
            initialize_network_interfaces();
        }

    public:
        /**
         * @enum filter_state
         * @brief Represents the current operational state of the packet filter.
         *
         * This enumeration is used to track and control the lifecycle of the
         * queued_multi_interface_packet_filter instance. It is used internally
         * to coordinate thread execution and resource management.
         *
         * - stopped:   The filter is not running.
         * - starting:  The filter is in the process of starting up.
         * - running:   The filter is actively processing packets.
         * - stopping:  The filter is in the process of shutting down.
         */
        enum class filter_state : uint8_t
        {
            stopped,   ///< Filter is stopped and not processing packets.
            starting,  ///< Filter is starting up.
            running,   ///< Filter is running and processing packets.
            stopping   ///< Filter is stopping and cleaning up resources.
        };

        /**
         * @brief Destructor. Ensures proper shutdown and resource cleanup.
         *
         * Signals the adapter event thread to exit, stops the filter if running,
         * and joins the adapter event thread to ensure all resources are released
         * before destruction.
         */
        ~queued_multi_interface_packet_filter() override
        {
            exit_adapter_event_thread_ = true;
            std::ignore = adapter_event_.signal();
            stop_filter();
            if (adapter_event_thread_.joinable())
                adapter_event_thread_.join();
        }

        /**
         * @brief Deleted copy constructor.
         *
         * Copying is not allowed to prevent multiple instances managing the same
         * resources and threads.
         */
        queued_multi_interface_packet_filter(const queued_multi_interface_packet_filter& other) = delete;

        /**
         * @brief Deleted move constructor.
         *
         * Moving is not allowed to prevent resource mismanagement.
         */
        queued_multi_interface_packet_filter(queued_multi_interface_packet_filter&& other) noexcept = delete;

        /**
         * @brief Deleted copy assignment operator.
         *
         * Copy assignment is not allowed to prevent multiple instances managing the same
         * resources and threads.
         */
        queued_multi_interface_packet_filter& operator=(const queued_multi_interface_packet_filter& other) = delete;

        /**
         * @brief Deleted move assignment operator.
         *
         * Move assignment is not allowed to prevent resource mismanagement.
         */
        queued_multi_interface_packet_filter& operator=(queued_multi_interface_packet_filter&& other) noexcept = delete;

        /**
         * @brief Constructs a queued_multi_interface_packet_filter with user-defined packet handlers.
         *
         * This templated constructor allows the user to specify custom functors or callable objects
         * for handling incoming and outgoing packets. These handlers are invoked for each packet
         * processed by the filter, enabling flexible and dynamic packet processing logic.
         *
         * @tparam F1 Type of the incoming packet handler functor.
         * @tparam F2 Type of the outgoing packet handler functor.
         * @param in  Functor or callable object for processing incoming packets.
         * @param out Functor or callable object for processing outgoing packets.
         *
         * @note The handlers must be compatible with the signature:
         *       packet_action(HANDLE, intermediate_buffer&)
         */
        template <typename F1, typename F2>
        queued_multi_interface_packet_filter(F1 in, F2 out) : queued_multi_interface_packet_filter()
        {
            filter_incoming_packet_ = in;
            filter_outgoing_packet_ = out;
        }

        /**
         * @brief Starts the packet filtering process.
         * @return True if the filter was successfully started, false otherwise.
         */
        bool start_filter();

        /**
         * @brief Stops the packet filtering process.
         * @return True if the filter was successfully stopped, false otherwise.
         */
        bool stop_filter();

        /**
         * @brief Adds a network adapter to the filter list.
         * @param name The name of the network adapter to filter.
         */
        void filter_network_adapter(const std::string& name);

        /**
         * @brief Removes a network adapter from the filter list.
         * @param name The name of the network adapter to remove from filtering.
         */
        void unfilter_network_adapter(const std::string& name);

        /**
         * @brief Retrieves the list of currently filtered network adapters.
         * @return A vector of strings representing the names of filtered adapters.
         */
        std::vector<std::string> get_filtered_adapters();

        /**
         * @brief Retrieves the list of all available network interfaces.
         * @return A vector of network_adapter objects representing each interface.
         */
        std::vector<network_adapter> get_interface_list();

        /**
         * @brief Gets the current filter state.
         * @return The current filter_state value.
         */
        [[nodiscard]] filter_state get_filter_state() const
        {
            return filter_state_.load();
        }

    private:
        /**
         * @brief Thread procedure for reading packets from network adapters.
         *
         * This method runs in a dedicated thread and is responsible for reading packets
         * from the filtered network adapters. It waits for packets to become available,
         * retrieves them in batches, and enqueues them for further processing.
         */
        void packet_read_thread();

        /**
         * @brief Thread procedure for processing packets.
         *
         * This method runs in a dedicated thread and processes packets that have been
         * read from the adapters. It applies the user-defined filtering logic to each
         * packet and determines the appropriate action (pass, drop, revert, or redirect).
         * Packets are then enqueued for delivery to either the network stack or the adapter.
         */
        void packet_process_thread();

        /**
         * @brief Thread procedure for writing packets to the MSTCP stack.
         *
         * This method runs in a dedicated thread and is responsible for sending processed
         * packets up to the Microsoft TCP/IP stack (MSTCP). It dequeues packets that are
         * destined for the stack and submits them in batches.
         */
        void packet_write_mstcp_thread();

        /**
         * @brief Thread procedure for writing packets to network adapters.
         *
         * This method runs in a dedicated thread and is responsible for sending processed
         * packets out to the network adapters. It dequeues packets that are destined for
         * the network and submits them in batches.
         */
        void packet_write_adapter_thread();

        /**
         * @brief Initializes the list of available network interfaces.
         *
         * Queries the system for all TCP/IP-bound network adapters and populates the
         * internal list of @ref network_adapter objects. This method is called during
         * construction and whenever the adapter list changes.
         */
        void initialize_network_interfaces();

        /**
         * @brief Updates the filter state of all network adapters.
         *
         * Iterates through the list of network interfaces and applies the current
         * filtering configuration, enabling or disabling packet filtering as needed
         * based on the filter state and adapter selection.
         */
        void update_adapters_filter_state() const;

        /**
         * @brief Initializes internal packet processing resources.
         *
         * Allocates and prepares packet blocks and queues required for batch packet
         * processing. Returns true on success, or false if memory allocation fails.
         *
         * @return True if initialization succeeds, false otherwise.
         */
        bool init_filter();

        /**
         * @brief Releases all resources and stops worker threads.
         *
         * Signals all worker threads to exit, releases network interface resources,
         * and clears all internal queues and events to ensure a clean shutdown.
         */
        void release_filter();

        /**
         * @brief Handles changes in the network adapter configuration.
         *
         * Invoked when the system's network adapter list changes (e.g., adapters are
         * added or removed). Refreshes the internal adapter list and reapplies the
         * current filtering configuration.
         */
        void on_network_adapter_change();

        /// <summary>outgoing packet processing functor</summary>
        /// <remarks>
        /// This functor is responsible for processing outgoing packets. It takes a handle to the adapter
        /// and a reference to the intermediate_buffer containing the packet data. The functor returns a
        /// packet_action struct that determines how the packet should be handled (e.g., passed, dropped, reverted).
        /// </remarks>
        std::function<packet_action(HANDLE, intermediate_buffer&)> filter_outgoing_packet_ = nullptr;

        /// <summary>incoming packet processing functor</summary>
        /// <remarks>
        /// This functor is responsible for processing incoming packets. Similar to the outgoing packet
        /// processing functor, it takes a handle to the adapter and a reference to the intermediate_buffer
        /// containing the packet data. It returns a packet_action struct to determine the packet's fate.
        /// </remarks>
        std::function<packet_action(HANDLE, intermediate_buffer&)> filter_incoming_packet_ = nullptr;

        /// <summary>working thread running status</summary>
        /// <remarks>
        /// This atomic variable represents the current state of the filter (e.g., stopped, starting, running, stopping).
        /// It is used to control the flow and termination of the packet processing threads.
        /// </remarks>
        std::atomic<filter_state> filter_state_ = filter_state::stopped;

        /// <summary>list of available network interfaces</summary>
        /// <remarks>
        /// This vector stores the network adapters available for packet filtering. It is populated at initialization
        /// and updated when network adapters change.
        /// </remarks>
        std::vector<network_adapter> network_interfaces_;

        /// <summary>reading thread object</summary>
        /// <remarks>
        /// This thread is responsible for reading packets from the network adapters. It places the packets into
        /// the packet_read_queue_ for further processing.
        /// </remarks>
        std::thread packet_read_thread_;

        /// <summary>processing thread object</summary>
        /// <remarks>
        /// This thread takes packets from the packet_read_queue_, processes them according to the filter rules,
        /// and then routes them to either the packet_write_mstcp_queue_ or packet_write_adapter_queue_.
        /// </remarks>
        std::thread packet_process_thread_;

        /// <summary>writing to mstcp thread object</summary>
        /// <remarks>
        /// This thread is responsible for writing packets back to the MSTCP stack. It takes processed packets from
        /// the packet_write_mstcp_queue_ and sends them up the protocol stack.
        /// </remarks>
        std::thread packet_write_mstcp_thread_;

        /// <summary>writing to adapter thread object</summary>
        /// <remarks>
        /// This thread handles writing packets directly to the network adapters. It takes processed packets from
        /// the packet_write_adapter_queue_ and sends them out on the network.
        /// </remarks>
        std::thread packet_write_adapter_thread_;

        /// <summary>filtered adapters</summary>
        /// <remarks>
        /// This set contains the names of network adapters that are currently being filtered. It is used to manage
        /// which adapters should have packet filtering applied.
        /// </remarks>
        std::set<std::string> filter_adapters_list_;

        /// <summary>packet in the adapter queue event</summary>
        /// <remarks>
        /// This event is signaled when there are packets in the adapter queue ready to be read. It is used to
        /// synchronize the packet reading thread.
        /// </remarks>
        netlib::winsys::safe_event packet_event_ =
            netlib::winsys::safe_event(::CreateEvent(nullptr, TRUE, FALSE, nullptr));

        /// <summary>adapter list change event</summary>
        /// <remarks>
        /// This event is signaled when the list of network adapters changes. It triggers the adapter_event_thread_
        /// to update the list of network interfaces and their filter states.
        /// </remarks>
        netlib::winsys::safe_event adapter_event_ =
            netlib::winsys::safe_event(::CreateEvent(nullptr, TRUE, FALSE, nullptr));

        /// <summary>thread to monitor adapter list change event</summary>
        /// <remarks>
        /// This thread waits for the adapter list change event to be signaled. Upon signaling, it updates the list
        /// of network interfaces and their filter states.
        /// </remarks>
        std::thread adapter_event_thread_;

        /// <summary>adapter list change event thread running condition</summary>
        /// <remarks>
        /// This atomic boolean controls the running state of the adapter_event_thread_. It is used to signal the
        /// thread to exit gracefully.
        /// </remarks>
        std::atomic_bool exit_adapter_event_thread_ = false;

        /// <summary>synchronization lock</summary>
        /// <remarks>
        /// This shared mutex is used to synchronize access to shared resources among multiple threads, particularly
        /// when updating the list of network interfaces and their filter states.
        /// </remarks>
        std::shared_mutex lock_;

        /**
         * @brief Queues for managing packets at different stages of processing.
         *
         * These queues hold unique pointers to @ref unsorted_packet_block objects, which
         * represent batches of packets. Each queue corresponds to a specific stage in the
         * packet processing pipeline:
         * - @c packet_read_queue_: Holds packet blocks ready to be filled with packets read from adapters.
         * - @c packet_process_queue_: Holds packet blocks that have been read and are ready for filtering/processing.
         * - @c packet_write_mstcp_queue_: Holds packet blocks ready to be written up to the MSTCP stack.
         * - @c packet_write_adapter_queue_: Holds packet blocks ready to be written out to network adapters.
         */
        std::queue<std::unique_ptr<unsorted_packet_block<maximum_packet_block>>> packet_read_queue_;
        std::queue<std::unique_ptr<unsorted_packet_block<maximum_packet_block>>> packet_process_queue_;
        std::queue<std::unique_ptr<unsorted_packet_block<maximum_packet_block>>> packet_write_mstcp_queue_;
        std::queue<std::unique_ptr<unsorted_packet_block<maximum_packet_block>>> packet_write_adapter_queue_;

        /**
         * @brief Condition variables for synchronizing packet processing threads.
         *
         * Each condition variable is associated with a corresponding queue and is used to
         * notify worker threads when new packet blocks are available for processing or when
         * the state of the queue changes.
         */
        std::condition_variable packet_read_queue_cv_;
        std::condition_variable packet_process_queue_cv_;
        std::condition_variable packet_write_mstcp_queue_cv_;
        std::condition_variable packet_write_adapter_queue_cv_;

        /**
         * @brief Mutexes for protecting access to the packet queues.
         *
         * Each mutex guards a specific queue to ensure thread-safe access and modification
         * by multiple worker threads operating concurrently in the packet processing pipeline.
         */
        std::mutex packet_read_queue_lock_;
        std::mutex packet_process_queue_lock_;
        std::mutex packet_write_mstcp_queue_lock_;
        std::mutex packet_write_adapter_queue_lock_;
    };

    /// <summary>
    /// Updates the filter state of network adapters.
    /// </summary>
    /// <remarks>
    /// Iterates through the list of network interfaces and updates their filter state based on whether they are
    /// included in the filter_adapters_list_. For adapters in the list, it sets the packet event and mode
    /// to enable packet filtering based on the configured incoming and outgoing packet handlers.
    /// For adapters not in the list, it clears the packet event and mode, effectively disabling packet filtering.
    /// </remarks>
    inline void queued_multi_interface_packet_filter::update_adapters_filter_state() const
    {
        for (auto&& adapter : network_interfaces_)
        {
            if (get_filter_state() == filter_state::running && 
                filter_adapters_list_.contains(adapter.get_internal_name()))
            {
                std::ignore = adapter.set_packet_event(packet_event_.get());
                std::ignore = adapter.set_mode(
                    (filter_outgoing_packet_ != nullptr ? MSTCP_FLAG_SENT_TUNNEL : 0) |
                    (filter_incoming_packet_ != nullptr ? MSTCP_FLAG_RECV_TUNNEL : 0));
            }
            else
            {
                std::ignore = adapter.set_packet_event(nullptr);
                std::ignore = adapter.set_mode(0);
            }
        }
    }

    /// <summary>
    /// Initializes the packet filter by allocating packet blocks.
    /// </summary>
    /// <returns>True if initialization succeeds, false if it fails due to memory allocation errors.</returns>
    /// <remarks>
    /// This method attempts to allocate a predefined number of packet blocks for the packet read queue.
    /// If memory allocation fails at any point, it cleans up any previously allocated blocks and returns false.
    /// This ensures that the system does not partially initialize, which could lead to undefined behavior.
    /// </remarks>
    inline bool queued_multi_interface_packet_filter::init_filter()
    {
        // Allocate packets blocks
        try
        {
            for (uint32_t i = 0; i < maximum_block_num; ++i)
            {
                auto packet_block_ptr = std::make_unique<unsorted_packet_block<maximum_packet_block>>();
                packet_read_queue_.push(std::move(packet_block_ptr));
            }
        }
        catch (const std::bad_alloc&)
        {
            // In case of bad_alloc, clear the queue to release already allocated blocks before returning false
            while (!packet_read_queue_.empty()) packet_read_queue_.pop();
            return false;
        }

        return true;
    }

    /// <summary>
    /// Releases resources and stops all working threads associated with the filter.
    /// </summary>
    /// <remarks>
    /// This method signals all event objects to wake up any waiting threads, releases network interfaces,
    /// and notifies all condition variables to ensure that all working threads can exit gracefully.
    /// It then joins all threads to ensure they have finished execution. Finally, it clears all packet queues
    /// to release any remaining resources.
    /// </remarks>
    inline void queued_multi_interface_packet_filter::release_filter()
    {
        std::ignore = packet_event_.signal();

        {
            std::shared_lock lock(lock_);
            for (auto&& adapter : network_interfaces_)
            {
                adapter.release();
            }
        }

        packet_read_queue_cv_.notify_all();
        packet_process_queue_cv_.notify_all();
        packet_write_mstcp_queue_cv_.notify_all();
        packet_write_adapter_queue_cv_.notify_all();

        // Wait for working threads to exit
        if (packet_read_thread_.joinable())
            packet_read_thread_.join();
        if (packet_process_thread_.joinable())
            packet_process_thread_.join();
        if (packet_write_mstcp_thread_.joinable())
            packet_write_mstcp_thread_.join();
        if (packet_write_adapter_thread_.joinable())
            packet_write_adapter_thread_.join();

        while (!packet_read_queue_.empty())
        {
            packet_read_queue_.pop();
        }

        while (!packet_process_queue_.empty())
        {
            packet_process_queue_.pop();
        }

        while (!packet_write_mstcp_queue_.empty())
        {
            packet_write_mstcp_queue_.pop();
        }

        while (!packet_write_adapter_queue_.empty())
        {
            packet_write_adapter_queue_.pop();
        }
    }

    /// <summary>
    /// Handles changes in the network adapter configuration.
    /// </summary>
    /// <remarks>
    /// This method is invoked when the list of network adapters changes (e.g., an adapter is added or removed).
    /// It locks the current context to prevent concurrent access, clears the existing list of network interfaces,
    /// re-initializes the list of network interfaces by querying the current system state, and updates the filter
    /// state for each adapter based on the current filter configuration. This ensures that the packet filter
    /// dynamically adapts to changes in the network configuration.
    /// </remarks>
    inline void queued_multi_interface_packet_filter::on_network_adapter_change()
    {
        std::lock_guard lock(lock_);

        network_interfaces_.clear();

        initialize_network_interfaces();

        update_adapters_filter_state();
    }

    /// <summary>
    /// Filters network traffic for a specified network adapter.
    /// </summary>
    /// <param name="name">The name of the network adapter to filter.</param>
    /// <remarks>
    /// This method adds the specified network adapter to the list of adapters to be filtered.
    /// It then updates the filter state for all adapters to apply the new configuration.
    /// This is achieved by locking the current context to prevent concurrent access,
    /// inserting the adapter name into the filter_adapters_list_, and calling update_adapters_filter_state()
    /// to apply the filtering rules to the specified adapter.
    /// </remarks>
    inline void queued_multi_interface_packet_filter::filter_network_adapter(const std::string& name)
    {
        std::lock_guard lock(lock_);
        filter_adapters_list_.insert(name);
        update_adapters_filter_state();
    }

    /// <summary>
     /// Removes the specified network adapter from the filter list.
     /// </summary>
     /// <param name="name">The name of the network adapter to remove from the filter list.</param>
     /// <remarks>
     /// This method removes the specified network adapter from the list of adapters to be filtered.
     /// It then updates the filter state for all adapters to apply the new configuration.
     /// This is achieved by locking the current context to prevent concurrent access,
     /// erasing the adapter name from the filter_adapters_list_, and calling update_adapters_filter_state()
     /// to refresh the filtering rules across all adapters.
     /// </remarks>
    inline void queued_multi_interface_packet_filter::unfilter_network_adapter(const std::string& name)
    {
        std::lock_guard lock(lock_);
        filter_adapters_list_.erase(name);
        update_adapters_filter_state();
    }

    /// <summary>
    /// Retrieves a list of currently filtered network adapters.
    /// </summary>
    /// <returns>A vector of strings, each representing the name of a filtered network adapter.</returns>
    /// <remarks>
    /// This method acquires a shared lock to safely access the filter_adapters_list_ set,
    /// then copies its contents into a vector of strings which is returned. This vector contains
    /// the names of all network adapters currently subject to filtering.
    /// </remarks>
    inline std::vector<std::string> queued_multi_interface_packet_filter::get_filtered_adapters()
    {
        std::shared_lock lock(lock_);
        return { filter_adapters_list_.begin(), filter_adapters_list_.end() };
    }

    /// <summary>
    /// Starts the packet filtering process.
    /// </summary>
    /// <returns>True if the filter was successfully started, false otherwise.</returns>
    /// <remarks>
    /// This method initiates the packet filtering process. It first checks if the filter is already running
    /// and returns false if so. Otherwise, it sets the filter state to 'starting'.
    /// 
    /// It then locks the shared resources to safely update the filter adapters list. If the list is empty,
    /// it adds all available network adapters to the filter list. After updating the filter adapters list,
    /// it calls update_adapters_filter_state() to apply the filter settings to the adapters.
    /// 
    /// If the initialization of the filter is successful, it changes the filter state to 'running' and
    /// starts the packet processing threads: packet_read_thread_, packet_process_thread_,
    /// packet_write_mstcp_thread_, and packet_write_adapter_thread_. If the initialization fails,
    /// it returns false.
    /// </remarks>
    inline bool queued_multi_interface_packet_filter::start_filter()
    {
        if (filter_state_ != filter_state::stopped)
            return false;

        filter_state_ = filter_state::starting;

        std::lock_guard lock(lock_);

        // If no adapters in the filter list, add all available adapters
        if (filter_adapters_list_.empty())
        {
            for (auto&& adapter : network_interfaces_)
            {
                filter_adapters_list_.insert(adapter.get_internal_name());
            }
        }

        if (init_filter())
        {
            filter_state_ = filter_state::running;
            packet_read_thread_ = std::thread(&queued_multi_interface_packet_filter::packet_read_thread, this);
            packet_process_thread_ = std::thread(&queued_multi_interface_packet_filter::packet_process_thread, this);
            packet_write_mstcp_thread_ = std::thread(&queued_multi_interface_packet_filter::packet_write_mstcp_thread, this);
            packet_write_adapter_thread_ = std::thread(&queued_multi_interface_packet_filter::packet_write_adapter_thread, this);
        }
        else
        {
            filter_state_ = filter_state::stopped;
        }

        update_adapters_filter_state();

        return filter_state_ == filter_state::running;
    }

    /// <summary>
    /// Stops the packet filtering process.
    /// </summary>
    /// <returns>True if the filter was successfully stopped, false otherwise.</returns>
    /// <remarks>
    /// This method stops the packet filtering process if it is currently running. It sets the filter state to 'stopping',
    /// calls release_filter() to clean up resources, and then sets the filter state to 'stopped'. If the filter is not
    /// in the 'running' state when this method is called, it returns false.
    /// </remarks>
    inline bool queued_multi_interface_packet_filter::stop_filter()
    {
        if (filter_state_ != filter_state::running)
            return false;

        filter_state_ = filter_state::stopping;

        release_filter();

        filter_state_ = filter_state::stopped;

        return true;
    }

    /// <summary>
    /// Retrieves the list of all network interfaces available for packet filtering.
    /// </summary>
    /// <returns>A vector of network_adapter objects, each representing a network interface.</returns>
    /// <remarks>
    /// This method acquires a shared lock to safely access the network_interfaces_ vector,
    /// then returns a copy of it. This vector contains objects representing each network
    /// interface that can potentially be filtered.
    /// </remarks>
    inline std::vector<network_adapter> queued_multi_interface_packet_filter::get_interface_list()
    {
        std::shared_lock lock(lock_);
        return network_interfaces_;
    }

    /// <summary>
    /// Initializes the list of network interfaces by querying the system for all TCP/IP bound adapters.
    /// </summary>
    /// <remarks>
    /// This method populates the network_interfaces_ vector with information about each network adapter found.
    /// It uses the GetTcpipBoundAdaptersInfo API to retrieve the list of adapters and then converts their names
    /// from the internal Windows 2000 format to a more friendly format. Each adapter's information, including
    /// its handle, MAC address, name, friendly name, medium type, and MTU, is stored in a network_adapter object
    /// and added to the network_interfaces_ vector.
    /// </remarks>
    inline void queued_multi_interface_packet_filter::initialize_network_interfaces()
    {
        TCP_AdapterList ad_list;
        std::vector<char> friendly_name(MAX_PATH * 4);

        GetTcpipBoundAdaptersInfo(&ad_list);

        for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
        {
            ConvertWindows2000AdapterName(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i]),
                friendly_name.data(), static_cast<DWORD>(friendly_name.size()));

            network_interfaces_.emplace_back(
                this,
                ad_list.m_nAdapterHandle[i],
                ad_list.m_czCurrentAddress[i],
                std::string(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i])),
                std::string(friendly_name.data()),
                ad_list.m_nAdapterMediumList[i],
                ad_list.m_usMTU[i]);
        }
    }

    /// <summary>
    /// Executes the packet reading thread logic.
    /// </summary>
    /// <remarks>
    /// This method runs in a dedicated thread and is responsible for continuously reading packets from the network adapters.
    /// It waits for packets to be available in the packet_read_queue_. When packets are available, it moves them to the
    /// packet_process_queue_ for further processing. The method uses a condition variable to wait for packets efficiently
    /// and exits gracefully if the filter state changes from running to another state.
    /// </remarks>
    inline void queued_multi_interface_packet_filter::packet_read_thread()
    {
        while (filter_state_ == filter_state::running)
        {
            std::unique_ptr<unsorted_packet_block<maximum_packet_block>> packet_block_ptr;

            std::unique_lock lock(packet_read_queue_lock_);

            if (!packet_read_queue_.empty())
            {
                packet_block_ptr = std::move(packet_read_queue_.front());
                packet_read_queue_.pop();
            }
            else
            {
                packet_read_queue_cv_.wait(lock, [this]
                    {
                        return filter_state_ != filter_state::running || !packet_read_queue_.
                            empty();
                    });

                if (filter_state_ != filter_state::running)
                    return;

                packet_block_ptr = std::move(packet_read_queue_.front());
                packet_read_queue_.pop();
            }

            lock.unlock();

            auto& read_request = packet_block_ptr->get_read_request();
            do
            {
                std::ignore = packet_event_.wait(INFINITE);
                std::ignore = packet_event_.reset_event();
            } while (!ReadPacketsUnsorted(reinterpret_cast<PINTERMEDIATE_BUFFER*>(const_cast<intermediate_buffer**>(read_request.data())),
                (DWORD)read_request.size(),
                reinterpret_cast<PDWORD>(&packet_block_ptr->get_packets_success())) &&
                filter_state_ == filter_state::running);

            std::lock_guard lk(packet_process_queue_lock_);
            packet_process_queue_.push(std::move(packet_block_ptr));
            packet_process_queue_cv_.notify_one();
        }
    }

    /// <summary>
    /// Executes the packet processing thread logic.
    /// </summary>
    /// <remarks>
    /// This method runs in a dedicated thread and is responsible for processing packets that have been read from the network adapters.
    /// It waits for packets to be available in the packet_process_queue_. When packets are available, it processes them based on the
    /// filter rules defined by filter_incoming_packet_ and filter_outgoing_packet_ functors. Depending on the action determined by the
    /// filter rules, packets are routed to either the write_adapter_request or write_mstcp_request for further handling. The method
    /// uses a condition variable to wait for packets efficiently and exits gracefully if the filter state changes from running to another state.
    /// </remarks>
    inline void queued_multi_interface_packet_filter::packet_process_thread()
    {
        while (filter_state_ == filter_state::running)
        {
            std::unique_lock lock(packet_process_queue_lock_);

            packet_process_queue_cv_.wait(lock, [this]
                {
                    return filter_state_ != filter_state::running || !packet_process_queue_.
                        empty();
                });

            if (filter_state_ != filter_state::running)
                return;

            auto packet_block_ptr = std::move(packet_process_queue_.front());
            packet_process_queue_.pop();

            lock.unlock();

            auto& write_adapter_request = packet_block_ptr->get_write_adapter_request();
            auto& write_mstcp_request = packet_block_ptr->get_write_mstcp_request();

            for (size_t i = 0; i < packet_block_ptr->get_packets_success(); ++i)
            {
                auto action = packet_action(packet_action::action_type::pass);

                if ((*packet_block_ptr)[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
                {
                    if (filter_outgoing_packet_ != nullptr)
                        action = filter_outgoing_packet_((*packet_block_ptr)[i].m_hAdapter, (*packet_block_ptr)[i]);
                }
                else
                {
                    if (filter_incoming_packet_ != nullptr)
                        action = filter_incoming_packet_((*packet_block_ptr)[i].m_hAdapter, (*packet_block_ptr)[i]);
                }

                // Alter target interface if requested
                if (action.interface_handle)
                {
                    (*packet_block_ptr)[i].m_hAdapter = action.interface_handle.value();
                }

                // Place packet back into the flow if was allowed to
                if (action.action == packet_action::action_type::pass)
                {
                    if ((*packet_block_ptr)[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
                    {
                        write_adapter_request.push_back(&(*packet_block_ptr)[i]);
                    }
                    else
                    {
                        write_mstcp_request.push_back(&(*packet_block_ptr)[i]);
                    }
                }
                else if (action.action == packet_action::action_type::revert)
                {
                    if ((*packet_block_ptr)[i].m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE)
                    {
                        write_adapter_request.push_back(&(*packet_block_ptr)[i]);
                    }
                    else
                    {
                        write_mstcp_request.push_back(&(*packet_block_ptr)[i]);
                    }
                }
            }

            std::lock_guard lk(packet_write_mstcp_queue_lock_);
            packet_write_mstcp_queue_.push(std::move(packet_block_ptr));
            packet_write_mstcp_queue_cv_.notify_one();
        }
    }

    /// <summary>
    /// Executes the packet writing to MSTCP stack thread logic.
    /// </summary>
    /// <remarks>
    /// This method runs in a dedicated thread and is responsible for writing packets back to the MSTCP stack.
    /// It waits for packets to be available in the packet_write_mstcp_queue_. When packets are available, it processes them by
    /// sending them up the protocol stack using the SendPacketsToMstcpUnsorted function. The method uses a condition variable
    /// to wait for packets efficiently and exits gracefully if the filter state changes from running to another state. After
    /// packets are sent, they are moved to the packet_write_adapter_queue_ for further processing.
    /// </remarks>
    inline void queued_multi_interface_packet_filter::packet_write_mstcp_thread()
    {
        while (filter_state_ == filter_state::running)
        {
            std::unique_lock lock(packet_write_mstcp_queue_lock_);

            packet_write_mstcp_queue_cv_.wait(lock, [this]
                {
                    return filter_state_ != filter_state::running || !
                        packet_write_mstcp_queue_.empty();
                });

            if (filter_state_ != filter_state::running)
                return;

            auto packet_block_ptr = std::move(packet_write_mstcp_queue_.front());
            packet_write_mstcp_queue_.pop();

            lock.unlock();

            if (auto& write_mstcp_request = packet_block_ptr->get_write_mstcp_request(); !write_mstcp_request.empty())
            {
                uint32_t packets_sent = 0;
                SendPacketsToMstcpUnsorted(reinterpret_cast<PINTERMEDIATE_BUFFER*>(write_mstcp_request.data()),
                    static_cast<DWORD>(write_mstcp_request.size()), reinterpret_cast<PDWORD>(&packets_sent));
                write_mstcp_request.clear();
            }

            std::lock_guard lk(packet_write_adapter_queue_lock_);
            packet_write_adapter_queue_.push(std::move(packet_block_ptr));
            packet_write_adapter_queue_cv_.notify_one();
        }
    }

    /// <summary>
    /// Executes the packet writing to network adapter thread logic.
    /// </summary>
    /// <remarks>
    /// This method runs in a dedicated thread and is responsible for writing packets to the network adapters.
    /// It waits for packets to be available in the packet_write_adapter_queue_. When packets are available, it processes them by
    /// sending them to the network adapters using the SendPacketsToAdaptersUnsorted function. The method uses a condition variable
    /// to wait for packets efficiently and exits gracefully if the filter state changes from running to another state. After
    /// packets are sent, they are moved to the packet_read_queue_ for further processing.
    /// </remarks>
    inline void queued_multi_interface_packet_filter::packet_write_adapter_thread()
    {
        while (filter_state_ == filter_state::running)
        {
            std::unique_lock lock(packet_write_adapter_queue_lock_);

            packet_write_adapter_queue_cv_.wait(lock, [this]
                {
                    return filter_state_ != filter_state::running || !
                        packet_write_adapter_queue_.empty();
                });

            if (filter_state_ != filter_state::running)
                return;

            auto packet_block_ptr = std::move(packet_write_adapter_queue_.front());
            packet_write_adapter_queue_.pop();

            lock.unlock();

            if (auto& write_adapter_request = packet_block_ptr->get_write_adapter_request(); !write_adapter_request.empty())
            {
                uint32_t packets_sent = 0;
                SendPacketsToAdaptersUnsorted(reinterpret_cast<PINTERMEDIATE_BUFFER*>(write_adapter_request.data()),
                    static_cast<DWORD>(write_adapter_request.size()), reinterpret_cast<PDWORD>(&packets_sent));
                write_adapter_request.clear();
            }

            std::lock_guard lk(packet_read_queue_lock_);
            packet_read_queue_.push(std::move(packet_block_ptr));
            packet_read_queue_cv_.notify_one();
        }
    }
}
