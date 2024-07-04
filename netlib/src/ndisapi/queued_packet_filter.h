// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  queued_packet_filter.h 
/// Abstract: Simple packet filter class declaration
/// </summary>
// --------------------------------------------------------------------------------

#pragma once

namespace ndisapi
{
	template <uint32_t Size>
	class packet_block
	{
		using request_storage_type_t = std::aligned_storage_t<sizeof(ETH_M_REQUEST) +
		                                                      sizeof(NDISRD_ETH_Packet) * (Size - 1),
		                                                      0x1000>;

		/// <summary>array of ndisapi::intermediate_buffer structures</summary>
		std::unique_ptr<ndisapi::intermediate_buffer[]> packet_buffer_;
		/// <summary>driver request for reading packets</summary>
		std::unique_ptr<request_storage_type_t> read_request_ptr_;
		/// <summary>driver request for writing packets to adapter</summary>
		std::unique_ptr<request_storage_type_t> write_adapter_request_ptr_;
		/// <summary>driver request for writing packets up to protocol stack</summary>
		std::unique_ptr<request_storage_type_t> write_mstcp_request_ptr_;

	public:
		explicit packet_block(HANDLE adapter)
		{
			packet_buffer_ = std::make_unique<ndisapi::intermediate_buffer[]>(Size);

			read_request_ptr_ = std::make_unique<request_storage_type_t>();
			write_adapter_request_ptr_ = std::make_unique<request_storage_type_t>();
			write_mstcp_request_ptr_ = std::make_unique<request_storage_type_t>();

			auto* read_request = reinterpret_cast<PETH_M_REQUEST>(read_request_ptr_.get());
			auto* write_adapter_request = reinterpret_cast<PETH_M_REQUEST>(write_adapter_request_ptr_.get());
			auto* write_mstcp_request = reinterpret_cast<PETH_M_REQUEST>(write_mstcp_request_ptr_.get());

			read_request->hAdapterHandle = adapter;
			write_adapter_request->hAdapterHandle = adapter;
			write_mstcp_request->hAdapterHandle = adapter;

			read_request->dwPacketsNumber = Size;

			//
			// Initialize packet buffers
			//
			ZeroMemory(packet_buffer_.get(), sizeof(ndisapi::intermediate_buffer) * Size);

			for (unsigned i = 0; i < Size; ++i)
			{
				read_request->EthPacket[i].Buffer = &packet_buffer_[i];
			}
		}

		[[nodiscard]] PETH_M_REQUEST get_read_request() const
		{
			return reinterpret_cast<PETH_M_REQUEST>(read_request_ptr_.get());
		}

		[[nodiscard]] PETH_M_REQUEST get_write_adapter_request() const
		{
			return reinterpret_cast<PETH_M_REQUEST>(write_adapter_request_ptr_.get());
		}

		[[nodiscard]] PETH_M_REQUEST get_write_mstcp_request() const
		{
			return reinterpret_cast<PETH_M_REQUEST>(write_mstcp_request_ptr_.get());
		}

		ndisapi::intermediate_buffer& operator[](const std::size_t idx)
		{
			return packet_buffer_[idx];
		}

		const ndisapi::intermediate_buffer& operator[](const std::size_t idx) const
		{
			return packet_buffer_[idx];
		}
	};

	// --------------------------------------------------------------------------------
	/// <summary>
	/// simple winpkfilter based filter class for quick prototyping 
	/// </summary>
	// --------------------------------------------------------------------------------
	class queued_packet_filter final : public CNdisApi
	{
	public:
		enum class packet_action
		{
			pass,
			drop,
			revert
		};

	private:
		static constexpr uint32_t maximum_packet_block = 510;
		static constexpr uint32_t maximum_block_num = 10;

		queued_packet_filter()
		{
			if (!IsDriverLoaded())
				throw std::runtime_error("Windows Packet Filter driver is not available!");

			initialize_network_interfaces();
		}

	public:
		enum class filter_state
		{
			stopped,
			starting,
			running,
			stopping
		};

		~queued_packet_filter() override { stop_filter(); }

		queued_packet_filter(const queued_packet_filter& other) = delete;
		queued_packet_filter(queued_packet_filter&& other) noexcept = delete;
		queued_packet_filter& operator=(const queued_packet_filter& other) = delete;
		queued_packet_filter& operator=(queued_packet_filter&& other) noexcept = delete;

		// ********************************************************************************
		/// <summary>
		/// Constructs queued_packet_filter
		/// </summary>
		/// <param name="in">incoming packets handling routine</param>
		/// <param name="out">outgoing packet handling routine</param>
		/// <returns></returns>
		// ********************************************************************************
		template <typename F1, typename F2>
		queued_packet_filter(F1 in, F2 out) : queued_packet_filter()
		{
			filter_incoming_packet_ = in;
			filter_outgoing_packet_ = out;
		}

		// ********************************************************************************
		/// <summary>
		/// Updates available network interfaces. Should be called when the filter is inactive. 
		/// </summary>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool reconfigure();

		// ********************************************************************************
		/// <summary>
		/// Starts packet filtering
		/// </summary>
		/// <param name="adapter">network interface index to filter</param>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool start_filter(size_t adapter);

		// ********************************************************************************
		/// <summary>
		/// Stops packet filtering
		/// </summary>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool stop_filter();

		// ********************************************************************************
		/// <summary>
		/// Queries the list of the names for the available network interfaces
		/// </summary>
		/// <returns>list of network adapters friendly names</returns>
		// ********************************************************************************
		std::vector<std::string> get_interface_names_list() const;

		// ********************************************************************************
		/// <summary>
		/// Inserts a packet into the inbound network flow.
		/// This function creates a request with the packet data and sends it to the MSTCP.
		/// </summary>
		/// <param name="packet_data">The packet data to be inserted.</param>
		// ********************************************************************************
		void insert_packet_to_mstcp(const INTERMEDIATE_BUFFER& packet_data) const;

		// ********************************************************************************
		/// <summary>
		/// Inserts a packet into the outbound network flow.
		/// This function creates a request with the packet data and sends it to the network.
		/// </summary>
		/// <param name="packet_data">The packet data to be inserted.</param>
		// ********************************************************************************
		void insert_packet_to_adapter(const INTERMEDIATE_BUFFER& packet_data) const;

		// ********************************************************************************
		/// <summary>
		/// Queries the list of the available network interfaces
		/// </summary>
		/// <returns>vector of available network adapters</returns>
		// ********************************************************************************
		const std::vector<std::unique_ptr<network_adapter>>& get_interface_list() const;

		// ********************************************************************************
		/// <summary>
		/// Returns current filter state
		/// </summary>
		/// <returns>current filter state</returns>
		// ********************************************************************************
		[[nodiscard]] filter_state get_filter_state() const
		{
			return filter_state_.load();
		}

	private:
		// ********************************************************************************
		/// <summary>
		/// Reading thread routine
		/// </summary>
		// ********************************************************************************
		void packet_read_thread();

		// ********************************************************************************
		/// <summary>
		/// Processing thread routine
		/// </summary>
		// ********************************************************************************
		void packet_process_thread();

		// ********************************************************************************
		/// <summary>
		/// Writing to mstcp thread routine
		/// </summary>
		// ********************************************************************************
		void packet_write_mstcp_thread();

		// ********************************************************************************
		/// <summary>
		/// Writing to adapter thread routine
		/// </summary>
		// ********************************************************************************
		void packet_write_adapter_thread();

		// ********************************************************************************
		/// <summary>
		/// Initializes available network interface list
		/// </summary>
		// ********************************************************************************
		void initialize_network_interfaces();

		// ********************************************************************************
		/// <summary>
		/// Initialize interface and associated data structures required for packet filtering
		/// </summary>
		/// <returns>true is success, false otherwise</returns>
		// ********************************************************************************
		bool init_filter();

		// ********************************************************************************
		/// <summary>
		/// Release interface and associated data structures required for packet filtering
		/// </summary>
		// ********************************************************************************
		void release_filter();

		/// <summary>outgoing packet processing functor</summary>
		std::function<packet_action(HANDLE, ndisapi::intermediate_buffer&)> filter_outgoing_packet_ = nullptr;
		/// <summary>incoming packet processing functor</summary>
		std::function<packet_action(HANDLE, ndisapi::intermediate_buffer&)> filter_incoming_packet_ = nullptr;
		/// <summary>working thread running status</summary>
		std::atomic<filter_state> filter_state_ = filter_state::stopped;
		/// <summary>list of available network interfaces</summary>
		std::vector<std::unique_ptr<network_adapter>> network_interfaces_;

		/// <summary>reading thread object</summary>
		std::thread packet_read_thread_;
		/// <summary>processing thread object</summary>
		std::thread packet_process_thread_;
		/// <summary>writing to mstcp thread object</summary>
		std::thread packet_write_mstcp_thread_;
		/// <summary>writing to adapter thread object</summary>
		std::thread packet_write_adapter_thread_;

		/// <summary>filtered adapter index</summary>
		size_t adapter_{0};

		std::queue<std::unique_ptr<packet_block<maximum_packet_block>>> packet_read_queue_;
		std::queue<std::unique_ptr<packet_block<maximum_packet_block>>> packet_process_queue_;
		std::queue<std::unique_ptr<packet_block<maximum_packet_block>>> packet_write_mstcp_queue_;
		std::queue<std::unique_ptr<packet_block<maximum_packet_block>>> packet_write_adapter_queue_;

		std::condition_variable packet_read_queue_cv_;
		std::condition_variable packet_process_queue_cv_;
		std::condition_variable packet_write_mstcp_queue_cv_;
		std::condition_variable packet_write_adapter_queue_cv_;

		std::mutex packet_read_queue_lock_;
		std::mutex packet_process_queue_lock_;
		std::mutex packet_write_mstcp_queue_lock_;
		std::mutex packet_write_adapter_queue_lock_;
	};

	inline bool queued_packet_filter::init_filter()
	{
		try
		{
			for (uint32_t i = 0; i < maximum_block_num; ++i)
			{
				auto packet_block_ptr = std::make_unique<packet_block<maximum_packet_block>>(
					network_interfaces_[adapter_]->get_adapter());
				packet_read_queue_.push(std::move(packet_block_ptr));
			}
		}
		catch (const std::bad_alloc&)
		{
			return false;
		}

		//
		// Set events for helper driver
		//
		if (!network_interfaces_[adapter_]->set_packet_event())
		{
			while (!packet_read_queue_.empty())
			{
				packet_read_queue_.pop();
			}

			return false;
		}

		network_interfaces_[adapter_]->set_mode(
			(filter_outgoing_packet_ != nullptr ? MSTCP_FLAG_SENT_TUNNEL : 0) |
			(filter_incoming_packet_ != nullptr ? MSTCP_FLAG_RECV_TUNNEL : 0));

		return true;
	}

	inline void queued_packet_filter::release_filter()
	{
		network_interfaces_[adapter_]->release();

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

	inline bool queued_packet_filter::reconfigure()
	{
		if (filter_state_ != filter_state::stopped)
			return false;

		network_interfaces_.clear();

		initialize_network_interfaces();

		return true;
	}

	inline bool queued_packet_filter::start_filter(const size_t adapter)
	{
		if (filter_state_ != filter_state::stopped)
			return false;

		filter_state_ = filter_state::starting;

		adapter_ = adapter;

		if (init_filter())
		{
			filter_state_ = filter_state::running;
			packet_read_thread_ = std::thread(&queued_packet_filter::packet_read_thread, this);
			packet_process_thread_ = std::thread(&queued_packet_filter::packet_process_thread, this);
			packet_write_mstcp_thread_ = std::thread(&queued_packet_filter::packet_write_mstcp_thread, this);
			packet_write_adapter_thread_ = std::thread(&queued_packet_filter::packet_write_adapter_thread, this);
		}
		else
			return false;

		return true;
	}

	inline bool queued_packet_filter::stop_filter()
	{
		if (filter_state_ != filter_state::running)
			return false;

		filter_state_ = filter_state::stopping;

		release_filter();

		filter_state_ = filter_state::stopped;

		return true;
	}

	inline std::vector<std::string> queued_packet_filter::get_interface_names_list() const
	{
		std::vector<std::string> result;
		result.reserve(network_interfaces_.size());

		for (auto&& e : network_interfaces_)
		{
			result.push_back(e->get_friendly_name());
		}

		return result;
	}

	inline const std::vector<std::unique_ptr<network_adapter>>& queued_packet_filter::get_interface_list() const
	{
		return network_interfaces_;
	}

	inline void queued_packet_filter::initialize_network_interfaces()
	{
		TCP_AdapterList ad_list;
		std::vector<char> friendly_name(MAX_PATH * 4);

		GetTcpipBoundAdaptersInfo(&ad_list);

		for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
		{
			ConvertWindows2000AdapterName(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i]),
			                              friendly_name.data(), static_cast<DWORD>(friendly_name.size()));

			network_interfaces_.push_back(
				std::make_unique<network_adapter>(
					this,
					ad_list.m_nAdapterHandle[i],
					ad_list.m_czCurrentAddress[i],
					std::string(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i])),
					std::string(friendly_name.data()),
					ad_list.m_nAdapterMediumList[i],
					ad_list.m_usMTU[i]));
		}
	}
	
	inline void queued_packet_filter::insert_packet_to_mstcp(const INTERMEDIATE_BUFFER& packet_data) const
	{
		ETH_REQUEST request{
			network_interfaces_[adapter_]->get_adapter(),
			NDISRD_ETH_Packet
			{
				const_cast<INTERMEDIATE_BUFFER*>(&packet_data)
			} };

		SendPacketToMstcp(&request);
	}

	inline void queued_packet_filter::insert_packet_to_adapter(const INTERMEDIATE_BUFFER& packet_data) const
	{
		ETH_REQUEST request{
			network_interfaces_[adapter_]->get_adapter(),
			NDISRD_ETH_Packet
			{
				const_cast<INTERMEDIATE_BUFFER*>(&packet_data)
			} };

		SendPacketToAdapter(&request);
	}

	inline void queued_packet_filter::packet_read_thread()
	{
		while (filter_state_ == filter_state::running)
		{
			std::unique_ptr<packet_block<maximum_packet_block>> packet_block_ptr;

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

			auto* read_request = packet_block_ptr->get_read_request();

			do
			{
				[[maybe_unused]] auto wait_result = network_interfaces_[adapter_]->wait_event(INFINITE);

				[[maybe_unused]] auto reset_result = network_interfaces_[adapter_]->reset_event();
			}
			while (!ReadPackets(read_request) && filter_state_ == filter_state::running);

			std::lock_guard lk(packet_process_queue_lock_);
			packet_process_queue_.push(std::move(packet_block_ptr));
			packet_process_queue_cv_.notify_one();
		}
	}

	inline void queued_packet_filter::packet_process_thread()
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

			auto* read_request = packet_block_ptr->get_read_request();
			auto* write_adapter_request = packet_block_ptr->get_write_adapter_request();
			auto* write_mstcp_request = packet_block_ptr->get_write_mstcp_request();

			for (size_t i = 0; i < read_request->dwPacketsSuccess; ++i)
			{
				auto packet_action = packet_action::pass;

				if ((*packet_block_ptr)[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
				{
					if (filter_outgoing_packet_ != nullptr)
						packet_action = filter_outgoing_packet_(read_request->hAdapterHandle, (*packet_block_ptr)[i]);
				}
				else
				{
					if (filter_incoming_packet_ != nullptr)
						packet_action = filter_incoming_packet_(read_request->hAdapterHandle, (*packet_block_ptr)[i]);
				}

				// Place packet back into the flow if was allowed to
				if (packet_action == packet_action::pass)
				{
					if ((*packet_block_ptr)[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
					{
						write_adapter_request->EthPacket[write_adapter_request->dwPacketsNumber].Buffer = &
							(*packet_block_ptr)[i];
						++write_adapter_request->dwPacketsNumber;
					}
					else
					{
						write_mstcp_request->EthPacket[write_mstcp_request->dwPacketsNumber].Buffer = &
							(*packet_block_ptr)[i];
						++write_mstcp_request->dwPacketsNumber;
					}
				}
				else if (packet_action == packet_action::revert)
				{
					if ((*packet_block_ptr)[i].m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE)
					{
						write_adapter_request->EthPacket[write_adapter_request->dwPacketsNumber].Buffer = &
							(*packet_block_ptr)[i];
						++write_adapter_request->dwPacketsNumber;
					}
					else
					{
						write_mstcp_request->EthPacket[write_mstcp_request->dwPacketsNumber].Buffer = &
							(*packet_block_ptr)[i];
						++write_mstcp_request->dwPacketsNumber;
					}
				}
			}

			read_request->dwPacketsSuccess = 0;

			std::lock_guard lk(packet_write_mstcp_queue_lock_);
			packet_write_mstcp_queue_.push(std::move(packet_block_ptr));
			packet_write_mstcp_queue_cv_.notify_one();
		}
	}

	inline void queued_packet_filter::packet_write_mstcp_thread()
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

			if (auto* write_mstcp_request = packet_block_ptr->get_write_mstcp_request(); write_mstcp_request->
				dwPacketsNumber)
			{
				SendPacketsToMstcp(write_mstcp_request);
				write_mstcp_request->dwPacketsNumber = 0;
			}

			std::lock_guard lk(packet_write_adapter_queue_lock_);
			packet_write_adapter_queue_.push(std::move(packet_block_ptr));
			packet_write_adapter_queue_cv_.notify_one();
		}
	}

	inline void queued_packet_filter::packet_write_adapter_thread()
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

			if (auto* write_adapter_request = packet_block_ptr->get_write_adapter_request(); write_adapter_request->
				dwPacketsNumber)
			{
				SendPacketsToAdapter(write_adapter_request);
				write_adapter_request->dwPacketsNumber = 0;
			}

			std::lock_guard lk(packet_read_queue_lock_);
			packet_read_queue_.push(std::move(packet_block_ptr));
			packet_read_queue_cv_.notify_one();
		}
	}
}
