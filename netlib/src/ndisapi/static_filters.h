#pragma once

namespace ndisapi
{
	enum class action_t
	{
		pass,
		drop,
		redirect,
		pass_redirect,
		drop_redirect
	};

	enum class direction_t
	{
		in,
		out,
		both
	};

	template <typename T>
	class filter
	{
		/// <summary>network interface index</summary>
		std::optional<size_t> if_index_ = std::nullopt;
		/// <summary>source MAC address</summary>
		std::optional<net::mac_address> source_hw_address_ = std::nullopt;
		/// <summary>destination MAC address</summary>
		std::optional<net::mac_address> dest_hw_address_ = std::nullopt;
		/// <summary>Ethernet type</summary>
		std::optional<uint16_t> ether_type_ = std::nullopt;
		/// <summary>source IP address</summary>
		std::optional<net::ip_subnet<T>> source_address_ = std::nullopt;
		/// <summary>destination IP address</summary>
		std::optional<net::ip_subnet<T>> dest_address_ = std::nullopt;
		/// <summary>source port (TCP/UDP only)</summary>
		std::optional<std::pair<uint16_t, uint16_t>> source_port_ = std::nullopt;
		/// <summary>destination port (TCP/UDP only)</summary>
		std::optional<std::pair<uint16_t, uint16_t>> dest_port_ = std::nullopt;
		/// <summary>IP protocol</summary>
		std::optional<uint8_t> protocol_ = std::nullopt;
		/// <summary>packet direction</summary>
		direction_t direction_ = direction_t::both;
		/// <summary>filter action</summary>
		action_t action_ = action_t::pass;

	public:
		filter() = default;

		[[nodiscard]] direction_t get_direction() const
		{
			return direction_;
		}

		filter& set_direction(const direction_t direction)
		{
			direction_ = direction;
			return *this;
		}

		[[nodiscard]] action_t get_action() const
		{
			return action_;
		}

		filter& set_action(const action_t action)
		{
			action_ = action;
			return *this;
		}

		[[nodiscard]] std::optional<size_t> get_if_index() const
		{
			return if_index_;
		}

		filter& set_if_index(const size_t if_index)
		{
			if_index_ = if_index;
			return *this;
		}

		[[nodiscard]] std::optional<net::mac_address> get_source_hw_address() const
		{
			return source_hw_address_;
		}

		filter& set_source_hw_address(const net::mac_address& source_address)
		{
			source_hw_address_ = source_address;
			return *this;
		}

		[[nodiscard]] std::optional<net::mac_address> get_dest_hw_address() const
		{
			return dest_hw_address_;
		}

		filter& set_dest_hw_address(const net::mac_address& dest_address)
		{
			dest_hw_address_ = dest_address;
			return *this;
		}

		[[nodiscard]] std::optional<uint16_t> get_ether_type() const
		{
			return ether_type_;
		}

		filter& set_ether_type(const uint16_t ether_type)
		{
			ether_type_ = ether_type;
			return *this;
		}

		[[nodiscard]] std::optional<net::ip_subnet<T>> get_source_address() const
		{
			return source_address_;
		}

		filter& set_source_address(const net::ip_subnet<T>& source_address)
		{
			source_address_ = source_address;
			return *this;
		}

		[[nodiscard]] std::optional<net::ip_subnet<T>> get_dest_address() const
		{
			return dest_address_;
		}

		filter& set_dest_address(const net::ip_subnet<T>& dest_address)
		{
			dest_address_ = dest_address;
			return *this;
		}

		[[nodiscard]] std::optional<std::pair<uint16_t, uint16_t>> get_source_port() const
		{
			return source_port_;
		}

		filter& set_source_port(const std::pair<uint16_t, uint16_t>& source_port)
		{
			source_port_ = source_port;
			return *this;
		}

		[[nodiscard]] std::optional<std::pair<uint16_t, uint16_t>> get_dest_port() const
		{
			return dest_port_;
		}

		filter& set_dest_port(const std::pair<uint16_t, uint16_t>& dest_port)
		{
			dest_port_ = dest_port;
			return *this;
		}

		[[nodiscard]] std::optional<uint8_t> get_protocol() const
		{
			return protocol_;
		}

		filter& set_protocol(const uint8_t protocol)
		{
			protocol_ = protocol;
			return *this;
		}
	};

	class static_filters final : public CNdisApi
	{
	public:
		static static_filters& get_instance(const action_t action = action_t::redirect, std::optional<std::reference_wrapper<std::osyncstream>> log_stream = std::nullopt)
		{
			static static_filters instance(action, log_stream); // Guaranteed to be destroyed.
			return instance;
		}

		static_filters(const static_filters& other) = delete;
		static_filters(static_filters&& other) noexcept = default;
		static_filters& operator=(const static_filters& other) = delete;
		static_filters& operator=(static_filters&& other) noexcept = default;
		~static_filters() override = default;

		template <typename T>
		static_filters& add_filter(const filter<T>& filter)
		{
			filters_.emplace_back(filter);
			return *this;
		}

		bool apply()
		{
			try
			{
				const size_t filter_size = filters_.size();
				const auto table_buffer = std::make_unique<uint8_t[]>(sizeof(STATIC_FILTER_TABLE) + sizeof(STATIC_FILTER) * filter_size);
				auto* filter_list = reinterpret_cast<PSTATIC_FILTER_TABLE>(table_buffer.get());
				memset(filter_list, 0, sizeof(STATIC_FILTER_TABLE) + sizeof(STATIC_FILTER) * filter_size);

				filter_list->m_TableSize = static_cast<uint32_t>(filter_size + 1);

				for (size_t i = 0; i < filter_size; ++i)
				{
					std::visit([this, &i, &filter_list](auto&& arg)
						{
							to_static_filter(arg, filter_list->m_StaticFilters[i]);
						}, filters_[i]);
				}

				// Set the default rule
				set_default_action(filter_list->m_StaticFilters[filter_size]);

				SetPacketFilterTable(filter_list);

				return true;
			}
			catch (const std::exception& e)
			{
				if (log_stream_)
				{
					log_stream_.value().get() << "Exception: " << e.what() << std::endl;
				}
				return false;
			}
		}

		void reset()
		{
			SetPacketFilterTable(nullptr);
			network_interfaces_.clear();
			initialize_network_interfaces();
		}

	private:
		explicit static_filters(const action_t action, std::optional<std::reference_wrapper<std::osyncstream>> log_stream = std::nullopt)
			: default_action_{ action }, log_stream_{ log_stream }
		{
			if (!IsDriverLoaded())
			{
				const char* error_message = "Windows Packet Filter driver is not available!";
				if (log_stream_)
				{
					log_stream_.value().get() << error_message << std::endl;
				}
				throw std::runtime_error(error_message);
			}

			initialize_network_interfaces();
		}

		void initialize_network_interfaces()
		{
			TCP_AdapterList ad_list;
			std::vector<char> friendly_name(MAX_PATH * 4);

			GetTcpipBoundAdaptersInfo(&ad_list);

			for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
			{
				ConvertWindows2000AdapterName(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i]),
					friendly_name.data(), static_cast<DWORD>(friendly_name.size()));

				network_interfaces_.emplace_back(
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

		template <typename T>
		void to_static_filter(const filter<T>& filter, STATIC_FILTER& static_filter)
		{
			if (auto index = filter.get_if_index(); index.has_value())
				static_filter.m_Adapter.QuadPart = reinterpret_cast<ULONG_PTR>(network_interfaces_.at(index.value())->get_adapter());
			else
				static_filter.m_Adapter.QuadPart = 0;

			switch (filter.get_direction())
			{
			case direction_t::in:
				static_filter.m_dwDirectionFlags = PACKET_FLAG_ON_RECEIVE;
				break;
			case direction_t::out:
				static_filter.m_dwDirectionFlags = PACKET_FLAG_ON_SEND;
				break;
			case direction_t::both:
				static_filter.m_dwDirectionFlags = PACKET_FLAG_ON_SEND | PACKET_FLAG_ON_RECEIVE;
				break;
			}

			switch (filter.get_action())
			{
			case action_t::pass:
				static_filter.m_FilterAction = FILTER_PACKET_PASS;
				break;
			case action_t::drop:
				static_filter.m_FilterAction = FILTER_PACKET_DROP;
				break;
			case action_t::redirect:
				static_filter.m_FilterAction = FILTER_PACKET_REDIRECT;
				break;
			case action_t::pass_redirect:
				static_filter.m_FilterAction = FILTER_PACKET_PASS_RDR;
				break;
			case action_t::drop_redirect:
				static_filter.m_FilterAction = FILTER_PACKET_DROP_RDR;
				break;
			}

			if (filter.get_source_hw_address() || filter.get_dest_hw_address() || filter.get_ether_type())
			{
				static_filter.m_ValidFields |= DATA_LINK_LAYER_VALID;
				static_filter.m_DataLinkFilter.m_dwUnionSelector = ETH_802_3;

				if (auto source_hw_address = filter.get_source_hw_address(); source_hw_address.has_value())
				{
					static_filter.m_DataLinkFilter.m_Eth8023Filter.m_ValidFields |= ETH_802_3_SRC_ADDRESS;
					memcpy(static_filter.m_DataLinkFilter.m_Eth8023Filter.m_SrcAddress,
						source_hw_address.value().get_data().data(), ETHER_ADDR_LENGTH);
				}

				if (auto dest_hw_address = filter.get_dest_hw_address(); dest_hw_address.has_value())
				{
					static_filter.m_DataLinkFilter.m_Eth8023Filter.m_ValidFields |= ETH_802_3_DEST_ADDRESS;
					memcpy(static_filter.m_DataLinkFilter.m_Eth8023Filter.m_DestAddress,
						dest_hw_address.value().get_data().data(), ETHER_ADDR_LENGTH);
				}

				if (auto ether_type = filter.get_ether_type(); ether_type.has_value())
				{
					static_filter.m_DataLinkFilter.m_Eth8023Filter.m_ValidFields |= ETH_802_3_PROTOCOL;
					static_filter.m_DataLinkFilter.m_Eth8023Filter.m_Protocol = ether_type.value();
				}
			}

			if (filter.get_source_address() || filter.get_dest_address() || filter.get_protocol())
			{
				static_filter.m_ValidFields |= NETWORK_LAYER_VALID;
				if constexpr (std::is_same_v<T, net::ip_address_v4>)
				{
					static_filter.m_NetworkFilter.m_dwUnionSelector = IPV4;
				}
				else if constexpr (std::is_same_v<T, net::ip_address_v6>)
				{
					static_filter.m_NetworkFilter.m_dwUnionSelector = IPV6;
				}

				if (auto source_address = filter.get_source_address(); source_address.has_value())
				{
					if constexpr (std::is_same_v<T, net::ip_address_v4>)
					{
						static_filter.m_NetworkFilter.m_IPv4.m_ValidFields |= IP_V4_FILTER_SRC_ADDRESS;
						static_filter.m_NetworkFilter.m_IPv4.m_SrcAddress.m_AddressType = IP_SUBNET_V4_TYPE;
						static_filter.m_NetworkFilter.m_IPv4.m_SrcAddress.m_IpSubnet.m_Ip = source_address.value().get_address().S_un.S_addr;
						static_filter.m_NetworkFilter.m_IPv4.m_SrcAddress.m_IpSubnet.m_IpMask = source_address.value().get_mask().S_un.S_addr;
					}
					else if constexpr (std::is_same_v<T, net::ip_address_v6>)
					{
						static_filter.m_NetworkFilter.m_IPv6.m_ValidFields |= IP_V6_FILTER_SRC_ADDRESS;
						static_filter.m_NetworkFilter.m_IPv6.m_SrcAddress.m_AddressType = IP_SUBNET_V6_TYPE;
						static_filter.m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpSubnet.m_Ip = source_address.value().get_address();
						static_filter.m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpSubnet.m_IpMask = source_address.value().get_mask();
					}
				}

				if (auto dest_address = filter.get_dest_address(); dest_address.has_value())
				{
					if constexpr (std::is_same_v<T, net::ip_address_v4>)
					{
						static_filter.m_NetworkFilter.m_IPv4.m_ValidFields |= IP_V4_FILTER_DEST_ADDRESS;
						static_filter.m_NetworkFilter.m_IPv4.m_DestAddress.m_AddressType = IP_SUBNET_V4_TYPE;
						static_filter.m_NetworkFilter.m_IPv4.m_DestAddress.m_IpSubnet.m_Ip = dest_address.value().get_address().S_un.S_addr;
						static_filter.m_NetworkFilter.m_IPv4.m_DestAddress.m_IpSubnet.m_IpMask = dest_address.value().get_mask().S_un.S_addr;
					}
					else if constexpr (std::is_same_v<T, net::ip_address_v6>)
					{
						static_filter.m_NetworkFilter.m_IPv6.m_ValidFields |= IP_V6_FILTER_DEST_ADDRESS;
						static_filter.m_NetworkFilter.m_IPv6.m_DestAddress.m_AddressType = IP_SUBNET_V6_TYPE;
						static_filter.m_NetworkFilter.m_IPv6.m_DestAddress.m_IpSubnet.m_Ip = dest_address.value().get_address();
						static_filter.m_NetworkFilter.m_IPv6.m_DestAddress.m_IpSubnet.m_IpMask = dest_address.value().get_mask();
					}
				}

				if (auto protocol = filter.get_protocol(); protocol.has_value())
				{
					if constexpr (std::is_same_v<T, net::ip_address_v4>)
					{
						static_filter.m_NetworkFilter.m_IPv4.m_ValidFields |= IP_V4_FILTER_PROTOCOL;
						static_filter.m_NetworkFilter.m_IPv4.m_Protocol = protocol.value();
					}
					else if constexpr (std::is_same_v<T, net::ip_address_v6>)
					{
						static_filter.m_NetworkFilter.m_IPv6.m_ValidFields |= IP_V6_FILTER_PROTOCOL;
						static_filter.m_NetworkFilter.m_IPv6.m_Protocol = protocol.value();
					}
				}
			}

			if (filter.get_source_port() || filter.get_dest_port())
			{
				static_filter.m_ValidFields |= TRANSPORT_LAYER_VALID;
				if (auto protocol = filter.get_protocol(); protocol.has_value())
				{
					if (protocol.value() == IPPROTO_TCP || protocol.value() == IPPROTO_UDP)
					{
						static_filter.m_TransportFilter.m_dwUnionSelector = TCPUDP;
					}
				}

				if (auto source_port = filter.get_source_port(); source_port.has_value())
				{
					static_filter.m_TransportFilter.m_TcpUdp.m_ValidFields |= TCPUDP_SRC_PORT;
					static_filter.m_TransportFilter.m_TcpUdp.m_SourcePort.m_StartRange = source_port.value().first;
					static_filter.m_TransportFilter.m_TcpUdp.m_SourcePort.m_EndRange = source_port.value().second;
				}

				if (auto dest_port = filter.get_dest_port(); dest_port.has_value())
				{
					static_filter.m_TransportFilter.m_TcpUdp.m_ValidFields |= TCPUDP_DEST_PORT;
					static_filter.m_TransportFilter.m_TcpUdp.m_DestPort.m_StartRange = dest_port.value().first;
					static_filter.m_TransportFilter.m_TcpUdp.m_DestPort.m_EndRange = dest_port.value().second;
				}
			}
		}

		void set_default_action(STATIC_FILTER& filter) const
		{
			filter.m_Adapter.QuadPart = 0;
			filter.m_ValidFields = 0;
			filter.m_dwDirectionFlags = PACKET_FLAG_ON_RECEIVE | PACKET_FLAG_ON_SEND;

			switch (default_action_)
			{
			case action_t::pass:
				filter.m_FilterAction = FILTER_PACKET_PASS;
				break;
			case action_t::drop:
				filter.m_FilterAction = FILTER_PACKET_DROP;
				break;
			case action_t::redirect:
				filter.m_FilterAction = FILTER_PACKET_REDIRECT;
				break;
			case action_t::pass_redirect:
				filter.m_FilterAction = FILTER_PACKET_PASS_RDR;
				break;
			case action_t::drop_redirect:
				filter.m_FilterAction = FILTER_PACKET_DROP_RDR;
				break;
			}
		}

		/// <summary>default filter action</summary>
		action_t default_action_;
		/// <summary>optional log stream for error logging</summary>
		std::optional<std::reference_wrapper<std::osyncstream>> log_stream_;
		/// <summary>list of available network interfaces</summary>
		std::vector<std::unique_ptr<network_adapter>> network_interfaces_;
		/// <summary>list of static filters</summary>
		std::vector<std::variant<filter<net::ip_address_v4>, filter<net::ip_address_v6>>> filters_;
	};
}
