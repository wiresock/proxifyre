#pragma once

namespace ndisapi
{
    /// <summary>
    /// Enum representing the possible actions that can be taken on a packet.
    /// </summary>
    enum class action_t : uint8_t
    {
        pass,           ///< Allow the packet to pass through.
        drop,           ///< Drop the packet.
        redirect,       ///< Redirect the packet to another destination.
        pass_redirect,  ///< Allow the packet to pass and also redirect it.
        drop_redirect   ///< Drop the packet and also redirect it.
    };

    /// <summary>
    /// Enum representing the direction of the packet.
    /// </summary>
    enum class direction_t : uint8_t
    {
        in,     ///< Incoming packet.
        out,    ///< Outgoing packet.
        both    ///< Both incoming and outgoing packets.
    };

    template <net::ip_address T>
    class filter
    {
        /// <summary>network interface handle</summary>
        HANDLE adapter_handle_ = nullptr;
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

        /// <summary>
        /// Default constructor for the filter class.
        /// </summary>
        filter() = default;

        /// <summary>
        /// Gets the direction of the packet.
        /// </summary>
        /// <returns>The direction of the packet.</returns>
        [[nodiscard]] direction_t get_direction() const
        {
            return direction_;
        }

        /// <summary>
        /// Sets the direction of the packet.
        /// </summary>
        /// <param name="direction">The direction to set.</param>
        /// <returns>A reference to the filter object.</returns>
        filter& set_direction(const direction_t direction)
        {
            direction_ = direction;
            return *this;
        }

        /// <summary>
        /// Gets the action to be taken on the packet.
        /// </summary>
        /// <returns>The action to be taken on the packet.</returns>
        [[nodiscard]] action_t get_action() const
        {
            return action_;
        }

        /// <summary>
        /// Sets the action to be taken on the packet.
        /// </summary>
        /// <param name="action">The action to set.</param>
        /// <returns>A reference to the filter object.</returns>
        filter& set_action(const action_t action)
        {
            action_ = action;
            return *this;
        }

        /// <summary>
        /// Gets the network interface handle.
        /// </summary>
        /// <returns>The network interface handle.</returns>
        [[nodiscard]] HANDLE get_adapter_handle() const
        {
            return adapter_handle_;
        }

        /// <summary>
        /// Sets the network interface handle.
        /// </summary>
        /// <param name="adapter_handle">The network interface handle to set.</param>
        /// <returns>A reference to the filter object.</returns>
        filter& set_adapter_handle(HANDLE adapter_handle)
        {
            adapter_handle_ = adapter_handle;
            return *this;
        }

        /// <summary>
        /// Gets the source MAC address.
        /// </summary>
        /// <returns>The source MAC address.</returns>
        [[nodiscard]] std::optional<net::mac_address> get_source_hw_address() const
        {
            return source_hw_address_;
        }

        /// <summary>
        /// Sets the source MAC address.
        /// </summary>
        /// <param name="source_address">The source MAC address to set.</param>
        /// <returns>A reference to the filter object.</returns>
        filter& set_source_hw_address(const net::mac_address& source_address)
        {
            source_hw_address_ = source_address;
            return *this;
        }

        /// <summary>
        /// Gets the destination MAC address.
        /// </summary>
        /// <returns>The destination MAC address.</returns>
        [[nodiscard]] std::optional<net::mac_address> get_dest_hw_address() const
        {
            return dest_hw_address_;
        }

        /// <summary>
        /// Sets the destination MAC address.
        /// </summary>
        /// <param name="dest_address">The destination MAC address to set.</param>
        /// <returns>A reference to the filter object.</returns>
        filter& set_dest_hw_address(const net::mac_address& dest_address)
        {
            dest_hw_address_ = dest_address;
            return *this;
        }

        /// <summary>
        /// Gets the Ethernet type.
        /// </summary>
        /// <returns>The Ethernet type.</returns>
        [[nodiscard]] std::optional<uint16_t> get_ether_type() const
        {
            return ether_type_;
        }

        /// <summary>
        /// Sets the Ethernet type.
        /// </summary>
        /// <param name="ether_type">The Ethernet type to set.</param>
        /// <returns>A reference to the filter object.</returns>
        filter& set_ether_type(const uint16_t ether_type)
        {
            ether_type_ = ether_type;
            return *this;
        }

        /// <summary>
        /// Gets the source IP address.
        /// </summary>
        /// <returns>The source IP address.</returns>
        [[nodiscard]] std::optional<net::ip_subnet<T>> get_source_address() const
        {
            return source_address_;
        }

        /// <summary>
        /// Sets the source IP address.
        /// </summary>
        /// <param name="source_address">The source IP address to set.</param>
        /// <returns>A reference to the filter object.</returns>
        filter& set_source_address(const net::ip_subnet<T>& source_address)
        {
            source_address_ = source_address;
            return *this;
        }

        /// <summary>
        /// Gets the destination IP address.
        /// </summary>
        /// <returns>The destination IP address.</returns>
        [[nodiscard]] std::optional<net::ip_subnet<T>> get_dest_address() const
        {
            return dest_address_;
        }

        /// <summary>
        /// Sets the destination IP address.
        /// </summary>
        /// <param name="dest_address">The destination IP address to set.</param>
        /// <returns>A reference to the filter object.</returns>
        filter& set_dest_address(const net::ip_subnet<T>& dest_address)
        {
            dest_address_ = dest_address;
            return *this;
        }

        /// <summary>
        /// Gets the source port (TCP/UDP only).
        /// </summary>
        /// <returns>The source port.</returns>
        [[nodiscard]] std::optional<std::pair<uint16_t, uint16_t>> get_source_port() const
        {
            return source_port_;
        }

        /// <summary>
        /// Sets the source port (TCP/UDP only).
        /// </summary>
        /// <param name="source_port">The source port to set.</param>
        /// <returns>A reference to the filter object.</returns>
        filter& set_source_port(const std::pair<uint16_t, uint16_t>& source_port)
        {
            source_port_ = source_port;
            return *this;
        }

        /// <summary>
        /// Gets the destination port (TCP/UDP only).
        /// </summary>
        /// <returns>The destination port.</returns>
        [[nodiscard]] std::optional<std::pair<uint16_t, uint16_t>> get_dest_port() const
        {
            return dest_port_;
        }

        /// <summary>
        /// Sets the destination port (TCP/UDP only).
        /// </summary>
        /// <param name="dest_port">The destination port to set.</param>
        /// <returns>A reference to the filter object.</returns>
        filter& set_dest_port(const std::pair<uint16_t, uint16_t>& dest_port)
        {
            dest_port_ = dest_port;
            return *this;
        }

        /// <summary>
        /// Gets the IP protocol.
        /// </summary>
        /// <returns>The IP protocol.</returns>
        [[nodiscard]] std::optional<uint8_t> get_protocol() const
        {
            return protocol_;
        }

        /// <summary>
        /// Sets the IP protocol.
        /// </summary>
        /// <param name="protocol">The IP protocol to set.</param>
        /// <returns>A reference to the filter object.</returns>
        filter& set_protocol(const uint8_t protocol)
        {
            protocol_ = protocol;
            return *this;
        }
    };

    class static_filters final : public CNdisApi, public netlib::log::logger<static_filters>
    {
        using log_level = netlib::log::log_level;

    public:

        /// <summary>
        /// Constructor for the static_filters class.
        /// </summary>
        /// <param name="filter_cache">Indicates whether to enable the filter cache.</param>
        /// <param name="fragment_cache">Indicates whether to enable the fragment cache.</param>
        /// <param name="log_level">The logging level to use.</param>
        /// <param name="log_stream">Optional output stream for logging.</param>
        explicit static_filters(
            const bool filter_cache,
            const bool fragment_cache,
            const log_level log_level = log_level::error,
            std::shared_ptr<std::ostream> log_stream = nullptr)
            : logger(log_level, std::move(log_stream))
        {
            using namespace std::string_literals;

            if (!IsDriverLoaded())
            {
                throw std::runtime_error("Windows Packet Filter driver is not available!"s);
            }

            if (filter_cache)
            {
                std::ignore = enable_filter_cache();
            }
            else
            {
                std::ignore = disable_filter_cache();
            }

            if (fragment_cache)
            {
                std::ignore = enable_fragment_cache();
            }
            else
            {
                std::ignore = disable_fragment_cache();
            }
        }


        static_filters(const static_filters& other) = delete;
        static_filters(static_filters&& other) noexcept = delete;
        static_filters& operator=(const static_filters& other) = delete;
        static_filters& operator=(static_filters&& other) noexcept = delete;

        ~static_filters() override
        {
            std::ignore = ResetPacketFilterTable();
        }

        /// <summary>
        /// Enables the packet filter cache.
        /// </summary>
        /// <returns>True if the packet filter cache was successfully enabled; otherwise, false.</returns>
        bool enable_filter_cache() const
        {
            return EnablePacketFilterCache();
        }

        /// <summary>
        /// Disables the packet filter cache.
        /// </summary>
        /// <returns>True if the packet filter cache was successfully disabled; otherwise, false.</returns>
        bool disable_filter_cache() const
        {
            return DisablePacketFilterCache();
        }

        /// <summary>
        /// Enables the packet fragment cache.
        /// </summary>
        /// <returns>True if the packet fragment cache was successfully enabled; otherwise, false.</returns>
        bool enable_fragment_cache() const
        {
            return EnablePacketFragmentCache();
        }

        /// <summary>
        /// Disables the packet fragment cache.
        /// </summary>
        /// <returns>True if the packet fragment cache was successfully disabled; otherwise, false.</returns>
        bool disable_fragment_cache() const
        {
            return DisablePacketFragmentCache();
        }

        /// <summary>
        /// Adds a filter to the front of the filter list.
        /// </summary>
        /// <typeparam name="T">The type of the IP address (IPv4 or IPv6).</typeparam>
        /// <param name="filter">The filter to add.</param>
        /// <returns>True if the filter was successfully added; otherwise, false.</returns>
        template <net::ip_address T>
        bool add_filter_front(const filter<T>& filter)
        {
            STATIC_FILTER static_filter{};
            to_static_filter(filter, static_filter);
            if (AddStaticFilterFront(&static_filter))
            {
                filters_.emplace_front(filter);
                return true;
            }
            return false;
        }

        /// <summary>
        /// Adds a filter to the back of the filter list.
        /// </summary>
        /// <typeparam name="T">The type of the IP address (IPv4 or IPv6).</typeparam>
        /// <param name="filter">The filter to add.</param>
        /// <returns>True if the filter was successfully added; otherwise, false.</returns>
        template <net::ip_address T>
        bool add_filter_back(const filter<T>& filter)
        {
            STATIC_FILTER static_filter{};
            to_static_filter(filter, static_filter);
            if (AddStaticFilterBack(&static_filter))
            {
                filters_.emplace_back(filter);
                return true;
            }
            return false;
        }

        /// <summary>
        /// Inserts a filter at the specified position in the filter list.
        /// </summary>
        /// <typeparam name="T">The type of the IP address (IPv4 or IPv6).</typeparam>
        /// <param name="filter">The filter to insert.</param>
        /// <param name="position">The position at which to insert the filter.</param>
        /// <returns>True if the filter was successfully inserted; otherwise, false.</returns>
        template <net::ip_address T>
        bool insert_filter(const filter<T>& filter, const uint32_t position)
        {
            if (position > filters_.size()) // Check if the position is out of bounds
            {
                return false; // Position is beyond the current size of the list
            }

            STATIC_FILTER static_filter{};
            to_static_filter(filter, static_filter);

            if (InsertStaticFilter(&static_filter, position))
            {
                auto it = filters_.begin();
                std::advance(it, position); // Move the iterator to the desired position
                filters_.insert(it, filter); // Insert the filter at the position
                return true;
            }
            return false;
        }


        /// <summary>
        /// Removes a filter at the specified position in the filter list.
        /// </summary>
        /// <param name="position">The position of the filter to remove.</param>
        /// <returns>True if the filter was successfully removed; otherwise, false.</returns>
        bool remove_filter(const uint32_t position)
        {
            // Check if the filter ID is within the bounds of the list size
            if (position >= filters_.size()) {
                return false; // Filter ID is out of bounds
            }

            auto it = filters_.begin();
            std::advance(it, position); // Move the iterator to the position of the filter to remove

            if (RemoveStaticFilter(position)) {
                filters_.erase(it); // Remove the filter from the list
                return true; // Successfully removed
            }

            return false; // Removal from the system/driver failed
        }

        /// <summary>
        /// Removes filters from the list based on a predicate.
        /// </summary>
        /// <typeparam name="T">The type of the IP address (IPv4 or IPv6).</typeparam>
        /// <param name="predicate">A function that takes a filter and returns true if the filter should be removed.</param>
        template <net::ip_address T>
        void remove_filters_if(std::function<bool(const filter<T>&)> predicate)
        {
            size_t position = 0; // Start position tracking from 0
            for (auto it = filters_.begin(); it != filters_.end(); )
            {
                if ([[maybe_unused]] const bool removed = std::visit([&]<typename U>(U& arg) -> bool {
                    using filter_type_t = std::decay_t<U>;
                    if constexpr (std::is_same_v<filter_type_t, filter<T>>)
                    {
                        // If the filter matches the type T, apply the predicate
                        if (predicate(arg))
                        {
                            const bool success = RemoveStaticFilter(static_cast<uint32_t>(position));
                            if (!success)
                            {
                                NETLIB_ERROR("Failed to remove filter at position: {}", position);
                            }
                            return success;
                        }
                    }
                    return false;
                }, *it))
                {
                    it = filters_.erase(it); // Remove the filter from the list and move to the next
                    // Do not increment position since we removed an element
                }
                else
                {
                    ++it; // Move to the next filter if it does not match the predicate or type
                    ++position; // Increment position only if we did not remove the filter
                }
            }
        }

        /// <summary>
        /// Stores the current filter table to the driver.
        /// </summary>
        /// <returns>True if the filter table was successfully stored; otherwise, false.</returns>
        bool store_table()
        {
            try
            {
                const size_t filter_size = filters_.size();
                const auto table_buffer = std::make_unique<uint8_t[]>(sizeof(STATIC_FILTER_TABLE) + sizeof(STATIC_FILTER) * (filter_size - 1));
                auto* filter_list = reinterpret_cast<PSTATIC_FILTER_TABLE>(table_buffer.get());
                memset(filter_list, 0, sizeof(STATIC_FILTER_TABLE) + sizeof(STATIC_FILTER) * (filter_size - 1));

                filter_list->m_TableSize = static_cast<uint32_t>(filter_size);

                size_t i = 0; // Initialize index counter outside the loop
                for (auto it = filters_.begin(); it != filters_.end(); ++it, ++i)
                {
                    std::visit([this, &i, &filter_list](auto&& arg)
                        {
                            to_static_filter(arg, filter_list->m_StaticFilters[i]);
                        }, *it);
                }

                SetPacketFilterTable(filter_list);

                return true;
            }
            catch (const std::exception& e)
            {
                using namespace std::string_literals;
                NETLIB_ERROR("Exception occured in store_table: {}", e.what());
                return false;
            }
        }

        /// <summary>
        /// Loads the filter table from the driver.
        /// </summary>
        /// <returns>True if the filter table was successfully loaded; otherwise, false.</returns>
        bool load_table()
        {
            uint32_t table_size = 0;
            if (!GetPacketFilterTableSize(reinterpret_cast<PDWORD>(&table_size)) || table_size == 0)
            {
                // Failed to get table size or table is empty
                return false;
            }

            // Allocate memory for the filter table
            const auto table_buffer = std::make_unique<uint8_t[]>(sizeof(STATIC_FILTER_TABLE) + sizeof(STATIC_FILTER) * (table_size - 1));
            auto* filter_list = reinterpret_cast<PSTATIC_FILTER_TABLE>(table_buffer.get());

            if (!GetPacketFilterTable(filter_list))
            {
                // Failed to get the filter table
                return false;
            }

            // Clear the current filters list
            filters_.clear();

            // Iterate through the STATIC_FILTER entries and reconstruct the filters list
            for (size_t i = 0; i < table_size - 1; ++i) // Last entry is the default action, so we skip it
            {
                // Determine the type of filter (IPv4 or IPv6) based on the union selector
                switch (const auto& static_filter = filter_list->m_StaticFilters[i]; static_filter.m_NetworkFilter.m_dwUnionSelector)
                {
                case IPV4:
                {
                    filter<net::ip_address_v4> new_filter;
                    from_static_filter(static_filter, new_filter);
                    filters_.emplace_back(std::move(new_filter));
                    break;
                }
                case IPV6:
                {
                    filter<net::ip_address_v6> new_filter;
                    from_static_filter(static_filter, new_filter);
                    filters_.emplace_back(std::move(new_filter));
                    break;
                }
                default:
                    // Handle other types or log an error
                    break;
                }
            }

            return true;
        }

        /// <summary>
        /// Resets the packet filter table in the driver.
        /// </summary>
        void reset() const
        {
            SetPacketFilterTable(nullptr);
        }

    private:

        /// <summary>
        /// Converts a filter object to a STATIC_FILTER structure.
        /// </summary>
        /// <typeparam name="T">The type of the IP address (IPv4 or IPv6).</typeparam>
        /// <param name="filter">The filter object to convert.</param>
        /// <param name="static_filter">The STATIC_FILTER structure to populate.</param>
        template <net::ip_address T>
        void to_static_filter(const filter<T>& filter, STATIC_FILTER& static_filter)
        {
            static_filter.m_Adapter.QuadPart = reinterpret_cast<ULONGLONG>(filter.get_adapter_handle());

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
            default:  // NOLINT(clang-diagnostic-covered-switch-default)
                assert(false && "Unhandled direction_t value");
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
            default:  // NOLINT(clang-diagnostic-covered-switch-default)
                assert(false && "Unhandled action_t value");
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

        /// <summary>
        /// Converts a STATIC_FILTER object to a filter object.
        /// </summary>
        /// <typeparam name="T">The type of the IP address (IPv4 or IPv6).</typeparam>
        /// <param name="static_filter">The STATIC_FILTER object to convert.</param>
        /// <param name="filter">The filter object to populate.</param>
        template <net::ip_address T>
        void from_static_filter(const STATIC_FILTER& static_filter, filter<T>& filter)
        {
            filter.set_adapter_handle(reinterpret_cast<HANDLE>(static_filter.m_Adapter.QuadPart));  // NOLINT(performance-no-int-to-ptr)

            // Direction
            if (static_filter.m_dwDirectionFlags & PACKET_FLAG_ON_RECEIVE)
            {
                if (static_filter.m_dwDirectionFlags & PACKET_FLAG_ON_SEND)
                {
                    filter.set_direction(direction_t::both);
                }
                else
                {
                    filter.set_direction(direction_t::in);
                }
            }
            else if (static_filter.m_dwDirectionFlags & PACKET_FLAG_ON_SEND)
            {
                filter.set_direction(direction_t::out);
            }

            // Action
            switch (static_filter.m_FilterAction)
            {
            case FILTER_PACKET_PASS:
                filter.set_action(action_t::pass);
                break;
            case FILTER_PACKET_DROP:
                filter.set_action(action_t::drop);
                break;
            case FILTER_PACKET_REDIRECT:
                filter.set_action(action_t::redirect);
                break;
            case FILTER_PACKET_PASS_RDR:
                filter.set_action(action_t::pass_redirect);
                break;
            case FILTER_PACKET_DROP_RDR:
                filter.set_action(action_t::drop_redirect);
                break;
            default:;
            }

            // Data Link Layer
            if (static_filter.m_ValidFields & DATA_LINK_LAYER_VALID)
            {
                if (static_filter.m_DataLinkFilter.m_dwUnionSelector == ETH_802_3)
                {
                    if (static_filter.m_DataLinkFilter.m_Eth8023Filter.m_ValidFields & ETH_802_3_SRC_ADDRESS)
                    {
                        filter.set_source_hw_address(net::mac_address(static_filter.m_DataLinkFilter.m_Eth8023Filter.m_SrcAddress));
                    }

                    if (static_filter.m_DataLinkFilter.m_Eth8023Filter.m_ValidFields & ETH_802_3_DEST_ADDRESS)
                    {
                        filter.set_dest_hw_address(net::mac_address(static_filter.m_DataLinkFilter.m_Eth8023Filter.m_DestAddress));
                    }

                    if (static_filter.m_DataLinkFilter.m_Eth8023Filter.m_ValidFields & ETH_802_3_PROTOCOL)
                    {
                        filter.set_ether_type(static_filter.m_DataLinkFilter.m_Eth8023Filter.m_Protocol);
                    }
                }
            }

            // Network Layer
            if (static_filter.m_ValidFields & NETWORK_LAYER_VALID)
            {
                if constexpr (std::is_same_v<T, net::ip_address_v4>)
                {
                    if (static_filter.m_NetworkFilter.m_dwUnionSelector == IPV4)
                    {
                        if (static_filter.m_NetworkFilter.m_IPv4.m_ValidFields & IP_V4_FILTER_SRC_ADDRESS)
                        {
                            filter.set_source_address(net::ip_subnet<T>(
                                net::ip_address_v4(ntohl(static_filter.m_NetworkFilter.m_IPv4.m_SrcAddress.m_IpSubnet.m_Ip)),
                                net::ip_address_v4(ntohl(static_filter.m_NetworkFilter.m_IPv4.m_SrcAddress.m_IpSubnet.m_IpMask))));
                        }

                        if (static_filter.m_NetworkFilter.m_IPv4.m_ValidFields & IP_V4_FILTER_DEST_ADDRESS)
                        {
                            filter.set_dest_address(net::ip_subnet<T>(
                                net::ip_address_v4(ntohl(static_filter.m_NetworkFilter.m_IPv4.m_DestAddress.m_IpSubnet.m_Ip)),
                                net::ip_address_v4(ntohl(static_filter.m_NetworkFilter.m_IPv4.m_DestAddress.m_IpSubnet.m_IpMask))));
                        }
                    }
                }
                else if constexpr (std::is_same_v<T, net::ip_address_v6>)
                {
                    // Check if the filter is for IPv6
                    if (static_filter.m_NetworkFilter.m_dwUnionSelector == IPV6)
                    {
                        if (static_filter.m_NetworkFilter.m_IPv6.m_ValidFields & IP_V6_FILTER_SRC_ADDRESS)
                        {
                            filter.set_source_address(net::ip_subnet<net::ip_address_v6>(
                                net::ip_address_v6(static_filter.m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpSubnet.m_Ip),
                                net::ip_address_v6(static_filter.m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpSubnet.m_IpMask)
                            ));
                        }

                        if (static_filter.m_NetworkFilter.m_IPv6.m_ValidFields & IP_V6_FILTER_DEST_ADDRESS)
                        {
                            filter.set_dest_address(net::ip_subnet<net::ip_address_v6>(
                                net::ip_address_v6(static_filter.m_NetworkFilter.m_IPv6.m_DestAddress.m_IpSubnet.m_Ip),
                                net::ip_address_v6(static_filter.m_NetworkFilter.m_IPv6.m_DestAddress.m_IpSubnet.m_IpMask)
                            ));
                        }
                    }
                }

                if (static_filter.m_NetworkFilter.m_dwUnionSelector == IPV4 || static_filter.m_NetworkFilter.m_dwUnionSelector == IPV6)
                {
                    if (static_filter.m_NetworkFilter.m_IPv4.m_ValidFields & IP_V4_FILTER_PROTOCOL ||
                        static_filter.m_NetworkFilter.m_IPv6.m_ValidFields & IP_V6_FILTER_PROTOCOL)
                    {
                        filter.set_protocol(static_filter.m_NetworkFilter.m_IPv4.m_Protocol); // Assuming protocol field is the same for IPv4 and IPv6
                    }
                }
            }

            // Transport Layer
            if (static_filter.m_ValidFields & TRANSPORT_LAYER_VALID)
            {
                if (static_filter.m_TransportFilter.m_dwUnionSelector == TCPUDP)
                {
                    if (static_filter.m_TransportFilter.m_TcpUdp.m_ValidFields & TCPUDP_SRC_PORT)
                    {
                        filter.set_source_port(std::make_pair(
                            static_filter.m_TransportFilter.m_TcpUdp.m_SourcePort.m_StartRange,
                            static_filter.m_TransportFilter.m_TcpUdp.m_SourcePort.m_EndRange));
                    }

                    if (static_filter.m_TransportFilter.m_TcpUdp.m_ValidFields & TCPUDP_DEST_PORT)
                    {
                        filter.set_dest_port(std::make_pair(
                            static_filter.m_TransportFilter.m_TcpUdp.m_DestPort.m_StartRange,
                            static_filter.m_TransportFilter.m_TcpUdp.m_DestPort.m_EndRange));
                    }
                }
            }
        }

        /// <summary>
        /// List of static filters.
        /// </summary>
        std::list<std::variant<filter<net::ip_address_v4>, filter<net::ip_address_v6>>> filters_;
    };
}
