#pragma once

namespace iphelper
{
    /// <summary>
    /// Equality comparison operator for the IF_LUID type
    /// </summary>
    /// <param name="lhs">left hand parameter</param>
    /// <param name="rhs">right hand parameter</param>
    /// <returns>true if equal, false otherwise</returns>
    inline bool operator==(const IF_LUID& lhs, const IF_LUID& rhs)
    {
        return (lhs.Value == rhs.Value) && (lhs.Info.IfType == rhs.Info.IfType) && (lhs.Info.NetLuidIndex == rhs.Info.
            NetLuidIndex);
    }

    /// <summary>
    /// Non-equality comparison operator for the IF_LUID type
    /// </summary>
    /// <param name="lhs">left hand parameter</param>
    /// <param name="rhs">right hand parameter</param>
    /// <returns>true if non-equal, false otherwise</returns>
    inline bool operator!=(const IF_LUID& lhs, const IF_LUID& rhs) { return !(lhs == rhs); }

    /// <summary>
    /// Less comparison operator for the IF_LUID type
    /// </summary>
    /// <param name="lhs">left hand parameter</param>
    /// <param name="rhs">right hand parameter</param>
    /// <returns>true if left is less, false otherwise</returns>
    inline bool operator<(const IF_LUID& lhs, const IF_LUID& rhs)
    {
        return std::tie(lhs.Value, lhs.Info.IfType, lhs.Info.NetLuidIndex) < std::tie(
            rhs.Value, rhs.Info.IfType, rhs.Info.NetLuidIndex);
    }

    // --------------------------------------------------------------------------------
    /// <summary>
    /// Simple wrapper for SOCKADDR_STORAGE
    /// </summary>
    // --------------------------------------------------------------------------------
    struct ip_address_info : SOCKADDR_STORAGE
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        ip_address_info() : SOCKADDR_STORAGE()
        {
        }

        /// <summary>
        /// Constructs ip_address_info from sockaddr
        /// </summary>
        /// <param name="address"></param>
        explicit ip_address_info(const sockaddr& address) : SOCKADDR_STORAGE()
        {
            *reinterpret_cast<sockaddr*>(this) = address;
        }

        /// <summary>
        /// Constructs ip_address_info from sockaddr_in
        /// </summary>
        /// <param name="address"></param>
        explicit ip_address_info(const sockaddr_in& address) : SOCKADDR_STORAGE()
        {
            *reinterpret_cast<sockaddr_in*>(this) = address;
        }

        /// <summary>
        /// Constructs ip_address_info from sockaddr_in6
        /// </summary>
        /// <param name="address"></param>
        explicit ip_address_info(const sockaddr_in6& address) : SOCKADDR_STORAGE()
        {
            *reinterpret_cast<sockaddr_in6*>(this) = address;
        }

        /// <summary>
        /// Constructs ip_address_info from SOCKET_ADDRESS
        /// </summary>
        /// <param name="address"></param>
        explicit ip_address_info(const SOCKET_ADDRESS& address) : SOCKADDR_STORAGE()
        {
            memcpy(this, address.lpSockaddr, address.iSockaddrLength);
        }

        /// <summary>
        /// Constructs ip_address_info from net::ip_address_v4
        /// </summary>
        /// <param name="address"></param>
        explicit ip_address_info(const net::ip_address_v4& address) : SOCKADDR_STORAGE()
        {
            ss_family = AF_INET;
            (reinterpret_cast<sockaddr_in*>(this))->sin_addr = address;
        }

        /// <summary>
        /// Constructs ip_address_info from net::ip_address_v6
        /// </summary>
        /// <param name="address"></param>
        explicit ip_address_info(const net::ip_address_v6& address) : SOCKADDR_STORAGE()
        {
            ss_family = AF_INET6;
            (reinterpret_cast<sockaddr_in6*>(this))->sin6_addr = address;
        }

        /// <summary>
        /// Typecast operator to sockaddr type
        /// </summary>
        explicit operator sockaddr() const { return *reinterpret_cast<sockaddr*>(const_cast<ip_address_info*>(this)); }

        /// <summary>
        /// Typecast operator to sockaddr_in
        /// </summary>
        explicit operator sockaddr_in() const
        {
            return *reinterpret_cast<sockaddr_in*>(const_cast<ip_address_info*>(this));
        }

        /// <summary>
        /// Typecast operator to sockaddr_in6
        /// </summary>
        explicit operator sockaddr_in6() const
        {
            return *reinterpret_cast<sockaddr_in6*>(const_cast<ip_address_info*>(this));
        }

        /// <summary>
        /// Equality operator
        /// </summary>
        /// <param name="rhs">ip_address_info to compare to</param>
        /// <returns>true if equal, false otherwise</returns>
        bool operator==(const ip_address_info& rhs) const
        {
            if (ss_family != rhs.ss_family)
                return false;

            switch (ss_family)
            {
            case AF_INET:
                return ((reinterpret_cast<const sockaddr_in*>(this))->sin_addr.S_un.S_addr == (reinterpret_cast<const
                    sockaddr_in&>(rhs)).sin_addr.S_un.S_addr);
            case AF_INET6:
                return (0 == std::memcmp(reinterpret_cast<const sockaddr_in6*>(this)->sin6_addr.u.Word,
                    reinterpret_cast<const sockaddr_in6&>(rhs).sin6_addr.u.Word,
                    sizeof(sockaddr_in6::sin6_addr)));
            default:
                break;
            }

            return false;
        }

        /// <summary>
        /// Typecast operator to std::string
        /// </summary>
        explicit operator std::string() const
        {
            return (ss_family == AF_INET)
                ? std::string(net::ip_address_v4((reinterpret_cast<const sockaddr_in*>(this))->sin_addr))
                : std::string(net::ip_address_v6((reinterpret_cast<const sockaddr_in6*>(this)->sin6_addr)));
        }

        /// <summary>
        /// Typecast operator to std::wstring
        /// </summary>
        explicit operator std::wstring() const
        {
            return (ss_family == AF_INET)
                ? std::wstring(net::ip_address_v4((reinterpret_cast<const sockaddr_in*>(this))->sin_addr))
                : std::wstring(net::ip_address_v6(reinterpret_cast<const sockaddr_in6*>(this)->sin6_addr));
        }
    };

    /// <summary>
    /// Stores IP address and hardware (MAC) address to represent network gateway information
    /// </summary>
    struct ip_gateway_info : ip_address_info  // NOLINT(clang-diagnostic-padded)
    {
        /// <summary>
        /// Constructs ip_gateway_info from sockaddr and net::mac_address
        /// </summary>
        /// <param name="address">IP address represented as sockaddr</param>
        /// <param name="hardware_address">Hardware (MAC) address</param>
        explicit ip_gateway_info(const sockaddr& address,
            const net::mac_address& hardware_address) :
            ip_address_info(address), hardware_address(hardware_address)
        {
        }

        /// <summary>
        /// Constructs ip_gateway_info from SOCKET_ADDRESS and net::mac_address
        /// </summary>
        /// <param name="address">IP address represented as SOCKET_ADDRESS</param>
        /// <param name="hardware_address">Hardware (MAC) address</param>
        explicit ip_gateway_info(const SOCKET_ADDRESS& address,
            const net::mac_address& hardware_address) :
            ip_address_info(address), hardware_address(hardware_address)
        {
        }

        /// <summary>
        /// Constructs ip_gateway_info from sockaddr
        /// </summary>
        /// <param name="address">IP address represented as sockaddr</param>
        explicit ip_gateway_info(const sockaddr& address) :
            ip_address_info(address)
        {
        }

        /// <summary>
        /// Constructs ip_gateway_info from SOCKET_ADDRESS
        /// </summary>
        /// <param name="address">IP address represented as SOCKET_ADDRESS</param>
        explicit ip_gateway_info(const SOCKET_ADDRESS& address) :
            ip_address_info(address)
        {
        }

        /// <summary>
        /// Hardware (MAC) address of the gateway
        /// </summary>
        std::optional<net::mac_address> hardware_address = std::nullopt;
    };

    /// <summary>
    /// Simple wrapper for the GUID
    /// </summary>
    struct guid_wrapper : GUID
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        guid_wrapper() = default;

        /// <summary>
        /// Constructs guid_wrapper from GUID
        /// </summary>
        /// <param name="guid"></param>
        explicit guid_wrapper(const GUID& guid) : GUID(guid)
        {
        }

        /// <summary>
        /// Converts GUID to string representation
        /// </summary>
        /// <typeparam name="T">Char type, e.g. char, wchar_t</typeparam>
        template <typename T>
        explicit operator std::basic_string<T>() const
        {
            std::basic_ostringstream<T> oss;
            oss << std::hex
                << std::uppercase
                << "{"
                << std::setfill(T('0')) << std::setw(8)
                << Data1 << "-"
                << std::setfill(T('0')) << std::setw(4)
                << Data2 << "-"
                << std::setfill(T('0')) << std::setw(4)
                << Data3 << "-"
                << std::setfill(T('0')) << std::setw(2)
                << static_cast<unsigned>(Data4[0])
                << std::setfill(T('0')) << std::setw(2)
                << static_cast<unsigned>(Data4[1]) << "-"
                << std::setfill(T('0')) << std::setw(2)
                << static_cast<unsigned>(Data4[2])
                << std::setfill(T('0')) << std::setw(2)
                << static_cast<unsigned>(Data4[3])
                << std::setfill(T('0')) << std::setw(2)
                << static_cast<unsigned>(Data4[4])
                << std::setfill(T('0')) << std::setw(2)
                << static_cast<unsigned>(Data4[5])
                << std::setfill(T('0')) << std::setw(2)
                << static_cast<unsigned>(Data4[6])
                << std::setfill(T('0')) << std::setw(2)
                << static_cast<unsigned>(Data4[7])
                << "}";

            return oss.str();
        }
    };

    /// <summary>
    /// Network adapter information class
    /// </summary>
    class network_adapter_info // NOLINT(clang-diagnostic-padded)
    {
        static constexpr std::string_view adapter_connection_name =
            R"(SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\)";

    public:
        /// <summary>
        /// Constructs object instance from IP HELPER API structures
        /// </summary>
        /// <param name="address">IP_ADAPTER_ADDRESSES pointer: 
        /// https://docs.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh</param>
        /// <param name="if_table">MIB_IF_TABLE2 pointer: 
        /// https://docs.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_table2</param>
        /// <param name="index">Network interface index in MIB_IF_TABLE2</param>
        network_adapter_info(const PIP_ADAPTER_ADDRESSES address, const PMIB_IF_TABLE2 if_table, const size_t index) :
            if_index_(address->IfIndex),
            ipv6_if_index_(address->Ipv6IfIndex),
            adapter_name_(address->AdapterName),
            description_(address->Description),
            friendly_name_(address->FriendlyName),
            physical_address_(address->PhysicalAddress),
            mtu_(static_cast<uint16_t>(address->Mtu)),
            transmit_link_speed_(address->TransmitLinkSpeed),
            receive_link_speed_(address->ReceiveLinkSpeed),
            luid_(address->Luid),
            if_type_(address->IfType),
            media_type_(if_table->Table[index].MediaType),
            physical_medium_type_(if_table->Table[index].PhysicalMediumType)
        {
            // Initialize from IP_ADAPTER_ADDRESSES
            auto* unicast_address = address->FirstUnicastAddress;
            while (unicast_address)
            {
                unicast_address_list_.emplace_back(unicast_address->Address);
                unicast_address = unicast_address->Next;
            }

            auto* dns_address = address->FirstDnsServerAddress;
            while (dns_address)
            {
                dns_server_address_list_.emplace_back(dns_address->Address);
                dns_address = dns_address->Next;
            }

            auto* gateway_address = address->FirstGatewayAddress;
            while (gateway_address)
            {
                gateway_address_list_.emplace_back(gateway_address->Address);
                gateway_address = gateway_address->Next;
            }

            if (if_table->Table[index].PhysicalMediumType == NdisPhysicalMediumUnspecified)
            {
                // For unknown physical media interface (usually virtual interfaces) try to look up the underlying media
                for (size_t i = 0; i < if_table->NumEntries; ++i)
                {
                    if ((i != index) && // different entry from the current one
                        (if_table->Table[i].MediaConnectState == MediaConnectStateConnected) && // in connected state
                        (if_table->Table[i].PhysicalAddressLength == ETH_ALEN) && // has ethernet address
                        (if_table->Table[i].PhysicalMediumType != NdisPhysicalMediumUnspecified) &&
                        // has real network media set
                        (net::mac_address(if_table->Table[i].PhysicalAddress) == physical_address_) &&
                        // and equal MAC address
                        (if_table->Table[i].InterfaceAndOperStatusFlags.HardwareInterface)
                        // and real hardware interface
                        )
                    {
                        true_medium_type_ = if_table->Table[i].PhysicalMediumType;
                        true_adapter_name_ = guid_wrapper(if_table->Table[i].InterfaceGuid);
                    }
                }
            }
        }

        /// <summary>
        /// Default destructor
        /// </summary>
        ~network_adapter_info() = default;

        /// <summary>
        /// Default copy constructor
        /// </summary>
        /// <param name="other">object instance to copy from</param>
        network_adapter_info(const network_adapter_info& other) = default;

        /// <summary>
        /// Default move constructor
        /// </summary>
        /// <param name="other">Object instance to move from</param>
        /// <returns></returns>
        network_adapter_info(network_adapter_info&& other) noexcept = default;

        /// <summary>
        /// Default copy assignment operator
        /// </summary>
        /// <param name="other">Object instance to assign to</param>
        /// <returns>this object pointer</returns>
        network_adapter_info& operator=(const network_adapter_info& other) = default;

        /// <summary>
        /// Default move assignment operator
        /// </summary>
        /// <param name="other">Object instance to assign from</param>
        /// <returns>this object instance</returns>
        network_adapter_info& operator=(network_adapter_info&& other) noexcept = default;

        /// <summary>
        /// Gets network interface IPv4 IF_INDEX
        /// </summary>
        /// <returns>Network interface IPv4 IF_INDEX</returns>
        [[nodiscard]] unsigned long get_if_index() const noexcept { return if_index_; }

        /// <summary>
        /// Gets network interface IPv6 IF_INDEX
        /// </summary>
        /// <returns>Network interface IPv6 IF_INDEX</returns>
        [[nodiscard]] unsigned long get_ipv6_if_index() const noexcept { return ipv6_if_index_; }

        /// <summary>
        /// Gets network interface name
        /// </summary>
        /// <returns>Network interface name as std::string reference</returns>
        [[nodiscard]] const std::string& get_adapter_name() const noexcept { return adapter_name_; }

        /// <summary>
        /// Gets network interface true (lowest level) network adapter name
        /// </summary>
        /// <returns>Network interface true name as std::string reference</returns>
        [[nodiscard]] std::string get_true_adapter_name() const { return std::string(true_adapter_name_); }

        /// <summary>
        /// Gets network interface description
        /// </summary>
        /// <returns>Network interface description as std::wstring reference</returns>
        [[nodiscard]] const std::wstring& get_description() const noexcept { return description_; }

        /// <summary>
        /// Gets network interface friendly name
        /// </summary>
        /// <returns>Network interface friendly name as std::wstring reference</returns>
        [[nodiscard]] const std::wstring& get_friendly_name() const noexcept { return friendly_name_; }

        /// <summary>
        /// Sets network interface friendly name
        /// </summary>
        /// <returns>Network interface friendly name as std::wstring reference</returns>
        [[nodiscard]] bool set_friendly_name(const std::string_view name) noexcept
        {
            const std::string key_name = std::string(adapter_connection_name) + adapter_name_ + "\\Connection";

            HKEY h_key;

            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                key_name.c_str(),
                0,
                KEY_WRITE,
                &h_key) != ERROR_SUCCESS)
                return false;

            const auto status = RegSetValueExA(
                h_key,
                "Name",
                0,
                REG_SZ,
                reinterpret_cast<const BYTE*>(name.data()),
                static_cast<uint32_t>(name.size() + 1));

            RegCloseKey(h_key);

            if (status == ERROR_SUCCESS)
            {
                friendly_name_ = std::wstring(name.cbegin(), name.cend());
                return true;
            }

            return false;
        }

        /// <summary>
        /// Gets network interface unicast addresses
        /// </summary>
        /// <returns>Network interface unicast addresses as a vector of ip_address_info</returns>
        [[nodiscard]] const std::vector<ip_address_info>& get_unicast_address_list() const noexcept
        {
            return unicast_address_list_;
        }

        /// <summary>
        /// Gets network interface associated DNS servers
        /// </summary>
        /// <returns>Network interface associated DNS servers as a vector of ip_address_info</returns>
        [[nodiscard]] const std::vector<ip_address_info>& get_dns_server_address_list() const noexcept
        {
            return dns_server_address_list_;
        }

        /// <summary>
        /// Retrieves the list of configured gateway addresses for this network interface.
        /// </summary>
        /// <remarks>
        /// This method returns a reference to a vector of <c>ip_gateway_info</c> objects, each representing a gateway
        /// address configured for the network interface. Each <c>ip_gateway_info</c> contains both the IP address and,
        /// if available, the hardware (MAC) address of the gateway.
        ///
        /// If the interface type is Ethernet or IEEE 802.11 (Wi-Fi), and any gateway entry does not have a resolved
        /// hardware address, this method will attempt to resolve and populate the hardware address for all gateways
        /// before returning the list. This ensures that the returned vector always contains up-to-date hardware address
        /// information where possible.
        ///
        /// The returned reference remains valid as long as the <c>network_adapter_info</c> object is alive and unmodified.
        /// </remarks>
        /// <returns>
        /// A const reference to a vector of <c>ip_gateway_info</c> objects, each representing a configured gateway for the interface.
        /// </returns>
        [[nodiscard]] const std::vector<ip_gateway_info>& get_gateway_address_list() const noexcept
        {
            // Initialize MAC addresses for the network gateways
            if ((if_type_ == IF_TYPE_ETHERNET_CSMACD) ||
                (if_type_ == IF_TYPE_IEEE80211))
                {
                    if (std::ranges::any_of(std::as_const(gateway_address_list_), [](auto&& gateway)
                        {
                            return !gateway.hardware_address.has_value();
                        }))
                    {
                        // If any of the gateway addresses does not have hardware address, initialize it
                        initialize_gateway_hw_address_list();
                    }
                }
            return gateway_address_list_;
        }

        /// <summary>
        /// Checks if network interface has specified unicast IP address
        /// </summary>
        /// <returns>true if network interface has specified unicast IP address, false otherwise</returns>
        [[nodiscard]] bool has_address(const ip_address_info& address) const
        {
            return unicast_address_list_.cend() != std::ranges::find(unicast_address_list_, address);
        }

        /// <summary>
        /// Gets network interface physical address
        /// </summary>
        /// <returns>Network interface physical address</returns>
        [[nodiscard]] const net::mac_address& get_physical_address() const noexcept { return physical_address_; }

        /// <summary>
        /// Gets network interface MTU
        /// </summary>
        /// <returns>Network interface MTU</returns>
        [[nodiscard]] uint16_t get_mtu() const noexcept { return mtu_; }

        /// <summary>
        /// Gets network interface IF_TYPE:
        /// https://docs.microsoft.com/en-us/windows-hardware/drivers/network/ndis-interface-types
        /// </summary>
        /// <returns>Network interface IF_TYPE</returns>
        [[nodiscard]] unsigned get_if_type() const noexcept { return if_type_; }

        /// <summary>
        /// Gets network interface LUID
        /// </summary>
        /// <returns>Network interface LUID</returns>
        [[nodiscard]] IF_LUID get_luid() const noexcept { return luid_; }

        /// <summary>
        /// Equality comparison operator (compares network adapter LUID)
        /// </summary>
        /// <param name="rhs">Object instance to compare to</param>
        /// <returns>true if both objects have the same LUID</returns>
        bool operator ==(const network_adapter_info& rhs) const { return luid_ == rhs.luid_; }

        /// <summary>
        /// Non-equality comparison operator (compares network adapter LUID)
        /// </summary>
        /// <param name="rhs">Object instance to compare to</param>
        /// <returns>true if both objects have different LUID</returns>
        bool operator !=(const network_adapter_info& rhs) const { return (luid_ != rhs.luid_); }

        /// <summary>
        /// Less comparison operator (compares network adapter LUID)
        /// </summary>
        /// <param name="rhs">Object instance to compare to</param>
        /// <returns>true if this object LUID is less than rhs</returns>
        bool operator <(const network_adapter_info& rhs) const { return (luid_ < rhs.luid_); }

        /// <summary>
        /// Checks if IP address information in the provided network_adapter_info is different
        /// from the current one.
        /// </summary>
        /// <typeparam name="BCheckGateway">If true also checks the gateway information</typeparam>
        /// <param name="rhs">network_adapter_info to compare to</param>
        /// <returns>true if provided network_adapter_info contains the same IP addresses, false otherwise</returns>
        template <bool BCheckGateway = true>
        [[nodiscard]] bool is_same_address_info(const network_adapter_info& rhs) const
        {
            auto ret_val = true;

            if (unicast_address_list_.size() != rhs.unicast_address_list_.size())
                return false;

            if constexpr (BCheckGateway)
            {
                if (gateway_address_list_.size() != rhs.gateway_address_list_.size())
                    return false;
            }

            // Check if any of the unicast addresses have changed
            std::for_each(rhs.unicast_address_list_.cbegin(), rhs.unicast_address_list_.cend(),
                [&ret_val, this](auto& address)
                {
                    if (unicast_address_list_.cend() == std::find(
                        unicast_address_list_.cbegin(), unicast_address_list_.cend(), address))
                        ret_val = false;
                });

            if (ret_val == false)
                return ret_val;

            // Check if any of the gateways have changed
            if constexpr (BCheckGateway)
            {
                std::for_each(rhs.gateway_address_list_.cbegin(), rhs.gateway_address_list_.cend(),
                    [&ret_val, this](auto& address)
                    {
                        if (gateway_address_list_.cend() == std::find(
                            gateway_address_list_.cbegin(), gateway_address_list_.cend(), address))
                            ret_val = false;
                    });
            }

            return ret_val;
        }

        /**
         * @brief Returns the difference between the unicast addresses of this network adapter and another.
         *
         * This function compares the unicast addresses of this network adapter and another one. It returns a vector of
         * ip_address_info objects that are present in this network adapter but not in another one.
         *
         * @param rhs The other network adapter to compare with.
         * @return std::vector<ip_address_info> A vector of ip_address_info objects that are present in this network adapter rhs but not in rhs.
         */
        [[nodiscard]] std::vector<ip_address_info> get_unicast_address_difference(const network_adapter_info& rhs) const
        {
            std::vector<ip_address_info> difference;

            std::ranges::copy_if(unicast_address_list_, std::back_inserter(difference),
                [&rhs](const ip_address_info& address) {
                    return std::ranges::find(rhs.unicast_address_list_, address) == rhs.unicast_address_list_.end();
                });

            return difference;
        }

        /// <summary>
        /// Gets network interface NDIS_MEDIUM
        /// </summary>
        /// <returns>Network interface NDIS_MEDIUM</returns>
        [[nodiscard]] NDIS_MEDIUM get_media_type() const { return media_type_; }

        /// <summary>
        /// Gets network interface NDIS_PHYSICAL_MEDIUM
        /// </summary>
        /// <returns>Network interface NDIS_PHYSICAL_MEDIUM</returns>
        [[nodiscard]] NDIS_PHYSICAL_MEDIUM get_physical_medium_type() const { return physical_medium_type_; }

        /// <summary>
        /// Gets network interface the lowest underlying layer NDIS_PHYSICAL_MEDIUM
        /// </summary>
        /// <returns>Network interface the lowest underlying layer NDIS_PHYSICAL_MEDIUM</returns>
        [[nodiscard]] NDIS_PHYSICAL_MEDIUM get_true_physical_medium_type() const { return true_medium_type_; }

        /// <summary>
        /// Gets network interface transmit link speed
        /// </summary>
        /// <returns>Network interface transmit link speed</returns>
        [[nodiscard]] ULONG64 transmit_link_speed() const
        {
            return transmit_link_speed_;
        }

        /// <summary>
        /// Gets network interface receive link speed
        /// </summary>
        /// <returns>Network interface receive link speed</returns>
        [[nodiscard]] ULONG64 receive_link_speed() const
        {
            return receive_link_speed_;
        }

        /// <summary>
        /// Adds IPv4 unicast address to the network interface
        /// </summary>
        /// <param name="address">IPv4 address to assign</param>
        /// <param name="prefix_length">subnet prefix</param>
        /// <returns>pointer to MIB_UNICASTIPADDRESS_ROW</returns>
        [[nodiscard]] std::unique_ptr<MIB_UNICASTIPADDRESS_ROW> add_unicast_address(
            const net::ip_address_v4 address, const uint8_t prefix_length) const
        {
            auto address_row = std::make_unique<MIB_UNICASTIPADDRESS_ROW>();

            InitializeUnicastIpAddressEntry(address_row.get());

            address_row->Address.Ipv4.sin_family = AF_INET;
            address_row->Address.Ipv4.sin_addr = address;
            address_row->Address.si_family = AF_INET;

            address_row->InterfaceIndex = if_index_;
            address_row->InterfaceLuid = luid_;

            address_row->PrefixOrigin = IpPrefixOriginManual;
            address_row->SuffixOrigin = IpSuffixOriginManual;
            address_row->OnLinkPrefixLength = prefix_length;
            address_row->DadState = IpDadStatePreferred;

            SetLastError(ERROR_SUCCESS);

            if (const auto error_code = CreateUnicastIpAddressEntry(address_row.get());
                NO_ERROR != error_code && error_code != ERROR_OBJECT_ALREADY_EXISTS)
            {
                SetLastError(error_code);
                address_row.reset();  // Release the unique_ptr
            }

            return address_row;  // Single return point - enables NRVO
        }

        /// <summary>
        /// Adds IPv6 unicast address to the network interface
        /// </summary>
        /// <param name="address">IPv6 address to assign</param>
        /// <param name="prefix_length">subnet prefix</param>
        /// <returns>pointer to MIB_UNICASTIPADDRESS_ROW</returns>
        [[nodiscard]] std::unique_ptr<MIB_UNICASTIPADDRESS_ROW> add_unicast_address(
            const net::ip_address_v6& address, const uint8_t prefix_length) const
        {
            auto address_row = std::make_unique<MIB_UNICASTIPADDRESS_ROW>();

            InitializeUnicastIpAddressEntry(address_row.get());

            address_row->Address.Ipv6.sin6_family = AF_INET6;
            address_row->Address.Ipv6.sin6_addr = address;
            address_row->Address.si_family = AF_INET6;

            address_row->InterfaceIndex = ipv6_if_index_;
            address_row->InterfaceLuid = luid_;

            address_row->PrefixOrigin = IpPrefixOriginManual;
            address_row->SuffixOrigin = IpSuffixOriginManual;
            address_row->OnLinkPrefixLength = prefix_length;
            address_row->DadState = IpDadStatePreferred;

            SetLastError(ERROR_SUCCESS);

            if (const auto error_code = CreateUnicastIpAddressEntry(address_row.get());
                NO_ERROR != error_code && error_code != ERROR_OBJECT_ALREADY_EXISTS)
            {
                SetLastError(error_code);
                address_row.reset();  // Release the unique_ptr
            }

            return address_row;  // Single return point - enables NRVO
        }

        /// <summary>
        /// Removes unicast IP address from the network adapter by MIB_UNICASTIPADDRESS_ROW pointer
        /// </summary>
        /// <param name="address">MIB_UNICASTIPADDRESS_ROW unique pointer</param>
        /// <returns>true if no error occurs, false otherwise</returns>
        [[nodiscard]] static bool delete_unicast_address(
            const std::unique_ptr<MIB_UNICASTIPADDRESS_ROW>& address) noexcept
        {
            SetLastError(ERROR_SUCCESS);

            const auto error_code = DeleteUnicastIpAddressEntry(address.get());

            if (NO_ERROR != error_code)
                SetLastError(error_code);

            return NO_ERROR == error_code;
        }

        /// <summary>
        /// Adds default IPv4 gateway to network interface
        /// </summary>
        /// <param name="address">Default gateway IPv4 address</param>
        /// <returns>unique pointer to MIB_IPFORWARD_ROW2</returns>
        [[nodiscard]] std::unique_ptr<MIB_IPFORWARD_ROW2> add_default_gateway(const net::ip_address_v4& address) const
        {
            auto forward_row = std::make_unique<MIB_IPFORWARD_ROW2>();
            InitializeIpForwardEntry(forward_row.get());

            forward_row->InterfaceIndex = if_index_;
            forward_row->InterfaceLuid = luid_;
            forward_row->DestinationPrefix.Prefix.si_family = AF_INET;
            forward_row->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
            forward_row->NextHop.si_family = AF_INET;
            forward_row->NextHop.Ipv4.sin_family = AF_INET;
            forward_row->NextHop.Ipv4.sin_addr = address;
            forward_row->SitePrefixLength = 0;
            forward_row->Metric = 1;
            forward_row->Protocol = MIB_IPPROTO_NT_STATIC;
            forward_row->Origin = NlroManual;

            SetLastError(ERROR_SUCCESS);

            if (const auto error_code = CreateIpForwardEntry2(forward_row.get());
                NO_ERROR != error_code && error_code != ERROR_OBJECT_ALREADY_EXISTS)
            {
                SetLastError(error_code);
                forward_row.reset();
            }

            return forward_row;
        }

        /// <summary>
        /// Adds default IPv6 gateway to network interface
        /// </summary>
        /// <param name="address">Default gateway IPv6 address</param>
        /// <returns>unique pointer to MIB_IPFORWARD_ROW2</returns>
        [[nodiscard]] std::unique_ptr<MIB_IPFORWARD_ROW2> add_default_gateway(const net::ip_address_v6& address) const
        {
            auto forward_row = std::make_unique<MIB_IPFORWARD_ROW2>();
            InitializeIpForwardEntry(forward_row.get());

            forward_row->InterfaceIndex = ipv6_if_index_;
            forward_row->InterfaceLuid = luid_;
            forward_row->DestinationPrefix.Prefix.si_family = AF_INET6;
            forward_row->DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
            forward_row->NextHop.si_family = AF_INET6;
            forward_row->NextHop.Ipv6.sin6_family = AF_INET6;
            forward_row->NextHop.Ipv6.sin6_addr = address;
            forward_row->SitePrefixLength = 0;
            forward_row->Metric = 1;
            forward_row->Protocol = MIB_IPPROTO_NT_STATIC;
            forward_row->Origin = NlroManual;

            SetLastError(ERROR_SUCCESS);

            if (const auto error_code = CreateIpForwardEntry2(forward_row.get());
                NO_ERROR != error_code && error_code != ERROR_OBJECT_ALREADY_EXISTS)
            {
                SetLastError(error_code);
                forward_row.reset();
            }

            return forward_row;
        }

        /// <summary>
        /// Configures network interface as a default IPv4 gateway with specified metric
        /// </summary>
        /// <param name="metric">network metric (priority)</param>
        /// <returns>unique pointer to MIB_IPFORWARD_ROW2</returns>
        [[nodiscard]] std::unique_ptr<MIB_IPFORWARD_ROW2> assign_default_gateway_v4(const uint32_t metric = 0) const
        {
            auto forward_row = std::make_unique<MIB_IPFORWARD_ROW2>();
            InitializeIpForwardEntry(forward_row.get());

            forward_row->InterfaceIndex = if_index_;
            forward_row->InterfaceLuid = luid_;
            forward_row->DestinationPrefix.Prefix.si_family = AF_INET;
            forward_row->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
            forward_row->NextHop.si_family = AF_INET;
            forward_row->NextHop.Ipv4.sin_family = AF_INET;
            forward_row->NextHop.Ipv4.sin_addr = net::ip_address_v4{};
            forward_row->SitePrefixLength = 0;
            forward_row->Metric = metric;
            forward_row->Protocol = MIB_IPPROTO_NT_STATIC;
            forward_row->Origin = NlroManual;

            SetLastError(ERROR_SUCCESS);

            if (const auto error_code = CreateIpForwardEntry2(forward_row.get());
                NO_ERROR != error_code && error_code != ERROR_OBJECT_ALREADY_EXISTS)
            {
                SetLastError(error_code);
                forward_row.reset();
            }

            return forward_row;
        }

        /// <summary>
        /// Configures network interface as a default IPv6 gateway with specified metric
        /// </summary>
        /// <param name="metric">network metric (priority)</param>
        /// <returns>unique pointer to MIB_IPFORWARD_ROW2</returns>
        [[nodiscard]] std::unique_ptr<MIB_IPFORWARD_ROW2> assign_default_gateway_v6(const uint32_t metric = 0) const
        {
            auto forward_row = std::make_unique<MIB_IPFORWARD_ROW2>();
            InitializeIpForwardEntry(forward_row.get());

            forward_row->InterfaceIndex = ipv6_if_index_;
            forward_row->InterfaceLuid = luid_;
            forward_row->DestinationPrefix.Prefix.si_family = AF_INET6;
            forward_row->DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
            forward_row->NextHop.si_family = AF_INET6;
            forward_row->NextHop.Ipv6.sin6_family = AF_INET6;
            forward_row->NextHop.Ipv6.sin6_addr = net::ip_address_v6{};
            forward_row->SitePrefixLength = 0;
            forward_row->Metric = metric;
            forward_row->Protocol = MIB_IPPROTO_NT_STATIC;
            forward_row->Origin = NlroManual;

            SetLastError(ERROR_SUCCESS);

            if (const auto error_code = CreateIpForwardEntry2(forward_row.get());
                NO_ERROR != error_code && error_code != ERROR_OBJECT_ALREADY_EXISTS)
            {
                SetLastError(error_code);
                forward_row.reset();
            }

            return forward_row;
        }

        /// <summary>
        /// Adds IPv4 NDP entry for the network interface
        /// </summary>
        /// <param name="address">IPv4 address</param>
        /// <param name="hw_address">hardware address</param>
        /// <returns>unique pointer to MIB_IPNET_ROW2</returns>
        [[nodiscard]] std::unique_ptr<MIB_IPNET_ROW2> add_ndp_entry(const net::ip_address_v4& address,
            const net::mac_address& hw_address) const
        {
            auto net_row = std::make_unique<MIB_IPNET_ROW2>();
            RtlSecureZeroMemory(net_row.get(), sizeof(MIB_IPNET_ROW2));

            net_row->Address.si_family = AF_INET;
            net_row->Address.Ipv4.sin_family = AF_INET;
            net_row->Address.Ipv4.sin_addr = address;
            net_row->InterfaceIndex = if_index_;
            net_row->InterfaceLuid = luid_;
            memmove(net_row->PhysicalAddress, hw_address.data.data(), ETH_ALEN);
            net_row->PhysicalAddressLength = ETH_ALEN;
            net_row->State = NlnsPermanent;
            net_row->IsRouter = TRUE;
            net_row->IsUnreachable = TRUE;

            // Clear previous error state so GetLastError() reflects only this operation's result
            SetLastError(ERROR_SUCCESS);

            if (const auto error_code = CreateIpNetEntry2(net_row.get());
                NO_ERROR != error_code && error_code != ERROR_OBJECT_ALREADY_EXISTS)
            {
                SetLastError(error_code);
                net_row.reset();
            }

            return net_row;
        }

        /// <summary>
        /// Adds IPv6 NDP entry for the network interface
        /// </summary>
        /// <param name="address">IPv6 address</param>
        /// <param name="hw_address">hardware address</param>
        /// <returns>unique pointer to MIB_IPNET_ROW2</returns>
        [[nodiscard]] std::unique_ptr<MIB_IPNET_ROW2> add_ndp_entry(const net::ip_address_v6& address,
            const net::mac_address& hw_address) const
        {
            auto net_row = std::make_unique<MIB_IPNET_ROW2>();
            RtlSecureZeroMemory(net_row.get(), sizeof(MIB_IPNET_ROW2));

            net_row->Address.si_family = AF_INET6;
            net_row->Address.Ipv6.sin6_family = AF_INET6;
            net_row->Address.Ipv6.sin6_addr = address;
            net_row->InterfaceIndex = ipv6_if_index_;
            net_row->InterfaceLuid = luid_;
            memmove(net_row->PhysicalAddress, hw_address.data.data(), ETH_ALEN);
            net_row->PhysicalAddressLength = ETH_ALEN;
            net_row->State = NlnsPermanent;
            net_row->IsRouter = TRUE;
            net_row->IsUnreachable = TRUE;

            SetLastError(ERROR_SUCCESS);

            if (const auto error_code = CreateIpNetEntry2(net_row.get());
                NO_ERROR != error_code && error_code != ERROR_OBJECT_ALREADY_EXISTS)
            {
                SetLastError(error_code);
                net_row.reset();
            }

            return net_row;
        }

        /// <summary>
        /// Configures IPv4 network interface routes
        /// </summary>
        /// <param name="ips">IPv4/IPv6 subnets to configure</param>
        /// <returns>vector of unique pointers to MIB_IPFORWARD_ROW2</returns>
        [[nodiscard]] std::vector<std::unique_ptr<MIB_IPFORWARD_ROW2>> configure_allowed_ips_v4(
            const std::vector<std::variant<net::ip_subnet<net::ip_address_v4>, net::ip_subnet<net::ip_address_v6>>>&
            ips) const
        {
            std::vector<std::unique_ptr<MIB_IPFORWARD_ROW2>> ret_val;

            std::ranges::for_each(ips, [this, &ret_val](auto&& v)
            {
                if (auto subnet_v4_ptr = std::get_if<net::ip_subnet<net::ip_address_v4>>(&v); subnet_v4_ptr)
                {
                    auto forward_row = std::make_unique<MIB_IPFORWARD_ROW2>();
                    InitializeIpForwardEntry(forward_row.get());

                    forward_row->InterfaceIndex = if_index_;
                    forward_row->InterfaceLuid = luid_;
                    forward_row->DestinationPrefix.Prefix.si_family = AF_INET;
                    forward_row->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
                    forward_row->DestinationPrefix.Prefix.Ipv4.sin_addr = subnet_v4_ptr->get_address();
                    forward_row->DestinationPrefix.PrefixLength = subnet_v4_ptr->get_prefix();
                    forward_row->NextHop.si_family = AF_INET;
                    forward_row->NextHop.Ipv4.sin_family = AF_INET;
                    forward_row->NextHop.Ipv4.sin_addr = net::ip_address_v4{};
                    forward_row->SitePrefixLength = 0;
                    forward_row->Metric = 0;
                    forward_row->Protocol = MIB_IPPROTO_NT_STATIC;
                    forward_row->Origin = NlroManual;

                    SetLastError(ERROR_SUCCESS);

                    if (const auto error_code = CreateIpForwardEntry2(forward_row.get()); error_code == NO_ERROR
                        || error_code == ERROR_OBJECT_ALREADY_EXISTS)
                        ret_val.push_back(std::move(forward_row));
                    else
                        SetLastError(error_code);
                }
            });

            return ret_val;
        }

        /// <summary>
        /// Configures IPv6 network interface routes
        /// </summary>
        /// <param name="ips">IPv4/IPv6 subnets to configure</param>
        /// <returns>vector of unique pointers to MIB_IPFORWARD_ROW2</returns>
        [[nodiscard]] std::vector<std::unique_ptr<MIB_IPFORWARD_ROW2>> configure_allowed_ips_v6(
            const std::vector<std::variant<net::ip_subnet<net::ip_address_v4>, net::ip_subnet<net::ip_address_v6>>>&
            ips) const
        {
            std::vector<std::unique_ptr<MIB_IPFORWARD_ROW2>> return_value;

            std::ranges::for_each(ips, [this, &return_value](auto&& v)
                {
                    if (auto subnet_v6_ptr = std::get_if<net::ip_subnet<net::ip_address_v6>>(&v); subnet_v6_ptr)
                    {
                        auto forward_row = std::make_unique<MIB_IPFORWARD_ROW2>();
                        InitializeIpForwardEntry(forward_row.get());

                        forward_row->InterfaceIndex = ipv6_if_index_;
                        forward_row->InterfaceLuid = luid_;
                        forward_row->DestinationPrefix.Prefix.si_family = AF_INET6;
                        forward_row->DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
                        forward_row->DestinationPrefix.Prefix.Ipv6.sin6_addr = subnet_v6_ptr->get_address();
                        forward_row->DestinationPrefix.PrefixLength = subnet_v6_ptr->get_prefix();
                        forward_row->NextHop.si_family = AF_INET6;
                        forward_row->NextHop.Ipv6.sin6_family = AF_INET6;
                        forward_row->NextHop.Ipv6.sin6_addr = net::ip_address_v6{};
                        forward_row->SitePrefixLength = 0;
                        forward_row->Metric = 0;
                        forward_row->Protocol = MIB_IPPROTO_NT_STATIC;
                        forward_row->Origin = NlroManual;

                        SetLastError(ERROR_SUCCESS);

                        if (const auto error_code = CreateIpForwardEntry2(forward_row.get()); error_code == NO_ERROR
                            || error_code == ERROR_OBJECT_ALREADY_EXISTS)
                            return_value.push_back(std::move(forward_row));
                        else
                            SetLastError(error_code);
                    }
                });

            return return_value;
        }

        /// <summary>
        /// Deletes routing table entry by MIB_IPFORWARD_ROW2 pointer
        /// </summary>
        /// <param name="address">MIB_IPFORWARD_ROW2 unique pointer</param>
        /// <returns>true if successful, false otherwise</returns>
        [[nodiscard]] static bool delete_routes(const std::unique_ptr<MIB_IPFORWARD_ROW2>& address) noexcept
        {
            SetLastError(ERROR_SUCCESS);

            const auto error_code = DeleteIpForwardEntry2(address.get());

            if (NO_ERROR == error_code)
                return true;

            SetLastError(error_code);

            return false;
        }

        /// <summary>
        /// Deletes routing table entries by MIB_IPFORWARD_ROW2 pointers
        /// </summary>
        /// <param name="address">vector of MIB_IPFORWARD_ROW2 unique pointers</param>
        /// <returns>true if successful, false otherwise</returns>
        [[nodiscard]] static bool delete_routes(std::vector<std::unique_ptr<MIB_IPFORWARD_ROW2>> address)
        {
            auto status = true;

            SetLastError(ERROR_SUCCESS);

            std::ranges::for_each(address, [&status](auto&& a) noexcept
            {
                if (const auto error_code = ::DeleteIpForwardEntry2(a.get()); NOERROR != error_code)
                {
                    status = false;
                    ::SetLastError(error_code);
                }
            });

            return status;
        }

        /// <summary>
        /// Removes all routing table entries associated with network interface
        /// </summary>
        /// <returns>true if successful, false otherwise</returns>
        [[nodiscard]] bool reset_adapter_routes() const
        {
            PMIB_IPFORWARD_TABLE2 table = nullptr;

            if (const auto error_code = GetIpForwardTable2(AF_UNSPEC, &table); NO_ERROR == error_code)
            {
                for (unsigned i = 0; i < table->NumEntries; ++i)
                {
                    if (table->Table[i].InterfaceLuid == luid_)
                    {
                        DeleteIpForwardEntry2(&table->Table[i]);
                    }
                }

                FreeMibTable(table);
                return true;
            }
            else
            {
                SetLastError(error_code);
            }

            return false;
        }

        /// <summary>
        /// Removes all unicast addresses associated with network interface
        /// </summary>
        /// <returns>true if successful, false otherwise</returns>
        [[nodiscard]] bool reset_unicast_addresses() const
        {
            PMIB_UNICASTIPADDRESS_TABLE table = nullptr;

            SetLastError(ERROR_SUCCESS);

            auto error_code = GetUnicastIpAddressTable(AF_UNSPEC, &table);

            if (NO_ERROR == error_code)
            {
                for (unsigned i = 0; i < table->NumEntries; ++i)
                {
                    if (table->Table[i].InterfaceLuid == luid_)
                    {
                        error_code = DeleteUnicastIpAddressEntry(&table->Table[i]);
                        if (NO_ERROR != error_code)
                            SetLastError(error_code);
                    }
                }

                FreeMibTable(table);
                return true;
            }

            SetLastError(error_code);

            return false;
        }

        /// <summary>
        /// Resets adapters addresses and routes
        /// </summary>
        /// <returns>true if successful, false otherwise</returns>
        [[nodiscard]] bool reset_adapter() const
        {
            return reset_unicast_addresses() && reset_adapter_routes();
        }

        /// <summary>
        /// Removes specified IPv4 address from the network interface
        /// </summary>
        /// <param name="address">IPv4 address to remove</param>
        /// <returns>true if successful, false otherwise</returns>
        [[nodiscard]] bool delete_unicast_address(const net::ip_address_v4 address) const
        {
            PMIB_UNICASTIPADDRESS_TABLE table = nullptr;

            SetLastError(ERROR_SUCCESS);

            auto error_code = GetUnicastIpAddressTable(AF_INET, &table);

            if (NO_ERROR == error_code)
            {
                for (unsigned i = 0; i < table->NumEntries; ++i)
                {
                    if (table->Table[i].InterfaceLuid == luid_ && net::ip_address_v4(
                        table->Table[i].Address.Ipv4.sin_addr) == address)
                    {
                        error_code = DeleteUnicastIpAddressEntry(&table->Table[i]);
                        if (NO_ERROR != error_code)
                            SetLastError(error_code);
                    }
                }

                FreeMibTable(table);
                return true;
            }

            SetLastError(error_code);

            return false;
        }

        /// <summary>
        /// Removes specified IPv6 address from the network interface
        /// </summary>
        /// <param name="address">IPv6 address to remove</param>
        /// <returns>true if successful, false otherwise</returns>
        [[nodiscard]] bool delete_unicast_address(const net::ip_address_v6& address) const
        {
            PMIB_UNICASTIPADDRESS_TABLE table = nullptr;

            SetLastError(ERROR_SUCCESS);

            auto error_code = GetUnicastIpAddressTable(AF_INET6, &table);

            if (NO_ERROR == error_code)
            {
                for (unsigned i = 0; i < table->NumEntries; ++i)
                {
                    if (table->Table[i].InterfaceLuid == luid_ && net::ip_address_v6(
                        table->Table[i].Address.Ipv6.sin6_addr) == address)
                    {
                        error_code = DeleteUnicastIpAddressEntry(&table->Table[i]);
                        if (NO_ERROR != error_code)
                            SetLastError(error_code);
                    }
                }

                FreeMibTable(table);
                return true;
            }

            SetLastError(error_code);

            return false;
        }

        /// <summary>
        /// Removes NDP entry by MIB_IPNET_ROW2 pointer
        /// </summary>
        /// <param name="address">unique pointer to MIB_IPNET_ROW2</param>
        /// <returns>true if successful, false otherwise</returns>
        [[nodiscard]] static bool delete_ndp_entry(const std::unique_ptr<MIB_IPNET_ROW2>& address) noexcept
        {
            SetLastError(ERROR_SUCCESS);

            const auto error_code = DeleteIpNetEntry2(address.get());
            if (NO_ERROR == error_code)
                return true;

            SetLastError(error_code);

            return false;
        }

    private:
        /// <summary>
        /// Initializes gateways address list (resolves hardware addresses)
        /// </summary>
        /// <returns>nothing</returns>
        void initialize_gateway_hw_address_list() const noexcept
        {
            SetLastError(ERROR_SUCCESS);

            if (!gateway_address_list_.empty())
            {
                std::ranges::for_each(gateway_address_list_, [this](auto& address)
                {
                    MIB_IPNET_ROW2 row{};

                    row.Address.si_family = address.ss_family;
                    row.InterfaceLuid = luid_;

                    switch (address.ss_family)
                    {
                    case AF_INET:
                        row.Address.Ipv4 = sockaddr_in(address);
                        break;
                    case AF_INET6:
                        row.Address.Ipv6 = sockaddr_in6(address);
                        break;
                    default:
                        break;
                    }

                    if (const auto error_code = ResolveIpNetEntry2(&row, nullptr); NO_ERROR == error_code)
                    {
                        address.hardware_address = net::mac_address(row.PhysicalAddress);
                    }
                    else
                    {
                        SetLastError(error_code);
                    }
                });
            }
        }

        /// <summary>
        /// The index of the IPv4 interface
        /// </summary>
        unsigned long if_index_;
        /// <summary>
        /// The interface index for the IPv6 IP address. This member is zero if IPv6 is not available on the interface. 
        /// </summary>
        unsigned long ipv6_if_index_;
        /// <summary>
        /// Contains the name of the adapter. Unlike an adapter's friendly name, the adapter name specified in adapter_name_
        /// is permanent and cannot be modified by the user.
        /// </summary>
        std::string adapter_name_;
        /// <summary>
        /// Contains the name of the underlying hardware adapter.
        /// </summary>
        guid_wrapper true_adapter_name_{};
        /// <summary>
        /// A description for the adapter. 
        /// </summary>
        std::wstring description_;
        /// <summary>
        /// A user-friendly name for the adapter.
        /// </summary>
        std::wstring friendly_name_;
        /// <summary>
        ///  List of IP unicast addresses for the adapter.
        /// </summary>
        std::vector<ip_address_info> unicast_address_list_;
        /// <summary>
        /// List of DNS server addresses for the adapter.
        /// </summary>
        std::vector<ip_address_info> dns_server_address_list_;
        /// <summary>
        /// List of gateways for the adapter.
        /// </summary>
        mutable std::vector<ip_gateway_info> gateway_address_list_;
        /// <summary>
        /// The Media Access Control (MAC) address for the adapter.
        /// </summary>
        net::mac_address physical_address_;
        /// <summary>
        /// The maximum transmission unit (MTU) size, in bytes.
        /// </summary>
        uint16_t mtu_;
        /// <summary>
        /// The current speed in bits per second of the transmit link for the adapter.
        /// </summary>
        ULONG64 transmit_link_speed_;
        /// <summary>
        /// The current speed in bits per second of the receive link for the adapter. 
        /// </summary>
        ULONG64 receive_link_speed_;
        /// <summary>
        /// The interface LUID for the adapter address. 
        /// </summary>
        IF_LUID luid_;
        /// <summary>
        /// The interface type as defined by the Internet Assigned Names Authority (IANA).
        /// Possible values for the interface type are listed in the Ipifcons.h header file. 
        /// </summary>
        unsigned if_type_;
        /// <summary>
        /// The NDIS media type for the interface. This member can be one of the values from the NDIS_MEDIUM
        /// enumeration type defined in the Ntddndis.h header file.
        /// </summary>
        NDIS_MEDIUM media_type_;
        /// <summary>
        /// The NDIS physical medium type.This member can be one of the values from the NDIS_PHYSICAL_MEDIUM
        /// enumeration type defined in the Ntddndis.h header file.
        /// </summary>
        NDIS_PHYSICAL_MEDIUM physical_medium_type_;
        /// <summary>
        /// If value above is NdisPhysicalMediumUnspecified (virtual network interface on top of the real one)
        /// this one may contain real physical media
        /// </summary>
        NDIS_PHYSICAL_MEDIUM true_medium_type_ = NdisPhysicalMediumUnspecified;
        /// <summary>
        /// NDISWANIP associated MAC address
        /// </summary>
        net::mac_address ndis_wan_ip_link_;
        /// <summary>
        /// NDISWANIPV6 associated MAC address
        /// </summary>
        net::mac_address ndis_wan_ipv6_link_;

        // Static class members
    public:
        /// <summary>
        /// Returns list of network interfaces which are:
        /// 1. Have at least one unicast address assigned
        /// 2. Operational (IfOperStatusUp)
        /// 3. Not software loopback
        /// </summary>
        /// <returns>vector of network_adapter_info</returns>
        static std::vector<network_adapter_info> get_external_network_connections()
        {
            std::vector<network_adapter_info> ret_val;
            unsigned long dw_size = 0;
            PMIB_IF_TABLE2 mib_table = nullptr;

            SetLastError(ERROR_SUCCESS);

            // Query detailed information on available network interfaces
            auto error_code = GetIfTable2(&mib_table);
            if (NO_ERROR != error_code)
            {
                SetLastError(error_code);
                return ret_val;
            }

            error_code = GetAdaptersAddresses(AF_UNSPEC,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                nullptr, nullptr, &dw_size);

            // Get available unicast addresses
            if ((ERROR_BUFFER_OVERFLOW == error_code) && dw_size)
            {
                do
                {
                    // Use nothrow allocation to prevent exceptions in callback context
                    std::unique_ptr<unsigned char[]> ip_address_info(new (std::nothrow) unsigned char[dw_size]);

                    if (!ip_address_info)
                    {
                        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                        FreeMibTable(mib_table);
                        return ret_val;
                    }

                    error_code = GetAdaptersAddresses(AF_UNSPEC,
                        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                        GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                        nullptr,
                        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(ip_address_info.get()),
                        &dw_size);

                    if (NO_ERROR == error_code)
                    {
                        auto* current_address = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(ip_address_info.get());

                        while (current_address)
                        {
                            if ((current_address->FirstUnicastAddress == nullptr) ||
                                (current_address->OperStatus != IfOperStatusUp) ||
                                (current_address->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
                                )
                            {
                                current_address = current_address->Next;
                                continue;
                            }

                            // Lookup advanced information on the network interface
                            for (size_t i = 0; i < mib_table->NumEntries; ++i)
                            {
                                if (mib_table->Table[i].InterfaceLuid == current_address->Luid)
                                {
                                    ret_val.emplace_back(current_address, mib_table, i);
                                    break;
                                }
                            }

                            current_address = current_address->Next;
                        }

                        break;
                    }
                    // In case of insufficient buffer size we try to recover by reallocating buffer
                    if (error_code != ERROR_BUFFER_OVERFLOW)
                    {
                        SetLastError(error_code);
                        break;
                    }
                } while (true);
            }
            else
            {
                // GetAdaptersAddresses has failed with status different from ERROR_BUFFER_OVERFLOW when obtaining required buffer size
                if (NO_ERROR != error_code)
                {
                    SetLastError(error_code);
                }
            }

            // Free interface table
            FreeMibTable(mib_table);

            return ret_val;
        }

        /// <summary>
        /// Finds network interface by provided LUID
        /// </summary>
        /// <param name="luid">LUID to lookup</param>
        /// <returns>optional network_adapter_info class instance</returns>
        static std::optional<network_adapter_info> get_connection_by_luid(const IF_LUID& luid)
        {
            unsigned long dw_size = 0;
            PMIB_IF_TABLE2 mib_table = nullptr;

            SetLastError(ERROR_SUCCESS);

            // Query detailed information on available network interfaces
            auto error_code = GetIfTable2(&mib_table);

            if (NO_ERROR != error_code)
            {
                SetLastError(error_code);
                return {};
            }

            // Get available unicast addresses
            error_code = GetAdaptersAddresses(AF_UNSPEC,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_INCLUDE_GATEWAYS |
                GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr, nullptr, &dw_size);

            if ((ERROR_BUFFER_OVERFLOW == error_code) && dw_size)
            {
                do
                {
                    // Use nothrow allocation to prevent exceptions in callback context
                    std::unique_ptr<unsigned char[]> ip_address_info(new (std::nothrow) unsigned char[dw_size]);

                    if (!ip_address_info)
                    {
                        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                        FreeMibTable(mib_table);
                        return {};
                    }

                    error_code = GetAdaptersAddresses(AF_UNSPEC,
                        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                        GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                        nullptr,
                        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(ip_address_info.get()),
                        &dw_size);

                    if (NO_ERROR == error_code)
                    {
                        auto* current_address = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(ip_address_info.get());

                        while (current_address)
                        {
                            if (current_address->Luid != luid)
                            {
                                current_address = current_address->Next;
                                continue;
                            }

                            // Lookup advanced information on the network interface
                            for (size_t i = 0; i < mib_table->NumEntries; ++i)
                            {
                                if (mib_table->Table[i].InterfaceLuid == current_address->Luid)
                                {
                                    network_adapter_info result{ current_address, mib_table, i };
                                    FreeMibTable(mib_table);
                                    return std::move(result);
                                }
                            }

                            current_address = current_address->Next;
                        }

                        break;
                    }
                    // In case of insufficient buffer size we try to recover by reallocating buffer
                    if (error_code != ERROR_BUFFER_OVERFLOW)
                    {
                        SetLastError(error_code);
                        break;
                    }
                } while (true);
            }
            else
            {
                // GetAdaptersAddresses has failed with status different from ERROR_BUFFER_OVERFLOW when obtaining required buffer size
                if (NO_ERROR != error_code)
                {
                    SetLastError(error_code);
                }
            }

            // Free interface table
            FreeMibTable(mib_table);

            return {};
        }

        /// <summary>
        /// Finds network interface by provided hardware address
        /// </summary>
        /// <param name="address">MAC address to lookup</param>
        /// <returns>optional network_adapter_info class instance</returns>
        static std::optional<network_adapter_info> get_connection_by_hw_address(const net::mac_address& address)
        {
            unsigned long dw_size = 0;
            PMIB_IF_TABLE2 mib_table = nullptr;

            SetLastError(ERROR_SUCCESS);

            // Query detailed information on available network interfaces
            auto error_code = GetIfTable2(&mib_table);

            if (NO_ERROR != error_code)
            {
                SetLastError(error_code);
                return {};
            }

            // Get available unicast addresses
            error_code = GetAdaptersAddresses(AF_UNSPEC,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_INCLUDE_GATEWAYS |
                GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr, nullptr, &dw_size);

            if ((ERROR_BUFFER_OVERFLOW == error_code) && dw_size)
            {
                do
                {
                    // Use nothrow allocation to prevent exceptions in callback context
                    std::unique_ptr<unsigned char[]> ip_address_info(new (std::nothrow) unsigned char[dw_size]);

                    if (!ip_address_info)
                    {
                        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                        FreeMibTable(mib_table);
                        return {};
                    }

                    error_code = GetAdaptersAddresses(AF_UNSPEC,
                        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                        GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                        nullptr,
                        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(ip_address_info.get()),
                        &dw_size);

                    if (NO_ERROR == error_code)
                    {
                        auto* current_address = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(ip_address_info.get());

                        while (current_address)
                        {
                            if (net::mac_address(current_address->PhysicalAddress) != address)
                            {
                                current_address = current_address->Next;
                                continue;
                            }

                            // Lookup advanced information on the network interface
                            for (size_t i = 0; i < mib_table->NumEntries; ++i)
                            {
                                if (mib_table->Table[i].InterfaceLuid == current_address->Luid)
                                {
                                    network_adapter_info result{ current_address, mib_table, i };
                                    FreeMibTable(mib_table);
                                    return std::move(result);
                                }
                            }

                            current_address = current_address->Next;
                        }

                        break;
                    }

                    // In case of insufficient buffer size we try to recover by reallocating buffer
                    if (error_code != ERROR_BUFFER_OVERFLOW)
                    {
                        SetLastError(error_code);
                        break;
                    }
                } while (true);
            }
            else
            {
                // GetAdaptersAddresses has failed with status different from ERROR_BUFFER_OVERFLOW when obtaining required buffer size
                if (NO_ERROR != error_code)
                {
                    SetLastError(error_code);
                }
            }

            // Free interface table
            FreeMibTable(mib_table);

            return {};
        }

        /// <summary>
        /// Finds network interface by provided GUID
        /// </summary>
        /// <param name="guid">GUID to lookup</param>
        /// <returns>optional network_adapter_info class instance</returns>
        static std::optional<network_adapter_info> get_connection_by_guid(const std::string& guid)
        {
            unsigned long dw_size = 0;
            PMIB_IF_TABLE2 mib_table = nullptr;

            SetLastError(ERROR_SUCCESS);

            // Query detailed information on available network interfaces
            auto error_code = GetIfTable2(&mib_table);

            if (NO_ERROR != error_code)
            {
                SetLastError(error_code);
                return {};
            }

            // Get available unicast addresses
            error_code = GetAdaptersAddresses(AF_UNSPEC,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_INCLUDE_GATEWAYS |
                GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr, nullptr, &dw_size);

            if ((ERROR_BUFFER_OVERFLOW == error_code) && dw_size)
            {
                do
                {
                    // Use nothrow allocation to prevent exceptions in callback context
                    std::unique_ptr<unsigned char[]> ip_address_info(new (std::nothrow) unsigned char[dw_size]);

                    if (!ip_address_info)
                    {
                        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                        FreeMibTable(mib_table);
                        return {};
                    }

                    error_code = GetAdaptersAddresses(AF_UNSPEC,
                        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                        GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                        nullptr,
                        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(ip_address_info.get()),
                        &dw_size);

                    if (NO_ERROR == error_code)
                    {
                        auto* current_address = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(ip_address_info.get());

                        while (current_address)
                        {
                            std::string adapter_name{ current_address->AdapterName };
                            std::ranges::transform(adapter_name, adapter_name.begin(), toupper);
                            if (adapter_name.find(guid) == std::string::npos)
                            {
                                current_address = current_address->Next;
                                continue;
                            }

                            // Lookup advanced information on the network interface
                            for (size_t i = 0; i < mib_table->NumEntries; ++i)
                            {
                                if (mib_table->Table[i].InterfaceLuid == current_address->Luid)
                                {
                                    network_adapter_info result{ current_address, mib_table, i };
                                    FreeMibTable(mib_table);
                                    return std::move(result);
                                }
                            }

                            current_address = current_address->Next;
                        }

                        break;
                    }

                    // In case of insufficient buffer size we try to recover by reallocating buffer
                    if (error_code != ERROR_BUFFER_OVERFLOW)
                    {
                        SetLastError(error_code);
                        break;
                    }
                } while (true);
            }
            else
            {
                // GetAdaptersAddresses has failed with status different from ERROR_BUFFER_OVERFLOW when obtaining required buffer size
                if (NO_ERROR != error_code)
                {
                    SetLastError(error_code);
                }
            }

            // Free interface table
            FreeMibTable(mib_table);

            return {};
        }
    };

    /// <summary>
    /// Base CRTP helper class to query best and routable interfaces
    /// and network changes callback notifications 
    /// </summary>
    /// <typeparam name="T">CRTP class</typeparam>
    template <typename T>
    class network_config_info  // NOLINT(clang-diagnostic-padded)
    {
        /// <summary>
        /// Lock type
        /// </summary>
        using mutex_type = std::mutex;
        /// <summary>
        /// Read lock type
        /// </summary>
        using read_lock = std::unique_lock<mutex_type>;
        /// <summary>
        /// Write lock type
        /// </summary>
        using write_lock = std::unique_lock<mutex_type>;
        /// <summary>
        /// NotifyIpInterfaceChange handle value
        /// </summary>
        HANDLE notify_ip_interface_change_{ nullptr };
        
        /// <summary>
        /// Synchronization lock
        /// </summary>
        mutex_type lock_;
        
        /// <summary>
        /// Tracks callback enters/leaves
        /// </summary>
        std::atomic_uint32_t notify_ip_interface_ref_{ 0 };

        /// <summary>
        /// Default constructor
        /// </summary>
        network_config_info() = default;

        /// <summary>
        /// Move constructor
        /// </summary>
        /// <param name="other">object instance to move from</param>
        network_config_info(network_config_info&& other) noexcept
        {
            write_lock rhs_lk(other.lock_);

            notify_ip_interface_change_ = other.notify_ip_interface_change_;
            other.notify_ip_interface_change_ = nullptr;
            notify_ip_interface_ref_ = other.notify_ip_interface_ref_.exchange(0);
        }

public:    
        /// <summary>
        /// Deleted copy constructor
        /// </summary>
        network_config_info(const network_config_info& other) = delete;  // NOLINT(bugprone-crtp-constructor-accessibility)

        /// <summary>
        /// Deleted copy assignment
        /// </summary>
        network_config_info& operator=(const network_config_info& other) = delete;

        /// <summary>
        /// Move assignment operator
        /// </summary>
        /// <param name="other">object instance to move from</param>
        /// <returns>this object reference</returns>
        network_config_info& operator=(network_config_info&& other) noexcept
        {
            if (this == &other)
                return *this;

            std::scoped_lock lock(lock_, other.lock_);

            notify_ip_interface_change_ = other.notify_ip_interface_change_;
            other.notify_ip_interface_change_ = nullptr;

            notify_ip_interface_ref_ = other.notify_ip_interface_ref_.exchange(0);
            return *this;
        }

        /// <summary>
        /// Destructor cancels NotifyIpInterfaceChange
        /// </summary>
        virtual ~network_config_info()
        {
            if (notify_ip_interface_change_)
                cancel_notify_ip_interface_change();
        }

        /// <summary>
        /// Determines best network interface to reach specified IPv4 address
        /// </summary>
        /// <param name="ip_address">IPv4 address</param>
        /// <returns>optional network_adapter_info</returns>
        static std::optional<network_adapter_info> get_best_interface(const net::ip_address_v4& ip_address) noexcept
        {
            try
            {
                unsigned long best_if_index = 0;
                sockaddr_in socket_address{};

                socket_address.sin_family = AF_INET;
                socket_address.sin_addr = ip_address;

                SetLastError(ERROR_SUCCESS);

                auto adapters = network_adapter_info::get_external_network_connections();

                const auto last_error_code = GetLastError();

                if (const auto error_code = GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&socket_address), &best_if_index)
                    ; NO_ERROR == error_code)
                {
                    for (auto& adapter : adapters)
                    {
                        if (adapter.get_if_index() == best_if_index)
                            return adapter;
                    }
                    SetLastError(last_error_code);
                }
                else
                {
                    SetLastError(error_code);
                }
            }
            catch (const std::bad_alloc&)
            {
                ::SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            }
            catch (const std::exception&)
            {
                ::SetLastError(ERROR_INTERNAL_ERROR);
            }
            catch (...)
            {
                ::SetLastError(ERROR_UNHANDLED_EXCEPTION);
            }

            return {};
        }

        /// <summary>
        /// Determines best network interface to reach specified IPv6 address
        /// </summary>
        /// <param name="ip_address">IPv6 address</param>
        /// <returns>optional network_adapter_info</returns>
        static std::optional<network_adapter_info> get_best_interface(const net::ip_address_v6& ip_address) noexcept
        {
            try
            {
                unsigned long best_if_index = 0;
                sockaddr_in6 socket_address{};

                socket_address.sin6_family = AF_INET6;
                socket_address.sin6_addr = ip_address;

                SetLastError(ERROR_SUCCESS);

                auto adapters = network_adapter_info::get_external_network_connections();

                const auto last_error_code = GetLastError();

                if (const auto error_code = GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&socket_address), &best_if_index)
                    ; NO_ERROR == error_code)
                {
                    for (auto& adapter : adapters)
                    {
                        if (adapter.get_if_index() == best_if_index)
                            return adapter;
                    }
                    SetLastError(last_error_code);
                }
                else
                {
                    SetLastError(error_code);
                }
            }
            catch (const std::bad_alloc&)
            {
                ::SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            }
            catch (const std::exception&)
            {
                ::SetLastError(ERROR_INTERNAL_ERROR);
            }
            catch (...)
            {
                ::SetLastError(ERROR_UNHANDLED_EXCEPTION);
            }

            return {};
        }

        /// <summary>
        /// Retrieves a list of routable network interfaces for the specified IPv4 address
        /// </summary>
        /// <param name="ip_address">IPv4 address</param>
        /// <returns>vector of network_adapter_info objects</returns>
        static std::vector<network_adapter_info> get_routable_interfaces(const net::ip_address_v4& ip_address)
        {
            auto is_invalid_route = [&ip_address](const auto& adapter)
                {
                    SOCKADDR_INET dest_address, best_route_address{};
                    dest_address.si_family = AF_INET;
                    dest_address.Ipv4.sin_family = AF_INET;
                    dest_address.Ipv4.sin_addr = ip_address;
                    MIB_IPFORWARD_ROW2 forward_row{};

                    if (const auto error_code = GetBestRoute2(nullptr, adapter.get_if_index(), nullptr, &dest_address, 0,
                        &forward_row, &best_route_address); NO_ERROR != error_code)
                    {
                        ::SetLastError(error_code);
                        return true;  // Invalid route - should be removed
                    }
                    return false;  // Valid route - keep it
                };

            auto adapters = network_adapter_info::get_external_network_connections();

            std::erase_if(adapters, is_invalid_route);  // C++20 erase_if

            return adapters;
        }

        /// <summary>
        /// Retrieves a list of routable network interfaces for the specified IPv6 address
        /// </summary>
        /// <param name="ip_address">IPv6 address</param>
        /// <returns>vector of network_adapter_info objects</returns>
        static std::vector<network_adapter_info> get_routable_interfaces(const net::ip_address_v6& ip_address)
        {
            auto is_invalid_route = [&ip_address](const auto& adapter)
                {
                    SOCKADDR_INET dest_address, best_route_address{};
                    dest_address.si_family = AF_INET6;
                    dest_address.Ipv6.sin6_family = AF_INET6;
                    dest_address.Ipv6.sin6_addr = ip_address;
                    MIB_IPFORWARD_ROW2 forward_row{};

                    if (const auto error_code = GetBestRoute2(nullptr, adapter.get_if_index(), nullptr, &dest_address, 0,
                        &forward_row, &best_route_address); NO_ERROR != error_code)
                    {
                        ::SetLastError(error_code);
                        return true;  // Invalid route - should be removed
                    }
                    return false;  // Valid route - keep it
                };

            auto adapters = network_adapter_info::get_external_network_connections();

            std::erase_if(adapters, is_invalid_route);  // C++20 erase_if

            return adapters;
        }

    protected:
        /// <summary>
        /// Sets callback for NotifyIpInterfaceChange
        /// </summary>
        /// <returns>true if successful, false otherwise</returns>
        bool set_notify_ip_interface_change() noexcept
        {
            SetLastError(ERROR_SUCCESS);

            // Pass the base class pointer instead of 'this' to avoid offset issues
            auto* base_ptr = static_cast<network_config_info*>(this);
            auto error_code = ::NotifyIpInterfaceChange(AF_UNSPEC, &network_config_info::ip_interface_changed_callback,
                base_ptr, FALSE, &notify_ip_interface_change_);

            if (NO_ERROR == error_code)
                return true;

            ::SetLastError(error_code);

            return false;
        }

        /// <summary>
        /// Cancels callback for NotifyIpInterfaceChange
        /// </summary>
        /// <returns>true if successful, false otherwise</returns>
        bool cancel_notify_ip_interface_change() noexcept
        {
            SetLastError(ERROR_SUCCESS);

            if (notify_ip_interface_change_ == nullptr)
                return true;

            const auto error_code = CancelMibChangeNotify2(notify_ip_interface_change_);
            notify_ip_interface_change_ = nullptr;

            if (NO_ERROR == error_code)
                return true;

            SetLastError(error_code);

            return false;
        }

        /// <summary>
        /// NotifyIpInterfaceChange callback. Calls ip_interface_changed_callback of CRTP derived class
        /// </summary>
        /// <param name="caller_context">base class pointer</param>
        /// <param name="row"> to MIB_IPINTERFACE_ROW</param>
        /// <param name="notification_type">type of notification</param>
        /// <returns></returns>
        static void __stdcall ip_interface_changed_callback(void* caller_context, PMIB_IPINTERFACE_ROW row,
            MIB_NOTIFICATION_TYPE notification_type) noexcept
        {
            try
            {
                if (auto* const base_pointer = static_cast<network_config_info<T>*>(caller_context); base_pointer)
                {
                    auto* const this_pointer = static_cast<T*>(base_pointer);

                    // RAII guard to ensure ref count is always decremented
                    struct ref_guard {
                        std::atomic_uint32_t* ref_ptr;
                        explicit ref_guard(std::atomic_uint32_t* p) noexcept : ref_ptr(p) { ref_ptr->fetch_add(1); }
                        ~ref_guard() noexcept { ref_ptr->fetch_sub(1); }
                        ref_guard(const ref_guard&) = delete;
                        ref_guard& operator=(const ref_guard&) = delete;
                        ref_guard(ref_guard&&) = delete;
                        ref_guard& operator=(ref_guard&&) = delete;
                    } guard{ &this_pointer->notify_ip_interface_ref_ };

                    this_pointer->ip_interface_changed_callback(row, notification_type);
                }
            }
            catch (const std::bad_alloc&)
            {
                ::SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            }
            catch (const std::exception&)
            {
                ::SetLastError(ERROR_INTERNAL_ERROR);
            }
            catch (...)
            {
                ::SetLastError(ERROR_UNHANDLED_EXCEPTION);
            }
        }

        /// <summary>
        /// Checks if enter/leave reference counter is zero, and we can unload
        /// </summary>
        /// <returns>true if unload is possible, false otherwise</returns>
        bool notify_ip_interface_can_unload() const
        {
            return (notify_ip_interface_ref_ == 0);
        }

        friend T;
    };
}
