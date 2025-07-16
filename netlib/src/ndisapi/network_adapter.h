/// <summary>
/// Module Name: network_adapter.h 
/// Abstract: Network interface wrapper class 
/// </summary>
// --------------------------------------------------------------------------------
#pragma once

namespace ndisapi
{
    /// <summary>
    /// Offset to the IPv4 address in the protocol buffer block
    /// </summary>
    constexpr unsigned ipv4_address_offset = 584;

    /// <summary>
    /// Offset to the IPv6 address in the protocol buffer block
    /// </summary>
    constexpr unsigned ipv6_address_offset = 588;

    /// <summary>
    /// NDISWAN network interface common types
    /// </summary>
    enum class ndis_wan_type
    {
        /// <summary>
        /// Undefined
        /// </summary>
        ndis_wan_none,
        /// <summary>
        /// \Device\NDISWANIP
        /// </summary>
        ndis_wan_ip,
        /// <summary>
        /// \Device\NDISWANIPV6
        /// </summary>
        ndis_wan_ipv6,
        /// <summary>
        /// \Device\NDISWANBH
        /// </summary>
        ndis_wan_bh
    };

    /// <summary>
    /// NDISWAN connection wrapper struct
    /// </summary>
    struct ndis_wan_link_info
    {
        /// <summary>
        /// Constructs ndis_wan_link_info from the RAS_LINK_INFO provided information
        /// </summary>
        /// <param name="family">Address family</param>
        /// <param name="link_info_ptr">RAS_LINK_INFO pointer</param>
        ndis_wan_link_info(const ADDRESS_FAMILY family, const PRAS_LINK_INFO link_info_ptr) :
            link_speed(link_info_ptr->LinkSpeed),
            mtu(static_cast<uint16_t>(link_info_ptr->MaximumTotalSize)),
            remote_hw_address(link_info_ptr->RemoteAddress),
            local_hw_address(link_info_ptr->LocalAddress)
        {
            sockaddr_in address_v4{};
            sockaddr_in6 address_v6{};

            address_v4.sin_family = AF_INET;
            address_v6.sin6_family = AF_INET6;

            switch (family)
            {
            case AF_INET:
                address_v4.sin_addr.S_un.S_un_b.s_b1 = link_info_ptr->ProtocolBuffer[ipv4_address_offset];
                address_v4.sin_addr.S_un.S_un_b.s_b2 = link_info_ptr->ProtocolBuffer[ipv4_address_offset + 1];
                address_v4.sin_addr.S_un.S_un_b.s_b3 = link_info_ptr->ProtocolBuffer[ipv4_address_offset + 2];
                address_v4.sin_addr.S_un.S_un_b.s_b4 = link_info_ptr->ProtocolBuffer[ipv4_address_offset + 3];
                ip_address = iphelper::ip_address_info(address_v4);
                break;
            case AF_INET6:
                address_v6.sin6_addr.u.Byte[8] = link_info_ptr->ProtocolBuffer[ipv6_address_offset];
                address_v6.sin6_addr.u.Byte[9] = link_info_ptr->ProtocolBuffer[ipv6_address_offset + 1];
                address_v6.sin6_addr.u.Byte[10] = link_info_ptr->ProtocolBuffer[ipv6_address_offset + 2];
                address_v6.sin6_addr.u.Byte[11] = link_info_ptr->ProtocolBuffer[ipv6_address_offset + 3];
                address_v6.sin6_addr.u.Byte[12] = link_info_ptr->ProtocolBuffer[ipv6_address_offset + 4];
                address_v6.sin6_addr.u.Byte[13] = link_info_ptr->ProtocolBuffer[ipv6_address_offset + 5];
                address_v6.sin6_addr.u.Byte[14] = link_info_ptr->ProtocolBuffer[ipv6_address_offset + 6];
                address_v6.sin6_addr.u.Byte[15] = link_info_ptr->ProtocolBuffer[ipv6_address_offset + 7];
                ip_address = iphelper::ip_address_info(address_v6);
                break;
            default:
                break;
            }
        }

        /// <summary>
        /// Specifies the speed of the link, in units of 100 bps.
        /// </summary>
        uint32_t link_speed;
        /// <summary>
        /// Specifies the maximum number of bytes per packet that the protocol can send over the network.
        /// </summary>
        uint16_t mtu;
        /// <summary>
        /// Represents the address of the remote node on the link in Ethernet-style format. NDISWAN supplies this value.
        /// </summary>
        net::mac_address remote_hw_address;
        /// <summary>
        /// Represents the protocol-determined context for indications on this link in Ethernet-style format.
        /// </summary>
        net::mac_address local_hw_address;
        /// <summary>
        /// Assigned IP address
        /// </summary>
        iphelper::ip_address_info ip_address{};
    };

    // --------------------------------------------------------------------------------
    /// <summary>
    /// Class representing network NDIS level interface
    /// </summary>
    // --------------------------------------------------------------------------------
    class network_adapter
    {
    public:
        /// <summary>
        /// Default constructor
        /// </summary>
        network_adapter() = default;

        /// <summary>
        /// Constructs network_adapter instance using the provided parameters
        /// </summary>
        /// <param name="api">NDISAPI instance to associate with</param>
        /// <param name="adapter_handle">NDISAPI adapter handle</param>
        /// <param name="mac_addr">network adapter hardware address</param>
        /// <param name="internal_name">Network adapter internal name, typically GUID</param>
        /// <param name="friendly_name">Network adapter user-friendly  name</param>
        /// <param name="medium">Network adapter NDIS medium</param>
        /// <param name="mtu">Network adapter MTU</param>
        network_adapter(
            CNdisApi* api,
            const HANDLE adapter_handle,
            const unsigned char* mac_addr,
            std::string internal_name,
            std::string friendly_name,
            const uint32_t medium,
            const uint16_t mtu
        ) : api_(api),
            hardware_address_{ mac_addr },
            internal_name_(std::move(internal_name)),
            friendly_name_(std::move(friendly_name)),
            medium_{ medium },
            mtu_{ mtu },
            adapter_handle_{ adapter_handle }
        {
            //
            // Initialize NDISWAN type
            //
            if (CNdisApi::IsNdiswanIp(internal_name_.c_str()))
            {
                ndis_wan_type_ = ndis_wan_type::ndis_wan_ip;
            }
            else if (CNdisApi::IsNdiswanIpv6(internal_name_.c_str()))
            {
                ndis_wan_type_ = ndis_wan_type::ndis_wan_ipv6;
            }
            else if (CNdisApi::IsNdiswanBh(internal_name_.c_str()))
            {
                ndis_wan_type_ = ndis_wan_type::ndis_wan_bh;
            }
        }

        ~network_adapter() = default;
        network_adapter(const network_adapter& other) = default;
        network_adapter(network_adapter&& other) noexcept = default;
        network_adapter& operator=(const network_adapter& other) = default;
        network_adapter& operator=(network_adapter&& other) noexcept = default;

        // ********************************************************************************
        /// <summary>
        /// Returns network interface handle value
        /// </summary>
        /// <returns>network adapter handle</returns>
        // ********************************************************************************
        [[nodiscard]] HANDLE get_adapter() const { return adapter_handle_; }

        // ********************************************************************************
        /// <summary>
        /// Stops filtering the network interface and tries to restore its original state
        /// </summary>
        // ********************************************************************************
        void release() const
        {
            ADAPTER_MODE adapter_mode{ adapter_handle_, 0 };

            // Reset adapter mode and flush the packet queue
            set_packet_event(nullptr);
            api_->SetAdapterMode(&adapter_mode);
            api_->FlushAdapterPacketQueue(adapter_handle_);
        }

        // ********************************************************************************
        /// <summary>
        /// Sets the operational mode of the network adapter.
        /// </summary>
        /// <param name="flags">A bitmask representing the desired operational mode(s) for the adapter.</param>
        /// <returns>True if the mode was successfully set, false otherwise.</returns>
        /// <remarks>
        /// This function configures the network adapter's operational mode based on the provided flags.
        /// These flags can enable various features such as promiscuous mode, packet filtering, etc.
        /// It directly interacts with the underlying NDISAPI to apply the settings.
        /// </remarks>
        // ********************************************************************************
        [[nodiscard]] bool set_mode(const uint32_t flags) const
        {
            ADAPTER_MODE adapter_mode{ adapter_handle_, flags };
            return api_->SetAdapterMode(&adapter_mode);
        }

        // ********************************************************************************
        /// <summary>
        /// Retrieves the current mode of the network adapter.
        /// </summary>
        /// <returns>A std::optional containing the adapter mode flags if successful, std::nullopt otherwise.</returns>
        /// <remarks>
        /// The mode flags determine the operational mode of the adapter, such as whether it's in promiscuous mode,
        /// filtering mode, etc. This function queries the underlying driver to obtain the current settings.
        /// </remarks>
        // ********************************************************************************
        [[nodiscard]] std::optional<uint32_t> get_mode() const
        {
            ADAPTER_MODE adapter_mode{ adapter_handle_, 0 };
            if (api_->GetAdapterMode(&adapter_mode))
                return adapter_mode.dwFlags;
            return {};
        }

        // ********************************************************************************
        /// <summary>
        /// Queries the list of RAS connections for NDISWAN interface
        /// </summary>
        /// <returns>list of RAS connections</returns>
        // ********************************************************************************
        [[nodiscard]] std::optional<std::vector<ndis_wan_link_info>> get_ras_links() const;

        // ********************************************************************************
        /// <summary>
        /// submits external packet event into the driver
        /// </summary>
        /// <returns>status of the operation</returns>
        // ********************************************************************************
        [[maybe_unused]] bool set_packet_event(const HANDLE event_handle) const
        {
            return api_->SetPacketEvent(
                adapter_handle_,
                event_handle);
        }
        // ********************************************************************************
        /// <summary>
        /// Network adapter internal name getter
        /// </summary>
        /// <returns>internal name string reference</returns>
        // ********************************************************************************
        [[nodiscard]] const std::string& get_internal_name() const { return internal_name_; }

        // ********************************************************************************
        /// <summary>
        /// Network adapter user friendly name getter
        /// </summary>
        /// <returns>user friendly name string reference</returns>
        // ********************************************************************************
        [[nodiscard]] const std::string& get_friendly_name() const { return friendly_name_; }

        // ********************************************************************************
        /// <summary>
        /// Queries network adapter hardware address
        /// </summary>
        /// <returns>network adapter MAC address</returns>
        // ********************************************************************************
        [[nodiscard]] net::mac_address get_hw_address() const { return hardware_address_; }

        // ********************************************************************************
        /// <summary>
        /// Returns network adapter NDIS medium
        /// </summary>
        // ********************************************************************************
        [[nodiscard]] uint32_t get_medium() const { return medium_; }
        // ********************************************************************************
        /// <summary>
        /// Returns network adapter maximum transmission unit
        /// </summary>
        // ********************************************************************************
        [[nodiscard]] uint16_t get_mtu() const { return mtu_; }
        // ********************************************************************************
        /// <summary>
        /// Returns network adapter NDISWAN type
        /// </summary>
        /// <returns></returns>
        // ********************************************************************************
        [[nodiscard]] ndis_wan_type get_ndis_wan_type() const { return ndis_wan_type_; }

    protected:
        /// <summary>
        /// Driver interface pointer
        /// </summary>
        CNdisApi* api_{ nullptr };
        /// <summary>
        /// Network interface current MAC address
        /// </summary>
        net::mac_address hardware_address_;
        /// <summary>
        /// Internal network interface name
        /// </summary>
        std::string internal_name_;
        /// <summary>
        /// User-friendly name
        /// </summary>
        std::string friendly_name_;
        /// <summary>
        /// Network medium
        /// </summary>
        uint32_t medium_{};
        /// <summary>
        /// Maximum Transmission Unit
        /// </summary>
        uint16_t mtu_{};
        /// <summary>
        /// Kernel handle associated with network interface
        /// </summary>
        HANDLE adapter_handle_{};
        /// <summary>
        /// NDISWAN adapter type
        /// </summary>
        ndis_wan_type ndis_wan_type_{ ndis_wan_type::ndis_wan_none };
    };

    inline std::optional<std::vector<ndis_wan_link_info>> network_adapter::get_ras_links() const
    {
        if (get_ndis_wan_type() == ndis_wan_type::ndis_wan_none)
            return {};

        const auto ras_links_storage = std::make_unique<std::aligned_storage_t<sizeof(RAS_LINKS)>>();
        const auto ras_links = reinterpret_cast<PRAS_LINKS>(ras_links_storage.get());

        std::vector<ndis_wan_link_info> result;

        if (api_->GetRasLinks(get_adapter(), ras_links))
        {
            for (size_t i = 0; i < ras_links->nNumberOfLinks; ++i)
            {
                switch (get_ndis_wan_type())
                {
                case ndis_wan_type::ndis_wan_ip:
                {
                    result.emplace_back(AF_INET, &ras_links->RasLinks[i]);
                    break;
                }
                case ndis_wan_type::ndis_wan_ipv6:
                {
                    result.emplace_back(AF_INET6, &ras_links->RasLinks[i]);
                    break;
                }
                case ndis_wan_type::ndis_wan_none:
                case ndis_wan_type::ndis_wan_bh:
                    break;
                }
            }
        }

        if (!result.empty())
            return { result };

        return {};
    }
}
