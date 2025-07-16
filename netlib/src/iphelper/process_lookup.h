#pragma once

namespace iphelper
{
    // --------------------------------------------------------------------------------
    /// <summary>
    /// Represents a networking application
    /// </summary>
    // --------------------------------------------------------------------------------
    struct network_process
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        network_process() = default;

        /// <summary>
        /// Constructs object instance from provided process ID, name and path
        /// </summary>
        /// <param name="id">process ID</param>
        /// <param name="name">process name</param>
        /// <param name="path">path to the executable</param>
        network_process(const unsigned long id, std::wstring name, std::wstring path) :
            id(id), name(std::move(name)), path_name(std::move(path)), device_path_name(convert_to_device_path(path_name))
        {
            this->name = to_upper(this->name);
            this->path_name = to_upper(this->path_name);
            this->device_path_name = to_upper(this->device_path_name);
        }

        // Utility function to validate wide string pointers
        static bool is_valid_wide_string(const wchar_t* ptr_str) {
            return ptr_str != nullptr && ptr_str[0] != L'\0';
        }

        /// <summary>
        /// Converts a given path to its corresponding device path.
        /// </summary>
        /// <param name="path">The original path to be converted.</param>
        /// <returns>
        /// A std::wstring containing the device path if the conversion is successful;
        /// otherwise, an empty std::wstring.
        /// </returns>
        /// <remarks>
        /// This function performs the following steps:
        /// 1. Validates the input path.
        /// 2. Extracts the drive letter from the path.
        /// 3. Queries the device name for the drive letter.
        /// 4. Replaces the drive letter with the device name in the original path.
        /// 5. Converts the resulting string to lower case.
        /// </remarks>
        static std::wstring convert_to_device_path(const std::wstring& path)
        {
            // Validate the input path
            if (!is_valid_wide_string(path.c_str())) {
                return L"";
            }

            // Extract the drive letter from the path
            if (path.size() < 2 || path[1] != L':') {
                // Invalid path format
                return L"";
            }

            const wchar_t drive_letter[3] = { path[0], path[1], L'\0' };

            // Query the device name for the drive letter
            wchar_t device_name[MAX_PATH];
            if (QueryDosDeviceW(drive_letter, device_name, MAX_PATH) == 0) {
                // Failed to query device name
                return L"";
            }

            // Replace the drive letter with the device name in the original path
            std::wstring device_path(device_name);
            device_path += path.substr(2);

            // Convert the resulting string to lower case
            std::ranges::transform(device_path, device_path.begin(), towlower);

            return device_path;
        }

        /**
        * @brief Converts a std::wstring to upper case.
        *
        * This is a utility function that converts a string to upper case. It uses the std::ranges::transform
        * function and the ::towupper function to convert the string to upper case.
        *
        * @param str The std::wstring to be converted to upper case.
        * @return The upper case version of the input std::wstring.
        */
        static std::wstring to_upper(const std::wstring& str) {
            std::wstring upper_case;
            std::ranges::transform(str, std::back_inserter(upper_case), ::towupper);
            return upper_case;
        }

        unsigned long id{};
        std::wstring name;
        std::wstring path_name;
        std::wstring device_path_name;
    };

    // --------------------------------------------------------------------------------
    /// <summary>
    /// process_lookup class utilizes IP Helper API to match TCP/UDP network packet to local process
    /// Designed as a singleton
    /// </summary>
    /// <typeparam name="T">net::ip_address_v4 or net::ip_address_v6</typeparam>
    // --------------------------------------------------------------------------------
    template <typename T>
    class process_lookup final: public netlib::log::logger<process_lookup<T>>
    {
        using log_level = netlib::log::log_level;

        /// <summary>  
        /// Timeout value for the protected apps cache in seconds.  
        /// </summary>  
        static constexpr std::chrono::seconds protected_apps_cache_timeout{ 2 };

        /// <summary>
        /// Type to store TCP sessions
        /// </summary>
        using tcp_hashtable_t = std::unordered_map<net::ip_session<T>, std::shared_ptr<network_process>>;

        /// <summary>
        /// Type to store UDP sessions
        /// </summary>
        using udp_hashtable_t = std::unordered_map<net::ip_endpoint<T>, std::shared_ptr<network_process>>;

        /// <summary>
        /// Type to store TCP protected sessions (the ones which can't be resolved and defaulted to SYSTEM).
        /// </summary>
        using tcp_protected_t = std::unordered_map<net::ip_session<T>, std::atomic<std::chrono::time_point<std::chrono::steady_clock>>>;

        /// <summary>
        /// Type to store UDP protected sessions (the ones which can't be resolved and defaulted to SYSTEM).
        /// </summary>
        using udp_protected_t = std::unordered_map<net::ip_endpoint<T>, std::atomic<std::chrono::time_point<std::chrono::steady_clock>>>;

    public:
        /// <summary>
        /// Initializes current state of TCP/UDP connections.
        /// </summary>
        explicit process_lookup(const log_level log_level = log_level::error,
            const std::optional<std::reference_wrapper<std::ostream>> log_stream = std::nullopt) :
            netlib::log::logger<process_lookup>(log_level, log_stream)
        {
            default_process_ = std::make_shared<network_process>(0, L"SYSTEM", L"SYSTEM");

            initialize_tcp_table();
            initialize_udp_table();
        }

        /// <summary>
        /// Deleted copy constructor
        /// </summary>
        process_lookup(const process_lookup& other) = delete;

        /// <summary>
        /// deleted move constructor
        /// </summary>
        process_lookup(process_lookup&& other) noexcept = delete;

        /// <summary>
        /// Deleted copy assignment
        /// </summary>
        process_lookup& operator=(const process_lookup& other) = delete;

        /// <summary>
        /// Deleted move assignment
        /// </summary>
        process_lookup& operator=(process_lookup&& other) noexcept = delete;

    private:
        /// <summary>
        /// TCP sessions hashtable
        /// </summary>
        tcp_hashtable_t tcp_to_app_;

        /// <summary>
        /// UDP sessions hashtable
        /// </summary>
        udp_hashtable_t udp_to_app_;

        /// <summary>
        /// Mutex for synchronizing access to the TCP to application mapping.
        /// </summary>
        std::shared_mutex tcp_to_app_mutex_;

        /// <summary>
        /// Mutex for synchronizing access to the UDP to application mapping.
        /// </summary>
        std::shared_mutex udp_to_app_mutex_;

        /// <summary>
        /// Type to store TCP protected sessions (the ones which can't be resolved and defaulted to SYSTEM).
        /// </summary>
        tcp_protected_t tcp_protected_apps_;

        /// <summary>
        /// Type to store UDP protected sessions (the ones which can't be resolved and defaulted to SYSTEM).
        /// </summary>
        udp_protected_t udp_protected_apps_;

        /// <summary>
        /// Mutex for protecting access to TCP protected applications.
        /// </summary>
        /// <remarks>
        /// This member variable is used to synchronize access to the TCP protected applications data structure,
        /// ensuring thread-safe operations when adding, removing, or querying protected TCP sessions.
        /// </remarks>
        std::mutex tcp_protected_apps_lock_;

        /// <summary>
        /// Mutex for protecting access to UDP protected applications.
        /// </summary>
        /// <remarks>
        /// This member variable is used to synchronize access to the UDP protected applications data structure,
        /// ensuring thread-safe operations when adding, removing, or querying protected UDP sessions.
        /// </remarks>
        std::mutex udp_protected_apps_lock_;

        /// <summary>
        /// Default process used when process lookup in not possible via IP Helper API
        /// Usually IP Helper API fails for system processes
        /// </summary>
        std::shared_ptr<network_process> default_process_;

        /// <summary>
        /// Memory buffer to query TCP connection tables
        /// </summary>
        std::unique_ptr<char[]> table_buffer_tcp_{};

        /// <summary>
        /// Memory buffer to query UDP connection tables
        /// </summary>
        std::unique_ptr<char[]> table_buffer_udp_{};

        /// <summary>
        /// Mutex for protecting access to the TCP table buffer.
        /// </summary>
        std::mutex table_buffer_tcp_lock_;

        /// <summary>
        /// Mutex for protecting access to the UDP table buffer.
        /// </summary>
        std::mutex table_buffer_udp_lock_;

        /// <summary>
        /// Current size of the memory buffer to query TCP connection tables
        /// </summary>
        DWORD table_buffer_size_tcp_{ 0 };

        /// <summary>
        /// Current size of the memory buffer to query UDP connection tables
        /// </summary>
        DWORD table_buffer_size_udp_{ 0 };

    public:

        /// <summary>
        /// Default destructor
        /// </summary>
        ~process_lookup() = default;

        /// <summary>
        /// Searches process by provided TCP session information.
        /// </summary>
        /// <typeparam name="SetToDefault">When true and fail to look up the process, sets to default.</typeparam>
        /// <typeparam name="UpdateProtected">When true update the protected process timestamp.</typeparam>
        /// <param name="session">TCP session to lookup.</param>
        /// <returns>Shared pointer to network_process instance.</returns>
        template <bool SetToDefault, bool UpdateProtected = true>
        std::shared_ptr<network_process> lookup_process_for_tcp(const net::ip_session<T>& session)
        {
            {
                std::shared_lock lock(tcp_to_app_mutex_);
                if (auto it = tcp_to_app_.find(session); it != tcp_to_app_.end())
                {
                    return it->second;
                }
            }

            auto now = std::chrono::steady_clock::now();

            std::unique_lock lock(tcp_protected_apps_lock_);
            if (auto it = tcp_protected_apps_.find(session); it != tcp_protected_apps_.end())
            {
                if (now - it->second.load() > protected_apps_cache_timeout)
                {
                    tcp_protected_apps_.erase(it);
                }
                else
                {
                    if constexpr (UpdateProtected)
                    {
                        it->second = now;
                    }
                    return default_process_;
                }
            }

            if constexpr (SetToDefault)
            {
                tcp_protected_apps_[session] = now;
                return default_process_;
            }
            else
            {
                return nullptr;
            }
        }

        /// <summary>
        /// Searches process by provided UDP endpoint information.
        /// </summary>
        /// <typeparam name="SetToDefault">When true and fail to look up the process, sets to default.</typeparam>
        /// <typeparam name="UpdateProtected">When true update the protected process timestamp.</typeparam>
        /// <param name="endpoint">UDP endpoint to lookup.</param>
        /// <returns>Shared pointer to network_process instance.</returns>
        template <bool SetToDefault, bool UpdateProtected = true>
        std::shared_ptr<network_process> lookup_process_for_udp(const net::ip_endpoint<T>& endpoint)
        {
            // UDP endpoints may have 0.0.0.0:137 form
            auto zero_ip_endpoint = endpoint;
            zero_ip_endpoint.ip = T{};

            {
                std::shared_lock lock(udp_to_app_mutex_);
                if (auto it = udp_to_app_.find(endpoint); it != udp_to_app_.end())
                {
                    return it->second;
                }

                if (auto it = udp_to_app_.find(zero_ip_endpoint); it != udp_to_app_.end())
                {
                    return it->second;
                }
            }

            auto now = std::chrono::steady_clock::now();

            std::unique_lock lock(udp_protected_apps_lock_);
            if (auto it = udp_protected_apps_.find(endpoint); it != udp_protected_apps_.end())
            {
                if (now - it->second.load() > protected_apps_cache_timeout)
                {
                    udp_protected_apps_.erase(it);
                }
                else
                {
                    if constexpr (UpdateProtected)
                    {
                        it->second = now;
                    }
                    return default_process_;
                }
            }

            if constexpr (SetToDefault)
            {
                udp_to_app_[endpoint] = default_process_;
                return default_process_;
            }
            else
            {
                return nullptr;
            }
        }

        /// <summary>
        /// Updates TCP/UDP hash tables
        /// </summary>
        /// <param name="tcp">set to true to update TCP table</param>
        /// <param name="udp">set to true to update UDP table</param>
        /// <returns>true if successful, false if error occurred</returns>
        bool actualize(const bool tcp, const bool udp)
        {
            auto ret_tcp = true, ret_udp = true;

            if (tcp)
            {
                ret_tcp = initialize_tcp_table();
            }

            if (udp)
            {
                ret_udp = initialize_udp_table();
            }

            auto now = std::chrono::steady_clock::now();

            // Erase timeout elements from udp_protected_apps_
            {
                std::unique_lock lock(udp_protected_apps_lock_);
                for (auto it = udp_protected_apps_.begin(); it != udp_protected_apps_.end(); )
                {
                    if (now - it->second.load() > protected_apps_cache_timeout)
                    {
                        it = udp_protected_apps_.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
            }

            // Erase timeout elements from tcp_protected_apps_
            {
                std::unique_lock lock(tcp_protected_apps_lock_);
                for (auto it = tcp_protected_apps_.begin(); it != tcp_protected_apps_.end(); )
                {
                    if (now - it->second.load() > protected_apps_cache_timeout)
                    {
                        it = tcp_protected_apps_.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
            }

            return (ret_udp && ret_tcp);
        }

        /// <summary>
        /// Returns current TCP hash table string representation
        /// </summary>
        /// <returns>string with TCP hash table entries dumped</returns>
        std::string dump_tcp_table()
        {
            std::ostringstream oss;

            std::for_each(tcp_to_app_.begin(), tcp_to_app_.end(), [&oss](auto&& entry)
                {
                    oss << std::string(entry.first.local.ip) << " : " << entry.first.local.port <<
                        " <---> " << std::string(entry.first.remote.ip) << " : " << entry.first.remote.port <<
                        " : " << entry.second->id << " : " << tools::strings::to_string(entry.second->name) << std::endl;
                });

            return oss.str();
        }

        /**
        * Retrieve TCP sessions that belong to a process matching a regular expression.
        *
        * @param process Regular expression pattern to match process name.
        *
        * @return A vector of ip_session objects of type T.
        */
        std::vector<net::ip_session<T>> get_tcp_sessions_for_process(const std::wregex& process)
        {
            std::vector<net::ip_session<T>> sessions;
            std::for_each(tcp_to_app_.begin(), tcp_to_app_.end(), [&sessions, &process](auto&& entry)
                {
                    if (std::regex_match(std::wstring(entry.second->name.begin(), entry.second->name.end()), process))
                        sessions.push_back(entry.first);
                });
            return sessions;
        }

        /// <summary>
        /// Returns current UDP hash table string representation
        /// </summary>
        /// <returns>string with UDP hash table entries dumped</returns>
        std::string dump_udp_table()
        {
            std::ostringstream oss;

            std::for_each(udp_to_app_.begin(), udp_to_app_.end(), [&oss](auto&& entry)
                {
                    oss << std::string(entry.first.ip) << " : " << entry.first.port <<
                        " : " << entry.second->id << " : " << tools::strings::to_string(entry.second->name) << std::endl;
                });

            return oss.str();
        }

    private:

        /// @brief Processes a TCP table entry for IPv4 and retrieves the owner module information.
        /// @details This function takes a PMIB_TCPROW_OWNER_MODULE entry for IPv4, retrieves owner module information, 
        ///          and constructs a shared_ptr<network_process> object with the obtained information.
        /// @param table_entry The PMIB_TCPROW_OWNER_MODULE entry to be processed.
        /// @return A shared_ptr<network_process> object with the owner module information, or nullptr if the operation fails.
        static std::shared_ptr<network_process> process_tcp_entry_v4(const PMIB_TCPROW_OWNER_MODULE table_entry)
        {
            DWORD size = 0;
            std::shared_ptr<network_process> process_ptr(nullptr);

            if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromTcpEntry(
                table_entry, TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
            {
                const auto module_ptr = std::make_unique<char[]>(size);

                if (auto* info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());
                    GetOwnerModuleFromTcpEntry(table_entry, TCPIP_OWNER_MODULE_INFO_BASIC, info, &size) == NO_ERROR &&
                    info->pModuleName && info->pModulePath)
                {
                    process_ptr = std::make_shared<network_process>(
                        table_entry->dwOwningPid,
                        network_process::is_valid_wide_string(info->pModuleName)?std::wstring(info->pModuleName):std::wstring(),
                        network_process::is_valid_wide_string(info->pModulePath)?std::wstring(info->pModulePath): std::wstring());
                }
            }

            return process_ptr;
        }

        /// @brief Processes a TCP table entry for IPv6 and retrieves the owner module information.
        /// @details This function takes a PMIB_TCP6ROW_OWNER_MODULE entry for IPv6, retrieves owner module information,
        ///          and constructs a shared_ptr<network_process> object with the obtained information.
        /// @param table_entry The PMIB_TCP6ROW_OWNER_MODULE entry to be processed.
        /// @return A shared_ptr<network_process> object with the owner module information, or nullptr if the operation fails.
        static std::shared_ptr<network_process> process_tcp_entry_v6(const PMIB_TCP6ROW_OWNER_MODULE table_entry)
        {
            DWORD size = 0;
            std::shared_ptr<network_process> process_ptr(nullptr);

            if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromTcp6Entry(
                table_entry, TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
            {
                const auto module_ptr = std::make_unique<char[]>(size);

                if (auto* info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());
                    GetOwnerModuleFromTcp6Entry(table_entry, TCPIP_OWNER_MODULE_INFO_BASIC, info, &size) == NO_ERROR &&
                    info->pModuleName && info->pModulePath)
                {
                    process_ptr = std::make_shared<network_process>(
                        table_entry->dwOwningPid,
                        network_process::is_valid_wide_string(info->pModuleName) ? std::wstring(info->pModuleName) : std::wstring(),
                        network_process::is_valid_wide_string(info->pModulePath) ? std::wstring(info->pModulePath) : std::wstring());
                }
            }

            return process_ptr;
        }

        /// @brief Initializes or updates the TCP hashtable by retrieving the extended TCP table for the selected IP address type.
        /// @details This function retrieves the extended TCP table and processes each entry to obtain owner module information. 
        ///          It then updates the tcp_to_app_ map with the network_process information for each IP session.
        /// @returns true if successful, false otherwise.
        bool initialize_tcp_table()
        {
            auto table_size = table_buffer_size_tcp_;

            try
            {
                tcp_hashtable_t tcp_to_app;
                {
                    std::unique_lock lock(table_buffer_tcp_lock_);

                    while (true)
                    {
                        if (const uint32_t result = ::GetExtendedTcpTable(table_buffer_tcp_.get(), &table_size, FALSE,
                            T::af_type,
                            TCP_TABLE_OWNER_MODULE_CONNECTIONS, 0); result ==
                            ERROR_INSUFFICIENT_BUFFER)
                        {
                            table_size *= 2;
                            table_buffer_tcp_ = std::make_unique<char[]>(table_size);
                            table_buffer_size_tcp_ = table_size;
                        }
                        else if (result == NO_ERROR)
                        {
                            break;
                        }
                        else
                        {
                            return false;
                        }
                    }
                    if constexpr (std::is_same_v<T, net::ip_address_v4>)
                    {
                        auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_MODULE>(table_buffer_tcp_.get());

                        for (size_t i = 0; i < table->dwNumEntries; i++)
                        {
                            if (auto process_ptr = process_tcp_entry_v4(&table->table[i]))
                            {
                                tcp_to_app[net::ip_session<T>(T{ table->table[i].dwLocalAddr },
                                    T{ table->table[i].dwRemoteAddr },
                                    ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort)),
                                    ntohs(static_cast<uint16_t>(table->table[i].dwRemotePort)))]
                                    = std::move(process_ptr);
                            }
                        }
                    }
                    else
                    {
                        auto* table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_MODULE>(table_buffer_tcp_.get());

                        for (size_t i = 0; i < table->dwNumEntries; i++)
                        {
                            if (auto process_ptr = process_tcp_entry_v6(&table->table[i]))
                            {
                                tcp_to_app[net::ip_session<T>(T{ table->table[i].ucLocalAddr },
                                    T{ table->table[i].ucRemoteAddr },
                                    ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort)),
                                    ntohs(static_cast<uint16_t>(table->table[i].dwRemotePort)),
                                    table->table[i].dwLocalScopeId,
                                    table->table[i].dwRemoteScopeId)] = std::move(process_ptr);
                            }
                        }
                    }
                }

                std::unique_lock lock(tcp_to_app_mutex_);
                tcp_to_app_ = std::move(tcp_to_app);
            }
            catch (...)
            {
                return false;
            }

            return true;
        }

        /// @brief Processes an IPv4 UDP table entry
        /// @param entry An IPv4 UDP table entry
        /// @return A shared_ptr to a network_process object if successful, nullptr otherwise
        static std::shared_ptr<network_process> process_udp_entry_v4(const PMIB_UDPROW_OWNER_MODULE entry)
        {
            DWORD size = 0;
            std::shared_ptr<network_process> process_ptr(nullptr);

            if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromUdpEntry(
                entry, TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
            {
                const auto module_ptr = std::make_unique<char[]>(size);

                if (auto* info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());
                    GetOwnerModuleFromUdpEntry(entry, TCPIP_OWNER_MODULE_INFO_BASIC, info, &size) == NO_ERROR &&
                    info->pModuleName && info->pModulePath)
                {
                    process_ptr = std::make_shared<network_process>(
                        entry->dwOwningPid,
                        network_process::is_valid_wide_string(info->pModuleName) ? std::wstring(info->pModuleName) : std::wstring(),
                        network_process::is_valid_wide_string(info->pModulePath) ? std::wstring(info->pModulePath) : std::wstring());
                }
            }

            return process_ptr;
        }

        /// @brief Processes an IPv6 UDP table entry
        /// @param entry An IPv6 UDP table entry
        /// @return A shared_ptr to a network_process object if successful, nullptr otherwise
        static std::shared_ptr<network_process> process_udp_entry_v6(const PMIB_UDP6ROW_OWNER_MODULE entry)
        {
            DWORD size = 0;
            std::shared_ptr<network_process> process_ptr(nullptr);

            if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromUdp6Entry(
                entry, TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
            {
                const auto module_ptr = std::make_unique<char[]>(size);

                if (auto* info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());
                    GetOwnerModuleFromUdp6Entry(entry, TCPIP_OWNER_MODULE_INFO_BASIC, info, &size) == NO_ERROR &&
                    info->pModuleName && info->pModulePath)
                {
                    process_ptr = std::make_shared<network_process>(
                        entry->dwOwningPid,
                        network_process::is_valid_wide_string(info->pModuleName) ? std::wstring(info->pModuleName) : std::wstring(),
                        network_process::is_valid_wide_string(info->pModulePath) ? std::wstring(info->pModulePath) : std::wstring());
                }
            }

            return process_ptr;
        }

        /// @brief Initializes/updates UDP hashtable
        /// @details This function initializes or updates the UDP hashtable with network_process objects,
        ///          mapping IP endpoints to their owner processes.
        /// @return true if successful, false otherwise
        bool initialize_udp_table()
        {
            auto table_size = table_buffer_size_udp_;

            try
            {
                udp_hashtable_t udp_to_app;
                {
                    std::unique_lock lock(table_buffer_udp_lock_);
                    do
                    {
                        const uint32_t result = ::GetExtendedUdpTable(table_buffer_udp_.get(), &table_size, FALSE,
                            T::af_type,
                            UDP_TABLE_OWNER_MODULE, 0);

                        if (result == ERROR_INSUFFICIENT_BUFFER)
                        {
                            table_size *= 2;
                            table_buffer_udp_ = std::make_unique<char[]>(table_size);
                            table_buffer_size_udp_ = table_size;
                            continue;
                        }

                        if (result == NO_ERROR)
                        {
                            break;
                        }

                        return false;
                    } while (true);

                    if constexpr (std::is_same_v<T, net::ip_address_v4>)
                    {
                        auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_MODULE>(table_buffer_udp_.get());

                        for (size_t i = 0; i < table->dwNumEntries; i++)
                        {
                            if (auto process_ptr = process_udp_entry_v4(&table->table[i]))
                            {
                                udp_to_app[net::ip_endpoint<T>(
                                    T{ table->table[i].dwLocalAddr },
                                    ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort)))] = std::move(process_ptr);
                            }
                        }
                    }
                    else
                    {
                        auto* table = reinterpret_cast<PMIB_UDP6TABLE_OWNER_MODULE>(table_buffer_udp_.get());

                        for (size_t i = 0; i < table->dwNumEntries; i++)
                        {
                            if (auto process_ptr = process_udp_entry_v6(&table->table[i]))
                            {
                                udp_to_app[net::ip_endpoint<T>(
                                    T{ table->table[i].ucLocalAddr },
                                    ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort)), 0)] = std::move(process_ptr);
                            }
                        }
                    }
                }

                std::unique_lock lock(udp_to_app_mutex_);
                udp_to_app_ = std::move(udp_to_app);
            }
            catch (...)
            {
                return false;
            }

            return true;
        }
    };
}
