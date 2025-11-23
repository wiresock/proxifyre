#pragma once

#include "owner_module_resolver.h"

namespace iphelper
{
    /**
     * @brief Represents a network process with associated module information.
     *
     * This structure encapsulates information about a process that owns network connections,
     * including process ID, name, executable path, and device path. All string fields are
     * automatically converted to uppercase for consistent matching.
     */
    struct network_process
    {
        /**
         * @brief Default constructor.
         */
        network_process() = default;

        /**
         * @brief Constructs a network_process with the specified information.
         *
         * @param id Process ID
         * @param name Process name (will be converted to uppercase)
         * @param path Full path to the process executable (will be converted to uppercase)
         *
         * @note All string parameters are automatically converted to uppercase and the
         *       device path is computed from the provided path.
         */
        network_process(const unsigned long id, std::wstring name, std::wstring path)
            : id(id),
            name(std::move(name)),
            path_name(std::move(path)),
            device_path_name(convert_to_device_path(path_name))
        {
            this->name = to_upper(this->name);
            this->path_name = to_upper(this->path_name);
            this->device_path_name = to_upper(this->device_path_name);
        }

        /**
         * @brief Validates that a wide string pointer is non-null and non-empty.
         *
         * @param ptr_str Pointer to wide string to validate
         * @return true if the string is valid (non-null and non-empty), false otherwise
         */
        static bool is_valid_wide_string(const wchar_t* ptr_str) {
            return ptr_str != nullptr && ptr_str[0] != L'\0';
        }

        /**
         * @brief Converts a DOS path to its corresponding device path.
         *
         * Converts paths like "C:\Windows\System32\notepad.exe" to device paths like
         * "\Device\HarddiskVolume3\Windows\System32\notepad.exe". This is useful for
         * kernel-level path matching and avoiding drive letter ambiguities.
         *
         * @param path DOS path to convert (must start with drive letter, e.g., "C:")
         * @return Device path string, or empty string on failure
         *
         * @note Uses QueryDosDeviceW internally with automatic buffer growth
         * @note Handles MULTI_SZ return values by taking only the first device name
         * @note Has a hard limit of 64KB buffer size to prevent excessive memory usage
         */
        static std::wstring convert_to_device_path(const std::wstring& path)
        {
            if (!is_valid_wide_string(path.c_str()) || path.size() < 2 || path[1] != L':')
                return L"";

            const wchar_t drive_letter[3] = { path[0], path[1], L'\0' };

            // QueryDosDeviceW can require > MAX_PATH and returns a MULTI_SZ list; we use only the first.
            DWORD cap = 256;
            std::wstring buf;
            for (;;) {
                buf.resize(cap);
                const DWORD got = QueryDosDeviceW(drive_letter, buf.data(), cap);
                if (got != 0) {
                    // Trim to first NUL (MULTI_SZ may have more)
                    buf.resize(wcslen(buf.c_str()));
                    break;
                }
                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                    return L"";
                }
                cap *= 2;
                if (cap > 1u << 16) // 64K hard stop
                    return L"";
            }

            std::wstring device_path = buf;
            device_path += path.substr(2);
            return device_path;
        }

        /**
         * @brief Converts a string to uppercase.
         *
         * @param str Input string to convert
         * @return Uppercase version of the input string
         *
         * @note Uses std::ranges::transform with ::towupper for Unicode-aware conversion
         */
        static std::wstring to_upper(const std::wstring& str) {
            std::wstring upper_case;
            std::ranges::transform(str, std::back_inserter(upper_case), ::towupper);
            return upper_case;
        }

        unsigned long id{};                 ///< Process ID
        std::wstring name;                  ///< Process name (uppercase)
        std::wstring path_name;             ///< Full path to executable (uppercase)
        std::wstring device_path_name;      ///< Device path version of path_name (uppercase)
        std::optional<uint16_t> tcp_proxy_port = std::nullopt; // Optional TCP proxy port if the process is associated with a proxy
        std::optional<uint16_t> udp_proxy_port = std::nullopt; // Optional UDP proxy port if the process is associated with a proxy
        bool excluded = false;          ///< Whether the process is excluded from proxying
        bool bypass_tcp = false;        ///< Whether TCP connections should bypass proxying (no proxy configured)
        bool bypass_udp = false;        ///< Whether UDP connections should bypass proxying (no proxy configured)
    };

    /**
     * @brief Maps TCP/UDP network connections to their owning processes using IP Helper API.
     *
     * This class provides efficient lookup of process information for network connections
     * by maintaining hash tables of TCP and UDP sessions mapped to their owning processes.
     * It includes a protected apps cache for processes that couldn't be resolved initially
     * (typically system processes) to avoid repeated expensive lookups.
     *
     * Key features:
     * - Thread-safe operations with reader-writer locks
     * - Protected apps cache with automatic expiration
     * - Support for both IPv4 and IPv6 connections
     * - Integration with owner_module_resolver for robust process resolution
     * - Comprehensive logging and debugging support
     * - Fallback mechanisms for service tag resolution
     *
     * @tparam T IP address type (net::ip_address_v4 or net::ip_address_v6)
     *
     * @note Designed as a non-copyable, non-movable class to ensure singleton-like behavior
     */
    template <typename T>
    class process_lookup final : public netlib::log::logger<process_lookup<T>>
    {
        using log_level = netlib::log::log_level;

        /// Timeout for protected apps cache entries (2 seconds)
        static constexpr std::chrono::seconds protected_apps_cache_timeout{ 2 };

        /// Initial buffer size for TCP/UDP table queries (128KB should handle most systems)
        static constexpr DWORD initial_buffer_size{ 131072 };

        /// Hash table type for TCP sessions
        using tcp_hashtable_t = std::unordered_map<net::ip_session<T>, std::shared_ptr<network_process>>;
        /// Hash table type for UDP endpoints
        using udp_hashtable_t = std::unordered_map<net::ip_endpoint<T>, std::shared_ptr<network_process>>;

        /// Protected TCP sessions cache (sessions that couldn't be resolved)
        using tcp_protected_t = std::unordered_map<net::ip_session<T>, std::chrono::time_point<std::chrono::steady_clock>>;
        /// Protected UDP sessions cache (endpoints that couldn't be resolved)
        using udp_protected_t = std::unordered_map<net::ip_endpoint<T>, std::chrono::time_point<std::chrono::steady_clock>>;

    public:
        /**
         * @brief Constructs a process_lookup instance with specified logging configuration.
         *
         * Initializes the internal hash tables by querying the current TCP and UDP
         * connection tables from the operating system.
         *
         * @param log_level Minimum log level for output
         * @param log_stream Optional output stream for log messages
         */
        explicit process_lookup(const log_level log_level = log_level::error,
            std::shared_ptr<std::ostream> log_stream = nullptr)
            : netlib::log::logger<process_lookup>(log_level, std::move(log_stream))
        {
            default_process_ = std::make_shared<network_process>(0, L"SYSTEM", L"SYSTEM");
            initialize_tcp_table();
            initialize_udp_table();
        }

        // Disable copy and move operations to ensure singleton-like behavior
        process_lookup(const process_lookup&) = delete;
        process_lookup(process_lookup&&) noexcept = delete;
        process_lookup& operator=(const process_lookup&) = delete;
        process_lookup& operator=(process_lookup&&) noexcept = delete;

        /**
         * @brief Default destructor.
         */
        ~process_lookup() = default;

    private:
        // Core data structures
        tcp_hashtable_t  tcp_to_app_;           ///< TCP sessions to process mapping
        udp_hashtable_t  udp_to_app_;           ///< UDP endpoints to process mapping
        std::shared_mutex tcp_to_app_mutex_;    ///< Reader-writer lock for TCP hash table
        std::shared_mutex udp_to_app_mutex_;    ///< Reader-writer lock for UDP hash table

        // Protected apps cache (for processes that couldn't be resolved)
        tcp_protected_t tcp_protected_apps_;        ///< TCP sessions with unresolvable processes
        udp_protected_t udp_protected_apps_;        ///< UDP endpoints with unresolvable processes
        std::mutex      tcp_protected_apps_lock_;   ///< Mutex for TCP protected apps
        std::mutex      udp_protected_apps_lock_;   ///< Mutex for UDP protected apps

        /// Default process object for unresolvable processes
        std::shared_ptr<network_process> default_process_;

        // Buffer management for IP Helper API calls
        std::unique_ptr<char[]> table_buffer_tcp_{ std::make_unique<char[]>(initial_buffer_size) };  ///< Buffer for TCP table queries (pre-allocated to 128KB)
        std::unique_ptr<char[]> table_buffer_udp_{ std::make_unique<char[]>(initial_buffer_size) };  ///< Buffer for UDP table queries (pre-allocated to 128KB)
        std::mutex table_buffer_tcp_lock_;                                                           ///< Mutex for TCP buffer access
        std::mutex table_buffer_udp_lock_;                                                           ///< Mutex for UDP buffer access
        DWORD table_buffer_size_tcp_{ initial_buffer_size };                                         ///< Current TCP buffer size
        DWORD table_buffer_size_udp_{ initial_buffer_size };                                         ///< Current UDP buffer size

    public:
        /**
         * @brief Looks up the process associated with a TCP session.
         *
         * Performs a fast hash table lookup to find the process that owns a specific
         * TCP connection. If not found, checks the protected apps cache to avoid
         * repeated expensive lookups for system processes.
         *
         * @tparam SetToDefault If true, adds unresolvable sessions to protected cache
         * @tparam UpdateProtected If true, updates timestamp for protected sessions
         *
         * @param session TCP session to look up
         * @return Shared pointer to network_process if found, nullptr if SetToDefault=false and not found
         *
         * @note Thread-safe operation using reader-writer locks
         * @note Protected sessions automatically expire after 2 seconds
         */
        template <bool SetToDefault, bool UpdateProtected = true>
        std::shared_ptr<network_process> lookup_process_for_tcp(const net::ip_session<T>& session)
        {
            {
                std::shared_lock lock(tcp_to_app_mutex_);
                if (auto it = tcp_to_app_.find(session); it != tcp_to_app_.end())
                    return it->second;
            }

            const auto now = std::chrono::steady_clock::now();

            std::unique_lock lock(tcp_protected_apps_lock_);
            if (auto it = tcp_protected_apps_.find(session); it != tcp_protected_apps_.end()) {
                if (now - it->second > protected_apps_cache_timeout) {
                    tcp_protected_apps_.erase(it);
                }
                else {
                    if constexpr (UpdateProtected) {
                        it->second = now;
                    }
                    return default_process_;
                }
            }

            if constexpr (SetToDefault) {
                tcp_protected_apps_.try_emplace(session, now);
                return default_process_;
            }
            else {
                return nullptr;
            }
        }

        /**
         * @brief Looks up the process associated with a UDP endpoint.
         *
         * Performs a fast hash table lookup to find the process that owns a specific
         * UDP endpoint. Also checks for wildcard bindings (0.0.0.0:port) if the
         * specific endpoint is not found.
         *
         * @tparam SetToDefault If true, adds unresolvable endpoints to protected cache
         * @tparam UpdateProtected If true, updates timestamp for protected endpoints
         *
         * @param endpoint UDP endpoint to look up
         * @return Shared pointer to network_process if found, nullptr if SetToDefault=false and not found
         *
         * @note Thread-safe operation using reader-writer locks
         * @note Handles wildcard UDP bindings (0.0.0.0:port format)
         * @note Protected endpoints automatically expire after 2 seconds
         */
        template <bool SetToDefault, bool UpdateProtected = true>
        std::shared_ptr<network_process> lookup_process_for_udp(const net::ip_endpoint<T>& endpoint)
        {
            // UDP endpoints may have 0.0.0.0:137 form
            auto zero_ip_endpoint = endpoint;
            zero_ip_endpoint.ip = T{};

            {
                std::shared_lock lock(udp_to_app_mutex_);
                if (auto it = udp_to_app_.find(endpoint); it != udp_to_app_.end())
                    return it->second;
                if (auto it = udp_to_app_.find(zero_ip_endpoint); it != udp_to_app_.end())
                    return it->second;
            }

            const auto now = std::chrono::steady_clock::now();

            std::unique_lock lock(udp_protected_apps_lock_);
            if (auto it = udp_protected_apps_.find(endpoint); it != udp_protected_apps_.end()) {
                if (now - it->second > protected_apps_cache_timeout) {
                    udp_protected_apps_.erase(it);
                }
                else {
                    if constexpr (UpdateProtected) {
                        it->second = now;
                    }
                    return default_process_;
                }
            }

            if constexpr (SetToDefault) {
                udp_protected_apps_.try_emplace(endpoint, now);
                return default_process_;
            }
            else {
                return nullptr;
            }
        }

        /**
         * @brief Updates the internal hash tables with current system state.
         *
         * Refreshes the TCP and/or UDP connection tables by querying the operating
         * system's current network connection state. Also performs cleanup of
         * expired protected app cache entries.
         *
         * @param tcp Whether to update TCP connection table
         * @param udp Whether to update UDP connection table
         * @return true if all requested updates succeeded, false if any failed
         *
         * @note This is an expensive operation that should not be called frequently
         * @note Automatically cleans up expired protected app cache entries
         */
        bool actualize(const bool tcp, const bool udp)
        {
            auto ret_tcp = true, ret_udp = true;

            if (tcp) ret_tcp = initialize_tcp_table();
            if (udp) ret_udp = initialize_udp_table();

            const auto now = std::chrono::steady_clock::now();

            {
                std::unique_lock lock(udp_protected_apps_lock_);
                for (auto it = udp_protected_apps_.begin(); it != udp_protected_apps_.end(); ) {
                    if (now - it->second > protected_apps_cache_timeout)
                        it = udp_protected_apps_.erase(it);
                    else
                        ++it;
                }
            }
            {
                std::unique_lock lock(tcp_protected_apps_lock_);
                for (auto it = tcp_protected_apps_.begin(); it != tcp_protected_apps_.end(); ) {
                    if (now - it->second > protected_apps_cache_timeout)
                        it = tcp_protected_apps_.erase(it);
                    else
                        ++it;
                }
            }

            return (ret_udp && ret_tcp);
        }

        /**
         * @brief Generates a string dump of the TCP connection table.
         *
         * Creates a human-readable representation of all TCP connections and their
         * associated processes for debugging and monitoring purposes.
         *
         * @return String containing formatted TCP connection information
         *
         * @note Thread-safe operation with read lock
         * @note Format: "local_ip:port <---> remote_ip:port : pid : process_name"
         */
        std::string dump_tcp_table()
        {
            std::ostringstream oss;
            std::shared_lock lock(tcp_to_app_mutex_);
            for (const auto& entry : tcp_to_app_) {
                oss << std::string(entry.first.local.ip) << " : " << entry.first.local.port
                    << " <---> " << std::string(entry.first.remote.ip) << " : " << entry.first.remote.port
                    << " : " << entry.second->id << " : "
                    << tools::strings::to_string(entry.second->name) << '\n';
            }
            return oss.str();
        }

        /**
         * @brief Retrieves TCP sessions belonging to processes matching a regex pattern.
         *
         * @param process Regular expression to match against process names
         * @return Vector of TCP sessions owned by matching processes
         *
         * @note Thread-safe operation with read lock
         * @note Performs case-sensitive regex matching against uppercase process names
         */
        std::vector<net::ip_session<T>> get_tcp_sessions_for_process(const std::wregex& process)
        {
            std::vector<net::ip_session<T>> sessions;
            std::shared_lock lock(tcp_to_app_mutex_);
            for (const auto& entry : tcp_to_app_) {
                if (std::regex_match(entry.second->name, process))
                    sessions.push_back(entry.first);
            }
            return sessions;
        }

        /**
         * @brief Retrieves all TCP sessions.
         *
         * This function returns a vector containing all TCP sessions currently stored in the TCP hashtable.
         * It reserves memory for the vector to avoid multiple allocations, improving performance.
         *
         * @return A vector of net::ip_session<T> objects representing all TCP sessions.
         */
        std::vector<net::ip_session<T>> get_all_tcp_sessions() const
        {
            std::vector<net::ip_session<T>> sessions;
            sessions.reserve(tcp_to_app_.size()); // Reserve memory to avoid multiple allocations

            for (const auto& entry : tcp_to_app_)
            {
                sessions.push_back(entry.first);
            }

            return sessions;
        }

        /**
         * @brief Generates a string dump of the UDP endpoint table.
         *
         * Creates a human-readable representation of all UDP endpoints and their
         * associated processes for debugging and monitoring purposes.
         *
         * @return String containing formatted UDP endpoint information
         *
         * @note Thread-safe operation with read lock
         * @note Format: "ip:port : pid : process_name"
         */
        std::string dump_udp_table()
        {
            std::ostringstream oss;
            std::shared_lock lock(udp_to_app_mutex_);
            for (const auto& entry : udp_to_app_) {
                oss << std::string(entry.first.ip) << " : " << entry.first.port
                    << " : " << entry.second->id << " : "
                    << tools::strings::to_string(entry.second->name) << '\n';
            }
            return oss.str();
        }

    private:
        /**
         * @brief Converts owner_module_resolver error codes to string representation.
         *
         * @param ec Error code to convert
         * @return String representation of the error code
         * @note Used for logging and debugging purposes
         */
        static constexpr const char* error_code_to_string(owner_module_resolver::error_code ec) noexcept {
            using ec_t = owner_module_resolver::error_code;
            switch (ec) {
            case ec_t::success:              return "success";
            case ec_t::invalid_pid:          return "invalid_pid";
            case ec_t::access_denied:        return "access_denied";
            case ec_t::module_not_found:     return "module_not_found";
            case ec_t::service_not_found:    return "service_not_found";
            case ec_t::insufficient_buffer:  return "insufficient_buffer";
            case ec_t::api_failed:           return "api_failed";
            }
            return "unknown";
        }

        /**
         * @brief Checks if a PID represents a system process that should be skipped.
         *
         * @param pid Process ID to check
         * @return true if the PID should be skipped (0 = System Idle Process, 4 = System Process)
         */
        static constexpr bool is_system_process(const DWORD pid) noexcept {
            return pid == 0 || pid == 4;
        }

        /**
         * @brief Processes a TCPv4 table entry and resolves its owner process.
         *
         * Uses the owner_module_resolver to determine the process and service information
         * for a TCP connection entry from the system's connection table.
         *
         * @param row Pointer to MIB_TCPROW_OWNER_MODULE structure
         * @return Shared pointer to network_process if successful, nullptr otherwise
         *
         * @note Implements fallback from service tag to process image resolution
         * @note Logs resolution attempts and results for debugging
         */
        std::shared_ptr<network_process>
            process_tcp_entry_v4(const PMIB_TCPROW_OWNER_MODULE row) noexcept
        {
            const DWORD pid = row->dwOwningPid;
            if (is_system_process(pid)) {
                NETLIB_DEBUG(
                    "TCPv4 entry with system process PID = {} ({}) skipping resolution",
                    pid,
                    pid == 0 ? "Idle" : "System");
                return nullptr;
            }
            const DWORD tag = owner_module_resolver::service_tag_from_owning_module_info(row->OwningModuleInfo);

            const auto ext = owner_module_resolver::resolve_from_pid_and_tag_extended(pid, tag);
            if (ext.error == owner_module_resolver::error_code::success) {
                NETLIB_DEBUG(
                    "Resolved TCPv4 owner: pid={} tag={} name=\"{}\" path=\"{}\"",
                    pid,
                    tag,
                    tools::strings::to_string(ext.data.base_name),
                    tools::strings::to_string(ext.data.full_path));

                return std::make_shared<network_process>(
                    pid,
                    std::wstring{ ext.data.base_name },
                    std::wstring{ ext.data.full_path }
                );
            }

            if (tag != 0 && ext.error == owner_module_resolver::error_code::service_not_found) {
                if (owner_module_resolver::result img{}; owner_module_resolver::resolve_from_pid_and_tag(pid, 0, img)) {
                    NETLIB_DEBUG(
                        "Service tag not found; fell back to process image (TCPv4): pid={} tag={} name=\"{}\" path=\"{}\"",
                        pid,
                        tag,
                        tools::strings::to_string(img.base_name),
                        tools::strings::to_string(img.full_path));

                    return std::make_shared<network_process>(
                        pid,
                        std::move(img.base_name),
                        std::move(img.full_path)
                    );
                }
            }

            NETLIB_DEBUG(
                "Failed to resolve TCPv4 owner: pid={} tag={} error={}{}",
                pid,
                tag,
                error_code_to_string(ext.error),
                ext.error_message.empty() ? "" : std::format(" msg=\"{}\"", tools::strings::to_string(ext.error_message)));

            return nullptr;
        }

        /**
         * @brief Processes a TCPv6 table entry and resolves its owner process.
         *
         * Uses the owner_module_resolver to determine the process and service information
         * for a TCP connection entry from the system's IPv6 connection table.
         *
         * @param row Pointer to MIB_TCP6ROW_OWNER_MODULE structure
         * @return Shared pointer to network_process if successful, nullptr otherwise
         *
         * @note Implements fallback from service tag to process image resolution
         * @note Logs resolution attempts and results for debugging
         */
        std::shared_ptr<network_process>
            process_tcp_entry_v6(const PMIB_TCP6ROW_OWNER_MODULE row) noexcept
        {
            const DWORD pid = row->dwOwningPid;
            if (is_system_process(pid)) {
                NETLIB_DEBUG(
                    "TCPv6 entry with system process PID = {} ({}) skipping resolution",
                    pid,
                    pid == 0 ? "Idle" : "System");
                return nullptr;
            }
            const DWORD tag = owner_module_resolver::service_tag_from_owning_module_info(row->OwningModuleInfo);

            const auto ext = owner_module_resolver::resolve_from_pid_and_tag_extended(pid, tag);
            if (ext.error == owner_module_resolver::error_code::success) {
                NETLIB_DEBUG(
                    "Resolved TCPv6 owner: pid={} tag={} name=\"{}\" path=\"{}\"",
                    pid,
                    tag,
                    tools::strings::to_string(ext.data.base_name),
                    tools::strings::to_string(ext.data.full_path));

                return std::make_shared<network_process>(
                    pid,
                    std::wstring{ ext.data.base_name },
                    std::wstring{ ext.data.full_path }
                );
            }

            if (tag != 0 && ext.error == owner_module_resolver::error_code::service_not_found) {
                if (owner_module_resolver::result img{}; owner_module_resolver::resolve_from_pid_and_tag(pid, 0, img)) {
                    NETLIB_DEBUG(
                        "Service tag not found; fell back to process image (TCPv6): pid={} tag={} name=\"{}\" path=\"{}\"",
                        pid,
                        tag,
                        tools::strings::to_string(img.base_name),
                        tools::strings::to_string(img.full_path));

                    return std::make_shared<network_process>(
                        pid,
                        std::move(img.base_name),
                        std::move(img.full_path)
                    );
                }
            }

            NETLIB_DEBUG(
                "Failed to resolve TCPv6 owner: pid={} tag={} error={}{}",
                pid,
                tag,
                error_code_to_string(ext.error),
                ext.error_message.empty() ? "" : std::format(" msg=\"{}\"", tools::strings::to_string(ext.error_message)));

            return nullptr;
        }

        /**
         * @brief Processes a UDPv4 table entry and resolves its owner process.
         *
         * Uses the owner_module_resolver to determine the process and service information
         * for a UDP endpoint entry from the system's connection table.
         *
         * @param row Pointer to MIB_UDPROW_OWNER_MODULE structure
         * @return Shared pointer to network_process if successful, nullptr otherwise
         *
         * @note Implements fallback from service tag to process image resolution
         * @note Logs resolution attempts and results for debugging
         */
        std::shared_ptr<network_process>
            process_udp_entry_v4(const PMIB_UDPROW_OWNER_MODULE row) noexcept
        {
            const DWORD pid = row->dwOwningPid;
            if (is_system_process(pid)) {
                NETLIB_DEBUG(
                    "UDPv4 entry with system process PID = {} ({}) skipping resolution",
                    pid,
                    pid == 0 ? "Idle" : "System");
                return nullptr;
            }
            const DWORD tag = owner_module_resolver::service_tag_from_owning_module_info(row->OwningModuleInfo);

            const auto ext = owner_module_resolver::resolve_from_pid_and_tag_extended(pid, tag);
            if (ext.error == owner_module_resolver::error_code::success) {
                NETLIB_DEBUG(
                    "Resolved UDPv4 owner: pid={} tag={} name=\"{}\" path=\"{}\"",
                    pid,
                    tag,
                    tools::strings::to_string(ext.data.base_name),
                    tools::strings::to_string(ext.data.full_path));

                return std::make_shared<network_process>(
                    pid,
                    std::wstring{ ext.data.base_name },
                    std::wstring{ ext.data.full_path }
                );
            }

            if (tag != 0 && ext.error == owner_module_resolver::error_code::service_not_found) {
                if (owner_module_resolver::result img{}; owner_module_resolver::resolve_from_pid_and_tag(pid, 0, img)) {
                    NETLIB_DEBUG(
                        "Service tag not found; fell back to process image (UDPv4): pid={} tag={} name=\"{}\" path=\"{}\"",
                        pid,
                        tag,
                        tools::strings::to_string(img.base_name),
                        tools::strings::to_string(img.full_path));

                    return std::make_shared<network_process>(
                        pid,
                        std::move(img.base_name),
                        std::move(img.full_path)
                    );
                }
            }

            NETLIB_DEBUG(
                "Failed to resolve UDPv4 owner: pid={} tag={} error={}{}",
                pid,
                tag,
                error_code_to_string(ext.error),
                ext.error_message.empty() ? "" : std::format(" msg=\"{}\"", tools::strings::to_string(ext.error_message)));

            return nullptr;
        }

        /**
         * @brief Processes a UDPv6 table entry and resolves its owner process.
         *
         * Uses the owner_module_resolver to determine the process and service information
         * for a UDP endpoint entry from the system's IPv6 connection table.
         *
         * @param row Pointer to MIB_UDP6ROW_OWNER_MODULE structure
         * @return Shared pointer to network_process if successful, nullptr otherwise
         *
         * @note Implements fallback from service tag to process image resolution
         * @note Logs resolution attempts and results for debugging
         */
        std::shared_ptr<network_process>
            process_udp_entry_v6(const PMIB_UDP6ROW_OWNER_MODULE row) noexcept
        {
            const DWORD pid = row->dwOwningPid;
            if (is_system_process(pid)) {
                NETLIB_DEBUG(
                    "UDPv6 entry with system process PID = {} ({}) skipping resolution",
                    pid,
                    pid == 0 ? "Idle" : "System");
                return nullptr;
            }
            const DWORD tag = owner_module_resolver::service_tag_from_owning_module_info(row->OwningModuleInfo);

            const auto ext = owner_module_resolver::resolve_from_pid_and_tag_extended(pid, tag);
            if (ext.error == owner_module_resolver::error_code::success) {
                NETLIB_DEBUG(
                    "Resolved UDPv6 owner: pid={} tag={} name=\"{}\" path=\"{}\"",
                    pid,
                    tag,
                    tools::strings::to_string(ext.data.base_name),
                    tools::strings::to_string(ext.data.full_path));

                return std::make_shared<network_process>(
                    pid,
                    std::wstring{ ext.data.base_name },
                    std::wstring{ ext.data.full_path }
                );
            }

            if (tag != 0 && ext.error == owner_module_resolver::error_code::service_not_found) {
                if (owner_module_resolver::result img{}; owner_module_resolver::resolve_from_pid_and_tag(pid, 0, img)) {
                    NETLIB_DEBUG(
                        "Service tag not found; fell back to process image (UDPv6): pid={} tag={} name=\"{}\" path=\"{}\"",
                        pid,
                        tag,
                        tools::strings::to_string(img.base_name),
                        tools::strings::to_string(img.full_path));

                    return std::make_shared<network_process>(
                        pid,
                        std::move(img.base_name),
                        std::move(img.full_path)
                    );
                }
            }

            NETLIB_DEBUG(
                "Failed to resolve UDPv6 owner: pid={} tag={} error={}{}",
                pid,
                tag,
                error_code_to_string(ext.error),
                ext.error_message.empty() ? "" : std::format(" msg=\"{}\"", tools::strings::to_string(ext.error_message)));

            return nullptr;
        }

        /**
         * @brief Initializes the TCP connection hash table from system state.
         *
         * Queries the extended TCP table from the operating system and populates
         * the internal TCP hash table with current connections and their owning processes.
         * Handles both IPv4 and IPv6 connections based on template parameter.
         *
         * @return true if initialization succeeded, false otherwise
         *
         * @note Uses automatic buffer growth for large connection tables
         * @note Thread-safe buffer management with mutex protection
         * @note Replaces the entire hash table atomically
         */
        bool initialize_tcp_table()
        {
            try {
                tcp_hashtable_t tcp_to_app;
                {
                    std::unique_lock lock(table_buffer_tcp_lock_);

                    auto table_size = table_buffer_size_tcp_;

                    for (;;) {
                        const uint32_t result = ::GetExtendedTcpTable(
                            table_buffer_tcp_.get(),
                            &table_size,
                            FALSE,
                            T::af_type,
                            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
                            0);

                        if (result == NO_ERROR) break;
                        if (result != ERROR_INSUFFICIENT_BUFFER) return false;

                        // Allocate exactly the size the API asked for
                        table_buffer_tcp_ = std::make_unique<char[]>(table_size);
                        table_buffer_size_tcp_ = table_size;
                    }

                    if constexpr (std::is_same_v<T, net::ip_address_v4>) {
                        auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_MODULE>(table_buffer_tcp_.get());
                        for (size_t i = 0; i < table->dwNumEntries; i++) {
                            if (auto process_ptr = process_tcp_entry_v4(&table->table[i])) {
                                tcp_to_app[net::ip_session<T>(
                                    T{ table->table[i].dwLocalAddr },
                                    T{ table->table[i].dwRemoteAddr },
                                    ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort)),
                                    ntohs(static_cast<uint16_t>(table->table[i].dwRemotePort)))]
                                    = std::move(process_ptr);
                            }
                        }
                    }
                    else {
                        auto* table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_MODULE>(table_buffer_tcp_.get());
                        for (size_t i = 0; i < table->dwNumEntries; i++) {
                            if (auto process_ptr = process_tcp_entry_v6(&table->table[i])) {
                                tcp_to_app[net::ip_session<T>(
                                    T{ table->table[i].ucLocalAddr },
                                    T{ table->table[i].ucRemoteAddr },
                                    ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort)),
                                    ntohs(static_cast<uint16_t>(table->table[i].dwRemotePort)),
                                    table->table[i].dwLocalScopeId,
                                    table->table[i].dwRemoteScopeId)]
                                    = std::move(process_ptr);
                            }
                        }
                    }
                }

                std::unique_lock lock(tcp_to_app_mutex_);
                tcp_to_app_ = std::move(tcp_to_app);
            }
            catch (...) {
                return false;
            }

            return true;
        }

        /**
         * @brief Initializes the UDP endpoint hash table from system state.
         *
         * Queries the extended UDP table from the operating system and populates
         * the internal UDP hash table with current endpoints and their owning processes.
         * Handles both IPv4 and IPv6 endpoints based on template parameter.
         *
         * @return true if initialization succeeded, false otherwise
         *
         * @note Uses automatic buffer growth for large endpoint tables
         * @note Thread-safe buffer management with mutex protection
         * @note Replaces the entire hash table atomically
         */
        bool initialize_udp_table()
        {
            try {
                udp_hashtable_t udp_to_app;
                {
                    std::unique_lock lock(table_buffer_udp_lock_);

                    auto table_size = table_buffer_size_udp_;

                    for (;;) {
                        const uint32_t result = ::GetExtendedUdpTable(
                            table_buffer_udp_.get(),
                            &table_size,
                            FALSE,
                            T::af_type,
                            UDP_TABLE_OWNER_MODULE,
                            0);

                        if (result == NO_ERROR) break;
                        if (result != ERROR_INSUFFICIENT_BUFFER) return false;

                        // Allocate exactly the size the API asked for
                        table_buffer_udp_ = std::make_unique<char[]>(table_size);
                        table_buffer_size_udp_ = table_size;
                    }

                    if constexpr (std::is_same_v<T, net::ip_address_v4>) {
                        auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_MODULE>(table_buffer_udp_.get());
                        for (size_t i = 0; i < table->dwNumEntries; i++) {
                            if (auto process_ptr = process_udp_entry_v4(&table->table[i])) {
                                udp_to_app[net::ip_endpoint<T>(
                                    T{ table->table[i].dwLocalAddr },
                                    ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort)))]
                                    = std::move(process_ptr);
                            }
                        }
                    }
                    else {
                        auto* table = reinterpret_cast<PMIB_UDP6TABLE_OWNER_MODULE>(table_buffer_udp_.get());
                        for (size_t i = 0; i < table->dwNumEntries; i++) {
                            if (auto process_ptr = process_udp_entry_v6(&table->table[i])) {
                                udp_to_app[net::ip_endpoint<T>(
                                    T{ table->table[i].ucLocalAddr },
                                    ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort)),
                                    0)]
                                    = std::move(process_ptr);
                            }
                        }
                    }
                }

                std::unique_lock lock(udp_to_app_mutex_);
                udp_to_app_ = std::move(udp_to_app);
            }
            catch (...) {
                return false;
            }

            return true;
        }
    };
}