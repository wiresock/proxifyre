#pragma once

#include "owner_module_resolver.h"

namespace iphelper
{
    // --------------------------------------------------------------------------------
    /// <summary>
    /// Represents a networking application
    /// </summary>
    // --------------------------------------------------------------------------------
    struct network_process
    {
        network_process() = default;

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

        static bool is_valid_wide_string(const wchar_t* ptr_str) {
            return ptr_str != nullptr && ptr_str[0] != L'\0';
        }

        // Converts "C:\Windows\System32\notepad.exe" -> "\Device\HarddiskVolume3\Windows\System32\notepad.exe".
        // Returns empty string on failure. Does NOT force any casing; ctor normalizes.
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
    class process_lookup final : public netlib::log::logger<process_lookup<T>>
    {
        using log_level = netlib::log::log_level;

        static constexpr std::chrono::seconds protected_apps_cache_timeout{ 2 };

        using tcp_hashtable_t = std::unordered_map<net::ip_session<T>, std::shared_ptr<network_process>>;
        using udp_hashtable_t = std::unordered_map<net::ip_endpoint<T>, std::shared_ptr<network_process>>;

        using tcp_protected_t = std::unordered_map<net::ip_session<T>, std::chrono::time_point<std::chrono::steady_clock>>;
        using udp_protected_t = std::unordered_map<net::ip_endpoint<T>, std::chrono::time_point<std::chrono::steady_clock>>;

    public:
        explicit process_lookup(const log_level log_level = log_level::error,
            const std::optional<std::reference_wrapper<std::ostream>> log_stream = std::nullopt)
            : netlib::log::logger<process_lookup>(log_level, log_stream)
        {
            default_process_ = std::make_shared<network_process>(0, L"SYSTEM", L"SYSTEM");
            initialize_tcp_table();
            initialize_udp_table();
        }

        process_lookup(const process_lookup&) = delete;
        process_lookup(process_lookup&&) noexcept = delete;
        process_lookup& operator=(const process_lookup&) = delete;
        process_lookup& operator=(process_lookup&&) noexcept = delete;

        ~process_lookup() = default;

    private:
        tcp_hashtable_t  tcp_to_app_;
        udp_hashtable_t  udp_to_app_;
        std::shared_mutex tcp_to_app_mutex_;
        std::shared_mutex udp_to_app_mutex_;

        tcp_protected_t tcp_protected_apps_;
        udp_protected_t udp_protected_apps_;
        std::mutex      tcp_protected_apps_lock_;
        std::mutex      udp_protected_apps_lock_;

        std::shared_ptr<network_process> default_process_;

        std::unique_ptr<char[]> table_buffer_tcp_{};
        std::unique_ptr<char[]> table_buffer_udp_{};
        std::mutex table_buffer_tcp_lock_;
        std::mutex table_buffer_udp_lock_;
        DWORD table_buffer_size_tcp_{ 0 };
        DWORD table_buffer_size_udp_{ 0 };

    public:
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
        // --- helper ---------------------------------------------------------------
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

        // --- TCPv4 ----------------------------------------------------------------
        std::shared_ptr<network_process>
            process_tcp_entry_v4(const PMIB_TCPROW_OWNER_MODULE row) noexcept
        {
            const DWORD pid = row->dwOwningPid;
            const DWORD tag = owner_module_resolver::service_tag_from_owning_module_info(row->OwningModuleInfo);

            const auto ext = owner_module_resolver::resolve_from_pid_and_tag_extended(pid, tag);
            if (ext.error == owner_module_resolver::error_code::success) {
                this->print_log(log_level::debug,
                    "Resolved TCPv4 owner: pid=" + std::to_string(pid) +
                    " tag=" + std::to_string(tag) +
                    " name=\"" + tools::strings::to_string(ext.data.base_name) +
                    "\" path=\"" + tools::strings::to_string(ext.data.full_path) + '\"');

                return std::make_shared<network_process>(
                    pid,
                    std::wstring{ ext.data.base_name },
                    std::wstring{ ext.data.full_path }
                );
            }

            if (tag != 0 && ext.error == owner_module_resolver::error_code::service_not_found) {
                if (owner_module_resolver::result img{}; owner_module_resolver::resolve_from_pid_and_tag(pid, 0, img)) {
                    this->print_log(log_level::warning,
                        "Service tag not found; fell back to process image (TCPv4): pid=" + std::to_string(pid) +
                        " tag=" + std::to_string(tag) +
                        " name=\"" + tools::strings::to_string(img.base_name) +
                        "\" path=\"" + tools::strings::to_string(img.full_path) + '\"');

                    return std::make_shared<network_process>(
                        pid,
                        std::move(img.base_name),
                        std::move(img.full_path)
                    );
                }
            }

            std::string msg = "Failed to resolve TCPv4 owner: pid=" + std::to_string(pid) +
                " tag=" + std::to_string(tag) +
                " error=" + error_code_to_string(ext.error);
            if (!ext.error_message.empty())
                msg += " msg=\"" + tools::strings::to_string(ext.error_message) + '\"';
            this->print_log(log_level::error, msg);
            return nullptr;
        }

        // --- TCPv6 ----------------------------------------------------------------
        std::shared_ptr<network_process>
            process_tcp_entry_v6(const PMIB_TCP6ROW_OWNER_MODULE row) noexcept
        {
            const DWORD pid = row->dwOwningPid;
            const DWORD tag = owner_module_resolver::service_tag_from_owning_module_info(row->OwningModuleInfo);

            const auto ext = owner_module_resolver::resolve_from_pid_and_tag_extended(pid, tag);
            if (ext.error == owner_module_resolver::error_code::success) {
                this->print_log(log_level::debug,
                    "Resolved TCPv6 owner: pid=" + std::to_string(pid) +
                    " tag=" + std::to_string(tag) +
                    " name=\"" + tools::strings::to_string(ext.data.base_name) +
                    "\" path=\"" + tools::strings::to_string(ext.data.full_path) + '\"');

                return std::make_shared<network_process>(
                    pid,
                    std::wstring{ ext.data.base_name },
                    std::wstring{ ext.data.full_path }
                );
            }

            if (tag != 0 && ext.error == owner_module_resolver::error_code::service_not_found) {
                if (owner_module_resolver::result img{}; owner_module_resolver::resolve_from_pid_and_tag(pid, 0, img)) {
                    this->print_log(log_level::warning,
                        "Service tag not found; fell back to process image (TCPv6): pid=" + std::to_string(pid) +
                        " tag=" + std::to_string(tag) +
                        " name=\"" + tools::strings::to_string(img.base_name) +
                        "\" path=\"" + tools::strings::to_string(img.full_path) + '\"');

                    return std::make_shared<network_process>(
                        pid,
                        std::move(img.base_name),
                        std::move(img.full_path)
                    );
                }
            }

            std::string msg = "Failed to resolve TCPv6 owner: pid=" + std::to_string(pid) +
                " tag=" + std::to_string(tag) +
                " error=" + error_code_to_string(ext.error);
            if (!ext.error_message.empty())
                msg += " msg=\"" + tools::strings::to_string(ext.error_message) + '\"';
            this->print_log(log_level::error, msg);
            return nullptr;
        }

        // --- UDPv4 ----------------------------------------------------------------
        std::shared_ptr<network_process>
            process_udp_entry_v4(const PMIB_UDPROW_OWNER_MODULE row) noexcept
        {
            const DWORD pid = row->dwOwningPid;
            const DWORD tag = owner_module_resolver::service_tag_from_owning_module_info(row->OwningModuleInfo);

            const auto ext = owner_module_resolver::resolve_from_pid_and_tag_extended(pid, tag);
            if (ext.error == owner_module_resolver::error_code::success) {
                this->print_log(log_level::debug,
                    "Resolved UDPv4 owner: pid=" + std::to_string(pid) +
                    " tag=" + std::to_string(tag) +
                    " name=\"" + tools::strings::to_string(ext.data.base_name) +
                    "\" path=\"" + tools::strings::to_string(ext.data.full_path) + '\"');

                return std::make_shared<network_process>(
                    pid,
                    std::wstring{ ext.data.base_name },
                    std::wstring{ ext.data.full_path }
                );
            }

            if (tag != 0 && ext.error == owner_module_resolver::error_code::service_not_found) {
                if (owner_module_resolver::result img{}; owner_module_resolver::resolve_from_pid_and_tag(pid, 0, img)) {
                    this->print_log(log_level::warning,
                        "Service tag not found; fell back to process image (UDPv4): pid=" + std::to_string(pid) +
                        " tag=" + std::to_string(tag) +
                        " name=\"" + tools::strings::to_string(img.base_name) +
                        "\" path=\"" + tools::strings::to_string(img.full_path) + '\"');

                    return std::make_shared<network_process>(
                        pid,
                        std::move(img.base_name),
                        std::move(img.full_path)
                    );
                }
            }

            std::string msg = "Failed to resolve UDPv4 owner: pid=" + std::to_string(pid) +
                " tag=" + std::to_string(tag) +
                " error=" + error_code_to_string(ext.error);
            if (!ext.error_message.empty())
                msg += " msg=\"" + tools::strings::to_string(ext.error_message) + '\"';
            this->print_log(log_level::error, msg);
            return nullptr;
        }

        // --- UDPv6 ----------------------------------------------------------------
        std::shared_ptr<network_process>
            process_udp_entry_v6(const PMIB_UDP6ROW_OWNER_MODULE row) noexcept
        {
            const DWORD pid = row->dwOwningPid;
            const DWORD tag = owner_module_resolver::service_tag_from_owning_module_info(row->OwningModuleInfo);

            const auto ext = owner_module_resolver::resolve_from_pid_and_tag_extended(pid, tag);
            if (ext.error == owner_module_resolver::error_code::success) {
                this->print_log(log_level::debug,
                    "Resolved UDPv6 owner: pid=" + std::to_string(pid) +
                    " tag=" + std::to_string(tag) +
                    " name=\"" + tools::strings::to_string(ext.data.base_name) +
                    "\" path=\"" + tools::strings::to_string(ext.data.full_path) + '\"');

                return std::make_shared<network_process>(
                    pid,
                    std::wstring{ ext.data.base_name },
                    std::wstring{ ext.data.full_path }
                );
            }

            if (tag != 0 && ext.error == owner_module_resolver::error_code::service_not_found) {
                if (owner_module_resolver::result img{}; owner_module_resolver::resolve_from_pid_and_tag(pid, 0, img)) {
                    this->print_log(log_level::warning,
                        "Service tag not found; fell back to process image (UDPv6): pid=" + std::to_string(pid) +
                        " tag=" + std::to_string(tag) +
                        " name=\"" + tools::strings::to_string(img.base_name) +
                        "\" path=\"" + tools::strings::to_string(img.full_path) + '\"');

                    return std::make_shared<network_process>(
                        pid,
                        std::move(img.base_name),
                        std::move(img.full_path)
                    );
                }
            }

            std::string msg = "Failed to resolve UDPv6 owner: pid=" + std::to_string(pid) +
                " tag=" + std::to_string(tag) +
                " error=" + error_code_to_string(ext.error);
            if (!ext.error_message.empty())
                msg += " msg=\"" + tools::strings::to_string(ext.error_message) + '\"';
            this->print_log(log_level::error, msg);
            return nullptr;
        }

        // --- TCP table init -------------------------------------------------------
        bool initialize_tcp_table()
        {
            auto table_size = table_buffer_size_tcp_;

            try {
                tcp_hashtable_t tcp_to_app;
                {
                    std::unique_lock lock(table_buffer_tcp_lock_);

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

        // --- UDP table init -------------------------------------------------------
        bool initialize_udp_table()
        {
            auto table_size = table_buffer_size_udp_;

            try {
                udp_hashtable_t udp_to_app;
                {
                    std::unique_lock lock(table_buffer_udp_lock_);

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
