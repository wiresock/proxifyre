#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>          // GetModuleFileNameExW
#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>
#include <atomic>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

namespace iphelper {

    /**
     * @brief Resolves process modules and service names from PIDs and service tags with intelligent caching.
     *
     * This class provides functionality to resolve process executable paths and service names
     * from process IDs (PIDs) and service tags. It includes robust caching with PID reuse protection,
     * multiple fallback mechanisms for different Windows APIs, and thread-safe operations.
     *
     * Key features:
     * - PID reuse protection using process creation time
     * - Intelligent caching with automatic expiration and cleanup
     * - Multiple fallback APIs (PSAPI, QueryFullProcessImageNameW)
     * - Service tag resolution using undocumented Windows APIs
     * - Thread-safe operations with reader-writer locks
     * - Memory bounds protection against pathological buffer growth
     *
     * @note Requires Windows Vista or later for full functionality
     * @note Uses C++20 features (std::ranges)
     */
    class owner_module_resolver {
    public:
        /**
         * @brief Contains the resolved process/service information.
         */
        struct result {
            std::wstring base_name;  ///< Process executable name (e.g. "notepad.exe") or service name
            std::wstring full_path;  ///< Full path to executable (e.g. "C:\\Windows\\System32\\notepad.exe") or same as base_name for services
        };

        /**
         * @brief Unique process identifier that prevents PID reuse issues.
         *
         * Combines process ID with creation time to create a truly unique identifier
         * that remains valid even when PIDs are recycled by the operating system.
         */
        struct process_identity {
            DWORD pid{};                ///< Process ID
            FILETIME creation_time{};   ///< Process creation time from GetProcessTimes()

            /**
             * @brief Equality comparison operator.
             * @param other The other process_identity to compare with
             * @return true if both PID and creation time match
             */
            bool operator==(const process_identity& other) const noexcept {
                return pid == other.pid &&
                    creation_time.dwLowDateTime == other.creation_time.dwLowDateTime &&
                    creation_time.dwHighDateTime == other.creation_time.dwHighDateTime;
            }

            /**
             * @brief Less-than comparison operator for use in ordered containers.
             * @param other The other process_identity to compare with
             * @return true if this identity is considered less than the other
             */
            bool operator<(const process_identity& other) const noexcept {
                if (pid != other.pid) return pid < other.pid;
                if (creation_time.dwHighDateTime != other.creation_time.dwHighDateTime)
                    return creation_time.dwHighDateTime < other.creation_time.dwHighDateTime;
                return creation_time.dwLowDateTime < other.creation_time.dwLowDateTime;
            }
        };

        /**
         * @brief Hash function for process_identity to enable use in unordered containers.
         */
        struct process_identity_hash {
            /**
             * @brief Computes hash value for a process_identity.
             * @param pi The process_identity to hash
             * @return Hash value combining PID and creation time components
             */
            std::size_t operator()(const process_identity& pi) const noexcept {
                const std::size_t h1 = std::hash<DWORD>{}(pi.pid);
                const std::size_t h2 = std::hash<DWORD>{}(pi.creation_time.dwLowDateTime);
                const std::size_t h3 = std::hash<DWORD>{}(pi.creation_time.dwHighDateTime);
                return h1 ^ (h2 << 1) ^ (h3 << 2);
            }
        };

        /**
         * @brief Hash function for std::pair to enable use in unordered containers.
         * @tparam H1 Hash function type for first element
         * @tparam H2 Hash function type for second element
         */
        template<typename H1, typename H2>
        struct pair_hash {
            /**
             * @brief Computes hash value for a pair.
             * @param p The pair to hash
             * @return Combined hash value of both pair elements
             */
            std::size_t operator()(const std::pair<process_identity, DWORD>& p) const noexcept {
                H1 h1;
                H2 h2;
                return h1(p.first) ^ (h2(p.second) << 1);
            }
        };

        /**
         * @brief Cache entry containing resolved data and timestamp.
         */
        struct cache_entry {
            result data;                                            ///< Resolved process/service information
            std::chrono::steady_clock::time_point timestamp;       ///< When this entry was cached
        };

        /// Type alias for cache key (process_identity + service_tag)
        using cache_key_t = std::pair<process_identity, DWORD>;

        /// Type alias for the cache container
        using cache_t = std::unordered_map<cache_key_t, cache_entry,
            pair_hash<process_identity_hash, std::hash<DWORD>>>;

        /**
         * @brief Extracts service tag from MIB_*ROW_OWNER_MODULE::OwningModuleInfo[16] array.
         *
         * This utility function extracts the service tag from the OwningModuleInfo array
         * found in IP Helper API structures like MIB_TCPROW_OWNER_MODULE.
         *
         * @param omi The OwningModuleInfo array (16 ULONGLONG elements)
         * @return Service tag if present, 0 if no service tag
         * @note Only examines the first element of the array (omi[0])
         */
        static DWORD service_tag_from_owning_module_info(const ULONGLONG omi[16]) noexcept {
            const DWORD lo0 = static_cast<DWORD>(omi[0] & 0xFFFFFFFFu);
            const DWORD lo1 = static_cast<DWORD>((omi[0] >> 32) & 0xFFFFFFFFu);
            return (lo0 == 0 && lo1 == 0) ? 0 : lo0;
        }

        /**
         * @brief Main entry point for resolving process/service information (cached version).
         *
         * @param pid Process ID to resolve
         * @param service_tag Service tag (0 for regular process resolution)
         * @param out [out] Resolved information
         * @return true if resolution was successful, false otherwise
         */
        static bool resolve_from_pid_and_tag(const DWORD pid, const DWORD service_tag, result& out) {
            return resolve_from_pid_and_tag_cached(pid, service_tag, out);
        }

        /**
         * @brief Cached version of process/service resolution with PID reuse protection.
         *
         * This method first attempts to get a unique process identity (PID + creation time),
         * then checks the cache for existing results. If not cached or expired, it performs
         * the actual resolution and caches the result.
         *
         * @param pid Process ID to resolve
         * @param service_tag Service tag (0 for regular process resolution)
         * @param out [out] Resolved information
         * @return true if resolution was successful, false otherwise
         *
         * @note Falls back to uncached resolution if process identity cannot be obtained
         * @note Automatically manages cache size and performs cleanup
         */
        static bool resolve_from_pid_and_tag_cached(const DWORD pid, const DWORD service_tag, result& out) {
            out = {};

            process_identity proc_id{};
            if (!get_process_identity(pid, proc_id)) {
                // Fallback if we can't read creation time
                return resolve_from_pid_and_tag_uncached(pid, service_tag, out);
            }

            const auto cache_key = std::make_pair(proc_id, service_tag);
            const auto now = std::chrono::steady_clock::now();

            {
                std::shared_lock lock(get_cache_mutex());
                auto& cache = get_cache();
                if (const auto it = cache.find(cache_key); it != cache.end() &&
                    (now - it->second.timestamp) < get_cache_duration())
                {
                    out = it->second.data;
                    return !out.base_name.empty();
                }
            }

            const bool success = resolve_from_pid_and_tag_uncached(pid, service_tag, out);
            if (success) {
                std::unique_lock lock(get_cache_mutex());
                auto& cache = get_cache();

                // Cap size and evict the oldest if needed
                if (cache.size() >= max_cache_entries) {
                    cleanup_cache_if_needed(now); // caller holds unique lock
                    if (cache.size() >= max_cache_entries) {
                        // NOTE: requires C++20 for std::ranges
                        const auto oldest_it = std::ranges::min_element(cache,
                            [](const auto& a, const auto& b) {
                                return a.second.timestamp < b.second.timestamp;
                            });
                        if (oldest_it != cache.end()) cache.erase(oldest_it);
                    }
                }

                cache[cache_key] = { .data = out, .timestamp = now };
                cleanup_cache_if_needed(now); // caller holds unique lock
            }
            return success;
        }

        /**
         * @brief Clears all cached entries.
         *
         * @note Thread-safe operation
         */
        static void clear_cache() {
            std::unique_lock lock(get_cache_mutex());
            get_cache().clear();
        }

        /**
         * @brief Gets cache statistics for monitoring purposes.
         *
         * @return Pair containing (valid_entries, total_entries)
         *         - valid_entries: Number of non-expired entries
         *         - total_entries: Total number of entries in cache
         *
         * @note Thread-safe operation
         */
        static std::pair<size_t, size_t> get_cache_stats() {
            std::shared_lock lock(get_cache_mutex());
            const auto& m = get_cache();
            const auto now = std::chrono::steady_clock::now();
            size_t total = m.size();
            size_t valid = 0;
            for (const auto& [key, entry] : m) {
                if ((now - entry.timestamp) < get_cache_duration()) ++valid;
            }
            return { valid, total };
        }

        /**
         * @brief Checks if a PID represents a system process.
         * @param pid Process ID to check
         * @return true if PID is 0 (System Idle Process) or 4 (System)
         */
        static bool is_system_process(const DWORD pid) noexcept { return pid == 0 || pid == 4; }

        /**
         * @brief Validates a service tag value.
         * @param tag Service tag to validate
         * @return true if tag is valid (> 0 and not 0xFFFFFFFF)
         */
        static bool is_valid_service_tag(const DWORD tag) noexcept {
            return tag > 0 && tag != 0xFFFFFFFFu;
        }

        /**
         * @brief Convenience method to get only the process name.
         * @param pid Process ID to resolve
         * @return Process name (base_name) or empty string if resolution fails
         */
        static std::wstring get_process_name_only(const DWORD pid) {
            if (result res; resolve_from_pid_and_tag(pid, 0, res)) return res.base_name;
            return L"";
        }

        /**
         * @brief Error codes for extended result reporting.
         */
        enum class error_code : uint8_t {
            success,            ///< Operation completed successfully
            invalid_pid,        ///< Invalid process ID provided
            access_denied,      ///< Access denied when querying process
            module_not_found,   ///< Process module could not be resolved
            service_not_found,  ///< Service name could not be resolved
            insufficient_buffer,///< Buffer too small (internal error)
            api_failed         ///< Windows API call failed
        };

        /**
         * @brief Extended result structure with detailed error information.
         */
        struct extended_result {
            result data;                                    ///< Resolved data (if successful)
            error_code error{ error_code::api_failed };    ///< Error code
            std::wstring error_message;                     ///< Human-readable error description
        };

        /**
         * @brief Extended version with detailed error reporting.
         *
         * @param pid Process ID to resolve
         * @param service_tag Service tag (0 for regular process resolution)
         * @return Extended result with detailed error information
         */
        static extended_result resolve_from_pid_and_tag_extended(const DWORD pid, const DWORD service_tag) {
            extended_result ext{};
            if (pid == 0) {
                ext.error = error_code::invalid_pid;
                ext.error_message = L"Invalid process ID";
                return ext;
            }
            if (service_tag == 0xFFFFFFFFu) {
                ext.error = error_code::api_failed;
                ext.error_message = L"Invalid service tag";
                return ext;
            }
            if (resolve_from_pid_and_tag(pid, service_tag, ext.data)) {
                ext.error = error_code::success;
            }
            else if (service_tag == 0) {
                ext.error = error_code::module_not_found;
                ext.error_message = L"Failed to resolve process image";
            }
            else {
                ext.error = error_code::service_not_found;
                ext.error_message = L"Failed to resolve service tag";
            }
            return ext;
        }

    private:
        /// Maximum cache entries to prevent unbounded memory growth
        static constexpr size_t max_cache_entries = 10000;
        /// Maximum buffer size to prevent pathological memory allocation (32KB)
        static constexpr size_t max_path_buffer_size = 32768;

        // -------- cache plumbing ----------

        /**
         * @brief Gets reference to the static cache instance.
         * @return Reference to the cache container
         */
        static cache_t& get_cache() {
            static cache_t cache;
            return cache;
        }

        /**
         * @brief Gets reference to the cache mutex for thread synchronization.
         * @return Reference to the shared mutex
         */
        static std::shared_mutex& get_cache_mutex() {
            static std::shared_mutex m;
            return m;
        }

        /**
         * @brief Gets the cache entry lifetime duration.
         * @return Cache duration (5 minutes)
         */
        static std::chrono::minutes get_cache_duration() {
            static constexpr std::chrono::minutes duration{ 5 };
            return duration;
        }

        /**
         * @brief Gets reference to the last cleanup timestamp.
         * @return Reference to the last cleanup time point
         */
        static std::chrono::steady_clock::time_point& get_last_cleanup() {
            static std::chrono::steady_clock::time_point last{ std::chrono::steady_clock::now() };
            return last;
        }

        /**
         * @brief Gets the interval between cache cleanups.
         * @return Cleanup interval (10 minutes)
         */
        static std::chrono::minutes get_cleanup_interval() {
            static constexpr std::chrono::minutes interval{ 10 };
            return interval;
        }

        /**
         * @brief Performs cache cleanup if enough time has elapsed.
         *
         * Removes expired entries from the cache based on their timestamps.
         * Only performs cleanup if the cleanup interval has elapsed since the last cleanup.
         *
         * @param now Current time point
         *
         * @warning Caller must hold a UNIQUE (write) lock on get_cache_mutex() before calling.
         */
        static void cleanup_cache_if_needed(const std::chrono::steady_clock::time_point now) {
            auto& last = get_last_cleanup();
            if ((now - last) < get_cleanup_interval()) return;
            last = now;

            auto& cache = get_cache();
            for (auto it = cache.begin(); it != cache.end();) {
                if ((now - it->second.timestamp) >= get_cache_duration())
                    it = cache.erase(it);
                else
                    ++it;
            }
        }

        /**
         * @brief Obtains unique process identity (PID + creation time).
         *
         * @param pid Process ID
         * @param identity [out] Process identity structure to fill
         * @return true if process identity was successfully obtained
         *
         * @note Uses PROCESS_QUERY_LIMITED_INFORMATION access level
         */
        static bool get_process_identity(const DWORD pid, process_identity& identity) {
            identity.pid = pid;

            const HANDLE process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!process_handle) return false;

            FILETIME creation_time{}, exit_time{}, kernel_time{}, user_time{};
            const BOOL ok = GetProcessTimes(process_handle, &creation_time, &exit_time, &kernel_time, &user_time);
            if (ok) identity.creation_time = creation_time;

            CloseHandle(process_handle);
            return ok != 0;
        }

        /**
         * @brief Uncached resolution that bypasses the cache system.
         *
         * @param pid Process ID to resolve
         * @param service_tag Service tag (0 for regular process resolution)
         * @param out [out] Resolved information
         * @return true if resolution was successful
         */
        static bool resolve_from_pid_and_tag_uncached(const DWORD pid, const DWORD service_tag, result& out) {
            out = {};
            if (service_tag == 0) return resolve_by_process_image(pid, out);
            return resolve_by_service_tag(pid, service_tag, out);
        }

        /**
         * @brief RAII helper class for managing SeDebugPrivilege.
         *
         * Automatically enables SeDebugPrivilege on construction (if requested)
         * and properly reverts it on destruction. Prevents copying/moving to
         * preserve RAII semantics.
         */
        class debug_privilege_toggle {
        public:
            /**
             * @brief Constructs debug privilege manager.
             * @param enable Whether to enable SeDebugPrivilege
             */
            explicit debug_privilege_toggle(const bool enable) {
                HANDLE token{};
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
                    return;

                if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid_)) {
                    CloseHandle(token);
                    return;
                }

                // see if already enabled
                DWORD bytes = 0;
                GetTokenInformation(token, TokenPrivileges, nullptr, 0, &bytes);
                std::vector<BYTE> buf(bytes ? bytes : sizeof(TOKEN_PRIVILEGES));

                if (GetTokenInformation(token, TokenPrivileges, buf.data(), static_cast<DWORD>(buf.size()), &bytes) != 0) {
                    const auto* tp = reinterpret_cast<const TOKEN_PRIVILEGES*>(buf.data());
                    for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
                        if (tp->Privileges[i].Luid.LowPart == luid_.LowPart &&
                            tp->Privileges[i].Luid.HighPart == luid_.HighPart) {
                            was_enabled_ = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                            break;
                        }
                    }
                }

                if (enable) {
                    TOKEN_PRIVILEGES tp{};
                    tp.PrivilegeCount = 1;
                    tp.Privileges[0].Luid = luid_;
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                    SetLastError(NO_ERROR);
                    if (AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
                        GetLastError() != ERROR_NOT_ALL_ASSIGNED) {
                        need_revert_ = !was_enabled_;
                    }
                }

                CloseHandle(token);
            }

            // Disallow copy and move to preserve RAII semantics
            debug_privilege_toggle(const debug_privilege_toggle&) = delete;
            debug_privilege_toggle& operator=(const debug_privilege_toggle&) = delete;
            debug_privilege_toggle(debug_privilege_toggle&&) = delete;
            debug_privilege_toggle& operator=(debug_privilege_toggle&&) = delete;

            /**
             * @brief Destructor that reverts privilege changes.
             */
            ~debug_privilege_toggle() {
                if (!need_revert_) return;

                HANDLE token{};
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
                    return;

                TOKEN_PRIVILEGES tp{};
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid_;
                tp.Privileges[0].Attributes = 0; // disable

                AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
                CloseHandle(token);
            }

            /**
             * @brief Checks if SeDebugPrivilege is currently enabled.
             * @return true if privilege is enabled (either was already enabled or we enabled it)
             */
            bool enabled() const noexcept { return need_revert_ || was_enabled_; }

        private:
            LUID luid_{};                   ///< LUID for SeDebugPrivilege
            bool was_enabled_{ false };     ///< Whether privilege was already enabled
            bool need_revert_{ false };     ///< Whether we need to revert changes
        };

        /// Function pointer type for I_QueryTagInformation
        using pfn_i_query_tag_information = ULONG(WINAPI*)(PVOID, ULONG, PVOID);

        /**
         * @brief Gets cached pointer to I_QueryTagInformation function.
         *
         * This function caches the address of the undocumented I_QueryTagInformation
         * function from advapi32.dll for efficient service tag resolution.
         *
         * @return Function pointer or nullptr if not available
         * @note Thread-safe with atomic operations
         * @note Keeps advapi32.dll loaded for process lifetime
         */
        static pfn_i_query_tag_information get_iqti() {
            static std::atomic<pfn_i_query_tag_information> cached{ nullptr };
            const auto p = cached.load(std::memory_order_acquire);
            if (!p) {
                HMODULE mod = GetModuleHandleW(L"advapi32.dll");
                if (!mod) {
                    mod = LoadLibraryW(L"advapi32.dll");
                    // Keep advapi32 loaded for the process lifetime
                }
                const auto f = mod ? reinterpret_cast<pfn_i_query_tag_information>(  // NOLINT(clang-diagnostic-cast-function-type-strict)
                    GetProcAddress(mod, "I_QueryTagInformation")) : nullptr;

                if (pfn_i_query_tag_information expected = nullptr;
                    !cached.compare_exchange_strong(expected, f,
                        std::memory_order_release,
                        std::memory_order_acquire)) {
                    return expected;
                }
                return f;
            }
            return p;
        }

        /**
         * @brief Resolves process executable path using Windows APIs.
         *
         * Attempts to resolve the full path to a process executable using multiple
         * fallback mechanisms:
         * 1. GetModuleFileNameExW (requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
         * 2. QueryFullProcessImageNameW (requires PROCESS_QUERY_LIMITED_INFORMATION)
         *
         * @param pid Process ID to resolve
         * @param out [out] Resolved process information
         * @return true if resolution was successful
         *
         * @note Automatically enables SeDebugPrivilege if possible
         * @note Protected against pathological buffer growth (32KB limit)
         */
        static bool resolve_by_process_image(const DWORD pid, result& out) {
            debug_privilege_toggle dbg(true);

            HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!process_handle) {
                // fallback: limited info + QueryFullProcessImageNameW
                process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (!process_handle) return false;
            }

            std::vector<wchar_t> buf(MAX_PATH * 2);
            DWORD len = 0;

            // Try psapi first
            if (DWORD got = GetModuleFileNameExW(process_handle, nullptr, buf.data(), static_cast<DWORD>(buf.size())); got == 0) {
                // fallback: QueryFullProcessImageNameW with growth loop
                for (;;) {
                    // Guard against pathological buffer growth
                    if (buf.size() >= max_path_buffer_size) {
                        CloseHandle(process_handle);
                        return false;
                    }

                    len = static_cast<DWORD>(buf.size());
                    if (QueryFullProcessImageNameW(process_handle, 0, buf.data(), &len)) {
                        break; // success
                    }
                    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                        CloseHandle(process_handle);
                        return false;
                    }
                    buf.resize(buf.size() * 2);
                }
            }
            else {
                // grow if needed (truncation if return >= buffer size)
                while (got >= static_cast<DWORD>(buf.size())) {
                    // Guard against pathological buffer growth
                    if (buf.size() >= max_path_buffer_size) {
                        CloseHandle(process_handle);
                        return false;
                    }

                    buf.resize(buf.size() * 2);
                    got = GetModuleFileNameExW(process_handle, nullptr, buf.data(), static_cast<DWORD>(buf.size()));
                    if (got == 0) break;
                }
                if (got == 0) {
                    // fallback with growth
                    for (;;) {
                        // Guard against pathological buffer growth
                        if (buf.size() >= max_path_buffer_size) {
                            CloseHandle(process_handle);
                            return false;
                        }

                        len = static_cast<DWORD>(buf.size());
                        if (QueryFullProcessImageNameW(process_handle, 0, buf.data(), &len)) {
                            break; // success
                        }
                        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                            CloseHandle(process_handle);
                            return false;
                        }
                        buf.resize(buf.size() * 2);
                    }
                }
                else {
                    len = got;
                }
            }

            out.full_path.assign(buf.data(), len);
            out.base_name = basename_from_path(out.full_path);

            CloseHandle(process_handle);
            return !out.base_name.empty();
        }

        /// Query type for service tag information
        enum class service_tag_query_type : uint8_t { service_name_from_tag = 1 };

        /**
         * @brief Structure for service tag query (used with I_QueryTagInformation).
         */
        struct service_tag_query {
            ULONG  process_id;  ///< Input: Process ID
            ULONG  service_tag; ///< Input: Service tag
            ULONG  reserved;    ///< Input: Must be 0
            PWSTR  buffer;      ///< Output: LocalAlloc'ed service name string
        };

        /**
         * @brief Resolves service name from PID and service tag.
         *
         * Uses the undocumented I_QueryTagInformation API to resolve service names
         * from service tags. The returned buffer is allocated with LocalAlloc and
         * must be freed with LocalFree.
         *
         * @param pid Process ID containing the service
         * @param service_tag Service tag to resolve
         * @param out [out] Resolved service information
         * @return true if resolution was successful
         *
         * @note Uses undocumented Windows API - may not work on all Windows versions
         * @note Automatically frees allocated memory
         */
        static bool resolve_by_service_tag(const DWORD pid, const DWORD service_tag, result& out) {
            const auto i_query_tag_information = get_iqti();
            if (!i_query_tag_information) return false;

            service_tag_query q;
            q.process_id = pid;
            q.service_tag = service_tag;
            q.reserved = 0;
            q.buffer = nullptr;

            const ULONG status = i_query_tag_information(nullptr,
                static_cast<ULONG>(service_tag_query_type::service_name_from_tag),
                &q);
            if (status != 0 || !q.buffer) return false;

            const std::wstring svc(q.buffer);
            LocalFree(q.buffer);

            out.base_name = svc;
            out.full_path = svc; // no dll path known at this stage
            return !out.base_name.empty();
        }

        /**
         * @brief Extracts filename from full path.
         * @param path Full path string
         * @return Filename portion (everything after the last '\\' or '/')
         */
        static std::wstring basename_from_path(const std::wstring& path) {
            const auto pos = path.find_last_of(L"\\/");
            return (pos == std::wstring::npos) ? path : path.substr(pos + 1);
        }
    };

} // namespace iphelper