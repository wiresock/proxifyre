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

    class owner_module_resolver {
    public:
        struct result {
            std::wstring base_name;  // e.g. "notepad.exe" or service name
            std::wstring full_path;  // e.g. "C:\\Windows\\System32\\notepad.exe" or same as base when service
        };

        // Unique process identifier that prevents PID reuse issues
        struct process_identity {
            DWORD pid{};
            FILETIME creation_time{};

            bool operator==(const process_identity& other) const noexcept {
                return pid == other.pid &&
                    creation_time.dwLowDateTime == other.creation_time.dwLowDateTime &&
                    creation_time.dwHighDateTime == other.creation_time.dwHighDateTime;
            }
            bool operator<(const process_identity& other) const noexcept {
                if (pid != other.pid) return pid < other.pid;
                if (creation_time.dwHighDateTime != other.creation_time.dwHighDateTime)
                    return creation_time.dwHighDateTime < other.creation_time.dwHighDateTime;
                return creation_time.dwLowDateTime < other.creation_time.dwLowDateTime;
            }
        };

        struct process_identity_hash {
            std::size_t operator()(const process_identity& pi) const noexcept {
                const std::size_t h1 = std::hash<DWORD>{}(pi.pid);
                const std::size_t h2 = std::hash<DWORD>{}(pi.creation_time.dwLowDateTime);
                const std::size_t h3 = std::hash<DWORD>{}(pi.creation_time.dwHighDateTime);
                return h1 ^ (h2 << 1) ^ (h3 << 2);
            }
        };

        template<typename H1, typename H2>
        struct pair_hash {
            std::size_t operator()(const std::pair<process_identity, DWORD>& p) const noexcept {
                H1 h1;
                H2 h2;
                return h1(p.first) ^ (h2(p.second) << 1);
            }
        };

        struct cache_entry {
            result data;
            std::chrono::steady_clock::time_point timestamp;
        };

        using cache_key_t = std::pair<process_identity, DWORD>;
        using cache_t = std::unordered_map<cache_key_t, cache_entry,
            pair_hash<process_identity_hash, std::hash<DWORD>>>;

        // Extract tag from MIB_*ROW_OWNER_MODULE::OwningModuleInfo[16]
        static DWORD service_tag_from_owning_module_info(const ULONGLONG omi[16]) noexcept {
            const DWORD lo0 = static_cast<DWORD>(omi[0] & 0xFFFFFFFFu);
            const DWORD lo1 = static_cast<DWORD>((omi[0] >> 32) & 0xFFFFFFFFu);
            return (lo0 == 0 && lo1 == 0) ? 0 : lo0;
        }

        // Main entry point (cached)
        static bool resolve_from_pid_and_tag(const DWORD pid, const DWORD service_tag, result& out) {
            return resolve_from_pid_and_tag_cached(pid, service_tag, out);
        }

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

                cache[cache_key] = {.data = out, .timestamp = now };
                cleanup_cache_if_needed(now); // caller holds unique lock
            }
            return success;
        }

        static void clear_cache() {
            std::unique_lock lock(get_cache_mutex());
            get_cache().clear();
        }

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

        // Utilities
        static bool is_system_process(const DWORD pid) noexcept { return pid == 0 || pid == 4; }
        static bool is_valid_service_tag(const DWORD tag) noexcept {
            return tag > 0 && tag != 0xFFFFFFFFu;
        }
        static std::wstring get_process_name_only(const DWORD pid) {
            if (result res; resolve_from_pid_and_tag(pid, 0, res)) return res.base_name;
            return L"";
        }

        enum class error_code: uint8_t {
            success,
            invalid_pid,
            access_denied,
            module_not_found,
            service_not_found,
            insufficient_buffer,
            api_failed
        };

        struct extended_result {
            result data;
            error_code error{ error_code::api_failed };
            std::wstring error_message;
        };

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
        // Maximum cache entries to prevent unbounded memory growth
        static constexpr size_t max_cache_entries = 10000;
        // Maximum buffer size to prevent pathological memory allocation (32KB)
        static constexpr size_t max_path_buffer_size = 32768;

        // -------- cache plumbing ----------
        static cache_t& get_cache() {
            static cache_t cache;
            return cache;
        }
        static std::shared_mutex& get_cache_mutex() {
            static std::shared_mutex m;
            return m;
        }
        static std::chrono::minutes get_cache_duration() {
            static constexpr std::chrono::minutes duration{ 5 };
            return duration;
        }
        static std::chrono::steady_clock::time_point& get_last_cleanup() {
            static std::chrono::steady_clock::time_point last{ std::chrono::steady_clock::now() };
            return last;
        }
        static std::chrono::minutes get_cleanup_interval() {
            static constexpr std::chrono::minutes interval{ 10 };
            return interval;
        }

        // NOTE: Caller must hold a UNIQUE (write) lock on get_cache_mutex() before calling.
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

        // -------- uncached path ----------
        static bool resolve_from_pid_and_tag_uncached(const DWORD pid, const DWORD service_tag, result& out) {
            out = {};
            if (service_tag == 0) return resolve_by_process_image(pid, out);
            return resolve_by_service_tag(pid, service_tag, out);
        }

        // -------- RAII helpers ----------
        class debug_privilege_toggle {
        public:
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

            bool enabled() const noexcept { return need_revert_ || was_enabled_; }

        private:
            LUID luid_{};
            bool was_enabled_{ false };
            bool need_revert_{ false };
        };

        // Cache the I_QueryTagInformation pointer once per process
        using pfn_i_query_tag_information = ULONG(WINAPI*)(PVOID, ULONG, PVOID);
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

        // -------- resolvers ----------
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

        // service tag query
        enum class service_tag_query_type : uint8_t { service_name_from_tag = 1 };
        struct service_tag_query {
            ULONG  process_id;
            ULONG  service_tag;
            ULONG  reserved;
            PWSTR  buffer; // LocalAlloc'ed
        };

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

        static std::wstring basename_from_path(const std::wstring& path) {
            const auto pos = path.find_last_of(L"\\/");
            return (pos == std::wstring::npos) ? path : path.substr(pos + 1);
        }
    };

} // namespace iphelper
