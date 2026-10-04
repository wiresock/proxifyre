#pragma once

// Deterministic ownership source for process_lookup<T, fake_ownership_source>.
//
// process_lookup's production table ingestion (the primary AF_INET/AF_INET6 loops and the IPv4
// instance's supplementary AF_INET6 folds), its four row enrichment functions, and the
// owner-module row layout all run unchanged. Only the operating-system services behind them are
// replaced:
//   * GetExtendedTcpTable/GetExtendedUdpTable return scripted owner-module rows, including the
//     ERROR_INSUFFICIENT_BUFFER sizing protocol, and every successful query is one recorded
//     capture;
//   * owner resolution (owner_module_resolver::resolve_from_pid_and_tag[_extended]) returns
//     scripted results, so success, failure, service fallback, and PID reuse are exact;
//   * the per-capture owner memo allocates through an allocator that counts its allocations
//     per capture and can be armed to throw std::bad_alloc while a chosen capture is ingested.
//
// Every owner lookup, image (fallback) lookup, and memo allocation is attributed to the capture
// being ingested: process_lookup enriches a capture's rows after querying it and before the
// next query.

#include "../../src/iphelper/owner_memo.h"

namespace netlib_test::ownership
{
    using v4 = net::ip_address_v4;
    using v6 = net::ip_address_v6;
    using process_ptr = std::shared_ptr<iphelper::network_process>;
    using resolver = iphelper::owner_module_resolver;

    /// One physical OS table query: protocol and address family.
    enum class table_kind : uint8_t { tcp_v4, tcp_v6, udp_v4, udp_v6 };

    inline const char* to_string(const table_kind kind)
    {
        switch (kind)
        {
        case table_kind::tcp_v4: return "TCP/AF_INET";
        case table_kind::tcp_v6: return "TCP/AF_INET6";
        case table_kind::udp_v4: return "UDP/AF_INET";
        case table_kind::udp_v6: return "UDP/AF_INET6";
        }
        return "?";
    }

    /// One successful table query and the work done while ingesting its rows.
    struct capture_record
    {
        table_kind kind{};
        size_t rows{};
        int owner_lookups{};    ///< resolve_from_pid_and_tag_extended calls (one per enrichment)
        int image_lookups{};    ///< resolve_from_pid_and_tag(pid, 0) calls (service fallback)
        int memo_allocations{}; ///< allocations made by owner memos while ingesting this capture
    };

    /// A scripted owner resolution response for one (PID, service tag).
    struct scripted_response
    {
        enum class kind : uint8_t { resolved, failed } outcome{ kind::resolved };
        resolver::result data;  ///< for resolved

        static scripted_response failure() { return { kind::failed, {} }; }
        static scripted_response success(std::wstring name, std::wstring path)
        {
            return { kind::resolved, { std::move(name), std::move(path) } };
        }
    };

    class fake_os
    {
    public:
        static fake_os& instance()
        {
            static fake_os os;
            return os;
        }

        void reset() { *this = fake_os{}; }

        // ---------------------------------------------------------------- rows

        std::vector<MIB_TCPROW_OWNER_MODULE> tcp4;
        std::vector<MIB_TCP6ROW_OWNER_MODULE> tcp6;
        std::vector<MIB_UDPROW_OWNER_MODULE> udp4;
        std::vector<MIB_UDP6ROW_OWNER_MODULE> udp6;

        // ---------------------------------------------------------------- owners

        /// Current image of each PID (tag 0 resolution and the service fallback).
        std::map<DWORD, resolver::result> images;
        /// Services hosted by a PID, by service tag.
        std::map<std::pair<DWORD, DWORD>, resolver::result> services;
        /// Responses consumed by the next owner lookups of an identity, before the maps above apply.
        std::map<std::pair<DWORD, DWORD>, std::deque<scripted_response>> scripts;

        /// Runs as a capture of @p kind is taken, before its rows are returned: models changes
        /// (for example PID reuse) that happened after the previous capture.
        std::function<void(table_kind)> on_capture;

        /// Memo allocations during the ingestion of a capture of this kind throw std::bad_alloc.
        std::optional<table_kind> fail_memo_allocations_in;

        // ---------------------------------------------------------------- observations

        std::vector<capture_record> captures;
        int owner_lookups_outside_captures{};

        /// Captures taken since @p mark (a value of captures.size()).
        [[nodiscard]] std::vector<capture_record> captures_since(const size_t mark) const
        {
            return { captures.begin() + static_cast<std::ptrdiff_t>(mark), captures.end() };
        }

        /// The only capture of @p kind taken since @p mark.
        [[nodiscard]] capture_record capture_since(const size_t mark, const table_kind kind) const
        {
            std::optional<capture_record> found;
            for (const auto& c : captures_since(mark))
            {
                if (c.kind != kind)
                    continue;
                EXPECT_FALSE(found.has_value()) << "more than one " << to_string(kind) << " capture";
                found = c;
            }
            EXPECT_TRUE(found.has_value()) << "no " << to_string(kind) << " capture";
            return found.value_or(capture_record{ kind });
        }

        // ---------------------------------------------------------------- the source

        template <class Table, class Row>
        DWORD query(const table_kind kind, const std::vector<Row>& rows, const PVOID buffer, const PDWORD size)
        {
            const auto needed = static_cast<DWORD>(offsetof(Table, table) + rows.size() * sizeof(Row));
            if (buffer == nullptr || *size < needed)
            {
                *size = needed;
                return ERROR_INSUFFICIENT_BUFFER;
            }

            if (on_capture)
                on_capture(kind);

            // on_capture may have changed the rows; size again.
            const auto final_needed = static_cast<DWORD>(offsetof(Table, table) + rows.size() * sizeof(Row));
            if (*size < final_needed)
            {
                *size = final_needed;
                return ERROR_INSUFFICIENT_BUFFER;
            }

            auto* table = static_cast<Table*>(buffer);
            table->dwNumEntries = static_cast<DWORD>(rows.size());
            if (!rows.empty())
                std::memcpy(table->table, rows.data(), rows.size() * sizeof(Row));
            captures.push_back({ kind, rows.size() });
            return NO_ERROR;
        }

        DWORD get_tcp(const PVOID buffer, const PDWORD size, const ULONG family, const TCP_TABLE_CLASS table_class)
        {
            EXPECT_EQ(table_class, TCP_TABLE_OWNER_MODULE_CONNECTIONS);
            return family == AF_INET
                ? query<MIB_TCPTABLE_OWNER_MODULE>(table_kind::tcp_v4, tcp4, buffer, size)
                : query<MIB_TCP6TABLE_OWNER_MODULE>(table_kind::tcp_v6, tcp6, buffer, size);
        }

        DWORD get_udp(const PVOID buffer, const PDWORD size, const ULONG family, const UDP_TABLE_CLASS table_class)
        {
            EXPECT_EQ(table_class, UDP_TABLE_OWNER_MODULE);
            return family == AF_INET
                ? query<MIB_UDPTABLE_OWNER_MODULE>(table_kind::udp_v4, udp4, buffer, size)
                : query<MIB_UDP6TABLE_OWNER_MODULE>(table_kind::udp_v6, udp6, buffer, size);
        }

        /// Mirrors owner_module_resolver::resolve_from_pid_and_tag_extended's error mapping.
        resolver::extended_result resolve_extended(const DWORD pid, const DWORD tag)
        {
            count(&capture_record::owner_lookups);

            resolver::extended_result ext{};
            const auto fail = [&]
            {
                ext.error = tag == 0 ? resolver::error_code::module_not_found : resolver::error_code::service_not_found;
                return ext;
            };

            if (const auto it = scripts.find({ pid, tag }); it != scripts.end() && !it->second.empty())
            {
                const auto response = it->second.front();
                it->second.pop_front();
                if (response.outcome == scripted_response::kind::failed)
                    return fail();
                ext.data = response.data;
                ext.error = resolver::error_code::success;
                return ext;
            }

            if (tag == 0)
            {
                if (const auto it = images.find(pid); it != images.end())
                {
                    ext.data = it->second;
                    ext.error = resolver::error_code::success;
                    return ext;
                }
                return fail();
            }

            if (const auto it = services.find({ pid, tag }); it != services.end())
            {
                ext.data = it->second;
                ext.error = resolver::error_code::success;
                return ext;
            }
            return fail();
        }

        bool resolve(const DWORD pid, const DWORD tag, resolver::result& out)
        {
            count(&capture_record::image_lookups);
            EXPECT_EQ(tag, 0u) << "only the host-image fallback uses the plain resolver";
            out = {};
            if (const auto it = images.find(pid); it != images.end())
            {
                out = it->second;
                return true;
            }
            return false;
        }

        void memo_allocation()
        {
            if (captures.empty())
            {
                ADD_FAILURE() << "owner memo allocated outside a capture";
                return;
            }
            ++captures.back().memo_allocations;
            if (fail_memo_allocations_in == captures.back().kind)
                throw std::bad_alloc();
        }

    private:
        void count(int capture_record::* counter)
        {
            if (captures.empty())
                ++owner_lookups_outside_captures;
            else
                ++(captures.back().*counter);
        }
    };

    /// Allocator of the owner memos built by process_lookup<T, fake_ownership_source>.
    template <class T>
    struct memo_allocator
    {
        using value_type = T;

        memo_allocator() noexcept = default;
        template <class U>
        memo_allocator(const memo_allocator<U>&) noexcept {}

        T* allocate(const size_t n)
        {
            fake_os::instance().memo_allocation();
            return std::allocator<T>{}.allocate(n);
        }

        void deallocate(T* p, const size_t n) noexcept { std::allocator<T>{}.deallocate(p, n); }

        template <class U>
        bool operator==(const memo_allocator<U>&) const noexcept { return true; }
    };

    /// The Source of process_lookup<T, fake_ownership_source>; see iphelper::system_ownership_source.
    struct fake_ownership_source
    {
        static DWORD get_extended_tcp_table(const PVOID buffer, const PDWORD size, BOOL,
            const ULONG family, const TCP_TABLE_CLASS table_class, ULONG) noexcept
        {
            return fake_os::instance().get_tcp(buffer, size, family, table_class);
        }

        static DWORD get_extended_udp_table(const PVOID buffer, const PDWORD size, BOOL,
            const ULONG family, const UDP_TABLE_CLASS table_class, ULONG) noexcept
        {
            return fake_os::instance().get_udp(buffer, size, family, table_class);
        }

        static resolver::extended_result resolve_from_pid_and_tag_extended(const DWORD pid, const DWORD tag)
        {
            return fake_os::instance().resolve_extended(pid, tag);
        }

        static bool resolve_from_pid_and_tag(const DWORD pid, const DWORD tag, resolver::result& out)
        {
            return fake_os::instance().resolve(pid, tag, out);
        }

        template <class Process>
        using owner_memo_type = iphelper::owner_memo<Process,
            memo_allocator<std::pair<const std::uint64_t, std::shared_ptr<Process>>>>;
    };

    using lookup_v4 = iphelper::process_lookup<v4, fake_ownership_source>;
    using lookup_v6 = iphelper::process_lookup<v6, fake_ownership_source>;

    // ------------------------------------------------------------------------------------
    // Rows
    // ------------------------------------------------------------------------------------

    inline in_addr parse_v4(const char* text)
    {
        in_addr a{};
        EXPECT_EQ(::inet_pton(AF_INET, text, &a), 1) << text;
        return a;
    }

    inline in6_addr parse_v6(const char* text)
    {
        in6_addr a{};
        EXPECT_EQ(::inet_pton(AF_INET6, text, &a), 1) << text;
        return a;
    }

    inline DWORD port_field(const uint16_t port) { return htons(port); }

    template <class Row>
    void set_owner(Row& row, const DWORD pid, const DWORD tag)
    {
        row.dwOwningPid = pid;
        row.OwningModuleInfo[0] = tag; // service_tag_from_owning_module_info reads the low 32 bits
    }

    inline MIB_TCPROW_OWNER_MODULE tcp4_row(const DWORD pid, const DWORD tag,
        const char* local, const uint16_t local_port, const char* remote, const uint16_t remote_port)
    {
        MIB_TCPROW_OWNER_MODULE row{};
        row.dwState = MIB_TCP_STATE_ESTAB;
        row.dwLocalAddr = parse_v4(local).S_un.S_addr;
        row.dwLocalPort = port_field(local_port);
        row.dwRemoteAddr = parse_v4(remote).S_un.S_addr;
        row.dwRemotePort = port_field(remote_port);
        set_owner(row, pid, tag);
        return row;
    }

    inline MIB_TCP6ROW_OWNER_MODULE tcp6_row(const DWORD pid, const DWORD tag,
        const char* local, const uint16_t local_port, const char* remote, const uint16_t remote_port,
        const DWORD local_scope = 0, const DWORD remote_scope = 0)
    {
        MIB_TCP6ROW_OWNER_MODULE row{};
        row.dwState = MIB_TCP_STATE_ESTAB;
        const auto l = parse_v6(local);
        const auto r = parse_v6(remote);
        std::memcpy(row.ucLocalAddr, &l, sizeof(row.ucLocalAddr));
        std::memcpy(row.ucRemoteAddr, &r, sizeof(row.ucRemoteAddr));
        row.dwLocalScopeId = local_scope;
        row.dwRemoteScopeId = remote_scope;
        row.dwLocalPort = port_field(local_port);
        row.dwRemotePort = port_field(remote_port);
        set_owner(row, pid, tag);
        return row;
    }

    inline MIB_UDPROW_OWNER_MODULE udp4_row(const DWORD pid, const DWORD tag, const char* local, const uint16_t local_port)
    {
        MIB_UDPROW_OWNER_MODULE row{};
        row.dwLocalAddr = parse_v4(local).S_un.S_addr;
        row.dwLocalPort = port_field(local_port);
        set_owner(row, pid, tag);
        return row;
    }

    inline MIB_UDP6ROW_OWNER_MODULE udp6_row(const DWORD pid, const DWORD tag, const char* local,
        const uint16_t local_port, const DWORD scope = 0)
    {
        MIB_UDP6ROW_OWNER_MODULE row{};
        const auto l = parse_v6(local);
        std::memcpy(row.ucLocalAddr, &l, sizeof(row.ucLocalAddr));
        row.dwLocalScopeId = scope;
        row.dwLocalPort = port_field(local_port);
        set_owner(row, pid, tag);
        return row;
    }

    // ------------------------------------------------------------------------------------
    // Lookup keys
    // ------------------------------------------------------------------------------------

    inline net::ip_session<v4> session4(const char* local, const uint16_t local_port,
        const char* remote, const uint16_t remote_port)
    {
        return { v4{ parse_v4(local) }, v4{ parse_v4(remote) }, local_port, remote_port };
    }

    inline net::ip_session<v6> session6(const char* local, const uint16_t local_port,
        const char* remote, const uint16_t remote_port,
        const std::optional<uint32_t> local_scope = std::nullopt,
        const std::optional<uint32_t> remote_scope = std::nullopt)
    {
        return { v6{ parse_v6(local) }, v6{ parse_v6(remote) }, local_port, remote_port, local_scope, remote_scope };
    }

    inline net::ip_endpoint<v4> endpoint4(const char* ip, const uint16_t port)
    {
        return { v4{ parse_v4(ip) }, port };
    }

    inline net::ip_endpoint<v6> endpoint6(const char* ip, const uint16_t port,
        const std::optional<uint32_t> scope = std::nullopt)
    {
        return { v6{ parse_v6(ip) }, port, scope };
    }

    // ------------------------------------------------------------------------------------
    // Owner images
    // ------------------------------------------------------------------------------------

    /// "<system drive>:\<relative>": QueryDosDeviceW converts it, so its owner is complete.
    inline std::wstring system_drive_path(const std::wstring& relative)
    {
        wchar_t windows[MAX_PATH]{};
        const auto n = ::GetSystemWindowsDirectoryW(windows, MAX_PATH);
        EXPECT_TRUE(n >= 2 && windows[1] == L':') << "no drive-letter system directory";
        return std::wstring{ windows[0], L':', L'\\' } + relative;
    }

    /// A drive letter that is not defined for this process (QueryDosDeviceW fails for it), or
    /// nullopt when every letter is defined.
    inline std::optional<wchar_t> undefined_drive_letter()
    {
        const DWORD defined = ::GetLogicalDrives();
        for (wchar_t letter = L'Z'; letter >= L'D'; --letter)
        {
            if (defined & (1u << (letter - L'A')))
                continue;
            const wchar_t drive[3] = { letter, L':', L'\0' };
            wchar_t target[512];
            if (::QueryDosDeviceW(drive, target, 512) == 0)
                return letter;
        }
        return std::nullopt;
    }

    inline resolver::result image(const std::wstring& name)
    {
        return { name, system_drive_path(L"Apps\\" + name) };
    }

    inline resolver::result service(const std::wstring& name)
    {
        return { name, name }; // service owners carry the service name as their path
    }

    // ------------------------------------------------------------------------------------
    // Fixture
    // ------------------------------------------------------------------------------------

    class fake_os_fixture : public ::testing::Test
    {
    protected:
        void SetUp() override { os().reset(); }
        void TearDown() override { os().reset(); }

        static fake_os& os() { return fake_os::instance(); }

        /// Mark for fake_os::captures_since: captures taken after this call.
        static size_t mark() { return os().captures.size(); }
    };
}
