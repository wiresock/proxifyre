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
//   * device-path conversion (QueryDosDeviceW in production) maps "X:\..." deterministically to
//     "\Device\FakeVolumeX\..." and can be told to fail the next conversions, so no test depends
//     on which drive letters exist on the host; the production completeness rule
//     (owner_identity::has_complete_device_path) still decides what is memoizable;
//   * the per-capture owner memo allocates through an allocator that counts its allocations
//     per capture and can be armed to throw std::bad_alloc while a chosen capture is ingested:
//     at every allocation, or only at a chosen ordinal.
//
// Every owner lookup, image (fallback) lookup, and memo allocation is attributed to the capture
// being ingested: process_lookup enriches a capture's rows after querying it and before the
// next query.
//
// The publication tests also use iphelper::process_lookup_test_access (defined here) to reach
// a published table's reader lock and to replace a published row's owner with an observable one.

#include "../../src/iphelper/owner_memo.h"

namespace iphelper
{
    /// Test-only access to process_lookup's published tables (declared in process_lookup.h).
    struct process_lookup_test_access
    {
        template <class T, class Source>
        static std::shared_mutex& tcp_table_mutex(process_lookup<T, Source>& lookup) noexcept
        {
            return lookup.tcp_to_app_mutex_;
        }

        template <class T, class Source>
        static std::shared_mutex& udp_table_mutex(process_lookup<T, Source>& lookup) noexcept
        {
            return lookup.udp_to_app_mutex_;
        }

        /// Makes @p owner the published owner of @p session, under the table's writer lock; false
        /// when @p session is not published. The replaced owner is released after the lock.
        template <class T, class Source>
        static bool replace_tcp_owner(process_lookup<T, Source>& lookup, const net::ip_session<T>& session,
            std::shared_ptr<network_process> owner)
        {
            std::unique_lock lock(lookup.tcp_to_app_mutex_);
            const auto it = lookup.tcp_to_app_.find(session);
            if (it == lookup.tcp_to_app_.end())
                return false;
            it->second.swap(owner);
            return true;
        }

        /// See replace_tcp_owner.
        template <class T, class Source>
        static bool replace_udp_owner(process_lookup<T, Source>& lookup, const net::ip_endpoint<T>& endpoint,
            std::shared_ptr<network_process> owner)
        {
            std::unique_lock lock(lookup.udp_to_app_mutex_);
            const auto it = lookup.udp_to_app_.find(endpoint);
            if (it == lookup.udp_to_app_.end())
                return false;
            it->second.swap(owner);
            return true;
        }
    };
}

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
        int device_path_conversions{}; ///< convert_to_device_path calls for drive paths (one per enrichment of a drive path)
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

    /// Device prefix of the fake conversion: "X:\dir\app.exe" -> "\Device\FakeVolumeX\dir\app.exe".
    inline constexpr const wchar_t* fake_device_prefix = L"\\Device\\FakeVolume";

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

        /// Runs at each owner lookup (resolve_from_pid_and_tag_extended) before it is answered:
        /// lets a test pause a table build while one of its rows is being enriched.
        std::function<void(DWORD pid, DWORD tag)> on_owner_lookup;

        /// The next N device-path conversions of a drive path fail (return an empty device path).
        int fail_device_path_conversions{ 0 };

        /// Memo allocations during the ingestion of a capture of this kind throw std::bad_alloc:
        /// every one of them, or only the fail_memo_allocation_ordinal-th (1-based) one.
        std::optional<table_kind> fail_memo_allocations_in;
        int fail_memo_allocation_ordinal{ 0 };

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
            if (on_owner_lookup)
                on_owner_lookup(pid, tag);

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

        /// The deterministic stand-in for QueryDosDeviceW (see the file comment).
        std::wstring convert_device_path(const std::wstring& path)
        {
            if (path.size() < 2 || path[1] != L':')
                return L""; // not a drive path: the production conversion has nothing to convert either
            count(&capture_record::device_path_conversions);
            if (fail_device_path_conversions > 0)
            {
                --fail_device_path_conversions;
                return L"";
            }
            return std::wstring{ fake_device_prefix } + path[0] + path.substr(2);
        }

        void memo_allocation()
        {
            if (captures.empty())
            {
                ADD_FAILURE() << "owner memo allocated outside a capture";
                return;
            }
            const int ordinal = ++captures.back().memo_allocations;
            if (fail_memo_allocations_in == captures.back().kind &&
                (fail_memo_allocation_ordinal == 0 || fail_memo_allocation_ordinal == ordinal))
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

        static std::wstring convert_to_device_path(const std::wstring& path)
        {
            return fake_os::instance().convert_device_path(path);
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

    /// The drive path of a process image; the fake conversion makes its owner complete.
    inline std::wstring image_path(const std::wstring& name)
    {
        return L"C:\\Apps\\" + name;
    }

    /// What owner_identity records as the device path of @p dos_path under the fake conversion.
    inline std::wstring fake_device_path(const std::wstring& dos_path)
    {
        return iphelper::owner_identity::to_upper(
            std::wstring{ fake_device_prefix } + dos_path[0] + dos_path.substr(2));
    }

    inline resolver::result image(const std::wstring& name)
    {
        return { name, image_path(name) };
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

    // ------------------------------------------------------------------------------------
    // Ingestion loops
    // ------------------------------------------------------------------------------------

    /// One of process_lookup's six ingestion loops: the TCP and UDP primary loops of the IPv4
    /// and IPv6 instances, and the IPv4 instance's two supplementary AF_INET6 folds (IPv4-mapped
    /// TCP; IPv4-mapped and unspecified UDP). Each captured table is enriched with its own memo.
    enum class loop : uint8_t { tcp_v4, tcp_v6, udp_v4, udp_v6, tcp_v4_mapped, udp_v4_mapped };

    inline constexpr loop all_loops[] = {
        loop::tcp_v4, loop::tcp_v6, loop::udp_v4, loop::udp_v6, loop::tcp_v4_mapped, loop::udp_v4_mapped };

    inline const char* loop_label(const loop l)
    {
        switch (l)
        {
        case loop::tcp_v4: return "TcpV4Primary";
        case loop::tcp_v6: return "TcpV6Primary";
        case loop::udp_v4: return "UdpV4Primary";
        case loop::udp_v6: return "UdpV6Primary";
        case loop::tcp_v4_mapped: return "TcpV4MappedSupplement";
        case loop::udp_v4_mapped: return "UdpV4MappedSupplement";
        }
        return "Unknown";
    }

    inline std::string loop_name(const ::testing::TestParamInfo<loop>& info) { return loop_label(info.param); }

    /// One ingestion loop: where its rows live, which capture and lookup instance serve them, and
    /// which packet handler (transport and address family) routes its owners.
    class loop_harness
    {
    public:
        explicit loop_harness(const loop l) : loop_(l) {}

        [[nodiscard]] loop which() const { return loop_; }

        [[nodiscard]] table_kind capture() const
        {
            switch (loop_)
            {
            case loop::tcp_v4: return table_kind::tcp_v4;
            case loop::udp_v4: return table_kind::udp_v4;
            case loop::tcp_v6:
            case loop::tcp_v4_mapped: return table_kind::tcp_v6;
            case loop::udp_v6:
            case loop::udp_v4_mapped: return table_kind::udp_v6;
            }
            return table_kind::tcp_v4;
        }

        /// The primary capture of the lookup instance that serves this loop (the loop's own
        /// capture for a primary loop).
        [[nodiscard]] table_kind primary_capture() const
        {
            if (loop_ == loop::tcp_v4_mapped)
                return table_kind::tcp_v4;
            if (loop_ == loop::udp_v4_mapped)
                return table_kind::udp_v4;
            return capture();
        }

        [[nodiscard]] bool supplement() const
        {
            return loop_ == loop::tcp_v4_mapped || loop_ == loop::udp_v4_mapped;
        }

        [[nodiscard]] bool tcp() const
        {
            return loop_ == loop::tcp_v4 || loop_ == loop::tcp_v6 || loop_ == loop::tcp_v4_mapped;
        }

        [[nodiscard]] bool served_by_v4() const
        {
            return loop_ != loop::tcp_v6 && loop_ != loop::udp_v6;
        }

        [[nodiscard]] proxy::owner_transport transport() const
        {
            return tcp() ? proxy::owner_transport::tcp : proxy::owner_transport::udp;
        }

        [[nodiscard]] proxy::owner_family family() const
        {
            return served_by_v4() ? proxy::owner_family::ipv4 : proxy::owner_family::ipv6;
        }

        /// Adds the loop's row number @p i (a distinct tuple) owned by (@p pid, @p tag).
        void add_row(const DWORD pid, const DWORD tag, const uint16_t i) const
        {
            auto& os = fake_os::instance();
            const auto port = static_cast<uint16_t>(10000 + i);
            switch (loop_)
            {
            case loop::tcp_v4: os.tcp4.push_back(tcp4_row(pid, tag, "10.0.0.1", port, "10.9.9.9", 443)); break;
            case loop::tcp_v6: os.tcp6.push_back(tcp6_row(pid, tag, "2001:db8::1", port, "2001:db8::9", 443)); break;
            case loop::udp_v4: os.udp4.push_back(udp4_row(pid, tag, "10.0.0.1", port)); break;
            case loop::udp_v6: os.udp6.push_back(udp6_row(pid, tag, "2001:db8::1", port)); break;
            case loop::tcp_v4_mapped:
                os.tcp6.push_back(tcp6_row(pid, tag, "::ffff:10.0.0.1", port, "::ffff:10.9.9.9", 443));
                break;
            case loop::udp_v4_mapped: os.udp6.push_back(udp6_row(pid, tag, "::ffff:10.0.0.1", port)); break;
            }
        }

        /// For a supplementary loop: adds row @p i of the same transport to the IPv4 instance's
        /// primary (AF_INET) capture, on local address 10.0.0.2 so it never collides with the
        /// loop's own rows. For a primary loop this is add_row.
        void add_primary_row(const DWORD pid, const DWORD tag, const uint16_t i) const
        {
            if (!supplement())
            {
                add_row(pid, tag, i);
                return;
            }
            auto& os = fake_os::instance();
            const auto port = static_cast<uint16_t>(10000 + i);
            if (tcp())
                os.tcp4.push_back(tcp4_row(pid, tag, "10.0.0.2", port, "10.9.9.9", 443));
            else
                os.udp4.push_back(udp4_row(pid, tag, "10.0.0.2", port));
        }

        void clear_rows() const
        {
            auto& os = fake_os::instance();
            os.tcp4.clear();
            os.tcp6.clear();
            os.udp4.clear();
            os.udp6.clear();
        }

        /// Rebuilds the tables that contain this loop (one or two captures).
        bool refresh()
        {
            return served_by_v4() ? v4_.actualize(tcp(), !tcp()) : v6_.actualize(tcp(), !tcp());
        }

        /// The published owner of row @p i, through the production lookup.
        process_ptr owner(const uint16_t i)
        {
            const auto port = static_cast<uint16_t>(10000 + i);
            switch (loop_)
            {
            case loop::tcp_v4:
            case loop::tcp_v4_mapped:
                return v4_.lookup_process_for_tcp<false>(session4("10.0.0.1", port, "10.9.9.9", 443));
            case loop::tcp_v6:
                return v6_.lookup_process_for_tcp<false>(session6("2001:db8::1", port, "2001:db8::9", 443));
            case loop::udp_v4:
            case loop::udp_v4_mapped:
                return v4_.lookup_process_for_udp<false>(endpoint4("10.0.0.1", port));
            case loop::udp_v6:
                return v6_.lookup_process_for_udp<false>(endpoint6("2001:db8::1", port));
            }
            return nullptr;
        }

        /// The published owner of primary row @p i (see add_primary_row).
        process_ptr primary_owner(const uint16_t i)
        {
            if (!supplement())
                return owner(i);
            const auto port = static_cast<uint16_t>(10000 + i);
            return tcp()
                ? v4_.lookup_process_for_tcp<false>(session4("10.0.0.2", port, "10.9.9.9", 443))
                : v4_.lookup_process_for_udp<false>(endpoint4("10.0.0.2", port));
        }

        /// Makes @p replacement the published owner of row @p i (process_lookup_test_access), so a
        /// test can observe when the published tables release it; false if row @p i is not published.
        bool replace_owner(const uint16_t i, process_ptr replacement)
        {
            using access = iphelper::process_lookup_test_access;
            const auto port = static_cast<uint16_t>(10000 + i);
            switch (loop_)
            {
            case loop::tcp_v4:
            case loop::tcp_v4_mapped:
                return access::replace_tcp_owner(v4_, session4("10.0.0.1", port, "10.9.9.9", 443), std::move(replacement));
            case loop::tcp_v6:
                return access::replace_tcp_owner(v6_, session6("2001:db8::1", port, "2001:db8::9", 443), std::move(replacement));
            case loop::udp_v4:
            case loop::udp_v4_mapped:
                return access::replace_udp_owner(v4_, endpoint4("10.0.0.1", port), std::move(replacement));
            case loop::udp_v6:
                return access::replace_udp_owner(v6_, endpoint6("2001:db8::1", port), std::move(replacement));
            }
            return false;
        }

        /// The reader lock of the published table that serves this loop's rows.
        std::shared_mutex& table_mutex()
        {
            using access = iphelper::process_lookup_test_access;
            if (served_by_v4())
                return tcp() ? access::tcp_table_mutex(v4_) : access::udp_table_mutex(v4_);
            return tcp() ? access::tcp_table_mutex(v6_) : access::udp_table_mutex(v6_);
        }

    private:
        loop loop_;
        // Constructed empty (each constructor builds its tables once).
        lookup_v4 v4_;
        lookup_v6 v6_;
    };

    /// A parameterized fixture over the six ingestion loops: a reset fake_os and a loop_harness.
    class loop_fixture : public fake_os_fixture, public ::testing::WithParamInterface<loop>
    {
    protected:
        void SetUp() override
        {
            fake_os_fixture::SetUp();
            harness_.emplace(GetParam());
        }

        void TearDown() override
        {
            harness_.reset();
            fake_os_fixture::TearDown();
        }

        loop_harness& h() { return *harness_; }
        const loop_harness& h() const { return *harness_; }

    private:
        std::optional<loop_harness> harness_;
    };

    /// Two rows of one identity in one capture: each row has its own owner object, built from
    /// the one enrichment the capture made for the identity.
    inline void expect_same_identity(const process_ptr& a, const process_ptr& b)
    {
        ASSERT_TRUE(a && b);
        EXPECT_NE(a, b) << "each row has its own owner object";
        EXPECT_EQ(a->id, b->id);
        EXPECT_EQ(a->name, b->name);
        EXPECT_EQ(a->path_name, b->path_name);
        EXPECT_EQ(a->device_path_name, b->device_path_name);
        EXPECT_EQ(a->resolved, b->resolved);
    }
}
