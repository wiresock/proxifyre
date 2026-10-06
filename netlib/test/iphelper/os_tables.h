#pragma once

// Test-side capture of the Windows TCP/UDP owner tables, used to establish the preconditions of
// the process_lookup characterization tests. This never resolves owners and is independent of
// the production resolver.
//
// A capture records whether the query succeeded separately from the rows it returned, so an API
// failure can never be mistaken for the absence of a row. The table API is injectable (test
// infrastructure only) so failure, empty-table, and buffer-growth outcomes can be exercised
// deterministically.

namespace netlib_test::os_tables
{
    enum class protocol { tcp, udp };

    inline const char* to_string(const protocol p) noexcept { return p == protocol::tcp ? "TCP" : "UDP"; }
    inline const char* family_name(const int family) noexcept { return family == AF_INET ? "AF_INET" : "AF_INET6"; }

    struct table_api
    {
        using tcp_query = DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);
        using udp_query = DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, UDP_TABLE_CLASS, ULONG);

        tcp_query get_tcp = &::GetExtendedTcpTable;
        udp_query get_udp = &::GetExtendedUdpTable;
    };

    // Maximum number of ERROR_INSUFFICIENT_BUFFER retries before the capture is reported failed.
    inline constexpr unsigned max_query_attempts = 8;

    struct row
    {
        std::array<uint8_t, 16> local{};    // AF_INET rows use the first four bytes
        std::array<uint8_t, 16> remote{};   // unused for UDP
        uint16_t local_port{};
        uint16_t remote_port{};             // 0 for UDP
        DWORD pid{};
    };

    struct capture
    {
        protocol proto{};
        int family{};
        bool ok{ false };
        DWORD api_error{ NO_ERROR };        // final API result when !ok
        unsigned attempts{ 0 };
        std::vector<row> rows;

        [[nodiscard]] std::string describe_failure() const
        {
            return std::format("{} {} table query (GetExtended{}Table) failed with error {} after {} attempt(s)",
                to_string(proto), family_name(family), proto == protocol::tcp ? "Tcp" : "Udp", api_error, attempts);
        }
    };

    namespace detail
    {
        template <typename Table, typename Row, typename Convert>
        void read_rows(const std::vector<std::byte>& buffer, std::vector<row>& rows, Convert convert)
        {
            const auto* table = reinterpret_cast<const Table*>(buffer.data());
            for (DWORD i = 0; i < table->dwNumEntries; ++i)
                rows.push_back(convert(table->table[i]));
        }

        inline uint16_t port(const DWORD value) noexcept { return ntohs(static_cast<uint16_t>(value)); }
    }

    inline capture capture_table(const protocol proto, const int family, const table_api& api = {})
    {
        capture result{ proto, family };

        DWORD size = 0;
        if (proto == protocol::tcp)
            size = family == AF_INET ? sizeof(MIB_TCPTABLE_OWNER_PID) : sizeof(MIB_TCP6TABLE_OWNER_PID);
        else
            size = family == AF_INET ? sizeof(MIB_UDPTABLE_OWNER_PID) : sizeof(MIB_UDP6TABLE_OWNER_PID);

        std::vector<std::byte> buffer(size);
        for (;;)
        {
            ++result.attempts;
            const DWORD status = proto == protocol::tcp
                ? api.get_tcp(buffer.data(), &size, FALSE, static_cast<ULONG>(family), TCP_TABLE_OWNER_PID_ALL, 0)
                : api.get_udp(buffer.data(), &size, FALSE, static_cast<ULONG>(family), UDP_TABLE_OWNER_PID, 0);
            if (status == NO_ERROR)
                break;
            if (status != ERROR_INSUFFICIENT_BUFFER || result.attempts >= max_query_attempts)
            {
                result.api_error = status;
                return result;
            }
            buffer.assign(size, std::byte{});
        }

        if (proto == protocol::tcp && family == AF_INET)
        {
            detail::read_rows<MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID>(buffer, result.rows, [](const auto& r) {
                row out;
                std::memcpy(out.local.data(), &r.dwLocalAddr, 4);
                std::memcpy(out.remote.data(), &r.dwRemoteAddr, 4);
                out.local_port = detail::port(r.dwLocalPort);
                out.remote_port = detail::port(r.dwRemotePort);
                out.pid = r.dwOwningPid;
                return out;
            });
        }
        else if (proto == protocol::tcp)
        {
            detail::read_rows<MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID>(buffer, result.rows, [](const auto& r) {
                row out;
                std::memcpy(out.local.data(), r.ucLocalAddr, 16);
                std::memcpy(out.remote.data(), r.ucRemoteAddr, 16);
                out.local_port = detail::port(r.dwLocalPort);
                out.remote_port = detail::port(r.dwRemotePort);
                out.pid = r.dwOwningPid;
                return out;
            });
        }
        else if (family == AF_INET)
        {
            detail::read_rows<MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID>(buffer, result.rows, [](const auto& r) {
                row out;
                std::memcpy(out.local.data(), &r.dwLocalAddr, 4);
                out.local_port = detail::port(r.dwLocalPort);
                out.pid = r.dwOwningPid;
                return out;
            });
        }
        else
        {
            detail::read_rows<MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID>(buffer, result.rows, [](const auto& r) {
                row out;
                std::memcpy(out.local.data(), r.ucLocalAddr, 16);
                out.local_port = detail::port(r.dwLocalPort);
                out.pid = r.dwOwningPid;
                return out;
            });
        }

        result.ok = true;
        return result;
    }

    // Both address-family captures of one protocol.
    struct protocol_view
    {
        capture v4;
        capture v6;

        [[nodiscard]] bool ok() const noexcept { return v4.ok && v6.ok; }

        [[nodiscard]] std::string describe_failures() const
        {
            std::string text;
            for (const auto* c : { &v4, &v6 })
                if (!c->ok)
                    text += (text.empty() ? "" : "; ") + c->describe_failure();
            return text;
        }
    };

    inline protocol_view capture_protocol(const protocol proto, const table_api& api = {})
    {
        return { capture_table(proto, AF_INET, api), capture_table(proto, AF_INET6, api) };
    }

    inline constexpr std::array<uint8_t, 16> v4_mapped(const uint8_t a, const uint8_t b, const uint8_t c, const uint8_t d)
    {
        return { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, a, b, c, d };
    }

    inline constexpr std::array<uint8_t, 16> v4_mapped_loopback = v4_mapped(127, 0, 0, 1);
    inline constexpr std::array<uint8_t, 16> v6_unspecified{};

    inline std::array<uint8_t, 16> v4_bytes(const char* literal)
    {
        std::array<uint8_t, 16> bytes{};
        ::inet_pton(AF_INET, literal, bytes.data());
        return bytes;
    }

    // Row predicates. They must only be evaluated on successful captures.
    inline bool has_tcp_row(const capture& c, const std::array<uint8_t, 16>& address, const size_t address_length,
        const uint16_t local_port, const uint16_t remote_port, const std::optional<DWORD> pid = std::nullopt)
    {
        return std::ranges::any_of(c.rows, [&](const row& r) {
            return r.local_port == local_port && r.remote_port == remote_port &&
                std::memcmp(r.local.data(), address.data(), address_length) == 0 &&
                std::memcmp(r.remote.data(), address.data(), address_length) == 0 &&
                (!pid || r.pid == *pid);
        });
    }

    inline bool has_port_row(const capture& c, const uint16_t port)
    {
        return std::ranges::any_of(c.rows, [&](const row& r) { return r.local_port == port || r.remote_port == port; });
    }

    inline bool has_udp_row(const capture& c, const std::array<uint8_t, 16>& address, const size_t address_length,
        const uint16_t port, const DWORD pid)
    {
        return std::ranges::any_of(c.rows, [&](const row& r) {
            return r.local_port == port && r.pid == pid &&
                std::memcmp(r.local.data(), address.data(), address_length) == 0;
        });
    }

    // Outcome of checking whether a dual-stack socket is visible ONLY through the AF_INET6
    // table, i.e. whether the IPv4 lookup can only have resolved it via the supplementary fold.
    enum class isolation { isolated, not_isolated, query_failed };

    inline const char* to_string(const isolation i) noexcept
    {
        switch (i)
        {
        case isolation::isolated: return "isolated";
        case isolation::not_isolated: return "not_isolated";
        case isolation::query_failed: return "query_failed";
        }
        return "?";
    }

    struct isolation_result
    {
        isolation state{ isolation::query_failed };
        std::string detail;
    };

    inline std::string describe_rows(const protocol_view& view, const uint16_t port)
    {
        std::ostringstream out;
        out << "OS rows for port " << port << ":";
        for (const auto* c : { &view.v4, &view.v6 })
        {
            if (!c->ok)
            {
                out << "\n  " << c->describe_failure();
                continue;
            }
            for (const auto& r : c->rows)
            {
                if (r.local_port != port && r.remote_port != port)
                    continue;
                char local[INET6_ADDRSTRLEN]{}, remote[INET6_ADDRSTRLEN]{};
                ::inet_ntop(c->family, r.local.data(), local, sizeof(local));
                ::inet_ntop(c->family, r.remote.data(), remote, sizeof(remote));
                out << "\n  " << (c->proto == protocol::tcp ? "tcp" : "udp") << (c->family == AF_INET ? "4 " : "6 ")
                    << local << ':' << r.local_port;
                if (c->proto == protocol::tcp)
                    out << " -> " << remote << ':' << r.remote_port;
                out << " pid=" << r.pid;
            }
        }
        return out.str();
    }

    // TCP: both directions of the loopback connection must be listed as IPv4-mapped AF_INET6 rows
    // owned by `pid`, and neither direction may have an AF_INET row.
    inline isolation_result mapped_tcp_isolation(const protocol_view& tcp, const DWORD pid,
        const uint16_t port_a, const uint16_t port_b)
    {
        if (!tcp.ok())
            return { isolation::query_failed, tcp.describe_failures() };

        const bool mapped =
            has_tcp_row(tcp.v6, v4_mapped_loopback, 16, port_a, port_b, pid) &&
            has_tcp_row(tcp.v6, v4_mapped_loopback, 16, port_b, port_a, pid);
        const bool native =
            has_tcp_row(tcp.v4, v4_bytes("127.0.0.1"), 4, port_a, port_b) ||
            has_tcp_row(tcp.v4, v4_bytes("127.0.0.1"), 4, port_b, port_a);
        if (mapped && !native)
            return { isolation::isolated, {} };
        return { isolation::not_isolated, std::format(
            "the OS did not list the dual-stack IPv4 connection exclusively as IPv4-mapped AF_INET6 rows "
            "(mapped rows: {}, native AF_INET rows: {}). {}",
            mapped ? "yes" : "no", native ? "yes" : "no", describe_rows(tcp, port_a)) };
    }

    // UDP: the binding must be listed as an AF_INET6 row with `v6_address` owned by `pid`, and the
    // port must have no AF_INET row at all.
    inline isolation_result mapped_udp_isolation(const protocol_view& udp, const std::array<uint8_t, 16>& v6_address,
        const DWORD pid, const uint16_t port)
    {
        if (!udp.ok())
            return { isolation::query_failed, udp.describe_failures() };

        const bool mapped = has_udp_row(udp.v6, v6_address, 16, port, pid);
        const bool native = has_port_row(udp.v4, port);
        if (mapped && !native)
            return { isolation::isolated, {} };
        char text[INET6_ADDRSTRLEN]{};
        ::inet_ntop(AF_INET6, v6_address.data(), text, sizeof(text));
        return { isolation::not_isolated, std::format(
            "the OS did not list the dual-stack [{}] UDP binding exclusively in the AF_INET6 table "
            "(AF_INET6 row: {}, AF_INET row: {}). {}",
            text, mapped ? "yes" : "no", native ? "yes" : "no", describe_rows(udp, port)) };
    }
}
