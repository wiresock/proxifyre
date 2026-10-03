// Baseline characterization tests for iphelper::process_lookup.
//
// These tests exercise the production lookup code (process_lookup<T>::actualize and the
// lookup_process_for_tcp/udp templates) against real loopback sockets owned by this test
// process, or by a helper child process started from this executable. They do not start the
// packet filter, open the NDIS driver, or change routing.
//
// Dual-stack cases always assert the end-to-end IPv4 lookup result, then inspect the OS tables
// to decide whether the supplementary (IPv4-mapped / unspecified AF_INET6) fold was isolated.
// When the OS lists the socket as a native AF_INET row, the case is reported as UNSUPPORTED
// (see main.cpp) rather than as a verified pass of the supplementary path.

#include "pch.h"
#include "test_support.h"

namespace
{
    using v4 = net::ip_address_v4;
    using v6 = net::ip_address_v6;
    using netlib_test::unique_socket;

    constexpr uint8_t v4_mapped_loopback[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1 };
    constexpr uint8_t v6_unspecified[16] = {};

    v4 v4_loopback() { return v4{ std::string{ "127.0.0.1" } }; }
    v6 v6_loopback() { return v6{ std::string{ "::1" } }; }

    // ------------------------------------------------------------------------------------
    // OS-table precondition probes (test-side only; they do not resolve owners)
    // ------------------------------------------------------------------------------------

    template <typename Table>
    std::unique_ptr<char[]> query_table(const ULONG af, const bool tcp)
    {
        DWORD size = sizeof(Table);
        auto buffer = std::make_unique<char[]>(size);
        for (;;)
        {
            const auto result = tcp
                ? ::GetExtendedTcpTable(buffer.get(), &size, FALSE, af, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
                : ::GetExtendedUdpTable(buffer.get(), &size, FALSE, af, UDP_TABLE_OWNER_PID, 0);
            if (result == NO_ERROR)
                return buffer;
            if (result != ERROR_INSUFFICIENT_BUFFER)
                return nullptr;
            buffer = std::make_unique<char[]>(size);
        }
    }

    // Returns the owning PID of an AF_INET TCP row (local/remote in host-order ports), if present.
    std::optional<DWORD> os_tcp4_row(const uint16_t local_port, const uint16_t remote_port)
    {
        const auto buffer = query_table<MIB_TCPTABLE_OWNER_PID>(AF_INET, true);
        if (!buffer)
            return std::nullopt;
        const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.get());
        for (DWORD i = 0; i < table->dwNumEntries; ++i)
        {
            const auto& row = table->table[i];
            if (ntohs(static_cast<uint16_t>(row.dwLocalPort)) == local_port &&
                ntohs(static_cast<uint16_t>(row.dwRemotePort)) == remote_port)
                return row.dwOwningPid;
        }
        return std::nullopt;
    }

    // Returns the owning PID of an AF_INET6 TCP row whose local and remote addresses equal addr.
    std::optional<DWORD> os_tcp6_row(const uint8_t(&addr)[16], const uint16_t local_port, const uint16_t remote_port)
    {
        const auto buffer = query_table<MIB_TCP6TABLE_OWNER_PID>(AF_INET6, true);
        if (!buffer)
            return std::nullopt;
        const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.get());
        for (DWORD i = 0; i < table->dwNumEntries; ++i)
        {
            const auto& row = table->table[i];
            if (ntohs(static_cast<uint16_t>(row.dwLocalPort)) == local_port &&
                ntohs(static_cast<uint16_t>(row.dwRemotePort)) == remote_port &&
                std::memcmp(row.ucLocalAddr, addr, 16) == 0 &&
                std::memcmp(row.ucRemoteAddr, addr, 16) == 0)
                return row.dwOwningPid;
        }
        return std::nullopt;
    }

    struct udp_row
    {
        std::array<uint8_t, 16> address{};  // IPv4 rows use the first four bytes
        DWORD pid{};
    };

    std::vector<udp_row> os_udp_rows(const ULONG af, const uint16_t port)
    {
        std::vector<udp_row> rows;
        if (af == AF_INET)
        {
            const auto buffer = query_table<MIB_UDPTABLE_OWNER_PID>(AF_INET, false);
            if (!buffer)
                return rows;
            const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.get());
            for (DWORD i = 0; i < table->dwNumEntries; ++i)
            {
                if (ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort)) != port)
                    continue;
                udp_row row;
                std::memcpy(row.address.data(), &table->table[i].dwLocalAddr, 4);
                row.pid = table->table[i].dwOwningPid;
                rows.push_back(row);
            }
        }
        else
        {
            const auto buffer = query_table<MIB_UDP6TABLE_OWNER_PID>(AF_INET6, false);
            if (!buffer)
                return rows;
            const auto* table = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buffer.get());
            for (DWORD i = 0; i < table->dwNumEntries; ++i)
            {
                if (ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort)) != port)
                    continue;
                udp_row row;
                std::memcpy(row.address.data(), table->table[i].ucLocalAddr, 16);
                row.pid = table->table[i].dwOwningPid;
                rows.push_back(row);
            }
        }
        return rows;
    }

    bool has_udp_row(const std::vector<udp_row>& rows, const uint8_t* address, const size_t length, const DWORD pid)
    {
        return std::ranges::any_of(rows, [&](const udp_row& row) {
            return row.pid == pid && std::memcmp(row.address.data(), address, length) == 0;
        });
    }

    std::string format_address(const int family, const void* bytes)
    {
        char text[INET6_ADDRSTRLEN]{};
        ::inet_ntop(family, bytes, text, sizeof(text));
        return text;
    }

    // Describes every TCP and UDP row, in both address families, that uses the given port.
    // Used in assertion messages so a precondition failure shows what the OS actually reported.
    std::string describe_os_rows(const uint16_t port)
    {
        std::ostringstream out;
        out << "OS rows for port " << port << ":";
        if (const auto buffer = query_table<MIB_TCPTABLE_OWNER_PID>(AF_INET, true))
        {
            const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.get());
            for (DWORD i = 0; i < table->dwNumEntries; ++i)
            {
                const auto& row = table->table[i];
                const auto lp = ntohs(static_cast<uint16_t>(row.dwLocalPort));
                const auto rp = ntohs(static_cast<uint16_t>(row.dwRemotePort));
                if (lp == port || rp == port)
                    out << "\n  tcp4 " << format_address(AF_INET, &row.dwLocalAddr) << ':' << lp << " -> "
                        << format_address(AF_INET, &row.dwRemoteAddr) << ':' << rp << " pid=" << row.dwOwningPid;
            }
        }
        if (const auto buffer = query_table<MIB_TCP6TABLE_OWNER_PID>(AF_INET6, true))
        {
            const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.get());
            for (DWORD i = 0; i < table->dwNumEntries; ++i)
            {
                const auto& row = table->table[i];
                const auto lp = ntohs(static_cast<uint16_t>(row.dwLocalPort));
                const auto rp = ntohs(static_cast<uint16_t>(row.dwRemotePort));
                if (lp == port || rp == port)
                    out << "\n  tcp6 [" << format_address(AF_INET6, row.ucLocalAddr) << "]:" << lp << " -> ["
                        << format_address(AF_INET6, row.ucRemoteAddr) << "]:" << rp << " pid=" << row.dwOwningPid;
            }
        }
        for (const auto& row : os_udp_rows(AF_INET, port))
            out << "\n  udp4 " << format_address(AF_INET, row.address.data()) << ':' << port << " pid=" << row.pid;
        for (const auto& row : os_udp_rows(AF_INET6, port))
            out << "\n  udp6 [" << format_address(AF_INET6, row.address.data()) << "]:" << port << " pid=" << row.pid;
        return out.str();
    }

    // ------------------------------------------------------------------------------------
    // Fixture
    // ------------------------------------------------------------------------------------

    class ProcessLookupBaselineTest : public ::testing::Test
    {
    public:
        const DWORD self_pid_{ ::GetCurrentProcessId() };
        const std::wstring self_path_{ netlib_test::upper(netlib_test::module_path_of_current_process()) };
        const std::wstring self_name_{ netlib_test::base_name(self_path_) };

        // Asserts that owner is the fully resolved current process.
        void expect_current_process(const std::shared_ptr<iphelper::network_process>& owner) const
        {
            ASSERT_NE(owner, nullptr);
            EXPECT_EQ(owner->id, self_pid_);
            EXPECT_TRUE(owner->resolved);
            EXPECT_EQ(owner->name, self_name_);
            EXPECT_EQ(owner->path_name, self_path_);
        }

        // A connected loopback TCP pair: client (connect) and server (accept) ends.
        struct tcp_pair
        {
            unique_socket listener;
            unique_socket client;
            unique_socket server;
            uint16_t listen_port{};
            uint16_t client_port{};
        };

        // Creates a TCP pair. listener_family/client_family select AF_INET or AF_INET6;
        // listener_v6_only applies to AF_INET6 listener and client sockets. Returns an error text
        // on failure.
        static std::optional<std::string> make_tcp_pair(tcp_pair& pair,
            const int listener_family, const char* listen_address, const bool listener_v6_only,
            const int client_family, const char* connect_address)
        {
            pair.listener = unique_socket{ ::socket(listener_family, SOCK_STREAM, IPPROTO_TCP) };
            if (!pair.listener.valid())
                return netlib_test::wsa_error_text(::WSAGetLastError());
            if (listener_family == AF_INET6 && !netlib_test::set_v6_only(pair.listener.get(), listener_v6_only))
                return netlib_test::wsa_error_text(::WSAGetLastError());

            int rc;
            if (listener_family == AF_INET)
            {
                const auto sa = netlib_test::make_v4(listen_address, 0);
                rc = ::bind(pair.listener.get(), reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
            }
            else
            {
                const auto sa = netlib_test::make_v6(listen_address, 0);
                rc = ::bind(pair.listener.get(), reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
            }
            if (rc != 0 || ::listen(pair.listener.get(), 1) != 0)
                return netlib_test::wsa_error_text(::WSAGetLastError());
            pair.listen_port = netlib_test::local_port(pair.listener.get());

            pair.client = unique_socket{ ::socket(client_family, SOCK_STREAM, IPPROTO_TCP) };
            if (!pair.client.valid())
                return netlib_test::wsa_error_text(::WSAGetLastError());
            // An AF_INET6 client shares the listener's dual-stack setting.
            if (client_family == AF_INET6 && !netlib_test::set_v6_only(pair.client.get(), listener_v6_only))
                return netlib_test::wsa_error_text(::WSAGetLastError());
            if (client_family == AF_INET)
            {
                const auto sa = netlib_test::make_v4(connect_address, pair.listen_port);
                rc = ::connect(pair.client.get(), reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
            }
            else
            {
                const auto sa = netlib_test::make_v6(connect_address, pair.listen_port);
                rc = ::connect(pair.client.get(), reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
            }
            if (rc != 0)
                return netlib_test::wsa_error_text(::WSAGetLastError());

            pair.server = unique_socket{ ::accept(pair.listener.get(), nullptr, nullptr) };
            if (!pair.server.valid())
                return netlib_test::wsa_error_text(::WSAGetLastError());
            pair.client_port = netlib_test::local_port(pair.client.get());
            return std::nullopt;
        }

        // Binds a UDP socket. Returns an error text on failure.
        static std::optional<std::string> bind_udp(unique_socket& s, const int family, const char* address,
            const bool v6_only = true, const uint16_t port = 0, const bool reuse = false)
        {
            s = unique_socket{ ::socket(family, SOCK_DGRAM, IPPROTO_UDP) };
            if (!s.valid())
                return netlib_test::wsa_error_text(::WSAGetLastError());
            if (family == AF_INET6 && !netlib_test::set_v6_only(s.get(), v6_only))
                return netlib_test::wsa_error_text(::WSAGetLastError());
            if (reuse && !netlib_test::set_reuse_address(s.get()))
                return netlib_test::wsa_error_text(::WSAGetLastError());

            int rc;
            if (family == AF_INET)
            {
                const auto sa = netlib_test::make_v4(address, port);
                rc = ::bind(s.get(), reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
            }
            else
            {
                const auto sa = netlib_test::make_v6(address, port);
                rc = ::bind(s.get(), reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
            }
            if (rc != 0)
                return netlib_test::wsa_error_text(::WSAGetLastError());
            return std::nullopt;
        }

        // Starts a helper child that holds a dual-stack AF_INET6 UDP socket bound (with
        // SO_REUSEADDR) to address:0 and returns its port, or an error text.
        static std::optional<std::string> start_dual_stack_udp_child(netlib_test::child_process& child,
            const char* address, uint16_t& port)
        {
            std::string line, error;
            if (!child.start({ std::string{ netlib_test::child_mode_flag },
                    std::string{ netlib_test::child_udp6_dual_stack_bind }, address, "0" }, line, error))
                return error;
            if (!line.starts_with("READY "))
                return "helper reported: " + line;
            port = static_cast<uint16_t>(std::stoul(line.substr(6)));
            return std::nullopt;
        }
    };

    // ------------------------------------------------------------------------------------
    // Native ownership
    // ------------------------------------------------------------------------------------

    TEST_F(ProcessLookupBaselineTest, TcpV4CurrentProcessOwnership)
    {
        tcp_pair pair;
        if (const auto error = make_tcp_pair(pair, AF_INET, "127.0.0.1", true, AF_INET, "127.0.0.1"))
            FAIL() << "IPv4 loopback TCP setup failed: " << *error;

        iphelper::process_lookup<v4> lookup;
        ASSERT_TRUE(lookup.actualize(true, false));

        // Client end: local = ephemeral port, remote = listener.
        expect_current_process(lookup.lookup_process_for_tcp<false>(
            net::ip_session<v4>(v4_loopback(), v4_loopback(), pair.client_port, pair.listen_port)));
        // Server (accepted) end.
        expect_current_process(lookup.lookup_process_for_tcp<false>(
            net::ip_session<v4>(v4_loopback(), v4_loopback(), pair.listen_port, pair.client_port)));
    }

    TEST_F(ProcessLookupBaselineTest, TcpV6CurrentProcessOwnership)
    {
        tcp_pair pair;
        if (const auto error = make_tcp_pair(pair, AF_INET6, "::1", true, AF_INET6, "::1"))
            NETLIB_TEST_UNSUPPORTED("IPv6 loopback TCP unavailable: " + *error);

        iphelper::process_lookup<v6> lookup;
        ASSERT_TRUE(lookup.actualize(true, false));

        expect_current_process(lookup.lookup_process_for_tcp<false>(
            net::ip_session<v6>(v6_loopback(), v6_loopback(), pair.client_port, pair.listen_port)));
        expect_current_process(lookup.lookup_process_for_tcp<false>(
            net::ip_session<v6>(v6_loopback(), v6_loopback(), pair.listen_port, pair.client_port)));
    }

    TEST_F(ProcessLookupBaselineTest, UnknownTcpSessionIsNotAttributed)
    {
        iphelper::process_lookup<v4> lookup;
        ASSERT_TRUE(lookup.actualize(true, false));

        // Port 0 never appears in a connected TCP row.
        EXPECT_EQ(lookup.lookup_process_for_tcp<false>(
            net::ip_session<v4>(v4_loopback(), v4_loopback(), 0, 0)), nullptr);
    }

    TEST_F(ProcessLookupBaselineTest, UdpV4ExactAndWildcardOwnership)
    {
        unique_socket exact, wildcard;
        if (const auto error = bind_udp(exact, AF_INET, "127.0.0.1"))
            FAIL() << "IPv4 UDP exact bind failed: " << *error;
        if (const auto error = bind_udp(wildcard, AF_INET, "0.0.0.0"))
            FAIL() << "IPv4 UDP wildcard bind failed: " << *error;
        const auto exact_port = netlib_test::local_port(exact.get());
        const auto wildcard_port = netlib_test::local_port(wildcard.get());

        iphelper::process_lookup<v4> lookup;
        ASSERT_TRUE(lookup.actualize(false, true));

        expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_loopback(), exact_port)));

        // A 0.0.0.0 binding owns traffic for any specific local address via the wildcard fallback.
        expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_loopback(), wildcard_port)));
        expect_current_process(lookup.lookup_process_for_udp<false>(
            net::ip_endpoint<v4>(v4{ std::string{ "192.0.2.10" } }, wildcard_port)));

        // An exact binding does not own other local addresses on the same port.
        EXPECT_EQ(lookup.lookup_process_for_udp<false>(
            net::ip_endpoint<v4>(v4{ std::string{ "192.0.2.10" } }, exact_port)), nullptr);
    }

    TEST_F(ProcessLookupBaselineTest, UdpV6ExactAndWildcardOwnership)
    {
        unique_socket exact, wildcard;
        if (const auto error = bind_udp(exact, AF_INET6, "::1"))
            NETLIB_TEST_UNSUPPORTED("IPv6 loopback UDP unavailable: " + *error);
        if (const auto error = bind_udp(wildcard, AF_INET6, "::"))
            NETLIB_TEST_UNSUPPORTED("IPv6 wildcard UDP unavailable: " + *error);
        const auto exact_port = netlib_test::local_port(exact.get());
        const auto wildcard_port = netlib_test::local_port(wildcard.get());

        iphelper::process_lookup<v6> lookup;
        ASSERT_TRUE(lookup.actualize(false, true));

        expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v6>(v6_loopback(), exact_port)));
        expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v6>(v6_loopback(), wildcard_port)));
        expect_current_process(lookup.lookup_process_for_udp<false>(
            net::ip_endpoint<v6>(v6{ std::string{ "2001:db8::10" } }, wildcard_port)));
        EXPECT_EQ(lookup.lookup_process_for_udp<false>(
            net::ip_endpoint<v6>(v6{ std::string{ "2001:db8::10" } }, exact_port)), nullptr);
    }

    // ------------------------------------------------------------------------------------
    // Dual-stack ownership through the IPv4 lookup
    // ------------------------------------------------------------------------------------
    //
    // process_lookup<ip_address_v4> folds IPv4-mapped and unspecified AF_INET6 rows into its
    // IPv4 keys (add_v4_mapped_tcp_sessions / add_v4_mapped_udp_endpoints). Each test below
    // always asserts the end-to-end result -- the IPv4 lookup attributes the dual-stack socket to
    // its owner -- and then inspects the OS tables to determine whether that result could only
    // have come from the supplementary fold. When the OS also (or only) lists the socket as a
    // native AF_INET row, the fold is not isolated, and the test records UNSUPPORTED with the
    // observed rows instead of claiming the supplementary path was verified.

    TEST_F(ProcessLookupBaselineTest, DualStackMappedTcpResolvedThroughV4Lookup)
    {
        // Both ends are dual-stack (IPV6_V6ONLY = 0) AF_INET6 sockets carrying IPv4 traffic. The
        // listener is bound to ::ffff:127.0.0.1 (not [::]) to stay loopback-only.
        tcp_pair pair;
        if (const auto error = make_tcp_pair(pair, AF_INET6, "::ffff:127.0.0.1", false, AF_INET6, "::ffff:127.0.0.1"))
            NETLIB_TEST_UNSUPPORTED("dual-stack TCP over IPv4 unavailable: " + *error);

        iphelper::process_lookup<v4> lookup;
        ASSERT_TRUE(lookup.actualize(true, false));

        expect_current_process(lookup.lookup_process_for_tcp<false>(
            net::ip_session<v4>(v4_loopback(), v4_loopback(), pair.listen_port, pair.client_port)));
        expect_current_process(lookup.lookup_process_for_tcp<false>(
            net::ip_session<v4>(v4_loopback(), v4_loopback(), pair.client_port, pair.listen_port)));

        const bool mapped_rows =
            os_tcp6_row(v4_mapped_loopback, pair.listen_port, pair.client_port) == std::optional<DWORD>{ self_pid_ } &&
            os_tcp6_row(v4_mapped_loopback, pair.client_port, pair.listen_port) == std::optional<DWORD>{ self_pid_ };
        const bool native_rows =
            os_tcp4_row(pair.listen_port, pair.client_port).has_value() ||
            os_tcp4_row(pair.client_port, pair.listen_port).has_value();

        if (!mapped_rows || native_rows)
            NETLIB_TEST_UNSUPPORTED(std::format(
                "the OS did not list this dual-stack IPv4 connection exclusively as IPv4-mapped AF_INET6 rows "
                "(mapped rows: {}, native AF_INET rows: {}); the end-to-end IPv4 lookup was asserted, but the "
                "supplementary mapped-TCP fold was not isolated. {}",
                mapped_rows ? "yes" : "no", native_rows ? "yes" : "no", describe_os_rows(pair.listen_port)));
    }

    TEST_F(ProcessLookupBaselineTest, UnspecifiedV6UdpResolvedThroughV4Wildcard)
    {
        unique_socket s;
        if (const auto error = bind_udp(s, AF_INET6, "::", false))
            NETLIB_TEST_UNSUPPORTED("dual-stack IPv6 UDP wildcard unavailable: " + *error);
        const auto port = netlib_test::local_port(s.get());

        iphelper::process_lookup<v4> lookup;
        ASSERT_TRUE(lookup.actualize(false, true));

        // A dual-stack [::] binding owns IPv4 traffic for any local address via the 0.0.0.0 key.
        expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_loopback(), port)));
        expect_current_process(lookup.lookup_process_for_udp<false>(
            net::ip_endpoint<v4>(v4{ std::string{ "192.0.2.10" } }, port)));

        ASSERT_TRUE(has_udp_row(os_udp_rows(AF_INET6, port), v6_unspecified, 16, self_pid_)) << describe_os_rows(port);
        if (!os_udp_rows(AF_INET, port).empty())
            NETLIB_TEST_UNSUPPORTED(std::format(
                "the OS lists the dual-stack [::] binding in both the AF_INET6 and AF_INET tables; the IPv4 "
                "wildcard lookup was asserted, but the unspecified-IPv6 fold was not isolated from the native "
                "0.0.0.0 row. {}", describe_os_rows(port)));
    }

    TEST_F(ProcessLookupBaselineTest, MappedV6UdpExactResolvedThroughV4Lookup)
    {
        unique_socket s;
        if (const auto error = bind_udp(s, AF_INET6, "::ffff:127.0.0.1", false))
            NETLIB_TEST_UNSUPPORTED("dual-stack IPv4-mapped UDP bind unavailable: " + *error);
        const auto port = netlib_test::local_port(s.get());

        iphelper::process_lookup<v4> lookup;
        ASSERT_TRUE(lookup.actualize(false, true));

        expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_loopback(), port)));
        // A mapped exact binding is not a wildcard.
        EXPECT_EQ(lookup.lookup_process_for_udp<false>(
            net::ip_endpoint<v4>(v4{ std::string{ "192.0.2.10" } }, port)), nullptr);

        const bool mapped_row = has_udp_row(os_udp_rows(AF_INET6, port), v4_mapped_loopback, 16, self_pid_);
        const bool native_row = !os_udp_rows(AF_INET, port).empty();
        if (!mapped_row || native_row)
            NETLIB_TEST_UNSUPPORTED(std::format(
                "the OS did not list the ::ffff:127.0.0.1 binding exclusively as an IPv4-mapped AF_INET6 row "
                "(mapped row: {}, native AF_INET row: {}); the IPv4 lookup was asserted, but the mapped-UDP "
                "fold was not isolated. {}",
                mapped_row ? "yes" : "no", native_row ? "yes" : "no", describe_os_rows(port)));
    }

    // ------------------------------------------------------------------------------------
    // Native IPv4 precedence over supplementary mapped rows
    // ------------------------------------------------------------------------------------
    //
    // A helper child (a different PID) holds the dual-stack AF_INET6 binding; this process then
    // binds the same IPv4 endpoint natively. The IPv4 lookup must first attribute the endpoint to
    // the child through the supplementary row alone, then to this process once a native AF_INET
    // row exists. This is only meaningful when the OS lists the child's binding exclusively in the
    // AF_INET6 table; otherwise the case is UNSUPPORTED on the host.
    //
    // Genuine native-IPv4 precedence over a mapped TCP row cannot be produced with real sockets:
    // one TCP 4-tuple cannot be held by both a native and a dual-stack socket. TCP precedence
    // therefore needs the deterministic fixtures planned for Task 2.

    void native_v4_udp_precedence_case(ProcessLookupBaselineTest& test, const char* v6_address,
        const char* v4_address, const uint8_t(&mapped_bytes)[16])
    {
        const DWORD self_pid = ::GetCurrentProcessId();

        netlib_test::child_process child;
        uint16_t port = 0;
        if (const auto error = ProcessLookupBaselineTest::start_dual_stack_udp_child(child, v6_address, port))
            NETLIB_TEST_UNSUPPORTED("helper could not bind dual-stack UDP: " + *error);
        ASSERT_NE(child.pid(), self_pid);

        const bool mapped_row = has_udp_row(os_udp_rows(AF_INET6, port), mapped_bytes, 16, child.pid());
        const bool native_row = !os_udp_rows(AF_INET, port).empty();
        if (!mapped_row || native_row)
            NETLIB_TEST_UNSUPPORTED(std::format(
                "the OS did not list the helper's dual-stack [{}] binding exclusively in the AF_INET6 table "
                "(AF_INET6 row: {}, AF_INET row: {}), so precedence of a native AF_INET row over the "
                "supplementary row cannot be isolated with real sockets. {}",
                v6_address, mapped_row ? "yes" : "no", native_row ? "yes" : "no", describe_os_rows(port)));

        iphelper::process_lookup<v4> lookup;
        ASSERT_TRUE(lookup.actualize(false, true));

        // Only the supplementary row exists: the endpoint belongs to the child.
        const auto owner = lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_loopback(), port));
        ASSERT_NE(owner, nullptr);
        EXPECT_EQ(owner->id, child.pid());

        unique_socket native;
        if (const auto error = ProcessLookupBaselineTest::bind_udp(native, AF_INET, v4_address, true, port, true))
            NETLIB_TEST_UNSUPPORTED("OS refused a native IPv4 bind sharing the dual-stack port: " + *error);

        uint8_t native_bytes[4]{};
        ::inet_pton(AF_INET, v4_address, native_bytes);
        ASSERT_TRUE(has_udp_row(os_udp_rows(AF_INET, port), native_bytes, 4, self_pid)) << describe_os_rows(port);
        ASSERT_TRUE(has_udp_row(os_udp_rows(AF_INET6, port), mapped_bytes, 16, child.pid())) << describe_os_rows(port);

        ASSERT_TRUE(lookup.actualize(false, true));
        test.expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_loopback(), port)));
    }

    TEST_F(ProcessLookupBaselineTest, NativeV4UdpExactTakesPrecedenceOverMappedRow)
    {
        native_v4_udp_precedence_case(*this, "::ffff:127.0.0.1", "127.0.0.1", v4_mapped_loopback);
    }

    TEST_F(ProcessLookupBaselineTest, NativeV4UdpWildcardTakesPrecedenceOverUnspecifiedV6Row)
    {
        native_v4_udp_precedence_case(*this, "::", "0.0.0.0", v6_unspecified);
    }
}
