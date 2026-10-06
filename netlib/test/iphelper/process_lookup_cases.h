#pragma once

// Shared fixture and dual-stack case bodies for the process_lookup characterization tests.
//
// The case bodies are free functions taking case_options so the same decision paths run both
// in the real baseline tests (default options: real table queries, real helper) and in the
// failure probes (process_lookup_failure_test.cpp), which inject helper or table-query faults.
//
// Outcome rules for every dual-stack case:
//   * the folding cases assert the end-to-end IPv4 lookup result before evaluating isolation;
//     the precedence cases evaluate isolation first and run no lookup assertion unless the
//     helper's row is isolated. An UNSUPPORTED reason states exactly which stage was reached;
//   * an OS table query failure is a test FAILURE (never UNSUPPORTED, never "absent");
//   * a helper launch/protocol/timeout/socket failure is a test FAILURE;
//   * UNSUPPORTED is recorded only when successful captures of both address-family tables show
//     the supplementary path cannot be isolated, or for a recognized environment limitation
//     (netlib_test::environment_limitation, or the host refusing a shared UDP port).

#include "os_tables.h"

namespace netlib_test::process_lookup_cases
{
    using v4 = net::ip_address_v4;
    using v6 = net::ip_address_v6;
    namespace tables = netlib_test::os_tables;

    inline v4 v4_loopback() { return v4{ std::string{ "127.0.0.1" } }; }
    inline v6 v6_loopback() { return v6{ std::string{ "::1" } }; }
    inline v4 v4_other() { return v4{ std::string{ "192.0.2.10" } }; }   // TEST-NET-1, never local
    inline v6 v6_other() { return v6{ std::string{ "2001:db8::10" } }; } // documentation prefix

    struct case_options
    {
        tables::table_api tables;
        helper_options helper;
    };

    class process_lookup_fixture : public ::testing::Test
    {
    public:
        process_lookup_fixture() = default;
        // Test-infrastructure override of the expected owner PID (failure probes only): runs a
        // case against an owner it cannot match, so its ownership assertions fail.
        explicit process_lookup_fixture(const DWORD expected_pid) : self_pid_(expected_pid) {}

        const DWORD self_pid_{ ::GetCurrentProcessId() };
        const std::wstring self_path_{ upper(module_path_of_current_process()) };
        const std::wstring self_name_{ base_name(self_path_) };

        // Asserts that owner is the fully resolved current process.
        void expect_current_process(const std::shared_ptr<iphelper::network_process>& owner) const
        {
            ASSERT_NE(owner, nullptr);
            EXPECT_EQ(owner->id, self_pid_);
            EXPECT_TRUE(owner->resolved);
            EXPECT_EQ(owner->name, self_name_);
            EXPECT_EQ(owner->path_name, self_path_);
        }
    };

    // A connected loopback TCP pair: client (connect) and server (accept) ends.
    struct tcp_pair
    {
        unique_socket listener;
        unique_socket client;
        unique_socket server;
        uint16_t listen_port{};
        uint16_t client_port{};
    };

    // Creates a TCP pair. v6_only applies to every AF_INET6 socket of the pair.
    inline std::optional<socket_failure> make_tcp_pair(tcp_pair& pair,
        const int listener_family, const char* listen_address, const bool v6_only,
        const int client_family, const char* connect_address)
    {
        if (auto f = create_socket(pair.listener, listener_family, SOCK_STREAM, IPPROTO_TCP)) return f;
        if (listener_family == AF_INET6)
            if (auto f = set_v6_only(pair.listener.get(), v6_only)) return f;
        if (auto f = bind_socket(pair.listener.get(), listener_family, listen_address, 0)) return f;
        if (::listen(pair.listener.get(), 1) != 0)
            return socket_failure{ socket_op::listen, listener_family, listen_address, ::WSAGetLastError() };
        if (auto f = local_port(pair.listener.get(), listener_family, pair.listen_port)) return f;

        if (auto f = create_socket(pair.client, client_family, SOCK_STREAM, IPPROTO_TCP)) return f;
        if (client_family == AF_INET6)
            if (auto f = set_v6_only(pair.client.get(), v6_only)) return f;
        if (auto f = connect_socket(pair.client.get(), client_family, connect_address, pair.listen_port)) return f;

        pair.server = unique_socket{ ::accept(pair.listener.get(), nullptr, nullptr) };
        if (!pair.server.valid())
            return socket_failure{ socket_op::accept, listener_family, {}, ::WSAGetLastError() };
        return local_port(pair.client.get(), client_family, pair.client_port);
    }

    // Stage descriptions for a not-isolated outcome. Each states exactly what had and had not
    // been asserted when the isolation precondition stopped the case, so the UNSUPPORTED reason
    // (console line and XML property alike) never overstates the executed coverage.
    //
    // Folding cases: the end-to-end ownership check of this process's own dual-stack socket has
    // run by the time isolation is evaluated, but its assertions may have failed (they are
    // recorded and reported separately), so the wording states that it ran, not that it passed.
    inline constexpr const char* folding_not_isolated_stage =
        "the end-to-end IPv4 ownership check of the dual-stack socket owned by this process ran "
        "and its assertion results are reported separately; the supplementary fold was not "
        "isolated, so this case does not establish mapped-fold coverage";
    // Precedence cases: isolation is checked before any lookup, so nothing was asserted.
    inline constexpr const char* precedence_not_isolated_stage =
        "the dual-stack binding held by the helper was not isolated in the OS tables, so no "
        "ownership or precedence assertion was run";

    // Leaves the calling test function according to an isolation decision. Returns normally
    // only for `isolated`. `stage` is one of the descriptions above.
#define NETLIB_TEST_REQUIRE_ISOLATION(result_expr, stage)                                           \
    do {                                                                                            \
        const auto netlib_isolation_ = (result_expr);                                               \
        if (netlib_isolation_.state == ::netlib_test::os_tables::isolation::query_failed)           \
            FAIL() << "OS table capture failed; isolation was not evaluated: " << netlib_isolation_.detail; \
        if (netlib_isolation_.state == ::netlib_test::os_tables::isolation::not_isolated)           \
            NETLIB_TEST_UNSUPPORTED(std::string{ stage } + ": " + netlib_isolation_.detail);        \
    } while (false)

    // ------------------------------------------------------------------------------------
    // Dual-stack ownership through the IPv4 lookup
    // ------------------------------------------------------------------------------------

    inline void dual_stack_mapped_tcp_case(const process_lookup_fixture& test, const case_options& options)
    {
        // Both ends are dual-stack (IPV6_V6ONLY = 0) AF_INET6 sockets carrying IPv4 traffic. The
        // listener is bound to ::ffff:127.0.0.1 (not [::]) to stay loopback-only.
        tcp_pair pair;
        NETLIB_TEST_REQUIRE_SOCKETS(make_tcp_pair(pair, AF_INET6, "::ffff:127.0.0.1", false, AF_INET6, "::ffff:127.0.0.1"));

        iphelper::process_lookup<v4> lookup;
        ASSERT_TRUE(lookup.actualize(true, false));

        test.expect_current_process(lookup.lookup_process_for_tcp<false>(
            net::ip_session<v4>(v4_loopback(), v4_loopback(), pair.listen_port, pair.client_port)));
        test.expect_current_process(lookup.lookup_process_for_tcp<false>(
            net::ip_session<v4>(v4_loopback(), v4_loopback(), pair.client_port, pair.listen_port)));

        NETLIB_TEST_REQUIRE_ISOLATION(tables::mapped_tcp_isolation(
            tables::capture_protocol(tables::protocol::tcp, options.tables),
            test.self_pid_, pair.listen_port, pair.client_port), folding_not_isolated_stage);
    }

    inline void unspecified_v6_udp_case(const process_lookup_fixture& test, const case_options& options)
    {
        unique_socket s;
        uint16_t port = 0;
        NETLIB_TEST_REQUIRE_SOCKETS(bind_udp(s, AF_INET6, "::", false, 0, false, port));

        iphelper::process_lookup<v4> lookup;
        ASSERT_TRUE(lookup.actualize(false, true));

        // A dual-stack [::] binding owns IPv4 traffic for any local address via the 0.0.0.0 key.
        test.expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_loopback(), port)));
        test.expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_other(), port)));

        NETLIB_TEST_REQUIRE_ISOLATION(tables::mapped_udp_isolation(
            tables::capture_protocol(tables::protocol::udp, options.tables),
            tables::v6_unspecified, test.self_pid_, port), folding_not_isolated_stage);
    }

    inline void mapped_v6_udp_exact_case(const process_lookup_fixture& test, const case_options& options)
    {
        unique_socket s;
        uint16_t port = 0;
        NETLIB_TEST_REQUIRE_SOCKETS(bind_udp(s, AF_INET6, "::ffff:127.0.0.1", false, 0, false, port));

        iphelper::process_lookup<v4> lookup;
        ASSERT_TRUE(lookup.actualize(false, true));

        test.expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_loopback(), port)));
        // A mapped exact binding is not a wildcard.
        EXPECT_EQ(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_other(), port)), nullptr);

        NETLIB_TEST_REQUIRE_ISOLATION(tables::mapped_udp_isolation(
            tables::capture_protocol(tables::protocol::udp, options.tables),
            tables::v4_mapped_loopback, test.self_pid_, port), folding_not_isolated_stage);
    }

    // ------------------------------------------------------------------------------------
    // Native IPv4 precedence over supplementary rows (UDP)
    // ------------------------------------------------------------------------------------
    //
    // A helper child (a different PID) holds the dual-stack AF_INET6 binding; this process then
    // binds the same IPv4 endpoint natively. The IPv4 lookup must first attribute the endpoint to
    // the child through the supplementary row alone, then to this process once a native AF_INET
    // row exists. Requires the helper's binding to be listed exclusively in the AF_INET6 table.
    //
    // Native precedence over a mapped TCP row cannot be produced with real sockets: one TCP
    // 4-tuple cannot be held by a native and a dual-stack socket at once. It is a Task 2
    // deterministic-fixture obligation, together with mapped TCP/UDP and unspecified UDP folding,
    // distinct-owner precedence, separate-capture PID reuse, partial-enrichment recovery, and
    // routing-policy isolation.

    inline void native_v4_udp_precedence_case(const process_lookup_fixture& test, const char* v6_address,
        const char* v4_address, const std::array<uint8_t, 16>& helper_row_address, const case_options& options)
    {
        helper_child child;
        const auto started = child.start(options.helper, v6_address);
        if (started.outcome == helper_outcome::environment_limitation)
            NETLIB_TEST_UNSUPPORTED(started.diagnostic);
        if (started.outcome != helper_outcome::ready)
            FAIL() << "helper start failed: " << started.diagnostic;
        const uint16_t port = started.port;
        ASSERT_NE(child.pid(), test.self_pid_);

        // Checked before any lookup: a not-isolated row means this case asserted nothing.
        NETLIB_TEST_REQUIRE_ISOLATION(tables::mapped_udp_isolation(
            tables::capture_protocol(tables::protocol::udp, options.tables),
            helper_row_address, child.pid(), port), precedence_not_isolated_stage);

        iphelper::process_lookup<v4> lookup;
        ASSERT_TRUE(lookup.actualize(false, true));

        // Only the supplementary row exists: the endpoint belongs to the child.
        const auto owner = lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_loopback(), port));
        ASSERT_NE(owner, nullptr);
        EXPECT_EQ(owner->id, child.pid());

        unique_socket native;
        uint16_t native_port = 0;
        if (const auto f = bind_udp(native, AF_INET, v4_address, true, port, true, native_port))
        {
            // Windows may refuse to share the port with the helper's dual-stack socket.
            if (f->op == socket_op::bind && (f->code == WSAEADDRINUSE || f->code == WSAEACCES))
                NETLIB_TEST_UNSUPPORTED("the host refused a native IPv4 bind sharing the helper's "
                    "dual-stack UDP port: " + describe(*f));
            FAIL() << "native IPv4 bind failed: " << describe(*f);
        }

        const auto udp = tables::capture_protocol(tables::protocol::udp, options.tables);
        ASSERT_TRUE(udp.ok()) << udp.describe_failures();
        ASSERT_TRUE(tables::has_udp_row(udp.v4, tables::v4_bytes(v4_address), 4, port, test.self_pid_))
            << tables::describe_rows(udp, port);
        ASSERT_TRUE(tables::has_udp_row(udp.v6, helper_row_address, 16, port, child.pid()))
            << tables::describe_rows(udp, port);

        ASSERT_TRUE(lookup.actualize(false, true));
        test.expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_loopback(), port)));
    }
}
