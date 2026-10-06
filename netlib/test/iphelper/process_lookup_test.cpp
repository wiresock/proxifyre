// Baseline characterization tests for iphelper::process_lookup.
//
// These tests exercise the production lookup code (process_lookup<T>::actualize and the
// lookup_process_for_tcp/udp templates) against real loopback sockets owned by this test
// process, or by a helper child process started from this executable. They do not start the
// packet filter, open the NDIS driver, or change routing.
//
// Dual-stack cases (process_lookup_cases.h) always assert the end-to-end IPv4 lookup result,
// then use successful captures of both OS address-family tables to decide whether the
// supplementary (IPv4-mapped / unspecified AF_INET6) fold was isolated. A capture failure fails
// the test; a non-isolated host reports UNSUPPORTED (see main.cpp) rather than a verified pass.

#include "pch.h"
#include "test_support.h"
#include "process_lookup_cases.h"

namespace
{
    using namespace netlib_test;
    using namespace netlib_test::process_lookup_cases;

    class ProcessLookupBaselineTest : public process_lookup_fixture
    {
    };

    // ------------------------------------------------------------------------------------
    // Native ownership
    // ------------------------------------------------------------------------------------

    TEST_F(ProcessLookupBaselineTest, TcpV4CurrentProcessOwnership)
    {
        tcp_pair pair;
        if (const auto f = make_tcp_pair(pair, AF_INET, "127.0.0.1", true, AF_INET, "127.0.0.1"))
            FAIL() << "IPv4 loopback TCP setup failed: " << describe(*f);

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
        NETLIB_TEST_REQUIRE_SOCKETS(make_tcp_pair(pair, AF_INET6, "::1", true, AF_INET6, "::1"));

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
        uint16_t exact_port = 0, wildcard_port = 0;
        if (const auto f = bind_udp(exact, AF_INET, "127.0.0.1", true, 0, false, exact_port))
            FAIL() << "IPv4 UDP exact bind failed: " << describe(*f);
        if (const auto f = bind_udp(wildcard, AF_INET, "0.0.0.0", true, 0, false, wildcard_port))
            FAIL() << "IPv4 UDP wildcard bind failed: " << describe(*f);

        iphelper::process_lookup<v4> lookup;
        ASSERT_TRUE(lookup.actualize(false, true));

        expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_loopback(), exact_port)));

        // A 0.0.0.0 binding owns traffic for any specific local address via the wildcard fallback.
        expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_loopback(), wildcard_port)));
        expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_other(), wildcard_port)));

        // An exact binding does not own other local addresses on the same port.
        EXPECT_EQ(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v4>(v4_other(), exact_port)), nullptr);
    }

    TEST_F(ProcessLookupBaselineTest, UdpV6ExactAndWildcardOwnership)
    {
        unique_socket exact, wildcard;
        uint16_t exact_port = 0, wildcard_port = 0;
        NETLIB_TEST_REQUIRE_SOCKETS(bind_udp(exact, AF_INET6, "::1", true, 0, false, exact_port));
        NETLIB_TEST_REQUIRE_SOCKETS(bind_udp(wildcard, AF_INET6, "::", true, 0, false, wildcard_port));

        iphelper::process_lookup<v6> lookup;
        ASSERT_TRUE(lookup.actualize(false, true));

        expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v6>(v6_loopback(), exact_port)));
        expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v6>(v6_loopback(), wildcard_port)));
        expect_current_process(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v6>(v6_other(), wildcard_port)));
        EXPECT_EQ(lookup.lookup_process_for_udp<false>(net::ip_endpoint<v6>(v6_other(), exact_port)), nullptr);
    }

    // ------------------------------------------------------------------------------------
    // Dual-stack ownership through the IPv4 lookup
    // ------------------------------------------------------------------------------------

    TEST_F(ProcessLookupBaselineTest, DualStackMappedTcpResolvedThroughV4Lookup)
    {
        dual_stack_mapped_tcp_case(*this, {});
    }

    TEST_F(ProcessLookupBaselineTest, UnspecifiedV6UdpResolvedThroughV4Wildcard)
    {
        unspecified_v6_udp_case(*this, {});
    }

    TEST_F(ProcessLookupBaselineTest, MappedV6UdpExactResolvedThroughV4Lookup)
    {
        mapped_v6_udp_exact_case(*this, {});
    }

    // ------------------------------------------------------------------------------------
    // Native IPv4 precedence over supplementary rows
    // ------------------------------------------------------------------------------------

    TEST_F(ProcessLookupBaselineTest, NativeV4UdpExactTakesPrecedenceOverMappedRow)
    {
        native_v4_udp_precedence_case(*this, "::ffff:127.0.0.1", "127.0.0.1", os_tables::v4_mapped_loopback, {});
    }

    TEST_F(ProcessLookupBaselineTest, NativeV4UdpWildcardTakesPrecedenceOverUnspecifiedV6Row)
    {
        native_v4_udp_precedence_case(*this, "::", "0.0.0.0", os_tables::v6_unspecified, {});
    }
}
