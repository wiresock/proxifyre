// Global DNS routing policy (dns_routing_policy.h).
//
// These are the decisions socks_local_router's IPv4/IPv6 UDP/TCP packet handlers apply to every
// outbound packet before process attribution: Direct mode passes port-53 traffic, Proxy mode
// redirects it to the selected proxy's listener or blocks it (never passes it), ProxiFyre's own
// upstream traffic is never captured, and non-DNS traffic keeps its ordinary routing. They also
// cover the DNS server override syntax. The shared UDP association's bookkeeping is tested in
// dns_udp_multiplexer_test.cpp.
//
// The header has no Windows dependencies, so this file also builds outside the Windows test
// project (see netlib/test/portable/run-portable-tests.sh).

#include "pch.h"
#include "../../src/proxy/dns_routing_policy.h"

#include <algorithm>
#include <functional>
#include <set>
#include <vector>

namespace
{
    using proxy::decide_dns_route;
    using proxy::dns_block_reason;
    using proxy::dns_family;
    using proxy::dns_message_id;
    using proxy::dns_port;
    using proxy::dns_proxy_target;
    using proxy::dns_route_action;
    using proxy::dns_routing_mode;
    using proxy::dns_transport;
    using proxy::split_dns_server_override;

    constexpr auto direct = dns_routing_mode::direct;
    constexpr auto proxy_mode = dns_routing_mode::proxy;
    constexpr auto apply = proxy::dns_upstream_guard::apply_policy;
    constexpr auto exempt = proxy::dns_upstream_guard::exempt;

    /// A selected proxy with listeners for every transport and family, mirroring the router's
    /// dns_listener_port_locked() for one proxy index.
    struct dns_proxy
    {
        bool tcp{ true };
        bool udp{ true };
        bool ipv4{ true };
        bool ipv6{ true };
        uint16_t tcp4{ 41001 };
        uint16_t udp4{ 41002 };
        uint16_t tcp6{ 41003 };
        uint16_t udp6{ 41004 };
        std::optional<dns_family> server_override;

        [[nodiscard]] dns_proxy_target target(const dns_transport transport, const dns_family family) const
        {
            const bool is_tcp = transport == dns_transport::tcp;
            const bool is_v4 = family == dns_family::ipv4;
            const uint16_t port = is_tcp ? (is_v4 ? tcp4 : tcp6) : (is_v4 ? udp4 : udp6);

            dns_proxy_target t;
            t.selected = true;
            t.transport_supported = is_tcp ? tcp : udp;
            t.family_supported = is_v4 ? ipv4 : ipv6;
            t.listener_port = port ? std::optional<uint16_t>{ port } : std::nullopt;
            t.override_configured = server_override.has_value();
            t.override_family_matches = server_override == family;
            return t;
        }
    };

    struct route_case
    {
        dns_transport transport;
        dns_family family;
    };

    const route_case all_cases[] = {
        { dns_transport::udp, dns_family::ipv4 },
        { dns_transport::udp, dns_family::ipv6 },
        { dns_transport::tcp, dns_family::ipv4 },
        { dns_transport::tcp, dns_family::ipv6 },
    };
}

// 1. Direct mode: UDP and TCP DNS over IPv4 and IPv6 pass, whatever proxy state exists. TCP/53
//    is now unconditionally direct (previously only UDP/53 was).
TEST(DnsRoutingPolicy, DirectModePassesUdpAndTcpDnsForBothFamilies)
{
    const dns_proxy configured{};
    for (const auto& c : all_cases)
    {
        EXPECT_EQ(decide_dns_route(direct, dns_port, apply, configured.target(c.transport, c.family)).action,
            dns_route_action::pass);
        // No proxy selected at all: Direct still passes.
        EXPECT_EQ(decide_dns_route(direct, dns_port, apply, dns_proxy_target{}).action, dns_route_action::pass);
    }
}

// 2. Proxy mode: UDP DNS uses the UDP listener, TCP DNS the TCP listener, per address family.
TEST(DnsRoutingPolicy, ProxyModeRedirectsToTheListenerOfTheTransportAndFamily)
{
    const dns_proxy p{};
    const auto udp4 = decide_dns_route(proxy_mode, dns_port, apply, p.target(dns_transport::udp, dns_family::ipv4));
    const auto udp6 = decide_dns_route(proxy_mode, dns_port, apply, p.target(dns_transport::udp, dns_family::ipv6));
    const auto tcp4 = decide_dns_route(proxy_mode, dns_port, apply, p.target(dns_transport::tcp, dns_family::ipv4));
    const auto tcp6 = decide_dns_route(proxy_mode, dns_port, apply, p.target(dns_transport::tcp, dns_family::ipv6));

    EXPECT_EQ(udp4.action, dns_route_action::proxy);
    EXPECT_EQ(udp4.listener_port, p.udp4);
    EXPECT_EQ(udp6.action, dns_route_action::proxy);
    EXPECT_EQ(udp6.listener_port, p.udp6);
    EXPECT_EQ(tcp4.action, dns_route_action::proxy);
    EXPECT_EQ(tcp4.listener_port, p.tcp4);
    EXPECT_EQ(tcp6.action, dns_route_action::proxy);
    EXPECT_EQ(tcp6.listener_port, p.tcp6);
}

// 3./4. Queries from the Windows DNS Client service, from applications with their own resolver,
//       and from owners that cannot be resolved are routed identically: the sender is consulted
//       only for packets addressed to a configured SOCKS5 server. This fails if the recursion
//       guard's sender check is ever applied to ordinary DNS (Dnscache's owner can be
//       unresolved, which would then defer or drop every query).
TEST(DnsRoutingPolicy, SenderNeverAffectsQueriesToOrdinaryResolvers)
{
    const dns_proxy p{};
    for (const auto& c : all_cases)
    {
        const auto target = p.target(c.transport, c.family);
        const auto expected = decide_dns_route(proxy_mode, dns_port, apply, target);
        ASSERT_EQ(expected.action, dns_route_action::proxy);

        for (const std::optional<bool> sender : { std::optional<bool>{}, std::optional<bool>{ false }, std::optional<bool>{ true } })
        {
            for (const bool lookup_final : { false, true })
            {
                const auto guard = proxy::decide_dns_upstream_guard(false, sender, lookup_final);
                const auto decision = decide_dns_route(proxy_mode, dns_port, guard, target);
                EXPECT_EQ(decision.action, dns_route_action::proxy);
                EXPECT_EQ(decision.listener_port, expected.listener_port);
            }
        }
    }
}

// 8./9. Fail closed: Proxy mode never passes DNS that the selected proxy cannot carry.
TEST(DnsRoutingPolicy, ProxyModeBlocksInsteadOfFallingBackToDirect)
{
    // No usable proxy (invalid reference or the proxy could not be created).
    for (const auto& c : all_cases)
    {
        (void)c;
        const auto d = decide_dns_route(proxy_mode, dns_port, apply, dns_proxy_target{});
        EXPECT_EQ(d.action, dns_route_action::block);
        EXPECT_EQ(d.reason, dns_block_reason::proxy_unavailable);
    }

    // The proxy lacks the transport (unsupported protocol combination).
    dns_proxy tcp_only{};
    tcp_only.udp = false;
    auto d = decide_dns_route(proxy_mode, dns_port, apply, tcp_only.target(dns_transport::udp, dns_family::ipv4));
    EXPECT_EQ(d.action, dns_route_action::block);
    EXPECT_EQ(d.reason, dns_block_reason::transport_unsupported);

    // The proxy does not accept IPv6 destinations.
    dns_proxy v4_only{};
    v4_only.ipv6 = false;
    d = decide_dns_route(proxy_mode, dns_port, apply, v4_only.target(dns_transport::tcp, dns_family::ipv6));
    EXPECT_EQ(d.action, dns_route_action::block);
    EXPECT_EQ(d.reason, dns_block_reason::family_unsupported);

    // The listener is not running (for example the IPv6 listener failed to start).
    dns_proxy no_v6_listener{};
    no_v6_listener.udp6 = 0;
    d = decide_dns_route(proxy_mode, dns_port, apply, no_v6_listener.target(dns_transport::udp, dns_family::ipv6));
    EXPECT_EQ(d.action, dns_route_action::block);
    EXPECT_EQ(d.reason, dns_block_reason::listener_unavailable);

    // A missing listener port value and an explicit zero are both unusable.
    auto target = dns_proxy{}.target(dns_transport::udp, dns_family::ipv4);
    target.listener_port = std::nullopt;
    EXPECT_EQ(decide_dns_route(proxy_mode, dns_port, apply, target).action, dns_route_action::block);
}

// 6. A server override applies to queries of its own family; queries of the other family are
//    blocked rather than sent to their original (often local) server.
TEST(DnsRoutingPolicy, ServerOverrideFamilyIsHandledExplicitly)
{
    dns_proxy with_v4_override{};
    with_v4_override.server_override = dns_family::ipv4;

    for (const auto transport : { dns_transport::udp, dns_transport::tcp })
    {
        EXPECT_EQ(decide_dns_route(proxy_mode, dns_port, apply, with_v4_override.target(transport, dns_family::ipv4)).action,
            dns_route_action::proxy);

        const auto other = decide_dns_route(proxy_mode, dns_port, apply, with_v4_override.target(transport, dns_family::ipv6));
        EXPECT_EQ(other.action, dns_route_action::block);
        EXPECT_EQ(other.reason, dns_block_reason::override_family_mismatch);
    }

    dns_proxy with_v6_override{};
    with_v6_override.server_override = dns_family::ipv6;
    EXPECT_EQ(decide_dns_route(proxy_mode, dns_port, apply, with_v6_override.target(dns_transport::udp, dns_family::ipv6)).action,
        dns_route_action::proxy);
    EXPECT_EQ(decide_dns_route(proxy_mode, dns_port, apply, with_v6_override.target(dns_transport::udp, dns_family::ipv4)).action,
        dns_route_action::block);
}

// 11. Recursion prevention: a packet to a configured SOCKS5 server is exempt only when its sender
//     is ProxiFyre itself. Another process's query to a host that is both the SOCKS5 server and a
//     resolver is subject to the policy; an unattributed one is deferred, then dropped.
TEST(DnsRoutingPolicy, UpstreamGuardExemptsOnlyProxiFyresOwnTraffic)
{
    using proxy::decide_dns_upstream_guard;
    using guard = proxy::dns_upstream_guard;

    // Not addressed to a SOCKS5 server: the sender is irrelevant.
    EXPECT_EQ(decide_dns_upstream_guard(false, std::nullopt, false), guard::apply_policy);
    EXPECT_EQ(decide_dns_upstream_guard(false, true, true), guard::apply_policy);

    EXPECT_EQ(decide_dns_upstream_guard(true, true, false), guard::exempt);
    EXPECT_EQ(decide_dns_upstream_guard(true, true, true), guard::exempt);
    EXPECT_EQ(decide_dns_upstream_guard(true, false, false), guard::apply_policy);
    EXPECT_EQ(decide_dns_upstream_guard(true, false, true), guard::apply_policy);
    EXPECT_EQ(decide_dns_upstream_guard(true, std::nullopt, false), guard::defer);
    EXPECT_EQ(decide_dns_upstream_guard(true, std::nullopt, true), guard::drop);
}

TEST(DnsRoutingPolicy, UpstreamGuardOutcomesMapToFailClosedActions)
{
    const dns_proxy p{};
    for (const auto& c : all_cases)
    {
        const auto target = p.target(c.transport, c.family);

        // ProxiFyre's own traffic passes, even with no usable DNS proxy.
        EXPECT_EQ(decide_dns_route(proxy_mode, dns_port, exempt, target).action, dns_route_action::pass);
        EXPECT_EQ(decide_dns_route(proxy_mode, dns_port, exempt, dns_proxy_target{}).action, dns_route_action::pass);

        // Another process's query to the SOCKS5 host is proxied like any other query.
        const auto other = decide_dns_route(proxy_mode, dns_port, apply, target);
        EXPECT_EQ(other.action, dns_route_action::proxy);

        // Unknown sender: deferred inline, dropped after the deferred lookup; never passed.
        EXPECT_EQ(decide_dns_route(proxy_mode, dns_port, proxy::dns_upstream_guard::defer, target).action,
            dns_route_action::defer);
        const auto dropped = decide_dns_route(proxy_mode, dns_port, proxy::dns_upstream_guard::drop, target);
        EXPECT_EQ(dropped.action, dns_route_action::block);
        EXPECT_EQ(dropped.reason, dns_block_reason::upstream_sender_unknown);

        // Direct mode passes DNS whatever the guard says.
        EXPECT_EQ(decide_dns_route(direct, dns_port, proxy::dns_upstream_guard::drop, target).action,
            dns_route_action::pass);
    }
}

// 15. Non-DNS traffic keeps its ordinary application routing in both modes; only the
//     destination port classifies traffic.
TEST(DnsRoutingPolicy, NonDnsTrafficIsNotClassified)
{
    const dns_proxy p{};
    for (const uint16_t port : { uint16_t{ 0 }, uint16_t{ 52 }, uint16_t{ 54 }, uint16_t{ 80 }, uint16_t{ 443 },
                                 uint16_t{ 853 }, uint16_t{ 5353 }, uint16_t{ 5355 }, uint16_t{ 65535 } })
    {
        for (const auto mode : { direct, proxy_mode })
        {
            EXPECT_EQ(decide_dns_route(mode, port, apply, p.target(dns_transport::udp, dns_family::ipv4)).action,
                dns_route_action::not_dns) << port;
            EXPECT_EQ(decide_dns_route(mode, port, exempt, dns_proxy_target{}).action, dns_route_action::not_dns) << port;
        }
    }
}

// 14. The TCP retry after a truncated UDP answer must take the same path as the UDP query: in
//     Proxy mode TCP/53 is redirected to the same proxy (its TCP listener), never passed, and a
//     proxy that cannot carry TCP blocks the retry instead of letting it leak. (The packet-level
//     retry is in netlib/test/portable/dns_packet_redirect_test.cpp.)
TEST(DnsRoutingPolicy, TcpRetryIsRedirectedOrBlockedNeverPassed)
{
    for (const auto family : { dns_family::ipv4, dns_family::ipv6 })
    {
        dns_proxy p{};
        p.server_override = family;
        const auto tcp = decide_dns_route(proxy_mode, dns_port, apply, p.target(dns_transport::tcp, family));
        EXPECT_EQ(tcp.action, dns_route_action::proxy);
        EXPECT_EQ(tcp.listener_port, family == dns_family::ipv4 ? p.tcp4 : p.tcp6);

        dns_proxy udp_only{};
        udp_only.tcp = false;
        const auto blocked = decide_dns_route(proxy_mode, dns_port, apply, udp_only.target(dns_transport::tcp, family));
        EXPECT_EQ(blocked.action, dns_route_action::block);
        EXPECT_EQ(blocked.reason, dns_block_reason::transport_unsupported);
    }
}

TEST(DnsRoutingPolicy, BlockReasonsHaveDiagnostics)
{
    for (auto reason = static_cast<int>(dns_block_reason::proxy_unavailable);
         reason < static_cast<int>(dns_block_reason::count); ++reason)
    {
        const std::string text = proxy::to_string(static_cast<dns_block_reason>(reason));
        EXPECT_FALSE(text.empty());
        EXPECT_NE(text, "unknown");
    }
}

TEST(DnsServerOverrideSyntax, AcceptsLiteralsWithOptionalPorts)
{
    struct expected
    {
        const char* input;
        const char* address;
        uint16_t port;
        bool bracketed;
    };

    const expected cases[] = {
        { "1.1.1.1", "1.1.1.1", 53, false },
        { "  1.1.1.1  ", "1.1.1.1", 53, false },
        { "1.1.1.1:5353", "1.1.1.1", 5353, false },
        { "192.168.1.1:53", "192.168.1.1", 53, false },
        { "2606:4700:4700::1111", "2606:4700:4700::1111", 53, false },
        { "::1", "::1", 53, false },
        { "[2606:4700:4700::1111]", "2606:4700:4700::1111", 53, true },
        { "[2606:4700:4700::1111]:853", "2606:4700:4700::1111", 853, true },
        { "[fe80::1]:65535", "fe80::1", 65535, true },
    };

    for (const auto& c : cases)
    {
        const auto parsed = split_dns_server_override(c.input);
        ASSERT_TRUE(parsed.has_value()) << c.input;
        EXPECT_EQ(parsed->address, c.address) << c.input;
        EXPECT_EQ(parsed->port, c.port) << c.input;
        EXPECT_EQ(parsed->bracketed, c.bracketed) << c.input;
    }
}

TEST(DnsServerOverrideSyntax, RejectsMalformedValues)
{
    for (const auto* input : { "", "   ", "1.1.1.1:", "1.1.1.1:0", "1.1.1.1:65536", "1.1.1.1:abc", "1.1.1.1:123456",
                               ":53", "[", "[]", "[]:53", "[::1", "[::1]53", "[::1]:", "[::1]:0", "dns server",
                               "fe80::1%12", "[fe80::1%eth0]:53", "a/b", "1.1.1.1 :53" })
    {
        EXPECT_FALSE(split_dns_server_override(input).has_value()) << '"' << input << '"';
    }
}

TEST(DnsMessageId, ReadsTheIdOfACompleteHeaderOnly)
{
    const uint8_t query[] = { 0xbe, 0xef, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    EXPECT_EQ(dns_message_id(query, sizeof(query)), uint16_t{ 0xbeef });
    EXPECT_FALSE(dns_message_id(query, sizeof(query) - 1).has_value());
    EXPECT_FALSE(dns_message_id(nullptr, 64).has_value());
}

// 1. Packets sourced from a local proxy listener are re-injected when translated and dropped
//    otherwise; there is no outcome that passes them to the wire.
TEST(ListenerReplyPolicy, UntranslatedListenerRepliesAreDroppedNeverPassed)
{
    using proxy::decide_listener_reply;
    using proxy::listener_reply_action;

    EXPECT_EQ(decide_listener_reply(true), listener_reply_action::revert);
    EXPECT_EQ(decide_listener_reply(false), listener_reply_action::drop);
}

// 5. Fragments: only a first fragment carries ports. IPv4 later fragments are not classified;
//    a fragmented datagram that would be redirected is blocked instead.
TEST(DnsFragmentPolicy, Ipv4FragmentClassification)
{
    using proxy::classify_ipv4_fragment;
    using proxy::ipv4_fragment;

    EXPECT_EQ(classify_ipv4_fragment(0x0000), ipv4_fragment::none);
    EXPECT_EQ(classify_ipv4_fragment(0x4000), ipv4_fragment::none);   // DF only
    EXPECT_EQ(classify_ipv4_fragment(0x2000), ipv4_fragment::first);  // MF, offset 0
    EXPECT_EQ(classify_ipv4_fragment(0x2001), ipv4_fragment::later);  // MF, offset 8
    EXPECT_EQ(classify_ipv4_fragment(0x00b9), ipv4_fragment::later);  // last fragment
}

TEST(DnsFragmentPolicy, FragmentedDatagramsThatWouldBeRedirectedAreBlocked)
{
    using proxy::apply_fragmentation;
    const dns_proxy p{};
    const auto redirect = decide_dns_route(proxy_mode, dns_port, apply, p.target(dns_transport::udp, dns_family::ipv4));
    ASSERT_EQ(redirect.action, dns_route_action::proxy);

    const auto fragmented = apply_fragmentation(redirect, true);
    EXPECT_EQ(fragmented.action, dns_route_action::block);
    EXPECT_EQ(fragmented.reason, dns_block_reason::fragmented);
    EXPECT_EQ(apply_fragmentation(redirect, false).action, dns_route_action::proxy);

    // Direct mode and non-DNS decisions are unaffected by fragmentation.
    const auto direct_pass = decide_dns_route(direct, dns_port, apply, {});
    EXPECT_EQ(apply_fragmentation(direct_pass, true).action, dns_route_action::pass);
    EXPECT_EQ(apply_fragmentation(decide_dns_route(proxy_mode, 443, apply, {}), true).action, dns_route_action::not_dns);
}

namespace
{
    /// Builds an IPv6 packet: 40-byte header followed by @p chain bytes.
    std::vector<uint8_t> ipv6_packet(const uint8_t next_header, const std::vector<uint8_t>& chain)
    {
        std::vector<uint8_t> packet(40, 0);
        packet[0] = 0x60;
        packet[4] = static_cast<uint8_t>(chain.size() >> 8);
        packet[5] = static_cast<uint8_t>(chain.size() & 0xff);
        packet[6] = next_header;
        packet[7] = 64;
        packet.insert(packet.end(), chain.begin(), chain.end());
        return packet;
    }

    std::vector<uint8_t> fragment_header(const uint8_t next, const uint16_t offset_in_8_bytes, const bool more)
    {
        const auto field = static_cast<uint16_t>((offset_in_8_bytes << 3) | (more ? 1 : 0));
        return { next, 0, static_cast<uint8_t>(field >> 8), static_cast<uint8_t>(field & 0xff), 0, 0, 0x12, 0x34 };
    }

    std::vector<uint8_t> ports(const uint16_t source, const uint16_t destination)
    {
        return { static_cast<uint8_t>(source >> 8), static_cast<uint8_t>(source & 0xff),
                 static_cast<uint8_t>(destination >> 8), static_cast<uint8_t>(destination & 0xff),
                 0, 8, 0, 0 };
    }

    std::vector<uint8_t> concat(std::initializer_list<std::vector<uint8_t>> parts)
    {
        std::vector<uint8_t> out;
        for (const auto& part : parts)
            out.insert(out.end(), part.begin(), part.end());
        return out;
    }

    std::optional<proxy::ipv6_first_fragment> parse(const std::vector<uint8_t>& packet)
    {
        return proxy::parse_ipv6_first_fragment(packet.data(), packet.size());
    }

    constexpr uint8_t udp_proto = 17, tcp_proto = 6, fragment_proto = 44, hop_proto = 0, dest_opts_proto = 60;
}

TEST(DnsFragmentPolicy, Ipv6FirstFragmentExposesTheUpperLayerDestinationPort)
{
    const auto udp_first = parse(ipv6_packet(fragment_proto, concat({ fragment_header(udp_proto, 0, true), ports(50001, 53) })));
    ASSERT_TRUE(udp_first.has_value());
    EXPECT_EQ(udp_first->protocol, udp_proto);
    EXPECT_EQ(udp_first->destination_port, 53);

    const auto tcp_first = parse(ipv6_packet(fragment_proto, concat({ fragment_header(tcp_proto, 0, true), ports(50001, 53) })));
    ASSERT_TRUE(tcp_first.has_value());
    EXPECT_EQ(tcp_first->protocol, tcp_proto);

    // Extension headers before and after the fragment header are skipped.
    const std::vector<uint8_t> hop_by_hop{ fragment_proto, 0, 1, 4, 0, 0, 0, 0 };
    const std::vector<uint8_t> destination_options{ udp_proto, 0, 1, 4, 0, 0, 0, 0 };
    const auto chained = parse(ipv6_packet(hop_proto,
        concat({ hop_by_hop, fragment_header(dest_opts_proto, 0, true), destination_options, ports(50001, 443) })));
    ASSERT_TRUE(chained.has_value());
    EXPECT_EQ(chained->protocol, udp_proto);
    EXPECT_EQ(chained->destination_port, 443);
}

TEST(DnsFragmentPolicy, Ipv6PacketsWithoutAClassifiableFirstFragmentAreNotReported)
{
    // Unfragmented: handled by the normal path.
    EXPECT_FALSE(parse(ipv6_packet(udp_proto, ports(50001, 53))).has_value());
    // A later fragment has no upper-layer header: its leading bytes must not be read as ports.
    EXPECT_FALSE(parse(ipv6_packet(fragment_proto, concat({ fragment_header(udp_proto, 185, false), ports(1, 53) }))).has_value());
    // Another upper-layer protocol (ICMPv6).
    EXPECT_FALSE(parse(ipv6_packet(fragment_proto, concat({ fragment_header(58, 0, true), ports(1, 53) }))).has_value());
    // Truncated: fragment header, but not the ports.
    EXPECT_FALSE(parse(ipv6_packet(fragment_proto, fragment_header(udp_proto, 0, true))).has_value());
    // Not IPv6, empty, or a nested fragment header.
    auto not_v6 = ipv6_packet(fragment_proto, concat({ fragment_header(udp_proto, 0, true), ports(1, 53) }));
    not_v6[0] = 0x45;
    EXPECT_FALSE(parse(not_v6).has_value());
    EXPECT_FALSE(proxy::parse_ipv6_first_fragment(nullptr, 100).has_value());
    EXPECT_FALSE(parse(ipv6_packet(fragment_proto,
        concat({ fragment_header(fragment_proto, 0, true), fragment_header(udp_proto, 0, true), ports(1, 53) }))).has_value());
}

// 6. Driver filters: Proxy mode keeps port-53 traffic of both families and transports, and the
//    DNS listeners' replies, in user mode; Direct mode installs none; no port-0 filters.
TEST(DnsFilterPlan, DirectModeInstallsNoFilters)
{
    proxy::dns_listener_ports listeners{ 41001, 41002, 41003, 41004 };
    EXPECT_TRUE(proxy::plan_dns_filters(direct, listeners).empty());
}

TEST(DnsFilterPlan, ProxyModeCoversPort53AndEveryRunningListener)
{
    using proxy::dns_filter_spec;
    const auto plan = proxy::plan_dns_filters(proxy_mode, { 41001, 41002, 41003, 41004 });

    const std::vector<dns_filter_spec> expected{
        { dns_family::ipv4, dns_transport::udp, dns_port, std::nullopt },
        { dns_family::ipv4, dns_transport::tcp, dns_port, std::nullopt },
        { dns_family::ipv6, dns_transport::udp, dns_port, std::nullopt },
        { dns_family::ipv6, dns_transport::tcp, dns_port, std::nullopt },
        { dns_family::ipv4, dns_transport::tcp, std::nullopt, uint16_t{ 41001 } },
        { dns_family::ipv4, dns_transport::udp, std::nullopt, uint16_t{ 41002 } },
        { dns_family::ipv6, dns_transport::tcp, std::nullopt, uint16_t{ 41003 } },
        { dns_family::ipv6, dns_transport::udp, std::nullopt, uint16_t{ 41004 } },
    };
    EXPECT_EQ(plan, expected);
}

TEST(DnsFilterPlan, ListenersThatAreNotRunningGetNoSourcePortFilter)
{
    // IPv6 listeners disabled (nullopt) and an IPv4 UDP listener reporting port 0.
    const auto plan = proxy::plan_dns_filters(proxy_mode, { 41001, uint16_t{ 0 }, std::nullopt, std::nullopt });

    ASSERT_EQ(plan.size(), 5u);
    for (const auto& spec : plan)
    {
        EXPECT_NE(spec.source_port, std::optional<uint16_t>{ 0 });
        EXPECT_TRUE(spec.destination_port.has_value() != spec.source_port.has_value());
    }
    EXPECT_EQ(plan.back().source_port, std::optional<uint16_t>{ 41001 });

    // Even with no listener at all, port 53 stays in user mode (where it is then blocked).
    EXPECT_EQ(proxy::plan_dns_filters(proxy_mode, {}).size(), 4u);
}

// ------------------------------------------------------------------ listener replies and fragments
//
// A fragmented listener reply must not reach the wire, and a later fragment's payload must never
// be read as ports.

TEST(ListenerFragmentPolicy, Ipv6FirstFragmentExposesTheSourcePort)
{
    constexpr uint16_t listener = 41004;
    const auto first = parse(ipv6_packet(fragment_proto, concat({ fragment_header(udp_proto, 0, true), ports(listener, 50001) })));
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->source_port, listener);
    EXPECT_EQ(first->destination_port, 50001);
}

TEST(ListenerFragmentPolicy, FragmentedListenerReplyIsDroppedInEveryMode)
{
    using proxy::decide_ipv6_fragment;
    using proxy::ipv6_fragment_action;
    constexpr uint16_t listener = 41004;

    // A large DNS answer from the UDP listener to client port 50001, fragmented by the stack.
    const auto reply = parse(ipv6_packet(fragment_proto, concat({ fragment_header(udp_proto, 0, true), ports(listener, 50001) })));
    ASSERT_TRUE(reply.has_value());
    for (const bool proxy_mode_active : { false, true })
        EXPECT_EQ(decide_ipv6_fragment(reply, true, proxy_mode_active), ipv6_fragment_action::drop_listener_reply);

    // A listener reply to client port 53 is still a listener reply, not DNS.
    const auto to_port_53 = parse(ipv6_packet(fragment_proto, concat({ fragment_header(tcp_proto, 0, true), ports(listener, 53) })));
    EXPECT_EQ(decide_ipv6_fragment(to_port_53, true, true), ipv6_fragment_action::drop_listener_reply);
}

TEST(ListenerFragmentPolicy, OtherIpv6FragmentsKeepTheirBehaviour)
{
    using proxy::decide_ipv6_fragment;
    using proxy::ipv6_fragment_action;

    const auto dns_query = parse(ipv6_packet(fragment_proto, concat({ fragment_header(udp_proto, 0, true), ports(50001, 53) })));
    EXPECT_EQ(decide_ipv6_fragment(dns_query, false, true), ipv6_fragment_action::drop_dns);
    EXPECT_EQ(decide_ipv6_fragment(dns_query, false, false), ipv6_fragment_action::pass);

    const auto unrelated = parse(ipv6_packet(fragment_proto, concat({ fragment_header(udp_proto, 0, true), ports(50001, 443) })));
    EXPECT_EQ(decide_ipv6_fragment(unrelated, false, true), ipv6_fragment_action::pass);

    // Later fragments and unparsable chains carry no ports: passed in every mode.
    const auto later = parse(ipv6_packet(fragment_proto, concat({ fragment_header(udp_proto, 185, false), ports(41004, 53) })));
    ASSERT_FALSE(later.has_value());
    EXPECT_EQ(decide_ipv6_fragment(later, true, true), ipv6_fragment_action::pass);
}

TEST(ListenerFragmentPolicy, LaterIpv4FragmentsAreNeverReadForPorts)
{
    using proxy::classify_ipv4_fragment;
    using proxy::ipv4_transport_header_present;

    // A later fragment of an unrelated datagram whose payload happens to start with a listener port.
    EXPECT_FALSE(ipv4_transport_header_present(classify_ipv4_fragment(0x00b9)));
    EXPECT_FALSE(ipv4_transport_header_present(classify_ipv4_fragment(0x2001)));
    EXPECT_TRUE(ipv4_transport_header_present(classify_ipv4_fragment(0x2000)));
    EXPECT_TRUE(ipv4_transport_header_present(classify_ipv4_fragment(0x4000)));
    EXPECT_TRUE(ipv4_transport_header_present(classify_ipv4_fragment(0x0000)));
}

// Listener segments: translated ones are re-injected; those of a connection that was just reset
// are dropped quietly (an expected part of an abort); others are dropped and reported.
TEST(ListenerSegmentPolicy, OutcomesMapToRevertQuietDropAndReportedDrop)
{
    using proxy::decide_tcp_listener_segment;
    using proxy::listener_segment_action;
    using proxy::listener_segment_outcome;

    EXPECT_EQ(decide_tcp_listener_segment(listener_segment_outcome::translated), listener_segment_action::revert);
    EXPECT_EQ(decide_tcp_listener_segment(listener_segment_outcome::recently_reset), listener_segment_action::drop_quietly);
    EXPECT_EQ(decide_tcp_listener_segment(listener_segment_outcome::unknown), listener_segment_action::drop_reported);
}

// Recursion guard and the UDP relay port: a UDP packet to a SOCKS5 server's address can be
// ProxiFyre's own only if a server has returned a relay on port 53. Until then no sender lookup or
// deferral happens for UDP, whatever the (possibly stale) table says. TCP is unchanged.
TEST(DnsRoutingPolicy, UpstreamExemptionCandidatesDependOnTheUdpRelayPort)
{
    using proxy::decide_dns_upstream_guard;
    using proxy::is_upstream_exemption_candidate;
    using guard = proxy::dns_upstream_guard;

    const std::optional<bool> senders[] = { std::optional<bool>{}, std::optional<bool>{ false }, std::optional<bool>{ true } };

    // The guard as the router computes it: the sender is looked up only for candidates.
    const auto route = [](const dns_transport transport, const bool relay_on_53, const bool matches,
                          const std::optional<bool> sender, const bool lookup_final)
    {
        const bool candidate = is_upstream_exemption_candidate(transport, relay_on_53, matches);
        return decide_dns_upstream_guard(candidate, candidate ? sender : std::optional<bool>{}, lookup_final);
    };

    for (const bool lookup_final : { false, true })
    {
        for (const auto& sender : senders)
        {
            // UDP, no relay on port 53: never exempt, never deferred or dropped by the guard.
            EXPECT_EQ(route(dns_transport::udp, false, true, sender, lookup_final), guard::apply_policy);
            EXPECT_EQ(route(dns_transport::udp, false, false, sender, lookup_final), guard::apply_policy);

            // Not addressed to a SOCKS5 server: the sender is irrelevant in every state.
            EXPECT_EQ(route(dns_transport::udp, true, false, sender, lookup_final), guard::apply_policy);
            EXPECT_EQ(route(dns_transport::tcp, false, false, sender, lookup_final), guard::apply_policy);
            EXPECT_EQ(route(dns_transport::tcp, true, false, sender, lookup_final), guard::apply_policy);
        }

        // UDP with a relay on port 53, and TCP whatever the flag: the sender decides.
        for (const auto& [transport, relay_on_53] : { std::pair{ dns_transport::udp, true },
                                                      std::pair{ dns_transport::tcp, false },
                                                      std::pair{ dns_transport::tcp, true } })
        {
            EXPECT_EQ(route(transport, relay_on_53, true, true, lookup_final), guard::exempt);
            EXPECT_EQ(route(transport, relay_on_53, true, false, lookup_final), guard::apply_policy);
            EXPECT_EQ(route(transport, relay_on_53, true, std::nullopt, lookup_final),
                lookup_final ? guard::drop : guard::defer);
        }
    }
}

// The DNS mode (which takes the router's lock) is needed only for a non-listener IPv6 first
// fragment addressed to port 53; the fragment decision itself does not change.
TEST(ListenerFragmentPolicy, DnsModeIsReadOnlyForNonListenerFirstFragmentsToPort53)
{
    using proxy::decide_ipv6_fragment;
    using proxy::ipv6_fragment_needs_dns_mode;

    const auto dns_query = parse(ipv6_packet(fragment_proto, concat({ fragment_header(udp_proto, 0, true), ports(50001, 53) })));
    const auto listener_reply = parse(ipv6_packet(fragment_proto, concat({ fragment_header(udp_proto, 0, true), ports(41004, 53) })));
    const auto unrelated = parse(ipv6_packet(fragment_proto, concat({ fragment_header(udp_proto, 0, true), ports(50001, 443) })));

    EXPECT_TRUE(ipv6_fragment_needs_dns_mode(dns_query, false));
    EXPECT_FALSE(ipv6_fragment_needs_dns_mode(listener_reply, true));
    EXPECT_FALSE(ipv6_fragment_needs_dns_mode(unrelated, false));
    EXPECT_FALSE(ipv6_fragment_needs_dns_mode(std::nullopt, false));

    // Whenever the mode is not read, the decision is the same in both modes.
    for (const auto& [first, listener] : { std::pair{ listener_reply, true }, std::pair{ unrelated, false },
                                           std::pair{ std::optional<proxy::ipv6_first_fragment>{}, false } })
    {
        if (!ipv6_fragment_needs_dns_mode(first, listener))
        {
            EXPECT_EQ(decide_ipv6_fragment(first, listener, false), decide_ipv6_fragment(first, listener, true));
        }
    }
}

// An IPv4 listener packet is translated only when it is not fragmented: a first fragment carries
// only part of the reply and is dropped and reported (the TCP redirect does not check fragments).
TEST(ListenerFragmentPolicy, Ipv4ListenerFirstFragmentsAreNotTranslated)
{
    using proxy::classify_ipv4_fragment;
    using proxy::ipv4_listener_packet_translatable;

    EXPECT_TRUE(ipv4_listener_packet_translatable(classify_ipv4_fragment(0x0000)));
    EXPECT_TRUE(ipv4_listener_packet_translatable(classify_ipv4_fragment(0x4000)));
    EXPECT_FALSE(ipv4_listener_packet_translatable(classify_ipv4_fragment(0x2000)));
    EXPECT_FALSE(ipv4_listener_packet_translatable(classify_ipv4_fragment(0x2001)));
}

// ------------------------------------------------------------------ ICMP errors about DNS answers
//
// In Proxy mode a DNS answer delivered to a socket that has closed makes the stack send an ICMP
// error, which quotes the answer, to the server the client queried. It must not leave the adapter.

namespace
{
    /// Builds an IPv4 packet: a 20-byte header plus @p options, followed by @p payload.
    std::vector<uint8_t> ipv4_packet(const uint8_t protocol, const uint16_t flags_and_offset,
        const std::vector<uint8_t>& payload, const std::vector<uint8_t>& options = {})
    {
        std::vector<uint8_t> packet(20, 0);
        packet[0] = static_cast<uint8_t>(0x40 | ((20 + options.size()) / 4));
        packet[6] = static_cast<uint8_t>(flags_and_offset >> 8);
        packet[7] = static_cast<uint8_t>(flags_and_offset & 0xff);
        packet[8] = 64;
        packet[9] = protocol;
        packet.insert(packet.end(), options.begin(), options.end());
        packet.insert(packet.end(), payload.begin(), payload.end());
        return packet;
    }

    /// Builds an ICMP or ICMPv6 message: an 8-byte header followed by the quoted packet.
    std::vector<uint8_t> icmp_message(const uint8_t type, const uint8_t code, const std::vector<uint8_t>& quoted)
    {
        std::vector<uint8_t> message{ type, code, 0, 0, 0, 0, 0, 0 };
        message.insert(message.end(), quoted.begin(), quoted.end());
        return message;
    }

    std::optional<uint16_t> quoted_v4(const std::vector<uint8_t>& message)
    {
        return proxy::icmpv4_error_quoted_source_port(message.data(), message.size());
    }

    std::optional<uint16_t> quoted_v6(const std::vector<uint8_t>& message)
    {
        return proxy::icmpv6_error_quoted_source_port(message.data(), message.size());
    }

    constexpr uint8_t icmpv4_unreachable = 3, icmpv4_port_unreachable = 3, icmpv4_echo_request = 8, icmpv4_echo_reply = 0;
    constexpr uint8_t icmpv6_unreachable = 1, icmpv6_port_unreachable = 4, icmpv6_echo_request = 128;
    constexpr uint8_t icmpv6_proto = 58, icmp_proto = 1;
}

TEST(DnsAnswerIcmpPolicy, Icmpv4ErrorExposesTheQuotedSourcePort)
{
    // Port unreachable about a UDP answer from port 53 to a closed client port.
    EXPECT_EQ(quoted_v4(icmp_message(icmpv4_unreachable, icmpv4_port_unreachable, ipv4_packet(udp_proto, 0, ports(53, 58440)))),
        std::optional<uint16_t>{ 53 });
    // The quoted header length is honoured (IP options), and TCP is read the same way.
    EXPECT_EQ(quoted_v4(icmp_message(icmpv4_unreachable, icmpv4_port_unreachable,
        ipv4_packet(tcp_proto, 0, ports(53, 58440), { 1, 1, 1, 1 }))), std::optional<uint16_t>{ 53 });
    // Every error type quotes the packet; the first fragment of a datagram still carries ports.
    for (const uint8_t type : { uint8_t{ 3 }, uint8_t{ 4 }, uint8_t{ 5 }, uint8_t{ 11 }, uint8_t{ 12 } })
    {
        EXPECT_EQ(quoted_v4(icmp_message(type, 0, ipv4_packet(udp_proto, 0x2000, ports(443, 50000)))),
            std::optional<uint16_t>{ 443 });
    }
    // The eight bytes RFC 792 requires after the quoted header are enough.
    EXPECT_EQ(icmp_message(icmpv4_unreachable, icmpv4_port_unreachable, ipv4_packet(udp_proto, 0, ports(53, 1))).size(), 36u);
}

TEST(DnsAnswerIcmpPolicy, Icmpv4MessagesWithoutAQuotedSourcePortAreNotReported)
{
    // Echo request and reply carry data, not a quoted packet, even if the data looks like one.
    EXPECT_FALSE(quoted_v4(icmp_message(icmpv4_echo_request, 0, ipv4_packet(udp_proto, 0, ports(53, 1)))).has_value());
    EXPECT_FALSE(quoted_v4(icmp_message(icmpv4_echo_reply, 0, ipv4_packet(udp_proto, 0, ports(53, 1)))).has_value());
    // Another quoted protocol (ICMP).
    EXPECT_FALSE(quoted_v4(icmp_message(icmpv4_unreachable, 0, ipv4_packet(icmp_proto, 0, ports(53, 1)))).has_value());
    // A later fragment has no transport header: its leading bytes must not be read as ports.
    EXPECT_FALSE(quoted_v4(icmp_message(icmpv4_unreachable, 0, ipv4_packet(udp_proto, 185, ports(53, 1)))).has_value());
    // Truncated before the quoted ports, with and without IP options.
    EXPECT_FALSE(quoted_v4(icmp_message(icmpv4_unreachable, 0, ipv4_packet(udp_proto, 0, {}))).has_value());
    EXPECT_FALSE(quoted_v4(icmp_message(icmpv4_unreachable, 0, ipv4_packet(udp_proto, 0, {}, { 1, 1, 1, 1 }))).has_value());
    // A quoted header that is not IPv4, or whose length field is too small.
    auto not_v4 = icmp_message(icmpv4_unreachable, 0, ipv4_packet(udp_proto, 0, ports(53, 1)));
    not_v4[8] = 0x65;
    EXPECT_FALSE(quoted_v4(not_v4).has_value());
    auto short_header = icmp_message(icmpv4_unreachable, 0, ipv4_packet(udp_proto, 0, ports(53, 1)));
    short_header[8] = 0x44;
    EXPECT_FALSE(quoted_v4(short_header).has_value());
    // No data at all.
    EXPECT_FALSE(proxy::icmpv4_error_quoted_source_port(nullptr, 100).has_value());
    EXPECT_FALSE(quoted_v4({ icmpv4_unreachable, icmpv4_port_unreachable, 0, 0 }).has_value());
}

TEST(DnsAnswerIcmpPolicy, Icmpv6ErrorExposesTheQuotedSourcePort)
{
    EXPECT_EQ(quoted_v6(icmp_message(icmpv6_unreachable, icmpv6_port_unreachable, ipv6_packet(udp_proto, ports(53, 58440)))),
        std::optional<uint16_t>{ 53 });
    EXPECT_EQ(quoted_v6(icmp_message(icmpv6_unreachable, icmpv6_port_unreachable, ipv6_packet(tcp_proto, ports(53, 58440)))),
        std::optional<uint16_t>{ 53 });
    // Extension headers and a first-fragment header in the quoted packet are skipped.
    const std::vector<uint8_t> hop_by_hop{ fragment_proto, 0, 1, 4, 0, 0, 0, 0 };
    const std::vector<uint8_t> destination_options{ udp_proto, 0, 1, 4, 0, 0, 0, 0 };
    EXPECT_EQ(quoted_v6(icmp_message(3, 0, ipv6_packet(hop_proto,
        concat({ hop_by_hop, fragment_header(dest_opts_proto, 0, true), destination_options, ports(53, 50001) })))),
        std::optional<uint16_t>{ 53 });
    // Every type below 128 is an error.
    for (const uint8_t type : { uint8_t{ 1 }, uint8_t{ 2 }, uint8_t{ 3 }, uint8_t{ 4 }, uint8_t{ 127 } })
    {
        EXPECT_EQ(quoted_v6(icmp_message(type, 0, ipv6_packet(udp_proto, ports(5353, 50000)))),
            std::optional<uint16_t>{ 5353 });
    }
}

TEST(DnsAnswerIcmpPolicy, Icmpv6MessagesWithoutAQuotedSourcePortAreNotReported)
{
    // Informational messages (echo, neighbor discovery) are not errors.
    EXPECT_FALSE(quoted_v6(icmp_message(icmpv6_echo_request, 0, ipv6_packet(udp_proto, ports(53, 1)))).has_value());
    EXPECT_FALSE(quoted_v6(icmp_message(135, 0, ipv6_packet(udp_proto, ports(53, 1)))).has_value());
    // Another upper-layer protocol, a later fragment, a truncated chain.
    EXPECT_FALSE(quoted_v6(icmp_message(icmpv6_unreachable, 0, ipv6_packet(icmpv6_proto, ports(53, 1)))).has_value());
    EXPECT_FALSE(quoted_v6(icmp_message(icmpv6_unreachable, 0,
        ipv6_packet(fragment_proto, concat({ fragment_header(udp_proto, 185, false), ports(53, 1) })))).has_value());
    EXPECT_FALSE(quoted_v6(icmp_message(icmpv6_unreachable, 0, ipv6_packet(udp_proto, {}))).has_value());
    EXPECT_FALSE(quoted_v6(icmp_message(icmpv6_unreachable, 0,
        ipv6_packet(fragment_proto, fragment_header(udp_proto, 0, true)))).has_value());
    // Not IPv6, or no data at all.
    auto not_v6 = icmp_message(icmpv6_unreachable, 0, ipv6_packet(udp_proto, ports(53, 1)));
    not_v6[8] = 0x45;
    EXPECT_FALSE(quoted_v6(not_v6).has_value());
    EXPECT_FALSE(proxy::icmpv6_error_quoted_source_port(nullptr, 100).has_value());
}

namespace
{
    std::optional<proxy::icmp_error_quote> quote_v4(const std::vector<uint8_t>& message)
    {
        return proxy::icmpv4_error_quote(message.data(), message.size());
    }

    std::optional<proxy::icmp_error_quote> quote_v6(const std::vector<uint8_t>& message)
    {
        return proxy::icmpv6_error_quote(message.data(), message.size());
    }

    /// A quoted UDP datagram from @p source to @p destination, both ports present.
    std::optional<proxy::icmp_error_quote> udp_quote(const uint16_t source, const uint16_t destination)
    {
        return proxy::icmp_error_quote{ udp_proto, source, destination };
    }

    /// The UDP redirect's view: which client ports have an active endpoint entry. Records the
    /// ports it was asked about, so a test can check that it is consulted only when needed.
    struct redirected_ports
    {
        std::vector<uint16_t> active;
        mutable std::vector<uint16_t> asked;

        bool operator()(const uint16_t port) const
        {
            asked.push_back(port);
            return std::ranges::find(active, port) != active.end();
        }
    };

    proxy::icmp_error_action decide(const proxy::dns_routing_mode mode,
        const std::optional<proxy::icmp_error_quote>& quote, const redirected_ports& redirect = {})
    {
        return proxy::decide_icmp_error(mode, quote, std::cref(redirect));
    }
}

TEST(DnsAnswerIcmpPolicy, OnlyErrorsAboutPort53AnswersAreDroppedAndOnlyInProxyMode)
{
    using proxy::icmp_error_action;

    EXPECT_EQ(decide(proxy_mode, udp_quote(53, 58440)), icmp_error_action::drop_dns_answer);
    EXPECT_EQ(decide(proxy_mode, proxy::icmp_error_quote{ tcp_proto, 53, 58440 }), icmp_error_action::drop_dns_answer);
    // Direct mode: the answer came from the real server, which may be told.
    EXPECT_EQ(decide(direct, udp_quote(53, 58440)), icmp_error_action::pass);
    // Other traffic, and messages that quote nothing usable, are never touched.
    EXPECT_EQ(decide(proxy_mode, udp_quote(443, 58440)), icmp_error_action::pass);
    EXPECT_EQ(decide(proxy_mode, udp_quote(5353, 58440)), icmp_error_action::pass);
    EXPECT_EQ(decide(proxy_mode, std::nullopt), icmp_error_action::pass);
    EXPECT_EQ(decide(direct, std::nullopt), icmp_error_action::pass);

    // End to end: a port-unreachable error about an answer, for both families.
    EXPECT_EQ(decide(proxy_mode,
        quote_v4(icmp_message(icmpv4_unreachable, icmpv4_port_unreachable, ipv4_packet(udp_proto, 0, ports(53, 58440))))),
        icmp_error_action::drop_dns_answer);
    EXPECT_EQ(decide(proxy_mode,
        quote_v6(icmp_message(icmpv6_unreachable, icmpv6_port_unreachable, ipv6_packet(udp_proto, ports(53, 58440))))),
        icmp_error_action::drop_dns_answer);
    // A ping whose data happens to look like a packet from port 53 is passed.
    EXPECT_EQ(decide(proxy_mode,
        quote_v4(icmp_message(icmpv4_echo_request, 0, ipv4_packet(udp_proto, 0, ports(53, 1))))),
        icmp_error_action::pass);
}

// ------------------------------------------------------------------ ICMP errors about proxied UDP replies
//
// A reply on a UDP flow the per-port UDP proxy redirected reaches the client presented as coming
// from the remote peer. If the client's socket has closed, the stack's ICMP error about it quotes
// the reply and is addressed to that peer, from the computer's own address. It must not leave the
// adapter, in either DNS mode.

TEST(ProxiedUdpIcmpPolicy, QuoteExposesBothPortsOfTheQuotedPacket)
{
    const auto v4 = quote_v4(icmp_message(icmpv4_unreachable, icmpv4_port_unreachable,
        ipv4_packet(udp_proto, 0, ports(443, 50001), { 1, 1, 1, 1 })));
    ASSERT_TRUE(v4.has_value());
    EXPECT_EQ(v4->protocol, udp_proto);
    EXPECT_EQ(v4->source_port, 443);
    EXPECT_EQ(v4->destination_port, std::optional<uint16_t>{ 50001 });

    const auto v6 = quote_v6(icmp_message(icmpv6_unreachable, icmpv6_port_unreachable,
        ipv6_packet(fragment_proto, concat({ fragment_header(udp_proto, 0, true), ports(3478, 50002) }))));
    ASSERT_TRUE(v6.has_value());
    EXPECT_EQ(v6->protocol, udp_proto);
    EXPECT_EQ(v6->source_port, 3478);
    EXPECT_EQ(v6->destination_port, std::optional<uint16_t>{ 50002 });

    const auto tcp = quote_v4(icmp_message(icmpv4_unreachable, 0, ipv4_packet(tcp_proto, 0, ports(80, 50003))));
    ASSERT_TRUE(tcp.has_value());
    EXPECT_EQ(tcp->protocol, tcp_proto);

    // A quote that ends between the ports has the source port only (it was enough for the DNS
    // rule before); the destination port is not guessed.
    const auto cut_v4 = quote_v4(icmp_message(icmpv4_unreachable, 0, ipv4_packet(udp_proto, 0, { 0x01, 0xbb })));
    ASSERT_TRUE(cut_v4.has_value());
    EXPECT_EQ(cut_v4->source_port, 443);
    EXPECT_FALSE(cut_v4->destination_port.has_value());
    const auto cut_v6 = quote_v6(icmp_message(icmpv6_unreachable, 0, ipv6_packet(udp_proto, { 0x01, 0xbb, 0xc3 })));
    ASSERT_TRUE(cut_v6.has_value());
    EXPECT_FALSE(cut_v6->destination_port.has_value());

    // The source-port helpers agree with the quote.
    const auto message = icmp_message(icmpv4_unreachable, 0, ipv4_packet(udp_proto, 0, ports(443, 50001)));
    EXPECT_EQ(proxy::icmpv4_error_quoted_source_port(message.data(), message.size()), std::optional<uint16_t>{ 443 });
}

TEST(ProxiedUdpIcmpPolicy, ErrorsAboutRepliesToRedirectedClientPortsAreDroppedInEitherMode)
{
    using proxy::icmp_error_action;
    const redirected_ports redirect{ { 50001, 50002 }, {} };

    for (const auto mode : { direct, proxy_mode })
    {
        EXPECT_EQ(decide(mode, udp_quote(443, 50001), redirect), icmp_error_action::drop_proxied_udp_reply);
        EXPECT_EQ(decide(mode, udp_quote(3478, 50002), redirect), icmp_error_action::drop_proxied_udp_reply);
        // A client port without an active redirect entry: its traffic was not proxied.
        EXPECT_EQ(decide(mode, udp_quote(443, 50003), redirect), icmp_error_action::pass);
    }

    // End to end, for both families, with any error type (not only port unreachable).
    EXPECT_EQ(decide(direct, quote_v4(icmp_message(icmpv4_unreachable, icmpv4_port_unreachable,
        ipv4_packet(udp_proto, 0, ports(443, 50001)))), redirect), icmp_error_action::drop_proxied_udp_reply);
    EXPECT_EQ(decide(direct, quote_v4(icmp_message(12, 0, ipv4_packet(udp_proto, 0, ports(443, 50001)))), redirect),
        icmp_error_action::drop_proxied_udp_reply);
    EXPECT_EQ(decide(direct, quote_v6(icmp_message(icmpv6_unreachable, icmpv6_port_unreachable,
        ipv6_packet(udp_proto, ports(443, 50002)))), redirect), icmp_error_action::drop_proxied_udp_reply);
    EXPECT_EQ(decide(direct, quote_v6(icmp_message(4, 0, ipv6_packet(udp_proto, ports(443, 50002)))), redirect),
        icmp_error_action::drop_proxied_udp_reply);

    // In Proxy mode an answer from port 53 is reported as a DNS answer whatever the redirect says.
    EXPECT_EQ(decide(proxy_mode, udp_quote(53, 50001), redirect), icmp_error_action::drop_dns_answer);
    // In Direct mode a proxied flow's reply from port 53 is still a proxied UDP reply.
    EXPECT_EQ(decide(direct, udp_quote(53, 50001), redirect), icmp_error_action::drop_proxied_udp_reply);
}

TEST(ProxiedUdpIcmpPolicy, OtherIcmpIsPassedAndTheRedirectIsConsultedOnlyForQuotedUdp)
{
    using proxy::icmp_error_action;
    const redirected_ports redirect{ { 50001 }, {} };

    // Ping and neighbor discovery whose data looks like a reply to a redirected port.
    EXPECT_EQ(decide(direct, quote_v4(icmp_message(icmpv4_echo_request, 0, ipv4_packet(udp_proto, 0, ports(443, 50001)))),
        redirect), icmp_error_action::pass);
    EXPECT_EQ(decide(direct, quote_v4(icmp_message(icmpv4_echo_reply, 0, ipv4_packet(udp_proto, 0, ports(443, 50001)))),
        redirect), icmp_error_action::pass);
    EXPECT_EQ(decide(direct, quote_v6(icmp_message(icmpv6_echo_request, 0, ipv6_packet(udp_proto, ports(443, 50001)))),
        redirect), icmp_error_action::pass);
    EXPECT_EQ(decide(direct, quote_v6(icmp_message(135, 0, ipv6_packet(udp_proto, ports(443, 50001)))), redirect),
        icmp_error_action::pass);
    // A TCP segment to the same port: the UDP redirect does not describe it (proxied TCP is
    // answered with a reset, not an ICMP error).
    EXPECT_EQ(decide(direct, proxy::icmp_error_quote{ tcp_proto, 443, 50001 }, redirect), icmp_error_action::pass);
    // A later fragment, or a quote cut before the destination port.
    EXPECT_EQ(decide(direct, quote_v4(icmp_message(icmpv4_unreachable, 0, ipv4_packet(udp_proto, 185, ports(443, 50001)))),
        redirect), icmp_error_action::pass);
    EXPECT_EQ(decide(direct, quote_v4(icmp_message(icmpv4_unreachable, 0, ipv4_packet(udp_proto, 0, { 0x01, 0xbb }))),
        redirect), icmp_error_action::pass);
    EXPECT_EQ(decide(direct, proxy::icmp_error_quote{ udp_proto, 443, std::nullopt }, redirect), icmp_error_action::pass);
    // A quoted datagram that the redirected port sent rather than received: the port to look up
    // is the quoted destination (here the peer's 443), not the source.
    EXPECT_EQ(decide(direct, udp_quote(50001, 443), redirect), icmp_error_action::pass);

    // Only that last quote, UDP with both ports, consulted the redirect; ping, neighbor
    // discovery, TCP and cut quotes never take its lock.
    EXPECT_EQ(redirect.asked, (std::vector<uint16_t>{ 443 }));

    // The DNS rule decides without consulting the redirect.
    const redirected_ports untouched{ { 50001 }, {} };
    EXPECT_EQ(decide(proxy_mode, udp_quote(53, 50001), untouched), icmp_error_action::drop_dns_answer);
    EXPECT_TRUE(untouched.asked.empty());
}

TEST(IcmpErrorFilterPlan, OutboundIcmpIsKeptInUserModeForDnsProxyModeAndForEachFamilyWithProxiedUdp)
{
    const std::vector<dns_family> none, v4_only{ dns_family::ipv4 }, v6_only{ dns_family::ipv6 },
        both{ dns_family::ipv4, dns_family::ipv6 };

    // No UDP is proxied: only DNS Proxy mode needs ICMP in user mode, for both families.
    EXPECT_EQ(proxy::plan_icmp_error_filters(direct, false, false), none);
    EXPECT_EQ(proxy::plan_icmp_error_filters(proxy_mode, false, false), both);
    // A UDP listener of a family needs that family's ICMP in either mode.
    EXPECT_EQ(proxy::plan_icmp_error_filters(direct, true, false), v4_only);
    EXPECT_EQ(proxy::plan_icmp_error_filters(direct, false, true), v6_only);
    EXPECT_EQ(proxy::plan_icmp_error_filters(direct, true, true), both);
    EXPECT_EQ(proxy::plan_icmp_error_filters(proxy_mode, true, false), both);
    EXPECT_EQ(proxy::plan_icmp_error_filters(proxy_mode, false, true), both);
}
