// Global DNS routing policy (dns_routing_policy.h).
//
// These are the decisions socks_local_router's IPv4/IPv6 UDP/TCP packet handlers apply to every
// outbound packet before process attribution: Direct mode passes port-53 traffic, Proxy mode
// redirects it to the selected proxy's listener or blocks it (never passes it), ProxiFyre's own
// upstream traffic is never captured, and non-DNS traffic keeps its ordinary routing. They also
// cover the DNS server override syntax and the bookkeeping that restores override answers to
// the server the resolver originally queried.
//
// The header has no Windows dependencies, so this file also builds outside the Windows test
// project (see netlib/test/portable/run-portable-tests.sh).

#include "pch.h"
#include "../../src/proxy/dns_routing_policy.h"

#include <set>
#include <thread>
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

// 3./4. The decision has no process input: queries from the Windows DNS Client service
//       (svchost.exe), from an application with its own resolver, from an excluded application,
//       or from an owner that cannot be resolved are all decided by port 53 and the global mode.
TEST(DnsRoutingPolicy, DecisionDoesNotDependOnTheSendingProcess)
{
    const dns_proxy p{};
    const auto target = p.target(dns_transport::udp, dns_family::ipv4);
    const auto expected = decide_dns_route(proxy_mode, dns_port, apply, target);

    // The only inputs are the mode, the destination port, the upstream guard, and the proxy.
    // Calling the decision repeatedly (as each sender would) yields the same result.
    for (int sender = 0; sender < 4; ++sender)
    {
        const auto decision = decide_dns_route(proxy_mode, dns_port, apply, target);
        EXPECT_EQ(decision.action, expected.action);
        EXPECT_EQ(decision.listener_port, expected.listener_port);
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

// 14. A resolver that receives a truncated UDP answer retries over TCP to the same server. Both
//     queries are routed through the same proxy, each through its own transport's listener.
TEST(DnsRoutingPolicy, TruncatedUdpAnswerTcpRetryUsesTheSameProxy)
{
    dns_proxy p{};
    p.server_override = dns_family::ipv4;

    const auto udp = decide_dns_route(proxy_mode, dns_port, apply, p.target(dns_transport::udp, dns_family::ipv4));
    const auto tcp = decide_dns_route(proxy_mode, dns_port, apply, p.target(dns_transport::tcp, dns_family::ipv4));
    EXPECT_EQ(udp.action, dns_route_action::proxy);
    EXPECT_EQ(tcp.action, dns_route_action::proxy);
    EXPECT_EQ(udp.listener_port, p.udp4);
    EXPECT_EQ(tcp.listener_port, p.tcp4);
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

namespace
{
    struct endpoint
    {
        std::string address;
        uint16_t port{};
        bool operator==(const endpoint&) const = default;
    };

    using tracker = proxy::dns_udp_origin_tracker<endpoint>;
    using clock = tracker::clock;
}

// 6./7. Answers relayed from the override are mapped back to the original (often private) server
//       by client port and DNS message ID.
TEST(DnsUdpOriginTracker, MapsOverrideAnswersToTheOriginalServer)
{
    tracker origins;
    const auto now = clock::now();

    origins.remember(50001, 0x1234, { "192.168.1.1", 53 }, now);
    origins.remember(50001, 0x9999, { "10.0.0.53", 53 }, now);
    origins.remember(50002, 0x1234, { "fd00::53", 53 }, now);

    EXPECT_EQ(origins.resolve(50001, 0x1234, now), (endpoint{ "192.168.1.1", 53 }));
    EXPECT_EQ(origins.resolve(50001, 0x9999, now), (endpoint{ "10.0.0.53", 53 }));
    EXPECT_EQ(origins.resolve(50002, 0x1234, now), (endpoint{ "fd00::53", 53 }));

    // Unknown query: no mapping (the router drops such an answer).
    EXPECT_FALSE(origins.resolve(50003, 0x1234, now).has_value());
    EXPECT_FALSE(origins.resolve(50001, 0x4321, now).has_value());

    // A lookup does not consume the entry: duplicate answers to a retransmitted query are
    // restored consistently.
    EXPECT_EQ(origins.resolve(50001, 0x1234, now), (endpoint{ "192.168.1.1", 53 }));

    // A retransmission to another server with the same port and ID updates the mapping.
    origins.remember(50001, 0x1234, { "192.168.1.2", 53 }, now);
    EXPECT_EQ(origins.resolve(50001, 0x1234, now), (endpoint{ "192.168.1.2", 53 }));
}

TEST(DnsUdpOriginTracker, EntriesExpire)
{
    tracker origins{ std::chrono::seconds{ 30 } };
    const auto start = clock::now();
    origins.remember(50001, 1, { "192.168.1.1", 53 }, start);
    origins.remember(50002, 2, { "192.168.1.1", 53 }, start + std::chrono::seconds{ 20 });

    EXPECT_TRUE(origins.resolve(50001, 1, start + std::chrono::seconds{ 30 }).has_value());
    EXPECT_FALSE(origins.resolve(50001, 1, start + std::chrono::seconds{ 31 }).has_value());

    origins.sweep(start + std::chrono::seconds{ 45 });
    EXPECT_EQ(origins.size(), 1u);
    origins.sweep(start + std::chrono::seconds{ 60 });
    EXPECT_EQ(origins.size(), 0u);

    origins.remember(50003, 3, { "192.168.1.1", 53 }, start);
    origins.clear();
    EXPECT_EQ(origins.size(), 0u);
}

TEST(DnsUdpOriginTracker, IsBoundedAndEvictsTheOldestLiveEntry)
{
    tracker origins{ std::chrono::seconds{ 30 }, 3 };
    const auto start = clock::now();
    origins.remember(1, 1, { "a", 53 }, start);
    origins.remember(2, 1, { "b", 53 }, start + std::chrono::milliseconds{ 1 });
    origins.remember(3, 1, { "c", 53 }, start + std::chrono::milliseconds{ 2 });
    origins.remember(4, 1, { "d", 53 }, start + std::chrono::milliseconds{ 3 });

    EXPECT_EQ(origins.size(), 3u);
    EXPECT_FALSE(origins.resolve(1, 1, start + std::chrono::milliseconds{ 4 }).has_value());
    EXPECT_TRUE(origins.resolve(4, 1, start + std::chrono::milliseconds{ 4 }).has_value());

    // Expired entries are reclaimed before a live entry is evicted.
    origins.remember(5, 1, { "e", 53 }, start + std::chrono::seconds{ 40 });
    EXPECT_EQ(origins.size(), 1u);
}

TEST(DnsUdpOriginTracker, IsSafeForConcurrentPacketAndMaintenanceThreads)
{
    tracker origins{ std::chrono::seconds{ 30 }, 4096 };
    std::vector<std::thread> threads;
    for (uint16_t t = 0; t < 4; ++t)
    {
        threads.emplace_back([&origins, t]
        {
            for (uint16_t i = 0; i < 2000; ++i)
            {
                const auto port = static_cast<uint16_t>(10000 + t * 2000 + i);
                origins.remember(port, i, { "server", 53 });
                EXPECT_TRUE(origins.resolve(port, i).has_value());
                if (i % 100 == 0)
                    origins.sweep();
            }
        });
    }
    for (auto& thread : threads)
        thread.join();

    EXPECT_LE(origins.size(), 4096u);
}

// 1. Packets sourced from a local proxy listener are re-injected when translated and dropped
//    otherwise; they are never passed to the wire. Other packets continue with normal routing.
TEST(ListenerReplyPolicy, UntranslatedListenerRepliesAreDroppedNeverPassed)
{
    using proxy::decide_listener_reply;
    using proxy::listener_reply_action;

    EXPECT_EQ(decide_listener_reply(true, true), listener_reply_action::revert);
    EXPECT_EQ(decide_listener_reply(true, false), listener_reply_action::drop);
    EXPECT_EQ(decide_listener_reply(false, false), listener_reply_action::not_listener);
    EXPECT_EQ(decide_listener_reply(false, true), listener_reply_action::not_listener);
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

// 9. Listener replies need DNS work (and lock_) only in Proxy mode with a usable proxy and an override.
TEST(DnsReplyRestore, NeededOnlyInProxyModeWithAnOverride)
{
    using proxy::dns_reply_restore_needed;
    EXPECT_TRUE(dns_reply_restore_needed(proxy_mode, true, true));
    EXPECT_FALSE(dns_reply_restore_needed(proxy_mode, true, false));
    EXPECT_FALSE(dns_reply_restore_needed(proxy_mode, false, true));
    EXPECT_FALSE(dns_reply_restore_needed(direct, true, true));
    EXPECT_FALSE(dns_reply_restore_needed(direct, false, false));
}

// 10. Eviction uses insertion order: a refreshed key is not the oldest, the queue of insertion
//     records stays bounded under repeated refreshes, and inserting into a full table is cheap.
TEST(DnsUdpOriginTracker, RefreshedKeysAreEvictedByTheirLatestTime)
{
    tracker origins{ std::chrono::seconds{ 30 }, 2 };
    const auto start = clock::now();
    origins.remember(1, 1, { "a", 53 }, start);
    origins.remember(2, 1, { "b", 53 }, start + std::chrono::milliseconds{ 1 });
    origins.remember(1, 1, { "a2", 53 }, start + std::chrono::milliseconds{ 2 }); // refresh: now newest
    origins.remember(3, 1, { "c", 53 }, start + std::chrono::milliseconds{ 3 });  // evicts key 2

    const auto at = start + std::chrono::milliseconds{ 4 };
    EXPECT_EQ(origins.resolve(1, 1, at), (endpoint{ "a2", 53 }));
    EXPECT_FALSE(origins.resolve(2, 1, at).has_value());
    EXPECT_TRUE(origins.resolve(3, 1, at).has_value());
    EXPECT_EQ(origins.size(), 2u);
}

TEST(DnsUdpOriginTracker, InsertionRecordsStayBoundedUnderRepeatedRefreshes)
{
    constexpr std::size_t capacity = 64;
    tracker origins{ std::chrono::seconds{ 30 }, capacity };
    const auto start = clock::now();
    for (int i = 0; i < 100000; ++i)
        origins.remember(static_cast<uint16_t>(i % 8), 7, { "x", 53 }, start + std::chrono::microseconds{ i });

    EXPECT_EQ(origins.size(), 8u);
    EXPECT_LE(origins.order_records(), 2 * capacity + 16);
    for (uint16_t port = 0; port < 8; ++port)
        EXPECT_TRUE(origins.resolve(port, 7, start + std::chrono::seconds{ 1 }).has_value());
}

TEST(DnsUdpOriginTracker, InsertingIntoAFullTableOfLiveEntriesIsCheap)
{
    constexpr std::size_t capacity = 8192;
    tracker origins{ std::chrono::seconds{ 30 }, capacity };
    const auto start = clock::now();

    // 200k inserts with the table permanently full of live entries. With a linear scan per
    // insert this is ~1.6e9 entry visits; with insertion-order eviction it is linear overall.
    const auto timer = std::chrono::steady_clock::now();
    for (uint32_t i = 0; i < 200000; ++i)
        origins.remember(static_cast<uint16_t>(i >> 16), static_cast<uint16_t>(i), { "s", 53 },
            start + std::chrono::microseconds{ i });
    const auto elapsed = std::chrono::steady_clock::now() - timer;

    EXPECT_EQ(origins.size(), capacity);
    EXPECT_LE(origins.order_records(), 2 * capacity + 16);
    // The newest entries survive, the oldest are evicted.
    EXPECT_TRUE(origins.resolve(3, static_cast<uint16_t>(199999 & 0xffff), start + std::chrono::seconds{ 1 }).has_value());
    EXPECT_FALSE(origins.resolve(0, 0, start + std::chrono::seconds{ 1 }).has_value());
    // Measured on the portable runner: ~10 ms with insertion-order eviction, ~6.7 s with the
    // earlier per-insert sweep and linear search for the oldest entry. The bound leaves two
    // orders of magnitude of headroom for slow or sanitized builds and still fails the latter.
    EXPECT_LT(elapsed, std::chrono::seconds{ 2 });
}
