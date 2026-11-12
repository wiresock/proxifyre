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
        EXPECT_EQ(decide_dns_route(direct, dns_port, false, configured.target(c.transport, c.family)).action,
            dns_route_action::pass);
        // No proxy selected at all: Direct still passes.
        EXPECT_EQ(decide_dns_route(direct, dns_port, false, dns_proxy_target{}).action, dns_route_action::pass);
    }
}

// 2. Proxy mode: UDP DNS uses the UDP listener, TCP DNS the TCP listener, per address family.
TEST(DnsRoutingPolicy, ProxyModeRedirectsToTheListenerOfTheTransportAndFamily)
{
    const dns_proxy p{};
    const auto udp4 = decide_dns_route(proxy_mode, dns_port, false, p.target(dns_transport::udp, dns_family::ipv4));
    const auto udp6 = decide_dns_route(proxy_mode, dns_port, false, p.target(dns_transport::udp, dns_family::ipv6));
    const auto tcp4 = decide_dns_route(proxy_mode, dns_port, false, p.target(dns_transport::tcp, dns_family::ipv4));
    const auto tcp6 = decide_dns_route(proxy_mode, dns_port, false, p.target(dns_transport::tcp, dns_family::ipv6));

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
    const auto expected = decide_dns_route(proxy_mode, dns_port, false, target);

    // The only inputs are the mode, the destination port, the upstream guard, and the proxy.
    // Calling the decision repeatedly (as each sender would) yields the same result.
    for (int sender = 0; sender < 4; ++sender)
    {
        const auto decision = decide_dns_route(proxy_mode, dns_port, false, target);
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
        const auto d = decide_dns_route(proxy_mode, dns_port, false, dns_proxy_target{});
        EXPECT_EQ(d.action, dns_route_action::block);
        EXPECT_EQ(d.reason, dns_block_reason::proxy_unavailable);
    }

    // The proxy lacks the transport (unsupported protocol combination).
    dns_proxy tcp_only{};
    tcp_only.udp = false;
    auto d = decide_dns_route(proxy_mode, dns_port, false, tcp_only.target(dns_transport::udp, dns_family::ipv4));
    EXPECT_EQ(d.action, dns_route_action::block);
    EXPECT_EQ(d.reason, dns_block_reason::transport_unsupported);

    // The proxy does not accept IPv6 destinations.
    dns_proxy v4_only{};
    v4_only.ipv6 = false;
    d = decide_dns_route(proxy_mode, dns_port, false, v4_only.target(dns_transport::tcp, dns_family::ipv6));
    EXPECT_EQ(d.action, dns_route_action::block);
    EXPECT_EQ(d.reason, dns_block_reason::family_unsupported);

    // The listener is not running (for example the IPv6 listener failed to start).
    dns_proxy no_v6_listener{};
    no_v6_listener.udp6 = 0;
    d = decide_dns_route(proxy_mode, dns_port, false, no_v6_listener.target(dns_transport::udp, dns_family::ipv6));
    EXPECT_EQ(d.action, dns_route_action::block);
    EXPECT_EQ(d.reason, dns_block_reason::listener_unavailable);

    // A missing listener port value and an explicit zero are both unusable.
    auto target = dns_proxy{}.target(dns_transport::udp, dns_family::ipv4);
    target.listener_port = std::nullopt;
    EXPECT_EQ(decide_dns_route(proxy_mode, dns_port, false, target).action, dns_route_action::block);
}

// 6. A server override applies to queries of its own family; queries of the other family are
//    blocked rather than sent to their original (often local) server.
TEST(DnsRoutingPolicy, ServerOverrideFamilyIsHandledExplicitly)
{
    dns_proxy with_v4_override{};
    with_v4_override.server_override = dns_family::ipv4;

    for (const auto transport : { dns_transport::udp, dns_transport::tcp })
    {
        EXPECT_EQ(decide_dns_route(proxy_mode, dns_port, false, with_v4_override.target(transport, dns_family::ipv4)).action,
            dns_route_action::proxy);

        const auto other = decide_dns_route(proxy_mode, dns_port, false, with_v4_override.target(transport, dns_family::ipv6));
        EXPECT_EQ(other.action, dns_route_action::block);
        EXPECT_EQ(other.reason, dns_block_reason::override_family_mismatch);
    }

    dns_proxy with_v6_override{};
    with_v6_override.server_override = dns_family::ipv6;
    EXPECT_EQ(decide_dns_route(proxy_mode, dns_port, false, with_v6_override.target(dns_transport::udp, dns_family::ipv6)).action,
        dns_route_action::proxy);
    EXPECT_EQ(decide_dns_route(proxy_mode, dns_port, false, with_v6_override.target(dns_transport::udp, dns_family::ipv4)).action,
        dns_route_action::block);
}

// 11. Recursion prevention: ProxiFyre's own traffic to an upstream SOCKS5 server (even one
//     listening on port 53) is never redirected into the DNS proxy.
TEST(DnsRoutingPolicy, UpstreamProxyTrafficIsNeverCaptured)
{
    const dns_proxy p{};
    for (const auto& c : all_cases)
    {
        EXPECT_EQ(decide_dns_route(proxy_mode, dns_port, true, p.target(c.transport, c.family)).action,
            dns_route_action::pass);
        EXPECT_EQ(decide_dns_route(proxy_mode, dns_port, true, dns_proxy_target{}).action, dns_route_action::pass);
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
            EXPECT_EQ(decide_dns_route(mode, port, false, p.target(dns_transport::udp, dns_family::ipv4)).action,
                dns_route_action::not_dns) << port;
            EXPECT_EQ(decide_dns_route(mode, port, true, dns_proxy_target{}).action, dns_route_action::not_dns) << port;
        }
    }
}

// 14. A resolver that receives a truncated UDP answer retries over TCP to the same server. Both
//     queries are routed through the same proxy, each through its own transport's listener.
TEST(DnsRoutingPolicy, TruncatedUdpAnswerTcpRetryUsesTheSameProxy)
{
    dns_proxy p{};
    p.server_override = dns_family::ipv4;

    const auto udp = decide_dns_route(proxy_mode, dns_port, false, p.target(dns_transport::udp, dns_family::ipv4));
    const auto tcp = decide_dns_route(proxy_mode, dns_port, false, p.target(dns_transport::tcp, dns_family::ipv4));
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
