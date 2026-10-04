// Routing decisions on owners shared within one captured connection table.
//
// Owners come from process_lookup's production table builds (fake_ownership_source.h); the
// decisions come from the production routing helpers socks_local_router's packet handlers use
// (process_routing_policy.h): route_owner() for the cached exclusion/bypass state and the IPv4
// optional proxy ports, select_proxy_port() and match_owner_to_app() for proxy selection,
// exclusions, family blocking, and limited-mode handling of unresolved owners. The fixture
// supplies only configuration: application patterns, exclusions, and what each proxy offers.
//
// An owner is shared by every connection of its (PID, service tag) within one capture. Its
// cached routing state must therefore follow the identity within that capture and never reach
// another capture, protocol table, address family, or lookup instance.

#include "pch.h"
#include "../iphelper/fake_ownership_source.h"

namespace
{
    using namespace netlib_test::ownership;
    using proxy::owner_family;
    using proxy::owner_transport;
    using proxy::proxy_port_action;
    using proxy::proxy_port_result;

    /// One configured proxy: transports, destination families, and its local listeners.
    struct proxy_offer
    {
        bool tcp{ true };
        bool udp{ true };
        bool ipv4{ true };
        bool ipv6{ true };
        uint16_t tcp4_port{ 40001 };
        uint16_t udp4_port{ 40002 };
        uint16_t tcp6_port{ 40003 };
        uint16_t udp6_port{ 40004 };
    };

    struct routing_config
    {
        std::multimap<size_t, std::wstring> proxy_to_names;
        std::vector<std::wstring> excluded;
        bool bypass_unresolved{ false };
        std::vector<proxy_offer> proxies;

        [[nodiscard]] proxy::owner_match_rules rules() const
        {
            return { proxy_to_names, excluded, bypass_unresolved, ::GetCurrentProcessId() };
        }

        template <owner_transport Transport, owner_family Family>
        [[nodiscard]] proxy::proxy_route_target target(const size_t proxy_id) const
        {
            const auto& p = proxies.at(proxy_id);
            constexpr bool tcp = Transport == owner_transport::tcp;
            constexpr bool v4 = Family == owner_family::ipv4;
            const uint16_t port = tcp ? (v4 ? p.tcp4_port : p.tcp6_port) : (v4 ? p.udp4_port : p.udp6_port);
            return { tcp ? p.tcp : p.udp, v4 ? p.ipv4 : p.ipv6,
                port ? std::optional<uint16_t>{ port } : std::nullopt };
        }

        /// The handler's owner decision for one packet of @p owner.
        template <owner_transport Transport, owner_family Family>
        [[nodiscard]] proxy_port_result route(const process_ptr& owner) const
        {
            EXPECT_TRUE(owner);
            if (!owner)
                return {};
            return proxy::route_owner<Transport, Family>(*owner, [&]
            {
                return proxy::select_proxy_port(rules(), *owner,
                    [this](const size_t id) { return target<Transport, Family>(id); });
            });
        }
    };

    constexpr auto tcp = owner_transport::tcp;
    constexpr auto udp = owner_transport::udp;
    constexpr auto ipv4 = owner_family::ipv4;
    constexpr auto ipv6 = owner_family::ipv6;

    void expect_route(const proxy_port_result& r, const proxy_port_action action, const uint16_t port = 0)
    {
        EXPECT_EQ(r.action, action);
        if (action == proxy_port_action::proxy)
            EXPECT_EQ(r.port, port);
    }

    void expect_untouched(const process_ptr& owner)
    {
        ASSERT_TRUE(owner);
        EXPECT_FALSE(owner->excluded);
        EXPECT_FALSE(owner->bypass_tcp);
        EXPECT_FALSE(owner->bypass_udp);
    }

    class OwnerRoutingPolicyTest : public fake_os_fixture
    {
    protected:
        static process_ptr tcp4(lookup_v4& l, const uint16_t port)
        {
            return l.lookup_process_for_tcp<false>(session4("10.0.0.1", port, "10.9.9.9", 443));
        }

        static process_ptr udp4(lookup_v4& l, const uint16_t port)
        {
            return l.lookup_process_for_udp<false>(endpoint4("10.0.0.1", port));
        }

        static process_ptr tcp6(lookup_v6& l, const uint16_t port)
        {
            return l.lookup_process_for_tcp<false>(session6("2001:db8::1", port, "2001:db8::9", 443));
        }

        static process_ptr udp6(lookup_v6& l, const uint16_t port)
        {
            return l.lookup_process_for_udp<false>(endpoint6("2001:db8::1", port));
        }

        /// (pid) owns native TCP/UDP rows of both families on ports [base, base + count).
        void add_everywhere(const DWORD pid, const uint16_t base, const uint16_t count = 10)
        {
            for (uint16_t i = 0; i < count; ++i)
            {
                const auto port = static_cast<uint16_t>(base + i);
                os().tcp4.push_back(tcp4_row(pid, 0, "10.0.0.1", port, "10.9.9.9", 443));
                os().udp4.push_back(udp4_row(pid, 0, "10.0.0.1", port));
                os().tcp6.push_back(tcp6_row(pid, 0, "2001:db8::1", port, "2001:db8::9", 443));
                os().udp6.push_back(udp6_row(pid, 0, "2001:db8::1", port));
            }
        }
    };

    // ------------------------------------------------------------------------------------

    TEST_F(OwnerRoutingPolicyTest, SharedOwnerCarriesOneDecisionForAllItsConnections)
    {
        os().images[3000] = image(L"APP.EXE");
        os().images[3001] = image(L"OTHER.EXE");
        add_everywhere(3000, 1000, 20);
        add_everywhere(3001, 2000, 20);
        lookup_v4 l4;

        routing_config config;
        config.proxies.push_back({});
        config.proxy_to_names.emplace(0, L"APP.EXE");

        const auto app = tcp4(l4, 1000);
        const auto other = tcp4(l4, 2000);
        ASSERT_TRUE(app && other);
        for (uint16_t i = 0; i < 20; ++i)
        {
            EXPECT_EQ(tcp4(l4, static_cast<uint16_t>(1000 + i)), app) << "connections of one identity share an owner";
            EXPECT_EQ(tcp4(l4, static_cast<uint16_t>(2000 + i)), other);
            expect_route(config.route<tcp, ipv4>(tcp4(l4, static_cast<uint16_t>(1000 + i))), proxy_port_action::proxy, 40001);
            expect_route(config.route<tcp, ipv4>(tcp4(l4, static_cast<uint16_t>(2000 + i))), proxy_port_action::none);
        }

        EXPECT_FALSE(app->bypass_tcp);
        EXPECT_TRUE(other->bypass_tcp) << "the unmatched identity bypasses TCP";
        EXPECT_FALSE(other->bypass_udp) << "TCP bypass does not mark UDP";
        expect_untouched(udp4(l4, 2000));
    }

    TEST_F(OwnerRoutingPolicyTest, ExclusionIsConfinedToTheExcludedIdentityInItsCapture)
    {
        os().images[3100] = image(L"BLOCKED.EXE");
        os().images[3101] = image(L"APP.EXE");
        add_everywhere(3100, 1000);
        add_everywhere(3101, 2000);
        os().tcp6.push_back(tcp6_row(3100, 0, "::ffff:10.0.0.1", 3000, "::ffff:10.9.9.9", 443)); // mapped
        lookup_v4 l4;
        lookup_v6 l6;

        routing_config config;
        config.proxies.push_back({});
        config.proxy_to_names.emplace(0, L"");     // catch-all
        config.excluded.push_back(L"BLOCKED");

        const auto blocked = tcp4(l4, 1000);
        expect_route(config.route<tcp, ipv4>(blocked), proxy_port_action::none);
        EXPECT_TRUE(blocked->excluded);
        for (uint16_t i = 1; i < 10; ++i)
            expect_route(config.route<tcp, ipv4>(tcp4(l4, static_cast<uint16_t>(1000 + i))), proxy_port_action::none);

        // The same identity in other captures, protocols, and families has its own owner, whose
        // state is decided when its own traffic is routed.
        const auto blocked_mapped = tcp4(l4, 3000);
        ASSERT_TRUE(blocked_mapped);
        EXPECT_EQ(blocked_mapped->name, L"BLOCKED.EXE");
        for (const auto& owner : { udp4(l4, 1000), blocked_mapped, process_ptr{ tcp6(l6, 1000) }, process_ptr{ udp6(l6, 1000) } })
        {
            EXPECT_NE(owner, blocked);
            expect_untouched(owner);
        }
        expect_route(config.route<udp, ipv4>(udp4(l4, 1000)), proxy_port_action::none);
        expect_route(config.route<tcp, ipv4>(blocked_mapped), proxy_port_action::none);
        expect_route(config.route<tcp, ipv6>(tcp6(l6, 1000)), proxy_port_action::none);

        // Other identities are unaffected.
        for (uint16_t i = 0; i < 10; ++i)
            expect_route(config.route<tcp, ipv4>(tcp4(l4, static_cast<uint16_t>(2000 + i))), proxy_port_action::proxy, 40001);
        EXPECT_FALSE(tcp4(l4, 2000)->excluded);
    }

    TEST_F(OwnerRoutingPolicyTest, TransportBypassStaysWithItsProtocolTable)
    {
        os().images[3200] = image(L"APP.EXE");
        add_everywhere(3200, 1000);
        lookup_v4 l4;
        lookup_v6 l6;

        routing_config config;
        proxy_offer udp_only;
        udp_only.tcp = false;
        config.proxies.push_back(udp_only);
        config.proxy_to_names.emplace(0, L"APP.EXE");

        const auto tcp_owner = tcp4(l4, 1000);
        const auto udp_owner = udp4(l4, 1000);
        ASSERT_NE(tcp_owner, udp_owner);

        for (uint16_t i = 0; i < 10; ++i)
            expect_route(config.route<tcp, ipv4>(tcp4(l4, static_cast<uint16_t>(1000 + i))), proxy_port_action::none);
        EXPECT_TRUE(tcp_owner->bypass_tcp);

        expect_untouched(udp_owner);
        for (uint16_t i = 0; i < 10; ++i)
            expect_route(config.route<udp, ipv4>(udp4(l4, static_cast<uint16_t>(1000 + i))), proxy_port_action::proxy, 40002);
        EXPECT_FALSE(udp_owner->bypass_udp);
        EXPECT_FALSE(udp_owner->bypass_tcp);

        expect_untouched(tcp6(l6, 1000));
        expect_route(config.route<udp, ipv6>(udp6(l6, 1000)), proxy_port_action::proxy, 40004);
    }

    TEST_F(OwnerRoutingPolicyTest, FamilyBlockDropsWithoutCachingState)
    {
        os().images[3300] = image(L"APP.EXE");
        add_everywhere(3300, 1000);
        lookup_v4 l4;
        lookup_v6 l6;

        routing_config config;
        proxy_offer ipv4_only;
        ipv4_only.ipv6 = false;
        config.proxies.push_back(ipv4_only);
        config.proxy_to_names.emplace(0, L"APP.EXE");

        for (int repeat = 0; repeat < 2; ++repeat)
        {
            for (uint16_t i = 0; i < 10; ++i)
            {
                const auto port = static_cast<uint16_t>(1000 + i);
                expect_route(config.route<tcp, ipv6>(tcp6(l6, port)), proxy_port_action::block);
                expect_route(config.route<udp, ipv6>(udp6(l6, port)), proxy_port_action::block);
                expect_route(config.route<tcp, ipv4>(tcp4(l4, port)), proxy_port_action::proxy, 40001);
                expect_route(config.route<udp, ipv4>(udp4(l4, port)), proxy_port_action::proxy, 40002);
            }
        }
        for (const auto& owner : { tcp6(l6, 1000), udp6(l6, 1000), process_ptr{ tcp4(l4, 1000) }, process_ptr{ udp4(l4, 1000) } })
            expect_untouched(owner);
    }

    TEST_F(OwnerRoutingPolicyTest, OptionalProxyPortIsConfinedToItsOwnerObject)
    {
        os().images[3400] = image(L"APP.EXE");
        add_everywhere(3400, 1000);
        os().tcp6.push_back(tcp6_row(3400, 0, "::ffff:10.0.0.1", 3000, "::ffff:10.9.9.9", 443)); // mapped
        lookup_v4 l4;
        lookup_v6 l6;

        routing_config config; // no application matches: selection alone is none
        config.proxies.push_back({});

        // Production code does not assign the optional ports; a preassigned one is honored by
        // the IPv4 handlers for the owner object that carries it.
        const auto owner = tcp4(l4, 1000);
        owner->tcp_proxy_port = 41000;

        for (uint16_t i = 0; i < 10; ++i)
            expect_route(config.route<tcp, ipv4>(tcp4(l4, static_cast<uint16_t>(1000 + i))), proxy_port_action::proxy, 41000);
        EXPECT_FALSE(owner->bypass_tcp);

        const auto mapped = tcp4(l4, 3000);
        ASSERT_TRUE(mapped);
        EXPECT_NE(mapped, owner) << "the supplement capture has its own owner";
        EXPECT_FALSE(mapped->tcp_proxy_port.has_value());
        expect_route(config.route<tcp, ipv4>(mapped), proxy_port_action::none);

        EXPECT_FALSE(udp4(l4, 1000)->udp_proxy_port.has_value());
        expect_route(config.route<udp, ipv4>(udp4(l4, 1000)), proxy_port_action::none);

        const auto owner6 = tcp6(l6, 1000);
        owner6->tcp_proxy_port = 41001;
        // The IPv6 handlers do not consult the optional port.
        expect_route(config.route<tcp, ipv6>(owner6), proxy_port_action::none);

        ASSERT_TRUE(l4.actualize(true, false));
        const auto refreshed = tcp4(l4, 1000);
        ASSERT_TRUE(refreshed);
        EXPECT_NE(refreshed, owner);
        EXPECT_FALSE(refreshed->tcp_proxy_port.has_value()) << "a new capture starts without the port";
        EXPECT_EQ(owner->tcp_proxy_port, std::optional<uint16_t>{ 41000 });
    }

    TEST_F(OwnerRoutingPolicyTest, PidReuseAcrossCapturesDoesNotInheritExclusion)
    {
        // PID 3500 is an excluded application in the AF_INET capture; before the AF_INET6
        // capture the PID is reused by an application that must be proxied.
        os().on_capture = [](const table_kind kind)
        {
            auto& os = fake_os::instance();
            os.images[3500] = image(kind == table_kind::tcp_v6 || kind == table_kind::udp_v6 ? L"APP.EXE" : L"BLOCKED.EXE");
        };
        for (uint16_t i = 0; i < 5; ++i)
        {
            os().tcp4.push_back(tcp4_row(3500, 0, "10.0.0.1", static_cast<uint16_t>(1000 + i), "10.9.9.9", 443));
            os().tcp6.push_back(tcp6_row(3500, 0, "::ffff:10.0.0.1", static_cast<uint16_t>(2000 + i), "::ffff:10.9.9.9", 443));
            os().udp4.push_back(udp4_row(3500, 0, "10.0.0.1", static_cast<uint16_t>(1000 + i)));
            os().udp6.push_back(udp6_row(3500, 0, "::ffff:10.0.0.1", static_cast<uint16_t>(2000 + i)));
        }
        lookup_v4 l4;

        routing_config config;
        config.proxies.push_back({});
        config.proxy_to_names.emplace(0, L"");
        config.excluded.push_back(L"BLOCKED");

        for (uint16_t i = 0; i < 5; ++i)
        {
            expect_route(config.route<tcp, ipv4>(tcp4(l4, static_cast<uint16_t>(1000 + i))), proxy_port_action::none);
            expect_route(config.route<udp, ipv4>(udp4(l4, static_cast<uint16_t>(1000 + i))), proxy_port_action::none);
        }
        EXPECT_TRUE(tcp4(l4, 1000)->excluded);
        EXPECT_TRUE(udp4(l4, 1000)->excluded);

        for (uint16_t i = 0; i < 5; ++i)
        {
            const auto t = tcp4(l4, static_cast<uint16_t>(2000 + i));
            const auto u = udp4(l4, static_cast<uint16_t>(2000 + i));
            ASSERT_TRUE(t && u);
            EXPECT_EQ(t->name, L"APP.EXE");
            EXPECT_EQ(u->name, L"APP.EXE");
            expect_route(config.route<tcp, ipv4>(t), proxy_port_action::proxy, 40001);
            expect_route(config.route<udp, ipv4>(u), proxy_port_action::proxy, 40002);
            EXPECT_FALSE(t->excluded) << "the new process does not inherit the old one's exclusion";
            EXPECT_FALSE(u->excluded);
        }
    }

    TEST_F(OwnerRoutingPolicyTest, UnresolvedDefaultOwnerBehaviorIsUnchanged)
    {
        os().images[3600] = image(L"APP.EXE");
        add_everywhere(3600, 1000);

        routing_config config;
        config.proxies.push_back({});
        config.proxy_to_names.emplace(0, L""); // catch-all

        {
            lookup_v4 l4;
            lookup_v6 l6;
            const auto d_tcp = l4.lookup_process_for_tcp<true>(session4("10.0.0.1", 9, "10.9.9.9", 443));
            const auto d_udp = l4.lookup_process_for_udp<true>(endpoint4("10.0.0.1", 9));
            const auto d6 = l6.lookup_process_for_tcp<true>(session6("2001:db8::1", 9, "2001:db8::9", 443));
            ASSERT_TRUE(d_tcp && d_udp && d6);
            EXPECT_EQ(d_tcp->name, L"SYSTEM");
            EXPECT_EQ(d_tcp->id, 0u);
            EXPECT_FALSE(d_tcp->resolved) << "the shared default stays unresolved";
            EXPECT_EQ(d_udp, d_tcp) << "one default per lookup instance, as before";
            EXPECT_NE(d6, d_tcp);
            EXPECT_NE(d_tcp, tcp4(l4, 1000));

            // Normal mode: the catch-all matches the unresolved default.
            expect_route(config.route<tcp, ipv4>(d_tcp), proxy_port_action::proxy, 40001);
            expect_route(config.route<tcp, ipv4>(tcp4(l4, 1000)), proxy_port_action::proxy, 40001);
        }
        {
            lookup_v4 l4;
            config.bypass_unresolved = true; // limited mode
            const auto d = l4.lookup_process_for_tcp<true>(session4("10.0.0.1", 9, "10.9.9.9", 443));
            expect_route(config.route<tcp, ipv4>(d), proxy_port_action::none);
            EXPECT_TRUE(d->bypass_tcp);
            // Resolved owners still match in limited mode.
            expect_route(config.route<tcp, ipv4>(tcp4(l4, 1000)), proxy_port_action::proxy, 40001);
        }
    }

    TEST_F(OwnerRoutingPolicyTest, ServiceFallbackOwnerRemainsResolvedForRouting)
    {
        // The service lookup fails for every row: each row keeps a host-image fallback owner,
        // which is usable (resolved) even though it is never memoized.
        os().images[3700] = image(L"SVCHOST.EXE");
        for (uint16_t i = 0; i < 3; ++i)
            os().tcp4.push_back(tcp4_row(3700, 7, "10.0.0.1", static_cast<uint16_t>(1000 + i), "10.9.9.9", 443));
        lookup_v4 l4;

        routing_config config;
        config.proxies.push_back({});
        config.proxy_to_names.emplace(0, L"");
        config.bypass_unresolved = true;

        for (uint16_t i = 0; i < 3; ++i)
        {
            const auto owner = tcp4(l4, static_cast<uint16_t>(1000 + i));
            ASSERT_TRUE(owner);
            EXPECT_EQ(owner->name, L"SVCHOST.EXE");
            EXPECT_TRUE(owner->resolved);
            expect_route(config.route<tcp, ipv4>(owner), proxy_port_action::proxy, 40001);
        }
    }

    TEST_F(OwnerRoutingPolicyTest, ConcurrentRoutingOfSharedOwnersIsConsistent)
    {
        os().images[3800] = image(L"APP.EXE");
        os().images[3801] = image(L"OTHER.EXE");
        add_everywhere(3800, 1000, 50);
        add_everywhere(3801, 2000, 50);
        lookup_v4 l4;

        routing_config config;
        config.proxies.push_back({});
        config.proxy_to_names.emplace(0, L"APP.EXE");

        std::atomic<int> wrong{ 0 };
        std::vector<std::thread> threads;
        for (int t = 0; t < 8; ++t)
        {
            threads.emplace_back([&, t]
            {
                for (int n = 0; n < 500; ++n)
                {
                    const auto i = static_cast<uint16_t>((n + t * 7) % 50);
                    const auto a = config.route<tcp, ipv4>(tcp4(l4, static_cast<uint16_t>(1000 + i)));
                    const auto o = config.route<tcp, ipv4>(tcp4(l4, static_cast<uint16_t>(2000 + i)));
                    if (a.action != proxy_port_action::proxy || a.port != 40001 || o.action != proxy_port_action::none)
                        ++wrong;
                }
            });
        }
        for (auto& thread : threads)
            thread.join();

        EXPECT_EQ(wrong.load(), 0);
        EXPECT_FALSE(tcp4(l4, 1000)->bypass_tcp);
        EXPECT_TRUE(tcp4(l4, 2000)->bypass_tcp);
        EXPECT_FALSE(tcp4(l4, 2000)->excluded);
    }

    TEST_F(OwnerRoutingPolicyTest, RefreshedCaptureStartsWithFreshRoutingState)
    {
        os().images[3900] = image(L"OTHER.EXE");
        add_everywhere(3900, 1000);
        lookup_v4 l4;

        routing_config config;
        config.proxies.push_back({});
        config.proxy_to_names.emplace(0, L"APP.EXE");

        const auto before = tcp4(l4, 1000);
        expect_route(config.route<tcp, ipv4>(before), proxy_port_action::none);
        ASSERT_TRUE(before->bypass_tcp);

        ASSERT_TRUE(l4.actualize(true, true));
        const auto after = tcp4(l4, 1000);
        ASSERT_TRUE(after);
        EXPECT_NE(after, before);
        expect_untouched(after);
        EXPECT_TRUE(before->bypass_tcp) << "an owner already handed out keeps its state";
    }
}
