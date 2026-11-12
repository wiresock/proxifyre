// Packet-level DNS routing tests that run netlib's real packet rewriting code.
//
// Each test builds a real Ethernet/IP/UDP or TCP frame, drives it through the production
// socks5_udp_local_redirect / tcp_local_redirect translations exactly as socks_local_router's
// DNS handlers do (handle_dns_udp(), handle_dns_tcp(), dns_udp_reply_origin()), and checks
// every rewritten header field, the SOCKS5 UDP header carried to the relay, the restored source
// of the answer, and the IP/UDP/TCP checksums (verified independently of the product checksum
// code, which is extracted from ndisapi/ndisapi.cpp by run-portable-tests.sh).
//
// The Windows Packet Filter driver and SOCKS5 sockets are not involved: the local proxy's reply
// is synthesized as the bytes socks5_local_udp_proxy_server sends back. This suite builds only on
// non-Windows hosts through winshim/ (see run-portable-tests.sh).

#include "winshim/packet_env.h"

#include <gtest/gtest.h>

static_assert(sizeof(ether_header) == 14);
static_assert(sizeof(iphdr) == 20);
static_assert(sizeof(ipv6hdr) == 40);
static_assert(sizeof(udphdr) == 8);
static_assert(sizeof(tcphdr) == 20, "tcp_seq must be 32-bit as on Windows");
static_assert(sizeof(proxy::socks5_udp_header<net::ip_address_v4>) == 10);
static_assert(sizeof(proxy::socks5_udp_header<net::ip_address_v6>) == 22);

namespace
{
    using v4 = net::ip_address_v4;
    using v6 = net::ip_address_v6;
    using log_level = netlib::log::log_level;

    constexpr uint16_t client_port = 50001;
    constexpr uint16_t udp_listener = 41002;
    constexpr uint16_t tcp_listener = 41001;

    const uint8_t client_mac[6] = { 0x02, 0, 0, 0, 0, 0x10 };
    const uint8_t gateway_mac[6] = { 0x02, 0, 0, 0, 0, 0x01 };

    std::vector<uint8_t> dns_message(const uint16_t id, const size_t extra = 17)
    {
        std::vector<uint8_t> m{ static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id & 0xff),
                                0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        for (size_t i = 0; i < extra; ++i)
            m.push_back(static_cast<uint8_t>(0x30 + i));
        return m;
    }

    uint32_t sum16(const uint8_t* data, const size_t size, uint32_t sum = 0)
    {
        for (size_t i = 0; i + 1 < size; i += 2)
            sum += static_cast<uint32_t>(data[i] << 8 | data[i + 1]);
        if (size & 1)
            sum += static_cast<uint32_t>(data[size - 1] << 8);
        return sum;
    }

    uint16_t fold(uint32_t sum)
    {
        while (sum >> 16)
            sum = (sum & 0xffff) + (sum >> 16);
        return static_cast<uint16_t>(sum);
    }

    // ------------------------------------------------------------------ frame builders

    struct frame
    {
        INTERMEDIATE_BUFFER buffer{};

        ether_header* eth() { return reinterpret_cast<ether_header*>(buffer.m_IBuffer); }
        iphdr* ip4() { return reinterpret_cast<iphdr*>(buffer.m_IBuffer + ETHER_HEADER_LENGTH); }
        ipv6hdr* ip6() { return reinterpret_cast<ipv6hdr*>(buffer.m_IBuffer + ETHER_HEADER_LENGTH); }
        size_t l3_header() { return ntohs(eth()->h_proto) == ETH_P_IP ? ip4()->ip_hl * 4u : sizeof(ipv6hdr); }
        uint8_t* l4() { return buffer.m_IBuffer + ETHER_HEADER_LENGTH + l3_header(); }
        udphdr* udp() { return reinterpret_cast<udphdr*>(l4()); }
        tcphdr* tcp() { return reinterpret_cast<tcphdr*>(l4()); }
        uint8_t* udp_payload() { return l4() + sizeof(udphdr); }
        size_t udp_payload_size() { return ntohs(udp()->length) - sizeof(udphdr); }
        std::vector<uint8_t> payload() { return { udp_payload(), udp_payload() + udp_payload_size() }; }

        void set_ethernet(const uint16_t ether_type)
        {
            memcpy(eth()->h_source, client_mac, 6);
            memcpy(eth()->h_dest, gateway_mac, 6);
            eth()->h_proto = htons(ether_type);
        }

        static frame udp4(const char* source, const char* destination, const uint16_t sport, const uint16_t dport,
            const std::vector<uint8_t>& payload)
        {
            frame f;
            f.set_ethernet(ETH_P_IP);
            auto* ip = f.ip4();
            ip->ip_v = 4;
            ip->ip_hl = 5;
            ip->ip_len = htons(static_cast<u_short>(sizeof(iphdr) + sizeof(udphdr) + payload.size()));
            ip->ip_ttl = 128;
            ip->ip_p = IPPROTO_UDP;
            ip->ip_src = v4{ std::string{ source } };
            ip->ip_dst = v4{ std::string{ destination } };
            f.udp()->th_sport = htons(sport);
            f.udp()->th_dport = htons(dport);
            f.udp()->length = htons(static_cast<u_short>(sizeof(udphdr) + payload.size()));
            memcpy(f.udp_payload(), payload.data(), payload.size());
            f.buffer.m_Length = static_cast<DWORD>(ETHER_HEADER_LENGTH + ntohs(ip->ip_len));
            CNdisApi::RecalculateUDPChecksum(&f.buffer);
            CNdisApi::RecalculateIPChecksum(&f.buffer);
            return f;
        }

        static frame udp6(const char* source, const char* destination, const uint16_t sport, const uint16_t dport,
            const std::vector<uint8_t>& payload)
        {
            frame f;
            f.set_ethernet(ETH_P_IPV6);
            auto* ip = f.ip6();
            ip->ip6_v = 6;
            ip->ip6_len = htons(static_cast<u_short>(sizeof(udphdr) + payload.size()));
            ip->ip6_next = IPPROTO_UDP;
            ip->ip6_hops = 64;
            ip->ip6_src = v6{ std::string{ source } };
            ip->ip6_dst = v6{ std::string{ destination } };
            f.udp()->th_sport = htons(sport);
            f.udp()->th_dport = htons(dport);
            f.udp()->length = htons(static_cast<u_short>(sizeof(udphdr) + payload.size()));
            memcpy(f.udp_payload(), payload.data(), payload.size());
            f.buffer.m_Length = static_cast<DWORD>(ETHER_HEADER_LENGTH + sizeof(ipv6hdr) + ntohs(ip->ip6_len));
            net::ipv6_helper::recalculate_tcp_udp_checksum(&f.buffer);
            return f;
        }

        static frame tcp4(const char* source, const char* destination, const uint16_t sport, const uint16_t dport,
            const uint8_t flags)
        {
            frame f;
            f.set_ethernet(ETH_P_IP);
            auto* ip = f.ip4();
            ip->ip_v = 4;
            ip->ip_hl = 5;
            ip->ip_len = htons(static_cast<u_short>(sizeof(iphdr) + sizeof(tcphdr)));
            ip->ip_ttl = 128;
            ip->ip_p = IPPROTO_TCP;
            ip->ip_src = v4{ std::string{ source } };
            ip->ip_dst = v4{ std::string{ destination } };
            f.tcp()->th_sport = htons(sport);
            f.tcp()->th_dport = htons(dport);
            f.tcp()->th_off = 5;
            f.tcp()->th_flags = flags;
            f.tcp()->th_win = htons(64240);
            f.buffer.m_Length = static_cast<DWORD>(ETHER_HEADER_LENGTH + ntohs(ip->ip_len));
            CNdisApi::RecalculateTCPChecksum(&f.buffer);
            CNdisApi::RecalculateIPChecksum(&f.buffer);
            return f;
        }

        // Independent checksum verification (RFC 1071): a correct checksum folds to 0xffff.
        bool ip4_checksum_valid() { return fold(sum16(reinterpret_cast<uint8_t*>(ip4()), ip4()->ip_hl * 4u)) == 0xffff; }

        bool l4_checksum_valid()
        {
            uint32_t sum = 0;
            size_t l4_size = 0;
            uint8_t protocol = 0;
            if (ntohs(eth()->h_proto) == ETH_P_IP)
            {
                l4_size = ntohs(ip4()->ip_len) - ip4()->ip_hl * 4u;
                protocol = ip4()->ip_p;
                sum = sum16(reinterpret_cast<uint8_t*>(&ip4()->ip_src), 8);
            }
            else
            {
                l4_size = ntohs(ip6()->ip6_len);
                protocol = ip6()->ip6_next;
                sum = sum16(reinterpret_cast<uint8_t*>(&ip6()->ip6_src), 32);
            }
            sum += protocol + static_cast<uint32_t>(l4_size);
            return fold(sum16(l4(), l4_size, sum)) == 0xffff;
        }

        bool ethernet_swapped()
        {
            return memcmp(eth()->h_source, gateway_mac, 6) == 0 && memcmp(eth()->h_dest, client_mac, 6) == 0;
        }
    };

    template <typename Addr>
    std::vector<uint8_t> socks5_udp_datagram(const Addr& address, const uint16_t port, const std::vector<uint8_t>& data)
    {
        proxy::socks5_udp_header<Addr> header;
        header.reserved = 0;
        header.fragment = 0;
        header.address_type = std::is_same_v<Addr, v4> ? 1 : 4;
        header.dest_address = address;
        header.dest_port = htons(port);
        std::vector<uint8_t> out(reinterpret_cast<uint8_t*>(&header), reinterpret_cast<uint8_t*>(&header) + sizeof(header));
        out.insert(out.end(), data.begin(), data.end());
        return out;
    }

    // ------------------------------------------------------------------ router-equivalent steps

    /// The local UDP proxy's reply to the redirected client, as socks5_local_udp_proxy_server
    /// emits it: from the listener port to the (swapped) original server address and client port,
    /// carrying the relay's SOCKS5 UDP header and the DNS answer.
    template <typename Addr>
    frame local_proxy_reply(const char* local_address, const char* original_server, const Addr& relay_source,
        const uint16_t relay_port, const std::vector<uint8_t>& answer)
    {
        const auto datagram = socks5_udp_datagram(relay_source, relay_port, answer);
        if constexpr (std::is_same_v<Addr, v4>)
            return frame::udp4(local_address, original_server, udp_listener, client_port, datagram);
        else
            return frame::udp6(local_address, original_server, udp_listener, client_port, datagram);
    }

    template <typename Addr, typename Raw>
    std::pair<proxy::dns_reply_restore, std::optional<net::ip_endpoint<Addr>>> classify(frame& reply,
        const net::ip_endpoint<Addr>& server_override, proxy::dns_udp_origin_tracker<net::ip_endpoint<Addr>>& origins)
    {
        const Raw& raw = server_override.ip;
        return proxy::classify_dns_override_reply(reply.udp_payload(), reply.udp_payload_size(),
            static_cast<uint8_t>(std::is_same_v<Addr, v4> ? 1 : 4), reinterpret_cast<const uint8_t*>(&raw), sizeof(Raw),
            server_override.port, ntohs(reply.udp()->th_dport), origins);
    }
}

// 6./7. IPv4 UDP query to a private resolver with an IPv4 override: the relay is asked for the
//       override, the IP packet keeps the original destination, and the answer is presented to
//       the client as coming from the original server.
TEST(DnsPacketRedirect, Ipv4UdpOverrideRewritesTheSocksDestinationAndRestoresTheAnswer)
{
    ndisapi::socks5_udp_local_redirect<v4> redirect{ log_level::error };
    proxy::dns_udp_origin_tracker<net::ip_endpoint<v4>> origins;
    const net::ip_endpoint<v4> server_override{ v4{ std::string{ "1.1.1.1" } }, 53 };
    const auto query = dns_message(0xabcd);

    auto packet = frame::udp4("192.168.1.10", "192.168.1.1", client_port, 53, query);
    ASSERT_TRUE(packet.ip4_checksum_valid());
    ASSERT_TRUE(packet.l4_checksum_valid());

    // handle_dns_udp(): remember the original server, register the endpoint, redirect.
    origins.remember(client_port, *proxy::dns_message_id(query.data(), query.size()),
        net::ip_endpoint<v4>{ v4{ packet.ip4()->ip_dst }, 53 });
    EXPECT_TRUE(redirect.is_new_endpoint(packet.buffer));
    ASSERT_TRUE(redirect.process_client_to_server_packet(packet.buffer, htons(udp_listener), server_override));

    // Hairpinned to the local listener; the IP packet keeps the original server address.
    EXPECT_TRUE(packet.ethernet_swapped());
    EXPECT_EQ(v4{ packet.ip4()->ip_src }, v4{ std::string{ "192.168.1.1" } });
    EXPECT_EQ(v4{ packet.ip4()->ip_dst }, v4{ std::string{ "192.168.1.10" } });
    EXPECT_EQ(ntohs(packet.udp()->th_sport), client_port);
    EXPECT_EQ(ntohs(packet.udp()->th_dport), udp_listener);

    // The SOCKS5 UDP header carried to the relay names the override.
    const auto relayed = packet.payload();
    const auto view = proxy::parse_socks5_udp_datagram(relayed.data(), relayed.size());
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->address_type, 1);
    EXPECT_EQ(std::vector<uint8_t>(view->address, view->address + 4), (std::vector<uint8_t>{ 1, 1, 1, 1 }));
    EXPECT_EQ(view->port, 53);
    EXPECT_EQ(std::vector<uint8_t>(view->data, view->data + view->data_size), query);
    EXPECT_TRUE(packet.ip4_checksum_valid());
    EXPECT_TRUE(packet.l4_checksum_valid());

    // The relay answers from the override; dns_udp_reply_origin() restores the original server.
    const auto answer = dns_message(0xabcd, 40);
    auto reply = local_proxy_reply("192.168.1.10", "192.168.1.1", server_override.ip, 53, answer);
    const auto [restore, origin] = classify<v4, in_addr>(reply, server_override, origins);
    ASSERT_EQ(restore, proxy::dns_reply_restore::restore);
    ASSERT_TRUE(origin.has_value());
    ASSERT_TRUE(redirect.process_server_to_client_packet(reply.buffer, origin));

    EXPECT_EQ(v4{ reply.ip4()->ip_src }, v4{ std::string{ "192.168.1.1" } });
    EXPECT_EQ(v4{ reply.ip4()->ip_dst }, v4{ std::string{ "192.168.1.10" } });
    EXPECT_EQ(ntohs(reply.udp()->th_sport), 53);
    EXPECT_EQ(ntohs(reply.udp()->th_dport), client_port);
    EXPECT_EQ(reply.payload(), answer);
    EXPECT_EQ(ntohs(reply.ip4()->ip_len), sizeof(iphdr) + sizeof(udphdr) + answer.size());
    EXPECT_TRUE(reply.ip4_checksum_valid());
    EXPECT_TRUE(reply.l4_checksum_valid());
}

// 2./7. Without an override the original destination is preserved end to end.
TEST(DnsPacketRedirect, Ipv4UdpWithoutOverrideKeepsTheOriginalDestination)
{
    ndisapi::socks5_udp_local_redirect<v4> redirect{ log_level::error };
    const auto query = dns_message(0x0102);

    auto packet = frame::udp4("10.0.0.20", "8.8.8.8", client_port, 53, query);
    EXPECT_TRUE(redirect.is_new_endpoint(packet.buffer));
    ASSERT_TRUE(redirect.process_client_to_server_packet(packet.buffer, htons(udp_listener)));

    const auto relayed = packet.payload();
    const auto view = proxy::parse_socks5_udp_datagram(relayed.data(), relayed.size());
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(std::vector<uint8_t>(view->address, view->address + 4), (std::vector<uint8_t>{ 8, 8, 8, 8 }));
    EXPECT_EQ(view->port, 53);

    const auto answer = dns_message(0x0102, 5);
    auto reply = local_proxy_reply("10.0.0.20", "8.8.8.8", v4{ std::string{ "8.8.8.8" } }, 53, answer);
    ASSERT_TRUE(redirect.process_server_to_client_packet(reply.buffer));
    EXPECT_EQ(v4{ reply.ip4()->ip_src }, v4{ std::string{ "8.8.8.8" } });
    EXPECT_EQ(ntohs(reply.udp()->th_sport), 53);
    EXPECT_EQ(reply.payload(), answer);
    EXPECT_TRUE(reply.ip4_checksum_valid());
    EXPECT_TRUE(reply.l4_checksum_valid());
}

// 2./6./7. IPv6 UDP query with an IPv6 override.
TEST(DnsPacketRedirect, Ipv6UdpOverrideRewritesTheSocksDestinationAndRestoresTheAnswer)
{
    ndisapi::socks5_udp_local_redirect<v6> redirect{ log_level::error };
    proxy::dns_udp_origin_tracker<net::ip_endpoint<v6>> origins;
    const net::ip_endpoint<v6> server_override{ v6{ std::string{ "2606:4700:4700::1111" } }, 53 };
    const auto query = dns_message(0x7777);

    auto packet = frame::udp6("fd00::10", "fd00::1", client_port, 53, query);
    ASSERT_TRUE(packet.l4_checksum_valid());

    origins.remember(client_port, 0x7777, net::ip_endpoint<v6>{ v6{ packet.ip6()->ip6_dst }, 53 });
    EXPECT_TRUE(redirect.is_new_endpoint(packet.buffer));
    ASSERT_TRUE(redirect.process_client_to_server_packet(packet.buffer, htons(udp_listener), server_override));

    EXPECT_TRUE(packet.ethernet_swapped());
    EXPECT_EQ(v6{ packet.ip6()->ip6_src }, v6{ std::string{ "fd00::1" } });
    EXPECT_EQ(ntohs(packet.udp()->th_dport), udp_listener);
    const auto relayed = packet.payload();
    const auto view = proxy::parse_socks5_udp_datagram(relayed.data(), relayed.size());
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->address_type, 4);
    EXPECT_EQ(v6{ *reinterpret_cast<const in6_addr*>(view->address) }, server_override.ip);
    EXPECT_EQ(view->port, 53);
    EXPECT_TRUE(packet.l4_checksum_valid());

    const auto answer = dns_message(0x7777, 64);
    auto reply = local_proxy_reply("fd00::10", "fd00::1", server_override.ip, 53, answer);
    const auto [restore, origin] = classify<v6, in6_addr>(reply, server_override, origins);
    ASSERT_EQ(restore, proxy::dns_reply_restore::restore);
    ASSERT_TRUE(redirect.process_server_to_client_packet(reply.buffer, origin));

    EXPECT_EQ(v6{ reply.ip6()->ip6_src }, v6{ std::string{ "fd00::1" } });
    EXPECT_EQ(v6{ reply.ip6()->ip6_dst }, v6{ std::string{ "fd00::10" } });
    EXPECT_EQ(ntohs(reply.udp()->th_sport), 53);
    EXPECT_EQ(reply.payload(), answer);
    EXPECT_TRUE(reply.l4_checksum_valid());
}

// 7./8. Answers to tracked queries are restored whatever source the relay reports; answers
//       naming the override that match no query are dropped; other traffic is unchanged.
TEST(DnsPacketRedirect, AnswersToTrackedQueriesAreRestoredWhateverSourceTheRelayReports)
{
    proxy::dns_udp_origin_tracker<net::ip_endpoint<v4>> origins;
    const net::ip_endpoint<v4> server_override{ v4{ std::string{ "1.1.1.1" } }, 53 };
    origins.remember(client_port, 0x1111, net::ip_endpoint<v4>{ v4{ std::string{ "192.168.1.1" } }, 53 });

    // Tracked query, relay reports the override: restored.
    auto known = local_proxy_reply("192.168.1.10", "192.168.1.1", server_override.ip, 53, dns_message(0x1111));
    const auto [restore, origin] = classify<v4, in_addr>(known, server_override, origins);
    EXPECT_EQ(restore, proxy::dns_reply_restore::restore);
    ASSERT_TRUE(origin.has_value());
    EXPECT_EQ(origin->ip, v4{ std::string{ "192.168.1.1" } });
    EXPECT_EQ(origin->port, 53);

    // Tracked query, relay reports another source (its own address, another port): restored too.
    auto relay_source = local_proxy_reply("192.168.1.10", "192.168.1.1", v4{ std::string{ "203.0.113.5" } }, 40000, dns_message(0x1111));
    const auto [relay_restore, relay_origin] = classify<v4, in_addr>(relay_source, server_override, origins);
    EXPECT_EQ(relay_restore, proxy::dns_reply_restore::restore);
    ASSERT_TRUE(relay_origin.has_value());
    EXPECT_EQ(relay_origin->ip, v4{ std::string{ "192.168.1.1" } });

    // Names the override but answers no tracked query: dropped.
    auto unknown = local_proxy_reply("192.168.1.10", "192.168.1.1", server_override.ip, 53, dns_message(0x2222));
    EXPECT_EQ((classify<v4, in_addr>(unknown, server_override, origins).first), proxy::dns_reply_restore::drop);
    auto truncated = local_proxy_reply("192.168.1.10", "192.168.1.1", server_override.ip, 53, std::vector<uint8_t>{ 0x11, 0x11, 0x01 });
    EXPECT_EQ((classify<v4, in_addr>(truncated, server_override, origins).first), proxy::dns_reply_restore::drop);

    // Other traffic through the same proxy that matches no tracked query: unchanged.
    auto other = local_proxy_reply("192.168.1.10", "203.0.113.5", v4{ std::string{ "203.0.113.5" } }, 443, dns_message(0x2222));
    EXPECT_EQ((classify<v4, in_addr>(other, server_override, origins).first), proxy::dns_reply_restore::unchanged);
    auto other_port = local_proxy_reply("192.168.1.10", "192.168.1.1", server_override.ip, 5353, dns_message(0x2222));
    EXPECT_EQ((classify<v4, in_addr>(other_port, server_override, origins).first), proxy::dns_reply_restore::unchanged);

    // A malformed SOCKS5 header (non-zero FRAG) or the other family's ATYP is not restored; the
    // redirect then fails to translate it and the router drops it.
    auto fragmented = local_proxy_reply("192.168.1.10", "192.168.1.1", server_override.ip, 53, dns_message(0x1111));
    fragmented.udp_payload()[2] = 1;
    EXPECT_EQ((classify<v4, in_addr>(fragmented, server_override, origins).first), proxy::dns_reply_restore::unchanged);
    auto wrong_family = frame::udp4("192.168.1.10", "192.168.1.1", udp_listener, client_port,
        socks5_udp_datagram(v6{ std::string{ "2001:db8::1" } }, 53, dns_message(0x1111)));
    EXPECT_EQ((classify<v4, in_addr>(wrong_family, server_override, origins).first), proxy::dns_reply_restore::unchanged);
}

// 8. End to end: a relay that reports its own address as the answer's source still produces an
//    answer the resolver accepts (source = the server it queried).
TEST(DnsPacketRedirect, RelayReportingAnotherSourceStillRestoresTheQueriedServer)
{
    ndisapi::socks5_udp_local_redirect<v4> redirect{ log_level::error };
    proxy::dns_udp_origin_tracker<net::ip_endpoint<v4>> origins;
    const net::ip_endpoint<v4> server_override{ v4{ std::string{ "1.1.1.1" } }, 53 };

    auto query = frame::udp4("192.168.1.10", "192.168.1.1", client_port, 53, dns_message(0x4242));
    origins.remember(client_port, 0x4242, net::ip_endpoint<v4>{ v4{ query.ip4()->ip_dst }, 53 });
    ASSERT_TRUE(redirect.is_new_endpoint(query.buffer));
    ASSERT_TRUE(redirect.process_client_to_server_packet(query.buffer, htons(udp_listener), server_override));

    const auto answer = dns_message(0x4242, 30);
    auto reply = local_proxy_reply("192.168.1.10", "192.168.1.1", v4{ std::string{ "198.51.100.7" } }, 1080, answer);
    const auto [restore, origin] = classify<v4, in_addr>(reply, server_override, origins);
    ASSERT_EQ(restore, proxy::dns_reply_restore::restore);
    ASSERT_TRUE(redirect.process_server_to_client_packet(reply.buffer, origin));
    EXPECT_EQ(v4{ reply.ip4()->ip_src }, v4{ std::string{ "192.168.1.1" } });
    EXPECT_EQ(ntohs(reply.udp()->th_sport), 53);
    EXPECT_EQ(reply.payload(), answer);
    EXPECT_TRUE(reply.ip4_checksum_valid());
    EXPECT_TRUE(reply.l4_checksum_valid());
}

// 8. A datagram that cannot be redirected is reported as such (the router then drops it rather
//    than passing it): here a near-MTU datagram that has no room for the SOCKS5 header.
TEST(DnsPacketRedirect, UnredirectableUdpIsRejectedSoTheRouterDropsIt)
{
    ndisapi::socks5_udp_local_redirect<v4> redirect{ log_level::error };
    const auto big = dns_message(0x3333, MAX_ETHER_FRAME - ETHER_HEADER_LENGTH - sizeof(iphdr) - sizeof(udphdr) - 12 - 4);
    auto packet = frame::udp4("192.168.1.10", "192.168.1.1", client_port, 53, big);
    EXPECT_TRUE(redirect.is_new_endpoint(packet.buffer));
    EXPECT_FALSE(redirect.process_client_to_server_packet(packet.buffer, htons(udp_listener)));

    // An unregistered endpoint is not redirected either.
    ndisapi::socks5_udp_local_redirect<v4> fresh{ log_level::error };
    auto small = frame::udp4("192.168.1.10", "192.168.1.1", client_port, 53, dns_message(1));
    EXPECT_FALSE(fresh.process_client_to_server_packet(small.buffer, htons(udp_listener)));
}

// 2./14. TCP DNS (for example the retry after a truncated UDP answer): the SYN and later
//        segments are hairpinned to the DNS proxy's TCP listener; the listener's replies are
//        presented as coming from the original server. The upstream CONNECT target (original or
//        override) is recorded separately in the router's source-port mapper.
TEST(DnsPacketRedirect, Ipv4TcpIsRedirectedToTheListenerAndRepliesKeepTheOriginalServer)
{
    ndisapi::tcp_local_redirect<v4> redirect{ log_level::error };

    auto syn = frame::tcp4("192.168.1.10", "192.168.1.1", client_port, 53, TH_SYN);
    ASSERT_TRUE(redirect.process_client_to_server_packet(syn.buffer, htons(tcp_listener)));
    EXPECT_TRUE(syn.ethernet_swapped());
    EXPECT_EQ(v4{ syn.ip4()->ip_src }, v4{ std::string{ "192.168.1.1" } });
    EXPECT_EQ(v4{ syn.ip4()->ip_dst }, v4{ std::string{ "192.168.1.10" } });
    EXPECT_EQ(ntohs(syn.tcp()->th_sport), client_port);
    EXPECT_EQ(ntohs(syn.tcp()->th_dport), tcp_listener);
    EXPECT_TRUE(syn.ip4_checksum_valid());
    EXPECT_TRUE(syn.l4_checksum_valid());

    // The listener's SYN-ACK: from the listener port to the swapped original server address.
    auto syn_ack = frame::tcp4("192.168.1.10", "192.168.1.1", tcp_listener, client_port, TH_SYN | TH_ACK);
    ASSERT_TRUE(redirect.process_server_to_client_packet(syn_ack.buffer));
    EXPECT_EQ(v4{ syn_ack.ip4()->ip_src }, v4{ std::string{ "192.168.1.1" } });
    EXPECT_EQ(ntohs(syn_ack.tcp()->th_sport), 53);
    EXPECT_EQ(ntohs(syn_ack.tcp()->th_dport), client_port);
    EXPECT_TRUE(syn_ack.ip4_checksum_valid());
    EXPECT_TRUE(syn_ack.l4_checksum_valid());

    auto ack = frame::tcp4("192.168.1.10", "192.168.1.1", client_port, 53, TH_ACK);
    EXPECT_TRUE(redirect.process_client_to_server_packet(ack.buffer, htons(tcp_listener)));
}

// 9. A TCP segment of a DNS connection that is not being redirected (for example one opened
//    before ProxiFyre started, or after the redirect entry expired) is rejected, and the router
//    drops it instead of passing it to the real server.
TEST(DnsPacketRedirect, TcpSegmentOfAnUnknownConnectionIsRejectedSoTheRouterDropsIt)
{
    ndisapi::tcp_local_redirect<v4> redirect{ log_level::error };
    auto data = frame::tcp4("192.168.1.10", "192.168.1.1", client_port, 53, TH_ACK | TH_PSH);
    EXPECT_FALSE(redirect.process_client_to_server_packet(data.buffer, htons(tcp_listener)));
}

// ------------------------------------------------------------------ TCP close tracking
//
// tcp_local_redirect keeps a connection's entry through the whole close. Every segment of an
// ordinary close is translated in both directions, so nothing is left for the router to drop
// (and count as blocked DNS) or, on the application path, to pass toward the real server.

namespace
{
    using tcp_redirect4 = ndisapi::tcp_local_redirect<v4>;
    constexpr const char* tcp_client = "192.168.1.10";
    constexpr const char* tcp_server = "192.168.1.1";

    /// A client-to-server segment, before redirection.
    frame client_segment(const uint8_t flags, const uint16_t dport = 53)
    {
        return frame::tcp4(tcp_client, tcp_server, client_port, dport, flags);
    }

    /// A segment from the local listener to the (swapped) original server address.
    frame listener_segment(const uint8_t flags)
    {
        return frame::tcp4(tcp_client, tcp_server, tcp_listener, client_port, flags);
    }

    bool send_client(tcp_redirect4& redirect, const uint8_t flags, const uint16_t dport = 53)
    {
        auto segment = client_segment(flags, dport);
        return redirect.process_client_to_server_packet(segment.buffer, htons(tcp_listener));
    }

    /// Sends a listener segment and returns the source port the client sees, if translated.
    std::optional<uint16_t> send_listener(tcp_redirect4& redirect, const uint8_t flags)
    {
        auto segment = listener_segment(flags);
        if (!redirect.process_server_to_client_packet(segment.buffer))
            return std::nullopt;
        EXPECT_EQ(v4{ segment.ip4()->ip_src }, v4{ std::string{ tcp_server } });
        EXPECT_TRUE(segment.ip4_checksum_valid());
        EXPECT_TRUE(segment.l4_checksum_valid());
        return ntohs(segment.tcp()->th_sport);
    }

    std::optional<tcp_redirect4::connection_state> state_of(tcp_redirect4& redirect)
    {
        return redirect.find_connection(v4{ std::string{ tcp_server } }, htons(client_port));
    }

    void establish(tcp_redirect4& redirect)
    {
        ASSERT_TRUE(send_client(redirect, TH_SYN));
        ASSERT_EQ(send_listener(redirect, TH_SYN | TH_ACK), uint16_t{ 53 });
        ASSERT_TRUE(send_client(redirect, TH_ACK));
    }
}

TEST(DnsTcpCloseTracking, ClientInitiatedCloseIsTranslatedToTheEnd)
{
    tcp_redirect4 redirect{ log_level::error };
    establish(redirect);

    EXPECT_TRUE(send_client(redirect, TH_FIN | TH_ACK));
    ASSERT_TRUE(state_of(redirect).has_value());
    EXPECT_TRUE(state_of(redirect)->client_fin);
    EXPECT_FALSE(state_of(redirect)->server_fin);

    // The listener's ACK and FIN still reach the client as coming from the server's port 53.
    EXPECT_EQ(send_listener(redirect, TH_ACK), uint16_t{ 53 });
    EXPECT_EQ(send_listener(redirect, TH_FIN | TH_ACK), uint16_t{ 53 });
    ASSERT_TRUE(state_of(redirect).has_value());
    EXPECT_TRUE(state_of(redirect)->server_fin);

    // The client's final ACK is translated too.
    EXPECT_TRUE(send_client(redirect, TH_ACK));

    // The entry lingers briefly after the close completes, then expires.
    const auto now = std::chrono::steady_clock::now();
    redirect.remove_expired(now);
    EXPECT_TRUE(state_of(redirect).has_value());
    redirect.remove_expired(now + tcp_redirect4::closed_linger + std::chrono::seconds{ 1 });
    EXPECT_FALSE(state_of(redirect).has_value());

    // A listener segment after expiry is not translated (the router then drops it).
    EXPECT_FALSE(send_listener(redirect, TH_ACK).has_value());
}

TEST(DnsTcpCloseTracking, ListenerInitiatedCloseAllowsTheHalfClosedSideToFinish)
{
    tcp_redirect4 redirect{ log_level::error };
    establish(redirect);

    EXPECT_EQ(send_listener(redirect, TH_FIN | TH_ACK), uint16_t{ 53 });
    EXPECT_TRUE(state_of(redirect)->server_fin);

    // Half-closed: the client may still send data before its own FIN.
    EXPECT_TRUE(send_client(redirect, TH_ACK));
    EXPECT_TRUE(send_client(redirect, TH_PSH | TH_ACK));
    EXPECT_TRUE(send_client(redirect, TH_FIN | TH_ACK));
    EXPECT_EQ(send_listener(redirect, TH_ACK), uint16_t{ 53 });
}

TEST(DnsTcpCloseTracking, FinRetransmissionsAreTranslated)
{
    tcp_redirect4 redirect{ log_level::error };
    establish(redirect);

    EXPECT_TRUE(send_client(redirect, TH_FIN | TH_ACK));
    EXPECT_TRUE(send_client(redirect, TH_FIN | TH_ACK));
    EXPECT_EQ(send_listener(redirect, TH_FIN | TH_ACK), uint16_t{ 53 });
    EXPECT_EQ(send_listener(redirect, TH_FIN | TH_ACK), uint16_t{ 53 });
    EXPECT_TRUE(send_client(redirect, TH_FIN | TH_ACK));
    EXPECT_TRUE(send_client(redirect, TH_ACK));
}

TEST(DnsTcpCloseTracking, RstFromEitherSideIsTranslatedAndEndsTrackingImmediately)
{
    {
        tcp_redirect4 redirect{ log_level::error };
        establish(redirect);
        EXPECT_TRUE(send_client(redirect, TH_RST | TH_ACK));
        EXPECT_FALSE(state_of(redirect).has_value());
        EXPECT_FALSE(send_client(redirect, TH_ACK));
    }
    {
        tcp_redirect4 redirect{ log_level::error };
        establish(redirect);
        EXPECT_TRUE(send_client(redirect, TH_FIN | TH_ACK));
        EXPECT_EQ(send_listener(redirect, TH_RST), uint16_t{ 53 });
        EXPECT_FALSE(state_of(redirect).has_value());
        EXPECT_FALSE(send_listener(redirect, TH_ACK).has_value());
    }
}

TEST(DnsTcpCloseTracking, IdleTimeoutsDependOnTheCloseState)
{
    const auto now = std::chrono::steady_clock::now();

    tcp_redirect4 open{ log_level::error };
    establish(open);
    open.remove_expired(now + tcp_redirect4::open_timeout - std::chrono::seconds{ 5 });
    EXPECT_TRUE(state_of(open).has_value());
    open.remove_expired(now + tcp_redirect4::open_timeout + std::chrono::seconds{ 5 });
    EXPECT_FALSE(state_of(open).has_value());

    tcp_redirect4 half_closed{ log_level::error };
    establish(half_closed);
    EXPECT_TRUE(send_client(half_closed, TH_FIN | TH_ACK));
    half_closed.remove_expired(now + tcp_redirect4::half_closed_timeout - std::chrono::seconds{ 5 });
    EXPECT_TRUE(state_of(half_closed).has_value());
    half_closed.remove_expired(now + tcp_redirect4::half_closed_timeout + std::chrono::seconds{ 5 });
    EXPECT_FALSE(state_of(half_closed).has_value());

    static_assert(tcp_redirect4::closed_linger < tcp_redirect4::half_closed_timeout);
    static_assert(tcp_redirect4::half_closed_timeout < tcp_redirect4::open_timeout);
}

TEST(DnsTcpCloseTracking, NewSynOnAClosingKeyStartsANewConnection)
{
    tcp_redirect4 redirect{ log_level::error };
    establish(redirect);
    EXPECT_TRUE(send_client(redirect, TH_FIN | TH_ACK));
    EXPECT_EQ(send_listener(redirect, TH_FIN | TH_ACK), uint16_t{ 53 });

    // The client reuses its source port for a connection to another destination port.
    ASSERT_TRUE(send_client(redirect, TH_SYN, 853));
    ASSERT_TRUE(state_of(redirect).has_value());
    EXPECT_FALSE(state_of(redirect)->client_fin);
    EXPECT_FALSE(state_of(redirect)->server_fin);
    EXPECT_EQ(send_listener(redirect, TH_SYN | TH_ACK), uint16_t{ 853 });

    // A retransmitted SYN of a connection being set up refreshes it and is still redirected.
    EXPECT_TRUE(send_client(redirect, TH_SYN, 853));
    EXPECT_EQ(send_listener(redirect, TH_SYN | TH_ACK), uint16_t{ 853 });
}

// 1. A listener segment that cannot be translated is dropped by the router rather than passed:
//    the decision the four handlers apply to process_server_to_client_packet's result.
TEST(DnsTcpCloseTracking, UntranslatableListenerSegmentIsDropped)
{
    tcp_redirect4 redirect{ log_level::error };
    auto stray = listener_segment(TH_ACK);
    const bool translated = redirect.process_server_to_client_packet(stray.buffer);
    EXPECT_FALSE(translated);
    EXPECT_EQ(proxy::decide_listener_reply(true, translated), proxy::listener_reply_action::drop);

    ndisapi::socks5_udp_local_redirect<v4> udp{ log_level::error };
    auto unknown = local_proxy_reply("192.168.1.10", "192.168.1.1", v4{ std::string{ "192.168.1.1" } }, 53, dns_message(1));
    const bool udp_translated = udp.process_server_to_client_packet(unknown.buffer);
    EXPECT_FALSE(udp_translated);
    EXPECT_EQ(proxy::decide_listener_reply(true, udp_translated), proxy::listener_reply_action::drop);
}

// 14. Truncation fallback end to end: the truncated UDP answer reaches the resolver unchanged
//     (TC bit intact, source = the server it queried), and the TCP retry to that same server is
//     redirected to the DNS proxy's TCP listener, with the listener's replies presented as the
//     server's port 53 through the end of the connection.
TEST(DnsPacketRedirect, TruncatedUdpAnswerAndTcpRetryBothGoThroughTheDnsProxy)
{
    ndisapi::socks5_udp_local_redirect<v4> udp{ log_level::error };
    ndisapi::tcp_local_redirect<v4> tcp{ log_level::error };
    proxy::dns_udp_origin_tracker<net::ip_endpoint<v4>> origins;
    const net::ip_endpoint<v4> server_override{ v4{ std::string{ "1.1.1.1" } }, 53 };

    // UDP query, redirected with the override.
    auto query = frame::udp4("192.168.1.10", "192.168.1.1", client_port, 53, dns_message(0x5151));
    origins.remember(client_port, 0x5151, net::ip_endpoint<v4>{ v4{ query.ip4()->ip_dst }, 53 });
    ASSERT_TRUE(udp.is_new_endpoint(query.buffer));
    ASSERT_TRUE(udp.process_client_to_server_packet(query.buffer, htons(udp_listener), server_override));

    // Truncated answer (TC bit, byte 2 bit 0x02) relayed from the override.
    auto truncated_answer = dns_message(0x5151, 20);
    truncated_answer[2] = static_cast<uint8_t>(0x80 | 0x02);
    auto reply = local_proxy_reply("192.168.1.10", "192.168.1.1", server_override.ip, 53, truncated_answer);
    const auto [restore, origin] = classify<v4, in_addr>(reply, server_override, origins);
    ASSERT_EQ(restore, proxy::dns_reply_restore::restore);
    ASSERT_TRUE(udp.process_server_to_client_packet(reply.buffer, origin));
    EXPECT_EQ(v4{ reply.ip4()->ip_src }, v4{ std::string{ "192.168.1.1" } });
    EXPECT_EQ(reply.payload(), truncated_answer);
    EXPECT_EQ(reply.payload()[2] & 0x02, 0x02);
    EXPECT_TRUE(reply.l4_checksum_valid());

    // The resolver retries over TCP to the same server from a new port.
    constexpr uint16_t retry_port = client_port + 1;
    auto syn = frame::tcp4("192.168.1.10", "192.168.1.1", retry_port, 53, TH_SYN);
    ASSERT_TRUE(tcp.process_client_to_server_packet(syn.buffer, htons(tcp_listener)));
    EXPECT_EQ(ntohs(syn.tcp()->th_dport), tcp_listener);

    for (const uint8_t flags : { uint8_t{ TH_SYN | TH_ACK }, uint8_t{ TH_PSH | TH_ACK }, uint8_t{ TH_FIN | TH_ACK } })
    {
        auto segment = frame::tcp4("192.168.1.10", "192.168.1.1", tcp_listener, retry_port, flags);
        ASSERT_TRUE(tcp.process_server_to_client_packet(segment.buffer));
        EXPECT_EQ(v4{ segment.ip4()->ip_src }, v4{ std::string{ "192.168.1.1" } });
        EXPECT_EQ(ntohs(segment.tcp()->th_sport), 53);
        EXPECT_TRUE(segment.l4_checksum_valid());
    }
    auto final_ack = frame::tcp4("192.168.1.10", "192.168.1.1", retry_port, 53, TH_FIN | TH_ACK);
    EXPECT_TRUE(tcp.process_client_to_server_packet(final_ack.buffer, htons(tcp_listener)));
}

// 5. RST takes precedence over SYN: a segment carrying both ends tracking instead of starting it.
TEST(DnsTcpCloseTracking, SynWithRstEndsTrackingInsteadOfStartingIt)
{
    {
        tcp_redirect4 redirect{ log_level::error };
        establish(redirect);
        EXPECT_TRUE(send_client(redirect, TH_SYN | TH_RST));
        EXPECT_FALSE(state_of(redirect).has_value());
        EXPECT_FALSE(send_listener(redirect, TH_ACK).has_value());
    }
    {
        // On an untracked key it neither creates an entry nor is rewritten.
        tcp_redirect4 redirect{ log_level::error };
        EXPECT_FALSE(send_client(redirect, TH_SYN | TH_RST));
        EXPECT_FALSE(state_of(redirect).has_value());
    }
}

// ------------------------------------------------------------------ segments after a reset
//
// After an RST, the proxy's segments still in flight are not translated (the connection is over)
// but are recognized as part of the abort, so the router drops them without reporting a fault.

namespace
{
    using segment_result = tcp_redirect4::server_segment_result;

    segment_result listener_segment_result(tcp_redirect4& redirect, const uint8_t flags)
    {
        auto segment = listener_segment(flags);
        const auto before = std::vector<uint8_t>(segment.buffer.m_IBuffer, segment.buffer.m_IBuffer + segment.buffer.m_Length);
        const auto result = redirect.process_server_to_client_segment(segment.buffer);
        if (result != segment_result::translated)
        {
            // Untranslated segments are left untouched.
            EXPECT_EQ(std::vector<uint8_t>(segment.buffer.m_IBuffer, segment.buffer.m_IBuffer + segment.buffer.m_Length), before);
        }
        return result;
    }

    bool recently_reset(tcp_redirect4& redirect)
    {
        return redirect.is_recently_reset(v4{ std::string{ tcp_server } }, htons(client_port));
    }
}

TEST(DnsTcpResetTracking, ListenerSegmentAfterClientRstIsRecognizedAsPartOfTheAbort)
{
    tcp_redirect4 redirect{ log_level::error };
    establish(redirect);
    ASSERT_TRUE(send_client(redirect, TH_RST | TH_ACK));

    EXPECT_TRUE(recently_reset(redirect));
    EXPECT_FALSE(state_of(redirect).has_value());
    EXPECT_EQ(listener_segment_result(redirect, TH_PSH | TH_ACK), segment_result::recently_reset);
    EXPECT_EQ(listener_segment_result(redirect, TH_FIN | TH_ACK), segment_result::recently_reset);
    // The bool entry point still reports "not translated".
    auto segment = listener_segment(TH_ACK);
    EXPECT_FALSE(redirect.process_server_to_client_packet(segment.buffer));
}

TEST(DnsTcpResetTracking, ListenerSegmentAfterListenerRstIsRecognizedAsPartOfTheAbort)
{
    tcp_redirect4 redirect{ log_level::error };
    establish(redirect);
    // The proxy's RST itself is still translated to the client.
    ASSERT_EQ(send_listener(redirect, TH_RST | TH_ACK), uint16_t{ 53 });

    EXPECT_TRUE(recently_reset(redirect));
    EXPECT_EQ(listener_segment_result(redirect, TH_ACK), segment_result::recently_reset);
    // A further RST from the proxy is not translated again.
    EXPECT_EQ(listener_segment_result(redirect, TH_RST), segment_result::recently_reset);
}

TEST(DnsTcpResetTracking, ClientSegmentsOnAResetKeyBehaveAsUntracked)
{
    tcp_redirect4 redirect{ log_level::error };
    establish(redirect);
    ASSERT_TRUE(send_client(redirect, TH_RST | TH_ACK));

    EXPECT_FALSE(send_client(redirect, TH_ACK));
    EXPECT_FALSE(send_client(redirect, TH_FIN | TH_ACK));
    EXPECT_FALSE(send_client(redirect, TH_RST));
    EXPECT_FALSE(send_client(redirect, TH_SYN | TH_RST));
    // None of these revived or refreshed the connection.
    EXPECT_FALSE(state_of(redirect).has_value());
    EXPECT_TRUE(recently_reset(redirect));
}

TEST(DnsTcpResetTracking, ResetRecordExpiresAfterTheLinger)
{
    tcp_redirect4 redirect{ log_level::error };
    establish(redirect);
    ASSERT_TRUE(send_client(redirect, TH_RST | TH_ACK));

    // Nothing on a reset key refreshes the record: neither the proxy's in-flight segments nor
    // the client's later segments move its expiry, so it ends closed_linger after the RST.
    const auto expiry = redirect.reset_record_expiry(v4{ std::string{ tcp_server } }, htons(client_port));
    ASSERT_TRUE(expiry.has_value());
    EXPECT_EQ(listener_segment_result(redirect, TH_PSH | TH_ACK), segment_result::recently_reset);
    EXPECT_EQ(listener_segment_result(redirect, TH_RST), segment_result::recently_reset);
    EXPECT_FALSE(send_client(redirect, TH_ACK));
    EXPECT_FALSE(send_client(redirect, TH_RST));
    EXPECT_EQ(redirect.reset_record_expiry(v4{ std::string{ tcp_server } }, htons(client_port)), expiry);

    const auto now = std::chrono::steady_clock::now();
    redirect.remove_expired(now);
    EXPECT_TRUE(recently_reset(redirect));
    redirect.remove_expired(now + tcp_redirect4::closed_linger + std::chrono::seconds{ 1 });
    EXPECT_FALSE(recently_reset(redirect));
    EXPECT_EQ(listener_segment_result(redirect, TH_ACK), segment_result::unknown);
}

TEST(DnsTcpResetTracking, NewSynOnAResetKeyStartsANewConnection)
{
    tcp_redirect4 redirect{ log_level::error };
    establish(redirect);
    ASSERT_TRUE(send_client(redirect, TH_RST | TH_ACK));

    ASSERT_TRUE(send_client(redirect, TH_SYN, 853));
    EXPECT_FALSE(recently_reset(redirect));
    ASSERT_TRUE(state_of(redirect).has_value());
    EXPECT_EQ(send_listener(redirect, TH_SYN | TH_ACK), uint16_t{ 853 });
}

TEST(DnsTcpResetTracking, UnknownConnectionsStillReportUnknown)
{
    tcp_redirect4 redirect{ log_level::error };
    EXPECT_EQ(listener_segment_result(redirect, TH_ACK), segment_result::unknown);
}
