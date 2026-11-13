// Shared SOCKS5 UDP association for the DNS proxy (dns_udp_multiplexer.h).
//
// All UDP DNS queries of one address family go through one SOCKS5 UDP association. These tests
// cover what makes that safe: every query in flight gets a unique, randomly chosen relay ID;
// each answer is mapped back to the client socket, its original ID and the server it queried,
// whatever source or address family the relay reports; unmatched answers are not delivered;
// the table stays bounded; and a failing or silently dead association is reopened without
// churning a working one.
//
// No test reads a clock: time points are constructed explicitly. The header has no Windows
// dependencies, so this file also builds outside the Windows test project (see
// netlib/test/portable/run-portable-tests.sh).

#include "pch.h"
#include "../../src/proxy/dns_udp_multiplexer.h"

#include <array>
#include <functional>
#include <set>
#include <vector>

namespace
{
    struct test_client
    {
        uint32_t server{};
        uint16_t port{};
        bool operator==(const test_client& rhs) const { return server == rhs.server && port == rhs.port; }
    };
}

namespace std
{
    template <>
    struct hash<test_client>
    {
        std::size_t operator()(const test_client& c) const noexcept
        {
            return std::hash<uint64_t>{}((static_cast<uint64_t>(c.server) << 16) | c.port);
        }
    };
}

namespace
{
    using namespace std::chrono_literals;
    using time_point = std::chrono::steady_clock::time_point;
    using table_t = proxy::dns_query_table<test_client>;

    const time_point t0{ std::chrono::seconds{ 1000 } };

    /// Deterministic "random" source returning the given values in order, then repeating the last.
    struct scripted_random
    {
        std::vector<uint16_t> values;
        std::size_t next{};
        uint16_t operator()()
        {
            const auto value = values[(std::min)(next, values.size() - 1)];
            ++next;
            return value;
        }
    };

    /// A SOCKS5 UDP datagram: header for @p address (4 or 16 bytes), port, then @p data.
    std::vector<uint8_t> socks_datagram(const std::vector<uint8_t>& address, const uint16_t port,
        const std::vector<uint8_t>& data)
    {
        std::vector<uint8_t> d{ 0, 0, 0, static_cast<uint8_t>(address.size() == 4 ? 1 : 4) };
        d.insert(d.end(), address.begin(), address.end());
        d.push_back(static_cast<uint8_t>(port >> 8));
        d.push_back(static_cast<uint8_t>(port & 0xff));
        d.insert(d.end(), data.begin(), data.end());
        return d;
    }

    /// A 12-byte DNS header with message ID @p id followed by @p extra bytes of body.
    std::vector<uint8_t> dns_message(const uint16_t id, const std::vector<uint8_t>& extra = {})
    {
        std::vector<uint8_t> m{ static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id & 0xff),
            0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0 };
        m.insert(m.end(), extra.begin(), extra.end());
        return m;
    }

    const std::vector<uint8_t> v4_server{ 192, 168, 1, 1 };
    const std::vector<uint8_t> v4_override{ 1, 1, 1, 1 };
    const std::vector<uint8_t> v6_relay_source{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x35 };
}

// --- Wire format ------------------------------------------------------------------------------

TEST(DnsUdpMultiplexer, MessageIdIsWrittenInNetworkByteOrder)
{
    std::array<uint8_t, 2> id{};
    proxy::set_dns_message_id(id.data(), 0xBEEF);
    EXPECT_EQ(id[0], 0xBE);
    EXPECT_EQ(id[1], 0xEF);
    EXPECT_EQ(proxy::socks5_udp_header_size(1), 10u);
    EXPECT_EQ(proxy::socks5_udp_header_size(4), 22u);
    EXPECT_EQ(proxy::socks5_udp_header_size(3), 0u);
}

TEST(DnsUdpMultiplexer, QueryOffsetRequiresTheListenersFamilyAndADnsHeader)
{
    const auto v4 = socks_datagram(v4_server, 53, dns_message(0x1234));
    EXPECT_EQ(proxy::socks5_dns_query_offset(v4.data(), v4.size(), 1), std::optional<std::size_t>{ 10 });
    // The IPv6 listener only accepts ATYP 4 headers, and vice versa.
    EXPECT_FALSE(proxy::socks5_dns_query_offset(v4.data(), v4.size(), 4));

    const auto v6 = socks_datagram(v6_relay_source, 53, dns_message(0x1234));
    EXPECT_EQ(proxy::socks5_dns_query_offset(v6.data(), v6.size(), 4), std::optional<std::size_t>{ 22 });

    // Too short to carry a DNS header: cannot be multiplexed.
    auto short_query = socks_datagram(v4_server, 53, { 0x12, 0x34, 0, 0 });
    EXPECT_FALSE(proxy::socks5_dns_query_offset(short_query.data(), short_query.size(), 1));

    // A fragmented SOCKS5 datagram (FRAG != 0) is not accepted.
    auto fragmented = v4;
    fragmented[2] = 1;
    EXPECT_FALSE(proxy::socks5_dns_query_offset(fragmented.data(), fragmented.size(), 1));
}

TEST(DnsUdpMultiplexer, ClientAnswerNamesTheQueriedServerAndRestoresTheOriginalId)
{
    // The relay answers from the override, in an IPv6 header, with the relay ID 0x7777.
    const std::vector<uint8_t> body{ 0xC0, 0x0C, 0x00, 0x01 };
    const auto relayed_bytes = socks_datagram(v6_relay_source, 53, dns_message(0x7777, body));
    const auto relayed = proxy::parse_socks5_udp_datagram(relayed_bytes.data(), relayed_bytes.size());
    ASSERT_TRUE(relayed);

    std::array<uint8_t, 512> out{};
    const auto size = proxy::build_dns_client_answer(*relayed, v4_server.data(), v4_server.size(), 53, 0x1234,
        out.data(), out.size());

    const auto expected = socks_datagram(v4_server, 53, dns_message(0x1234, body));
    ASSERT_EQ(size, expected.size());
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), out.begin()));
}

TEST(DnsUdpMultiplexer, ClientAnswerIsNotBuiltWhenItCannotBeDelivered)
{
    const auto relayed_bytes = socks_datagram(v4_override, 53, dns_message(0x7777, { 1, 2, 3 }));
    const auto relayed = proxy::parse_socks5_udp_datagram(relayed_bytes.data(), relayed_bytes.size());
    ASSERT_TRUE(relayed);

    std::array<uint8_t, 512> out{};
    // Output buffer one byte too small.
    EXPECT_EQ(proxy::build_dns_client_answer(*relayed, v4_server.data(), 4, 53, 1, out.data(), 10 + 15 - 1), 0u);
    EXPECT_EQ(proxy::build_dns_client_answer(*relayed, v4_server.data(), 4, 53, 1, out.data(), 10 + 15), 25u);
    // Address size other than 4 or 16.
    EXPECT_EQ(proxy::build_dns_client_answer(*relayed, v4_server.data(), 5, 53, 1, out.data(), out.size()), 0u);

    // Data too short for a DNS header.
    const auto short_bytes = socks_datagram(v4_override, 53, { 0x77, 0x77 });
    const auto short_view = proxy::parse_socks5_udp_datagram(short_bytes.data(), short_bytes.size());
    ASSERT_TRUE(short_view);
    EXPECT_EQ(proxy::build_dns_client_answer(*short_view, v4_server.data(), 4, 53, 1, out.data(), out.size()), 0u);
}

// --- Query table ------------------------------------------------------------------------------

TEST(DnsQueryTable, RelayIdComesFromTheRandomSourceAndMapsBack)
{
    table_t table{ 10s, 1024 };
    scripted_random random{ { 0xA1B2 } };
    const test_client client{ 0xC0A80101, 50000 };

    const auto relay_id = table.insert(client, 0x1234, t0, random);
    ASSERT_EQ(relay_id, std::optional<uint16_t>{ 0xA1B2 });

    const auto pending = table.take(0xA1B2, t0 + 1s);
    ASSERT_TRUE(pending);
    EXPECT_EQ(pending->client, client);
    EXPECT_EQ(pending->original_id, 0x1234);

    // The entry is consumed: a second answer with the same relay ID is not delivered.
    EXPECT_FALSE(table.take(0xA1B2, t0 + 1s));
    EXPECT_EQ(table.size(), 0u);
}

TEST(DnsQueryTable, ClientsWithTheSameMessageIdGetDistinctRelayIds)
{
    // Two sockets (or the same ID to two servers) pick the same message ID; the relay must still
    // tell their answers apart.
    table_t table{ 10s, 1024 };
    scripted_random random{ { 0x0101, 0x0202 } };
    const test_client a{ 0xC0A80101, 50000 };
    const test_client b{ 0xC0A80101, 50001 };

    const auto id_a = table.insert(a, 0x1234, t0, random);
    const auto id_b = table.insert(b, 0x1234, t0, random);
    ASSERT_TRUE(id_a && id_b);
    EXPECT_NE(*id_a, *id_b);
    EXPECT_EQ(table.take(*id_b, t0)->client, b);
    EXPECT_EQ(table.take(*id_a, t0)->client, a);
}

TEST(DnsQueryTable, RandomCollisionsAreRedrawnAndTheScanFallbackFindsAFreeId)
{
    table_t table{ 10s, 1024 };
    const test_client a{ 1, 1 };
    const test_client b{ 2, 2 };
    const test_client c{ 3, 3 };

    scripted_random first{ { 0x0500 } };
    ASSERT_EQ(table.insert(a, 1, t0, first), std::optional<uint16_t>{ 0x0500 });

    // The first draw collides, the second is free.
    scripted_random second{ { 0x0500, 0x0600 } };
    EXPECT_EQ(table.insert(b, 1, t0, second), std::optional<uint16_t>{ 0x0600 });

    // Every draw collides: the linear scan from the (colliding) start finds the next free ID.
    scripted_random stuck{ { 0x0500 } };
    EXPECT_EQ(table.insert(c, 1, t0, stuck), std::optional<uint16_t>{ 0x0501 });
}

TEST(DnsQueryTable, RetransmissionReusesItsRelayId)
{
    table_t table{ 10s, 1024 };
    scripted_random random{ { 0x1111, 0x2222 } };
    const test_client client{ 0xC0A80101, 50000 };

    const auto first = table.insert(client, 0xABCD, t0, random);
    const auto retransmit = table.insert(client, 0xABCD, t0 + 2s, random);
    EXPECT_EQ(first, retransmit);
    EXPECT_EQ(table.size(), 1u);

    // The retransmission refreshed the entry: still alive 9 s after it, 11 s after the first.
    EXPECT_EQ(table.expire(t0 + 11s), 0u);
    EXPECT_TRUE(table.take(*first, t0 + 11s));
}

TEST(DnsQueryTable, ExpiredQueriesAreCountedAndNotDelivered)
{
    table_t table{ 10s, 1024 };
    scripted_random random{ { 1, 2, 3 } };
    (void)table.insert({ 1, 1 }, 1, t0, random);
    (void)table.insert({ 2, 2 }, 1, t0 + 5s, random);
    const auto late = table.insert({ 3, 3 }, 1, t0, random);

    // An answer arriving after the TTL is not delivered, and its entry is removed.
    EXPECT_FALSE(table.take(*late, t0 + 11s));
    EXPECT_EQ(table.size(), 2u);

    EXPECT_EQ(table.expire(t0 + 10s), 0u);
    EXPECT_EQ(table.expire(t0 + 11s), 1u);
    EXPECT_EQ(table.size(), 1u);
    EXPECT_EQ(table.expire(t0 + 16s), 1u);
    EXPECT_EQ(table.size(), 0u);
}

TEST(DnsQueryTable, FullTableEvictsTheOldestQuery)
{
    table_t table{ 10s, 3 };
    scripted_random random{ { 10, 20, 30, 40 } };
    (void)table.insert({ 1, 1 }, 1, t0 + 2s, random);
    (void)table.insert({ 2, 2 }, 1, t0, random);      // oldest
    (void)table.insert({ 3, 3 }, 1, t0 + 1s, random);
    (void)table.insert({ 4, 4 }, 1, t0 + 3s, random);

    EXPECT_EQ(table.size(), 3u);
    EXPECT_FALSE(table.take(20, t0 + 3s)); // evicted
    EXPECT_TRUE(table.take(10, t0 + 3s));
    EXPECT_TRUE(table.take(30, t0 + 3s));
    EXPECT_TRUE(table.take(40, t0 + 3s));

    // An evicted query's retransmission is a new query.
    EXPECT_TRUE(table.insert({ 2, 2 }, 1, t0 + 4s, random));
}

TEST(DnsQueryTable, ClearForgetsEverythingIncludingRetransmissionIndex)
{
    table_t table{ 10s, 16 };
    scripted_random random{ { 7, 8 } };
    (void)table.insert({ 1, 1 }, 1, t0, random);
    table.clear();
    EXPECT_EQ(table.size(), 0u);
    EXPECT_FALSE(table.take(7, t0));
    // Not treated as a retransmission of the forgotten query.
    EXPECT_EQ(table.insert({ 1, 1 }, 1, t0, random), std::optional<uint16_t>{ 8 });
}

// --- Association health -----------------------------------------------------------------------

TEST(DnsAssociationHealth, FailedOpensBackOffExponentiallyUpTo30Seconds)
{
    proxy::dns_association_health<> health;
    EXPECT_TRUE(health.may_open(t0));

    const std::array<std::chrono::seconds, 7> expected{ 1s, 2s, 4s, 8s, 16s, 30s, 30s };
    for (const auto delay : expected)
    {
        health.on_open_failed(t0);
        EXPECT_FALSE(health.may_open(t0 + delay - 1ms));
        EXPECT_TRUE(health.may_open(t0 + delay));
    }

    // An association that stays open for the minimum age resets the backoff.
    health.on_opened(t0 + 30s);
    EXPECT_EQ(health.consecutive_failures(), 7u);
    health.on_closed(t0 + 60s);
    EXPECT_EQ(health.consecutive_failures(), 0u);
    EXPECT_TRUE(health.may_open(t0 + 60s));
}

TEST(DnsAssociationHealth, AssociationClosingSoonAfterOpeningBacksOff)
{
    // A server that accepts UDP ASSOCIATE and then drops the control connection must not be
    // reconnected in a tight loop.
    proxy::dns_association_health<> health{ 3, 30s };
    health.on_opened(t0);
    health.on_closed(t0 + 1s);
    EXPECT_EQ(health.consecutive_failures(), 1u);
    EXPECT_FALSE(health.may_open(t0 + 1s));
    EXPECT_TRUE(health.may_open(t0 + 2s));

    health.on_opened(t0 + 2s);
    health.on_closed(t0 + 3s);
    EXPECT_EQ(health.consecutive_failures(), 2u);
    EXPECT_FALSE(health.may_open(t0 + 4s));
    EXPECT_TRUE(health.may_open(t0 + 5s));
}

TEST(DnsAssociationHealth, LongLivedAssociationResetsTheBackoffWhileOpen)
{
    proxy::dns_association_health<> health{ 3, 30s };
    health.on_open_failed(t0);
    health.on_open_failed(t0);
    health.on_opened(t0 + 2s);
    EXPECT_FALSE(health.on_unanswered(0, t0 + 31s));
    EXPECT_EQ(health.consecutive_failures(), 1u + 1u);
    EXPECT_FALSE(health.on_unanswered(0, t0 + 32s));
    EXPECT_EQ(health.consecutive_failures(), 0u);
}

TEST(DnsAssociationHealth, SilentAssociationIsReopenedOnlyAfterUnansweredQueriesAndMinimumAge)
{
    proxy::dns_association_health<> health{ 3, 30s };
    health.on_opened(t0);

    EXPECT_FALSE(health.on_unanswered(2, t0 + 40s));
    EXPECT_TRUE(health.on_unanswered(1, t0 + 40s));
}

TEST(DnsAssociationHealth, YoungAssociationIsNotChurnedByAResolverThatNeverAnswers)
{
    proxy::dns_association_health<> health{ 3, 30s };
    health.on_opened(t0);
    EXPECT_FALSE(health.on_unanswered(10, t0 + 29s));
    // Still no datagram from the relay once old enough: reopen.
    EXPECT_TRUE(health.on_unanswered(0, t0 + 30s));
}

TEST(DnsAssociationHealth, RelayDatagramResetsTheCountAndIsRemembered)
{
    proxy::dns_association_health<> health{ 3, 30s };
    health.on_opened(t0);
    EXPECT_FALSE(health.last_datagram().has_value());
    EXPECT_FALSE(health.on_unanswered(2, t0 + 40s));
    health.on_relay_datagram(t0 + 41s);
    EXPECT_EQ(health.last_datagram(), std::optional<time_point>{ t0 + 41s });
    EXPECT_FALSE(health.on_unanswered(2, t0 + 41s));
    EXPECT_TRUE(health.on_unanswered(1, t0 + 42s));

    // Reopening resets the count, the age and the last datagram.
    health.on_opened(t0 + 50s);
    EXPECT_FALSE(health.last_datagram().has_value());
    EXPECT_FALSE(health.on_unanswered(5, t0 + 60s));
}

TEST(DnsQueryTable, ExpireCountsOnlyQueriesSentAfterTheGivenTime)
{
    table_t table{ 10s, 1024 };
    scripted_random random{ { 1, 2, 3 } };
    (void)table.insert({ 1, 1 }, 1, t0, random);
    (void)table.insert({ 2, 2 }, 1, t0 + 2s, random);
    (void)table.insert({ 3, 3 }, 1, t0 + 3s, random);
    // All three expire; only the two sent after t0 + 1 s are counted.
    EXPECT_EQ(table.expire(t0 + 20s, t0 + 1s), 2u);
    EXPECT_EQ(table.size(), 0u);
}

TEST(DnsQueryTable, InsertDoesNotSilentlyDiscardExpiredQueries)
{
    // Unanswered queries feed the association health check, so they must be counted by
    // expire() even when new queries keep arriving.
    table_t table{ 10s, 1024 };
    scripted_random random{ { 1, 2 } };
    (void)table.insert({ 1, 1 }, 1, t0, random);
    (void)table.insert({ 2, 2 }, 1, t0 + 20s, random);
    EXPECT_EQ(table.expire(t0 + 20s), 1u);
    EXPECT_EQ(table.size(), 1u);
}

// --- Answers too large for one unfragmented packet ---------------------------------------------

namespace
{
    /// A DNS answer for "example.com" A with @p answer_bytes bytes of answer records.
    std::vector<uint8_t> large_answer(const uint16_t id, const std::size_t answer_bytes)
    {
        std::vector<uint8_t> m{ static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id & 0xff),
            0x81, 0x80, 0, 1, 0, 9, 0, 1, 0, 2 };
        const std::vector<uint8_t> question{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1 };
        m.insert(m.end(), question.begin(), question.end());
        m.insert(m.end(), answer_bytes, 0x5a);
        return m;
    }
}

TEST(DnsAnswerTruncation, LimitKeepsTheListenerReplyWithinTheMinimumMtu)
{
    // 1280 bytes = IP + UDP (8) + SOCKS5 header + DNS answer.
    EXPECT_EQ(proxy::dns_udp_answer_limit(1), 1280u - 20 - 8 - 10);
    EXPECT_EQ(proxy::dns_udp_answer_limit(4), 1280u - 40 - 8 - 22);
}

TEST(DnsAnswerTruncation, AnswersWithinTheLimitAreUnchanged)
{
    auto answer = large_answer(0x1234, 100);
    const auto original = answer;
    EXPECT_EQ(proxy::truncate_dns_answer(answer.data(), answer.size(), answer.size()), answer.size());
    EXPECT_EQ(answer, original);
}

TEST(DnsAnswerTruncation, LargeAnswerKeepsHeaderAndQuestionWithTheTcBit)
{
    auto answer = large_answer(0x1234, 2000);
    const auto size = proxy::truncate_dns_answer(answer.data(), answer.size(), 1242);

    ASSERT_EQ(size, 12u + 17u);
    EXPECT_EQ(answer[0], 0x12);
    EXPECT_EQ(answer[1], 0x34);
    EXPECT_EQ(answer[2], 0x81 | 0x02); // QR, RD kept; TC set
    EXPECT_EQ(answer[3], 0x80);
    EXPECT_EQ(answer[4], 0);           // QDCOUNT 1 kept
    EXPECT_EQ(answer[5], 1);
    for (std::size_t i = 6; i < 12; ++i)
        EXPECT_EQ(answer[i], 0) << i;  // ANCOUNT, NSCOUNT, ARCOUNT zeroed
    const std::vector<uint8_t> question(answer.begin() + 12, answer.begin() + static_cast<std::ptrdiff_t>(size));
    EXPECT_EQ(question, (std::vector<uint8_t>{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1 }));
}

TEST(DnsAnswerTruncation, CompressedQuestionNameIsKept)
{
    std::vector<uint8_t> answer{ 0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1 };
    answer.insert(answer.end(), 2000, 0x5a);
    EXPECT_EQ(proxy::truncate_dns_answer(answer.data(), answer.size(), 1242), 12u + 6u);
    EXPECT_EQ(answer[5], 1);
}

TEST(DnsAnswerTruncation, UnparsableQuestionLeavesOnlyTheHeader)
{
    // A label length that runs past the end of the message, and a reserved label type (0x80).
    for (const uint8_t bad_label : { uint8_t{ 0x3f }, uint8_t{ 0x80 } })
    {
        std::vector<uint8_t> answer{ 0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, bad_label };
        answer.resize(bad_label == 0x3f ? 40 : 2000, 0x5a);
        answer[12] = bad_label;
        const auto limit = std::size_t{ 30 };
        const auto size = proxy::truncate_dns_answer(answer.data(), answer.size(), limit);
        EXPECT_EQ(size, 12u) << int{ bad_label };
        EXPECT_EQ(answer[2] & 0x02, 0x02);
        EXPECT_EQ(answer[4], 0);
        EXPECT_EQ(answer[5], 0);
    }
}

TEST(DnsAnswerTruncation, ClientAnswerIsTruncatedToTheListenersLimit)
{
    const auto big = large_answer(0x7777, 1500);
    const auto relayed_bytes = socks_datagram(v4_override, 53, big);
    const auto relayed = proxy::parse_socks5_udp_datagram(relayed_bytes.data(), relayed_bytes.size());
    ASSERT_TRUE(relayed);

    std::vector<uint8_t> out(4096);
    const auto size = proxy::build_dns_client_answer(*relayed, v4_server.data(), 4, 53, 0x1234, out.data(), out.size());
    ASSERT_EQ(size, 10u + 12u + 17u);
    EXPECT_EQ(out[10], 0x12);           // original ID restored
    EXPECT_EQ(out[11], 0x34);
    EXPECT_EQ(out[12] & 0x02, 0x02);    // TC set

    // An answer that fits is delivered whole.
    const auto fits = large_answer(0x7777, proxy::dns_udp_answer_limit(1) - 12 - 17);
    const auto fits_bytes = socks_datagram(v4_override, 53, fits);
    const auto fits_view = proxy::parse_socks5_udp_datagram(fits_bytes.data(), fits_bytes.size());
    ASSERT_TRUE(fits_view);
    EXPECT_EQ(proxy::build_dns_client_answer(*fits_view, v4_server.data(), 4, 53, 1, out.data(), out.size()),
        10u + proxy::dns_udp_answer_limit(1));
}

// --- Question check ---------------------------------------------------------------------------

namespace
{
    /// A DNS message with header flags @p flags and one question for @p name (dot-separated).
    std::vector<uint8_t> dns_with_question(const uint16_t id, const uint16_t flags, const std::string& name,
        const uint16_t type = 1, const std::vector<uint8_t>& records = {})
    {
        std::vector<uint8_t> m{ static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id & 0xff),
            static_cast<uint8_t>(flags >> 8), static_cast<uint8_t>(flags & 0xff), 0, 1,
            0, static_cast<uint8_t>(records.empty() ? 0 : 1), 0, 0, 0, 0 };
        std::size_t start = 0;
        while (start <= name.size())
        {
            const auto dot = name.find('.', start);
            const auto label = name.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
            m.push_back(static_cast<uint8_t>(label.size()));
            m.insert(m.end(), label.begin(), label.end());
            if (dot == std::string::npos)
                break;
            start = dot + 1;
        }
        m.push_back(0);
        m.push_back(static_cast<uint8_t>(type >> 8));
        m.push_back(static_cast<uint8_t>(type & 0xff));
        m.push_back(0);
        m.push_back(1);
        m.insert(m.end(), records.begin(), records.end());
        return m;
    }

    std::vector<uint8_t> query(const uint16_t id, const std::string& name, const uint16_t type = 1)
    {
        return dns_with_question(id, 0x0100, name, type);
    }

    std::vector<uint8_t> response(const uint16_t id, const std::string& name, const uint16_t type = 1)
    {
        return dns_with_question(id, 0x8180, name, type, { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34 });
    }
}

TEST(DnsQuestionCheck, AnswerMustCarryTheQueriedQuestion)
{
    const auto asked = query(1, "example.com");
    const auto fingerprint = proxy::dns_question_fingerprint(asked.data(), asked.size());
    ASSERT_TRUE(fingerprint.has_value());

    const auto same = response(2, "example.com");
    EXPECT_TRUE(proxy::dns_answer_matches_question(same.data(), same.size(), *fingerprint));
    // Names compare without regard to ASCII case (resolvers may randomize it).
    const auto mixed_case = response(2, "ExAmPlE.CoM");
    EXPECT_TRUE(proxy::dns_answer_matches_question(mixed_case.data(), mixed_case.size(), *fingerprint));

    const auto other_name = response(2, "example.org");
    EXPECT_FALSE(proxy::dns_answer_matches_question(other_name.data(), other_name.size(), *fingerprint));
    const auto other_type = response(2, "example.com", 28);
    EXPECT_FALSE(proxy::dns_answer_matches_question(other_type.data(), other_type.size(), *fingerprint));
}

TEST(DnsQuestionCheck, QuestionlessErrorResponsesAreAcceptedOtherQuestionlessMessagesAreNot)
{
    const auto asked = query(1, "example.com");
    const auto fingerprint = *proxy::dns_question_fingerprint(asked.data(), asked.size());

    // FORMERR / NOTIMP without a question section.
    std::vector<uint8_t> error{ 0, 2, 0x81, 0x84, 0, 0, 0, 0, 0, 0, 0, 0 };
    EXPECT_TRUE(proxy::dns_answer_matches_question(error.data(), error.size(), fingerprint));

    std::vector<uint8_t> success_without_question{ 0, 2, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0 };
    EXPECT_FALSE(proxy::dns_answer_matches_question(success_without_question.data(), success_without_question.size(), fingerprint));
    std::vector<uint8_t> query_without_question{ 0, 2, 0x01, 0x04, 0, 0, 0, 0, 0, 0, 0, 0 };
    EXPECT_FALSE(proxy::dns_answer_matches_question(query_without_question.data(), query_without_question.size(), fingerprint));

    // A query without a parsable question has no fingerprint.
    EXPECT_FALSE(proxy::dns_question_fingerprint(success_without_question.data(), success_without_question.size()));
    auto truncated = asked;
    truncated.resize(truncated.size() - 2);
    EXPECT_FALSE(proxy::dns_question_fingerprint(truncated.data(), truncated.size()));
}

// --- Relay session ------------------------------------------------------------------------------

namespace
{
    using session_t = proxy::dns_relay_session<test_client>;

    session_t make_session()
    {
        return session_t{ 10s, 4096, 3, 30s };
    }

    std::pair<const uint8_t*, std::size_t> address_bytes(const test_client& client)
    {
        return { reinterpret_cast<const uint8_t*>(&client.server), sizeof(client.server) };
    }

    /// Sends @p name from @p client through @p session; returns the relay ID used.
    uint16_t send_query(session_t& session, const test_client& client, const uint16_t id, const std::string& name,
        const time_point at, const uint16_t relay_id)
    {
        auto datagram = socks_datagram(v4_override, 53, query(id, name));
        EXPECT_EQ(session.prepare_query(client, datagram.data(), datagram.size(), 1, at, [relay_id] { return relay_id; }),
            proxy::dns_relay_query::send);
        return static_cast<uint16_t>((datagram[10] << 8) | datagram[11]);
    }

    session_t::answer receive(session_t& session, const uint16_t relay_id, const std::string& name, const time_point at)
    {
        const auto relayed = socks_datagram(v4_override, 53, response(relay_id, name));
        std::vector<uint8_t> out(1024);
        return session.prepare_answer(relayed.data(), relayed.size(), address_bytes, out.data(), out.size(), at);
    }
}

TEST(DnsRelaySession, QueryIsRewrittenAndItsAnswerDelivered)
{
    auto session = make_session();
    const test_client client{ 0x0101A8C0, 50000 };
    session.on_opened(t0);

    EXPECT_EQ(send_query(session, client, 0x1234, "example.com", t0, 0x7777), 0x7777);
    const auto answer = receive(session, 0x7777, "example.com", t0 + 1s);
    EXPECT_EQ(answer.outcome, proxy::dns_relay_answer::deliver);
    ASSERT_TRUE(answer.client.has_value());
    EXPECT_EQ(*answer.client, client);
    EXPECT_GT(answer.size, 10u + 12u);
    EXPECT_EQ(receive(session, 0x7777, "example.com", t0 + 1s).outcome, proxy::dns_relay_answer::unmatched);
}

TEST(DnsRelaySession, MalformedQueriesAreRejected)
{
    auto session = make_session();
    auto no_question = socks_datagram(v4_override, 53, std::vector<uint8_t>{ 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
    EXPECT_EQ(session.prepare_query({ 1, 1 }, no_question.data(), no_question.size(), 1, t0, [] { return uint16_t{ 1 }; }),
        proxy::dns_relay_query::malformed);
    auto wrong_family = socks_datagram(v6_relay_source, 53, query(1, "example.com"));
    EXPECT_EQ(session.prepare_query({ 1, 1 }, wrong_family.data(), wrong_family.size(), 1, t0, [] { return uint16_t{ 1 }; }),
        proxy::dns_relay_query::malformed);
    EXPECT_EQ(session.queries_in_flight(), 0u);
}

TEST(DnsRelaySession, AnswerToAnotherQuestionIsDroppedWithoutConsumingTheQuery)
{
    auto session = make_session();
    session.on_opened(t0);
    (void)send_query(session, { 1, 1 }, 0x1111, "example.com", t0, 0x2222);

    // A late or forged answer carrying the same relay ID but another question.
    EXPECT_EQ(receive(session, 0x2222, "attacker.example", t0 + 1s).outcome, proxy::dns_relay_answer::question_mismatch);
    // The real answer still gets through.
    EXPECT_EQ(receive(session, 0x2222, "example.com", t0 + 2s).outcome, proxy::dns_relay_answer::deliver);
}

TEST(DnsRelaySession, UnparsableRelayDatagramsAreMalformed)
{
    auto session = make_session();
    std::vector<uint8_t> out(64);
    const std::vector<uint8_t> garbage{ 1, 2, 3 };
    EXPECT_EQ(session.prepare_answer(garbage.data(), garbage.size(), address_bytes, out.data(), out.size(), t0).outcome,
        proxy::dns_relay_answer::malformed);
}

// The scenario behind a review finding: Windows also queries a resolver the proxy cannot reach.
// Its queries expire unanswered while answers from a working resolver keep arriving; the
// association must stay open, because the relay is clearly alive.
TEST(DnsRelaySession, UnreachableResolverDoesNotRetireAWorkingAssociation)
{
    auto session = make_session();
    session.on_opened(t0);

    uint16_t relay_id = 0x100;
    for (int round = 0; round < 12; ++round)
    {
        const auto at = t0 + std::chrono::seconds{ round * 5 };
        // Three lookups to the dead resolver and one to the working resolver, sent together.
        for (int dead = 0; dead < 3; ++dead)
            (void)send_query(session, { 0xDEAD, static_cast<uint16_t>(60000 + round * 4 + dead) }, 1, "dead.example", at, ++relay_id);
        const auto working = send_query(session, { 0x0808, static_cast<uint16_t>(61000 + round) }, 1, "ok.example", at, ++relay_id);
        // The working resolver answers 50 ms later.
        EXPECT_EQ(receive(session, working, "ok.example", at + 50ms).outcome, proxy::dns_relay_answer::deliver);
        EXPECT_FALSE(session.expire(at + 1s)) << "round " << round;
        EXPECT_FALSE(session.expire(at + 4s)) << "round " << round;
    }
}

TEST(DnsRelaySession, SilentlyDeadAssociationIsRetired)
{
    auto session = make_session();
    session.on_opened(t0);
    // Nothing ever comes back from the relay.
    for (int i = 0; i < 3; ++i)
        (void)send_query(session, { 1, static_cast<uint16_t>(i) }, 1, "a.example", t0 + 25s, static_cast<uint16_t>(10 + i));
    EXPECT_FALSE(session.expire(t0 + 30s));
    EXPECT_TRUE(session.expire(t0 + 36s));
}

TEST(DnsRelaySession, AnswersAfterTheQueriesWereSentDoNotHideALaterSilence)
{
    auto session = make_session();
    session.on_opened(t0);
    const auto first = send_query(session, { 1, 1 }, 1, "a.example", t0 + 30s, 1);
    EXPECT_EQ(receive(session, first, "a.example", t0 + 31s).outcome, proxy::dns_relay_answer::deliver);
    // The relay goes silent after t0 + 31 s: three later queries expire unanswered.
    for (int i = 0; i < 3; ++i)
        (void)send_query(session, { 1, static_cast<uint16_t>(2 + i) }, 1, "a.example", t0 + 32s, static_cast<uint16_t>(2 + i));
    EXPECT_TRUE(session.expire(t0 + 43s));
}

TEST(DnsRelaySession, ClosingForgetsQueriesInFlightAndBacksOffWhenEarly)
{
    auto session = make_session();
    session.on_opened(t0);
    (void)send_query(session, { 1, 1 }, 1, "a.example", t0, 5);
    session.on_closed(t0 + 2s);
    EXPECT_EQ(session.queries_in_flight(), 0u);
    EXPECT_EQ(session.consecutive_failures(), 1u);
    EXPECT_FALSE(session.may_open(t0 + 2s));
    EXPECT_TRUE(session.may_open(t0 + 3s));
}
