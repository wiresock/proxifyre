// Owner memoization through process_lookup's production table builds.
//
// process_lookup<T, fake_ownership_source> runs the production ingestion loops and row
// enrichment over scripted owner-module rows and owner resolution (fake_ownership_source.h). The
// assertions count the owner lookups made while each capture is ingested and observe the
// published tables through the production lookup_process_for_tcp/udp paths.
//
// There are six ingestion loops: the TCP and UDP primary loops of the IPv4 and IPv6 instances,
// and the IPv4 instance's two supplementary AF_INET6 folds (IPv4-mapped TCP; IPv4-mapped and
// unspecified UDP). Each captured table is enriched with its own memo.

#include "pch.h"
#include "fake_ownership_source.h"

namespace
{
    using namespace netlib_test::ownership;

    // ------------------------------------------------------------------------------------
    // One ingestion loop: where its rows live, which capture and lookup instance serve them.
    // ------------------------------------------------------------------------------------

    enum class loop : uint8_t { tcp_v4, tcp_v6, udp_v4, udp_v6, tcp_v4_mapped, udp_v4_mapped };

    std::string loop_name(const ::testing::TestParamInfo<loop>& info)
    {
        switch (info.param)
        {
        case loop::tcp_v4: return "TcpV4Primary";
        case loop::tcp_v6: return "TcpV6Primary";
        case loop::udp_v4: return "UdpV4Primary";
        case loop::udp_v6: return "UdpV6Primary";
        case loop::tcp_v4_mapped: return "TcpV4MappedSupplement";
        case loop::udp_v4_mapped: return "UdpV4MappedSupplement";
        }
        return "Unknown";
    }

    class loop_harness
    {
    public:
        explicit loop_harness(const loop l) : loop_(l) {}

        [[nodiscard]] table_kind capture() const
        {
            switch (loop_)
            {
            case loop::tcp_v4: return table_kind::tcp_v4;
            case loop::udp_v4: return table_kind::udp_v4;
            case loop::tcp_v6:
            case loop::tcp_v4_mapped: return table_kind::tcp_v6;
            case loop::udp_v6:
            case loop::udp_v4_mapped: return table_kind::udp_v6;
            }
            return table_kind::tcp_v4;
        }

        [[nodiscard]] bool tcp() const
        {
            return loop_ == loop::tcp_v4 || loop_ == loop::tcp_v6 || loop_ == loop::tcp_v4_mapped;
        }

        [[nodiscard]] bool served_by_v4() const
        {
            return loop_ != loop::tcp_v6 && loop_ != loop::udp_v6;
        }

        /// Adds the loop's row number @p i (a distinct tuple) owned by (@p pid, @p tag).
        void add_row(const DWORD pid, const DWORD tag, const uint16_t i) const
        {
            auto& os = fake_os::instance();
            const auto port = static_cast<uint16_t>(10000 + i);
            switch (loop_)
            {
            case loop::tcp_v4: os.tcp4.push_back(tcp4_row(pid, tag, "10.0.0.1", port, "10.9.9.9", 443)); break;
            case loop::tcp_v6: os.tcp6.push_back(tcp6_row(pid, tag, "2001:db8::1", port, "2001:db8::9", 443)); break;
            case loop::udp_v4: os.udp4.push_back(udp4_row(pid, tag, "10.0.0.1", port)); break;
            case loop::udp_v6: os.udp6.push_back(udp6_row(pid, tag, "2001:db8::1", port)); break;
            case loop::tcp_v4_mapped:
                os.tcp6.push_back(tcp6_row(pid, tag, "::ffff:10.0.0.1", port, "::ffff:10.9.9.9", 443));
                break;
            case loop::udp_v4_mapped: os.udp6.push_back(udp6_row(pid, tag, "::ffff:10.0.0.1", port)); break;
            }
        }

        void clear_rows() const
        {
            auto& os = fake_os::instance();
            os.tcp4.clear();
            os.tcp6.clear();
            os.udp4.clear();
            os.udp6.clear();
        }

        /// Rebuilds the tables that contain this loop (one or two captures).
        bool refresh()
        {
            return served_by_v4() ? v4_.actualize(tcp(), !tcp()) : v6_.actualize(tcp(), !tcp());
        }

        /// The published owner of row @p i, through the production lookup.
        process_ptr owner(const uint16_t i)
        {
            const auto port = static_cast<uint16_t>(10000 + i);
            switch (loop_)
            {
            case loop::tcp_v4:
            case loop::tcp_v4_mapped:
                return v4_.lookup_process_for_tcp<false>(session4("10.0.0.1", port, "10.9.9.9", 443));
            case loop::tcp_v6:
                return v6_.lookup_process_for_tcp<false>(session6("2001:db8::1", port, "2001:db8::9", 443));
            case loop::udp_v4:
            case loop::udp_v4_mapped:
                return v4_.lookup_process_for_udp<false>(endpoint4("10.0.0.1", port));
            case loop::udp_v6:
                return v6_.lookup_process_for_udp<false>(endpoint6("2001:db8::1", port));
            }
            return nullptr;
        }

    private:
        loop loop_;
        // Constructed empty (each constructor builds its tables once).
        lookup_v4 v4_;
        lookup_v6 v6_;
    };

    class OwnerMemoLookupTest : public fake_os_fixture, public ::testing::WithParamInterface<loop>
    {
    protected:
        void SetUp() override
        {
            fake_os_fixture::SetUp();
            harness_.emplace(GetParam());
        }

        void TearDown() override
        {
            harness_.reset();
            fake_os_fixture::TearDown();
        }

        loop_harness& h() { return *harness_; }

    private:
        std::optional<loop_harness> harness_;
    };

    // ------------------------------------------------------------------------------------
    // One identity, many rows
    // ------------------------------------------------------------------------------------

    TEST_P(OwnerMemoLookupTest, FiftyRowsOfOneIdentityAreEnrichedOnce)
    {
        os().images[1000] = image(L"APP.EXE");
        for (uint16_t i = 0; i < 50; ++i)
            h().add_row(1000, 0, i);

        const auto m = mark();
        ASSERT_TRUE(h().refresh());

        const auto c = os().capture_since(m, h().capture());
        EXPECT_EQ(c.rows, 50u);
        EXPECT_EQ(c.owner_lookups, 1) << "one enrichment for the identity in this capture";
        EXPECT_GT(c.memo_allocations, 0) << "this capture's rows go through an owner memo";

        const auto first = h().owner(0);
        ASSERT_TRUE(first);
        EXPECT_EQ(first->name, L"APP.EXE");
        EXPECT_EQ(first->id, 1000u);
        EXPECT_TRUE(first->resolved);
        EXPECT_FALSE(first->device_path_name.empty());
        for (uint16_t i = 0; i < 50; ++i)
            EXPECT_EQ(h().owner(i), first) << "row " << i << " is published with the shared owner";
    }

    TEST_P(OwnerMemoLookupTest, DistinctServiceTagsStayDistinct)
    {
        // One svchost process hosting two services, plus untagged rows of the host itself.
        os().images[1200] = image(L"SVCHOST.EXE");
        os().services[{ 1200, 7 }] = service(L"DNSCACHE");
        os().services[{ 1200, 9 }] = service(L"WINHTTPAUTOPROXYSVC");
        for (uint16_t i = 0; i < 30; ++i)
            h().add_row(1200, i % 3 == 0 ? 0 : (i % 3 == 1 ? 7 : 9), i);

        const auto m = mark();
        ASSERT_TRUE(h().refresh());

        EXPECT_EQ(os().capture_since(m, h().capture()).owner_lookups, 3) << "one enrichment per (PID, service tag)";
        ASSERT_TRUE(h().owner(0) && h().owner(1) && h().owner(2));
        EXPECT_EQ(h().owner(0)->name, L"SVCHOST.EXE");
        EXPECT_EQ(h().owner(1)->name, L"DNSCACHE");
        EXPECT_EQ(h().owner(2)->name, L"WINHTTPAUTOPROXYSVC");
        EXPECT_NE(h().owner(0), h().owner(1));
        EXPECT_NE(h().owner(1), h().owner(2));
        EXPECT_EQ(h().owner(1), h().owner(28));
        EXPECT_EQ(h().owner(0), h().owner(27));
    }

    TEST_P(OwnerMemoLookupTest, SystemPidRowsBypassEnrichmentAndAreNotPublished)
    {
        os().images[3000] = image(L"APP.EXE");
        for (uint16_t i = 0; i < 100; ++i)
            h().add_row(i % 2 ? 0 : 4, 0, i);
        h().add_row(3000, 0, 100);

        const auto m = mark();
        ASSERT_TRUE(h().refresh());

        EXPECT_EQ(os().capture_since(m, h().capture()).owner_lookups, 1) << "PID 0/4 rows are skipped, as before";
        EXPECT_EQ(h().owner(0), nullptr);
        EXPECT_EQ(h().owner(1), nullptr);
        ASSERT_TRUE(h().owner(100));
        EXPECT_EQ(h().owner(100)->name, L"APP.EXE");
    }

    // ------------------------------------------------------------------------------------
    // Failed and partial enrichment
    // ------------------------------------------------------------------------------------

    TEST_P(OwnerMemoLookupTest, FailuresAreRetriedAndTheLaterCompleteOwnerIsReused)
    {
        os().images[1300] = image(L"APP.EXE");
        os().scripts[{ 1300, 0 }] = { scripted_response::failure(), scripted_response::failure() };
        for (uint16_t i = 0; i < 10; ++i)
            h().add_row(1300, 0, i);

        const auto m = mark();
        ASSERT_TRUE(h().refresh());

        EXPECT_EQ(os().capture_since(m, h().capture()).owner_lookups, 3)
            << "two failed rows retried, then one complete enrichment reused";
        EXPECT_EQ(h().owner(0), nullptr) << "a failed row is left out, as before";
        EXPECT_EQ(h().owner(1), nullptr);
        ASSERT_TRUE(h().owner(2));
        EXPECT_EQ(h().owner(2)->name, L"APP.EXE");
        for (uint16_t i = 2; i < 10; ++i)
            EXPECT_EQ(h().owner(i), h().owner(2));
    }

    TEST_P(OwnerMemoLookupTest, ServiceFallbackIsUsedForItsRowButTheServiceIsRetried)
    {
        // The service lookup of the first row fails; the production fallback to the host image
        // owns that row. The next row resolves the service, which is then reused.
        os().images[1501] = image(L"SVCHOST.EXE");
        os().services[{ 1501, 7 }] = service(L"DNSCACHE");
        os().scripts[{ 1501, 7 }] = { scripted_response::failure() };
        for (uint16_t i = 0; i < 10; ++i)
            h().add_row(1501, 7, i);

        const auto m = mark();
        ASSERT_TRUE(h().refresh());

        const auto c = os().capture_since(m, h().capture());
        EXPECT_EQ(c.owner_lookups, 2) << "the fallback is not memoized; the recovered service is";
        EXPECT_EQ(c.image_lookups, 1);

        const auto fallback = h().owner(0);
        ASSERT_TRUE(fallback);
        EXPECT_EQ(fallback->name, L"SVCHOST.EXE");
        EXPECT_TRUE(fallback->resolved) << "a usable fallback owner remains a resolved owner";

        const auto recovered = h().owner(1);
        ASSERT_TRUE(recovered);
        EXPECT_EQ(recovered->name, L"DNSCACHE");
        EXPECT_TRUE(recovered->resolved);
        EXPECT_NE(recovered, fallback);
        for (uint16_t i = 1; i < 10; ++i)
            EXPECT_EQ(h().owner(i), recovered);
    }

    TEST_P(OwnerMemoLookupTest, RepeatedServiceFallbackIsNeverMemoized)
    {
        os().images[1502] = image(L"SVCHOST.EXE"); // tag 9 never resolves
        for (uint16_t i = 0; i < 5; ++i)
            h().add_row(1502, 9, i);

        const auto m = mark();
        ASSERT_TRUE(h().refresh());

        const auto c = os().capture_since(m, h().capture());
        EXPECT_EQ(c.owner_lookups, 5) << "every row retries its service";
        EXPECT_EQ(c.image_lookups, 5);
        for (uint16_t i = 0; i < 5; ++i)
        {
            ASSERT_TRUE(h().owner(i)) << "each row keeps its usable fallback";
            EXPECT_EQ(h().owner(i)->name, L"SVCHOST.EXE");
            EXPECT_TRUE(h().owner(i)->resolved);
        }
        EXPECT_NE(h().owner(0), h().owner(1)) << "fallback owners are per row, not shared";
    }

    TEST_P(OwnerMemoLookupTest, IncompleteDevicePathIsRetriedAndTheLaterCompleteOwnerIsReused)
    {
        // The first enrichment reports a drive that QueryDosDeviceW cannot convert (as when the
        // conversion fails); the production completeness check keeps that owner for its row only.
        const auto undefined = undefined_drive_letter();
        ASSERT_TRUE(undefined.has_value()) << "every drive letter is defined on this host";
        const std::wstring unconvertible = std::wstring{ *undefined, L':', L'\\' } + L"APP.EXE";

        os().images[1503] = image(L"APP.EXE");
        os().scripts[{ 1503, 0 }] = { scripted_response::success(L"APP.EXE", unconvertible) };
        for (uint16_t i = 0; i < 10; ++i)
            h().add_row(1503, 0, i);

        const auto m = mark();
        ASSERT_TRUE(h().refresh());

        EXPECT_EQ(os().capture_since(m, h().capture()).owner_lookups, 2);

        const auto partial = h().owner(0);
        ASSERT_TRUE(partial) << "the incomplete owner is still published for its row";
        EXPECT_EQ(partial->name, L"APP.EXE");
        EXPECT_TRUE(partial->device_path_name.empty());
        EXPECT_TRUE(partial->resolved);

        const auto complete = h().owner(1);
        ASSERT_TRUE(complete);
        EXPECT_FALSE(complete->device_path_name.empty());
        EXPECT_NE(complete, partial);
        for (uint16_t i = 1; i < 10; ++i)
            EXPECT_EQ(h().owner(i), complete);
    }

    // ------------------------------------------------------------------------------------
    // Lifetime: one capture
    // ------------------------------------------------------------------------------------

    TEST_P(OwnerMemoLookupTest, EveryCaptureEnrichesAfresh)
    {
        os().images[1600] = image(L"OLD.EXE");
        for (uint16_t i = 0; i < 20; ++i)
            h().add_row(1600, 0, i);

        auto m = mark();
        ASSERT_TRUE(h().refresh());
        EXPECT_EQ(os().capture_since(m, h().capture()).owner_lookups, 1);
        const auto first = h().owner(19);
        ASSERT_TRUE(first);
        EXPECT_EQ(first->name, L"OLD.EXE");

        os().images[1600] = image(L"NEW.EXE"); // PID reused between the two refreshes

        m = mark();
        ASSERT_TRUE(h().refresh());
        EXPECT_EQ(os().capture_since(m, h().capture()).owner_lookups, 1) << "nothing carried over";
        const auto second = h().owner(19);
        ASSERT_TRUE(second);
        EXPECT_EQ(second->name, L"NEW.EXE") << "the reused PID resolves to the new process";
        EXPECT_NE(second, first);
        EXPECT_EQ(first->name, L"OLD.EXE") << "an owner already handed out is not modified";
    }

    // ------------------------------------------------------------------------------------
    // Memo allocation failure
    // ------------------------------------------------------------------------------------

    TEST_P(OwnerMemoLookupTest, MemoAllocationFailureKeepsThePublishedTable)
    {
        os().images[1700] = image(L"OLD.EXE");
        os().images[1701] = image(L"NEW.EXE");
        h().add_row(1700, 0, 0);
        ASSERT_TRUE(h().refresh());
        const auto published = h().owner(0);
        ASSERT_TRUE(published);
        ASSERT_EQ(published->name, L"OLD.EXE");

        // The next capture lists a different connection. Its memo cannot allocate.
        h().clear_rows();
        h().add_row(1701, 0, 1);
        os().fail_memo_allocations_in = h().capture();

        const auto m = mark();
        EXPECT_FALSE(h().refresh()) << "a memo allocation failure fails the table build";
        EXPECT_GT(os().capture_since(m, h().capture()).memo_allocations, 0) << "the injected fault was reached";
        EXPECT_EQ(h().owner(0), published) << "the previously published table remains";
        EXPECT_EQ(h().owner(1), nullptr) << "nothing of the failed build is published";

        os().fail_memo_allocations_in.reset();
        ASSERT_TRUE(h().refresh());
        EXPECT_EQ(h().owner(0), nullptr);
        ASSERT_TRUE(h().owner(1));
        EXPECT_EQ(h().owner(1)->name, L"NEW.EXE");
    }

    INSTANTIATE_TEST_CASE_P(AllIngestionLoops, OwnerMemoLookupTest,
        ::testing::Values(loop::tcp_v4, loop::tcp_v6, loop::udp_v4, loop::udp_v6,
            loop::tcp_v4_mapped, loop::udp_v4_mapped),
        loop_name);

    // ------------------------------------------------------------------------------------
    // IPv4 builds: primary capture plus AF_INET6 supplement
    // ------------------------------------------------------------------------------------

    class OwnerMemoMappedTest : public fake_os_fixture
    {
    };

    TEST_F(OwnerMemoMappedTest, MappedTcpRowsAreFoldedAndGenuineIpv6RowsAreNot)
    {
        os().images[2000] = image(L"DUAL.EXE");
        os().images[2001] = image(L"V6ONLY.EXE");
        os().tcp6.push_back(tcp6_row(2000, 0, "::ffff:127.0.0.1", 50000, "::ffff:127.0.0.1", 8080));
        os().tcp6.push_back(tcp6_row(2001, 0, "2001:db8::1", 50001, "2001:db8::9", 8080));

        lookup_v4 lookup4;
        lookup_v6 lookup6;

        const auto mapped = lookup4.lookup_process_for_tcp<false>(session4("127.0.0.1", 50000, "127.0.0.1", 8080));
        ASSERT_TRUE(mapped);
        EXPECT_EQ(mapped->name, L"DUAL.EXE");
        EXPECT_EQ(lookup4.lookup_process_for_tcp<false>(session4("0.0.0.0", 50001, "0.0.0.0", 8080)), nullptr);

        const auto native6 = lookup6.lookup_process_for_tcp<false>(session6("2001:db8::1", 50001, "2001:db8::9", 8080));
        ASSERT_TRUE(native6);
        EXPECT_EQ(native6->name, L"V6ONLY.EXE");
        EXPECT_NE(native6, mapped);
    }

    TEST_F(OwnerMemoMappedTest, MappedAndUnspecifiedUdpRowsAreFoldedIntoIpv4Endpoints)
    {
        os().images[2100] = image(L"MAPPED.EXE");
        os().images[2101] = image(L"ANY.EXE");
        os().images[2102] = image(L"V6ONLY.EXE");
        os().udp6.push_back(udp6_row(2100, 0, "::ffff:127.0.0.1", 5300));
        os().udp6.push_back(udp6_row(2101, 0, "::", 5301));
        os().udp6.push_back(udp6_row(2102, 0, "2001:db8::1", 5302));

        lookup_v4 lookup4;

        const auto mapped = lookup4.lookup_process_for_udp<false>(endpoint4("127.0.0.1", 5300));
        ASSERT_TRUE(mapped);
        EXPECT_EQ(mapped->name, L"MAPPED.EXE");

        // [::]:5301 folds to the 0.0.0.0:5301 wildcard, matched for any local address.
        const auto any = lookup4.lookup_process_for_udp<false>(endpoint4("192.0.2.10", 5301));
        ASSERT_TRUE(any);
        EXPECT_EQ(any->name, L"ANY.EXE");

        EXPECT_EQ(lookup4.lookup_process_for_udp<false>(endpoint4("192.0.2.10", 5302)), nullptr)
            << "a genuine IPv6 endpoint is not folded";
    }

    TEST_F(OwnerMemoMappedTest, NativeIpv4TcpRowTakesPrecedenceOverACollidingMappedRow)
    {
        // A synthetic collision live sockets cannot reliably create: the AF_INET and AF_INET6
        // captures both list 127.0.0.1:50000 -> 127.0.0.1:8080, with different owners.
        os().images[2200] = image(L"NATIVE.EXE");
        os().images[2201] = image(L"MAPPED.EXE");
        os().tcp4.push_back(tcp4_row(2200, 0, "127.0.0.1", 50000, "127.0.0.1", 8080));
        os().tcp6.push_back(tcp6_row(2201, 0, "::ffff:127.0.0.1", 50000, "::ffff:127.0.0.1", 8080));
        os().tcp6.push_back(tcp6_row(2201, 0, "::ffff:127.0.0.1", 50001, "::ffff:127.0.0.1", 8080));

        const auto m = mark();
        lookup_v4 lookup;

        const auto collided = lookup.lookup_process_for_tcp<false>(session4("127.0.0.1", 50000, "127.0.0.1", 8080));
        ASSERT_TRUE(collided);
        EXPECT_EQ(collided->name, L"NATIVE.EXE") << "the native IPv4 row wins";
        EXPECT_EQ(collided->id, 2200u);

        const auto mapped = lookup.lookup_process_for_tcp<false>(session4("127.0.0.1", 50001, "127.0.0.1", 8080));
        ASSERT_TRUE(mapped);
        EXPECT_EQ(mapped->name, L"MAPPED.EXE");
        EXPECT_NE(mapped, collided);

        EXPECT_EQ(os().capture_since(m, table_kind::tcp_v4).owner_lookups, 1);
        EXPECT_EQ(os().capture_since(m, table_kind::tcp_v6).owner_lookups, 1)
            << "the mapped identity is enriched once for its two rows";
    }

    TEST_F(OwnerMemoMappedTest, NativeIpv4UdpExactAndWildcardRowsTakePrecedence)
    {
        os().images[2300] = image(L"NATIVE.EXE");
        os().images[2301] = image(L"MAPPED.EXE");
        os().images[2302] = image(L"ANY6.EXE");
        os().udp4.push_back(udp4_row(2300, 0, "127.0.0.1", 5400));
        os().udp4.push_back(udp4_row(2300, 0, "0.0.0.0", 5401));
        os().udp6.push_back(udp6_row(2301, 0, "::ffff:127.0.0.1", 5400));
        os().udp6.push_back(udp6_row(2302, 0, "::", 5401));

        lookup_v4 lookup;

        const auto exact = lookup.lookup_process_for_udp<false>(endpoint4("127.0.0.1", 5400));
        ASSERT_TRUE(exact);
        EXPECT_EQ(exact->name, L"NATIVE.EXE");

        const auto wildcard = lookup.lookup_process_for_udp<false>(endpoint4("192.0.2.20", 5401));
        ASSERT_TRUE(wildcard);
        EXPECT_EQ(wildcard->name, L"NATIVE.EXE");
        EXPECT_EQ(wildcard, exact) << "one capture's identity shares its owner";
    }

    TEST_F(OwnerMemoMappedTest, UdpExactEndpointIsMatchedBeforeTheFoldedWildcard)
    {
        os().images[2400] = image(L"EXACT.EXE");
        os().images[2401] = image(L"ANY6.EXE");
        os().udp4.push_back(udp4_row(2400, 0, "127.0.0.1", 5500));
        os().udp6.push_back(udp6_row(2401, 0, "::", 5500));

        lookup_v4 lookup;

        const auto exact = lookup.lookup_process_for_udp<false>(endpoint4("127.0.0.1", 5500));
        ASSERT_TRUE(exact);
        EXPECT_EQ(exact->name, L"EXACT.EXE");

        const auto other = lookup.lookup_process_for_udp<false>(endpoint4("192.0.2.30", 5500));
        ASSERT_TRUE(other);
        EXPECT_EQ(other->name, L"ANY6.EXE");
    }

    TEST_F(OwnerMemoMappedTest, PidReusedBetweenPrimaryAndSupplementCaptureGetsItsNewOwner)
    {
        // PID 2500 owns native rows in the AF_INET capture. Before the AF_INET6 capture it exits
        // and the PID is reused by another process, which owns the mapped rows.
        for (const bool tcp : { true, false })
        {
            SCOPED_TRACE(tcp ? "TCP" : "UDP");
            os().reset();
            os().images[2500] = image(L"OLD.EXE");
            os().on_capture = [](const table_kind kind)
            {
                if (kind == table_kind::tcp_v6 || kind == table_kind::udp_v6)
                    fake_os::instance().images[2500] = image(L"NEW.EXE");
                else
                    fake_os::instance().images[2500] = image(L"OLD.EXE");
            };
            for (uint16_t i = 0; i < 5; ++i)
            {
                const auto native_port = static_cast<uint16_t>(51000 + i);
                const auto mapped_port = static_cast<uint16_t>(52000 + i);
                if (tcp)
                {
                    os().tcp4.push_back(tcp4_row(2500, 0, "127.0.0.1", native_port, "127.0.0.1", 8080));
                    os().tcp6.push_back(tcp6_row(2500, 0, "::ffff:127.0.0.1", mapped_port, "::ffff:127.0.0.1", 8080));
                }
                else
                {
                    os().udp4.push_back(udp4_row(2500, 0, "127.0.0.1", native_port));
                    os().udp6.push_back(udp6_row(2500, 0, "::ffff:127.0.0.1", mapped_port));
                }
            }

            lookup_v4 lookup;
            const auto m = mark();
            ASSERT_TRUE(lookup.actualize(tcp, !tcp));

            const auto owner_of = [&](const uint16_t port)
            {
                return tcp
                    ? lookup.lookup_process_for_tcp<false>(session4("127.0.0.1", port, "127.0.0.1", 8080))
                    : lookup.lookup_process_for_udp<false>(endpoint4("127.0.0.1", port));
            };

            const auto old_owner = owner_of(51000);
            const auto new_owner = owner_of(52000);
            ASSERT_TRUE(old_owner && new_owner);
            EXPECT_EQ(old_owner->name, L"OLD.EXE");
            EXPECT_EQ(new_owner->name, L"NEW.EXE") << "the supplement does not reuse the primary capture's owner";
            EXPECT_NE(old_owner, new_owner);
            for (uint16_t i = 1; i < 5; ++i)
            {
                EXPECT_EQ(owner_of(static_cast<uint16_t>(51000 + i)), old_owner);
                EXPECT_EQ(owner_of(static_cast<uint16_t>(52000 + i)), new_owner);
            }

            EXPECT_EQ(os().capture_since(m, tcp ? table_kind::tcp_v4 : table_kind::udp_v4).owner_lookups, 1);
            EXPECT_EQ(os().capture_since(m, tcp ? table_kind::tcp_v6 : table_kind::udp_v6).owner_lookups, 1)
                << "the supplement enriches the identity in its own capture";
        }
    }

    TEST_F(OwnerMemoMappedTest, Ipv6TcpScopeIdsRemainPartOfTheSessionKey)
    {
        os().images[2600] = image(L"SCOPE5.EXE");
        os().images[2601] = image(L"SCOPE7.EXE");
        os().tcp6.push_back(tcp6_row(2600, 0, "fe80::1", 53000, "fe80::9", 8080, 5, 5));
        os().tcp6.push_back(tcp6_row(2601, 0, "fe80::1", 53000, "fe80::9", 8080, 7, 7));

        lookup_v6 lookup;

        const auto on5 = lookup.lookup_process_for_tcp<false>(session6("fe80::1", 53000, "fe80::9", 8080, 5, 5));
        const auto on7 = lookup.lookup_process_for_tcp<false>(session6("fe80::1", 53000, "fe80::9", 8080, 7, 7));
        ASSERT_TRUE(on5 && on7);
        EXPECT_EQ(on5->name, L"SCOPE5.EXE");
        EXPECT_EQ(on7->name, L"SCOPE7.EXE");
        EXPECT_EQ(lookup.lookup_process_for_tcp<false>(session6("fe80::1", 53000, "fe80::9", 8080, 9, 9)), nullptr);
    }

    TEST_F(OwnerMemoMappedTest, Ipv6UdpEndpointsAreKeyedWithScopeZero)
    {
        os().images[2700] = image(L"LINKLOCAL.EXE");
        os().udp6.push_back(udp6_row(2700, 0, "fe80::1", 5600, 5));

        lookup_v6 lookup;

        const auto unscoped = lookup.lookup_process_for_udp<false>(endpoint6("fe80::1", 5600));
        ASSERT_TRUE(unscoped);
        EXPECT_EQ(unscoped->name, L"LINKLOCAL.EXE");
        EXPECT_EQ(lookup.lookup_process_for_udp<false>(endpoint6("fe80::1", 5600, 0)), unscoped);
        EXPECT_EQ(lookup.lookup_process_for_udp<false>(endpoint6("fe80::1", 5600, 5)), nullptr)
            << "the row's scope is not part of the published key";
    }

    TEST_F(OwnerMemoMappedTest, PrimaryAndSupplementIdentitiesAreEnrichedOncePerCapture)
    {
        // The same live process owns native and mapped rows: each capture enriches it once and
        // the two captures do not share an owner object.
        os().images[2800] = image(L"BOTH.EXE");
        for (uint16_t i = 0; i < 25; ++i)
        {
            os().tcp4.push_back(tcp4_row(2800, 0, "127.0.0.1", static_cast<uint16_t>(54000 + i), "127.0.0.1", 8080));
            os().tcp6.push_back(tcp6_row(2800, 0, "::ffff:127.0.0.1", static_cast<uint16_t>(55000 + i), "::ffff:127.0.0.1", 8080));
            os().udp4.push_back(udp4_row(2800, 0, "127.0.0.1", static_cast<uint16_t>(54000 + i)));
            os().udp6.push_back(udp6_row(2800, 0, "::ffff:127.0.0.1", static_cast<uint16_t>(55000 + i)));
        }

        const auto m = mark();
        lookup_v4 lookup;

        const auto captures = os().captures_since(m);
        ASSERT_EQ(captures.size(), 4u) << "TCP primary + supplement, UDP primary + supplement";
        for (const auto& c : captures)
        {
            EXPECT_EQ(c.rows, 25u) << to_string(c.kind);
            EXPECT_EQ(c.owner_lookups, 1) << to_string(c.kind);
            EXPECT_GT(c.memo_allocations, 0) << to_string(c.kind);
        }

        const auto tcp_native = lookup.lookup_process_for_tcp<false>(session4("127.0.0.1", 54000, "127.0.0.1", 8080));
        const auto tcp_mapped = lookup.lookup_process_for_tcp<false>(session4("127.0.0.1", 55000, "127.0.0.1", 8080));
        const auto udp_native = lookup.lookup_process_for_udp<false>(endpoint4("127.0.0.1", 54000));
        const auto udp_mapped = lookup.lookup_process_for_udp<false>(endpoint4("127.0.0.1", 55000));
        ASSERT_TRUE(tcp_native && tcp_mapped && udp_native && udp_mapped);
        const std::set<iphelper::network_process*> distinct{ tcp_native.get(), tcp_mapped.get(), udp_native.get(), udp_mapped.get() };
        EXPECT_EQ(distinct.size(), 4u) << "no owner object is shared across captures or protocols";
    }
}
