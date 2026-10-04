#include "pch.h"

#include <random>

// -----------------------------------------------------------------------------
// Tests for iphelper::owner_memo / memoized_owner, the per-capture memo that lets a connection-table
// build enrich each (PID, service tag) once instead of once per row.
//
// Ported from WireSock (fa8f028b7bd4c88fb2903803f7be06f7814d82b9,
// netlib/test/iphelper/owner_memo_test.cpp). The memoized type is Proxifyre's immutable
// owner_identity; process_lookup builds each row's network_process (which adds the routing state)
// from it, so no mutable state is ever shared between rows.
//
// The rows are the real Windows row types (TCPv4/v6, UDPv4/v6 owner-module rows) and the loop is
// the build's loop: every row goes through memoized_owner(). The enrichment is a scripted double
// so that each case - success, transient failure, a process exiting mid-build, PID reuse - is
// exact. "Per-row" below is the behaviour before the memo: enrich every row.
// process_lookup's own loops and enrichment are exercised in owner_memo_lookup_test.cpp.
// -----------------------------------------------------------------------------

namespace iphelper::test {
namespace {

using identity_ptr = std::shared_ptr<const owner_identity>;

template <class Row>
Row make_row(const DWORD pid, const DWORD service_tag, const DWORD local_port)
{
    Row row{};
    row.dwOwningPid = pid;
    row.OwningModuleInfo[0] = service_tag; // service_tag_from_owning_module_info reads the low 32 bits
    row.dwLocalPort = local_port;          // stands in for the tuple
    return row;
}

/// Scripted enrichment: outcome per (pid, tag) and call ordinal, counting every call.
class fake_enricher
{
public:
    /// The next calls for this identity fail (false) or succeed (true) in this order; then succeed.
    void script(const DWORD pid, const DWORD tag, std::vector<bool> outcomes) { scripts_[key(pid, tag)] = std::move(outcomes); }
    /// Every call for this identity fails.
    void always_fail(const DWORD pid, const DWORD tag) { failing_.insert(key(pid, tag)); }
    /// The process behind this PID is replaced (PID reuse): later successes carry the new generation.
    void reuse_pid(const DWORD pid) { ++generation_[pid]; }

    template <class Row>
    identity_ptr operator()(const Row* row)
    {
        ++calls;
        const DWORD pid = row->dwOwningPid;
        if (owner_module_resolver::is_system_process(pid))
            return nullptr; // the resolver's own skip
        const DWORD tag = owner_module_resolver::service_tag_from_owning_module_info(row->OwningModuleInfo);
        ++user_calls;
        const auto k = key(pid, tag);
        if (failing_.contains(k))
            return nullptr;
        if (auto it = scripts_.find(k); it != scripts_.end() && it->second.size() > ordinal_[k])
            if (!it->second[ordinal_[k]++])
                return nullptr;
        ++successes;
        return std::make_shared<const owner_identity>(pid, name(pid, tag), L"PROC-" + std::to_wstring(generation_[pid]));
    }

    static std::wstring name(const DWORD pid, const DWORD tag)
    {
        return L"P" + std::to_wstring(pid) + L"-T" + std::to_wstring(tag);
    }

    int calls = 0, user_calls = 0, successes = 0;

private:
    static std::uint64_t key(const DWORD pid, const DWORD tag) { return (static_cast<std::uint64_t>(pid) << 32) | tag; }
    std::unordered_map<std::uint64_t, std::vector<bool>> scripts_;
    std::unordered_map<std::uint64_t, size_t> ordinal_;
    std::unordered_set<std::uint64_t> failing_;
    std::unordered_map<DWORD, int> generation_;
};

/// What one build publishes: local port -> owner (null when the row was left out).
struct build_result
{
    std::vector<std::pair<DWORD, identity_ptr>> owners;
    size_t memoized = 0;

    /// tuple -> (pid, name, path) for comparing builds by content rather than by object.
    [[nodiscard]] std::vector<std::tuple<DWORD, unsigned long, std::wstring, std::wstring>> fingerprint() const
    {
        std::vector<std::tuple<DWORD, unsigned long, std::wstring, std::wstring>> f;
        for (const auto& [port, owner] : owners)
            if (owner)
                f.emplace_back(port, owner->id, owner->name, owner->path_name);
        return f;
    }
    [[nodiscard]] identity_ptr at(const DWORD port) const
    {
        for (const auto& [p, owner] : owners)
            if (p == port)
                return owner;
        return nullptr;
    }
};

/// The build loop with the memo (as process_lookup's table builds run it).
template <class Row>
build_result build_memoized(const std::vector<Row>& rows, fake_enricher& enrich)
{
    build_result result;
    owner_memo<const owner_identity> owners; // this build only
    for (const auto& row : rows)
        result.owners.emplace_back(row.dwLocalPort,
            memoized_owner(owners, &row, [&](const Row* r) { return enrich(r); }));
    result.memoized = owners.size();
    return result;
}

/// The loop before the memo: every row enriched on its own.
template <class Row>
build_result build_per_row(const std::vector<Row>& rows, fake_enricher& enrich)
{
    build_result result;
    for (const auto& row : rows)
        result.owners.emplace_back(row.dwLocalPort, enrich(&row));
    return result;
}

template <class Row>
class OwnerMemoTest : public ::testing::Test
{
};

using row_types = ::testing::Types<MIB_TCPROW_OWNER_MODULE, MIB_TCP6ROW_OWNER_MODULE,
                                   MIB_UDPROW_OWNER_MODULE, MIB_UDP6ROW_OWNER_MODULE>;
TYPED_TEST_CASE(OwnerMemoTest, row_types);

// ---------------------------------------------------------------- one identity, many rows

TYPED_TEST(OwnerMemoTest, OneIdentityManyRowsIsEnrichedOnce)
{
    std::vector<TypeParam> rows;
    for (DWORD i = 0; i < 50; ++i)
        rows.push_back(make_row<TypeParam>(1000, 0, 10000 + i));

    fake_enricher per_row_enrich, memo_enrich;
    const auto per_row = build_per_row(rows, per_row_enrich);
    const auto memoized = build_memoized(rows, memo_enrich);

    EXPECT_EQ(per_row_enrich.user_calls, 50);
    EXPECT_EQ(memo_enrich.user_calls, 1) << "one enrichment for the identity";
    EXPECT_EQ(memoized.memoized, 1u);
    ASSERT_EQ(memoized.fingerprint().size(), 50u) << "every tuple is still published";
    EXPECT_EQ(memoized.fingerprint(), per_row.fingerprint());
    for (const auto& [port, owner] : memoized.owners)
        EXPECT_EQ(owner.get(), memoized.owners.front().second.get()) << "rows share the enriched object";
}

TYPED_TEST(OwnerMemoTest, SamePidDifferentServiceTagsStayDistinct)
{
    // One svchost process hosting three services (tags 7 and 9, and untagged rows of the host).
    std::vector<TypeParam> rows;
    for (DWORD i = 0; i < 30; ++i)
        rows.push_back(make_row<TypeParam>(1200, i % 3 == 0 ? 0 : (i % 3 == 1 ? 7 : 9), 20000 + i));

    fake_enricher per_row_enrich, memo_enrich;
    const auto per_row = build_per_row(rows, per_row_enrich);
    const auto memoized = build_memoized(rows, memo_enrich);

    EXPECT_EQ(memo_enrich.user_calls, 3) << "one enrichment per (PID, service tag)";
    EXPECT_EQ(memoized.memoized, 3u);
    EXPECT_EQ(memoized.fingerprint(), per_row.fingerprint());
    EXPECT_EQ(memoized.at(20000)->name, fake_enricher::name(1200, 0));
    EXPECT_EQ(memoized.at(20001)->name, fake_enricher::name(1200, 7));
    EXPECT_EQ(memoized.at(20002)->name, fake_enricher::name(1200, 9));
    EXPECT_NE(memoized.at(20000).get(), memoized.at(20001).get());
    EXPECT_NE(memoized.at(20001).get(), memoized.at(20002).get());
    EXPECT_EQ(memoized.at(20001).get(), memoized.at(20004).get());
}

TYPED_TEST(OwnerMemoTest, DifferentPidsAreEnrichedIndependently)
{
    std::vector<TypeParam> rows;
    for (DWORD i = 0; i < 40; ++i)
        rows.push_back(make_row<TypeParam>(2000 + i % 4, 0, 30000 + i)); // interleaved, as in a live table

    fake_enricher per_row_enrich, memo_enrich;
    const auto per_row = build_per_row(rows, per_row_enrich);
    const auto memoized = build_memoized(rows, memo_enrich);

    EXPECT_EQ(memo_enrich.user_calls, 4);
    EXPECT_EQ(memoized.fingerprint(), per_row.fingerprint());
    for (DWORD i = 0; i < 40; ++i)
        EXPECT_EQ(memoized.at(30000 + i)->id, 2000 + i % 4);
}

TYPED_TEST(OwnerMemoTest, SystemRowsBypassTheMemo)
{
    // PID 0 (TIME_WAIT) and PID 4 rows: enriched (skipped) by the resolver itself, never memoized.
    std::vector<TypeParam> rows;
    for (DWORD i = 0; i < 100; ++i)
        rows.push_back(make_row<TypeParam>(i % 2 ? 0 : 4, 0, 40000 + i));
    rows.push_back(make_row<TypeParam>(3000, 0, 40100));

    fake_enricher enrich;
    const auto memoized = build_memoized(rows, enrich);

    EXPECT_EQ(enrich.calls, 101) << "system rows reach the resolver's own skip, as before";
    EXPECT_EQ(memoized.memoized, 1u) << "only the user identity is memoized";
    EXPECT_EQ(memoized.fingerprint().size(), 1u);
}

TYPED_TEST(OwnerMemoTest, SystemRowsAreNotStoredEvenWhenTheirEnrichmentSucceeds)
{
    // The memo itself keeps PID 0/4 out of its storage, whatever the enrichment returns.
    owner_memo<const owner_identity> owners;
    const auto idle = make_row<TypeParam>(0, 0, 40200);
    const auto system = make_row<TypeParam>(4, 0, 40201);
    int calls = 0;
    const auto enrich = [&](const TypeParam* row) -> owner_enrichment<const owner_identity> {
        ++calls;
        return { std::make_shared<const owner_identity>(row->dwOwningPid, L"SYSTEM", L"SYSTEM"), true };
    };
    for (int i = 0; i < 3; ++i)
    {
        EXPECT_TRUE(memoized_owner(owners, &idle, enrich));
        EXPECT_TRUE(memoized_owner(owners, &system, enrich));
    }
    EXPECT_EQ(calls, 6);
    EXPECT_EQ(owners.size(), 0u);
}

// ---------------------------------------------------------------- failures

TYPED_TEST(OwnerMemoTest, TransientFailureIsRetriedOnTheIdentitysNextRow)
{
    // Row 1 of P fails (e.g. OpenProcess denied for a moment), row 2 succeeds: exactly what the
    // per-row loop publishes - row 1 left out, every later row owned by P.
    std::vector<TypeParam> rows;
    for (DWORD i = 0; i < 10; ++i)
        rows.push_back(make_row<TypeParam>(1300, 0, 50000 + i));

    fake_enricher per_row_enrich, memo_enrich;
    per_row_enrich.script(1300, 0, { false });
    memo_enrich.script(1300, 0, { false });
    const auto per_row = build_per_row(rows, per_row_enrich);
    const auto memoized = build_memoized(rows, memo_enrich);

    EXPECT_FALSE(memoized.at(50000)) << "the failed row is left out, as before";
    ASSERT_TRUE(memoized.at(50001)) << "the identity's next row retries and succeeds";
    EXPECT_EQ(memo_enrich.user_calls, 2);
    EXPECT_EQ(memoized.fingerprint(), per_row.fingerprint());
}

TYPED_TEST(OwnerMemoTest, FailureIsNeverMemoized)
{
    std::vector<TypeParam> rows;
    for (DWORD i = 0; i < 10; ++i)
        rows.push_back(make_row<TypeParam>(1400, 0, 51000 + i));

    fake_enricher per_row_enrich, memo_enrich;
    per_row_enrich.always_fail(1400, 0);
    memo_enrich.always_fail(1400, 0);
    const auto per_row = build_per_row(rows, per_row_enrich);
    const auto memoized = build_memoized(rows, memo_enrich);

    EXPECT_EQ(memo_enrich.user_calls, 10) << "every row of a failing identity is still attempted";
    EXPECT_EQ(memoized.memoized, 0u);
    EXPECT_TRUE(memoized.fingerprint().empty());
    EXPECT_EQ(memoized.fingerprint(), per_row.fingerprint());
}

TYPED_TEST(OwnerMemoTest, ProcessExitingMidBuildKeepsItsRemainingRows)
{
    // The one intended difference. P owns 10 rows of the enumeration; its first row is enriched,
    // then P exits (its later enrichments would fail). The per-row loop drops those rows; the memo
    // keeps them with the owner the enumeration reported, which the next build corrects anyway.
    std::vector<TypeParam> rows;
    for (DWORD i = 0; i < 10; ++i)
        rows.push_back(make_row<TypeParam>(1500, 0, 52000 + i));

    fake_enricher per_row_enrich, memo_enrich;
    const std::vector<bool> exits_after_first(10, false);
    auto script = exits_after_first;
    script[0] = true;
    per_row_enrich.script(1500, 0, script);
    memo_enrich.script(1500, 0, script);
    const auto per_row = build_per_row(rows, per_row_enrich);
    const auto memoized = build_memoized(rows, memo_enrich);

    EXPECT_EQ(per_row.fingerprint().size(), 1u);
    EXPECT_EQ(memoized.fingerprint().size(), 10u);
    for (const auto& [port, owner] : memoized.owners)
        EXPECT_EQ(owner->id, 1500u);
}

// ---------------------------------------------------------------- partial results

TYPED_TEST(OwnerMemoTest, PartialEnrichmentIsReturnedButRetriedUntilComplete)
{
    // A service lookup can fail while its host-image fallback succeeds. Keeping that owner
    // for row 1 must not prevent row 2 from recovering the service identity.
    owner_memo<const owner_identity> owners;
    auto row = make_row<TypeParam>(1501, 7, 52001);
    const auto host = std::make_shared<const owner_identity>(1501, L"HOST.EXE", L"HOST.EXE");
    const auto service = std::make_shared<const owner_identity>(1501, L"SERVICE", L"SERVICE");
    int calls = 0;
    const auto enrich = [&](const TypeParam*) -> owner_enrichment<const owner_identity> {
        return ++calls == 1 ? owner_enrichment<const owner_identity>{host, false}
                            : owner_enrichment<const owner_identity>{service, true};
    };
    const auto first = memoized_owner(owners, &row, enrich);
    EXPECT_EQ(first, host);
    EXPECT_EQ(owners.size(), 0u);
    const auto second = memoized_owner(owners, &row, enrich);
    const auto third = memoized_owner(owners, &row, enrich);
    EXPECT_EQ(first->name, L"HOST.EXE");
    EXPECT_EQ(second->name, L"SERVICE");
    EXPECT_EQ(third, second);
    EXPECT_EQ(calls, 2);
    EXPECT_EQ(owners.size(), 1u);
}

TYPED_TEST(OwnerMemoTest, RepeatedPartialEnrichmentIsNeverMemoized)
{
    owner_memo<const owner_identity> owners;
    auto row = make_row<TypeParam>(1502, 9, 52002);
    const auto host = std::make_shared<const owner_identity>(1502, L"HOST.EXE", L"HOST.EXE");
    int calls = 0;
    for (int i = 0; i < 3; ++i)
        EXPECT_EQ(memoized_owner(owners, &row, [&](const TypeParam*) -> owner_enrichment<const owner_identity> {
            ++calls;
            return {host, false};
        }), host);
    EXPECT_EQ(calls, 3);
    EXPECT_EQ(owners.size(), 0u);
}

TYPED_TEST(OwnerMemoTest, IncompleteDevicePathIsRetriedWithoutDroppingItsRow)
{
    // Simulate the outputs of a failed, then successful, QueryDosDeviceW conversion. The two
    // owners are built independently.
    const auto make_owner = [](std::wstring device_path)
    {
        auto owner = std::make_shared<owner_identity>();
        owner->id = 1503;
        owner->name = L"APP.EXE";
        owner->path_name = L"X:\\APP.EXE";
        owner->device_path_name = std::move(device_path);
        return owner;
    };
    auto row = make_row<TypeParam>(1503, 0, 52003);
    const auto partial = make_owner(L"");
    const auto complete = make_owner(L"\\DEVICE\\VOLUME\\APP.EXE");
    owner_memo<const owner_identity> owners;
    int calls = 0;
    const auto enrich = [&](const TypeParam*) -> owner_enrichment<const owner_identity> {
        const auto owner = ++calls == 1 ? partial : complete;
        return {owner, owner->has_complete_device_path()};
    };
    EXPECT_EQ(memoized_owner(owners, &row, enrich), partial);
    EXPECT_EQ(owners.size(), 0u);
    EXPECT_EQ(memoized_owner(owners, &row, enrich), complete);
    EXPECT_EQ(memoized_owner(owners, &row, enrich), complete);
    EXPECT_EQ(calls, 2);
    EXPECT_TRUE(partial->device_path_name.empty());
    EXPECT_EQ(complete->device_path_name, L"\\DEVICE\\VOLUME\\APP.EXE");
}

TEST(OwnerMemoMetadataTest, NonDrivePathsNeedNoDeviceConversion)
{
    owner_identity service(1504, L"SERVICE", L"SERVICE");
    EXPECT_TRUE(service.has_complete_device_path());
    EXPECT_TRUE(service.device_path_name.empty());
    owner_identity unc(1504, L"APP.EXE", L"\\\\SERVER\\SHARE\\APP.EXE");
    EXPECT_TRUE(unc.has_complete_device_path());
    owner_identity empty;
    EXPECT_TRUE(empty.has_complete_device_path());
}

TEST(OwnerMemoMetadataTest, DrivePathIsCompleteOnlyWithItsDevicePath)
{
    owner_identity partial;
    partial.path_name = L"X:\\APP.EXE";
    EXPECT_FALSE(partial.has_complete_device_path());
    partial.device_path_name = L"\\DEVICE\\HARDDISKVOLUME9\\APP.EXE";
    EXPECT_TRUE(partial.has_complete_device_path());
}

TEST(OwnerMemoMetadataTest, CompletenessDoesNotChangeTheResolvedState)
{
    // Memoization completeness and ownership resolution are separate properties: an owner with
    // an incomplete device path is still a resolved owner.
    owner_identity partial(1505, L"APP.EXE", L"X:\\APP.EXE");
    partial.device_path_name.clear();
    EXPECT_FALSE(partial.has_complete_device_path());
    EXPECT_TRUE(partial.resolved);
    const owner_identity unresolved(0, L"SYSTEM", L"SYSTEM", false);
    EXPECT_TRUE(unresolved.has_complete_device_path());
    EXPECT_FALSE(unresolved.resolved);
}

// ---------------------------------------------------------------- lifetime and PID reuse

TYPED_TEST(OwnerMemoTest, PidReusedAfterEnrichmentKeepsCapturedOwnerForThisBuild)
{
    const auto row = make_row<TypeParam>(1601, 0, 53001);
    owner_memo<const owner_identity> owners;
    fake_enricher enrich;
    const auto first = memoized_owner(owners, &row, [&](const auto* r) { return enrich(r); });
    enrich.reuse_pid(1601);
    const auto later = memoized_owner(owners, &row, [&](const auto* r) { return enrich(r); });
    const auto per_row = enrich(&row);
    EXPECT_EQ(first, later);
    EXPECT_EQ(later->path_name, L"PROC-0");
    EXPECT_EQ(per_row->path_name, L"PROC-1");
    owner_memo<const owner_identity> next_build;
    EXPECT_EQ(memoized_owner(next_build, &row, [&](const auto* r) { return enrich(r); })->path_name, L"PROC-1");
}

TYPED_TEST(OwnerMemoTest, PidReusedBeforeFirstEnrichmentHasTheBaselineRace)
{
    const auto row = make_row<TypeParam>(1602, 0, 53002);
    fake_enricher enrich;
    enrich.reuse_pid(1602); // capture happened first; neither implementation has a process birth time
    owner_memo<const owner_identity> owners;
    const auto memo = memoized_owner(owners, &row, [&](const auto* r) { return enrich(r); });
    const auto per_row = enrich(&row);
    EXPECT_EQ(memo->path_name, L"PROC-1");
    EXPECT_EQ(memo->path_name, per_row->path_name);
}

TYPED_TEST(OwnerMemoTest, EveryBuildEnrichesAfresh)
{
    // Two consecutive builds of the same table: each enriches for itself. Between them PID 1600
    // is reused by another process (a new creation time): the second build sees the new process.
    std::vector<TypeParam> rows;
    for (DWORD i = 0; i < 20; ++i)
        rows.push_back(make_row<TypeParam>(1600, 0, 53000 + i));

    fake_enricher enrich;
    const auto first = build_memoized(rows, enrich);
    enrich.reuse_pid(1600);
    const auto second = build_memoized(rows, enrich);

    EXPECT_EQ(enrich.user_calls, 2) << "one enrichment per build, none carried over";
    ASSERT_TRUE(first.at(53000) && second.at(53000));
    EXPECT_NE(first.at(53000).get(), second.at(53000).get());
    EXPECT_EQ(first.at(53019)->path_name, L"PROC-0");
    EXPECT_EQ(second.at(53019)->path_name, L"PROC-1") << "the reused PID resolves to the new process";
}

// ---------------------------------------------------------------- allocation failure

/// Allocator whose allocations throw once armed.
template <class T>
struct failing_allocator
{
    using value_type = T;
    static inline bool armed = false;

    failing_allocator() noexcept = default;
    template <class U>
    failing_allocator(const failing_allocator<U>&) noexcept {}

    T* allocate(const size_t n)
    {
        if (failing_allocator<char>::armed)
            throw std::bad_alloc();
        return std::allocator<T>{}.allocate(n);
    }
    void deallocate(T* p, const size_t n) noexcept { std::allocator<T>{}.deallocate(p, n); }
    template <class U>
    bool operator==(const failing_allocator<U>&) const noexcept { return true; }
};

TYPED_TEST(OwnerMemoTest, MemoizingFailureThrowsAndMemoizesNothing)
{
    using memo_t = owner_memo<const owner_identity, failing_allocator<std::pair<const std::uint64_t, identity_ptr>>>;
    memo_t owners;
    const auto row = make_row<TypeParam>(1700, 0, 54000);
    fake_enricher enrich;
    failing_allocator<char>::armed = true;
    EXPECT_THROW(memoized_owner(owners, &row, [&](const auto* r) { return enrich(r); }), std::bad_alloc);
    failing_allocator<char>::armed = false;
    EXPECT_EQ(owners.size(), 0u);
    EXPECT_EQ(enrich.user_calls, 1);
    EXPECT_TRUE(memoized_owner(owners, &row, [&](const auto* r) { return enrich(r); }));
    EXPECT_EQ(owners.size(), 1u);
}

// ---------------------------------------------------------------- equivalence on random tables

TYPED_TEST(OwnerMemoTest, PublishesWhatPerRowEnrichmentPublishes)
{
    // Random tables shaped like the live ones: mostly PID 0 rows, some PID 4, a few processes
    // owning many rows, svchost-style PIDs with several service tags, and identities that never
    // resolve (protected processes). Enrichment is deterministic per identity, as it is while the
    // processes stay alive: memoized and per-row builds must publish the same tuple -> owner map.
    std::mt19937 random(20260926);
    for (int table = 0; table < 50; ++table)
    {
        std::vector<TypeParam> rows;
        const int row_count = 200 + static_cast<int>(random() % 800);
        for (int i = 0; i < row_count; ++i)
        {
            const auto dice = random() % 100;
            const DWORD pid = dice < 60 ? 0 : dice < 62 ? 4 : 5000 + static_cast<DWORD>(random() % 16);
            const DWORD tag = pid >= 5012 ? static_cast<DWORD>(random() % 3) * 11 : 0;
            rows.push_back(make_row<TypeParam>(pid, tag, static_cast<DWORD>(i)));
        }
        fake_enricher per_row_enrich, memo_enrich;
        for (auto* e : { &per_row_enrich, &memo_enrich })
        {
            e->always_fail(5003, 0);
            e->always_fail(5013, 11);
        }
        const auto per_row = build_per_row(rows, per_row_enrich);
        const auto memoized = build_memoized(rows, memo_enrich);

        ASSERT_EQ(memoized.fingerprint(), per_row.fingerprint()) << "table " << table;
        std::set<std::pair<DWORD, DWORD>> identities;
        int failing_rows = 0;
        for (const auto& row : rows)
        {
            if (owner_module_resolver::is_system_process(row.dwOwningPid))
                continue;
            const auto tag = owner_module_resolver::service_tag_from_owning_module_info(row.OwningModuleInfo);
            if ((row.dwOwningPid == 5003 && tag == 0) || (row.dwOwningPid == 5013 && tag == 11))
                ++failing_rows;
            else
                identities.emplace(row.dwOwningPid, tag);
        }
        EXPECT_EQ(memo_enrich.user_calls, static_cast<int>(identities.size()) + failing_rows)
            << "one enrichment per resolvable identity, plus a retry for every row of a failing one";
        EXPECT_EQ(memoized.memoized, identities.size());
    }
}

} // namespace
} // namespace iphelper::test
