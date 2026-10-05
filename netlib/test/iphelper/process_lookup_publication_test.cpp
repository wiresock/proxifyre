// Publication and retirement of process_lookup's ownership tables.
//
// Every refresh builds a candidate table outside the table's reader lock, then publishes it in
// place of the current one. These tests run the production builds and publication of all six
// ingestion loops (fake_ownership_source.h) and observe them from other threads:
//   * owners that only the replaced table still references are destroyed after its reader lock
//     is released: while such an owner's deleter runs on the refreshing thread, another thread
//     takes the reader lock and completes production lookups that already see the new table;
//   * cached lookups complete against the published table while a candidate's capture or row
//     enrichment is paused;
//   * a failed candidate build publishes nothing and retires nothing;
//   * an owner a reader holds outlives the table that published it, and is destroyed when that
//     reader releases it, with the table's lock free.
//
// A published row's owner is made observable by replacing it with an equal object whose deleter
// reports to a retirement_probe (loop_harness::replace_owner); the test then drops its own
// references, so the published table holds the last one. A probe never touches a table lock from
// the refreshing thread, which may hold it. Every wait is bounded, and every worker thread is
// released and joined on all paths, including a failed assertion.

#include "pch.h"
#include <condition_variable>
#include "test_support.h"
#include "fake_ownership_source.h"

namespace
{
    using namespace netlib_test::ownership;
    using owner_ref = std::weak_ptr<iphelper::network_process>;

    /// How long a thread waits for another to make progress that needs no further event: a reader
    /// completing its lookups while a retired owner is being destroyed.
    constexpr std::chrono::seconds progress_timeout{ 5 };
    /// How long a thread waits for a stage that the test drives: a refresh reaching a pause, a
    /// replaced owner starting to be destroyed, a paused refresh being resumed.
    constexpr std::chrono::seconds stage_timeout{ 30 };

    /// A one-shot signal with bounded waits.
    class event
    {
    public:
        void set()
        {
            {
                std::scoped_lock lock(mutex_);
                set_ = true;
            }
            cv_.notify_all();
        }

        [[nodiscard]] bool wait(const std::chrono::seconds timeout = stage_timeout)
        {
            std::unique_lock lock(mutex_);
            return cv_.wait_for(lock, timeout, [this] { return set_; });
        }

        [[nodiscard]] bool is_set()
        {
            std::scoped_lock lock(mutex_);
            return set_;
        }

    private:
        std::mutex mutex_;
        std::condition_variable cv_;
        bool set_{ false };
    };

    /// Runs a body on a new thread. On stop() or destruction, release() is called first (it must
    /// make the body finish promptly) and the thread is joined, so no path leaves it running.
    class worker
    {
    public:
        worker(std::function<void()> body, std::function<void()> release)
            : release_(std::move(release)), thread_(std::move(body))
        {
        }

        worker(const worker&) = delete;
        worker& operator=(const worker&) = delete;

        ~worker() { stop(); }

        void stop()
        {
            if (thread_.joinable())
            {
                release_();
                thread_.join();
            }
        }

        [[nodiscard]] std::thread::id id() const noexcept { return thread_.get_id(); }

    private:
        std::function<void()> release_;
        std::thread thread_;
    };

    /// Observes the destruction of one owner object (see observed_owner).
    ///
    /// The owner's deleter calls retire() on the thread that releases the last reference. retire()
    /// records that thread and runs the check installed for it. While a reader is expected, it
    /// then waits (bounded) for that reader to report before the owner is deleted: a reader that
    /// cannot progress until the deleter returns is detected by the timeout instead of deadlocking.
    class retirement_probe
    {
    public:
        /// retire() waits for reader_report() (or cancel()).
        void expect_reader()
        {
            std::scoped_lock lock(mutex_);
            reader_expected_ = true;
        }

        /// Runs @p check on the releasing thread at retirement, before the owner is deleted.
        void check_at_retirement(std::function<void()> check)
        {
            std::scoped_lock lock(mutex_);
            check_ = std::move(check);
        }

        /// Called by the owner's deleter.
        void retire()
        {
            std::function<void()> check;
            {
                std::scoped_lock lock(mutex_);
                check = std::move(check_);
            }
            if (check)
                check();

            std::unique_lock lock(mutex_);
            retired_ = true;
            retiring_thread_ = std::this_thread::get_id();
            cv_.notify_all();
            if (reader_expected_)
                cv_.wait_for(lock, progress_timeout, [this] { return reader_reported_ || cancelled_; });
            reader_reported_before_deletion_ = reader_reported_;
        }

        /// Reader: waits until the owner is being destroyed; false if it was not (timeout or cancel).
        [[nodiscard]] bool wait_until_retiring()
        {
            std::unique_lock lock(mutex_);
            cv_.wait_for(lock, stage_timeout, [this] { return retired_ || cancelled_; });
            return retired_;
        }

        /// Reader: its work during the retirement is complete.
        void reader_report()
        {
            {
                std::scoped_lock lock(mutex_);
                reader_reported_ = true;
            }
            cv_.notify_all();
        }

        /// Releases every wait: the test is finishing.
        void cancel()
        {
            {
                std::scoped_lock lock(mutex_);
                cancelled_ = true;
            }
            cv_.notify_all();
        }

        [[nodiscard]] bool retired()
        {
            std::scoped_lock lock(mutex_);
            return retired_;
        }

        [[nodiscard]] std::thread::id retiring_thread()
        {
            std::scoped_lock lock(mutex_);
            return retiring_thread_;
        }

        [[nodiscard]] bool reader_reported_before_deletion()
        {
            std::scoped_lock lock(mutex_);
            return reader_reported_before_deletion_;
        }

    private:
        std::mutex mutex_;
        std::condition_variable cv_;
        std::function<void()> check_;
        bool reader_expected_{ false };
        bool retired_{ false };
        bool reader_reported_{ false };
        bool reader_reported_before_deletion_{ false };
        bool cancelled_{ false };
        std::thread::id retiring_thread_;
    };

    struct probing_deleter
    {
        std::shared_ptr<retirement_probe> probe;

        void operator()(const iphelper::network_process* owner) const noexcept
        {
            probe->retire();
            delete owner;
        }
    };

    /// An owner object with the identity of @p published (and fresh routing state, like every
    /// published row's owner) whose destruction @p probe observes.
    process_ptr observed_owner(const iphelper::network_process& published, std::shared_ptr<retirement_probe> probe)
    {
        return { new iphelper::network_process(static_cast<const iphelper::owner_identity&>(published)),
            probing_deleter{ std::move(probe) } };
    }

    /// Whether @p mutex can be locked shared right now. Never call it on a thread that may hold
    /// @p mutex: the refreshing thread, or a deleter that may run on it.
    bool reader_lock_available(std::shared_mutex& mutex)
    {
        if (!mutex.try_lock_shared())
            return false;
        mutex.unlock_shared();
        return true;
    }

    class ProcessLookupPublicationTest : public loop_fixture
    {
    protected:
        /// Publishes the loop's row 0, owned by OLD.EXE, and replaces its owner with an equal
        /// object observed by @p probe that only the published table references.
        void publish_observed_row(const std::shared_ptr<retirement_probe>& probe, owner_ref& observed)
        {
            os().images[900] = image(L"OLD.EXE");
            h().clear_rows();
            h().add_row(900, 0, 0);
            ASSERT_TRUE(h().refresh());

            {
                const auto published = h().owner(0);
                ASSERT_TRUE(published);
                ASSERT_EQ(published->name, L"OLD.EXE");
                auto replacement = observed_owner(*published, probe);
                observed = replacement;
                ASSERT_TRUE(h().replace_owner(0, std::move(replacement)));
            }
            {
                const auto looked_up = h().owner(0);
                ASSERT_TRUE(looked_up);
                ASSERT_EQ(looked_up, observed.lock()) << "the production lookup returns the observed owner";
                ASSERT_EQ(looked_up->name, L"OLD.EXE");
            }
            ASSERT_EQ(observed.use_count(), 1) << "the published table holds the only reference";
            ASSERT_FALSE(probe->retired());
        }

        /// The next capture: row 0 is gone and row 1 is owned by NEW.EXE.
        void stage_replacement()
        {
            os().images[901] = image(L"NEW.EXE");
            h().clear_rows();
            h().add_row(901, 0, 1);
        }

        void expect_replacement_published()
        {
            EXPECT_EQ(h().owner(0), nullptr) << "the replaced row is no longer published";
            const auto replacement = h().owner(1);
            ASSERT_TRUE(replacement) << "the replacement is published";
            EXPECT_EQ(replacement->name, L"NEW.EXE");
        }

        enum class pause_stage : uint8_t { capture, enrichment };

        /// Pauses a refresh at @p stage of its candidate build and checks that readers use the
        /// published table meanwhile, then that the resumed refresh publishes the candidate.
        void expect_readers_progress_while_the_build_is_paused(const pause_stage stage)
        {
            os().images[900] = image(L"OLD.EXE");
            h().add_row(900, 0, 0);
            ASSERT_TRUE(h().refresh());
            const auto published = h().owner(0);
            ASSERT_TRUE(published);
            stage_replacement();

            // The refresh pauses (once) when it reaches the stage: the capture of this loop's
            // table (for a supplementary loop, after the primary capture has been ingested into
            // the candidate) or the enrichment of the replacement's owner.
            event paused, resume;
            const auto pause = [&] { paused.set(); (void)resume.wait(); };
            if (stage == pause_stage::capture)
                os().on_capture = [pause, kind = h().capture()](const table_kind k) { if (k == kind) pause(); };
            else
                os().on_owner_lookup = [pause](const DWORD pid, DWORD) { if (pid == 901) pause(); };

            bool refreshed = false;
            event refresh_returned;
            worker writer(
                [&] { refreshed = h().refresh(); refresh_returned.set(); },
                [&] { resume.set(); });

            ASSERT_TRUE(paused.wait()) << "the refresh reached the paused stage";

            EXPECT_TRUE(reader_lock_available(h().table_mutex())) << "a paused build does not hold the reader lock";
            EXPECT_EQ(h().owner(0), published) << "a cached lookup completes against the published table";
            EXPECT_EQ(h().owner(1), nullptr) << "nothing of the paused candidate is visible";
            EXPECT_FALSE(refresh_returned.is_set()) << "the lookups completed while the build was still paused";

            resume.set();
            writer.stop();
            os().on_capture = nullptr;
            os().on_owner_lookup = nullptr;

            EXPECT_TRUE(refreshed);
            ASSERT_NO_FATAL_FAILURE(expect_replacement_published());
            EXPECT_EQ(published->name, L"OLD.EXE") << "an owner handed out before remains usable";
        }
    };

    // ------------------------------------------------------------------------------------
    // Retirement
    // ------------------------------------------------------------------------------------

    TEST_P(ProcessLookupPublicationTest, ReplacedTableIsRetiredAfterItsReaderLockIsReleased)
    {
        const auto probe = std::make_shared<retirement_probe>();
        owner_ref observed;
        ASSERT_NO_FATAL_FAILURE(publish_observed_row(probe, observed));
        stage_replacement();
        probe->expect_reader();

        // A reader that starts when the observed owner starts to be destroyed and reports to the
        // probe, which holds the deletion until it has (or until progress_timeout).
        struct
        {
            bool ran{ false };
            bool lock_available{ false };
            process_ptr replacement;
            process_ptr replaced;
        } seen;
        worker reader(
            [&]
            {
                if (!probe->wait_until_retiring())
                    return;
                seen.ran = true;
                seen.lock_available = reader_lock_available(h().table_mutex());
                seen.replacement = h().owner(1);
                seen.replaced = h().owner(0);
                probe->reader_report();
            },
            [&] { probe->cancel(); });

        const auto refreshing_thread = std::this_thread::get_id();
        EXPECT_TRUE(h().refresh());
        reader.stop();

        EXPECT_TRUE(probe->retired()) << "the refresh released the replaced table's last owner reference";
        EXPECT_EQ(probe->retiring_thread(), refreshing_thread) << "the replaced table was retired by the refresh";
        EXPECT_TRUE(observed.expired());
        ASSERT_TRUE(seen.ran) << "the reader ran during the retirement";
        EXPECT_TRUE(seen.lock_available) << "the reader lock is free while the replaced table is destroyed";
        EXPECT_TRUE(probe->reader_reported_before_deletion())
            << "production lookups completed while the replaced table's owner was being destroyed";
        ASSERT_TRUE(seen.replacement) << "the new table was published before the old one was retired";
        EXPECT_EQ(seen.replacement->name, L"NEW.EXE");
        EXPECT_EQ(seen.replaced, nullptr) << "the replaced table was no longer published";
        ASSERT_NO_FATAL_FAILURE(expect_replacement_published());
    }

    // ------------------------------------------------------------------------------------
    // Readers during a candidate build
    // ------------------------------------------------------------------------------------

    TEST_P(ProcessLookupPublicationTest, ReadersProgressWhileTheCandidateCaptureIsPaused)
    {
        expect_readers_progress_while_the_build_is_paused(pause_stage::capture);
    }

    TEST_P(ProcessLookupPublicationTest, ReadersProgressWhileTheCandidateEnrichmentIsPaused)
    {
        expect_readers_progress_while_the_build_is_paused(pause_stage::enrichment);
    }

    // ------------------------------------------------------------------------------------
    // Failed build
    // ------------------------------------------------------------------------------------

    TEST_P(ProcessLookupPublicationTest, FailedBuildPublishesAndRetiresNothing)
    {
        const auto probe = std::make_shared<retirement_probe>();
        owner_ref observed;
        ASSERT_NO_FATAL_FAILURE(publish_observed_row(probe, observed));
        stage_replacement();
        if (h().supplement())
        {
            // The primary capture is ingested into the candidate before the supplement fails.
            os().images[902] = image(L"NEWPRIMARY.EXE");
            h().add_primary_row(902, 0, 2);
        }

        os().fail_memo_allocations_in = h().capture();
        const auto m = mark();
        EXPECT_FALSE(h().refresh()) << "a memo allocation failure fails the candidate build";
        os().fail_memo_allocations_in.reset();
        EXPECT_GT(os().capture_since(m, h().capture()).memo_allocations, 0) << "the injected fault was reached";

        EXPECT_FALSE(probe->retired()) << "a failed build retires nothing";
        {
            const auto still_published = h().owner(0);
            ASSERT_TRUE(still_published);
            EXPECT_EQ(still_published, observed.lock()) << "the previously published owner remains";
            EXPECT_EQ(still_published->name, L"OLD.EXE");
        }
        EXPECT_EQ(observed.use_count(), 1) << "nothing of the failed build retained the published owner";
        EXPECT_EQ(h().owner(1), nullptr) << "nothing of the failed candidate is published";
        if (h().supplement())
            EXPECT_EQ(h().primary_owner(2), nullptr) << "primary rows of the failed candidate are not published";

        const auto refreshing_thread = std::this_thread::get_id();
        ASSERT_TRUE(h().refresh()) << "the next build recovers";
        EXPECT_TRUE(probe->retired()) << "the recovered build retires the replaced table";
        EXPECT_EQ(probe->retiring_thread(), refreshing_thread);
        EXPECT_TRUE(observed.expired());
        ASSERT_NO_FATAL_FAILURE(expect_replacement_published());
        if (h().supplement())
        {
            const auto primary = h().primary_owner(2);
            ASSERT_TRUE(primary);
            EXPECT_EQ(primary->name, L"NEWPRIMARY.EXE");
        }
    }

    // ------------------------------------------------------------------------------------
    // Owners held by readers
    // ------------------------------------------------------------------------------------

    TEST_P(ProcessLookupPublicationTest, OwnerHeldByAReaderOutlivesItsTableAndIsReleasedWithoutTheLock)
    {
        const auto probe = std::make_shared<retirement_probe>();
        owner_ref observed;
        ASSERT_NO_FATAL_FAILURE(publish_observed_row(probe, observed));
        stage_replacement();

        // A reader looks the owner up, holds it across the replacement of its table, uses it, and
        // releases it. The check runs on the releasing thread only when that is the reader, which
        // holds no table lock.
        event holding, replaced;
        struct
        {
            std::thread::id thread;
            bool used{ false };
            bool lock_free_at_release{ false };
        } seen;
        worker reader(
            [&]
            {
                seen.thread = std::this_thread::get_id();
                auto held = h().owner(0);
                holding.set();
                if (!held || !replaced.wait())
                    return;

                seen.used = held->name == L"OLD.EXE" && held->id == 900 &&
                    held->path_name == iphelper::owner_identity::to_upper(image_path(L"OLD.EXE"));
                held->excluded.store(true);
                held->bypass_tcp.store(true);
                held->bypass_udp.store(true);
                held->tcp_proxy_port = 1080;
                seen.used = seen.used && held->excluded.load() && held->bypass_tcp.load() &&
                    held->bypass_udp.load() && held->tcp_proxy_port == 1080;

                auto& mutex = h().table_mutex();
                const auto reader_thread = seen.thread;
                probe->check_at_retirement([&mutex, &seen, reader_thread]
                {
                    if (std::this_thread::get_id() != reader_thread)
                        return; // possibly the refreshing thread: never touch the lock there
                    seen.lock_free_at_release = mutex.try_lock();
                    if (seen.lock_free_at_release)
                        mutex.unlock();
                });
                held.reset();
            },
            [&] { replaced.set(); });

        ASSERT_TRUE(holding.wait()) << "the reader looked the owner up";
        EXPECT_EQ(observed.use_count(), 2) << "the published table and the reader hold the owner";

        ASSERT_TRUE(h().refresh());
        EXPECT_FALSE(probe->retired()) << "the replaced table released its reference; the reader still holds one";
        EXPECT_EQ(observed.use_count(), 1);
        ASSERT_NO_FATAL_FAILURE(expect_replacement_published());

        replaced.set();
        reader.stop();

        EXPECT_TRUE(seen.used) << "the held owner remained usable after its table was replaced";
        EXPECT_TRUE(probe->retired());
        EXPECT_TRUE(observed.expired());
        EXPECT_EQ(probe->retiring_thread(), seen.thread) << "the reader's release destroyed the owner";
        EXPECT_TRUE(seen.lock_free_at_release) << "the owner was released with the table lock free";
    }

    INSTANTIATE_TEST_CASE_P(AllIngestionLoops, ProcessLookupPublicationTest, ::testing::ValuesIn(all_loops), loop_name);
}
