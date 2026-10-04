// Lifecycle regression for helper child processes (test_support.h): a parent that dies at the
// process-creation boundary must take its still-suspended child with it.
//
// Before the fix, launched_process::launch() created the child and only then called
// AssignProcessToJobObject. A parent terminated between those two calls left a suspended helper
// outside any kill-on-close job. The child is now a job member from CreateProcessW onwards
// (PROC_THREAD_ATTRIBUTE_JOB_LIST), so there is no such window.
//
// Shape of the regression (two processes besides the test runner):
//   * the "parent" is this executable running DISABLED_HelperLifecycleProbe.HoldAtCreationBoundary
//     as a subprocess. It installs after_child_created_hook(), which fires the instant
//     CreateProcessW has returned: it reports the child's PID on stdout and then blocks on stdin;
//   * the outer test (HelperLifecycleTest) waits for that report, opens the child with an
//     observation handle only, terminates the parent (and nothing else), and waits for the child
//     to exit.
//
// Why supervisory cleanup cannot mask a failure: the parent runs inside the outer test's own
// kill-on-close job, but that job's handle is held by the outer test and stays open until the
// test function returns, i.e. until after the child's exit has been awaited and the assertion
// recorded. Terminating the parent with TerminateProcess touches no job. The outer test never
// holds a handle to the parent's job (it is created inside the parent and never shared), so the
// only way the child can exit while the test is waiting is that job losing its last handle when
// the parent dies, which is exactly the property under test. If the child survives, the wait
// times out, the failure is recorded, and only then is the child terminated through the
// observation handle (and the outer job closes afterwards).

#include "pch.h"
#include "test_support.h"

namespace
{
    using namespace netlib_test;

    constexpr const char* boundary_probe = "DISABLED_HelperLifecycleProbe.HoldAtCreationBoundary";

    // Parent PID of a process opened with PROCESS_QUERY_LIMITED_INFORMATION; 0 on failure.
    DWORD parent_pid_of(const HANDLE process)
    {
        // PROCESS_BASIC_INFORMATION: the sixth pointer-sized field is InheritedFromUniqueProcessId
        // (winternl.h names it Reserved3).
        struct basic_information
        {
            PVOID exit_status;
            PVOID peb;
            PVOID affinity_mask;
            PVOID base_priority;
            ULONG_PTR unique_process_id;
            ULONG_PTR inherited_from_unique_process_id;
        };
        static_assert(sizeof(basic_information) == sizeof(PROCESS_BASIC_INFORMATION));
        basic_information info{};
        ULONG length = 0;
        if (::NtQueryInformationProcess(process, ProcessBasicInformation, &info, sizeof(info), &length) != 0)
            return 0;
        return static_cast<DWORD>(info.inherited_from_unique_process_id);
    }

    // Runs only as the parent subprocess of the test below (it is DISABLED_ for ordinary runs).
    TEST(DISABLED_HelperLifecycleProbe, HoldAtCreationBoundary)
    {
        after_child_created_hook() = [](const DWORD pid) {
            // CreateProcessW has just returned: the child exists, suspended. Nothing after this
            // point in launch() (membership check, ResumeThread) runs while we block here.
            std::cout << "CREATED " << pid << std::endl;
            child_hold_until_stdin_eof();
            std::cout << "BOUNDARY-RELEASED" << std::endl;
        };
        helper_child child;
        const auto result = child.start({}, "::ffff:127.0.0.1");
        after_child_created_hook() = nullptr;
        // Reached only if the outer test released stdin instead of terminating this process.
        FAIL() << "the parent was not terminated at the creation boundary (helper outcome "
            << static_cast<int>(result.outcome) << "): " << result.diagnostic;
    }

    TEST(HelperLifecycleTest, ParentTerminatedAtCreationBoundaryTakesChildWithIt)
    {
        // Supervisory job for the parent: a safety net only. It is held by `parent` and cannot
        // fire before this function returns.
        launched_process parent;
        const auto launched = parent.launch(module_path_of_current_process(),
            { std::string{ "--gtest_filter=" } + boundary_probe, "--gtest_also_run_disabled_tests" });
        ASSERT_FALSE(launched) << launched->describe();

        // 1. Synchronize at the boundary: the parent reports the PID of the child it has just
        //    created and then blocks on stdin, which this test never closes or writes to.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{ 30 };
        std::string line;
        infra_failure error;
        unsigned long reported = 0;
        for (;;)
        {
            const auto status = parent.read_line(line, deadline, 4096, error);
            ASSERT_EQ(status, launched_process::read_status::line)
                << "no CREATED report from the parent (read status " << static_cast<int>(status) << "): " << error.describe();
            if (line.starts_with("CREATED ") && parse_uint(std::string_view{ line }.substr(8), reported))
                break;
        }
        const auto child_pid = static_cast<DWORD>(reported);
        ASSERT_NE(child_pid, 0u);
        ASSERT_NE(child_pid, parent.pid());

        // 2. Observation handle only: not a job handle, not inherited. PROCESS_TERMINATE is for
        //    the guaranteed last-resort cleanup after a recorded failure, nothing else.
        unique_handle child{ ::OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, child_pid) };
        ASSERT_TRUE(child) << "OpenProcess(" << child_pid << ") failed: " << ::GetLastError();
        const auto cleanup = gsl::finally([&] {
            if (::WaitForSingleObject(child.get(), 0) != WAIT_OBJECT_0)
            {
                ::TerminateProcess(child.get(), 1);
                ::WaitForSingleObject(child.get(), 5000);
            }
        });

        // The child is alive (created suspended and never resumed) and really is the parent's
        // child, so the PID cannot have been recycled.
        ASSERT_EQ(::WaitForSingleObject(child.get(), 0), WAIT_TIMEOUT);
        ASSERT_EQ(parent_pid_of(child.get()), parent.pid());

        // 3. Terminate the parent, and only the parent, while it is blocked at the boundary.
        ASSERT_TRUE(::TerminateProcess(parent.process(), 1)) << ::GetLastError();
        ASSERT_TRUE(parent.wait_exit(std::chrono::seconds{ 10 }).has_value());

        // 4. Observe the child's exit before any supervisory cleanup runs (the `parent`
        //    destructor, which closes the outer job, runs after this function returns).
        const auto waited = ::WaitForSingleObject(child.get(), 10000);
        EXPECT_EQ(waited, WAIT_OBJECT_0)
            << "the suspended helper (pid " << child_pid << ") survived its parent's termination at the creation boundary";
        if (waited == WAIT_OBJECT_0)
        {
            DWORD code = 0;
            ::GetExitCodeProcess(child.get(), &code);
            std::cout << "[ lifecycle ] helper " << child_pid << " exited with code " << code
                << " after its parent " << parent.pid() << " was terminated at the creation boundary\n";
        }
    }

    // Normal operation is unaffected by the boundary instrumentation: a helper started without
    // a hook is a member of its own job, which is nested inside any job this process is in.
    TEST(HelperLifecycleTest, HelperIsInItsJobFromTheStartAndNestsInsideTheParentJob)
    {
        helper_child child;
        const auto result = child.start({}, "::ffff:127.0.0.1");
        ASSERT_EQ(result.outcome, helper_outcome::ready) << result.diagnostic;

        // Membership in some job (its own) is certain; if this process is itself in a job (as it
        // is when run as a probe subprocess), the child is in that one too.
        BOOL in_any_job = FALSE;
        ASSERT_TRUE(::IsProcessInJob(child.process(), nullptr, &in_any_job));
        EXPECT_TRUE(in_any_job);

        BOOL self_in_job = FALSE;
        ASSERT_TRUE(::IsProcessInJob(::GetCurrentProcess(), nullptr, &self_in_job));
        if (self_in_job)
        {
            // Nested: the child counts towards the enclosing job's accounting as well.
            JOBOBJECT_BASIC_PROCESS_ID_LIST ids{};
            // A nullptr job handle queries the job of the calling process (Windows 8+).
            const bool queried = ::QueryInformationJobObject(nullptr, JobObjectBasicProcessIdList, &ids, sizeof(ids), nullptr) ||
                ::GetLastError() == ERROR_MORE_DATA;
            EXPECT_TRUE(queried) << ::GetLastError();
            EXPECT_GE(ids.NumberOfAssignedProcesses, 2u);   // this process and the helper at least
        }
        std::cout << "[ lifecycle ] helper " << child.pid() << " in job: " << (in_any_job ? "yes" : "no")
            << "; this process in a job: " << (self_in_job ? "yes" : "no") << '\n';
    }
}
