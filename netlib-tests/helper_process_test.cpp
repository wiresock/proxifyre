// Tests for the helper child process infrastructure (test_support.h): status classification,
// the finite readiness deadline, and cleanup on every exit path.
//
// Each failure case uses a real child (this executable in a helper mode) or a real failed
// CreateProcessW, and checks that the helper and everything in its job have exited when start()
// returns.

#include "pch.h"
#include "test_support.h"

namespace
{
    using namespace netlib_test;

    std::wstring missing_executable()
    {
        auto path = module_path_of_current_process();
        path.resize(path.find_last_of(L"\\/") + 1);
        return path + L"netlib-tests-missing-helper.exe";
    }

    helper_options with_command(std::vector<std::string> command,
        const std::chrono::milliseconds timeout = helper_ready_timeout)
    {
        helper_options options;
        options.command = std::move(command);
        options.ready_timeout = timeout;
        return options;
    }

    // Duplicates the helper's process handle so its exit can be observed after the helper
    // object (and its own handle) is gone. The duplicate also prevents PID reuse confusion.
    unique_handle observe(const helper_child& child)
    {
        HANDLE dup = nullptr;
        ::DuplicateHandle(::GetCurrentProcess(), child.process(), ::GetCurrentProcess(), &dup,
            SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0);
        return unique_handle{ dup };
    }

    void expect_helper_gone(const helper_child& child)
    {
        EXPECT_TRUE(child.has_exited());
        EXPECT_EQ(child.active_processes(), 0u);
    }

    TEST(HelperProcessTest, ReadyHelperReportsPortAndExitsOnDestruction)
    {
        unique_handle watcher;
        {
            helper_child child;
            const auto result = child.start({}, "::ffff:127.0.0.1");
            ASSERT_EQ(result.outcome, helper_outcome::ready) << result.diagnostic;
            EXPECT_GT(result.port, 0);
            EXPECT_NE(child.pid(), ::GetCurrentProcessId());
            EXPECT_FALSE(child.has_exited());
            // The helper, plus any process Windows starts on its behalf (observed: 2, consistent
            // with a console host for the windowless console process).
            EXPECT_GE(child.active_processes(), 1u);
            watcher = observe(child);
            ASSERT_TRUE(watcher);
        }
        EXPECT_EQ(::WaitForSingleObject(watcher.get(), 0), WAIT_OBJECT_0);
    }

    TEST(HelperProcessTest, LaunchFailureIsFailureWithOperationAndError)
    {
        helper_child child;
        helper_options options;
        options.executable = missing_executable();

        const auto result = child.start(options, "::ffff:127.0.0.1");
        EXPECT_EQ(result.outcome, helper_outcome::failure);
        EXPECT_NE(result.diagnostic.find("CreateProcessW failed (code 2)"), std::string::npos) << result.diagnostic;
        expect_helper_gone(child);
    }

    class HelperMalformedStatusTest : public ::testing::TestWithParam<const char*>
    {
    };

    TEST_P(HelperMalformedStatusTest, MalformedStatusIsFailureAndHelperIsTerminated)
    {
        helper_child child;
        const auto result = child.start(with_command({ std::string{ child_print_line }, GetParam() }), "::ffff:127.0.0.1");
        EXPECT_EQ(result.outcome, helper_outcome::failure);
        EXPECT_NE(result.diagnostic.find("malformed helper status line"), std::string::npos) << result.diagnostic;
        // The helper was still holding (print-line waits for stdin EOF); start() must kill it.
        expect_helper_gone(child);
    }

    INSTANTIATE_TEST_CASE_P(Statuses, HelperMalformedStatusTest, ::testing::Values(
        "BOGUS", "READY", "READY 0", "READY 70000", "READY 12x", "READY  80",
        "ERROR 4", "ERROR 99 10048", "ERROR x 1", "ERROR 4 -1"));

    TEST(HelperProcessTest, PrematureExitIsFailureWithExitCode)
    {
        helper_child child;
        const auto result = child.start(with_command({ std::string{ child_exit_now }, "7" }), "::ffff:127.0.0.1");
        EXPECT_EQ(result.outcome, helper_outcome::failure);
        EXPECT_NE(result.diagnostic.find("exited before reporting status (exit code 7)"), std::string::npos) << result.diagnostic;
        expect_helper_gone(child);
    }

    TEST(HelperProcessTest, MissingReadinessTimesOutAndHelperIsTerminated)
    {
        helper_child child;
        const auto started = std::chrono::steady_clock::now();
        const auto result = child.start(with_command({ std::string{ child_never_ready } }, std::chrono::milliseconds{ 300 }),
            "::ffff:127.0.0.1");
        const auto elapsed = std::chrono::steady_clock::now() - started;

        EXPECT_EQ(result.outcome, helper_outcome::failure);
        EXPECT_NE(result.diagnostic.find("did not report status within 300 ms"), std::string::npos) << result.diagnostic;
        EXPECT_GE(elapsed, std::chrono::milliseconds{ 300 });
        EXPECT_LT(elapsed, std::chrono::seconds{ 10 });
        expect_helper_gone(child);
    }

    TEST(HelperProcessTest, UnrecognizedSocketErrorIsFailureWithOperationAndCode)
    {
        helper_child child;
        // bind -> WSAEADDRINUSE is not a recognized environmental limitation.
        const auto result = child.start(with_command({ std::string{ child_print_line }, "ERROR 4 10048" }), "::ffff:127.0.0.1");
        EXPECT_EQ(result.outcome, helper_outcome::failure);
        EXPECT_NE(result.diagnostic.find("bind(AF_INET6, ::ffff:127.0.0.1) failed with WSA error 10048"), std::string::npos)
            << result.diagnostic;
        expect_helper_gone(child);
    }

    TEST(HelperProcessTest, RecognizedSocketLimitationIsEnvironmentLimitation)
    {
        helper_child child;
        // socket(AF_INET6) -> WSAEAFNOSUPPORT: IPv6 not installed.
        const auto result = child.start(with_command({ std::string{ child_print_line }, "ERROR 1 10047" }), "::");
        EXPECT_EQ(result.outcome, helper_outcome::environment_limitation);
        EXPECT_NE(result.diagnostic.find("IPv6 is not installed"), std::string::npos) << result.diagnostic;
        expect_helper_gone(child);
    }

    TEST(HelperProcessTest, RealSocketFailureInHelperIsReportedAsFailure)
    {
        helper_child child;
        // 192.0.2.1 is not an IPv6 literal: the child reports bind/WSAEINVAL, an unexpected failure.
        const auto result = child.start({}, "192.0.2.1");
        EXPECT_EQ(result.outcome, helper_outcome::failure);
        EXPECT_NE(result.diagnostic.find("helper socket setup: bind(AF_INET6, 192.0.2.1) failed with WSA error 10022"),
            std::string::npos) << result.diagnostic;
        expect_helper_gone(child);
    }

    TEST(SocketLimitationTest, OnlyDocumentedConditionsAreLimitations)
    {
        EXPECT_TRUE(environment_limitation({ socket_op::create, AF_INET6, {}, WSAEAFNOSUPPORT }));
        EXPECT_TRUE(environment_limitation({ socket_op::bind, AF_INET6, "::1", WSAEADDRNOTAVAIL }));
        EXPECT_TRUE(environment_limitation({ socket_op::connect, AF_INET6, "::1", WSAEADDRNOTAVAIL }));

        EXPECT_FALSE(environment_limitation({ socket_op::create, AF_INET, {}, WSAEAFNOSUPPORT }));
        EXPECT_FALSE(environment_limitation({ socket_op::create, AF_INET6, {}, WSAENOBUFS }));
        EXPECT_FALSE(environment_limitation({ socket_op::bind, AF_INET6, "::ffff:127.0.0.1", WSAEADDRNOTAVAIL }));
        EXPECT_FALSE(environment_limitation({ socket_op::bind, AF_INET6, "::1", WSAEADDRINUSE }));
        EXPECT_FALSE(environment_limitation({ socket_op::set_v6_only, AF_INET6, {}, WSAEINVAL }));
        EXPECT_FALSE(environment_limitation({ socket_op::listen, AF_INET6, "::1", WSAEADDRNOTAVAIL }));
    }
}
