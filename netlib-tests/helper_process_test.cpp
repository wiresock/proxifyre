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

    // ------------------------------------------------------------------------------------
    // Status line framing: the pure framing step (deterministic, no process)
    // ------------------------------------------------------------------------------------

    constexpr size_t limit = helper_status_max_payload;   // 256

    struct framed
    {
        frame_status status{};
        std::string line;
        std::string detail;
    };

    framed frame(std::string& pending)
    {
        framed f;
        f.status = frame_line(pending, limit, f.line, f.detail);
        return f;
    }

    TEST(StatusLineFramingTest, PayloadAtLimitWithLfOrCrLfIsCompleteAndConsumed)
    {
        for (const char* terminator : { "\n", "\r\n" })
        {
            std::string pending = std::string(limit, 'A') + terminator + "NEXT";
            const auto f = frame(pending);
            EXPECT_EQ(f.status, frame_status::complete);
            EXPECT_EQ(f.line, std::string(limit, 'A'));   // terminator (and its CR) not in the payload
            EXPECT_EQ(pending, "NEXT");
        }
    }

    TEST(StatusLineFramingTest, PayloadOnePastLimitIsOversizedNotTruncated)
    {
        for (const char* terminator : { "\n", "\r\n" })
        {
            std::string pending = std::string(limit + 1, 'A') + terminator;
            const auto f = frame(pending);
            EXPECT_EQ(f.status, frame_status::oversized) << f.detail;
            EXPECT_TRUE(f.line.empty());
            EXPECT_NE(f.detail.find("257 payload bytes before the line terminator exceed the 256-byte limit"), std::string::npos) << f.detail;
        }
    }

    TEST(StatusLineFramingTest, UnterminatedPrefixIsIncompleteUntilItCannotBeAValidFrame)
    {
        std::string pending(limit, 'A');                       // 256 bytes, no LF: more may come
        EXPECT_EQ(frame(pending).status, frame_status::incomplete);
        pending += '\r';                                       // 257: could still be "256 + CR" + LF
        EXPECT_EQ(frame(pending).status, frame_status::incomplete);
        pending += '\n';
        EXPECT_EQ(frame(pending).status, frame_status::complete);

        std::string not_cr = std::string(limit, 'A') + 'A';    // 257 payload bytes, no LF
        const auto f = frame(not_cr);
        EXPECT_EQ(f.status, frame_status::oversized);
        EXPECT_NE(f.detail.find("257 bytes without a line terminator exceed the 256-byte limit"), std::string::npos) << f.detail;

        std::string cr_then_more = std::string(limit, 'A') + "\rA";   // 258, no LF
        EXPECT_EQ(frame(cr_then_more).status, frame_status::oversized);
    }

    TEST(StatusLineFramingTest, OversizedInputArrivingInSeveralReadsIsRejectedOnceItExceedsTheLimit)
    {
        std::string pending(200, 'A');
        EXPECT_EQ(frame(pending).status, frame_status::incomplete);
        pending += std::string(50, 'A');                        // 250
        EXPECT_EQ(frame(pending).status, frame_status::incomplete);
        pending += std::string(10, 'A');                        // 260, still no LF: rejected now
        EXPECT_EQ(frame(pending).status, frame_status::oversized);

        std::string late_lf(200, 'A');
        EXPECT_EQ(frame(late_lf).status, frame_status::incomplete);
        late_lf += std::string(60, 'A') + '\n';                 // LF after 260 payload bytes
        const auto f = frame(late_lf);
        EXPECT_EQ(f.status, frame_status::oversized);
        EXPECT_NE(f.detail.find("260 payload bytes"), std::string::npos) << f.detail;
    }

    TEST(StatusLineFramingTest, OnlyTheCrImmediatelyBeforeLfIsFraming)
    {
        std::string embedded = "READY\r 80\r\n";
        auto f = frame(embedded);
        EXPECT_EQ(f.status, frame_status::complete);
        EXPECT_EQ(f.line, "READY\r 80");          // kept: it is not removed to make the line parse

        std::string doubled = "READY 80\r\r\n";
        f = frame(doubled);
        EXPECT_EQ(f.status, frame_status::complete);
        EXPECT_EQ(f.line, "READY 80\r");

        std::string prefix = "READY 80";          // no LF: never a line, whatever follows (EOF/timeout)
        EXPECT_EQ(frame(prefix).status, frame_status::incomplete);
        EXPECT_EQ(prefix, "READY 80");
    }

    // ------------------------------------------------------------------------------------
    // Status line framing through a real helper child
    // ------------------------------------------------------------------------------------

    helper_options write_bytes(const std::string& spec, const std::chrono::milliseconds timeout = helper_ready_timeout)
    {
        return with_command({ std::string{ child_write_bytes }, spec }, timeout);
    }

    TEST(HelperStatusFramingTest, ReadyPayloadAtLimitIsAcceptedWithLfCrLfAndRuntimeTranslation)
    {
        const auto payload = zero_padded_status("READY ", "80", limit);
        for (const char* terminator : { "\\n", "\\r\\n" })
        {
            helper_child child;
            const auto result = child.start(write_bytes(payload + terminator), "::ffff:127.0.0.1");
            EXPECT_EQ(result.outcome, helper_outcome::ready) << terminator << ": " << result.diagnostic;
            EXPECT_EQ(result.port, 80);
        }
        // print-line goes through std::cout, i.e. the C runtime's text-mode CRLF translation,
        // which is how real helpers report READY/ERROR.
        helper_child child;
        const auto result = child.start(with_command({ std::string{ child_print_line }, payload }), "::ffff:127.0.0.1");
        EXPECT_EQ(result.outcome, helper_outcome::ready) << result.diagnostic;
        EXPECT_EQ(result.port, 80);
    }

    TEST(HelperStatusFramingTest, ReadyPayloadOnePastLimitIsFailure)
    {
        const auto payload = zero_padded_status("READY ", "80", limit + 1);
        for (const char* terminator : { "\\n", "\\r\\n" })
        {
            helper_child child;
            const auto result = child.start(write_bytes(payload + terminator), "::ffff:127.0.0.1");
            EXPECT_EQ(result.outcome, helper_outcome::failure) << terminator;
            EXPECT_NE(result.diagnostic.find("oversized helper status line: 257 payload bytes"), std::string::npos) << result.diagnostic;
            expect_helper_gone(child);
        }
    }

    TEST(HelperStatusFramingTest, PaddedErrorPrefixWithTrailingJunkIsFailureNotLimitation)
    {
        // The first 256 bytes parse as "ERROR 1 10047" (IPv6 not installed); the old reader
        // returned exactly that prefix and reported UNSUPPORTED.
        helper_child child;
        const auto result = child.start(write_bytes(zero_padded_status("ERROR 1 ", "10047", limit) + "JUNK\\n"), "::");
        EXPECT_EQ(result.outcome, helper_outcome::failure);
        EXPECT_NE(result.diagnostic.find("oversized helper status line: 260 payload bytes"), std::string::npos) << result.diagnostic;
        EXPECT_EQ(result.diagnostic.find("IPv6 is not installed"), std::string::npos) << result.diagnostic;
        expect_helper_gone(child);
    }

    TEST(HelperStatusFramingTest, PaddedReadyPrefixWithTrailingJunkIsFailureNotReady)
    {
        helper_child child;
        const auto result = child.start(write_bytes(zero_padded_status("READY ", "80", limit) + "JUNK\\r\\n"), "::ffff:127.0.0.1");
        EXPECT_EQ(result.outcome, helper_outcome::failure);
        EXPECT_EQ(result.port, 0);
        EXPECT_NE(result.diagnostic.find("oversized helper status line: 260 payload bytes"), std::string::npos) << result.diagnostic;
        expect_helper_gone(child);
    }

    TEST(HelperStatusFramingTest, UnterminatedPaddedReadyPrefixIsATimeoutNotReady)
    {
        helper_child child;
        const auto result = child.start(write_bytes(zero_padded_status("READY ", "80", limit), std::chrono::milliseconds{ 500 }),
            "::ffff:127.0.0.1");
        EXPECT_EQ(result.outcome, helper_outcome::failure);
        EXPECT_NE(result.diagnostic.find("did not report status within 500 ms; 256 byte(s) of unterminated output: \"READY 000"),
            std::string::npos) << result.diagnostic;
        expect_helper_gone(child);
    }

    TEST(HelperStatusFramingTest, OversizedInputInSeveralReadsIsFailure)
    {
        // Two chunks 100 ms apart; the line terminator arrives only with the second one.
        helper_child child;
        const auto result = child.start(write_bytes(std::string(200, 'A') + "|" + std::string(100, 'A') + "\\n"), "::ffff:127.0.0.1");
        EXPECT_EQ(result.outcome, helper_outcome::failure);
        EXPECT_NE(result.diagnostic.find("oversized helper status line: 300 payload bytes"), std::string::npos) << result.diagnostic;
        expect_helper_gone(child);

        // Without any terminator the rejection happens as soon as the limit is exceeded, well
        // before the readiness deadline.
        helper_child unterminated;
        const auto started = std::chrono::steady_clock::now();
        const auto r2 = unterminated.start(write_bytes(std::string(200, 'A') + "|" + std::string(100, 'A'), std::chrono::seconds{ 10 }),
            "::ffff:127.0.0.1");
        EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds{ 5 });
        EXPECT_EQ(r2.outcome, helper_outcome::failure);
        EXPECT_NE(r2.diagnostic.find("oversized helper status line: 300 bytes without a line terminator"), std::string::npos) << r2.diagnostic;
        expect_helper_gone(unterminated);
    }

    TEST(HelperStatusFramingTest, PartialLineBeforeExitIsFailureWithExitCodeAndTheUnterminatedBytes)
    {
        helper_child child;
        const auto result = child.start(with_command({ std::string{ child_write_bytes }, "READY 80", "7" }), "::ffff:127.0.0.1");
        EXPECT_EQ(result.outcome, helper_outcome::failure);
        EXPECT_NE(result.diagnostic.find("exited before reporting status (exit code 7); 8 byte(s) of unterminated output: \"READY 80\""),
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
