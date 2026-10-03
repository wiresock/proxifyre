// Failure-path regression tests for the process_lookup characterization cases.
//
// DISABLED_NetlibFailureProbe tests run the real case bodies from process_lookup_cases.h with a
// single injected fault (helper launch/protocol/timeout/socket failure, or a failed OS table
// query). They are disabled so ordinary runs never execute them in-process; instead
// ProcessLookupFailureProbeTest runs each one in a subprocess of this executable and asserts
// the observable outcome: exit code, console output, XML results, and that no process launched
// on the probe's behalf (helpers included) survives it.
//
// Infrastructure and query failures must fail the probe even with --netlib_allow_unsupported.
// Only the documented environmental limitation may produce UNSUPPORTED.

#include "pch.h"
#include "test_support.h"
#include "process_lookup_cases.h"

namespace
{
    using namespace netlib_test;
    using namespace netlib_test::process_lookup_cases;

    // ------------------------------------------------------------------------------------
    // Injected table-query failures (one address family fails, the other is real)
    // ------------------------------------------------------------------------------------

    constexpr DWORD injected_query_error = ERROR_NOT_SUPPORTED;   // 50

    template <ULONG FailingFamily>
    DWORD WINAPI tcp_query_failing(const PVOID buffer, const PDWORD size, const BOOL order, const ULONG family,
        const TCP_TABLE_CLASS table_class, const ULONG reserved)
    {
        if (family == FailingFamily)
            return injected_query_error;
        return ::GetExtendedTcpTable(buffer, size, order, family, table_class, reserved);
    }

    template <ULONG FailingFamily>
    DWORD WINAPI udp_query_failing(const PVOID buffer, const PDWORD size, const BOOL order, const ULONG family,
        const UDP_TABLE_CLASS table_class, const ULONG reserved)
    {
        if (family == FailingFamily)
            return injected_query_error;
        return ::GetExtendedUdpTable(buffer, size, order, family, table_class, reserved);
    }

    case_options failing_tcp(const ULONG family)
    {
        case_options options;
        options.tables.get_tcp = family == AF_INET ? &tcp_query_failing<AF_INET> : &tcp_query_failing<AF_INET6>;
        return options;
    }

    case_options failing_udp(const ULONG family)
    {
        case_options options;
        options.tables.get_udp = family == AF_INET ? &udp_query_failing<AF_INET> : &udp_query_failing<AF_INET6>;
        return options;
    }

    case_options helper_command(std::vector<std::string> command,
        const std::chrono::milliseconds timeout = helper_ready_timeout)
    {
        case_options options;
        options.helper.command = std::move(command);
        options.helper.ready_timeout = timeout;
        return options;
    }

    std::wstring missing_executable()
    {
        auto path = module_path_of_current_process();
        path.resize(path.find_last_of(L"\\/") + 1);
        return path + L"netlib-tests-missing-helper.exe";
    }

    void precedence_exact(const process_lookup_fixture& test, const case_options& options)
    {
        native_v4_udp_precedence_case(test, "::ffff:127.0.0.1", "127.0.0.1", os_tables::v4_mapped_loopback, options);
    }

    // ------------------------------------------------------------------------------------
    // Probes (run only in a subprocess by ProcessLookupFailureProbeTest)
    // ------------------------------------------------------------------------------------

    class DISABLED_NetlibFailureProbe : public process_lookup_fixture
    {
    };

    TEST_F(DISABLED_NetlibFailureProbe, HelperLaunchFailure)
    {
        case_options options;
        options.helper.executable = missing_executable();
        precedence_exact(*this, options);
    }

    TEST_F(DISABLED_NetlibFailureProbe, HelperMalformedStatus)
    {
        precedence_exact(*this, helper_command({ std::string{ child_print_line }, "BOGUS" }));
    }

    TEST_F(DISABLED_NetlibFailureProbe, HelperPrematureExit)
    {
        precedence_exact(*this, helper_command({ std::string{ child_exit_now }, "7" }));
    }

    TEST_F(DISABLED_NetlibFailureProbe, HelperNeverReady)
    {
        precedence_exact(*this, helper_command({ std::string{ child_never_ready } }, std::chrono::milliseconds{ 500 }));
    }

    TEST_F(DISABLED_NetlibFailureProbe, HelperUnrecognizedSocketError)
    {
        precedence_exact(*this, helper_command({ std::string{ child_print_line }, "ERROR 4 10048" }));
    }

    TEST_F(DISABLED_NetlibFailureProbe, HelperRecognizedLimitation)
    {
        precedence_exact(*this, helper_command({ std::string{ child_print_line }, "ERROR 1 10047" }));
    }

    TEST_F(DISABLED_NetlibFailureProbe, Ipv4TcpQueryFailure)
    {
        dual_stack_mapped_tcp_case(*this, failing_tcp(AF_INET));
    }

    TEST_F(DISABLED_NetlibFailureProbe, Ipv6TcpQueryFailure)
    {
        dual_stack_mapped_tcp_case(*this, failing_tcp(AF_INET6));
    }

    TEST_F(DISABLED_NetlibFailureProbe, Ipv4UdpQueryFailure)
    {
        unspecified_v6_udp_case(*this, failing_udp(AF_INET));
    }

    TEST_F(DISABLED_NetlibFailureProbe, Ipv6UdpQueryFailure)
    {
        mapped_v6_udp_exact_case(*this, failing_udp(AF_INET6));
    }

    TEST_F(DISABLED_NetlibFailureProbe, PrecedenceIpv6UdpQueryFailure)
    {
        // The real helper starts; its isolation check then hits the failed AF_INET6 capture.
        precedence_exact(*this, failing_udp(AF_INET6));
    }

    TEST_F(DISABLED_NetlibFailureProbe, AssertionFailure)
    {
        FAIL() << "deliberate probe failure";
    }

    TEST_F(DISABLED_NetlibFailureProbe, Crash)
    {
        // Start a live helper, then terminate abnormally with an access-violation status (without
        // a WER dialog). The helper's kill-on-close job must not let it outlive this process.
        helper_child child;
        const auto started = child.start({}, "::ffff:127.0.0.1");
        ASSERT_EQ(started.outcome, helper_outcome::ready) << started.diagnostic;
        std::cout << "probe helper pid " << child.pid() << std::endl;
        ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(0xC0000005));
    }

    // ------------------------------------------------------------------------------------
    // Subprocess runner
    // ------------------------------------------------------------------------------------

    struct probe_run
    {
        self_run run;
        std::string xml;
        bool xml_written{ false };
    };

    std::string temp_xml_path(const std::string& name)
    {
        char dir[MAX_PATH + 1]{};
        ::GetTempPathA(MAX_PATH, dir);
        std::string safe = name;
        std::ranges::replace_if(safe, [](const char ch) { return !std::isalnum(static_cast<unsigned char>(ch)); }, '_');
        return std::format("{}netlib-tests-probe-{}-{}.xml", dir, ::GetCurrentProcessId(), safe);
    }

    probe_run run_probe(const std::string& filter, const bool allow_unsupported, const bool also_disabled = true)
    {
        probe_run result;
        const auto xml_path = temp_xml_path(filter.substr(filter.find('.') + 1));
        std::remove(xml_path.c_str());

        std::vector<std::string> args{ "--gtest_filter=" + filter, "--gtest_output=xml:" + xml_path };
        if (also_disabled)
            args.emplace_back("--gtest_also_run_disabled_tests");
        if (allow_unsupported)
            args.emplace_back("--netlib_allow_unsupported");

        result.run = run_self(args, std::chrono::seconds{ 120 });

        if (std::ifstream in{ xml_path, std::ios::binary })
        {
            result.xml.assign(std::istreambuf_iterator<char>(in), {});
            result.xml_written = true;
        }
        std::remove(xml_path.c_str());
        return result;
    }

    bool contains(const std::string& text, const std::string& what) { return text.find(what) != std::string::npos; }

    struct failure_expectation
    {
        const char* probe;
        const char* diagnostic;   // operation and error expected in the failure output
    };

    std::ostream& operator<<(std::ostream& os, const failure_expectation& e) { return os << e.probe; }

    class ProcessLookupFailureProbeTest : public ::testing::TestWithParam<failure_expectation>
    {
    };

    // Each infrastructure or query fault must be a real failure in both modes: exit code 1,
    // a FAILED line naming the probe, the preserved diagnostic, no UNSUPPORTED record, a
    // failure in the XML, and no surviving process.
    TEST_P(ProcessLookupFailureProbeTest, FaultFailsEvenWhenUnsupportedIsAllowed)
    {
        const auto& expectation = GetParam();
        const std::string filter = std::string{ "DISABLED_NetlibFailureProbe." } + expectation.probe;

        for (const bool allow : { true, false })
        {
            SCOPED_TRACE(allow ? "--netlib_allow_unsupported" : "strict");
            const auto probe = run_probe(filter, allow);
            ASSERT_FALSE(probe.run.failure) << probe.run.failure->describe();
            const auto& out = probe.run.output;

            EXPECT_EQ(probe.run.exit_code, 1u) << out;
            EXPECT_TRUE(contains(out, "[  FAILED  ] " + filter)) << out;
            EXPECT_TRUE(contains(out, expectation.diagnostic)) << out;
            EXPECT_FALSE(contains(out, "[ UNSUPPORTED ]")) << out;
            EXPECT_TRUE(contains(out, "netlib-tests summary: 1 run: 0 verified, 0 unsupported, 1 failed.")) << out;
            ASSERT_TRUE(probe.xml_written);
            EXPECT_TRUE(contains(probe.xml, "<testsuites tests=\"1\" failures=\"1\"")) << probe.xml;
            EXPECT_TRUE(contains(probe.xml, "<failure message=")) << probe.xml;
            EXPECT_FALSE(contains(probe.xml, "name=\"unsupported\"")) << probe.xml;
            EXPECT_EQ(probe.run.surviving_processes, 0u);
        }
    }

    INSTANTIATE_TEST_CASE_P(Faults, ProcessLookupFailureProbeTest, ::testing::Values(
        failure_expectation{ "HelperLaunchFailure", "helper launch: CreateProcessW failed (code 2)" },
        failure_expectation{ "HelperMalformedStatus", "malformed helper status line: \"BOGUS\"" },
        failure_expectation{ "HelperPrematureExit", "helper exited before reporting status (exit code 7)" },
        failure_expectation{ "HelperNeverReady", "helper did not report status within 500 ms" },
        failure_expectation{ "HelperUnrecognizedSocketError", "bind(AF_INET6, ::ffff:127.0.0.1) failed with WSA error 10048" },
        failure_expectation{ "Ipv4TcpQueryFailure", "TCP AF_INET table query (GetExtendedTcpTable) failed with error 50" },
        failure_expectation{ "Ipv6TcpQueryFailure", "TCP AF_INET6 table query (GetExtendedTcpTable) failed with error 50" },
        failure_expectation{ "Ipv4UdpQueryFailure", "UDP AF_INET table query (GetExtendedUdpTable) failed with error 50" },
        failure_expectation{ "Ipv6UdpQueryFailure", "UDP AF_INET6 table query (GetExtendedUdpTable) failed with error 50" },
        failure_expectation{ "PrecedenceIpv6UdpQueryFailure", "UDP AF_INET6 table query (GetExtendedUdpTable) failed with error 50" },
        failure_expectation{ "AssertionFailure", "deliberate probe failure" }));

    TEST(ProcessLookupProbeExitTest, RecognizedLimitationAloneIsUnsupportedNotFailure)
    {
        const std::string filter = "DISABLED_NetlibFailureProbe.HelperRecognizedLimitation";

        const auto strict = run_probe(filter, false);
        ASSERT_FALSE(strict.run.failure) << strict.run.failure->describe();
        EXPECT_EQ(strict.run.exit_code, 5u) << strict.run.output;
        EXPECT_TRUE(contains(strict.run.output, "[ UNSUPPORTED ] " + filter + ": helper: IPv6 is not installed")) << strict.run.output;
        EXPECT_TRUE(contains(strict.run.output, "netlib-tests summary: 1 run: 0 verified, 1 unsupported, 0 failed.")) << strict.run.output;
        EXPECT_TRUE(contains(strict.xml, "failures=\"0\"")) << strict.xml;
        EXPECT_TRUE(contains(strict.xml, "<property name=\"unsupported\" value=\"helper: IPv6 is not installed")) << strict.xml;

        EXPECT_EQ(strict.run.surviving_processes, 0u);

        const auto allowed = run_probe(filter, true);
        ASSERT_FALSE(allowed.run.failure) << allowed.run.failure->describe();
        EXPECT_EQ(allowed.run.exit_code, 0u) << allowed.run.output;
        EXPECT_EQ(allowed.run.surviving_processes, 0u);
    }

    TEST(ProcessLookupProbeExitTest, CrashIsNonZeroWithoutSummary)
    {
        const auto probe = run_probe("DISABLED_NetlibFailureProbe.Crash", true);
        ASSERT_FALSE(probe.run.failure) << probe.run.failure->describe();
        EXPECT_EQ(probe.run.exit_code, 0xC0000005u) << probe.run.output;
        EXPECT_TRUE(contains(probe.run.output, "probe helper pid ")) << probe.run.output;
        EXPECT_FALSE(contains(probe.run.output, "netlib-tests summary:")) << probe.run.output;
        EXPECT_FALSE(probe.xml_written);
        EXPECT_EQ(probe.run.surviving_processes, 0u);
    }

    TEST(ProcessLookupProbeExitTest, UnmatchedFilterExitsFour)
    {
        const auto probe = run_probe("NoSuchTestCase.*", true, false);
        ASSERT_FALSE(probe.run.failure) << probe.run.failure->describe();
        EXPECT_EQ(probe.run.exit_code, 4u) << probe.run.output;
        EXPECT_TRUE(contains(probe.run.output, "netlib-tests: no tests were run.")) << probe.run.output;
    }
}
