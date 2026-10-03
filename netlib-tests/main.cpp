// main.cpp: entry point for the native netlib test executable.
//
// Responsibilities beyond RUN_ALL_TESTS():
//   * Initialise Winsock for the real-socket characterization tests.
//   * Serve as a helper child process (see netlib_test::child_main) so tests can create
//     sockets owned by a second, independent PID.
//   * Refuse to report success when no test executed, and report environment-dependent
//     cases that could not be exercised as UNSUPPORTED instead of as passes. The pinned
//     GoogleTest 1.8.1 package predates GTEST_SKIP, so this is tracked explicitly here.

#include "pch.h"
#include "test_support.h"

namespace
{
    constexpr std::string_view allow_unsupported_flag = "--netlib_allow_unsupported";

    struct winsock_session
    {
        bool ok{ false };

        winsock_session()
        {
            WSADATA data{};
            ok = ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
        }

        ~winsock_session()
        {
            if (ok)
                ::WSACleanup();
        }

        winsock_session(const winsock_session&) = delete;
        winsock_session& operator=(const winsock_session&) = delete;
    };
}

int main(int argc, char** argv)
{
    const winsock_session winsock;
    if (!winsock.ok)
    {
        std::cerr << "netlib-tests: WSAStartup failed: " << ::WSAGetLastError() << '\n';
        return 3;
    }

    if (argc >= 2 && std::string_view{ argv[1] } == netlib_test::child_mode_flag)
        return netlib_test::child_main(argc, argv);

    // Strip our own flag before GoogleTest parses the command line.
    bool allow_unsupported = false;
    std::vector<char*> args;
    args.reserve(static_cast<size_t>(argc));
    for (int i = 0; i < argc; ++i)
    {
        if (std::string_view{ argv[i] } == allow_unsupported_flag)
        {
            allow_unsupported = true;
            continue;
        }
        args.push_back(argv[i]);
    }
    int gtest_argc = static_cast<int>(args.size());

    ::testing::InitGoogleTest(&gtest_argc, args.data());

    const int result = RUN_ALL_TESTS();

    const auto& unit_test = *::testing::UnitTest::GetInstance();
    const auto unsupported = netlib_test::unsupported_cases();

    std::cout << "\nnetlib-tests summary: " << unit_test.test_to_run_count() << " test(s) run, "
        << unit_test.successful_test_count() << " without assertion failures, "
        << unit_test.failed_test_count() << " failed, "
        << unsupported.size() << " unsupported on this host.\n";

    for (const auto& item : unsupported)
        std::cout << "[ UNSUPPORTED ] " << item << '\n';

    if (result != 0)
        return result;

    if (unit_test.test_to_run_count() == 0)
    {
        // A filter that matches nothing must not be mistaken for a passing run.
        std::cerr << "netlib-tests: no tests were run.\n";
        return 4;
    }

    if (!unsupported.empty() && !allow_unsupported)
    {
        std::cerr << "netlib-tests: " << unsupported.size()
            << " case(s) could not be exercised on this host and were NOT verified. "
            << "Pass " << allow_unsupported_flag << " to accept this explicitly.\n";
        return 5;
    }

    return 0;
}
