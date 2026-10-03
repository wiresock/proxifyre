#pragma once

// Shared helpers for the native netlib tests: RAII sockets, an explicit UNSUPPORTED outcome,
// and a helper child process used to obtain sockets owned by a second PID.

namespace netlib_test
{
    // ------------------------------------------------------------------------------------
    // Explicit unsupported-environment outcome
    // ------------------------------------------------------------------------------------

    inline std::mutex& unsupported_lock()
    {
        static std::mutex lock;
        return lock;
    }

    inline std::vector<std::string>& unsupported_storage()
    {
        static std::vector<std::string> items;
        return items;
    }

    inline std::vector<std::string> unsupported_cases()
    {
        std::lock_guard lock(unsupported_lock());
        return unsupported_storage();
    }

    inline void record_unsupported(const std::string& reason)
    {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        std::string name = info ? std::string(info->test_case_name()) + "." + info->name() : "<unknown>";
        auto entry = std::move(name) + ": " + reason;
        std::cout << "[ UNSUPPORTED ] " << entry << '\n';
        ::testing::Test::RecordProperty("unsupported", reason);
        std::lock_guard lock(unsupported_lock());
        unsupported_storage().push_back(std::move(entry));
    }

    // Marks the current test as not exercised on this host and leaves it. main() reports the
    // case separately and returns a non-zero exit code unless explicitly allowed.
#define NETLIB_TEST_UNSUPPORTED(reason)                     \
    do {                                                    \
        ::netlib_test::record_unsupported(reason);          \
        return;                                             \
    } while (false)

    // ------------------------------------------------------------------------------------
    // Sockets
    // ------------------------------------------------------------------------------------

    class unique_socket
    {
    public:
        unique_socket() = default;
        explicit unique_socket(const SOCKET s) noexcept : socket_(s) {}
        ~unique_socket() { reset(); }

        unique_socket(const unique_socket&) = delete;
        unique_socket& operator=(const unique_socket&) = delete;
        unique_socket(unique_socket&& other) noexcept : socket_(std::exchange(other.socket_, INVALID_SOCKET)) {}
        unique_socket& operator=(unique_socket&& other) noexcept
        {
            if (this != &other)
            {
                reset();
                socket_ = std::exchange(other.socket_, INVALID_SOCKET);
            }
            return *this;
        }

        [[nodiscard]] SOCKET get() const noexcept { return socket_; }
        [[nodiscard]] bool valid() const noexcept { return socket_ != INVALID_SOCKET; }

        void reset() noexcept
        {
            if (socket_ != INVALID_SOCKET)
            {
                ::closesocket(socket_);
                socket_ = INVALID_SOCKET;
            }
        }

    private:
        SOCKET socket_{ INVALID_SOCKET };
    };

    inline std::string wsa_error_text(const int code)
    {
        return std::format("WSA error {}", code);
    }

    inline bool set_v6_only(const SOCKET s, const bool v6_only)
    {
        const DWORD value = v6_only ? 1 : 0;
        return ::setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
            reinterpret_cast<const char*>(&value), sizeof(value)) == 0;
    }

    inline bool set_reuse_address(const SOCKET s)
    {
        const BOOL value = TRUE;
        return ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
            reinterpret_cast<const char*>(&value), sizeof(value)) == 0;
    }

    inline sockaddr_in make_v4(const char* address, const uint16_t port)
    {
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        ::inet_pton(AF_INET, address, &sa.sin_addr);
        return sa;
    }

    inline sockaddr_in6 make_v6(const char* address, const uint16_t port)
    {
        sockaddr_in6 sa{};
        sa.sin6_family = AF_INET6;
        sa.sin6_port = htons(port);
        ::inet_pton(AF_INET6, address, &sa.sin6_addr);
        return sa;
    }

    inline uint16_t local_port(const SOCKET s)
    {
        sockaddr_storage ss{};
        int len = sizeof(ss);
        if (::getsockname(s, reinterpret_cast<sockaddr*>(&ss), &len) != 0)
            return 0;
        if (ss.ss_family == AF_INET)
            return ntohs(reinterpret_cast<const sockaddr_in*>(&ss)->sin_port);
        return ntohs(reinterpret_cast<const sockaddr_in6*>(&ss)->sin6_port);
    }

    // ------------------------------------------------------------------------------------
    // Current-process identity, as process_lookup is expected to report it
    // ------------------------------------------------------------------------------------

    inline std::wstring upper(std::wstring s)
    {
        std::ranges::transform(s, s.begin(), ::towupper);
        return s;
    }

    inline std::wstring module_path_of_current_process()
    {
        std::wstring buffer(32768, L'\0');
        const auto len = ::GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        buffer.resize(len);
        return buffer;
    }

    inline std::wstring base_name(const std::wstring& path)
    {
        const auto pos = path.find_last_of(L"\\/");
        return pos == std::wstring::npos ? path : path.substr(pos + 1);
    }

    // ------------------------------------------------------------------------------------
    // Helper child process
    // ------------------------------------------------------------------------------------

    inline constexpr std::string_view child_mode_flag = "--netlib-test-child";

    // Child command: bind a dual-stack (IPV6_V6ONLY = 0) AF_INET6 UDP socket with SO_REUSEADDR
    // to <address>:<port>, report "READY <port>" (or "ERROR <code>") on stdout, then hold the
    // socket until stdin reaches EOF (the parent closes the pipe or exits).
    inline constexpr std::string_view child_udp6_dual_stack_bind = "udp6-dual-stack-bind";

    inline int child_main(const int argc, char** argv)
    {
        if (argc != 5 || std::string_view{ argv[2] } != child_udp6_dual_stack_bind)
        {
            std::cout << "ERROR usage" << std::endl;
            return 2;
        }

        const auto port = static_cast<uint16_t>(std::strtoul(argv[4], nullptr, 10));
        unique_socket s{ ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP) };
        if (!s.valid() || !set_v6_only(s.get(), false) || !set_reuse_address(s.get()))
        {
            std::cout << "ERROR " << ::WSAGetLastError() << std::endl;
            return 1;
        }

        const auto sa = make_v6(argv[3], port);
        if (::bind(s.get(), reinterpret_cast<const sockaddr*>(&sa), sizeof(sa)) != 0)
        {
            std::cout << "ERROR " << ::WSAGetLastError() << std::endl;
            return 1;
        }

        std::cout << "READY " << local_port(s.get()) << std::endl;

        // Block until the parent releases us.
        char ch{};
        DWORD read = 0;
        while (::ReadFile(::GetStdHandle(STD_INPUT_HANDLE), &ch, 1, &read, nullptr) && read != 0) {}
        return 0;
    }

    // Parent-side handle for a running helper child.
    class child_process
    {
    public:
        child_process() = default;
        child_process(const child_process&) = delete;
        child_process& operator=(const child_process&) = delete;

        ~child_process() { stop(); }

        // Starts the helper and waits for its first stdout line. Returns false (and fills
        // error) when the helper could not be started or did not answer.
        bool start(const std::vector<std::string>& args, std::string& first_line, std::string& error)
        {
            SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
            HANDLE out_read = nullptr, out_write = nullptr, in_read = nullptr, in_write = nullptr;
            if (!::CreatePipe(&out_read, &out_write, &sa, 0) || !::CreatePipe(&in_read, &in_write, &sa, 0))
            {
                error = std::format("CreatePipe failed: {}", ::GetLastError());
                return false;
            }
            ::SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);
            ::SetHandleInformation(in_write, HANDLE_FLAG_INHERIT, 0);
            stdout_read_ = out_read;
            stdin_write_ = in_write;

            std::wstring command_line = L"\"" + module_path_of_current_process() + L"\"";
            for (const auto& arg : args)
                command_line += L" " + std::wstring(arg.begin(), arg.end());

            STARTUPINFOW si{};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = in_read;
            si.hStdOutput = out_write;
            si.hStdError = ::GetStdHandle(STD_ERROR_HANDLE);

            PROCESS_INFORMATION pi{};
            const BOOL created = ::CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, TRUE,
                CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
            ::CloseHandle(out_write);
            ::CloseHandle(in_read);
            if (!created)
            {
                error = std::format("CreateProcess failed: {}", ::GetLastError());
                return false;
            }
            ::CloseHandle(pi.hThread);
            process_ = pi.hProcess;
            pid_ = pi.dwProcessId;

            first_line.clear();
            for (;;)
            {
                char ch{};
                DWORD read = 0;
                if (!::ReadFile(stdout_read_, &ch, 1, &read, nullptr) || read == 0)
                {
                    error = "helper exited before reporting status";
                    return false;
                }
                if (ch == '\n')
                    break;
                if (ch != '\r')
                    first_line.push_back(ch);
            }
            return true;
        }

        [[nodiscard]] DWORD pid() const noexcept { return pid_; }

        void stop() noexcept
        {
            if (stdin_write_)
            {
                ::CloseHandle(stdin_write_);
                stdin_write_ = nullptr;
            }
            if (process_)
            {
                if (::WaitForSingleObject(process_, 5000) != WAIT_OBJECT_0)
                    ::TerminateProcess(process_, 1);
                ::CloseHandle(process_);
                process_ = nullptr;
            }
            if (stdout_read_)
            {
                ::CloseHandle(stdout_read_);
                stdout_read_ = nullptr;
            }
        }

    private:
        HANDLE process_{ nullptr };
        HANDLE stdout_read_{ nullptr };
        HANDLE stdin_write_{ nullptr };
        DWORD pid_{ 0 };
    };
}
