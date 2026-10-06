#pragma once

// Shared infrastructure for the native netlib tests:
//   * an explicit UNSUPPORTED outcome, distinct from passing and failing tests;
//   * RAII sockets whose failures carry the failed operation and WSA error code, and a narrow
//     table of recognized environmental limitations;
//   * helper child processes (this executable started in a helper mode) that run inside a
//     kill-on-close job object, inherit only their own pipe ends, and must report readiness
//     within a finite deadline;
//   * running this executable as a subprocess to observe the exit code and output of
//     deliberately failing probe tests.

namespace netlib_test
{
    // ------------------------------------------------------------------------------------
    // Explicit unsupported-environment outcome
    // ------------------------------------------------------------------------------------

    struct unsupported_case
    {
        std::string test;    // "<test case>.<test name>"
        std::string reason;
    };

    inline std::mutex& unsupported_lock()
    {
        static std::mutex lock;
        return lock;
    }

    inline std::vector<unsupported_case>& unsupported_storage()
    {
        static std::vector<unsupported_case> items;
        return items;
    }

    inline std::vector<unsupported_case> unsupported_cases()
    {
        std::lock_guard lock(unsupported_lock());
        return unsupported_storage();
    }

    inline void record_unsupported(const std::string& reason)
    {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        std::string name = info ? std::string(info->test_case_name()) + "." + info->name() : "<unknown>";
        std::cout << "[ UNSUPPORTED ] " << name << ": " << reason << '\n';
        ::testing::Test::RecordProperty("unsupported", reason);
        std::lock_guard lock(unsupported_lock());
        unsupported_storage().push_back({ std::move(name), reason });
    }

    // Marks the current test as not exercised on this host and leaves the calling function.
    // Use only for a specific, documented environmental condition. main() reports such cases
    // separately and returns a non-zero exit code unless explicitly allowed.
#define NETLIB_TEST_UNSUPPORTED(reason)                     \
    do {                                                    \
        ::netlib_test::record_unsupported(reason);          \
        return;                                             \
    } while (false)

    // ------------------------------------------------------------------------------------
    // Socket failures and recognized environmental limitations
    // ------------------------------------------------------------------------------------

    // Numeric values are part of the helper child's status protocol ("ERROR <op> <code>").
    enum class socket_op : int
    {
        create = 1,
        set_v6_only = 2,
        set_reuse_address = 3,
        bind = 4,
        listen = 5,
        connect = 6,
        accept = 7,
        get_local_address = 8,
    };

    inline constexpr int socket_op_min = 1;
    inline constexpr int socket_op_max = 8;

    inline const char* to_string(const socket_op op) noexcept
    {
        switch (op)
        {
        case socket_op::create: return "socket";
        case socket_op::set_v6_only: return "setsockopt(IPV6_V6ONLY)";
        case socket_op::set_reuse_address: return "setsockopt(SO_REUSEADDR)";
        case socket_op::bind: return "bind";
        case socket_op::listen: return "listen";
        case socket_op::connect: return "connect";
        case socket_op::accept: return "accept";
        case socket_op::get_local_address: return "getsockname";
        }
        return "<unknown socket operation>";
    }

    struct socket_failure
    {
        socket_op op{};
        int family{};          // AF_INET or AF_INET6
        std::string address;   // address literal used by bind/connect, if any
        int code{};            // WSA error code
    };

    inline std::string describe(const socket_failure& f)
    {
        return std::format("{}({}{}{}) failed with WSA error {}", to_string(f.op),
            f.family == AF_INET6 ? "AF_INET6" : "AF_INET",
            f.address.empty() ? "" : ", ", f.address, f.code);
    }

    // The only socket failures accepted as environmental limitations. Anything else is a test
    // failure. Each entry is a documented Winsock outcome for a host lacking the capability:
    //   * socket(AF_INET6) -> WSAEAFNOSUPPORT: the IPv6 protocol is not installed.
    //   * bind/connect to ::1 -> WSAEADDRNOTAVAIL: the IPv6 loopback address is not configured.
    inline std::optional<std::string> environment_limitation(const socket_failure& f)
    {
        if (f.op == socket_op::create && f.family == AF_INET6 && f.code == WSAEAFNOSUPPORT)
            return "IPv6 is not installed on this host (" + describe(f) + ")";
        if ((f.op == socket_op::bind || f.op == socket_op::connect) && f.family == AF_INET6 &&
            f.address == "::1" && f.code == WSAEADDRNOTAVAIL)
            return "the IPv6 loopback address ::1 is not available on this host (" + describe(f) + ")";
        return std::nullopt;
    }

    // Leaves the calling test function: UNSUPPORTED for a recognized limitation, otherwise a
    // failure that preserves the operation and error code.
#define NETLIB_TEST_REQUIRE_SOCKETS(expr)                                                   \
    do {                                                                                    \
        if (const auto netlib_failure_ = (expr))                                            \
        {                                                                                   \
            if (const auto netlib_limit_ = ::netlib_test::environment_limitation(*netlib_failure_)) \
                NETLIB_TEST_UNSUPPORTED(*netlib_limit_);                                    \
            FAIL() << "socket setup failed: " << ::netlib_test::describe(*netlib_failure_); \
        }                                                                                   \
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

    union socket_address
    {
        sockaddr base;
        sockaddr_in v4;
        sockaddr_in6 v6;
    };

    // Parses an address literal; returns false for a literal that is not valid for the family.
    inline bool make_address(const int family, const char* address, const uint16_t port, socket_address& out, int& length)
    {
        out = {};
        if (family == AF_INET)
        {
            out.v4.sin_family = AF_INET;
            out.v4.sin_port = htons(port);
            length = sizeof(sockaddr_in);
            return ::inet_pton(AF_INET, address, &out.v4.sin_addr) == 1;
        }
        out.v6.sin6_family = AF_INET6;
        out.v6.sin6_port = htons(port);
        length = sizeof(sockaddr_in6);
        return ::inet_pton(AF_INET6, address, &out.v6.sin6_addr) == 1;
    }

    inline std::optional<socket_failure> create_socket(unique_socket& s, const int family, const int type, const int protocol)
    {
        s = unique_socket{ ::socket(family, type, protocol) };
        if (!s.valid())
            return socket_failure{ socket_op::create, family, {}, ::WSAGetLastError() };
        return std::nullopt;
    }

    inline std::optional<socket_failure> set_v6_only(const SOCKET s, const bool v6_only)
    {
        const DWORD value = v6_only ? 1 : 0;
        if (::setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&value), sizeof(value)) != 0)
            return socket_failure{ socket_op::set_v6_only, AF_INET6, {}, ::WSAGetLastError() };
        return std::nullopt;
    }

    inline std::optional<socket_failure> set_reuse_address(const SOCKET s, const int family)
    {
        const BOOL value = TRUE;
        if (::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&value), sizeof(value)) != 0)
            return socket_failure{ socket_op::set_reuse_address, family, {}, ::WSAGetLastError() };
        return std::nullopt;
    }

    inline std::optional<socket_failure> bind_socket(const SOCKET s, const int family, const char* address, const uint16_t port)
    {
        socket_address sa{};
        int length = 0;
        if (!make_address(family, address, port, sa, length))
            return socket_failure{ socket_op::bind, family, address, WSAEINVAL };
        if (::bind(s, &sa.base, length) != 0)
            return socket_failure{ socket_op::bind, family, address, ::WSAGetLastError() };
        return std::nullopt;
    }

    inline std::optional<socket_failure> connect_socket(const SOCKET s, const int family, const char* address, const uint16_t port)
    {
        socket_address sa{};
        int length = 0;
        if (!make_address(family, address, port, sa, length))
            return socket_failure{ socket_op::connect, family, address, WSAEINVAL };
        if (::connect(s, &sa.base, length) != 0)
            return socket_failure{ socket_op::connect, family, address, ::WSAGetLastError() };
        return std::nullopt;
    }

    inline std::optional<socket_failure> local_port(const SOCKET s, const int family, uint16_t& port)
    {
        sockaddr_storage ss{};
        int len = sizeof(ss);
        if (::getsockname(s, reinterpret_cast<sockaddr*>(&ss), &len) != 0)
            return socket_failure{ socket_op::get_local_address, family, {}, ::WSAGetLastError() };
        port = ss.ss_family == AF_INET
            ? ntohs(reinterpret_cast<const sockaddr_in*>(&ss)->sin_port)
            : ntohs(reinterpret_cast<const sockaddr_in6*>(&ss)->sin6_port);
        return std::nullopt;
    }

    // Creates and binds a UDP socket; v6_only applies to AF_INET6 sockets.
    inline std::optional<socket_failure> bind_udp(unique_socket& s, const int family, const char* address,
        const bool v6_only, const uint16_t port, const bool reuse, uint16_t& bound_port)
    {
        if (auto f = create_socket(s, family, SOCK_DGRAM, IPPROTO_UDP)) return f;
        if (family == AF_INET6)
            if (auto f = set_v6_only(s.get(), v6_only)) return f;
        if (reuse)
            if (auto f = set_reuse_address(s.get(), family)) return f;
        if (auto f = bind_socket(s.get(), family, address, port)) return f;
        return local_port(s.get(), family, bound_port);
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
    // Processes
    // ------------------------------------------------------------------------------------

    // Helper children are placed in their kill-on-close job by CreateProcessW itself. This is a
    // requirement of the test host only (Windows 10 / Windows Server 2016 or newer); the product's
    // platform requirements are unchanged.
#ifndef PROC_THREAD_ATTRIBUTE_JOB_LIST
#error "netlib-tests requires PROC_THREAD_ATTRIBUTE_JOB_LIST (Windows 10 SDK, _WIN32_WINNT >= 0x0A00)"
#endif

    class unique_handle
    {
    public:
        unique_handle() = default;
        explicit unique_handle(const HANDLE h) noexcept : handle_(h == INVALID_HANDLE_VALUE ? nullptr : h) {}
        ~unique_handle() { reset(); }

        unique_handle(const unique_handle&) = delete;
        unique_handle& operator=(const unique_handle&) = delete;
        unique_handle(unique_handle&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
        unique_handle& operator=(unique_handle&& other) noexcept
        {
            if (this != &other)
            {
                reset();
                handle_ = std::exchange(other.handle_, nullptr);
            }
            return *this;
        }

        [[nodiscard]] HANDLE get() const noexcept { return handle_; }
        [[nodiscard]] explicit operator bool() const noexcept { return handle_ != nullptr; }

        void reset(const HANDLE h = nullptr) noexcept
        {
            if (handle_)
                ::CloseHandle(handle_);
            handle_ = h == INVALID_HANDLE_VALUE ? nullptr : h;
        }

    private:
        HANDLE handle_{ nullptr };
    };

    // A failure of the test infrastructure itself (never an environmental limitation).
    struct infra_failure
    {
        std::string operation;  // Win32 API or protocol step that failed
        DWORD code{};           // Win32 error code, or process exit code where stated
        std::string detail;

        [[nodiscard]] std::string describe() const
        {
            return std::format("{} failed (code {}){}{}", operation, code, detail.empty() ? "" : ": ", detail);
        }
    };

    // Line framing for the helper status protocol. A frame is a payload of at most max_payload
    // bytes followed by LF; one CR immediately before the LF belongs to the frame, not to the
    // payload. Nothing else is removed or skipped, so malformed input stays malformed.
    //   complete    the payload is in `line` and the frame was consumed from `pending`;
    //   incomplete  no LF yet, and the buffered prefix can still become a valid frame;
    //   oversized   the input cannot be a valid frame: LF arrived after more than max_payload
    //               payload bytes, or more bytes are buffered without LF than any valid frame
    //               holds (max_payload plus one CR). `detail` describes the rejection.
    // A prefix of an oversized or unterminated frame is never reported as a line.
    enum class frame_status { complete, incomplete, oversized };

    inline std::string printable_excerpt(const std::string_view data, const size_t limit = 32)
    {
        std::string text;
        for (const auto ch : data.substr(0, limit))
            text += (ch >= 0x20 && ch < 0x7F && ch != '"') ? ch : '.';
        if (data.size() > limit)
            text += "...";
        return text;
    }

    inline frame_status frame_line(std::string& pending, const size_t max_payload, std::string& line, std::string& detail)
    {
        line.clear();
        if (const auto lf = pending.find('\n'); lf != std::string::npos)
        {
            const size_t payload = (lf > 0 && pending[lf - 1] == '\r') ? lf - 1 : lf;
            if (payload > max_payload)
            {
                detail = std::format("{} payload bytes before the line terminator exceed the {}-byte limit (input starts \"{}\")",
                    payload, max_payload, printable_excerpt(pending));
                return frame_status::oversized;
            }
            line.assign(pending, 0, payload);
            pending.erase(0, lf + 1);
            return frame_status::complete;
        }
        if (pending.size() > max_payload + 1 || (pending.size() == max_payload + 1 && pending.back() != '\r'))
        {
            detail = std::format("{} bytes without a line terminator exceed the {}-byte limit (input starts \"{}\")",
                pending.size(), max_payload, printable_excerpt(pending));
            return frame_status::oversized;
        }
        return frame_status::incomplete;
    }

    // Test instrumentation for launched_process::launch(): called with the new child's PID the
    // moment CreateProcessW has returned successfully, before any further setup and before
    // ResumeThread. Empty in ordinary runs. The lifecycle regression installs a hook that
    // reports the PID and blocks, so the parent can be terminated at exactly that boundary.
    inline std::function<void(DWORD)>& after_child_created_hook()
    {
        static std::function<void(DWORD)> hook;
        return hook;
    }

    // A process launched with stdin/stdout pipes (stderr merged into stdout) inside a job object
    // configured with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. The job is fully configured before the
    // child exists, and the child is made a member of it by CreateProcessW itself through
    // PROC_THREAD_ATTRIBUTE_JOB_LIST (Windows 10 / Windows Server 2016 and newer); there is no
    // window in which the child exists outside the job, so a parent that dies at any point after
    // CreateProcessW returns takes the child with it. The child inherits only its two pipe ends
    // (PROC_THREAD_ATTRIBUTE_HANDLE_LIST), so it cannot capture this process's sockets and never
    // holds a handle to its own job (which would keep the job alive after the parent's death).
    // Destruction closes stdin, waits briefly for a voluntary exit, then terminates the job.
    class launched_process
    {
    public:
        enum class read_status { line, eof, timeout, error, oversized };

        launched_process() = default;
        launched_process(const launched_process&) = delete;
        launched_process& operator=(const launched_process&) = delete;
        ~launched_process() { stop(std::chrono::milliseconds{ 5000 }); }

        std::optional<infra_failure> launch(const std::wstring& executable, const std::vector<std::string>& args)
        {
            // The job is configured completely, kill-on-close included, before the child exists.
            // CreateJobObjectW with null security attributes yields a non-inheritable handle; the
            // explicit flag below keeps that true even if the creation code changes.
            job_.reset(::CreateJobObjectW(nullptr, nullptr));
            if (!job_)
                return infra_failure{ "CreateJobObjectW", ::GetLastError(), {} };

            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!::SetInformationJobObject(job_.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
                return infra_failure{ "SetInformationJobObject", ::GetLastError(), {} };
            if (!::SetHandleInformation(job_.get(), HANDLE_FLAG_INHERIT, 0))
                return infra_failure{ "SetHandleInformation(job)", ::GetLastError(), {} };

            SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
            HANDLE raw_out_read = nullptr, raw_out_write = nullptr, raw_in_read = nullptr, raw_in_write = nullptr;
            if (!::CreatePipe(&raw_out_read, &raw_out_write, &sa, 0))
                return infra_failure{ "CreatePipe(stdout)", ::GetLastError(), {} };
            stdout_read_.reset(raw_out_read);
            unique_handle child_stdout{ raw_out_write };
            if (!::CreatePipe(&raw_in_read, &raw_in_write, &sa, 0))
                return infra_failure{ "CreatePipe(stdin)", ::GetLastError(), {} };
            unique_handle child_stdin{ raw_in_read };
            stdin_write_.reset(raw_in_write);
            if (!::SetHandleInformation(stdout_read_.get(), HANDLE_FLAG_INHERIT, 0) ||
                !::SetHandleInformation(stdin_write_.get(), HANDLE_FLAG_INHERIT, 0))
                return infra_failure{ "SetHandleInformation", ::GetLastError(), {} };

            // Two attributes: the restricted inheritance list and the job list. The attribute
            // list stores pointers to `inherited` and `jobs`, so both arrays (and the handles they
            // name) stay alive in this scope until CreateProcessW has returned; the list itself
            // is deleted by attribute_guard afterwards.
            SIZE_T attribute_size = 0;
            ::InitializeProcThreadAttributeList(nullptr, 2, 0, &attribute_size);
            std::vector<std::byte> attribute_storage(attribute_size);
            auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data());
            if (!::InitializeProcThreadAttributeList(attributes, 2, 0, &attribute_size))
                return infra_failure{ "InitializeProcThreadAttributeList", ::GetLastError(), {} };
            const auto attribute_guard = gsl::finally([attributes] { ::DeleteProcThreadAttributeList(attributes); });
            HANDLE inherited[2] = { child_stdin.get(), child_stdout.get() };
            if (!::UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    inherited, sizeof(inherited), nullptr, nullptr))
                return infra_failure{ "UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)", ::GetLastError(), {} };
            // If the host does not support the job list (Windows 8.1 and older), this or
            // CreateProcessW fails and no child is ever created: there is no fallback to
            // assigning the child after creation, because that reopens the orphan window.
            HANDLE jobs[1] = { job_.get() };
            if (!::UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
                    jobs, sizeof(jobs), nullptr, nullptr))
                return infra_failure{ "UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_JOB_LIST)", ::GetLastError(),
                    "the test host must run Windows 10 / Windows Server 2016 or newer; no helper was started" };

            std::wstring command_line = quote(executable);
            for (const auto& arg : args)
                command_line += L" " + quote(std::wstring(arg.begin(), arg.end()));

            STARTUPINFOEXW si{};
            si.StartupInfo.cb = sizeof(si);
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = child_stdin.get();
            si.StartupInfo.hStdOutput = child_stdout.get();
            si.StartupInfo.hStdError = child_stdout.get();
            si.lpAttributeList = attributes;

            // From the moment this call succeeds the (still suspended) child is a member of job_;
            // the parent dying anywhere below closes job_'s only handle and kills the child.
            PROCESS_INFORMATION pi{};
            if (!::CreateProcessW(executable.c_str(), command_line.data(), nullptr, nullptr, TRUE,
                    CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                    nullptr, nullptr, &si.StartupInfo, &pi))
                return infra_failure{ "CreateProcessW", ::GetLastError(), {} };
            process_.reset(pi.hProcess);
            unique_handle thread{ pi.hThread };
            pid_ = pi.dwProcessId;

            if (const auto& hook = after_child_created_hook())
                hook(pid_);

            // Membership is established by CreateProcessW; this only guards against a platform
            // that accepted the attribute without honouring it. Such a child is killed directly.
            BOOL in_job = FALSE;
            if (!::IsProcessInJob(process_.get(), job_.get(), &in_job) || !in_job)
            {
                const auto error = in_job ? ERROR_SUCCESS : ::GetLastError();
                terminate();
                return infra_failure{ "IsProcessInJob", error, "the new child is not a member of its kill-on-close job" };
            }
            if (::ResumeThread(thread.get()) == static_cast<DWORD>(-1))
            {
                const auto error = ::GetLastError();
                terminate();
                return infra_failure{ "ResumeThread", error, {} };
            }
            // child_stdin / child_stdout close here, so EOF is observed once the child exits.
            return std::nullopt;
        }

        [[nodiscard]] DWORD pid() const noexcept { return pid_; }
        [[nodiscard]] HANDLE process() const noexcept { return process_.get(); }

        // Output received but not yet consumed as a complete line (diagnostics only).
        [[nodiscard]] const std::string& buffered() const noexcept { return pending_; }

        // Reads one complete status line (see frame_line) with at most max_payload payload bytes
        // before the deadline. Returns `oversized` (with the reason in `error`) for input that
        // cannot be a valid line, and `eof` / `timeout` when the output ends or the deadline
        // passes before a complete line, whatever prefix has been buffered.
        read_status read_line(std::string& line, const std::chrono::steady_clock::time_point deadline,
            const size_t max_payload, infra_failure& error)
        {
            line.clear();
            for (;;)
            {
                std::string detail;
                switch (frame_line(pending_, max_payload, line, detail))
                {
                case frame_status::complete:
                    return read_status::line;
                case frame_status::oversized:
                    error = { "status line framing", ERROR_INVALID_DATA, std::move(detail) };
                    return read_status::oversized;
                case frame_status::incomplete:
                    break;
                }
                const auto status = fill(deadline, error);
                if (status != read_status::line)
                    return status;
            }
        }

        // Reads everything until the child closes its output, or the deadline passes.
        read_status read_all(std::string& output, const std::chrono::steady_clock::time_point deadline, infra_failure& error)
        {
            for (;;)
            {
                output += pending_;
                pending_.clear();
                const auto status = fill(deadline, error);
                if (status != read_status::line)
                    return status;
            }
        }

        void close_stdin() noexcept { stdin_write_.reset(); }

        // Waits for exit; returns the exit code, or nullopt on timeout.
        std::optional<DWORD> wait_exit(const std::chrono::milliseconds timeout) const noexcept
        {
            if (!process_)
                return std::nullopt;
            if (::WaitForSingleObject(process_.get(), static_cast<DWORD>(timeout.count())) != WAIT_OBJECT_0)
                return std::nullopt;
            DWORD code = 0;
            ::GetExitCodeProcess(process_.get(), &code);
            return code;
        }

        // Kills every process in the job (and the direct child itself, should it ever not be a
        // job member) and waits for the direct child to exit.
        void terminate() noexcept
        {
            if (job_)
                ::TerminateJobObject(job_.get(), 1);
            if (process_)
            {
                ::TerminateProcess(process_.get(), 1);
                ::WaitForSingleObject(process_.get(), 5000);
            }
        }

        // Number of live processes in the job (0 once the child and any descendants are gone).
        [[nodiscard]] DWORD active_processes() const noexcept
        {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info{};
            if (!job_ || !::QueryInformationJobObject(job_.get(), JobObjectBasicAccountingInformation,
                    &info, sizeof(info), nullptr))
                return 0;
            return info.ActiveProcesses;
        }

        [[nodiscard]] bool has_exited() const noexcept
        {
            return !process_ || ::WaitForSingleObject(process_.get(), 0) == WAIT_OBJECT_0;
        }

        void stop(const std::chrono::milliseconds grace) noexcept
        {
            close_stdin();
            if (process_ && !wait_exit(grace))
                terminate();
            job_.reset();      // KILL_ON_JOB_CLOSE: nothing in the job survives this
            stdout_read_.reset();
        }

    private:
        static std::wstring quote(const std::wstring& arg)
        {
            if (!arg.empty() && arg.find_first_of(L" \t\"") == std::wstring::npos)
                return arg;
            std::wstring quoted = L"\"";
            for (const auto ch : arg)
            {
                if (ch == L'"')
                    quoted += L'\\';
                quoted += ch;
            }
            return quoted + L"\"";
        }

        // Appends available output to pending_. Returns line when data arrived.
        read_status fill(const std::chrono::steady_clock::time_point deadline, infra_failure& error)
        {
            for (;;)
            {
                DWORD available = 0;
                if (!::PeekNamedPipe(stdout_read_.get(), nullptr, 0, nullptr, &available, nullptr))
                {
                    const auto code = ::GetLastError();
                    if (code == ERROR_BROKEN_PIPE)
                        return read_status::eof;
                    error = { "PeekNamedPipe", code, {} };
                    return read_status::error;
                }
                if (available > 0)
                {
                    char buffer[4096];
                    DWORD read = 0;
                    if (!::ReadFile(stdout_read_.get(), buffer,
                            (std::min<DWORD>)(available, sizeof(buffer)), &read, nullptr))
                    {
                        error = { "ReadFile", ::GetLastError(), {} };
                        return read_status::error;
                    }
                    pending_.append(buffer, read);
                    return read_status::line;
                }
                if (std::chrono::steady_clock::now() >= deadline)
                    return read_status::timeout;
                ::Sleep(5);
            }
        }

        unique_handle job_;
        unique_handle process_;
        unique_handle stdout_read_;
        unique_handle stdin_write_;
        DWORD pid_{ 0 };
        std::string pending_;
    };

    // ------------------------------------------------------------------------------------
    // Helper child process
    // ------------------------------------------------------------------------------------

    inline constexpr std::string_view child_mode_flag = "--netlib-test-child";

    // Child commands (argv[2]):
    //   udp6-dual-stack-bind <address> <port>
    //       Bind a dual-stack (IPV6_V6ONLY = 0) AF_INET6 UDP socket with SO_REUSEADDR, report
    //       "READY <port>" or "ERROR <socket_op> <wsa error>", then hold the socket until stdin
    //       reaches EOF.
    //   print-line <text>   Report <text> as the status line (via std::cout, i.e. with the C
    //                       runtime's CRLF translation), then hold until stdin EOF.
    //   write-bytes <spec> [<code>]
    //                       Write exactly the bytes of <spec> to stdout with WriteFile, then hold
    //                       until stdin EOF, or exit with <code> when given. Escapes: \n LF, \r CR,
    //                       \\ backslash, \| bar. A bare '|' splits the output into chunks written
    //                       100 ms apart, so the parent's reader sees them in separate reads.
    //   exit-now <code>     Exit immediately with <code> without reporting a status.
    //   never-ready         Report nothing; hold until stdin EOF (or termination).
    // All but the first exist only to exercise the parent's failure handling.
    inline constexpr std::string_view child_udp6_dual_stack_bind = "udp6-dual-stack-bind";
    inline constexpr std::string_view child_print_line = "print-line";
    inline constexpr std::string_view child_write_bytes = "write-bytes";
    inline constexpr std::string_view child_exit_now = "exit-now";
    inline constexpr std::string_view child_never_ready = "never-ready";

    // Documented readiness deadline for helper children.
    inline constexpr std::chrono::milliseconds helper_ready_timeout{ 10000 };

    // Documented limit of a helper status line: at most this many payload bytes before the LF
    // (an immediately preceding CR is not counted). Longer or unterminated input is a failure.
    inline constexpr size_t helper_status_max_payload = 256;

    inline void child_hold_until_stdin_eof()
    {
        char ch{};
        DWORD read = 0;
        while (::ReadFile(::GetStdHandle(STD_INPUT_HANDLE), &ch, 1, &read, nullptr) && read != 0) {}
    }

    // Decodes a write-bytes spec into chunks (see child commands above).
    inline std::vector<std::string> decode_write_bytes_spec(const std::string_view spec)
    {
        std::vector<std::string> chunks(1);
        for (size_t i = 0; i < spec.size(); ++i)
        {
            if (spec[i] == '|')
            {
                chunks.emplace_back();
                continue;
            }
            if (spec[i] == '\\' && i + 1 < spec.size())
            {
                switch (spec[++i])
                {
                case 'n': chunks.back() += '\n'; continue;
                case 'r': chunks.back() += '\r'; continue;
                default: chunks.back() += spec[i]; continue;
                }
            }
            chunks.back() += spec[i];
        }
        return chunks;
    }

    inline void child_write_raw_chunks(const std::vector<std::string>& chunks)
    {
        const HANDLE out = ::GetStdHandle(STD_OUTPUT_HANDLE);
        for (size_t i = 0; i < chunks.size(); ++i)
        {
            if (i != 0)
                ::Sleep(100);
            DWORD written = 0;
            ::WriteFile(out, chunks[i].data(), static_cast<DWORD>(chunks[i].size()), &written, nullptr);
            ::FlushFileBuffers(out);
        }
    }

    inline int child_main(const int argc, char** argv)
    {
        const std::string_view command = argc >= 3 ? std::string_view{ argv[2] } : std::string_view{};

        if (command == child_udp6_dual_stack_bind && argc == 5)
        {
            const auto port = static_cast<uint16_t>(std::strtoul(argv[4], nullptr, 10));
            unique_socket s;
            uint16_t bound = 0;
            if (const auto f = bind_udp(s, AF_INET6, argv[3], false, port, true, bound))
            {
                std::cout << "ERROR " << static_cast<int>(f->op) << ' ' << f->code << std::endl;
                return 1;
            }
            std::cout << "READY " << bound << std::endl;
            child_hold_until_stdin_eof();
            return 0;
        }
        if (command == child_print_line && argc == 4)
        {
            std::cout << argv[3] << std::endl;
            child_hold_until_stdin_eof();
            return 0;
        }
        if (command == child_write_bytes && (argc == 4 || argc == 5))
        {
            child_write_raw_chunks(decode_write_bytes_spec(argv[3]));
            if (argc == 5)
                return static_cast<int>(std::strtol(argv[4], nullptr, 10));
            child_hold_until_stdin_eof();
            return 0;
        }
        if (command == child_exit_now && argc == 4)
            return static_cast<int>(std::strtol(argv[3], nullptr, 10));
        if (command == child_never_ready && argc == 3)
        {
            child_hold_until_stdin_eof();
            return 0;
        }

        std::cout << "USAGE-ERROR" << std::endl;
        return 2;
    }

    // How a helper start ended. Only `ready` and `environment_limitation` are non-failures, and
    // only `ready` lets a test proceed.
    enum class helper_outcome { ready, environment_limitation, failure };

    struct helper_start_result
    {
        helper_outcome outcome{ helper_outcome::failure };
        uint16_t port{};
        std::string diagnostic;
    };

    struct helper_options
    {
        std::wstring executable;                              // empty: this executable
        std::vector<std::string> command;                     // empty: the dual-stack UDP bind command
        std::chrono::milliseconds ready_timeout{ helper_ready_timeout };
    };

    // Builds "<prefix><zeros><value>" of exactly total_payload bytes: a status line whose tokens
    // parse like "<prefix><value>" but which fills a given length (framing regressions).
    inline std::string zero_padded_status(const std::string& prefix, const std::string& value, const size_t total_payload)
    {
        return prefix + std::string(total_payload - prefix.size() - value.size(), '0') + value;
    }

    // Parses a non-negative decimal integer occupying the whole token.
    inline bool parse_uint(const std::string_view token, unsigned long& value)
    {
        if (token.empty())
            return false;
        const auto* end = token.data() + token.size();
        const auto [ptr, ec] = std::from_chars(token.data(), end, value);
        return ec == std::errc{} && ptr == end;
    }

    inline std::vector<std::string_view> split_spaces(const std::string_view line)
    {
        std::vector<std::string_view> tokens;
        size_t start = 0;
        while (start <= line.size())
        {
            const auto pos = line.find(' ', start);
            tokens.push_back(line.substr(start, pos == std::string_view::npos ? std::string_view::npos : pos - start));
            if (pos == std::string_view::npos)
                break;
            start = pos + 1;
        }
        return tokens;
    }

    // A helper child holding a dual-stack UDP socket for the lifetime of this object.
    class helper_child
    {
    public:
        // Starts the helper and classifies the result. Every non-ready outcome terminates the
        // helper (and anything in its job) before returning.
        helper_start_result start(const helper_options& options, const char* bind_address)
        {
            helper_start_result result = start_impl(options, bind_address);
            if (result.outcome != helper_outcome::ready)
                process_.terminate();
            return result;
        }

        [[nodiscard]] DWORD pid() const noexcept { return process_.pid(); }
        [[nodiscard]] HANDLE process() const noexcept { return process_.process(); }
        [[nodiscard]] DWORD active_processes() const noexcept { return process_.active_processes(); }
        [[nodiscard]] bool has_exited() const noexcept { return process_.has_exited(); }

    private:
        helper_start_result start_impl(const helper_options& options, const char* bind_address)
        {
            const auto executable = options.executable.empty() ? module_path_of_current_process() : options.executable;
            std::vector<std::string> args{ std::string{ child_mode_flag } };
            if (options.command.empty())
            {
                args.emplace_back(child_udp6_dual_stack_bind);
                args.emplace_back(bind_address);
                args.emplace_back("0");
            }
            else
            {
                args.insert(args.end(), options.command.begin(), options.command.end());
            }

            if (const auto failure = process_.launch(executable, args))
                return { helper_outcome::failure, 0, "helper launch: " + failure->describe() };

            // Only a complete, framed status line is parsed. Incomplete output at EOF or at the
            // deadline is reported (never parsed), and oversized input is rejected outright.
            const auto deadline = std::chrono::steady_clock::now() + options.ready_timeout;
            std::string line;
            infra_failure read_error;
            const auto unterminated = [this] {
                return process_.buffered().empty() ? std::string{} : std::format(
                    "; {} byte(s) of unterminated output: \"{}\"", process_.buffered().size(),
                    printable_excerpt(process_.buffered()));
            };
            switch (process_.read_line(line, deadline, helper_status_max_payload, read_error))
            {
            case launched_process::read_status::line:
                break;
            case launched_process::read_status::eof:
            {
                const auto code = process_.wait_exit(std::chrono::milliseconds{ 5000 });
                return { helper_outcome::failure, 0, std::format(
                    "helper exited before reporting status (exit code {}){}",
                    code ? std::to_string(*code) : std::string{ "unknown" }, unterminated()) };
            }
            case launched_process::read_status::timeout:
                return { helper_outcome::failure, 0, std::format(
                    "helper did not report status within {} ms{}", options.ready_timeout.count(), unterminated()) };
            case launched_process::read_status::oversized:
                return { helper_outcome::failure, 0, "oversized helper status line: " + read_error.detail };
            case launched_process::read_status::error:
                return { helper_outcome::failure, 0, "reading helper status: " + read_error.describe() };
            }

            const auto tokens = split_spaces(line);
            unsigned long first = 0, second = 0;
            if (tokens.size() == 2 && tokens[0] == "READY" && parse_uint(tokens[1], first) && first > 0 && first <= 65535)
                return { helper_outcome::ready, static_cast<uint16_t>(first), {} };

            if (tokens.size() == 3 && tokens[0] == "ERROR" && parse_uint(tokens[1], first) && parse_uint(tokens[2], second) &&
                first >= socket_op_min && first <= socket_op_max && second <= INT_MAX)
            {
                const socket_failure failure{ static_cast<socket_op>(first), AF_INET6,
                    bind_address ? bind_address : "", static_cast<int>(second) };
                if (const auto limitation = environment_limitation(failure))
                    return { helper_outcome::environment_limitation, 0, "helper: " + *limitation };
                return { helper_outcome::failure, 0, "helper socket setup: " + describe(failure) };
            }

            return { helper_outcome::failure, 0, std::format("malformed helper status line: \"{}\"", line) };
        }

        launched_process process_;
    };

    // ------------------------------------------------------------------------------------
    // Running this executable as a subprocess (failure probes)
    // ------------------------------------------------------------------------------------

    struct self_run
    {
        std::optional<infra_failure> failure;   // launch/read failure or timeout
        DWORD exit_code{};
        std::string output;                     // stdout and stderr, merged
        DWORD surviving_processes{};            // processes left in the job after the exit
    };

    inline self_run run_self(const std::vector<std::string>& args, const std::chrono::milliseconds timeout)
    {
        self_run run;
        launched_process process;
        if (auto failure = process.launch(module_path_of_current_process(), args))
        {
            run.failure = std::move(failure);
            return run;
        }
        process.close_stdin();

        infra_failure error;
        switch (process.read_all(run.output, std::chrono::steady_clock::now() + timeout, error))
        {
        case launched_process::read_status::timeout:
            process.terminate();
            run.failure = infra_failure{ "subprocess", WAIT_TIMEOUT, std::format("no exit within {} ms", timeout.count()) };
            return run;
        case launched_process::read_status::error:
            process.terminate();
            run.failure = error;
            return run;
        default:
            break;
        }

        if (const auto code = process.wait_exit(std::chrono::milliseconds{ 10000 }))
            run.exit_code = *code;
        else
        {
            process.terminate();
            run.failure = infra_failure{ "subprocess", WAIT_TIMEOUT, "output closed but process did not exit" };
            return run;
        }

        // Descendants (e.g. helpers started by the subprocess, in its own nested job) are also
        // members of this job. Allow a short interval for kill-on-close teardown to complete.
        const auto settle = std::chrono::steady_clock::now() + std::chrono::seconds{ 5 };
        while ((run.surviving_processes = process.active_processes()) != 0 && std::chrono::steady_clock::now() < settle)
            ::Sleep(10);
        return run;
    }
}
