#include "unmanaged.h"

// Bring in the small destination-inclusion policy C-API (added feature)
#include "policy/dest_inclusion_policy.h"

#include <cwctype>   // for towlower
#include <string>

// Force this TU to be compiled as native even if project defaults change
#pragma managed(push, off)

/**
 * @brief Platform-specific mutex implementation for thread safety.
 */
struct mutex_impl
{
    std::mutex lock;
};

/**
 * @brief Helper to normalize process names to policy keys:
 * - take only filename
 * - drop trailing extension (e.g., .exe)
 * - lowercase
 */
static std::wstring normalize_process_key(std::wstring s)
{
    // 1) strip any path
    if (const auto pos = s.find_last_of(L"\\/"); pos != std::wstring::npos)
        s = s.substr(pos + 1);

    // 2) drop extension if present
    if (const auto dot = s.find_last_of(L'.'); dot != std::wstring::npos)
        s = s.substr(0, dot);

    // 3) lowercase
    for (auto& ch : s) ch = static_cast<wchar_t>(std::towlower(ch));

    return s;
}

/**
 * @brief Constructs the socksify_unmanaged singleton instance.
 * Initializes Winsock, logging, and the SOCKS5 local router.
 * @param log_level The logging level to use for the proxy gateway.
 */
socksify_unmanaged::socksify_unmanaged(const log_level_mx log_level) :
    log_level_{ log_level }
{
    using namespace std::string_literals;

    WSADATA wsa_data;

    if (constexpr auto version_requested = MAKEWORD(2, 2); ::WSAStartup(version_requested, &wsa_data) != 0)
    {
        // Keep behavior: just print through our logger bridge
        print_log(log_level_mx::info, "WSAStartup failed with error\n");
    }

    lock_ = std::make_unique<mutex_impl>();

    print_log(log_level_mx::info, "Creating SOCKS5 Local Router instance..."s);

    // Map our mixed log level to netlib level (no verbosity tuning calls)
    auto um_log_level = netlib::log::log_level::all;
    switch (log_level_)
    {
    case log_level_mx::error:
        um_log_level = netlib::log::log_level::error;
        break;
    case log_level_mx::warning:
        um_log_level = netlib::log::log_level::warning;
        break;
    case log_level_mx::info:
        um_log_level = netlib::log::log_level::info;
        break;
    case log_level_mx::deb:
        um_log_level = netlib::log::log_level::debug;
        break;
    case log_level_mx::all:
        um_log_level = netlib::log::log_level::all;
        break;
    }

    // Keep pcap output disabled here (pass nullptr) to avoid extra deps.
    proxy_ = std::make_unique<proxy::socks_local_router>(
        um_log_level,
        logger::get_instance()->get_log_stream(),
        /*pcap*/ nullptr
    );

    if (!proxy_)
    {
        print_log(log_level_mx::info, "[ERROR]: Failed to create the SOCKS5 Local Router instance!"s);
        throw std::runtime_error("[ERROR]: Failed to create the SOCKS5 Local Router instance!");
    }

    // Wire destination-policy decider (optional gate).
    // Normalizes process name to match policy keys added from Program.cs (e.g., "rdcman", "mstsc").
    proxy_->set_redirect_decider([](const std::wstring& proc,
                                    const sockaddr* sa,
                                    int salen) -> bool
    {
        const std::wstring key = normalize_process_key(proc);
        return dip_should_redirect_for(key.c_str(), sa, salen) == 1;
    });

    print_log(log_level_mx::info, "SOCKS5 Local Router instance successfully created."s);
}

/**
 * @brief Destructor for socksify_unmanaged.
 * Cleans up Winsock resources.
 */
socksify_unmanaged::~socksify_unmanaged()
{
    WSACleanup();
}

/**
 * @brief Gets the singleton instance of socksify_unmanaged.
 * @param log_level The logging level to use (default: log_level_mx::all).
 * @return Pointer to the singleton instance.
 */
socksify_unmanaged* socksify_unmanaged::get_instance(const log_level_mx log_level)
{
    static socksify_unmanaged inst(log_level); // NOLINT(clang-diagnostic-exit-time-destructors)
    return &inst;
}

/**
 * @brief Starts the SOCKS5 local router and network filter.
 * @return True if started successfully, false otherwise.
 */
bool socksify_unmanaged::start() const
{
    using namespace std::string_literals;
    std::lock_guard lock(lock_->lock);

    if (!proxy_->start())
    {
        print_log(log_level_mx::info, "[ERROR]: Failed to start the SOCKS5 Local Router instance!"s);
        return false;
    }

    print_log(log_level_mx::info, "SOCKS5 Local Router instance started successfully."s);
    return true;
}

/**
 * @brief Stops the SOCKS5 local router and network filter.
 * @return True if stopped successfully, false otherwise.
 */
bool socksify_unmanaged::stop() const
{
    using namespace std::string_literals;
    std::lock_guard lock(lock_->lock);

    if (!proxy_)
    {
        print_log(log_level_mx::info,
            "[ERROR]: Failed to stop the SOCKS5 Local Router instance. Instance does not exist."s);
        return false;
    }

    if (!proxy_->stop())
    {
        print_log(log_level_mx::info, "[ERROR]: Failed to stop the SOCKS5 Local Router instance."s);
        return false;
    }

    print_log(log_level_mx::info, "SOCKS5 Local Router instance stopped successfully."s);

    return true;
}

/**
 * @brief Adds a SOCKS5 proxy to the gateway.
 */
LONG_PTR socksify_unmanaged::add_socks5_proxy(
    const std::string& endpoint,
    const supported_protocols_mx protocol,
    const bool start,
    const std::string& login,
    const std::string& password) const
{
    using namespace std::string_literals;
    std::optional<std::pair<std::string, std::string>> cred{ std::nullopt };

    if (!login.empty())
    {
        cred = std::make_pair(login, password);
    }

    proxy::socks_local_router::supported_protocols protocols = proxy::socks_local_router::supported_protocols::both;
    switch (protocol)
    {
    case supported_protocols_mx::tcp:
        protocols = proxy::socks_local_router::supported_protocols::tcp;
        break;
    case supported_protocols_mx::udp:
        protocols = proxy::socks_local_router::supported_protocols::udp;
        break;
    case supported_protocols_mx::both:
        protocols = proxy::socks_local_router::supported_protocols::both;
        break;
    }

    if (const auto result = proxy_->add_socks5_proxy(endpoint, protocols, cred, start); result)
    {
        return static_cast<LONG_PTR>(result.value());
    }

    return -1;
}

/**
 * @brief Associates a process name with a specific proxy.
 */
bool socksify_unmanaged::associate_process_name_to_proxy(const std::wstring& process_name,
    const LONG_PTR proxy_id) const
{
    return proxy_->associate_process_name_to_proxy(process_name, static_cast<size_t>(proxy_id));
}

/**
 * @brief Associates a process name to the exclusion list.
 */
bool socksify_unmanaged::exclude_process_name(const std::wstring& process_name) const
{
    return proxy_->exclude_process_name(process_name);
}

/**
 * @brief Sets the maximum number of log entries to keep.
 */
void socksify_unmanaged::set_log_limit(const uint32_t log_limit)
{
    logger::get_instance()->set_log_limit(log_limit);
}

/**
 * @brief Gets the current log limit.
 */
uint32_t socksify_unmanaged::get_log_limit()
{
    return logger::get_instance()->get_log_limit();
}

/**
 * @brief Sets the event handle to signal when log limit is exceeded.
 */
void socksify_unmanaged::set_log_event(HANDLE log_event)
{
    logger::get_instance()->set_log_event(log_event);
}

/**
 * @brief Reads and clears the log storage.
 */
log_storage_mx_t socksify_unmanaged::read_log()
{
    return logger::get_instance()->read_log().value_or(log_storage_mx_t{});
}

/**
 * @brief Static helper for printing log messages.
 */
void socksify_unmanaged::log_printer(const char* log)
{
    logger::get_instance()->log_printer(log);
}

/**
 * @brief Static helper for logging events.
 */
void socksify_unmanaged::log_event(const event_mx log)
{
    logger::get_instance()->log_event(log);
}

/**
 * @brief Prints a log message at the specified log level.
 */
void socksify_unmanaged::print_log(const log_level_mx level, const std::string& message) const
{
    // Inclusive threshold: log when level <= current level
    if (level <= log_level_)
    {
        log_printer(message.c_str());
    }
}

// ---------- per-process CIDR policy forwards ----------
bool socksify_unmanaged::include_process_dst_cidr(const std::wstring& process_name,
                                                  const std::string& cidr) const
{
    return dip_add_process(process_name.c_str(), cidr.c_str()) == 1;
}

bool socksify_unmanaged::remove_process_dst_cidr(const std::wstring& process_name,
                                                 const std::string& cidr) const
{
    return dip_remove_process(process_name.c_str(), cidr.c_str()) == 1;
}
// -----------------------------------------------------

#pragma managed(pop)
