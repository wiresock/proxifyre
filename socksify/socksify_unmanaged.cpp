#include "unmanaged.h"

/**
 * @brief Platform-specific mutex implementation for thread safety.
 */
struct mutex_impl
{
    std::mutex lock;
};

/**
 * @brief Constructs the socksify_unmanaged singleton instance.
 * Initializes Winsock, logging, and the SOCKS5 local router.
 * @param log_level The logging level to use for the proxy gateway.
 * @throws std::runtime_error if WSAStartup or pcap log file creation fails.
 */
socksify_unmanaged::socksify_unmanaged(const log_level_mx log_level) :
    log_level_{ log_level }
{
    using namespace std::string_literals;

    WSADATA wsa_data;

    constexpr auto version_requested = MAKEWORD(2, 2);
    if (const auto wsa_error = ::WSAStartup(version_requested, &wsa_data); wsa_error != 0)
    {
        // WSAStartup returns the error code directly. Winsock is unusable when
        // it fails, so fail fast (as documented) instead of continuing with a
        // broken socket subsystem and producing confusing follow-on errors.
        const auto message = "WSAStartup failed with error "s + std::to_string(wsa_error);
        print_log(log_level_mx::error, message);
        throw std::runtime_error(message);
    }

    // WSAStartup succeeded. Because a constructor that exits via an exception
    // does not run the destructor, the remainder of construction must release
    // the Winsock reference acquired above if it throws (e.g. the pcap log file
    // fails to open, or router construction throws). This guard calls
    // WSACleanup() on such a failure and is disengaged once construction
    // completes, leaving the matching cleanup to the destructor.
    struct winsock_cleanup_guard
    {
        winsock_cleanup_guard() noexcept = default;

        explicit winsock_cleanup_guard(const bool engaged) noexcept
            : engaged(engaged)
        {
        }

        ~winsock_cleanup_guard() noexcept
        {
            reset();
        }

        winsock_cleanup_guard(const winsock_cleanup_guard&) = delete;
        winsock_cleanup_guard& operator=(const winsock_cleanup_guard&) = delete;

        winsock_cleanup_guard(winsock_cleanup_guard&& other) noexcept
            : engaged(std::exchange(other.engaged, false))
        {
        }

        winsock_cleanup_guard& operator=(winsock_cleanup_guard&& other) noexcept
        {
            if (this != &other)
            {
                reset();
                engaged = std::exchange(other.engaged, false);
            }

            return *this;
        }

        void release() noexcept
        {
            engaged = false;
        }

        void reset() noexcept
        {
            if (engaged)
            {
                engaged = false;
                ::WSACleanup();
            }
        }

        bool engaged = true;
    } winsock_guard;

    lock_ = std::make_unique<mutex_impl>();

    print_log(log_level_mx::info, "Creating SOCKS5 Local Router instance..."s);

    auto um_log_level = netlib::log::log_level::all;

    switch (log_level_)
    {
    case log_level_mx::error:
        um_log_level = netlib::log::log_level::error;
        set_global_log_verbosity(netlib::log::log_verbosity::level);
        break;
    case log_level_mx::warning:
        um_log_level = netlib::log::log_level::warning;
        set_global_log_verbosity(netlib::log::log_verbosity::level);
        break;
    case log_level_mx::info:
        um_log_level = netlib::log::log_level::info;
        set_global_log_verbosity(netlib::log::log_verbosity::logger | netlib::log::log_verbosity::level);
        break;
    case log_level_mx::deb:
        um_log_level = netlib::log::log_level::debug;
        set_global_log_verbosity(netlib::log::log_verbosity::thread | netlib::log::log_verbosity::path | netlib::log::log_verbosity::level);
        break;
    case log_level_mx::all:
        um_log_level = netlib::log::log_level::all;
        set_global_log_verbosity(netlib::log::log_verbosity::all);
        break;
    }

    // Conditionally open the pcap log file if the log level is debug or higher
    if (um_log_level >= netlib::log::log_level::debug) {
        pcap_log_file_.emplace("proxifyre_log.pcap", std::ios::binary | std::ios::out);
        // Check if the optional contains a value and then access it to call is_open()
        if (!pcap_log_file_->is_open()) {
            throw std::runtime_error("Failed to open pcap log file.");
        }
    }

    proxy_ = std::make_unique<proxy::socks_local_router>(
        um_log_level,
        logger::get_instance()->get_log_stream(),
        pcap_log_file_ ?
        std::shared_ptr<std::ostream>(&pcap_log_file_.value(), [](std::ostream*) {
            // No-op deleter - the stream is owned by the optional member variable
            }) : nullptr
    );

    if (!proxy_)
    {
        print_log(log_level_mx::error, "Failed to create the SOCKS5 Local Router instance!"s);
        throw std::runtime_error("Failed to create the SOCKS5 Local Router instance!");
    }

    print_log(log_level_mx::info, "SOCKS5 Local Router instance successfully created."s);

    // Construction succeeded; hand Winsock cleanup back to the destructor.
    winsock_guard.engaged = false;
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
    std::scoped_lock lock(lock_->lock);

    if (!proxy_->start())
    {
        print_log(log_level_mx::error, "Failed to start the SOCKS5 Local Router instance!"s);
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
    std::scoped_lock lock(lock_->lock);

    if (!proxy_)
    {
        print_log(log_level_mx::error,
            "Failed to stop the SOCKS5 Local Router instance. Instance does not exist."s);
        return false;
    }

    // socks_local_router::stop() returns true on success and false only when
    // the router was already inactive (an idempotent no-op, e.g. when Dispose
    // runs after an explicit Stop()). That is not a failure, so log it at info
    // level to avoid noisy error logs while preserving the documented false
    // return for callers that distinguish "stopped now" from "was not active".
    if (!proxy_->stop())
    {
        print_log(log_level_mx::info,
            "SOCKS5 Local Router instance was already stopped (not active)."s);
        return false;
    }

    print_log(log_level_mx::info, "SOCKS5 Local Router instance stopped successfully."s);

    return true;
}

/**
 * @brief Enables LAN traffic bypass.
 * When enabled, traffic to/from local network ranges will pass through without being proxied.
 */
void socksify_unmanaged::set_bypass_lan() const
{
    if (proxy_)
    {
        proxy_->set_bypass_lan();
    }
}

/**
 * @brief Adds a SOCKS5 proxy to the gateway.
 * @param endpoint The proxy endpoint in "IP:Port" format.
 * @param protocol The supported protocol(s) for the proxy.
 * @param address_family The supported destination address family/families.
 * @param start Whether to start the proxy immediately.
 * @param login Optional username for authentication.
 * @param password Optional password for authentication.
 * @return A handle (LONG_PTR) to the proxy instance, or -1 on failure.
 */
LONG_PTR socksify_unmanaged::add_socks5_proxy(
    const std::string& endpoint,
    const supported_protocols_mx protocol,
    const supported_address_families_mx address_family,
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

    proxy::socks_local_router::supported_address_families address_families =
        proxy::socks_local_router::supported_address_families::all;
    switch (address_family)
    {
    case supported_address_families_mx::ipv4:
        address_families = proxy::socks_local_router::supported_address_families::ipv4;
        break;
    case supported_address_families_mx::ipv6:
        address_families = proxy::socks_local_router::supported_address_families::ipv6;
        break;
    case supported_address_families_mx::both:
        address_families = proxy::socks_local_router::supported_address_families::all;
        break;
    }

    if (const auto result = proxy_->add_socks5_proxy(endpoint, protocols, cred, address_families, start); result)
    {
        return static_cast<LONG_PTR>(result.value());
    }

    return -1;
}

/**
 * @brief Adds a SOCKS5 proxy with both IPv4 and IPv6 destinations enabled.
 */
LONG_PTR socksify_unmanaged::add_socks5_proxy(
    const std::string& endpoint,
    const supported_protocols_mx protocol,
    const bool start,
    const std::string& login,
    const std::string& password) const
{
    return add_socks5_proxy(endpoint, protocol, supported_address_families_mx::both, start, login, password);
}

/**
 * @brief Associates a process name with a specific proxy.
 * @param process_name The process name to associate.
 * @param proxy_id The handle of the proxy to associate with.
 * @return True if association was successful, false otherwise.
 */
bool socksify_unmanaged::associate_process_name_to_proxy(const std::wstring& process_name,
    const LONG_PTR proxy_id) const
{
    return proxy_->associate_process_name_to_proxy(process_name, static_cast<size_t>(proxy_id));
}

/**
 * @brief Associates a process name to the exclusion list.
 * @param process_name The process name to associate.
 * @return True if addition was successful, false otherwise.
 */
bool socksify_unmanaged::exclude_process_name(const std::wstring& process_name) const
{
    return proxy_->exclude_process_name(process_name);
}

/**
 * @brief Sets the maximum number of log entries to keep.
 * @param log_limit The new log limit.
 */
 // ReSharper disable once CppMemberFunctionMayBeStatic
void socksify_unmanaged::set_log_limit(const uint32_t log_limit)
{
    logger::get_instance()->set_log_limit(log_limit);
}

/**
 * @brief Gets the current log limit.
 * @return The log limit.
 */
 // ReSharper disable once CppMemberFunctionMayBeStatic
uint32_t socksify_unmanaged::get_log_limit()
{
    return logger::get_instance()->get_log_limit();
}

/**
 * @brief Sets the event handle to signal when log limit is exceeded.
 * @param log_event The Windows event handle.
 */
 // ReSharper disable once CppMemberFunctionMayBeStatic
void socksify_unmanaged::set_log_event(HANDLE log_event)
{
    logger::get_instance()->set_log_event(log_event);
}

/**
 * @brief Reads and clears the log storage.
 * @return The log storage as a log_storage_mx_t object.
 */
 // ReSharper disable once CppMemberFunctionMayBeStatic
log_storage_mx_t socksify_unmanaged::read_log()
{
    return logger::get_instance()->read_log().value_or(log_storage_mx_t{});
}

/**
 * @brief Static helper for printing log messages.
 * @param log The message to log.
 */
void socksify_unmanaged::log_printer(const char* log)
{
    logger::get_instance()->log_printer(log);
}

/**
 * @brief Static helper for logging events.
 * @param log The event to log.
 */
void socksify_unmanaged::log_event(const event_mx log)
{
    logger::get_instance()->log_event(log);
}

/**
 * @brief Prints a log message at the specified log level.
 * @param level The log level.
 * @param message The message to print.
 */
void socksify_unmanaged::print_log(const log_level_mx level, const std::string& message) const
{
    // Emit the message when its severity is at or below the configured
    // verbosity threshold. log_level_mx orders severities from error (0) to
    // all (255), so a message must be printed when level <= log_level_. The
    // previous strict comparison dropped messages whose level equalled the
    // threshold, e.g. error messages were never shown at the "error" level and
    // info messages were never shown at the "info" level.
    if (level <= log_level_)
    {
        log_printer(message.c_str());
    }
}
