#include "unmanaged.h"

struct mutex_impl
{
    std::mutex lock;
};

socksify_unmanaged::socksify_unmanaged(const log_level_mx log_level) :
    log_level_{log_level}
{
    using namespace std::string_literals;

    WSADATA wsa_data;

    if (constexpr auto version_requested = MAKEWORD(2, 2); ::WSAStartup(version_requested, &wsa_data) != 0)
    {
        print_log(log_level_mx::info, "WSAStartup failed with error\n");
    }

    lock_ = std::make_unique<mutex_impl>();

    print_log(log_level_mx::info, "Creating SOCKS5 Local Router instance..."s);

    auto um_log_level = netlib::log::log_level::all;

    switch (log_level_)
    {
    case log_level_mx::none:
        um_log_level = netlib::log::log_level::error;
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

    proxy_ = std::make_unique<proxy::socks_local_router>(um_log_level, logger::get_instance()->get_log_stream());

    if (!proxy_)
    {
        print_log(log_level_mx::info, "[ERROR]: Failed to create the SOCKS5 Local Router instance!"s);
        throw std::runtime_error("[ERROR]: Failed to create the SOCKS5 Local Router instance!");
    }

    print_log(log_level_mx::info, "SOCKS5 Local Router instance successfully created."s);
}

socksify_unmanaged::~socksify_unmanaged()
{
    WSACleanup();
}

socksify_unmanaged* socksify_unmanaged::get_instance(const log_level_mx log_level)
{
    static socksify_unmanaged inst(log_level); // NOLINT(clang-diagnostic-exit-time-destructors)
    return &inst;
}

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

    if (proxy_->stop())
    {
        print_log(log_level_mx::info, "[ERROR]: Failed to stop the SOCKS5 Local Router instance."s);
        return false;
    }

    print_log(log_level_mx::info, "SOCKS5 Local Router instance stopped successfully."s);

    return true;
}

LONG_PTR socksify_unmanaged::add_socks5_proxy(
    const std::string& endpoint,
    const supported_protocols_mx protocol,
    const bool start,
    const std::string& login,
    const std::string& password) const
{
    using namespace std::string_literals;
    std::optional<std::pair<std::string, std::string>> cred{std::nullopt};

    if (login != ""s)
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
    default:
        break;
    }

    if (const auto result = proxy_->add_socks5_proxy(endpoint, protocols, cred, start); result)
    {
        return static_cast<LONG_PTR>(result.value());
    }

    return -1;
}

bool socksify_unmanaged::associate_process_name_to_proxy(const std::wstring& process_name,
                                                         const LONG_PTR proxy_id) const
{
    return proxy_->associate_process_name_to_proxy(process_name, static_cast<size_t>(proxy_id));
}

// ReSharper disable once CppMemberFunctionMayBeStatic
void socksify_unmanaged::set_log_limit(const uint32_t log_limit)
{
    logger::get_instance()->set_log_limit(log_limit);
}

// ReSharper disable once CppMemberFunctionMayBeStatic
uint32_t socksify_unmanaged::get_log_limit()
{
    return logger::get_instance()->get_log_limit();
}

// ReSharper disable once CppMemberFunctionMayBeStatic
void socksify_unmanaged::set_log_event(HANDLE log_event)
{
    logger::get_instance()->set_log_event(log_event);
}

// ReSharper disable once CppMemberFunctionMayBeStatic
log_storage_mx_t socksify_unmanaged::read_log()
{
    return logger::get_instance()->read_log().value_or(log_storage_mx_t{});
}

void socksify_unmanaged::log_printer(const char* log)
{
    logger::get_instance()->log_printer(log);
}

void socksify_unmanaged::log_event(const event_mx log)
{
    logger::get_instance()->log_event(log);
}

void socksify_unmanaged::print_log(const log_level_mx level, const std::string& message) const
{
    if (level < log_level_)
    {
        log_printer(message.c_str());
    }
}
