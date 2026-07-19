#include "pch.h"
#include "Socksifier.h"
#include "socksify_unmanaged.h"

// ReSharper disable CppInconsistentNaming

/// <summary>
/// Initializes a new instance of the <see cref="Socksifier"/> class with the specified log level.
/// Sets up the unmanaged core, log event, and starts the logging thread.
/// </summary>
/// <param name="log_level">The logging level to use.</param>
Socksifier::Socksifier::Socksifier(LogLevel log_level)
{
    // Default poll interval (ms). Without this the field is 0 and log_thread() busy-spins
    // (WaitOne(0)) until the managed side assigns LogEventInterval.
    log_event_interval_ = 1000;

    unmanaged_ptr_ = socksify_unmanaged::get_instance(static_cast<log_level_mx>(log_level));

    log_event_ = gcnew Threading::AutoResetEvent(false);
    unmanaged_ptr_->set_log_event(static_cast<HANDLE>(log_event_->SafeWaitHandle->DangerousGetHandle()));
    logging_thread_ = gcnew Threading::Thread(gcnew Threading::ThreadStart(this, &Socksifier::log_thread));
    logging_thread_->Start();
}

/// <summary>
/// Finalizer for the <see cref="Socksifier"/> class.
/// Ensures the logging thread is stopped and unmanaged resources are released.
/// </summary>
Socksifier::Socksifier::!Socksifier()
{
    // Set flag that we are going to exit
    logger_thread_active_ = false;

    if (log_event_ != nullptr)
        log_event_->Set();

    if (logging_thread_ != nullptr && logging_thread_->IsAlive)
        logging_thread_->Join();

    // Release unmanaged core
    if (unmanaged_ptr_)
    {
        [[maybe_unused]] auto result = unmanaged_ptr_->stop();
        unmanaged_ptr_ = nullptr;
    }

    // Dispose the AutoResetEvent
    if (log_event_ != nullptr)
    {
        log_event_->Close();
        log_event_ = nullptr;
    }
}

/// <summary>
/// Destructor for the <see cref="Socksifier"/> class.
/// Calls the finalizer to clean up resources.
/// </summary>
Socksifier::Socksifier::~Socksifier()
{
    this->!Socksifier();

    // Clear the singleton so a subsequent GetInstance() (e.g. on a service restart within the
    // same process) creates a fresh, usable instance instead of returning this disposed one
    // (whose unmanaged core is gone), which would silently disable proxying.
    msclr::lock l(Socksifier::typeid);
    if (instance_ == this)
        instance_ = nullptr;
}

/// <summary>
/// Thread procedure for processing and dispatching log events.
/// Waits for log events or interval, reads logs from the unmanaged core, and raises managed log events.
/// </summary>
void Socksifier::Socksifier::log_thread()
{
    do
    {
        log_event_->WaitOne(log_event_interval_);

        // Exit if thread was awakened to do it
        if (!logger_thread_active_)
            break;

        if (unmanaged_ptr_)
        {
            if (auto log = unmanaged_ptr_->read_log(); !log.empty())
            {
                auto managed_log_list = gcnew Collections::Generic::List<LogEntry^>;
                for (auto& [fst, snd] : log)
                {
                    if (std::holds_alternative<std::string>(snd))
                        managed_log_list->Add(gcnew LogEntry(fst, ProxyGatewayEvent::Message,
                            gcnew String(std::get<std::string>(snd).c_str())));
                    else
                    {
                        switch (std::get<event_mx>(snd).type)
                        {
                        case event_type_mx::connected:
                            managed_log_list->Add(gcnew LogEntry(fst, ProxyGatewayEvent::Connected, nullptr));
                            break;
                        case event_type_mx::disconnected:
                            managed_log_list->Add(gcnew LogEntry(fst, ProxyGatewayEvent::Disconnected, nullptr));
                            break;
                        case event_type_mx::address_error:
                            managed_log_list->Add(gcnew LogEntry(fst, ProxyGatewayEvent::AddressError, nullptr));
                            break;
                        default:
                            break;
                        }
                    }
                }

                LogEvent(this, gcnew LogEventArgs(managed_log_list));
            }
        }
    } while (logger_thread_active_);
}

/// <summary>
/// Gets the current log limit from the unmanaged core.
/// </summary>
/// <returns>The log limit.</returns>
UInt32 Socksifier::Socksifier::GetLogLimit()
{
    return unmanaged_ptr_->get_log_limit();
}

/// <summary>
/// Sets the log limit in the unmanaged core.
/// </summary>
/// <param name="value">The new log limit.</param>
void Socksifier::Socksifier::SetLogLimit(const UInt32 value)
{
    unmanaged_ptr_->set_log_limit(value);
}

/// <summary>
/// Gets the singleton instance of the <see cref="Socksifier"/> class with the specified log level.
/// </summary>
/// <param name="log_level">The logging level to use.</param>
/// <returns>The singleton instance.</returns>
Socksifier::Socksifier^ Socksifier::Socksifier::GetInstance(const LogLevel log_level)
{
    if (instance_ == nullptr)
    {
        msclr::lock l(Socksifier::typeid);

        if (instance_ == nullptr)
            instance_ = gcnew Socksifier(log_level);
    }

    return instance_;
}

/// <summary>
/// Gets the singleton instance of the <see cref="Socksifier"/> class with the default log level.
/// </summary>
/// <returns>The singleton instance.</returns>
Socksifier::Socksifier^ Socksifier::Socksifier::GetInstance()
{
    return GetInstance(LogLevel::All);
}

/// <summary>
/// Starts the proxy gateway via the unmanaged core.
/// </summary>
/// <returns>True if started successfully, otherwise false.</returns>
bool Socksifier::Socksifier::Start()
{
    if (unmanaged_ptr_)
        return unmanaged_ptr_->start();

    return false;
}

/// <summary>
/// Stops the proxy gateway via the unmanaged core.
/// </summary>
/// <returns>True if stopped successfully, otherwise false.</returns>
bool Socksifier::Socksifier::Stop()
{
    if (unmanaged_ptr_)
        return unmanaged_ptr_->stop();
    return false;
}

/// <summary>
/// Enables LAN traffic bypass.
/// When enabled, traffic to/from local network ranges will pass through without being proxied.
/// </summary>
void Socksifier::Socksifier::SetBypassLan()
{
    if (unmanaged_ptr_)
    {
        unmanaged_ptr_->set_bypass_lan();
    }
}

/// <summary>
/// Adds a SOCKS5 proxy to the gateway.
/// </summary>
/// <param name="endpoint">The proxy endpoint (IP:Port).</param>
/// <param name="username">The username for authentication.</param>
/// <param name="password">The password for authentication.</param>
/// <param name="protocols">The supported protocols.</param>
/// <param name="addressFamilies">The supported destination address families.</param>
/// <param name="start">Whether to start the proxy immediately.</param>
/// <returns>A handle to the proxy instance, or -1 on failure.</returns>
IntPtr Socksifier::Socksifier::AddSocks5Proxy(String^ endpoint, String^ username, String^ password,
    SupportedProtocolsEnum protocols, SupportedAddressFamiliesEnum addressFamilies, const bool start)
{
    return AddSocks5Proxy(
        endpoint,
        username,
        password,
        protocols,
        addressFamilies,
        Socks5TransportEnum::TCP,
        nullptr,
        nullptr,
        false,
        start);
}

/// <summary>
/// Adds a SOCKS5 proxy to the gateway with an explicit upstream transport.
/// </summary>
/// <param name="endpoint">The proxy endpoint (IP:Port).</param>
/// <param name="username">The username for authentication.</param>
/// <param name="password">The password for authentication.</param>
/// <param name="protocols">The supported protocols.</param>
/// <param name="addressFamilies">The supported destination address families.</param>
/// <param name="transport">The upstream transport.</param>
/// <param name="tlsServerName">TLS SNI and certificate validation name.</param>
/// <param name="tlsPinnedSha256">Optional SHA-256 certificate fingerprint pin.</param>
/// <param name="tlsAllowInvalidCertificate">Whether to bypass normal certificate validation.</param>
/// <param name="start">Whether to start the proxy immediately.</param>
/// <returns>A handle to the proxy instance, or -1 on failure.</returns>
IntPtr Socksifier::Socksifier::AddSocks5Proxy(String^ endpoint, String^ username, String^ password,
    SupportedProtocolsEnum protocols, SupportedAddressFamiliesEnum addressFamilies, Socks5TransportEnum transport,
    String^ tlsServerName, String^ tlsPinnedSha256, const bool tlsAllowInvalidCertificate, const bool start)
{
    if (!unmanaged_ptr_)
        return static_cast<IntPtr>(-1);

    const auto has_username = !String::IsNullOrEmpty(username);
    const auto has_password = !String::IsNullOrEmpty(password);
    if (has_username != has_password)
        return static_cast<IntPtr>(-1);

    auto protocols_mx = supported_protocols_mx::both;
    switch (protocols)
    {
    case SupportedProtocolsEnum::TCP:
        protocols_mx = supported_protocols_mx::tcp;
        break;
    case SupportedProtocolsEnum::UDP:
        protocols_mx = supported_protocols_mx::udp;
        break;
    default:
        break;
    }

    auto address_families_mx = supported_address_families_mx::both;
    switch (addressFamilies)
    {
    case SupportedAddressFamiliesEnum::IPv4:
        address_families_mx = supported_address_families_mx::ipv4;
        break;
    case SupportedAddressFamiliesEnum::IPv6:
        address_families_mx = supported_address_families_mx::ipv6;
        break;
    default:
        break;
    }

    auto transport_mx = socks5_transport_mx::tcp;
    switch (transport)
    {
    case Socks5TransportEnum::TLS:
        transport_mx = socks5_transport_mx::tls;
        break;
    default:
        break;
    }

    const auto tls_server_name_mx = tlsServerName != nullptr
        ? msclr::interop::marshal_as<std::string>(tlsServerName)
        : std::string{};
    const auto tls_pinned_sha256_mx = tlsPinnedSha256 != nullptr
        ? msclr::interop::marshal_as<std::string>(tlsPinnedSha256)
        : std::string{};

    if (has_username && has_password)
    {
        return static_cast<IntPtr>(unmanaged_ptr_->add_socks5_proxy(
            msclr::interop::marshal_as<std::string>(endpoint),
            protocols_mx,
            address_families_mx,
            start,
            msclr::interop::marshal_as<std::string>(username),
            msclr::interop::marshal_as<std::string>(password),
            transport_mx,
            tls_server_name_mx,
            tls_pinned_sha256_mx,
            tlsAllowInvalidCertificate
        ));
    }

    return static_cast<IntPtr>(unmanaged_ptr_->add_socks5_proxy(
        msclr::interop::marshal_as<std::string>(endpoint),
        protocols_mx,
        address_families_mx,
        start,
        "",
        "",
        transport_mx,
        tls_server_name_mx,
        tls_pinned_sha256_mx,
        tlsAllowInvalidCertificate));
}

/// <summary>
/// Adds a SOCKS5 proxy with both IPv4 and IPv6 destinations enabled.
/// </summary>
/// <param name="endpoint">The SOCKS5 proxy endpoint.</param>
/// <param name="username">The username for authentication.</param>
/// <param name="password">The password for authentication.</param>
/// <param name="protocols">The supported protocols.</param>
/// <param name="start">Whether to start the proxy immediately.</param>
/// <returns>A handle to the proxy instance, or -1 on failure.</returns>
IntPtr Socksifier::Socksifier::AddSocks5Proxy(String^ endpoint, String^ username, String^ password,
    SupportedProtocolsEnum protocols, const bool start)
{
    return AddSocks5Proxy(endpoint, username, password, protocols, SupportedAddressFamiliesEnum::BOTH, start);
}

/// <summary>
/// Associates a process name with a specific proxy instance.
/// </summary>
/// <param name="processName">The process name to associate.</param>
/// <param name="proxy">The proxy handle.</param>
/// <returns>True if association was successful, otherwise false.</returns>
bool Socksifier::Socksifier::AssociateProcessNameToProxy(String^ processName, IntPtr proxy)
{
    if (!unmanaged_ptr_)
        return false;
#if _WIN64
    return unmanaged_ptr_->associate_process_name_to_proxy(msclr::interop::marshal_as<std::wstring>(processName),
        proxy.ToInt64());
#else
    return unmanaged_ptr_->associate_process_name_to_proxy(msclr::interop::marshal_as<std::wstring>(processName),
        proxy.ToInt32());
#endif //_WIN64
}

/// <summary>
/// Excludes a process from being tunnelled by the gateway.
/// </summary>
/// <param name="excludedEntry">The process name to exclude.</param>
/// <returns>True if exclusion was successful, otherwise false.</returns>
bool Socksifier::Socksifier::ExcludeProcessName(String^ excludedEntry)
{
    if (!unmanaged_ptr_) {
        return false;
    }
    return unmanaged_ptr_->exclude_process_name(msclr::interop::marshal_as<std::wstring>(excludedEntry));
}
