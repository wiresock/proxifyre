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
/// Adds a SOCKS5 proxy to the gateway.
/// </summary>
/// <param name="endpoint">The proxy endpoint (IP:Port).</param>
/// <param name="username">The username for authentication.</param>
/// <param name="password">The password for authentication.</param>
/// <param name="protocols">The supported protocols.</param>
/// <param name="start">Whether to start the proxy immediately.</param>
/// <returns>A handle to the proxy instance, or -1 on failure.</returns>
IntPtr Socksifier::Socksifier::AddSocks5Proxy(String^ endpoint, String^ username, String^ password,
    SupportedProtocolsEnum protocols, const bool start)
{
    if (!unmanaged_ptr_)
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

    if (username != nullptr && password != nullptr)
    {
        return static_cast<IntPtr>(unmanaged_ptr_->add_socks5_proxy(
            msclr::interop::marshal_as<std::string>(endpoint),
            protocols_mx,
            start,
            msclr::interop::marshal_as<std::string>(username),
            msclr::interop::marshal_as<std::string>(password)
        ));
    }

    return static_cast<IntPtr>(unmanaged_ptr_->add_socks5_proxy(
        msclr::interop::marshal_as<std::string>(endpoint), protocols_mx, start));
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
/// <param name="excludedEntry">The process name to exclude.</param>.</param>
/// <returns>True if exclusion was successful, otherwise false.</returns>
bool Socksifier::Socksifier::ExcludeProcessName(String^ excludedEntry)
{
    if (!unmanaged_ptr_) {
        return false;
    }
    return unmanaged_ptr_->exclude_process_name(msclr::interop::marshal_as<std::wstring>(excludedEntry));
}