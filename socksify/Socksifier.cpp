#include "pch.h"
#include <msclr/lock.h>
#include "Socksifier.h"
#include <msclr/marshal_cppstd.h>

// Forward-declare the unmanaged enum/types so the included header sees them.
enum class log_level_mx : unsigned char;
enum class supported_protocols_mx : unsigned char;
struct event_mx;

#include "socksify_unmanaged.h"
#include "policy/dest_inclusion_policy.h"

namespace Managed = Socksifier;

Managed::Socksifier::Socksifier(Managed::LogLevel /*log_level*/)
{
    // Use the original API you reverted to:
    unmanaged_ptr_ = socksify_unmanaged::get_instance();

    log_event_ = gcnew System::Threading::AutoResetEvent(false);
    logging_thread_ = gcnew System::Threading::Thread(
        gcnew System::Threading::ThreadStart(this, &Managed::Socksifier::log_thread));
    logging_thread_->Start();
}

Managed::Socksifier::!Socksifier()
{
    logger_thread_active_ = false;
    if (log_event_) log_event_->Set();
    if (logging_thread_ && logging_thread_->IsAlive) logging_thread_->Join();

    if (unmanaged_ptr_) { unmanaged_ptr_->stop(); unmanaged_ptr_ = nullptr; }
    if (log_event_) { log_event_->Close(); log_event_ = nullptr; }
}

Managed::Socksifier::~Socksifier()
{
    this->!Socksifier();
}

void Managed::Socksifier::RaiseLogEvent()
{
    LogEvent(this, gcnew LogEventArgs());
}

void Managed::Socksifier::log_thread()
{
    while (logger_thread_active_)
    {
        log_event_->WaitOne(log_event_interval_);
        if (!logger_thread_active_) break;
        RaiseLogEvent();
    }
}

Managed::Socksifier^ Managed::Socksifier::GetInstance(Managed::LogLevel log_level)
{
    if (instance_ == nullptr)
    {
        msclr::lock l(Managed::Socksifier::typeid);
        if (instance_ == nullptr) instance_ = gcnew Managed::Socksifier(log_level);
    }
    return instance_;
}

Managed::Socksifier^ Managed::Socksifier::GetInstance()
{
    if (instance_ == nullptr)
    {
        msclr::lock l(Managed::Socksifier::typeid);
        if (instance_ == nullptr) instance_ = gcnew Managed::Socksifier(Managed::LogLevel::Info);
    }
    return instance_;
}

bool Managed::Socksifier::Start() { return unmanaged_ptr_ ? unmanaged_ptr_->start() : false; }
bool Managed::Socksifier::Stop()  { return unmanaged_ptr_ ? unmanaged_ptr_->stop()  : false; }

System::IntPtr Managed::Socksifier::AddSocks5Proxy(System::String^ endpoint, System::String^ username,
    System::String^ password, Managed::SupportedProtocolsEnum protocols, const bool start)
{
    if (!unmanaged_ptr_) return System::IntPtr(-1);

    // Map managed enum to the unmanaged "mx" enum underlying value (unsigned char).
    unsigned char code = 2; // BOTH
    if (protocols == Managed::SupportedProtocolsEnum::TCP) code = 0;
    else if (protocols == Managed::SupportedProtocolsEnum::UDP) code = 1;

    // We only need the name for the cast; forward-declare above keeps compile happy.
    auto mx = static_cast<supported_protocols_mx>(code);

    if (username != nullptr && password != nullptr)
        return System::IntPtr(unmanaged_ptr_->add_socks5_proxy(
            msclr::interop::marshal_as<std::string>(endpoint), mx, start,
            msclr::interop::marshal_as<std::string>(username),
            msclr::interop::marshal_as<std::string>(password)));

    return System::IntPtr(unmanaged_ptr_->add_socks5_proxy(
        msclr::interop::marshal_as<std::string>(endpoint), mx, start));
}

bool Managed::Socksifier::AssociateProcessNameToProxy(System::String^ processName, System::IntPtr proxy)
{
    if (!unmanaged_ptr_) return false;
#if _WIN64
    return unmanaged_ptr_->associate_process_name_to_proxy(
        msclr::interop::marshal_as<std::wstring>(processName), proxy.ToInt64());
#else
    return unmanaged_ptr_->associate_process_name_to_proxy(
        msclr::interop::marshal_as<std::wstring>(processName), proxy.ToInt32());
#endif
}

bool Managed::Socksifier::ExcludeProcessName(System::String^ excludedEntry)
{
    if (!unmanaged_ptr_) return false;
    return unmanaged_ptr_->exclude_process_name(msclr::interop::marshal_as<std::wstring>(excludedEntry));
}

// ---------- CIDR inclusion calls the tiny C-exports directly ----------
bool Managed::Socksifier::IncludeProcessDestinationCidr(System::String^ processName, System::String^ cidr)
{
    if (processName == nullptr || cidr == nullptr) return false;
    auto wproc = msclr::interop::marshal_as<std::wstring>(processName);
    auto scidr = msclr::interop::marshal_as<std::string>(cidr);
    return dip_add_process(wproc.c_str(), scidr.c_str()) == 1;
}

bool Managed::Socksifier::RemoveProcessDestinationCidr(System::String^ processName, System::String^ cidr)
{
    if (processName == nullptr || cidr == nullptr) return false;
    auto wproc = msclr::interop::marshal_as<std::wstring>(processName);
    auto scidr = msclr::interop::marshal_as<std::string>(cidr);
    return dip_remove_process(wproc.c_str(), scidr.c_str()) == 1;
}

bool Managed::Socksifier::IncludeGlobalDestinationCidr(System::String^ cidr)
{
    if (cidr == nullptr) return false;
    auto scidr = msclr::interop::marshal_as<std::string>(cidr);
    return dip_add_global(scidr.c_str()) == 1;
}

bool Managed::Socksifier::RemoveGlobalDestinationCidr(System::String^ cidr)
{
    if (cidr == nullptr) return false;
    auto scidr = msclr::interop::marshal_as<std::string>(cidr);
    return dip_remove_global(scidr.c_str()) == 1;
}
