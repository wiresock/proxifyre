#include "pch.h"
#include <msclr/lock.h>
#include "Socksifier.h"
#include <msclr/marshal_cppstd.h>

#include "socksify_unmanaged.h"
#include "policy/dest_inclusion_policy.h"

namespace Managed = Socksifier;

Managed::Socksifier::Socksifier(Managed::LogLevel log_level)
{
    unmanaged_ptr_ = socksify_unmanaged::get_instance_with_level(
        static_cast<log_level_mx>(static_cast<unsigned char>(static_cast<int>(log_level))));

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

    unsigned char code = 2; // BOTH
    if (protocols == Managed::SupportedProtocolsEnum::TCP) code = 0;
    else if (protocols == Managed::SupportedProtocolsEnum::UDP) code = 1;

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

bool Managed::Socksifier::IncludeProcessDestinationCidr(System::String^ processName, System::String^ cidr)
{
    if (!unmanaged_ptr_) return false;
    return unmanaged_ptr_->include_process_dst_cidr(
        msclr::interop::marshal_as<std::wstring>(processName),
        msclr::interop::marshal_as<std::string>(cidr));
}
bool Managed::Socksifier::RemoveProcessDestinationCidr(System::String^ processName, System::String^ cidr)
{
    if (!unmanaged_ptr_) return false;
    return unmanaged_ptr_->remove_process_dst_cidr(
        msclr::interop::marshal_as<std::wstring>(processName),
        msclr::interop::marshal_as<std::string>(cidr));
}
bool Managed::Socksifier::IncludeGlobalDestinationCidr(System::String^ cidr)
{
    if (!unmanaged_ptr_) return false;
    return unmanaged_ptr_->include_global_dst_cidr(
        msclr::interop::marshal_as<std::string>(cidr));
}
bool Managed::Socksifier::RemoveGlobalDestinationCidr(System::String^ cidr)
{
    if (!unmanaged_ptr_) return false;
    return unmanaged_ptr_->remove_global_dst_cidr(
        msclr::interop::marshal_as<std::string>(cidr));
}
