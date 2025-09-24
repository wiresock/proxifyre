#pragma once

class socksify_unmanaged;

namespace Socksifier
{
    public enum class LogLevel { Error = 0, Warning = 1, Info = 2, Debug = 4, All = 255 };
    public enum class SupportedProtocolsEnum { TCP, UDP, BOTH };

    public ref class LogEventArgs sealed : public System::EventArgs
    {
    public:
        LogEventArgs() {}
    };

    public ref class Socksifier sealed
    {
    private:
        static Socksifier^ instance_ = nullptr;

        socksify_unmanaged* unmanaged_ptr_{ nullptr };
        System::Threading::AutoResetEvent^ log_event_;
        System::Threading::Thread^ logging_thread_;
        volatile bool logger_thread_active_ = true;
        System::Int32 log_event_interval_ = 1000;

        // backing delegate for event (lets us null-check safely)
        System::EventHandler<LogEventArgs^>^ log_event_delegate_ = nullptr;

        void log_thread();
        void RaiseLogEvent();

        Socksifier(LogLevel log_level);

    public:
        !Socksifier();
        ~Socksifier();

        static Socksifier^ GetInstance(LogLevel log_level);
        static Socksifier^ GetInstance();

        event System::EventHandler<LogEventArgs^>^ LogEvent
        {
            void add(System::EventHandler<LogEventArgs^>^ value)
            {
                log_event_delegate_ = static_cast<System::EventHandler<LogEventArgs^>^>(
                    System::Delegate::Combine(log_event_delegate_, value));
            }
            void remove(System::EventHandler<LogEventArgs^>^ value)
            {
                log_event_delegate_ = static_cast<System::EventHandler<LogEventArgs^>^>(
                    System::Delegate::Remove(log_event_delegate_, value));
            }
            void raise(System::Object^ sender, LogEventArgs^ e)
            {
                auto d = log_event_delegate_;
                if (d != nullptr) d(sender, e);
            }
        };

        bool Start();
        bool Stop();

        System::IntPtr AddSocks5Proxy(System::String^ endpoint, System::String^ username, System::String^ password,
                                      SupportedProtocolsEnum protocols, bool start);
        bool AssociateProcessNameToProxy(System::String^ processName, System::IntPtr proxy);
        bool ExcludeProcessName(System::String^ excludedEntry);

        bool IncludeProcessDestinationCidr(System::String^ processName, System::String^ cidr);
        bool RemoveProcessDestinationCidr(System::String^ processName, System::String^ cidr);
        bool IncludeGlobalDestinationCidr(System::String^ cidr);
        bool RemoveGlobalDestinationCidr(System::String^ cidr);

        property System::Int32 LogEventInterval
        {
            System::Int32 get() { return log_event_interval_; }
            void set(System::Int32 value) { log_event_interval_ = value; }
        }
    };
}
