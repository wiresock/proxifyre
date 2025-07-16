// ReSharper disable CppInconsistentNaming
#pragma once

using namespace System;

/// <summary>
/// Forward declaration for the unmanaged implementation of the Socksifier logic.
/// </summary>
class socksify_unmanaged;

namespace Socksifier
{
    /// <summary>
    /// Specifies the logging level for the Socksifier component.
    /// </summary>
    /// <remarks>
    /// The log levels are bitmask values. Higher values include all lower levels.
    /// </remarks>
    public enum class LogLevel
    {
        /// <summary>
        /// Error messages only.
        /// </summary>
        Error = 0,
        /// <summary>
        /// Warning and error messages.
        /// </summary>
        Warning = 1,
        /// <summary>
        /// Informational, warning, and error messages.
        /// </summary>
        Info = 2,
        /// <summary>
        /// Debug, informational, warning, and error messages.
        /// </summary>
        Debug = 4,
        /// <summary>
        /// All log messages.
        /// </summary>
        All = 255,
    };

    /// <summary>
    /// Represents the status of the proxy gateway.
    /// </summary>
    public enum class ProxyGatewayStatus
    {
        /// <summary>The gateway is stopped.</summary>
        Stopped,
        /// <summary>The gateway is connected.</summary>
        Connected,
        /// <summary>The gateway is disconnected.</summary>
        Disconnected,
        /// <summary>An error has occurred in the gateway.</summary>
        Error
    };

    /// <summary>
    /// Enumerates the types of events that can occur in the proxy gateway.
    /// </summary>
    public enum class ProxyGatewayEvent
    {
        /// <summary>The gateway has connected.</summary>
        Connected,
        /// <summary>The gateway has disconnected.</summary>
        Disconnected,
        /// <summary>A message event.</summary>
        Message,
        /// <summary>An address error event.</summary>
        AddressError,
        /// <summary>An NDIS error event.</summary>
        NdisError
    };

    /// <summary>
    /// Specifies the supported protocols for proxying.
    /// </summary>
    public enum class SupportedProtocolsEnum
    {
        /// <summary>TCP protocol only.</summary>
        TCP,
        /// <summary>UDP protocol only.</summary>
        UDP,
        /// <summary>Both TCP and UDP protocols.</summary>
        BOTH
    };

    /// <summary>
    /// Represents a single log entry for Socksifier events.
    /// </summary>
    public ref class LogEntry sealed
    {
        long long time_stamp_;
        ProxyGatewayEvent tunnel_event_;
        String^ description_;
        UInt64 data_;

    public:
        /// <summary>
        /// Initializes a new instance of the <see cref="LogEntry"/> class with a description.
        /// </summary>
        /// <param name="time_stamp">The timestamp of the log entry.</param>
        /// <param name="event">The event type.</param>
        /// <param name="description">The event description.</param>
        LogEntry(const long long time_stamp, const ProxyGatewayEvent event, String^ description)
            : time_stamp_(time_stamp),
            tunnel_event_(event),
            description_(description)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="LogEntry"/> class with data.
        /// </summary>
        /// <param name="time_stamp">The timestamp of the log entry.</param>
        /// <param name="event">The event type.</param>
        /// <param name="data">The event data.</param>
        LogEntry(const long long time_stamp, const ProxyGatewayEvent event, const UInt64 data)
            : time_stamp_(time_stamp),
            tunnel_event_(event),
            data_(data)
        {
        }

        /// <summary>
        /// Gets the timestamp of the log entry.
        /// </summary>
        property long long TimeStamp
        {
            long long get() { return time_stamp_; }
        }

        /// <summary>
        /// Gets the event type of the log entry.
        /// </summary>
        property ProxyGatewayEvent Event
        {
            ProxyGatewayEvent get() { return tunnel_event_; }
        }

        /// <summary>
        /// Gets the description of the log entry.
        /// </summary>
        property String^ Description
        {
            String ^ get() { return description_; }
        }

        /// <summary>
        /// Gets the data associated with the log entry.
        /// </summary>
        property UInt64 Data
        {
            UInt64 get() { return data_; }
        }
    };

    /// <summary>
    /// Provides data for log event notifications.
    /// </summary>
    public ref class LogEventArgs sealed : public EventArgs
    {
        Collections::Generic::List<LogEntry^>^ log_;

    public:
        /// <summary>
        /// Initializes a new instance of the <see cref="LogEventArgs"/> class.
        /// </summary>
        /// <param name="log">The list of log entries.</param>
        explicit LogEventArgs(Collections::Generic::List<LogEntry^>^ log)
            : log_(log)
        {
        }

        /// <summary>
        /// Gets the list of log entries.
        /// </summary>
        property Collections::Generic::List<LogEntry^>^ Log
        {
            Collections::Generic::List<LogEntry^> ^ get() { return log_; }
        }
    };

    /// <summary>
    /// Main entry point for managing SOCKS proxying and process association.
    /// </summary>
    public ref class Socksifier sealed
    {
        /// <summary>
        /// Private constructor for singleton pattern.
        /// </summary>
        /// <param name="log_level">The logging level to use.</param>
        Socksifier(LogLevel log_level);

    public:
        /// <summary>
        /// Finalizer for releasing unmanaged resources.
        /// </summary>
        !Socksifier();

        /// <summary>
        /// Destructor for releasing managed and unmanaged resources.
        /// </summary>
        ~Socksifier();

        /// <summary>
        /// Gets the singleton instance of the Socksifier with a specified log level.
        /// </summary>
        /// <param name="log_level">The logging level to use.</param>
        /// <returns>The singleton instance.</returns>
        static Socksifier^ Socksifier::GetInstance(LogLevel log_level);

        /// <summary>
        /// Gets the singleton instance of the Socksifier.
        /// </summary>
        /// <returns>The singleton instance.</returns>
        static Socksifier^ Socksifier::GetInstance();

        /// <summary>
        /// Occurs when a log event is available.
        /// </summary>
        event EventHandler<LogEventArgs^>^ LogEvent;

        /// <summary>
        /// Starts the proxy gateway.
        /// </summary>
        /// <returns>True if started successfully, otherwise false.</returns>
        bool Start();

        /// <summary>
        /// Stops the proxy gateway.
        /// </summary>
        /// <returns>True if stopped successfully, otherwise false.</returns>
        bool Stop();

        /// <summary>
        /// Adds a SOCKS5 proxy to the gateway.
        /// </summary>
        /// <param name="endpoint">The proxy endpoint (IP:Port).</param>
        /// <param name="username">The username for authentication.</param>
        /// <param name="password">The password for authentication.</param>
        /// <param name="protocols">The supported protocols.</param>
        /// <param name="start">Whether to start the proxy immediately.</param>
        /// <returns>A handle to the proxy instance.</returns>
        IntPtr AddSocks5Proxy(String^ endpoint, String^ username, String^ password, SupportedProtocolsEnum protocols,
            bool start);

        /// <summary>
        /// Associates a process name with a specific proxy.
        /// </summary>
        /// <param name="processName">The process name to associate.</param>
        /// <param name="proxy">The proxy handle.</param>
        /// <returns>True if association was successful, otherwise false.</returns>
        bool AssociateProcessNameToProxy(String^ processName, IntPtr proxy);

        /// <summary>
        /// Gets or sets the interval (in milliseconds) for log event notifications.
        /// </summary>
        property Int32 LogEventInterval
        {
            Int32 get() { return log_event_interval_; }
            void set(const Int32 value) { log_event_interval_ = value; }
        }

        /// <summary>
        /// Gets or sets the maximum number of log entries to keep.
        /// </summary>
        property UInt32 LogLimit
        {
            UInt32 get() { return GetLogLimit(); }
            void set(const UInt32 value) { SetLogLimit(value); };
        }

    private:
        /// <summary>
        /// Thread procedure for processing and dispatching log events.
        /// </summary>
        void log_thread();

        /// <summary>
        /// Gets the current log limit.
        /// </summary>
        /// <returns>The log limit.</returns>
        UInt32 GetLogLimit();

        /// <summary>
        /// Sets the log limit.
        /// </summary>
        /// <param name="value">The new log limit.</param>
        void SetLogLimit(UInt32 value);

        /// <summary>
        /// Singleton instance of the Socksifier.
        /// </summary>
        static Socksifier^ instance_;

        /// <summary>
        /// Pointer to the unmanaged implementation.
        /// </summary>
        socksify_unmanaged* unmanaged_ptr_{ nullptr };

        /// <summary>
        /// Event used to signal log events to the logging thread.
        /// </summary>
        Threading::AutoResetEvent^ log_event_;

        /// <summary>
        /// The thread responsible for logging.
        /// </summary>
        Threading::Thread^ logging_thread_;

        /// <summary>
        /// Indicates whether the logger thread is active.
        /// </summary>
        volatile bool logger_thread_active_ = true;

        /// <summary>
        /// Specifies interval in milliseconds to trigger log_event_ (if not triggered by log size).
        /// </summary>
        Int32 log_event_interval_;
    };
}