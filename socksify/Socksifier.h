// ReSharper disable CppInconsistentNaming
#pragma once

using namespace System;

class socksify_unmanaged;

namespace Socksifier
{
	public enum class LogLevel
	{
		None = 0,
		Info = 1,
		Deb = 2,
		All = 3,
	};

	public enum class ProxyGatewayStatus
	{
		Stopped,
		Connected,
		Disconnected,
		Error
	};

	public enum class ProxyGatewayEvent
	{
		Connected,
		Disconnected,
		Message,
		AddressError,
		NdisError
	};

	public ref class LogEntry sealed
	{
		long long time_stamp_;
		ProxyGatewayEvent tunnel_event_;
		String^ description_;
		UInt64 data_;

	public:
		LogEntry(long long time_stamp, ProxyGatewayEvent event, String^ description)
			: time_stamp_(time_stamp),
			  tunnel_event_(event),
			  description_(description)
		{
		}

		LogEntry(long long time_stamp, ProxyGatewayEvent event, UInt64 data)
			: time_stamp_(time_stamp),
			  tunnel_event_(event),
			  data_(data)
		{
		}

		property long long TimeStamp
		{
			long long get() { return time_stamp_; }
		}

		property ProxyGatewayEvent Event
		{
			ProxyGatewayEvent get() { return tunnel_event_; }
		}

		property String^ Description
		{
			String^ get() { return description_; }
		}

		property UInt64 Data
		{
			UInt64 get() { return data_; }
		}
	};

	public ref class LogEventArgs sealed : public EventArgs
	{
		Collections::Generic::List<LogEntry^>^ log_;

	public:
		explicit LogEventArgs(Collections::Generic::List<LogEntry^>^ log)
			: log_(log)
		{
		}

		property Collections::Generic::List<LogEntry^>^ Log
		{
			Collections::Generic::List<LogEntry^>^ get() { return log_; }
		}
	};


	public ref class Socksifier sealed
	{
		Socksifier(LogLevel log_level);

	public:
		!Socksifier();
		~Socksifier();

		static Socksifier^ Socksifier::GetInstance(LogLevel log_level);
		static Socksifier^ Socksifier::GetInstance();

		event System::EventHandler<LogEventArgs^>^ LogEvent;

		bool Start();
		bool Stop();
		IntPtr AddSocks5Proxy(String^ endpoint, String^ username, String^ password, bool start);
		bool AssociateProcessNameToProxy(String^ processName, IntPtr proxy);

		property Int32 LogEventInterval
		{
			Int32 get() { return log_event_interval_; }
			void set(const Int32 value) { log_event_interval_ = value; }
		}

		property UInt32 LogLimit
		{
			UInt32 get() { return GetLogLimit(); }
			void set(const UInt32 value) { SetLogLimit(value); };
		}

	private:
		void log_thread();
		UInt32 GetLogLimit();
		void SetLogLimit(UInt32 value);

		static Socksifier^ instance_;
		socksify_unmanaged* unmanaged_ptr_{nullptr};

		Threading::AutoResetEvent^ log_event_;
		Threading::Thread^ logging_thread_;
		volatile bool logger_thread_active_ = true;
		// Specifies interval in milliseconds to trigger log_event_ (if not triggered by log size)
		Int32 log_event_interval_;
	};
}
