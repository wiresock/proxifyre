#include "pch.h"
#include "Socksifier.h"
#include "socksify_unmanaged.h"

// ReSharper disable CppInconsistentNaming

Socksifier::Socksifier::Socksifier(LogLevel log_level)
{
	unmanaged_ptr_ = socksify_unmanaged::get_instance(static_cast<log_level_mx>(log_level));

	log_event_ = gcnew Threading::AutoResetEvent(false);
	unmanaged_ptr_->set_log_event(static_cast<HANDLE>(log_event_->SafeWaitHandle->DangerousGetHandle()));
	logging_thread_ = gcnew Threading::Thread(gcnew Threading::ThreadStart(this, &Socksifier::log_thread));
	logging_thread_->Start();
}

Socksifier::Socksifier::!Socksifier()
{
	// Set flag that we are going to exit
	logger_thread_active_ = false;

	log_event_->Set();

	if (logging_thread_->IsAlive)
		logging_thread_->Join();

	// Release unmanaged core
	if (unmanaged_ptr_)
	{
		[[maybe_unused]] auto result = unmanaged_ptr_->stop();
		unmanaged_ptr_ = nullptr;
	}
}

Socksifier::Socksifier::~Socksifier()
{
	this->!Socksifier();
}

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
	}
	while (logger_thread_active_);
}

UInt32 Socksifier::Socksifier::GetLogLimit()
{
	return unmanaged_ptr_->get_log_limit();
}

void Socksifier::Socksifier::SetLogLimit(const UInt32 value)
{
	unmanaged_ptr_->set_log_limit(value);
}

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

Socksifier::Socksifier^ Socksifier::Socksifier::GetInstance()
{
	return GetInstance(LogLevel::All);
}

bool Socksifier::Socksifier::Start()
{
	if (unmanaged_ptr_)
		return unmanaged_ptr_->start();

	return false;
}

bool Socksifier::Socksifier::Stop()
{
	if (unmanaged_ptr_)
		return unmanaged_ptr_->stop();
	return false;
}

IntPtr Socksifier::Socksifier::AddSocks5Proxy(String^ endpoint, String^ username, String^ password, SupportedProtocolsEnum protocols, const bool start)
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
