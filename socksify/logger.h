#pragma once
class logger
{
	static constexpr auto default_log_limit = 100;
	log_storage_mx_t log_storage_;
	std::mutex log_storage_lock_;
	size_t log_limit_{default_log_limit};
	HANDLE log_event_{nullptr};

	logger() = default;

public:
	static logger* get_instance()
	{
		static logger inst; // NOLINT(clang-diagnostic-exit-time-destructors)
		return &inst;
	}

	void log_printer(const char* log)
	{
		using namespace std::chrono;
		const auto ms = duration_cast<milliseconds>(
			system_clock::now().time_since_epoch()
		);

		std::lock_guard<std::mutex> lock(log_storage_lock_);

		log_storage_.emplace_back(ms.count(), log);

		if (log_event_ && log_storage_.size() > log_limit_)
			::SetEvent(log_event_);
	}

	void log_event(const event_mx log_event)
	{
		using namespace std::chrono;

		switch (log_event.type)
		{
		case event_type_mx::address_error:
		case event_type_mx::connected:
		case event_type_mx::disconnected:
			{
				const auto ms = duration_cast<milliseconds>(
					system_clock::now().time_since_epoch()
				);

				std::lock_guard<std::mutex> lock(log_storage_lock_);

				log_storage_.emplace_back(ms.count(), log_event);
			}
			break;
		}

		if (log_event_ && log_storage_.size() > log_limit_)
			::SetEvent(log_event_);
	}

	std::optional<log_storage_mx_t> read_log()
	{
		using namespace std::chrono;

		std::lock_guard<std::mutex> lock(log_storage_lock_);

		return log_storage_.empty() ? std::nullopt : std::make_optional(std::move(log_storage_));
	}

	size_t size()
	{
		std::lock_guard<std::mutex> lock(log_storage_lock_);
		return log_storage_.size();
	}

	void set_log_limit(const uint32_t log_limit)
	{
		log_limit_ = log_limit;
	}

	[[nodiscard]] uint32_t get_log_limit() const
	{
		return static_cast<uint32_t>(log_limit_);
	}

	void set_log_event(HANDLE log_event)
	{
		log_event_ = log_event;
	}
};
