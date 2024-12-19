#pragma once

class logger
{
    static constexpr auto default_log_limit = 100;
    log_storage_mx_t log_storage_;
    std::mutex log_storage_lock_;
    size_t log_limit_{default_log_limit};
    HANDLE log_event_{nullptr};

    /**
     * @brief Custom stream buffer for logging.
     */
    class log_streambuf final : public std::streambuf
    {
        logger* log_;
        std::string buffer_;

    protected:
        /**
         * @brief Handles overflow by writing to the logger.
         * @param c The character to write.
         * @return The character written.
         */
        int overflow(const int c) override
        {
            if (c != EOF)
            {
                buffer_ += static_cast<char>(c);
                if (c == '\n')
                {
                    log_->log_printer(buffer_.c_str());
                    buffer_.clear();
                }
            }
            return c;
        }

    public:
        /**
         * @brief Constructs the log_streambuf with a logger pointer.
         * @param log Pointer to the logger instance.
         */
        explicit log_streambuf(logger* log) : log_(log)
        {
        }
    };

    log_streambuf streambuf_;
    std::ostream log_stream_;

    /**
     * @brief Private constructor to enforce singleton pattern.
     */
    logger() : streambuf_(this), log_stream_(&streambuf_)
    {
    }

public:
    /**
     * @brief Gets the singleton instance of the logger.
     * @return Pointer to the logger instance.
     */
    static logger* get_instance()
    {
        static logger inst; // NOLINT(clang-diagnostic-exit-time-destructors)
        return &inst;
    }

    /**
     * @brief Logs a message.
     * @param log The message to log.
     */
    void log_printer(const char* log)
    {
        using namespace std::chrono;
        const auto ms = duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
        );

        std::lock_guard lock(log_storage_lock_);

        log_storage_.emplace_back(ms.count(), log);

        if (log_event_ && log_storage_.size() > log_limit_)
            ::SetEvent(log_event_);
    }

    /**
     * @brief Logs an event.
     * @param log_event The event to log.
     */
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

                std::lock_guard lock(log_storage_lock_);

                log_storage_.emplace_back(ms.count(), log_event);
            }
            break;
        }

        if (log_event_ && log_storage_.size() > log_limit_)
            ::SetEvent(log_event_);
    }

    /**
     * @brief Reads the log storage.
     * @return Optional containing the log storage if not empty.
     */
    std::optional<log_storage_mx_t> read_log()
    {
        using namespace std::chrono;

        std::lock_guard lock(log_storage_lock_);

        return log_storage_.empty() ? std::nullopt : std::make_optional(std::move(log_storage_));
    }

    /**
     * @brief Gets the size of the log storage.
     * @return The size of the log storage.
     */
    size_t size()
    {
        std::lock_guard lock(log_storage_lock_);
        return log_storage_.size();
    }

    /**
     * @brief Sets the log limit.
     * @param log_limit The new log limit.
     */
    void set_log_limit(const uint32_t log_limit)
    {
        log_limit_ = log_limit;
    }

    /**
     * @brief Gets the log limit.
     * @return The log limit.
     */
    [[nodiscard]] uint32_t get_log_limit() const
    {
        return static_cast<uint32_t>(log_limit_);
    }

    /**
     * @brief Sets the log event handle.
     * @param log_event The log event handle.
     */
    void set_log_event(HANDLE log_event)
    {
        log_event_ = log_event;
    }

    /**
     * @brief Gets the log stream.
     * @return Reference to the log stream.
     */
    std::ostream& get_log_stream()
    {
        return log_stream_;
    }
};
