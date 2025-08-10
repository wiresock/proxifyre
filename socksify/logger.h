#pragma once

/**
 * @brief Thread-safe singleton logger for storing and managing log messages and events.
 *
 * The logger class provides a thread-safe mechanism for logging messages and events,
 * storing them in an internal buffer with a configurable limit. It supports log event
 * notification via a Windows event handle and provides a custom stream buffer for
 * integration with standard C++ streams.
 */
class logger
{
    static constexpr auto default_log_limit = 100; ///< Default maximum number of log entries to keep.
    log_storage_mx_t log_storage_;                 ///< Container for storing log entries.
    std::mutex log_storage_lock_;                  ///< Mutex for synchronizing access to log storage.
    size_t log_limit_{ default_log_limit };          ///< Maximum number of log entries before signaling event.
    HANDLE log_event_{ nullptr };                    ///< Windows event handle for log notifications.

    /**
     * @brief Custom stream buffer for logging.
     *
     * This stream buffer allows the logger to be used as a standard output stream.
     * Each line written to the stream is added to the logger's storage.
     */
    class log_streambuf final : public std::streambuf
    {
        logger* log_;         ///< Pointer to the parent logger.
        std::string buffer_;  ///< Buffer for accumulating characters until a newline.

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

    log_streambuf streambuf_; ///< Stream buffer for log output.
    std::ostream log_stream_; ///< Output stream using the custom stream buffer.

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
     *
     * The message is timestamped and added to the log storage. If the log storage exceeds
     * the configured limit and a log event handle is set, the event is signaled.
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
     *
     * Supported event types are address_error, connected, and disconnected.
     * The event is timestamped and added to the log storage. If the log storage exceeds
     * the configured limit and a log event handle is set, the event is signaled.
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
     * @brief Reads and clears the log storage.
     * @return Optional containing the log storage if not empty, otherwise std::nullopt.
     *
     * The returned log storage is moved out of the logger, clearing the internal buffer.
     */
    std::optional<log_storage_mx_t> read_log()
    {
        using namespace std::chrono;

        std::lock_guard lock(log_storage_lock_);

        return log_storage_.empty() ? std::nullopt : std::make_optional(std::move(log_storage_));
    }

    /**
     * @brief Gets the size of the log storage.
     * @return The number of log entries currently stored.
     */
    size_t size()
    {
        std::lock_guard lock(log_storage_lock_);
        return log_storage_.size();
    }

    /**
     * @brief Sets the log limit.
     * @param log_limit The new log limit.
     *
     * When the number of log entries exceeds this limit, the log event is signaled (if set).
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
     *
     * The event is signaled when the log storage exceeds the configured limit.
     */
    void set_log_event(const HANDLE log_event)
    {
        log_event_ = log_event;
    }

    /**
     * @brief Gets the log stream.
     * @return Shared pointer to the log stream.
     *
     * The returned shared pointer can be used with standard C++ stream operations to log messages.
     * Note: The shared pointer uses a no-op deleter to avoid destroying the stream when the
     * shared pointer is released, since the stream is owned by the logger instance.
     */
    std::shared_ptr<std::ostream> get_log_stream()
    {
        return {
            &log_stream_, [](std::ostream*) {
            // No-op deleter - the stream is owned by the logger instance
            }
        };
    }
};