#pragma once

namespace netlib::log
{
    /**
     * @brief Log level enumeration for controlling logger verbosity.
     */
    enum class log_level : uint8_t
    {
        error = 0,   ///< Error messages only.
        warning = 1, ///< Warning and error messages.
        info = 2,    ///< Informational, warning, and error messages.
        debug = 4,   ///< Debug, info, warning, and error messages.
        all = 255,   ///< All log messages.
    };

    /**
     * @brief Converts a log_level enum value to its string representation.
     * @param level The log_level value.
     * @return String view representing the log level.
     */
    inline std::string_view to_string(const log_level level)
    {
        switch (level)
        {
        case log_level::error: return "error";
        case log_level::warning: return "warning";
        case log_level::info: return "info";
        case log_level::debug: return "debug";
        case log_level::all: return "all";
        }
        return "unknown";
    }

    /**
     * @brief Parses a string to obtain the corresponding log_level enum value.
     * @param str The string representation of the log level.
     * @return The corresponding log_level value, or log_level::error if not recognized.
     */
    inline log_level from_string(const std::string_view str)
    {
        if (str == "error") return log_level::error;
        if (str == "warning") return log_level::warning;
        if (str == "info") return log_level::info;
        if (str == "debug") return log_level::debug;
        if (str == "all") return log_level::all;
        return log_level::error;
    }

    /**
     * @brief Base logger class template for thread-safe logging.
     * @tparam Derived The derived logger type.
     *
     * Provides log level filtering and output stream management.
     */
    template <typename Derived>
    class logger
    {
    protected:
        log_level log_level_{ log_level::error }; ///< Current log level.
        std::optional<std::reference_wrapper<std::ostream>> log_stream_; ///< Optional output stream for logging.

    private:
        /**
         * @brief Constructs a logger with a log level and optional output stream.
         * @param level The log level.
         * @param stream The output stream (optional).
         */
        logger(const log_level level, const std::optional<std::reference_wrapper<std::ostream>> stream)
            : log_level_(level), log_stream_(stream) {
        }

    public:
        /**
         * @brief Prints a log message if the specified level is enabled.
         * @param level The log level of the message.
         * @param message The message to log.
         */
        void print_log(const log_level level, const std::string& message) const noexcept
        {
            if ((level <= log_level_) && log_stream_)
            {
                const auto now = std::chrono::system_clock::now();
                const auto now_time_t = std::chrono::system_clock::to_time_t(now);
                std::tm now_tm{};

                // Convert to local time and handle any errors
                if (localtime_s(&now_tm, &now_time_t) != 0) {
                    std::osyncstream(log_stream_->get()) << "Failed to get local time." << '\n';
                    return;
                }

                const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
                const auto thread_id = std::this_thread::get_id();

                std::osyncstream(log_stream_->get()) << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S")
                    << '.' << std::setfill('0') << std::setw(3) << now_ms.count()
                    << " [Thread " << thread_id << "] [" << typeid(Derived).name() << "] " << message << '\n';
            }
        }

        friend Derived;
    };
}