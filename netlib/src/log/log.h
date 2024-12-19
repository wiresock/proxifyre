#pragma once

namespace netlib::log
{
    enum class log_level : uint8_t
    {
        error = 0,
        warning = 1, // Consider adding a warning level if applicable
        info = 2,
        debug = 4,
        all = 255,
    };

    inline std::string_view to_string(const log_level level)
    {
        switch (level)
        {
        case log_level::error: return "error";
        case log_level::warning: return "warning"; // Handle the new warning level
        case log_level::info: return "info";
        case log_level::debug: return "debug";
        case log_level::all: return "all";
        default: return "unknown";
        }
    }

    // Example of a function to parse log levels from strings
    // This could be expanded to be more robust and handle errors.
    inline log_level from_string(const std::string_view str)
    {
        if (str == "error") return log_level::error;
        if (str == "warning") return log_level::warning; // Handle the new warning level
        if (str == "info") return log_level::info;
        if (str == "debug") return log_level::debug;
        if (str == "all") return log_level::all;
        return log_level::error; // Default or error handling
    }

    template <typename Derived>
    class logger
    {
    protected:
        log_level log_level_{log_level::error};
        std::optional<std::reference_wrapper<std::ostream>> log_stream_;

        explicit logger(const log_level level = log_level::error,
                        const std::optional<std::reference_wrapper<std::ostream>> stream = std::nullopt)
            : log_level_(level), log_stream_(stream)
        {
        }

    public:
        void print_log(const log_level level, const std::string& message, const bool force_flush = false) const noexcept
        {
            if ((level <= log_level_) && log_stream_)
            {
                const auto now = std::chrono::system_clock::now();
                const auto now_time_t = std::chrono::system_clock::to_time_t(now);
                std::tm now_tm{};

                // Convert to local time and handle any errors
                if (localtime_s(&now_tm, &now_time_t) != 0)
                {
                    std::osyncstream(log_stream_->get()) << "Failed to get local time." << '\n';
                    return;
                }

                const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) %
                    1000;
                const auto thread_id = std::this_thread::get_id();
                std::osyncstream output_stream(log_stream_->get());

                output_stream << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S")
                    << '.' << std::setfill('0') << std::setw(3) << now_ms.count()
                    << " [Thread " << thread_id << "] [" << typeid(Derived).name() << "] " << message << '\n';

                if (force_flush)
                {
                    output_stream.flush();
                }
            }
        }

        friend Derived;
    };
}
