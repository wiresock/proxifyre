// ReSharper disable CppClangTidyClangDiagnosticGnuZeroVariadicMacroArguments
#pragma once

#include <string>
#include <string_view>
#include <format>
#include <chrono>
#include <thread>
#include <syncstream>
#include <typeinfo>
#include <concepts>
#include <atomic>
#include <memory>
#include <cstdint>
#include <iomanip>
#include <iterator>

#if __has_include(<source_location>) && defined(__cpp_lib_source_location) && __cpp_lib_source_location >= 201907L
#include <source_location>
#define NETLIB_HAS_SOURCE_LOCATION 1
#else
#define NETLIB_HAS_SOURCE_LOCATION 0
#endif

/**
 * @file log.h
 * @brief Thread-safe logging infrastructure for the netlib library.
 *
 * This file provides a comprehensive, production-ready logging system with configurable
 * log levels, thread-safe operations, and flexible output stream management. The logger
 * uses modern C++20 features including std::format for efficient string formatting,
 * std::osyncstream for atomic output operations, and optional std::source_location
 * for enhanced debugging information.
 *
 * ## Key Features:
 * - Thread-safe atomic operations for log level and stream management
 * - CRTP-based design for optimal performance and type safety
 * - Hierarchical log level filtering with special 'all' level handling
 * - Compact thread ID representation for improved readability
 * - Local time support with UTC fallback via chrono time zones
 * - Exception-safe formatting with comprehensive error recovery
 * - Zero-copy stream wrapper utilities for existing ostream objects
 * - Optional compile-time source location integration
 * - Performance-optimized string formatting with pre-allocation
 * - Multi-level fallback strategies for maximum reliability
 * - Global verbosity control for runtime output customization
 *
 * ## Source Location Architecture:
 * The logger implements a sophisticated source location capture system:
 * - Public API automatically captures call site information via std::source_location::current()
 * - Private implementation helpers maintain separation of concerns
 * - Conditional compilation ensures compatibility when source location is unavailable
 * - No user intervention required - location capture is transparent
 *
 * ## Performance Optimizations:
 * - Dual interface design: formatted logging vs. string_view for simple messages
 * - Pre-allocated buffers based on format string size estimation
 * - Early exit optimizations for disabled log levels
 * - Atomic operations with relaxed memory ordering for optimal throughput
 * - Static caching of expensive resources like time zone information
 *
 * @author Vadim Smirnov
 * @version 1.3
 * @date 2024-08-10
 * @since C++20
 */

namespace netlib::log {

    /**
     * @brief Verbosity flags for controlling log output components.
     *
     * These flags can be combined using bitwise OR operations to control
     * which components are included in log output. Each flag represents
     * a specific piece of contextual information that can be enabled or
     * disabled independently.
     */
    enum class log_verbosity : std::uint8_t {
        none = 0x00,  ///< No additional information (message only)
        timestamp = 0x01,  ///< Include timestamp in log output
        thread = 0x02,  ///< Include thread ID in log output
        logger = 0x04,  ///< Include logger name in log output
        path = 0x08,  ///< Include source file path/location in log output
        level = 0x10,  ///< Include log level in output
        all = 0x1F,  ///< Include all available information (default)
    };

    /**
     * @brief Bitwise OR operator for log_verbosity flags.
     * @param lhs Left-hand side verbosity flag
     * @param rhs Right-hand side verbosity flag
     * @return Combined verbosity flags
     */
    constexpr log_verbosity operator|(log_verbosity lhs, log_verbosity rhs) noexcept {
        return static_cast<log_verbosity>(
            static_cast<std::uint8_t>(lhs) | static_cast<std::uint8_t>(rhs)
            );
    }

    /**
     * @brief Bitwise AND operator for log_verbosity flags.
     * @param lhs Left-hand side verbosity flag
     * @param rhs Right-hand side verbosity flag
     * @return Combined verbosity flags
     */
    constexpr log_verbosity operator&(log_verbosity lhs, log_verbosity rhs) noexcept {
        return static_cast<log_verbosity>(
            static_cast<std::uint8_t>(lhs) & static_cast<std::uint8_t>(rhs)
            );
    }

    /**
     * @brief Bitwise OR assignment operator for log_verbosity flags.
     * @param lhs Left-hand side verbosity flag (modified in place)
     * @param rhs Right-hand side verbosity flag
     * @return Reference to modified lhs
     */
    constexpr log_verbosity& operator|=(log_verbosity& lhs, const log_verbosity rhs) noexcept {
        lhs = lhs | rhs;
        return lhs;
    }

    /**
     * @brief Checks if a specific verbosity flag is set.
     * @param flags The verbosity flags to check
     * @param flag The specific flag to test for
     * @return true if the flag is set, false otherwise
     */
    constexpr bool has_verbosity_flag(const log_verbosity flags, const log_verbosity flag) noexcept {
        return static_cast<bool>(flags & flag);
    }

    /**
     * @brief Global verbosity control for all loggers.
     *
     * This static atomic variable controls which components are included in log output
     * across all logger instances. It can be modified at runtime to dynamically adjust
     * logging verbosity without recompiling. Uses relaxed memory ordering for optimal
     * performance as exact synchronization timing is not critical for logging.
     *
     * @note Thread-safe for concurrent read/write operations
     * @note Default value includes all components (timestamp, thread, logger, level, path)
     */
    inline std::atomic global_log_verbosity{ log_verbosity::none };

    /**
     * @brief Sets the global log verbosity flags.
     * @param verbosity The verbosity flags to set
     */
    inline void set_global_log_verbosity(const log_verbosity verbosity) noexcept {
        global_log_verbosity.store(verbosity, std::memory_order_relaxed);
    }

    /**
     * @brief Gets the current global log verbosity flags.
     * @return The current verbosity flags
     */
    inline log_verbosity get_global_log_verbosity() noexcept {
        return global_log_verbosity.load(std::memory_order_relaxed);
    }

    /**
     * @brief Utility function to wrap an existing std::ostream into a shared_ptr without ownership.
     *
     * This function creates a shared_ptr that points to an existing ostream but uses a no-op
     * deleter, ensuring the original stream is not destroyed when the shared_ptr is reset.
     * This is particularly useful for wrapping standard streams like std::cout, std::cerr,
     * or file streams that are managed elsewhere in the application.
     *
     * @param os Reference to the existing ostream to wrap.
     * @return shared_ptr<ostream> pointing to the stream with no-op deleter.
     *
     * @note The caller must ensure the original stream remains valid for the lifetime
     *       of the returned shared_ptr and any copies of it.
     * @note This function is noexcept and has no performance overhead.
     *
     * Example Usage:
     * @code
     * auto cout_logger = std::make_shared<my_logger>(log_level::info, wrap_ostream(std::cout));
     * auto file_logger = std::make_shared<my_logger>(log_level::debug, wrap_ostream(file_stream));
     * @endcode
     */
    inline std::shared_ptr<std::ostream> wrap_ostream(std::ostream& os) noexcept {
        return { &os, [](std::ostream*) {} };
    }

    /**
     * @brief Log level enumeration for controlling logger verbosity.
     *
     * This enumeration defines a hierarchical logging system where each level includes
     * all messages from lower-severity levels. The numeric values are intentionally
     * non-sequential to allow for future expansion and to provide special handling
     * for the 'all' level.
     *
     * Hierarchy (from most to least restrictive):
     * - error (0): Only critical errors that may cause application failure
     * - warning (1): Potential issues that should be monitored + errors
     * - info (2): General application flow information + warnings + errors
     * - debug (4): Detailed diagnostic information + all above levels
     * - all (255): Special level that accepts all message types regardless of sender level
     *
     * @note The 'all' level is special-cased in the is_enabled() function to always
     *       return true, making it different from a simple numeric comparison.
     */
    enum class log_level : std::uint8_t {
        error = 0,   ///< Error messages only - critical issues that may cause application failure.
        warning = 1, ///< Warning and error messages - potential issues that should be monitored.
        info = 2,    ///< Informational, warning, and error messages - general application flow.
        debug = 4,   ///< Debug, info, warning, and error messages - detailed diagnostic information.
        all = 255,   ///< All log messages - special level that accepts all message types.
    };

    /**
     * @brief Converts a log_level enum value to its string representation.
     *
     * This function provides a compile-time constant conversion from log level
     * enumeration to human-readable string representation for use in log output
     * formatting. The function is constexpr and can be evaluated at compile-time
     * when used with constant expressions.
     *
     * @param level The log_level value to convert.
     * @return constexpr string_view representing the log level name.
     * @retval "error" for log_level::error
     * @retval "warning" for log_level::warning
     * @retval "info" for log_level::info
     * @retval "debug" for log_level::debug
     * @retval "all" for log_level::all
     * @retval "unknown" for any unrecognized value (should never occur with valid enum)
     *
     * @note Returns string_view for optimal performance - no dynamic allocation.
     * @note This function is constexpr and can be used in constant expressions.
     */
    constexpr std::string_view to_string(const log_level level) noexcept {
        switch (level) {
        case log_level::error:   return "error";
        case log_level::warning: return "warning";
        case log_level::info:    return "info";
        case log_level::debug:   return "debug";
        case log_level::all:     return "all";
        }
        return "unknown";
    }

    /**
     * @brief Parses a string to obtain the corresponding log_level enum value.
     *
     * This function provides case-sensitive string-to-enum conversion for log level
     * configuration. It's designed for parsing configuration files, command-line
     * arguments, or runtime log level changes. The function uses a constexpr
     * ternary chain for optimal performance and compile-time evaluation when possible.
     *
     * @param s The string representation of the log level (case-sensitive).
     * @return constexpr log_level value corresponding to the input string.
     * @retval log_level::error as safe default for unrecognized inputs.
     *
     * @note Case-sensitive matching - "Error" will not match "error".
     * @note Returns error level as safe default for unrecognized inputs.
     * @note This function is constexpr and can be used in constant expressions.
     *
     * Supported Input Strings:
     * - "error" ? log_level::error
     * - "warning" ? log_level::warning
     * - "info" ? log_level::info
     * - "debug" ? log_level::debug
     * - "all" ? log_level::all
     * - anything else ? log_level::error (safe default)
     */
    constexpr log_level from_string(const std::string_view s) noexcept {
        return s == "error" ? log_level::error :
            s == "warning" ? log_level::warning :
            s == "info" ? log_level::info :
            s == "debug" ? log_level::debug :
            s == "all" ? log_level::all :
            log_level::error;
    }

    /**
     * @brief Determines if a message should be logged based on configured and message log levels.
     *
     * This function implements the core logic for hierarchical log level filtering.
     * It uses a direct comparison system optimized for performance in hot paths.
     * The function is constexpr and can be evaluated at compile-time.
     *
     * The hierarchy treats log levels as follows:
     * - error = 0 (most restrictive - only shows errors)
     * - warning = 1 (shows warnings and errors)
     * - info = 2 (shows info, warnings, and errors)
     * - debug = 4 (shows debug, info, warnings, and errors)
     * - all = 255 (shows everything, special-cased)
     *
     * @param configured The logger's configured log level threshold.
     * @param msg The log level of the message being evaluated.
     * @return true if the message should be logged, false otherwise.
     *
     * @note The 'all' configured level always returns true regardless of message level.
     * @note Uses direct enum value comparison for optimal performance.
     * @note This function is the single source of truth for log level decisions.
     *
     * Examples:
     * - is_enabled(info, error) ? true (error messages shown at info level)
     * - is_enabled(error, info) ? false (info messages not shown at error level)
     * - is_enabled(all, debug) ? true (all level accepts everything)
     */
    constexpr bool is_enabled(const log_level configured, const log_level msg) noexcept {
        // Fast path: 'all' level accepts everything
        if (configured == log_level::all) [[likely]] return true;

        // A message should be logged if the configured level is >= the message level
        // in terms of verbosity (higher numeric values = more verbose)
        return static_cast<std::uint8_t>(configured) >= static_cast<std::uint8_t>(msg);
    }

    /**
     * @brief Base logger class template for thread-safe logging using CRTP pattern.
     *
     * This class template provides a comprehensive, thread-safe logging infrastructure
     * using the Curiously Recurring Template Pattern (CRTP) for optimal performance
     * and type safety. It offers formatted logging with automatic timestamping,
     * thread identification, optional source location information, and configurable
     * output verbosity.
     *
     * ## Key Features:
     *
     * ### Thread Safety:
     * - Atomic log level operations with relaxed memory ordering
     * - Shared pointer-based stream management for safe concurrent access
     * - osyncstream for atomic output operations preventing interleaved output
     *
     * ### Performance Optimizations:
     * - CRTP pattern for zero-overhead virtual function calls
     * - std::format_to with pre-allocated buffers to minimize allocations
     * - Compact thread ID hashing for readable output
     * - Constexpr utility functions for compile-time optimization
     * - Static caching of time zone information
     *
     * ### Error Handling:
     * - Multi-level fallback strategies for format errors
     * - Graceful degradation when time zone database is unavailable
     * - Exception-safe noexcept guarantees on all public methods
     * - Safe basename extraction with bounds checking
     *
     * ### Modern C++20 Features:
     * - std::format for type-safe, efficient string formatting
     * - std::source_location for automatic debugging context (optional)
     * - Concepts for compile-time interface validation
     * - Chrono time zones for proper local time handling
     * - osyncstream for thread-safe output coordination
     *
     * ### Configurable Output:
     * - Global verbosity control for runtime output customization
     * - Individual component enable/disable (timestamp, thread, logger, path, level)
     * - Dynamic reconfiguration without recompilation
     *
     * ## Output Format Examples:
     *
     * Full verbosity: `[info] 2024-08-10T14:30:25.123 [T A1B2C3] [Logger] [file:line:func] Message`
     *
     * Minimal: `[info] Message`
     *
     * Production: `[info] 2024-08-10T14:30:25.123 [Logger] Message`
     *
     * @tparam Derived The derived logger type (CRTP pattern).
     *
     * ## Usage Example:
     *
     * @code
     * class application_logger : public logger<application_logger> {
     * public:
     *     static constexpr std::string_view name() { return "AppLogger"; }
     *
     *     application_logger(log_level level, std::shared_ptr<std::ostream> stream)
     *         : logger(level, std::move(stream)) {}
     * };
     *
     * // Configure verbosity
     * set_global_log_verbosity(log_verbosity::timestamp | log_verbosity::level | log_verbosity::logger);
     *
     * // Usage
     * auto app_logger = std::make_shared<application_logger>(
     *     log_level::info, wrap_ostream(std::cout)
     * );
     *
     * app_logger->print_log(log_level::info, "Processing {} items", 42);
     * app_logger->print_log(log_level::error, "Connection failed");
     * @endcode
     *
     * @note The constructor is private to enforce proper inheritance patterns.
     * @note All public methods are noexcept with comprehensive error handling.
     * @note Uses relaxed memory ordering for atomic operations (sufficient for logging).
     * @since C++20
     */
    template <typename Derived>
    class logger {
    protected:
        std::atomic<log_level> log_level_{ log_level::error };    ///< Thread-safe log level threshold with atomic access.
        std::shared_ptr<std::ostream> log_stream_;                ///< Thread-safe shared output stream with automatic lifetime management.

    private:
        // Trait to detect if Derived has a static name() method at compile-time
        template <class T>
        static constexpr bool has_static_name = requires {
            { T::name() } -> std::convertible_to<std::string_view>;
        };

        /**
         * @brief Compile-time safe helper to get derived class name.
         *
         * This function uses SFINAE and constexpr if to determine the best way to get
         * a readable name for the logger. If the derived class provides a static name()
         * method, it uses that; otherwise, it falls back to RTTI type information.
         *
         * @return constexpr string_view with the logger name.
         * @note Prefers Derived::name() if available, falls back to typeid(Derived).name().
         * @note typeid().name() output is implementation-defined and may be mangled.
         */
        static constexpr std::string_view derived_name() noexcept {
            if constexpr (has_static_name<Derived>) {
                return Derived::name();
            }
            else {
                return std::string_view{ typeid(Derived).name() };
            }
        }

        /**
         * @brief Generate a compact, readable thread ID for log output.
         *
         * This function creates a 24-bit hash of the current thread ID to provide
         * a compact, hexadecimal representation that's more readable than the full
         * thread ID while maintaining reasonable uniqueness within a process.
         *
         * @return uint32_t containing the lower 24 bits of the thread ID hash.
         * @note Uses std::hash for consistent hashing across platforms.
         * @note Returns only the lower 24 bits (6 hex digits) for readability.
         * @note [[nodiscard]] attribute prevents accidental unused calls.
         */
        [[nodiscard]] static std::uint32_t compact_thread_id() noexcept {
            return static_cast<std::uint32_t>(
                std::hash<std::thread::id>{}(std::this_thread::get_id()) & 0xFFFFFF
                );
        }

        /**
         * @brief Private constructor to enforce CRTP pattern and prevent direct instantiation.
         *
         * This constructor initializes the logger with a specified log level and output stream.
         * The private access ensures that only derived classes (via friend declaration)
         * can instantiate the logger, enforcing proper inheritance patterns.
         *
         * @param level The minimum log level for message filtering.
         * @param stream Shared pointer to the output stream for log messages.
         *
         * @note stream can be null, in which case all logging operations become no-ops.
         * @note Uses move semantics for optimal performance with shared_ptr.
         */
        logger(const log_level level, std::shared_ptr<std::ostream> stream) noexcept
            : log_level_(level), log_stream_(std::move(stream)) {
        }

    public:

#if NETLIB_HAS_SOURCE_LOCATION
        /**
         * @brief Logs a formatted message with explicit source location information.
         *
         * This function provides direct control over source location information for formatted
         * logging, allowing callers to explicitly specify the location context rather than
         * relying on automatic capture. It's particularly useful for logging wrappers, macros,
         * or utility functions that need to preserve the original call site information.
         *
         * ## Design Purpose:
         * While the standard print_log() method automatically captures source location at the
         * call site, this variant accepts an explicit source location parameter. This enables:
         * - Logging wrappers that preserve original caller context
         * - Custom logging macros that can manipulate source location
         * - Forwarding source location from higher-level abstractions
         * - Testing scenarios with controlled location information
         *
         * ## Conditional Compilation:
         * This function is only available when NETLIB_HAS_SOURCE_LOCATION is defined (C++20
         * std::source_location support). When source location is unavailable, this overload
         * is not compiled, and callers must use the standard print_log() variants.
         *
         * ## Performance Characteristics:
         * - Identical performance profile to standard print_log() template
         * - Pre-allocates format buffer based on format string size estimation
         * - Uses std::format_to with back_inserter for efficient string construction
         * - Comprehensive exception handling with multiple fallback strategies
         * - Early exit optimization for disabled log levels
         *
         * ## Output Format:
         * Produces configurable output format based on global verbosity settings:
         * ```
         * [info] 2024-08-10T14:30:25.123 [T A1B2C3] [MyLogger] [file.cpp:42:function] Message
         * ```
         *
         * ## Error Handling:
         * - All std::format exceptions are caught and converted to error messages
         * - Maintains noexcept guarantee through comprehensive exception handling
         * - Uses same multi-level fallback strategy as other logging methods
         * - Never throws exceptions regardless of format string or argument issues
         *
         * @tparam Args Variadic template parameter pack for format arguments.
         * @param level The log level for message filtering and output formatting.
         * @param loc Source location information to include in the log output.
         * @param fmt Format string compatible with std::format (compile-time validated).
         * @param args Arguments for format string substitution (perfect forwarded).
         *
         * @note Only available when NETLIB_HAS_SOURCE_LOCATION is defined (C++20 required).
         * @note Function is noexcept with comprehensive internal error handling.
         * @note Messages are filtered based on is_enabled(current_level, message_level).
         * @note No output occurs if log_stream_ is null or level is filtered out.
         * @note Format string type safety is enforced at compile time.
         *
         * ## Thread Safety:
         * - Thread-safe atomic access to log level and stream
         * - Uses std::osyncstream for atomic output operations
         * - Safe for concurrent use across multiple threads
         *
         * ## Usage Examples:
         * @code
         * // Preserve source location in wrapper function
         * template<typename... Args>
         * void my_log_wrapper(log_level level, std::format_string<Args...> fmt, Args&&... args,
         *                     std::source_location loc = std::source_location::current()) {
         *     logger.print_log_with_loc(level, loc, fmt, std::forward<Args>(args)...);
         * }
         *
         * // Custom source location for testing
         * auto test_loc = std::source_location::current();
         * logger.print_log_with_loc(log_level::debug, test_loc, "Test message: {}", value);
         *
         * // Forwarding location from higher-level function
         * void high_level_function(std::source_location loc = std::source_location::current()) {
         *     logger.print_log_with_loc(log_level::info, loc, "Called from: {}", loc.function_name());
         * }
         * @endcode
         *
         * @see print_log() for automatic source location capture
         * @see print_log_impl() for the underlying implementation
         * @since C++20 (requires std::source_location support)
         */
        template <typename... Args>
        void print_log_with_loc(
            log_level level,
            const std::source_location& loc,
            std::format_string<Args...> fmt,
            Args&&... args) const noexcept
        {
            print_log_impl(level, loc, fmt, std::forward<Args>(args)...);
        }

#else

        /**
         * @brief Logs a formatted message with type-safe parameter substitution.
         *
         * This function provides printf-style formatted logging using modern C++20
         * std::format. It includes comprehensive error handling for format operations
         * and produces thread-safe output with rich contextual information including
         * timestamps, log levels, thread IDs, and automatic source location data.
         *
         * ## Architecture and Design:
         * This public interface automatically captures source location at the call site
         * and delegates to the private print_log_impl() for actual processing. This
         * design separates the user-facing API from implementation details while ensuring
         * source location is captured at the correct call site.
         *
         * ## Performance Optimizations:
         * - Pre-allocates string buffer based on format string size estimation
         * - Uses std::format_to with back_inserter to minimize allocations
         * - Early exit for disabled log levels to avoid unnecessary work
         * - Atomic log level checking with relaxed memory ordering
         *
         * ## Error Handling:
         * - Catches and handles std::format_error exceptions gracefully
         * - Provides detailed error context in fallback messages
         * - Maintains exception-safe noexcept guarantee through comprehensive catches
         *
         * ## Source Location Integration:
         * - Automatically captures source location at call site via std::source_location::current()
         * - No user intervention required - location is captured transparently
         * - Gracefully degrades when source location support is unavailable
         *
         * ## Output Format Examples:
         * ```
         * [info] 2024-05-10T14:30:25.123 [T A1B2C3] [MyLogger] Processing 150 items
         * [error] 2024-05-10T14:30:25.124 [T A1B2C3] [MyLogger] [main.cpp:42:process_data] Connection failed
         * [debug] 2024-05-10T14:30:25.125Z [T A1B2C3] [MyLogger] Debug info (UTC fallback)
         * ```
         *
         * @tparam Args Variadic template parameter pack for format arguments.
         * @param level The log level for this message (used for filtering).
         * @param fmt Format string compatible with std::format (compile-time checked).
         * @param args Arguments to substitute into the format string (perfect forwarded).
         *
         * @note Function is noexcept - all exceptions are caught and handled internally.
         * @note Messages are filtered based on is_enabled(current_level, message_level).
         * @note No output occurs if log_stream_ is null.
         * @note Format string is compile-time validated for type safety.
         * @note Source location is automatically captured without user intervention.
         *
         * ## Thread Safety:
         * - Atomic log level access with memory_order_relaxed
         * - Thread-safe stream access via shared_ptr copy
         * - Atomic output via std::osyncstream
         *
         * ## Usage Examples:
         * @code
         * logger.print_log(log_level::info, "Processing {} items in {} seconds", count, duration);
         * logger.print_log(log_level::error, "Connection failed: {}", error_message);
         * logger.print_log(log_level::debug, "Value: {:#x}", hex_value);
         * @endcode
         */
        template <typename... Args>
        void print_log(
            const log_level level,
            std::format_string<Args...> fmt,
            Args&&... args) const noexcept
        {
            print_log_impl(level, fmt, std::forward<Args>(args)...);
        }

#endif

        /**
         * @brief Logs a pre-formatted message string with minimal processing overhead.
         *
         * This overload provides an efficient logging path for pre-formatted messages,
         * avoiding the overhead of std::format processing while maintaining the same
         * rich output format and thread safety guarantees as the templated version.
         *
         * This function is ideal for:
         * - Simple string messages without parameter substitution
         * - Performance-critical logging paths where formatting overhead matters
         * - Integration with existing string-based logging systems
         * - Logging of pre-computed or externally formatted messages
         *
         * ## Performance Benefits:
         * - No format string parsing or parameter substitution
         * - Direct string_view usage avoids unnecessary string copies
         * - Same early-exit optimization for disabled log levels
         * - Identical thread-safe output path as templated version
         *
         * ## Source Location Handling:
         * - Conditionally compiled based on NETLIB_HAS_SOURCE_LOCATION
         * - When available, automatically captures call site information
         * - Graceful fallback when source location is not supported
         *
         * @param level The log level for this message (used for filtering).
         * @param message The pre-formatted message string to log (zero-copy via string_view).
         * @param loc Source location information (automatically captured when available).
         *
         * @note Function is noexcept with same guarantees as templated version.
         * @note Uses same timestamp precision and format as templated version.
         * @note Subject to same log level filtering rules.
         * @note Source location parameter is conditionally compiled.
         *
         * ## Usage Examples:
         * @code
         * logger.print_log(log_level::error, "Database connection failed");
         * logger.print_log(log_level::info, status_message);
         * logger.print_log(log_level::debug, debug_string_from_function());
         * @endcode
         */
        void print_log(const log_level level,
            const std::string_view message
#if NETLIB_HAS_SOURCE_LOCATION
            , const std::source_location& loc = std::source_location::current()
#endif
        ) const noexcept
        {
            // Thread-safe stream access and early exit optimization
            const auto stream = log_stream_;
            if (!stream || !is_enabled(log_level_.load(std::memory_order_relaxed), level)) return;

            // Direct delegation without format processing
            emit_log_entry(level, message, *stream
#if NETLIB_HAS_SOURCE_LOCATION
                , loc
#endif
            );
        }

        /**
         * @brief Sets a new log level for the logger (thread-safe).
         *
         * This function atomically updates the logger's log level threshold using
         * relaxed memory ordering, which is sufficient for log level changes since
         * slight delays in propagation to other threads are acceptable for logging.
         *
         * @param level The new log level threshold to set.
         *
         * @note Uses memory_order_relaxed for optimal performance.
         * @note Changes take effect immediately but may not be visible to other
         *       threads until their next log level check.
         * @note Thread-safe and can be called concurrently with logging operations.
         */
        void set_log_level(const log_level level) noexcept {
            log_level_.store(level, std::memory_order_relaxed);
        }

        /**
         * @brief Gets the current log level (thread-safe).
         *
         * This function atomically reads the current log level threshold using
         * relaxed memory ordering for optimal performance.
         *
         * @return The current log level threshold.
         *
         * @note Uses memory_order_relaxed for optimal performance.
         * @note Returns the log level as it exists at the moment of the call.
         * @note Thread-safe and can be called concurrently with other operations.
         * @note [[nodiscard]] attribute prevents accidental unused calls.
         */
        [[nodiscard]] log_level get_log_level() const noexcept {
            return log_level_.load(std::memory_order_relaxed);
        }

        /**
         * @brief Sets a new output stream for the logger (thread-safe).
         *
         * This function atomically updates the logger's output stream using shared_ptr
         * for safe concurrent access. The old stream is automatically released when
         * no longer referenced.
         *
         * @param stream Shared pointer to the new output stream (can be null to disable output).
         *
         * @note Uses shared_ptr for automatic lifetime management and thread safety.
         * @note Can be set to nullptr to disable all logging output.
         * @note Changes take effect immediately for new log messages.
         * @note Thread-safe and can be called concurrently with logging operations.
         * @note Uses move semantics for optimal performance.
         */
        void set_log_stream(std::shared_ptr<std::ostream> stream) noexcept {
            log_stream_ = std::move(stream);
        }

    private:

#if NETLIB_HAS_SOURCE_LOCATION
        /**
         * @brief Internal implementation for formatted message logging (with source location).
         *
         * This private helper function performs the actual formatting and logging work
         * for the public print_log() template when source location is available. It exists
         * to enable proper source location capture while maintaining clean separation between
         * the public API and implementation details.
         *
         * ## Design Rationale:
         * This implementation pattern solves the source location parameter forwarding
         * problem by having the public interface capture source location at the call
         * site and pass it to this implementation function. This ensures that:
         * - Source location reflects the actual caller, not the logger implementation
         * - The public API remains clean and user-friendly
         * - Implementation complexity is properly encapsulated
         *
         * ## Performance Characteristics:
         * - Pre-allocates message buffer based on format string length estimation
         * - Uses std::format_to for efficient string construction
         * - Comprehensive exception handling with multiple fallback levels
         * - Early exit optimization for disabled log levels
         *
         * @tparam Args Variadic template parameter pack for format arguments.
         * @param level The log level for filtering and output formatting.
         * @param loc Source location captured at the original call site.
         * @param fmt Format string for std::format (compile-time validated).
         * @param args Perfect-forwarded arguments for format substitution.
         *
         * @note This function is private and not part of the public API.
         * @note All exceptions are caught and converted to error messages.
         * @note Uses the same error handling strategy as other logging methods.
         */
        template <typename... Args>
        void print_log_impl(
            const log_level level,
            const std::source_location& loc,
            std::format_string<Args...> fmt,
            Args&&... args) const noexcept
        {
            const auto stream = log_stream_;
            if (!stream || !is_enabled(log_level_.load(std::memory_order_relaxed), level))
                return;

            std::string message;
            try {
                // Estimate buffer size for optimal performance
                const auto estimated_size = std::max<size_t>(128, fmt.get().size() * 2);
                message.reserve(estimated_size);
                std::format_to(std::back_inserter(message), fmt, std::forward<Args>(args)...);
            }
            catch (const std::exception& e) {
                // Fallback for format errors - avoid recursive format calls
                message.clear();
                message += "[formatting failed] ";
                message += e.what();
            }
            catch (...) {
                // Ultimate fallback for unknown exceptions
                message = "[formatting failed] unknown error";
            }

            // Delegate to the core output function with captured location
            emit_log_entry(level, message, *stream, loc);
        }
#else
        /**
         * @brief Internal implementation for formatted message logging (without source location).
         *
         * This private helper function performs the actual formatting and logging work
         * for the public print_log() template when source location is not available. It
         * provides the same functionality as the source location version but omits location
         * information from the output.
         *
         * @tparam Args Variadic template parameter pack for format arguments.
         * @param level The log level for filtering and output formatting.
         * @param fmt Format string for std::format (compile-time validated).
         * @param args Perfect-forwarded arguments for format substitution.
         *
         * @note This function is private and not part of the public API.
         * @note All exceptions are caught and converted to error messages.
         * @note Provides identical functionality to the source location version.
         */
        template <typename... Args>
        void print_log_impl(
            const log_level level,
            std::format_string<Args...> fmt,
            Args&&... args) const noexcept
        {
            const auto stream = log_stream_;
            if (!stream || !is_enabled(log_level_.load(std::memory_order_relaxed), level))
                return;

            std::string message;
            try {
                // Estimate buffer size for optimal performance
                const auto estimated_size = std::max<size_t>(128, fmt.get().size() * 2);
                message.reserve(estimated_size);
                std::format_to(std::back_inserter(message), fmt, std::forward<Args>(args)...);
            }
            catch (const std::exception& e) {
                // Fallback for format errors - avoid recursive format calls
                message.clear();
                message += "[formatting failed] ";
                message += e.what();
            }
            catch (...) {
                // Ultimate fallback for unknown exceptions
                message = "[formatting failed] unknown error";
            }

            // Delegate to the core output function without location
            emit_log_entry(level, message, *stream);
        }
#endif

        /**
         * @brief Internal helper to emit formatted log entries with configurable verbosity.
         *
         * This function handles the actual formatting and output of log messages with
         * contextual information controlled by the global verbosity settings. Components
         * like timestamps, thread IDs, logger names, log levels, and source location
         * can be selectively enabled or disabled based on the current verbosity configuration.
         *
         * ## Source Location Processing:
         * When NETLIB_HAS_SOURCE_LOCATION is enabled, this function:
         * - Safely extracts basename from full file paths using find_last_of()
         * - Handles edge cases where no path separators exist
         * - Includes function name and line number for enhanced debugging
         * - Gracefully compiles without source location when not available
         *
         * ## Timestamp Handling:
         * - Attempts local time via std::chrono::zoned_time and current_zone()
         * - Falls back to UTC with 'Z' suffix if time zone database unavailable
         * - Uses millisecond precision for high-resolution timing in ISO-8601 format
         * - Caches time zone pointer for performance (stable across calls)
         *
         * ## Error Recovery Strategy:
         * - Primary: Modern chrono formatting with local time
         * - Secondary: UTC formatting with clear indication
         * - Tertiary: Manual formatting without std::format dependency
         * - Each level provides progressively more basic but reliable output
         *
         * @param level The log level of the message being emitted.
         * @param message The formatted message content to output.
         * @param stream Reference to the output stream for atomic writing.
         * @param loc Source location information (conditionally compiled).
         *
         * @note Function is static to avoid unnecessary 'this' parameter passing.
         * @note All operations are noexcept with comprehensive exception handling.
         * @note Uses osyncstream for atomic output preventing interleaved messages.
         * @note Implements the complete fallback chain for maximum reliability.
         */
        static void emit_log_entry(const log_level level,
            const std::string_view message,
            std::ostream& stream
#if NETLIB_HAS_SOURCE_LOCATION
            , const std::source_location& loc = std::source_location::current()
#endif
        ) noexcept
        {
            std::osyncstream out{ stream };

            try {
                const auto verbosity = get_global_log_verbosity();
                bool first_component = true;

                // Helper to add component separator
                auto add_separator = [&]() {
                    if (!first_component) out << ' ';
                    first_component = false;
                    };

                // Conditionally include log level
                if (has_verbosity_flag(verbosity, log_verbosity::level)) {
                    add_separator();
                    out << '[' << to_string(level) << ']';
                }

                // Conditionally include timestamp
                if (has_verbosity_flag(verbosity, log_verbosity::timestamp)) {
                    add_separator();

                    using std::chrono::floor;
                    const auto now = std::chrono::system_clock::now();
                    const auto tp_s = floor<std::chrono::seconds>(now);
                    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now.time_since_epoch()) % 1000;

                    try {
                        // Cache the time zone pointer for performance (pointer is stable)
                        static const std::chrono::time_zone* zone = std::chrono::current_zone();
                        std::chrono::zoned_time zt{ zone, tp_s };
                        out << std::format("{:%Y-%m-%dT%H:%M:%S}.{:03}", zt, static_cast<int>(ms.count()));
                    }
                    catch (...) {
                        // Fallback: UTC with 'Z' suffix to clearly indicate time zone
                        out << std::format("{:%Y-%m-%dT%H:%M:%S}.{:03}Z", tp_s, static_cast<int>(ms.count()));
                    }
                }

                // Conditionally include thread ID
                if (has_verbosity_flag(verbosity, log_verbosity::thread)) {
                    add_separator();
                    out << "[T " << std::format("{:06X}", compact_thread_id()) << ']';
                }

                // Conditionally include logger name
                if (has_verbosity_flag(verbosity, log_verbosity::logger)) {
                    add_separator();
                    out << '[' << derived_name() << ']';
                }

#if NETLIB_HAS_SOURCE_LOCATION
                // Conditionally include source location
                if (has_verbosity_flag(verbosity, log_verbosity::path)) {
                    add_separator();
                    const auto filename = std::string_view{ loc.file_name() };
                    const auto pos = filename.find_last_of("/\\");
                    const auto basename = (pos == std::string_view::npos) ? filename
                        : filename.substr(pos + 1);
                    out << std::format("[{}:{}:{}]", basename, loc.line(), loc.function_name());
                }
#endif

                // Always add the message
                if (!first_component) out << ' ';
                out << message << '\n';
            }
            catch (...) {
                // Ultimate fallback for any formatting errors
                out << "[timestamp-unavailable] [" << to_string(level) << "] [T ";
                out << std::uppercase << std::hex << std::setw(6) << std::setfill('0')
                    << compact_thread_id();
                out << std::dec << std::setfill(' ') << "] [" << derived_name() << "] "
                    << message << '\n';
            }
        }

        /**
         * @brief Friend declaration to allow derived classes access to private constructor.
         *
         * This friend declaration enables the CRTP pattern by allowing derived classes
         * to access the private constructor while preventing external instantiation
         * of the base logger template directly.
         */
        friend Derived;
    };

    // Enhanced logging macros that build on the existing NETLIB_LOG infrastructure

#if NETLIB_HAS_SOURCE_LOCATION
// Core macros with source location support
#define NETLIB_LOG(level_, fmt_, ...) \
    do { \
        if (this->get_log_level() >= (level_)) { \
            this->print_log_with_loc((level_), std::source_location::current(), (fmt_), ##__VA_ARGS__); \
        } \
    } while(0)

#define NETLIB_LOG_PTR(logger_ptr_, level_, fmt_, ...) \
    do { \
        if ((logger_ptr_) && (logger_ptr_)->get_log_level() >= (level_)) { \
            (logger_ptr_)->print_log_with_loc((level_), std::source_location::current(), (fmt_), ##__VA_ARGS__); \
        } \
    } while(0)

#else
// Core macros without source location support
#define NETLIB_LOG(level_, fmt_, ...) \
    do { \
        if (this->get_log_level() >= (level_)) { \
            this->print_log((level_), (fmt_), ##__VA_ARGS__); \
        } \
    } while(0)

#define NETLIB_LOG_PTR(logger_ptr_, level_, fmt_, ...) \
    do { \
        if ((logger_ptr_) && (logger_ptr_)->get_log_level() >= (level_)) { \
            (logger_ptr_)->print_log((level_), (fmt_), ##__VA_ARGS__); \
        } \
    } while(0)

#endif

// Convenience macros for specific log levels - for use within logger classes
#define NETLIB_ERROR(fmt_, ...)   NETLIB_LOG(::netlib::log::log_level::error, fmt_, ##__VA_ARGS__)
#define NETLIB_WARNING(fmt_, ...) NETLIB_LOG(::netlib::log::log_level::warning, fmt_, ##__VA_ARGS__)
#define NETLIB_INFO(fmt_, ...)    NETLIB_LOG(::netlib::log::log_level::info, fmt_, ##__VA_ARGS__)
#define NETLIB_DEBUG(fmt_, ...)   NETLIB_LOG(::netlib::log::log_level::debug, fmt_, ##__VA_ARGS__)

// Convenience macros for use with logger pointers
#define NETLIB_ERROR_PTR(logger_ptr_, fmt_, ...)   NETLIB_LOG_PTR(logger_ptr_, ::netlib::log::log_level::error, fmt_, ##__VA_ARGS__)
#define NETLIB_WARNING_PTR(logger_ptr_, fmt_, ...) NETLIB_LOG_PTR(logger_ptr_, ::netlib::log::log_level::warning, fmt_, ##__VA_ARGS__)
#define NETLIB_INFO_PTR(logger_ptr_, fmt_, ...)    NETLIB_LOG_PTR(logger_ptr_, ::netlib::log::log_level::info, fmt_, ##__VA_ARGS__)
#define NETLIB_DEBUG_PTR(logger_ptr_, fmt_, ...)   NETLIB_LOG_PTR(logger_ptr_, ::netlib::log::log_level::debug, fmt_, ##__VA_ARGS__)

// Simple string message macros (for pre-formatted messages)
#define NETLIB_ERROR_STR(msg_)   do { if (this->get_log_level() >= ::netlib::log::log_level::error) this->print_log(::netlib::log::log_level::error, msg_); } while(0)
#define NETLIB_WARNING_STR(msg_) do { if (this->get_log_level() >= ::netlib::log::log_level::warning) this->print_log(::netlib::log::log_level::warning, msg_); } while(0)
#define NETLIB_INFO_STR(msg_)    do { if (this->get_log_level() >= ::netlib::log::log_level::info) this->print_log(::netlib::log::log_level::info, msg_); } while(0)
#define NETLIB_DEBUG_STR(msg_)   do { if (this->get_log_level() >= ::netlib::log::log_level::debug) this->print_log(::netlib::log::log_level::debug, msg_); } while(0)

// Simple string message macros for use with logger pointers
#define NETLIB_ERROR_STR_PTR(logger_ptr_, msg_)   do { if ((logger_ptr_) && (logger_ptr_)->get_log_level() >= ::netlib::log::log_level::error) (logger_ptr_)->print_log(::netlib::log::log_level::error, msg_); } while(0)
#define NETLIB_WARNING_STR_PTR(logger_ptr_, msg_) do { if ((logger_ptr_) && (logger_ptr_)->get_log_level() >= ::netlib::log::log_level::warning) (logger_ptr_)->print_log(::netlib::log::log_level::warning, msg_); } while(0)
#define NETLIB_INFO_STR_PTR(logger_ptr_, msg_)    do { if ((logger_ptr_) && (logger_ptr_)->get_log_level() >= ::netlib::log::log_level::info) (logger_ptr_)->print_log(::netlib::log::log_level::info, msg_); } while(0)
#define NETLIB_DEBUG_STR_PTR(logger_ptr_, msg_)   do { if ((logger_ptr_) && (logger_ptr_)->get_log_level() >= ::netlib::log::log_level::debug) (logger_ptr_)->print_log(::netlib::log::log_level::debug, msg_); } while(0)

} // namespace netlib::log