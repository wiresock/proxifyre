#pragma once

/**
 * @brief Forward declaration for a platform-specific mutex implementation.
 */
struct mutex_impl;

namespace proxy
{
    /**
     * @brief Forward declaration for the SOCKS local router class.
     */
    class socks_local_router;
}

/**
 * @brief Manages the lifecycle and configuration of the unmanaged SOCKS proxy gateway.
 *
 * This class provides a singleton interface for starting/stopping the proxy gateway,
 * adding SOCKS5 proxies, associating processes to proxies, and managing logging.
 * It wraps the core proxy logic and exposes thread-safe methods for integration
 * with managed and unmanaged code.
 */
class socksify_unmanaged
{
    /**
     * @brief Constructs a socksify_unmanaged instance with the specified log level.
     * @param log_level The logging level to use for the proxy gateway.
     */
    explicit socksify_unmanaged(log_level_mx log_level);

public:
    /**
     * @brief Destructor for socksify_unmanaged. Cleans up resources.
     */
    ~socksify_unmanaged();

    // Deleted copy/move constructors and assignment operators to enforce singleton semantics.
    socksify_unmanaged(const socksify_unmanaged& other) = delete;
    socksify_unmanaged(socksify_unmanaged&& other) = delete;
    socksify_unmanaged& operator=(const socksify_unmanaged& other) = delete;
    socksify_unmanaged& operator=(socksify_unmanaged&& other) = delete;

    /**
     * @brief Gets the singleton instance of socksify_unmanaged.
     * @param log_level The logging level to use (default: log_level_mx::all).
     * @return Pointer to the singleton instance.
     */
    static socksify_unmanaged* get_instance(log_level_mx log_level = log_level_mx::all);

    /**
     * @brief Starts the proxy gateway and network filter.
     * @return True if started successfully, false otherwise.
     */
    [[nodiscard]] bool start() const;

    /**
     * @brief Stops the proxy gateway and network filter.
     * @return True if stopped successfully, false otherwise.
     */
    [[nodiscard]] bool stop() const;

    /**
     * @brief Adds a SOCKS5 proxy to the gateway.
     * @param endpoint The proxy endpoint in "IP:Port" format.
     * @param protocol The supported protocol(s) for the proxy.
     * @param start Whether to start the proxy immediately.
     * @param login Optional username for authentication.
     * @param password Optional password for authentication.
     * @return A handle (LONG_PTR) to the proxy instance, or 0 on failure.
     */
    [[nodiscard]] LONG_PTR add_socks5_proxy(
        const std::string& endpoint,
        supported_protocols_mx protocol,
        bool start = false,
        const std::string& login = "",
        const std::string& password = ""
    ) const;

    /**
     * @brief Associates a process name with a specific proxy.
     * @param process_name The process name to associate.
     * @param proxy_id The handle of the proxy to associate with.
     * @return True if association was successful, false otherwise.
     */
    [[nodiscard]] bool associate_process_name_to_proxy(
        const std::wstring& process_name,
        LONG_PTR proxy_id) const;
    bool exclude_process_name(const std::wstring& process_name) const;

    /**
     * @brief Sets the maximum number of log entries to keep.
     * @param log_limit The new log limit.
     */
    void set_log_limit(uint32_t log_limit);

    /**
     * @brief Gets the current log limit.
     * @return The log limit.
     */
    [[nodiscard]] uint32_t get_log_limit();

    /**
     * @brief Sets the event handle to signal when log limit is exceeded.
     * @param log_event The Windows event handle.
     */
    void set_log_event(HANDLE log_event);

    /**
     * @brief Reads and clears the log storage.
     * @return The log storage as a log_storage_mx_t object.
     */
    log_storage_mx_t read_log();

private:
    /**
     * @brief Static helper for printing log messages.
     * @param log The message to log.
     */
    static void log_printer(const char* log);

    /**
     * @brief Static helper for logging events.
     * @param log The event to log.
     */
    static void log_event(event_mx log);

    /**
     * @brief Prints a log message at the specified log level.
     * @param level The log level.
     * @param message The message to print.
     */
    void print_log(log_level_mx level, const std::string& message) const;

    log_level_mx log_level_{ log_level_mx::error }; ///< The current log level.
    std::string address_; ///< The address for the proxy (if applicable).
    std::unique_ptr<proxy::socks_local_router> proxy_; ///< The core proxy router instance.
    std::unique_ptr<mutex_impl> lock_; ///< Mutex for thread safety.

    /// <summary>
    /// Optional output file stream for logging pcap data.
    /// </summary>
    std::optional<std::ofstream> pcap_log_file_;
};