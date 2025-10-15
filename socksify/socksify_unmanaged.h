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
    explicit socksify_unmanaged(log_level_mx log_level);

public:
    ~socksify_unmanaged();

    socksify_unmanaged(const socksify_unmanaged& other) = delete;
    socksify_unmanaged(socksify_unmanaged&& other) = delete;
    socksify_unmanaged& operator=(const socksify_unmanaged& other) = delete;
    socksify_unmanaged& operator=(socksify_unmanaged&& other) = delete;

    static socksify_unmanaged* get_instance(log_level_mx log_level = log_level_mx::all);

    [[nodiscard]] bool start() const;
    [[nodiscard]] bool stop() const;

    [[nodiscard]] LONG_PTR add_socks5_proxy(
        const std::string& endpoint,
        supported_protocols_mx protocol,
        bool start = false,
        const std::string& login = "",
        const std::string& password = ""
    ) const;

    [[nodiscard]] bool associate_process_name_to_proxy(
        const std::wstring& process_name,
        LONG_PTR proxy_id) const;

    bool exclude_process_name(const std::wstring& process_name) const;

    void set_log_limit(uint32_t log_limit);
    [[nodiscard]] uint32_t get_log_limit();
    void set_log_event(HANDLE log_event);
    log_storage_mx_t read_log();

    // --- NEW: wrappers for per-process destination CIDR management -----------
    [[nodiscard]] bool include_process_dst_cidr(const std::wstring& process_name,
                                                const std::string& cidr) const;
    [[nodiscard]] bool remove_process_dst_cidr(const std::wstring& process_name,
                                               const std::string& cidr) const;
    // -------------------------------------------------------------------------

private:
    static void log_printer(const char* log);
    static void log_event(event_mx log);
    void print_log(log_level_mx level, const std::string& message) const;

    log_level_mx log_level_{ log_level_mx::error };
    std::string address_;
    std::unique_ptr<proxy::socks_local_router> proxy_;
    std::unique_ptr<mutex_impl> lock_;
    std::optional<std::ofstream> pcap_log_file_;
};
