#pragma once

// Forward declarations (match underlying type : unsigned char from your mixed_types.h)
enum class log_level_mx : unsigned char;           // defined elsewhere
enum class supported_protocols_mx : unsigned char; // defined elsewhere

struct sockaddr;

#include <string>

class socksify_unmanaged
{
    explicit socksify_unmanaged(log_level_mx log_level);

public:
    ~socksify_unmanaged();

    socksify_unmanaged(const socksify_unmanaged&) = delete;
    socksify_unmanaged& operator=(const socksify_unmanaged&) = delete;

    static socksify_unmanaged* get_instance();
    static socksify_unmanaged* get_instance_with_level(log_level_mx log_level);

    bool start() const;
    bool stop() const;

    long long add_socks5_proxy(
        const std::string& endpoint,
        supported_protocols_mx protocol,
        bool start = false,
        const std::string& login = std::string(),
        const std::string& password = std::string()
    ) const;

    bool associate_process_name_to_proxy(const std::wstring& process_name, long long proxy_id) const;
    bool exclude_process_name(const std::wstring& process_name) const;

    // Inclusion API
    bool include_process_dst_cidr(const std::wstring& process_name, const std::string& cidr) const;
    bool remove_process_dst_cidr(const std::wstring& process_name, const std::string& cidr) const;
    bool include_global_dst_cidr(const std::string& cidr) const;
    bool remove_global_dst_cidr(const std::string& cidr) const;

    bool should_redirect_for(const std::wstring& process_name, const sockaddr* dst, int dstlen) const;

    // No-op logging to keep ABI stable
    void set_log_event(void*) {}
    void set_log_limit(unsigned int) {}
    unsigned int get_log_limit() { return 100; }

private:
    log_level_mx log_level_;
};
