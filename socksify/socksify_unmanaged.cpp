#include "pch.h"                     // MUST be first in a /Yu "pch.h" project

#include <memory>
#include <string>

#include "socksify_unmanaged.h"
#include "policy/dest_inclusion_policy.h"

// ---- Minimal internal stub (replace with your real router if you have one) ----
namespace {
    struct router_stub {
        bool start() { return true; }
        bool stop()  { return false; }
    };
    std::unique_ptr<router_stub> g_router;
}

static log_level_mx _default_level()
{
    // Underlying type is unsigned char; treat 2 as an "Info-like" level.
    return static_cast<log_level_mx>(static_cast<unsigned char>(2));
}

socksify_unmanaged::socksify_unmanaged(log_level_mx level)
    : log_level_(level)
{
    g_router = std::make_unique<router_stub>();
}

socksify_unmanaged::~socksify_unmanaged() = default;

socksify_unmanaged* socksify_unmanaged::get_instance()
{
    static socksify_unmanaged s(_default_level());
    return &s;
}

socksify_unmanaged* socksify_unmanaged::get_instance_with_level(log_level_mx log_level)
{
    static socksify_unmanaged s(log_level);
    return &s;
}

bool socksify_unmanaged::start() const { return g_router ? g_router->start() : false; }
bool socksify_unmanaged::stop()  const { return g_router ? g_router->stop()  : false; }

long long socksify_unmanaged::add_socks5_proxy(
    const std::string& /*endpoint*/,
    const supported_protocols_mx /*protocol*/,
    const bool /*start*/,
    const std::string& /*login*/,
    const std::string& /*password*/) const
{
    // Return a dummy id to satisfy callers. Wire to your real router if needed.
    return 0;
}

bool socksify_unmanaged::associate_process_name_to_proxy(const std::wstring& /*process_name*/, const long long /*proxy_id*/) const
{
    return true;
}

bool socksify_unmanaged::exclude_process_name(const std::wstring& /*process_name*/) const
{
    return true;
}

// ---------- Inclusion API forwards ----------
bool socksify_unmanaged::include_process_dst_cidr(const std::wstring& process_name, const std::string& cidr) const
{
    return dip_add_process(process_name.c_str(), cidr.c_str()) == 1;
}
bool socksify_unmanaged::remove_process_dst_cidr(const std::wstring& process_name, const std::string& cidr) const
{
    return dip_remove_process(process_name.c_str(), cidr.c_str()) == 1;
}
bool socksify_unmanaged::include_global_dst_cidr(const std::string& cidr) const
{
    return dip_add_global(cidr.c_str()) == 1;
}
bool socksify_unmanaged::remove_global_dst_cidr(const std::string& cidr) const
{
    return dip_remove_global(cidr.c_str()) == 1;
}

bool socksify_unmanaged::should_redirect_for(const std::wstring& process_name, const sockaddr* dst, const int dstlen) const
{
    return dip_should_redirect_for(process_name.c_str(), dst, dstlen) == 1;
}
