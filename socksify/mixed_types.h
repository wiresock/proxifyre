#pragma once

enum class log_level_mx
{
    none = 0,
    info = 1,
    deb = 2,
    all = 3,
};

enum class status_mx
{
    stopped,
    connected,
    disconnected,
    error
};

enum class supported_protocols_mx
{
    tcp,
    udp,
    both
};

enum class event_type_mx : uint32_t
{
    connected,
    disconnected,
    address_error,
};

struct event_mx
{
    event_type_mx type; // event type
    size_t data; // optional data
};

using log_entry_mx_t = std::variant<std::string, event_mx>;
using log_storage_mx_t = std::vector<std::pair<long long, log_entry_mx_t>>;
