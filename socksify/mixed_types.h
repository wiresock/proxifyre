#pragma once

/**
 * @brief Specifies the logging level for the unmanaged Socksifier core.
 *
 * This enum is intended to be typecasted from the managed LogLevel enum in Socksifier.h.
 * The values are chosen to match the managed LogLevel for direct casting.
 */
enum class log_level_mx : uint8_t
{
    /// <summary>Error messages only.</summary>
    error = 0,
    /// <summary>Warning and error messages.</summary>
    warning = 1,
    /// <summary>Informational, warning, and error messages.</summary>
    info = 2,
    /// <summary>Debug, informational, warning, and error messages.</summary>
    deb = 4,
    /// <summary>All log messages.</summary>
    all = 255,
};

/**
 * @brief Represents the status of the proxy gateway.
 */
enum class status_mx : uint8_t
{
    /// <summary>The gateway is stopped.</summary>
    stopped = 0,
    /// <summary>The gateway is connected.</summary>
    connected = 1,
    /// <summary>The gateway is disconnected.</summary>
    disconnected = 2,
    /// <summary>An error has occurred in the gateway.</summary>
    error = 3
};

/**
 * @brief Specifies the supported protocols for proxying.
 */
enum class supported_protocols_mx : uint8_t
{
    /// <summary>TCP protocol only.</summary>
    tcp = 0,
    /// <summary>UDP protocol only.</summary>
    udp = 1,
    /// <summary>Both TCP and UDP protocols.</summary>
    both = 2
};

/**
 * @brief Enumerates the types of events that can occur in the proxy gateway.
 */
enum class event_type_mx : uint32_t
{
    /// <summary>The gateway has connected.</summary>
    connected = 0,
    /// <summary>The gateway has disconnected.</summary>
    disconnected = 1,
    /// <summary>An address error event.</summary>
    address_error = 2,
};

/**
 * @brief Represents a loggable event with type and optional data.
 */
struct event_mx
{
    event_type_mx type; ///< Event type
    size_t data;        ///< Optional data
};

using log_entry_mx_t = std::variant<std::string, event_mx>;
using log_storage_mx_t = std::vector<std::pair<long long, log_entry_mx_t>>;