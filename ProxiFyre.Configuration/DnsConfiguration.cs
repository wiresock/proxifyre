using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre.Configuration
{
    /// <summary>
    /// Global routing mode for conventional DNS (UDP and TCP port 53).
    /// </summary>
    public enum DnsRoutingMode
    {
        /// <summary>DNS bypasses every SOCKS5 proxy (default).</summary>
        Direct,

        /// <summary>DNS is sent through one selected SOCKS5 proxy, or dropped; it never leaks direct.</summary>
        Proxy
    }

    /// <summary>
    /// A parsed DNS server override.
    /// </summary>
    public sealed class DnsServerOverride
    {
        public const int DefaultPort = 53;

        internal DnsServerOverride(IPAddress address, int port)
        {
            Address = address;
            Port = port;
        }

        public IPAddress Address { get; }

        public int Port { get; }

        public bool IsIpv6 => Address.AddressFamily == AddressFamily.InterNetworkV6;

        public override string ToString()
        {
            var port = Port.ToString(CultureInfo.InvariantCulture);
            return IsIpv6 ? "[" + Address + "]:" + port : Address + ":" + port;
        }
    }

    public enum DnsServerOverrideParseError
    {
        None,
        Missing,
        InvalidPort,
        NotAnIpLiteral,
        UnusableAddress
    }

    /// <summary>
    /// DNS configuration helpers shared by the service, validator, and GUI. They never perform
    /// DNS resolution.
    /// </summary>
    public static class DnsConfiguration
    {
        public const string DirectMode = "Direct";
        public const string ProxyMode = "Proxy";

        /// <summary>Maximum length of a proxy rule identifier.</summary>
        public const int MaximumProxyIdLength = 64;

        /// <summary>
        /// The trimmed proxy id that DNS Proxy mode routes through, or null when DNS does not
        /// reference a rule (DNS omitted, Direct, an unknown mode, or no proxyId).
        /// </summary>
        public static string GetReferencedProxyId(DnsSettings settings)
        {
            DnsRoutingMode mode;
            if (settings == null || !TryGetMode(settings.Mode, out mode) || mode != DnsRoutingMode.Proxy)
                return null;
            return GetNamedProxyId(settings);
        }

        /// <summary>
        /// The trimmed dns.proxyId in any mode, or null when it is missing or blank. Direct mode
        /// keeps the selection so that switching back to Proxy mode does not lose it.
        /// </summary>
        public static string GetNamedProxyId(DnsSettings settings)
        {
            if (settings == null || string.IsNullOrWhiteSpace(settings.ProxyId))
                return null;
            return settings.ProxyId.Trim();
        }

        /// <summary>
        /// Returns the effective mode. A missing DNS section or mode means Direct.
        /// </summary>
        public static DnsRoutingMode GetMode(DnsSettings settings)
        {
            DnsRoutingMode mode;
            return TryGetMode(settings == null ? null : settings.Mode, out mode) ? mode : DnsRoutingMode.Direct;
        }

        /// <summary>
        /// Parses a mode token case-insensitively. Null or whitespace is Direct.
        /// </summary>
        public static bool TryGetMode(string value, out DnsRoutingMode mode)
        {
            var candidate = value == null ? null : value.Trim();
            if (string.IsNullOrEmpty(candidate) || string.Equals(candidate, DirectMode, StringComparison.OrdinalIgnoreCase))
            {
                mode = DnsRoutingMode.Direct;
                return true;
            }

            if (string.Equals(candidate, ProxyMode, StringComparison.OrdinalIgnoreCase))
            {
                mode = DnsRoutingMode.Proxy;
                return true;
            }

            mode = DnsRoutingMode.Direct;
            return false;
        }

        /// <summary>
        /// Proxy identifiers contain 1 to 64 letters, digits, '-', '_', or '.' characters.
        /// </summary>
        public static bool IsValidProxyId(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length > MaximumProxyIdLength)
                return false;
            return value.All(c => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                                  c == '-' || c == '_' || c == '.');
        }

        /// <summary>
        /// Creates an identifier ("proxy-1", "proxy-2", ...) that does not collide,
        /// case-insensitively, with <paramref name="existingIds"/>.
        /// </summary>
        public static string CreateUniqueProxyId(IEnumerable<string> existingIds)
        {
            var existing = new HashSet<string>(
                (existingIds ?? Enumerable.Empty<string>()).Where(id => id != null).Select(id => id.Trim()),
                StringComparer.OrdinalIgnoreCase);
            for (var index = 1; ; index++)
            {
                var candidate = "proxy-" + index.ToString(CultureInfo.InvariantCulture);
                if (!existing.Contains(candidate))
                    return candidate;
            }
        }

        /// <summary>
        /// Returns the index of the rule whose identifier equals <paramref name="proxyId"/>
        /// (case-insensitively, ignoring surrounding whitespace), or -1.
        /// </summary>
        public static int FindProxyRuleIndex(IList<ProxyRule> rules, string proxyId)
        {
            if (rules == null || string.IsNullOrWhiteSpace(proxyId))
                return -1;
            var wanted = proxyId.Trim();
            for (var index = 0; index < rules.Count; index++)
            {
                var id = rules[index] == null ? null : rules[index].Id;
                if (id != null && string.Equals(id.Trim(), wanted, StringComparison.OrdinalIgnoreCase))
                    return index;
            }
            return -1;
        }

        /// <summary>
        /// Parses a DNS server override: "1.1.1.1", "1.1.1.1:5353", "2606:4700:4700::1111",
        /// "[2606:4700:4700::1111]" or "[2606:4700:4700::1111]:5353". Host names are rejected so
        /// the override can never require DNS resolution itself. The syntax matches the native
        /// engine's split_dns_server_override().
        /// </summary>
        public static bool TryParseServerOverride(string value, out DnsServerOverride result, out DnsServerOverrideParseError error)
        {
            result = null;
            error = DnsServerOverrideParseError.None;

            if (string.IsNullOrWhiteSpace(value))
            {
                error = DnsServerOverrideParseError.Missing;
                return false;
            }

            var candidate = value.Trim();
            string addressText;
            var port = DnsServerOverride.DefaultPort;
            bool expectIpv6;

            if (candidate.StartsWith("[", StringComparison.Ordinal))
            {
                var closing = candidate.IndexOf(']');
                if (closing <= 1)
                {
                    error = DnsServerOverrideParseError.NotAnIpLiteral;
                    return false;
                }

                addressText = candidate.Substring(1, closing - 1);
                var rest = candidate.Substring(closing + 1);
                if (rest.Length > 0)
                {
                    if (rest[0] != ':' || !TryParsePort(rest.Substring(1), out port))
                    {
                        error = rest[0] == ':' ? DnsServerOverrideParseError.InvalidPort : DnsServerOverrideParseError.NotAnIpLiteral;
                        return false;
                    }
                }
                expectIpv6 = true;
            }
            else
            {
                var firstColon = candidate.IndexOf(':');
                if (firstColon < 0)
                {
                    addressText = candidate;
                    expectIpv6 = false;
                }
                else if (candidate.IndexOf(':', firstColon + 1) < 0)
                {
                    addressText = candidate.Substring(0, firstColon);
                    if (!TryParsePort(candidate.Substring(firstColon + 1), out port))
                    {
                        error = DnsServerOverrideParseError.InvalidPort;
                        return false;
                    }
                    expectIpv6 = false;
                }
                else
                {
                    addressText = candidate;
                    expectIpv6 = true;
                }
            }

            if (addressText.Length == 0 || addressText.Any(c => char.IsWhiteSpace(c) || c == '%' || c == '/' || c == '\\' || c == '[' || c == ']'))
            {
                error = DnsServerOverrideParseError.NotAnIpLiteral;
                return false;
            }

            IPAddress address;
            if (!expectIpv6)
            {
                // IPAddress.TryParse accepts shorthand such as "1" or "1.1"; the native engine
                // (inet_pton) accepts only four dotted-decimal parts, and .NET Framework reads a leading
                // zero as octal, so require four plain decimal parts here.
                var parts = addressText.Split('.');
                if (parts.Length != 4 || parts.Any(part => part.Length == 0 || part.Length > 3 || !part.All(c => c >= '0' && c <= '9') ||
                                                       (part.Length > 1 && part[0] == '0')) ||
                    !IPAddress.TryParse(addressText, out address) || address.AddressFamily != AddressFamily.InterNetwork)
                {
                    error = DnsServerOverrideParseError.NotAnIpLiteral;
                    return false;
                }

                var bytes = address.GetAddressBytes();
                if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.Broadcast) || (bytes[0] >= 224 && bytes[0] <= 239))
                {
                    error = DnsServerOverrideParseError.UnusableAddress;
                    return false;
                }
            }
            else
            {
                if (!IPAddress.TryParse(addressText, out address) || address.AddressFamily != AddressFamily.InterNetworkV6)
                {
                    error = DnsServerOverrideParseError.NotAnIpLiteral;
                    return false;
                }

                if (address.Equals(IPAddress.IPv6Any) || address.IsIPv6Multicast || address.IsIPv4MappedToIPv6)
                {
                    error = DnsServerOverrideParseError.UnusableAddress;
                    return false;
                }
            }

            result = new DnsServerOverride(address, port);
            return true;
        }

        private static bool TryParsePort(string text, out int port)
        {
            port = 0;
            return text.Length > 0 && text.Length <= 5 &&
                   int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out port) &&
                   port >= 1 && port <= 65535;
        }
    }
}
