using System;
using System.Collections.Generic;
using System.Linq;

namespace ProxiFyre.Configuration
{
    [Flags]
    public enum ProxyProtocolSelection
    {
        None = 0,
        Tcp = 1,
        Udp = 2,
        Both = Tcp | Udp
    }

    [Flags]
    public enum ProxyAddressFamilySelection
    {
        None = 0,
        Ipv4 = 1,
        Ipv6 = 2,
        Both = Ipv4 | Ipv6
    }

    public enum Socks5TransportKind
    {
        Tcp,
        Tls
    }

    public enum ConfigurationLogLevel
    {
        Error,
        Warning,
        Info,
        Debug,
        All
    }

    /// <summary>
    /// Converts validated schema tokens to dependency-free shared values.
    /// </summary>
    public static class ConfigurationValueParser
    {
        public static ConfigurationLogLevel GetLogLevel(string value)
        {
            var candidate = value == null ? null : value.Trim();
            if (string.Equals(candidate, "Error", StringComparison.OrdinalIgnoreCase))
                return ConfigurationLogLevel.Error;
            if (string.Equals(candidate, "Warning", StringComparison.OrdinalIgnoreCase))
                return ConfigurationLogLevel.Warning;
            if (string.Equals(candidate, "Debug", StringComparison.OrdinalIgnoreCase))
                return ConfigurationLogLevel.Debug;
            if (string.Equals(candidate, "All", StringComparison.OrdinalIgnoreCase))
                return ConfigurationLogLevel.All;

            // Missing and every unsupported value (including numeric or combined enum text)
            // retain the engine's established Info fallback.
            return ConfigurationLogLevel.Info;
        }

        public static ProxyProtocolSelection GetProtocols(IList<string> values)
        {
            // An omitted or historically empty list means both, matching the existing engine.
            if (values == null || values.Count == 0)
                return ProxyProtocolSelection.Both;

            var result = ProxyProtocolSelection.None;
            foreach (var value in values)
            {
                if (string.Equals(value, "TCP", StringComparison.OrdinalIgnoreCase))
                    result |= ProxyProtocolSelection.Tcp;
                else if (string.Equals(value, "UDP", StringComparison.OrdinalIgnoreCase))
                    result |= ProxyProtocolSelection.Udp;
                else
                    throw new InvalidOperationException("supportedProtocols must contain only TCP and UDP.");
            }

            return result == ProxyProtocolSelection.None ? ProxyProtocolSelection.Both : result;
        }

        public static ProxyAddressFamilySelection GetAddressFamilies(IList<string> values)
        {
            if (values == null)
                return ProxyAddressFamilySelection.Both;
            if (values.Count == 0)
                throw new InvalidOperationException("supportedAddressFamilies must contain IPv4, IPv6, or both.");

            var result = ProxyAddressFamilySelection.None;
            foreach (var value in values)
            {
                if (string.Equals(value, "IPv4", StringComparison.OrdinalIgnoreCase))
                    result |= ProxyAddressFamilySelection.Ipv4;
                else if (string.Equals(value, "IPv6", StringComparison.OrdinalIgnoreCase))
                    result |= ProxyAddressFamilySelection.Ipv6;
                else
                    throw new InvalidOperationException("supportedAddressFamilies must contain only IPv4 and IPv6.");
            }

            return result;
        }

        public static Socks5TransportKind GetTransport(string value)
        {
            string canonical;
            if (!ConfigurationNormalizer.TryGetCanonicalTransport(value, out canonical))
                throw new InvalidOperationException("socks5Transport must be TCP or TLS.");
            return canonical == "TLS" ? Socks5TransportKind.Tls : Socks5TransportKind.Tcp;
        }
    }
}
