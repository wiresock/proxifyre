using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre.Configuration
{
    public enum EndpointParseError
    {
        None,
        Missing,
        MissingHost,
        MissingPort,
        InvalidPort,
        InvalidHost,
        Ipv6UpstreamNotSupported
    }

    public sealed class ProxyEndpoint
    {
        internal ProxyEndpoint(string host, int port, bool isIpv4Literal)
        {
            Host = host;
            Port = port;
            IsIpv4Literal = isIpv4Literal;
        }

        public string Host { get; }

        public int Port { get; }

        public bool IsIpv4Literal { get; }

        public override string ToString()
        {
            return Host + ":" + Port.ToString(CultureInfo.InvariantCulture);
        }
    }

    /// <summary>
    /// Parses an upstream endpoint without performing DNS resolution.
    /// </summary>
    public static class EndpointParser
    {
        public static bool TryParse(string value, out ProxyEndpoint endpoint, out EndpointParseError error)
        {
            endpoint = null;
            error = EndpointParseError.None;

            if (string.IsNullOrWhiteSpace(value))
            {
                error = EndpointParseError.Missing;
                return false;
            }

            var candidate = value.Trim();
            if (candidate.StartsWith("[", StringComparison.Ordinal))
            {
                var closeBracket = candidate.IndexOf(']');
                if (closeBracket > 1)
                {
                    IPAddress bracketedAddress;
                    if (IPAddress.TryParse(candidate.Substring(1, closeBracket - 1), out bracketedAddress) &&
                        bracketedAddress.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        error = EndpointParseError.Ipv6UpstreamNotSupported;
                        return false;
                    }
                }

                error = EndpointParseError.InvalidHost;
                return false;
            }

            var separator = candidate.LastIndexOf(':');
            if (separator < 0)
            {
                error = EndpointParseError.MissingPort;
                return false;
            }

            var host = candidate.Substring(0, separator);
            var portText = candidate.Substring(separator + 1);
            if (host.Length == 0)
            {
                error = EndpointParseError.MissingHost;
                return false;
            }

            if (host.IndexOf(':') >= 0)
            {
                IPAddress ipv6Address;
                error = IPAddress.TryParse(host, out ipv6Address) && ipv6Address.AddressFamily == AddressFamily.InterNetworkV6
                    ? EndpointParseError.Ipv6UpstreamNotSupported
                    : EndpointParseError.InvalidHost;
                return false;
            }

            int port;
            if (portText.Length == 0)
            {
                error = EndpointParseError.MissingPort;
                return false;
            }
            if (!int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out port) || port < 1 || port > 65535)
            {
                error = EndpointParseError.InvalidPort;
                return false;
            }

            if (host.Any(c => char.IsWhiteSpace(c) || char.IsControl(c) || c == '/' || c == '\\' || c == '[' || c == ']'))
            {
                error = EndpointParseError.InvalidHost;
                return false;
            }

            IPAddress address;
            var isIpLiteral = IPAddress.TryParse(host, out address);
            if (isIpLiteral && address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                error = EndpointParseError.Ipv6UpstreamNotSupported;
                return false;
            }
            if (isIpLiteral && address.AddressFamily != AddressFamily.InterNetwork)
            {
                error = EndpointParseError.InvalidHost;
                return false;
            }

            endpoint = new ProxyEndpoint(host, port, isIpLiteral);
            return true;
        }

        public static string ExtractHost(string endpoint)
        {
            var value = (endpoint ?? string.Empty).Trim();
            if (value.StartsWith("[", StringComparison.Ordinal))
            {
                var end = value.IndexOf(']');
                return end > 1 ? value.Substring(1, end - 1) : value;
            }

            var colon = value.LastIndexOf(':');
            return colon > 0 ? value.Substring(0, colon) : value;
        }
    }
}
