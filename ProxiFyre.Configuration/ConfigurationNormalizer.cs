using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ProxiFyre.Configuration
{
    /// <summary>
    /// Produces a canonical copy without changing rule ordering or meaningful match text.
    /// Validate before normalizing so malformed tokens remain visible to the caller.
    /// </summary>
    public sealed class ConfigurationNormalizer
    {
        private static readonly string[] LogLevels = { "Error", "Warning", "Info", "Debug", "All" };

        public ProxiFyreConfiguration Normalize(ProxiFyreConfiguration configuration)
        {
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration));

            var result = new ProxiFyreConfiguration
            {
                LogLevel = NormalizeLogLevel(configuration.LogLevel),
                BypassLan = configuration.BypassLan,
                Proxies = configuration.Proxies == null
                    ? null
                    : configuration.Proxies.Select(rule => rule == null ? null : NormalizeRule(rule)).ToList(),
                Excludes = configuration.Excludes == null
                    ? new List<string>()
                    : configuration.Excludes.Where(value => !string.IsNullOrWhiteSpace(value)).ToList(),
                Dns = configuration.Dns == null ? null : NormalizeDns(configuration.Dns),
                ExtensionData = CloneExtensionData(configuration.ExtensionData)
            };

            DropUnusedInvalidProxyIds(result.Proxies, DnsConfiguration.GetReferencedProxyId(configuration.Dns));
            return result;
        }

        /// <summary>
        /// Removes ids that the validator reports only as warnings: an invalid id, or a repeat of an
        /// earlier rule's id, that DNS Proxy mode does not reference. They have no effect, and
        /// dropping them lets a saved configuration clear the warning. An id DNS references is
        /// kept, because the validator reports it as an error instead.
        /// </summary>
        private static void DropUnusedInvalidProxyIds(IList<ProxyRule> rules, string referencedId)
        {
            if (rules == null)
                return;

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var rule in rules)
            {
                if (rule == null || rule.Id == null)
                    continue;

                var referenced = referencedId != null &&
                                 string.Equals(rule.Id, referencedId, StringComparison.OrdinalIgnoreCase);
                if (!DnsConfiguration.IsValidProxyId(rule.Id))
                {
                    if (!referenced)
                        rule.Id = null;
                    continue;
                }

                if (!seen.Add(rule.Id) && !referenced)
                    rule.Id = null;
            }
        }

        public DnsSettings NormalizeDns(DnsSettings dns)
        {
            if (dns == null)
                throw new ArgumentNullException(nameof(dns));

            var mode = dns.Mode == null ? null : dns.Mode.Trim();
            DnsRoutingMode parsed;
            if (DnsConfiguration.TryGetMode(mode, out parsed))
                mode = parsed == DnsRoutingMode.Proxy ? DnsConfiguration.ProxyMode : DnsConfiguration.DirectMode;

            return new DnsSettings
            {
                Mode = mode,
                ProxyId = EmptyToNull(dns.ProxyId),
                ServerOverride = EmptyToNull(dns.ServerOverride),
                ExtensionData = CloneExtensionData(dns.ExtensionData)
            };
        }

        private static string EmptyToNull(string value)
        {
            if (value == null)
                return null;
            var trimmed = value.Trim();
            return trimmed.Length == 0 ? null : trimmed;
        }

        public ProxyRule NormalizeRule(ProxyRule rule)
        {
            if (rule == null)
                throw new ArgumentNullException(nameof(rule));

            var appNames = new List<string>();
            var catchAllAdded = false;
            if (rule.AppNames != null)
            {
                foreach (var appName in rule.AppNames)
                {
                    if (appName == string.Empty)
                    {
                        if (!catchAllAdded)
                        {
                            appNames.Add(string.Empty);
                            catchAllAdded = true;
                        }
                    }
                    else if (!string.IsNullOrWhiteSpace(appName))
                    {
                        appNames.Add(appName);
                    }
                }
            }

            string transport;
            var hasCanonicalTransport = TryGetCanonicalTransport(rule.Socks5Transport, out transport);
            return new ProxyRule
            {
                Id = EmptyToNull(rule.Id),
                AppNames = appNames,
                Socks5ProxyEndpoint = rule.Socks5ProxyEndpoint == null ? null : rule.Socks5ProxyEndpoint.Trim(),
                Username = rule.Username,
                Password = rule.Password,
                Socks5Transport = hasCanonicalTransport ? transport : rule.Socks5Transport,
                TlsServerName = rule.TlsServerName == null ? null : rule.TlsServerName.Trim(),
                TlsPinnedSha256 = NormalizeOptionalFingerprint(rule.TlsPinnedSha256),
                TlsAllowInvalidCertificate = rule.TlsAllowInvalidCertificate,
                SupportedProtocols = CanonicalizeList(rule.SupportedProtocols, new[] { "TCP", "UDP" }),
                SupportedAddressFamilies = CanonicalizeList(rule.SupportedAddressFamilies, new[] { "IPv4", "IPv6" }),
                ExtensionData = CloneExtensionData(rule.ExtensionData)
            };
        }

        public static string NormalizeFingerprint(string value)
        {
            return new string((value ?? string.Empty)
                .Where(c => c != ':' && c != '-' && !char.IsWhiteSpace(c))
                .Select(char.ToLowerInvariant)
                .ToArray());
        }

        public static bool TryGetCanonicalTransport(string value, out string canonical)
        {
            var transport = value == null ? null : value.Trim();
            if (string.IsNullOrEmpty(transport) ||
                string.Equals(transport, "TCP", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(transport, "Plain", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(transport, "SOCKS5", StringComparison.OrdinalIgnoreCase))
            {
                canonical = "TCP";
                return true;
            }

            if (string.Equals(transport, "TLS", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(transport, "SOCKS5TLS", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(transport, "SOCKS5_TLS", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(transport, "SOCKS5-TLS", StringComparison.OrdinalIgnoreCase))
            {
                canonical = "TLS";
                return true;
            }

            canonical = null;
            return false;
        }

        private static List<string> CanonicalizeList(IList<string> values, string[] canonicalValues)
        {
            if (values == null)
                return null;

            var result = new List<string>();
            foreach (var value in values)
            {
                var canonical = Canonicalize(value, canonicalValues);
                var output = canonical ?? value;
                if (!result.Any(existing => string.Equals(existing, output, StringComparison.OrdinalIgnoreCase)))
                    result.Add(output);
            }
            return result;
        }

        private static string NormalizeLogLevel(string value)
        {
            if (value == null)
                return null;
            var trimmed = value.Trim();
            return Canonicalize(trimmed, LogLevels) ?? trimmed;
        }

        private static string NormalizeOptionalFingerprint(string value)
        {
            if (value == null)
                return null;
            var normalized = NormalizeFingerprint(value);
            return normalized.Length == 0 ? null : normalized;
        }

        private static string Canonicalize(string value, IEnumerable<string> canonicalValues)
        {
            return canonicalValues.FirstOrDefault(item => string.Equals(item, value, StringComparison.OrdinalIgnoreCase));
        }

        private static IDictionary<string, JToken> CloneExtensionData(IDictionary<string, JToken> source)
        {
            var result = new Dictionary<string, JToken>(StringComparer.Ordinal);
            if (source == null)
                return result;

            foreach (var item in source)
                result[item.Key] = item.Value == null ? null : item.Value.DeepClone();
            return result;
        }
    }
}
