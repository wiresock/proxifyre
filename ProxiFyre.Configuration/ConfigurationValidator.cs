using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace ProxiFyre.Configuration
{
    /// <summary>
    /// Returns structured diagnostics without logging or changing the supplied model.
    /// </summary>
    public sealed class ConfigurationValidator
    {
        /// <summary>
        /// RFC 1929 stores each authentication field behind a single-byte length.
        /// The C++/CLI bridge marshals managed credentials through the Windows ANSI
        /// encoding before enforcing this limit.
        /// </summary>
        public const int Socks5CredentialMaximumEncodedBytes = 255;

        private const uint ThreadAnsiCodePage = 3;
        private const uint NoBestFitCharacters = 0x00000400;
        private static readonly string[] SupportedLogLevels = { "Error", "Warning", "Info", "Debug", "All" };

        public ValidationResult Validate(ProxiFyreConfiguration configuration)
        {
            var issues = new List<ValidationIssue>();
            if (configuration == null)
            {
                issues.Add(Error("CONFIGURATION_NULL", "The configuration contains no settings.", null));
                return new ValidationResult(issues);
            }

            ValidateLogLevel(configuration.LogLevel, issues);
            ValidateExclusions(configuration.Excludes, issues);

            if (configuration.Proxies == null)
            {
                issues.Add(Error("PROXIES_MISSING", "The required proxies property is missing.", "proxies"));
                return new ValidationResult(issues);
            }
            if (configuration.Proxies.Count == 0)
            {
                issues.Add(Error("PROXIES_EMPTY", "At least one proxy rule must be configured.", "proxies"));
                return new ValidationResult(issues);
            }

            for (var index = 0; index < configuration.Proxies.Count; index++)
            {
                var rule = configuration.Proxies[index];
                if (rule == null)
                {
                    issues.Add(Error(
                        "PROXY_NULL",
                        "The proxy list contains a null entry. Remove it or replace it with a valid rule.",
                        RulePath(index),
                        index));
                    continue;
                }

                ValidateSingleRule(rule, index, issues);
            }

            ValidateCatchAllOrdering(configuration.Proxies, issues);
            ValidateApplicationOverlap(configuration.Proxies, issues);
            return new ValidationResult(issues);
        }

        public ValidationResult ValidateRule(ProxyRule rule, int? proxyRuleIndex = null)
        {
            var issues = new List<ValidationIssue>();
            if (rule == null)
            {
                issues.Add(Error(
                    "PROXY_NULL",
                    "The proxy rule is null.",
                    proxyRuleIndex.HasValue ? RulePath(proxyRuleIndex.Value) : "proxy",
                    proxyRuleIndex));
            }
            else
            {
                ValidateSingleRule(rule, proxyRuleIndex, issues);
            }
            return new ValidationResult(issues);
        }

        private static void ValidateLogLevel(string value, ICollection<ValidationIssue> issues)
        {
            if (string.IsNullOrWhiteSpace(value))
                return; // The engine's established fallback is Info.

            if (!SupportedLogLevels.Any(level => string.Equals(level, value.Trim(), StringComparison.OrdinalIgnoreCase)))
            {
                issues.Add(Warning(
                    "LOG_LEVEL_UNKNOWN",
                    "The log level is not recognized and the engine will use Info. Supported values are Error, Warning, Info, Debug, and All.",
                    "logLevel"));
            }
        }

        private static void ValidateExclusions(IList<string> excludes, ICollection<ValidationIssue> issues)
        {
            if (excludes == null)
                return;

            for (var index = 0; index < excludes.Count; index++)
            {
                if (string.IsNullOrWhiteSpace(excludes[index]))
                {
                    issues.Add(Warning(
                        "EXCLUSION_BLANK",
                        "Null and whitespace-only exclusions are ignored.",
                        "excludes[" + index + "]"));
                }
            }
        }

        private static void ValidateSingleRule(ProxyRule rule, int? index, ICollection<ValidationIssue> issues)
        {
            var prefix = index.HasValue ? RulePath(index.Value) : "proxy";

            ProxyEndpoint endpoint;
            EndpointParseError endpointError;
            if (!EndpointParser.TryParse(rule.Socks5ProxyEndpoint, out endpoint, out endpointError))
            {
                var code = "ENDPOINT_INVALID";
                var message = "The SOCKS5 endpoint must contain a hostname or IPv4 address and a port from 1 to 65535.";
                if (endpointError == EndpointParseError.Missing)
                {
                    code = "ENDPOINT_MISSING";
                    message = "A non-empty SOCKS5 proxy endpoint is required.";
                }
                else if (endpointError == EndpointParseError.InvalidPort || endpointError == EndpointParseError.MissingPort)
                {
                    code = "ENDPOINT_PORT_INVALID";
                    message = "The SOCKS5 endpoint port must be an integer from 1 to 65535.";
                }
                else if (endpointError == EndpointParseError.Ipv6UpstreamNotSupported)
                {
                    code = "ENDPOINT_IPV6_UNSUPPORTED";
                    message = "The current engine cannot connect to an IPv6-literal SOCKS5 endpoint; use an IPv4 address or a hostname with an A record.";
                }

                issues.Add(Error(code, message, prefix + ".socks5ProxyEndpoint", index));
            }

            var hasUsername = !string.IsNullOrEmpty(rule.Username);
            var hasPassword = !string.IsNullOrEmpty(rule.Password);
            if (hasUsername && !hasPassword)
            {
                issues.Add(Error(
                    "AUTH_PASSWORD_MISSING",
                    "A password is required when a username is configured.",
                    prefix + ".password",
                    index));
            }
            else if (!hasUsername && hasPassword)
            {
                issues.Add(Error(
                    "AUTH_USERNAME_MISSING",
                    "A username is required when a password is configured.",
                    prefix + ".username",
                    index));
            }

            ValidateCredentialLength(
                rule.Username,
                "AUTH_USERNAME_TOO_LONG",
                "The username must encode to no more than 255 bytes for SOCKS5 authentication.",
                prefix + ".username",
                index,
                issues);
            ValidateCredentialLength(
                rule.Password,
                "AUTH_PASSWORD_TOO_LONG",
                "The password must encode to no more than 255 bytes for SOCKS5 authentication.",
                prefix + ".password",
                index,
                issues);

            ValidateApplications(rule.AppNames, prefix, index, issues);
            ValidateProtocols(rule.SupportedProtocols, prefix, index, issues);
            ValidateAddressFamilies(rule.SupportedAddressFamilies, prefix, index, issues);
            ValidateTransportAndTls(rule, prefix, index, issues);
        }

        private static void ValidateCredentialLength(
            string value,
            string code,
            string message,
            string path,
            int? ruleIndex,
            ICollection<ValidationIssue> issues)
        {
            if (string.IsNullOrEmpty(value))
                return;

            // These arguments match msclr::interop::marshal_as<std::string>, so the
            // service validates the bytes its unmanaged SOCKS5 layer will receive.
            var encodedByteCount = WideCharToMultiByte(
                ThreadAnsiCodePage,
                NoBestFitCharacters,
                value,
                value.Length,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                IntPtr.Zero);
            if (encodedByteCount == 0 || encodedByteCount > Socks5CredentialMaximumEncodedBytes)
                issues.Add(Error(code, message, path, ruleIndex));
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern int WideCharToMultiByte(
            uint codePage,
            uint flags,
            string wideCharacters,
            int wideCharacterCount,
            IntPtr multiByteCharacters,
            int multiByteCharacterCapacity,
            IntPtr defaultCharacter,
            IntPtr usedDefaultCharacter);

        private static void ValidateApplications(
            IList<string> appNames,
            string prefix,
            int? ruleIndex,
            ICollection<ValidationIssue> issues)
        {
            if (appNames == null || appNames.Count == 0)
            {
                issues.Add(Warning(
                    "APP_NAMES_EMPTY",
                    "This rule has no application matches and will not match any process.",
                    prefix + ".appNames",
                    ruleIndex));
                return;
            }

            var meaningfulCount = 0;
            var catchAllCount = 0;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (var index = 0; index < appNames.Count; index++)
            {
                var appName = appNames[index];
                if (appName == string.Empty)
                {
                    meaningfulCount++;
                    catchAllCount++;
                    continue;
                }
                if (string.IsNullOrWhiteSpace(appName))
                {
                    issues.Add(Warning(
                        "APP_NAME_WHITESPACE",
                        "Null and whitespace-only application matches are ignored. An explicit empty string, not spaces, is the catch-all.",
                        prefix + ".appNames[" + index + "]",
                        ruleIndex));
                    continue;
                }

                meaningfulCount++;
                if (!seen.Add(appName))
                {
                    issues.Add(Warning(
                        "APP_MATCH_DUPLICATE",
                        "This application match is duplicated within the same rule.",
                        prefix + ".appNames[" + index + "]",
                        ruleIndex));
                }
            }

            if (meaningfulCount == 0)
            {
                issues.Add(Warning(
                    "APP_NAMES_EMPTY",
                    "After blank entries are removed, this rule has no application matches.",
                    prefix + ".appNames",
                    ruleIndex));
            }
            if (catchAllCount > 1)
            {
                issues.Add(Warning(
                    "CATCH_ALL_DUPLICATE_IN_RULE",
                    "This rule contains the catch-all more than once; only one explicit empty string is needed.",
                    prefix + ".appNames",
                    ruleIndex));
            }
        }

        private static void ValidateProtocols(
            IList<string> protocols,
            string prefix,
            int? ruleIndex,
            ICollection<ValidationIssue> issues)
        {
            if (protocols == null)
                return; // Omitted means both for backward compatibility.
            if (protocols.Count == 0)
            {
                issues.Add(Warning(
                    "PROTOCOLS_EMPTY_LEGACY",
                    "An explicit empty protocol list is treated as TCP and UDP for compatibility. Newly edited rules should select at least one protocol.",
                    prefix + ".supportedProtocols",
                    ruleIndex));
                return;
            }

            for (var index = 0; index < protocols.Count; index++)
            {
                var value = protocols[index];
                if (!string.Equals(value, "TCP", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(value, "UDP", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add(Error(
                        "PROTOCOL_UNKNOWN",
                        "Only TCP and UDP are valid protocol values; an unknown value must not silently enable both protocols.",
                        prefix + ".supportedProtocols[" + index + "]",
                        ruleIndex));
                }
            }
        }

        private static void ValidateAddressFamilies(
            IList<string> families,
            string prefix,
            int? ruleIndex,
            ICollection<ValidationIssue> issues)
        {
            if (families == null)
                return; // Omitted means both.
            if (families.Count == 0)
            {
                issues.Add(Error(
                    "ADDRESS_FAMILIES_EMPTY",
                    "Select IPv4, IPv6, or both; omit the property to retain the legacy both-families default.",
                    prefix + ".supportedAddressFamilies",
                    ruleIndex));
                return;
            }

            for (var index = 0; index < families.Count; index++)
            {
                var value = families[index];
                if (!string.Equals(value, "IPv4", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(value, "IPv6", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add(Error(
                        "ADDRESS_FAMILY_UNKNOWN",
                        "Only IPv4 and IPv6 are valid address-family values.",
                        prefix + ".supportedAddressFamilies[" + index + "]",
                        ruleIndex));
                }
            }
        }

        private static void ValidateTransportAndTls(
            ProxyRule rule,
            string prefix,
            int? ruleIndex,
            ICollection<ValidationIssue> issues)
        {
            string transport;
            if (!ConfigurationNormalizer.TryGetCanonicalTransport(rule.Socks5Transport, out transport))
            {
                issues.Add(Error(
                    "TRANSPORT_UNKNOWN",
                    "The SOCKS5 transport must be TCP or TLS.",
                    prefix + ".socks5Transport",
                    ruleIndex));
                return;
            }

            if (transport != "TLS")
                return;

            if (!string.IsNullOrWhiteSpace(rule.TlsPinnedSha256))
            {
                var fingerprint = ConfigurationNormalizer.NormalizeFingerprint(rule.TlsPinnedSha256);
                if (fingerprint.Length != 64 || !fingerprint.All(Uri.IsHexDigit))
                {
                    issues.Add(Error(
                        "TLS_PIN_INVALID",
                        "The certificate pin must contain exactly 64 hexadecimal SHA-256 characters after separators are removed.",
                        prefix + ".tlsPinnedSha256",
                        ruleIndex));
                }
            }

            if (rule.TlsAllowInvalidCertificate)
            {
                var hasPin = !string.IsNullOrWhiteSpace(rule.TlsPinnedSha256);
                issues.Add(Warning(
                    hasPin ? "TLS_INVALID_CERTIFICATE_ALLOWED" : "TLS_IDENTITY_VERIFICATION_DISABLED",
                    hasPin
                        ? "Normal TLS certificate validation is disabled. The configured certificate pin remains the identity check."
                        : "Invalid TLS certificates are allowed without a pin. Upstream identity verification is completely disabled.",
                    prefix + ".tlsAllowInvalidCertificate",
                    ruleIndex));
            }
        }

        private static void ValidateCatchAllOrdering(IList<ProxyRule> rules, ICollection<ValidationIssue> issues)
        {
            var catchAllRules = new List<int>();
            for (var index = 0; index < rules.Count; index++)
            {
                var rule = rules[index];
                if (rule != null && rule.AppNames != null && rule.AppNames.Contains(string.Empty))
                {
                    catchAllRules.Add(index);
                    if (index < rules.Count - 1)
                    {
                        issues.Add(Warning(
                            "CATCH_ALL_NOT_LAST",
                            "This catch-all rule shadows every rule after it because the first matching proxy wins. Move it last.",
                            RulePath(index) + ".appNames",
                            index));
                    }
                }
            }

            if (catchAllRules.Count > 1)
            {
                foreach (var index in catchAllRules.Skip(1))
                {
                    issues.Add(Warning(
                        "MULTIPLE_CATCH_ALL_RULES",
                        "Multiple catch-all rules are configured; only the first effective catch-all can be reached.",
                        RulePath(index) + ".appNames",
                        index));
                }
            }
        }

        private static void ValidateApplicationOverlap(IList<ProxyRule> rules, ICollection<ValidationIssue> issues)
        {
            var previous = new List<ApplicationMatch>();
            for (var ruleIndex = 0; ruleIndex < rules.Count; ruleIndex++)
            {
                var rule = rules[ruleIndex];
                if (rule == null || rule.AppNames == null)
                    continue;

                var currentRuleMatches = new List<ApplicationMatch>();

                for (var appIndex = 0; appIndex < rule.AppNames.Count; appIndex++)
                {
                    var value = rule.AppNames[appIndex];
                    if (string.IsNullOrWhiteSpace(value))
                        continue;

                    var shadowingMatch = previous.FirstOrDefault(item => MatchesOverlap(item.Value, value));
                    if (shadowingMatch != null)
                    {
                        issues.Add(Warning(
                            "APP_MATCH_SHADOWED",
                            "This application match overlaps an earlier match in rule " +
                            (shadowingMatch.RuleIndex + 1) + "; the earlier rule wins.",
                            RulePath(ruleIndex) + ".appNames[" + appIndex + "]",
                            ruleIndex));
                    }

                    currentRuleMatches.Add(new ApplicationMatch(ruleIndex, value));
                }

                // Duplicate matches within one rule are diagnosed separately by
                // ValidateApplications. Only prior rules can win because of ordering.
                previous.AddRange(currentRuleMatches);
            }
        }

        private static bool MatchesOverlap(string left, string right)
        {
            if (string.Equals(left, right, StringComparison.OrdinalIgnoreCase))
                return true;

            var leftIsPath = left.IndexOf('/') >= 0 || left.IndexOf('\\') >= 0;
            var rightIsPath = right.IndexOf('/') >= 0 || right.IndexOf('\\') >= 0;
            if (leftIsPath && rightIsPath)
            {
                return left.IndexOf(right, StringComparison.OrdinalIgnoreCase) >= 0 ||
                       right.IndexOf(left, StringComparison.OrdinalIgnoreCase) >= 0;
            }
            if (leftIsPath || rightIsPath)
            {
                var pathValue = leftIsPath ? left : right;
                var nameValue = leftIsPath ? right : left;
                var pathTail = GetPathTail(pathValue);
                return !string.IsNullOrEmpty(pathTail) && NameMatchesOverlap(pathTail, nameValue);
            }

            return NameMatchesOverlap(left, right);
        }

        private static bool NameMatchesOverlap(string left, string right)
        {
            return string.Equals(left, right, StringComparison.OrdinalIgnoreCase) ||
                   left.StartsWith(right + ".", StringComparison.OrdinalIgnoreCase) ||
                   right.StartsWith(left + ".", StringComparison.OrdinalIgnoreCase);
        }

        private static string GetPathTail(string value)
        {
            var lastSlash = Math.Max(value.LastIndexOf('/'), value.LastIndexOf('\\'));
            return lastSlash >= 0 && lastSlash < value.Length - 1
                ? value.Substring(lastSlash + 1)
                : lastSlash < 0 ? value : string.Empty;
        }

        private static string RulePath(int index)
        {
            return "proxies[" + index + "]";
        }

        private static ValidationIssue Error(string code, string message, string path, int? ruleIndex = null)
        {
            return new ValidationIssue(ValidationSeverity.Error, code, message, path, ruleIndex);
        }

        private static ValidationIssue Warning(string code, string message, string path, int? ruleIndex = null)
        {
            return new ValidationIssue(ValidationSeverity.Warning, code, message, path, ruleIndex);
        }

        private sealed class ApplicationMatch
        {
            public ApplicationMatch(int ruleIndex, string value)
            {
                RuleIndex = ruleIndex;
                Value = value;
            }

            public int RuleIndex { get; }

            public string Value { get; }
        }
    }
}
