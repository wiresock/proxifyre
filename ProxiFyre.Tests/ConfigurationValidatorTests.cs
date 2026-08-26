using NUnit.Framework;
using ProxiFyre.Configuration;
using System.Collections.Generic;
using System.Linq;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class ConfigurationValidatorTests
    {
        private readonly ConfigurationValidator _validator = new ConfigurationValidator();

        [Test]
        public void MissingAndEmptyProxyListsHaveDistinctErrors()
        {
            var missing = TestModels.ValidConfiguration();
            missing.Proxies = null;
            var empty = TestModels.ValidConfiguration();
            empty.Proxies.Clear();

            HasIssue(_validator.Validate(missing), "PROXIES_MISSING", ValidationSeverity.Error);
            HasIssue(_validator.Validate(empty), "PROXIES_EMPTY", ValidationSeverity.Error);
        }

        [Test]
        public void NullProxyEntryIsAnError()
        {
            var configuration = TestModels.ValidConfiguration();
            configuration.Proxies[0] = null;

            HasIssue(_validator.Validate(configuration), "PROXY_NULL", ValidationSeverity.Error);
        }

        [TestCase(null, "ENDPOINT_MISSING")]
        [TestCase("", "ENDPOINT_MISSING")]
        [TestCase("proxy.example.com", "ENDPOINT_PORT_INVALID")]
        [TestCase("proxy.example.com:0", "ENDPOINT_PORT_INVALID")]
        [TestCase("proxy.example.com:65536", "ENDPOINT_PORT_INVALID")]
        [TestCase("[2001:db8::1]:1080", "ENDPOINT_IPV6_UNSUPPORTED")]
        [TestCase("2001:db8::1:1080", "ENDPOINT_IPV6_UNSUPPORTED")]
        public void InvalidEndpointsAreRejectedWithoutDnsLookup(string endpoint, string expectedCode)
        {
            var rule = TestModels.ValidRule();
            rule.Socks5ProxyEndpoint = endpoint;

            HasIssue(_validator.ValidateRule(rule), expectedCode, ValidationSeverity.Error);
        }

        [TestCase("127.0.0.1:1")]
        [TestCase("proxy.example.com:65535")]
        [TestCase("localhost:1080")]
        public void HostnamesAndIpv4EndpointsAreAccepted(string endpoint)
        {
            var rule = TestModels.ValidRule();
            rule.Socks5ProxyEndpoint = endpoint;

            NoIssueWithPrefix(_validator.ValidateRule(rule), "ENDPOINT_");
        }

        [Test]
        public void AuthenticationRequiresBothFieldsAndNeverIncludesPasswordInDiagnostics()
        {
            var rule = TestModels.ValidRule();
            rule.Username = "user";
            rule.Password = null;
            HasIssue(_validator.ValidateRule(rule), "AUTH_PASSWORD_MISSING", ValidationSeverity.Error);

            rule.Username = null;
            rule.Password = "top-secret-value";
            var result = _validator.ValidateRule(rule);
            HasIssue(result, "AUTH_USERNAME_MISSING", ValidationSeverity.Error);
            Assert.That(result.Issues.All(issue => !issue.Message.Contains("top-secret-value")), Is.True);
        }

        [Test]
        public void WhitespaceApplicationIsIgnoredButExplicitEmptyStringIsCatchAll()
        {
            var whitespace = TestModels.ValidRule();
            whitespace.AppNames = new List<string> { "   " };
            var whitespaceResult = _validator.ValidateRule(whitespace);
            HasIssue(whitespaceResult, "APP_NAME_WHITESPACE", ValidationSeverity.Warning);
            HasIssue(whitespaceResult, "APP_NAMES_EMPTY", ValidationSeverity.Warning);

            var catchAll = TestModels.ValidConfiguration();
            catchAll.Proxies[0].AppNames = new List<string> { string.Empty };
            var catchAllResult = _validator.Validate(catchAll);
            Assert.That(catchAllResult.IsValid, Is.True);
            NoIssueWithPrefix(catchAllResult, "APP_NAME_WHITESPACE");
            NoIssueWithPrefix(catchAllResult, "CATCH_ALL_NOT_LAST");
        }

        [Test]
        public void CatchAllBeforeAnotherRuleWarnsAboutShadowing()
        {
            var configuration = TestModels.ValidConfiguration();
            configuration.Proxies[0].AppNames = new List<string> { string.Empty };
            configuration.Proxies.Add(TestModels.ValidRule());

            HasIssue(_validator.Validate(configuration), "CATCH_ALL_NOT_LAST", ValidationSeverity.Warning);
        }

        [Test]
        public void MultipleCatchAllRulesWarn()
        {
            var configuration = TestModels.ValidConfiguration();
            configuration.Proxies[0].AppNames = new List<string> { string.Empty };
            var second = TestModels.ValidRule();
            second.AppNames = new List<string> { string.Empty };
            configuration.Proxies.Add(second);

            HasIssue(_validator.Validate(configuration), "MULTIPLE_CATCH_ALL_RULES", ValidationSeverity.Warning);
        }

        [Test]
        public void DuplicateAndOverlappingApplicationMatchesWarnWithoutReordering()
        {
            var configuration = TestModels.ValidConfiguration();
            configuration.Proxies[0].AppNames = new List<string> { "firefox", "FIREFOX" };
            var second = TestModels.ValidRule();
            second.AppNames = new List<string> { "firefox.exe" };
            configuration.Proxies.Add(second);

            var result = _validator.Validate(configuration);

            HasIssue(result, "APP_MATCH_DUPLICATE", ValidationSeverity.Warning);
            HasIssue(result, "APP_MATCH_SHADOWED", ValidationSeverity.Warning);
            Assert.That(result.Issues.Any(issue => issue.Code == "APP_MATCH_SHADOWED" &&
                                                   issue.ProxyRuleIndex == 0), Is.False,
                "A duplicate inside one rule must not be described as shadowed by an earlier rule.");
            Assert.That(result.Issues.Any(issue => issue.Code == "APP_MATCH_SHADOWED" &&
                                                   issue.ProxyRuleIndex == 1), Is.True);
            Assert.That(configuration.Proxies[0].AppNames[0], Is.EqualTo("firefox"));
            Assert.That(configuration.Proxies[1].AppNames[0], Is.EqualTo("firefox.exe"));
        }

        [TestCase(@"C:\Apps\firefox.exe", "firefox.exe")]
        [TestCase("firefox", @"C:\Apps\firefox.exe")]
        [TestCase(@"C:\Apps\firefox", "firefox.exe")]
        public void FullPathAndExecutableNameOverlapsAreReported(string earlier, string later)
        {
            var configuration = TestModels.ValidConfiguration();
            configuration.Proxies[0].AppNames = new List<string> { earlier };
            var second = TestModels.ValidRule();
            second.AppNames = new List<string> { later };
            configuration.Proxies.Add(second);

            HasIssue(_validator.Validate(configuration), "APP_MATCH_SHADOWED", ValidationSeverity.Warning);
        }

        [Test]
        public void OmittedProtocolsMeanBothAndUnknownProtocolsAreErrors()
        {
            var rule = TestModels.ValidRule();
            rule.SupportedProtocols = null;
            var omitted = _validator.ValidateRule(rule);
            Assert.That(omitted.IsValid, Is.True);
            Assert.That(ConfigurationValueParser.GetProtocols(null), Is.EqualTo(ProxyProtocolSelection.Both));

            rule.SupportedProtocols = new List<string> { "TCp", "typo" };
            HasIssue(_validator.ValidateRule(rule), "PROTOCOL_UNKNOWN", ValidationSeverity.Error);
            Assert.Throws<System.InvalidOperationException>(
                () => ConfigurationValueParser.GetProtocols(rule.SupportedProtocols));
        }

        [Test]
        public void ExplicitEmptyProtocolsRetainLegacyBothBehaviorWithWarning()
        {
            var rule = TestModels.ValidRule();
            rule.SupportedProtocols = new List<string>();

            var result = _validator.ValidateRule(rule);

            Assert.That(result.IsValid, Is.True);
            HasIssue(result, "PROTOCOLS_EMPTY_LEGACY", ValidationSeverity.Warning);
            Assert.That(ConfigurationValueParser.GetProtocols(rule.SupportedProtocols), Is.EqualTo(ProxyProtocolSelection.Both));
        }

        [Test]
        public void AddressFamilyRulesDistinguishOmittedEmptyAndUnknown()
        {
            var rule = TestModels.ValidRule();
            rule.SupportedAddressFamilies = null;
            Assert.That(_validator.ValidateRule(rule).IsValid, Is.True);
            Assert.That(
                ConfigurationValueParser.GetAddressFamilies(null),
                Is.EqualTo(ProxyAddressFamilySelection.Both));

            rule.SupportedAddressFamilies = new List<string>();
            HasIssue(_validator.ValidateRule(rule), "ADDRESS_FAMILIES_EMPTY", ValidationSeverity.Error);

            rule.SupportedAddressFamilies = new List<string> { "IPv5" };
            HasIssue(_validator.ValidateRule(rule), "ADDRESS_FAMILY_UNKNOWN", ValidationSeverity.Error);
        }

        [TestCase(null)]
        [TestCase("TCP")]
        [TestCase("plain")]
        [TestCase("SOCKS5")]
        [TestCase("TLS")]
        [TestCase("SOCKS5_TLS")]
        public void ExistingTransportAliasesAreAccepted(string transport)
        {
            var rule = TestModels.ValidRule();
            rule.Socks5Transport = transport;

            NoIssueWithPrefix(_validator.ValidateRule(rule), "TRANSPORT_");
        }

        [Test]
        public void InvalidTransportIsAnError()
        {
            var rule = TestModels.ValidRule();
            rule.Socks5Transport = "HTTPS";

            HasIssue(_validator.ValidateRule(rule), "TRANSPORT_UNKNOWN", ValidationSeverity.Error);
        }

        [Test]
        public void TlsCertificatePinsAreNormalizedForValidation()
        {
            var rule = TestModels.ValidRule();
            rule.Socks5Transport = "TLS";
            rule.TlsPinnedSha256 = string.Join(":", Enumerable.Repeat("aA", 32));
            Assert.That(_validator.ValidateRule(rule).IsValid, Is.True);

            rule.TlsPinnedSha256 = "not-a-pin";
            HasIssue(_validator.ValidateRule(rule), "TLS_PIN_INVALID", ValidationSeverity.Error);
        }

        [Test]
        public void InvalidCertificateModesProduceProminentWarnings()
        {
            var rule = TestModels.ValidRule();
            rule.Socks5Transport = "TLS";
            rule.TlsAllowInvalidCertificate = true;
            rule.TlsPinnedSha256 = null;
            HasIssue(_validator.ValidateRule(rule), "TLS_IDENTITY_VERIFICATION_DISABLED", ValidationSeverity.Warning);

            rule.TlsPinnedSha256 = new string('a', 64);
            HasIssue(_validator.ValidateRule(rule), "TLS_INVALID_CERTIFICATE_ALLOWED", ValidationSeverity.Warning);
        }

        [Test]
        public void TlsServerNameFallsBackToEndpointHost()
        {
            var rule = TestModels.ValidRule();
            rule.Socks5ProxyEndpoint = "fallback.example.com:443";
            rule.TlsServerName = " ";

            Assert.That(rule.EffectiveTlsServerName, Is.EqualTo("fallback.example.com"));
        }

        [Test]
        public void BlankExclusionsAndUnknownLogLevelAreWarnings()
        {
            var configuration = TestModels.ValidConfiguration();
            configuration.Excludes = new List<string> { "valid", null, " " };
            configuration.LogLevel = "Verbose";

            var result = _validator.Validate(configuration);

            HasIssue(result, "EXCLUSION_BLANK", ValidationSeverity.Warning);
            HasIssue(result, "LOG_LEVEL_UNKNOWN", ValidationSeverity.Warning);
            Assert.That(result.IsValid, Is.True);
        }

        private static void HasIssue(ValidationResult result, string code, ValidationSeverity severity)
        {
            Assert.That(
                result.Issues.Any(issue => issue.Code == code && issue.Severity == severity),
                Is.True,
                "Expected " + severity + " issue " + code + ". Actual: " +
                string.Join(", ", result.Issues.Select(issue => issue.Code)));
        }

        private static void NoIssueWithPrefix(ValidationResult result, string prefix)
        {
            Assert.That(
                result.Issues.Any(issue => issue.Code.StartsWith(prefix, System.StringComparison.Ordinal)),
                Is.False,
                "Unexpected issue: " + string.Join(", ", result.Issues.Select(issue => issue.Code)));
        }
    }
}
