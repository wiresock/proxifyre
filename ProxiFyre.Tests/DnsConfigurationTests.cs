using Newtonsoft.Json.Linq;
using NUnit.Framework;
using ProxiFyre.Configuration;
using System.Collections.Generic;
using System.Linq;

namespace ProxiFyre.Tests
{
    /// <summary>
    /// DNS routing configuration: the JSON schema, stable proxy references, validation of the two
    /// modes and the server override, and normalization. The engine-side packet routing is
    /// covered by netlib/test/proxy/dns_routing_policy_test.cpp and
    /// netlib/test/portable/dns_packet_redirect_test.cpp.
    /// </summary>
    [TestFixture]
    public sealed class DnsConfigurationTests
    {
        private readonly ConfigurationSerializer _serializer = new ConfigurationSerializer();
        private readonly ConfigurationValidator _validator = new ConfigurationValidator();
        private readonly ConfigurationNormalizer _normalizer = new ConfigurationNormalizer();

        private static ProxiFyreConfiguration TwoProxyConfiguration()
        {
            var first = TestModels.ValidRule();
            first.Id = "office";
            first.AppNames = new List<string> { "browser" };
            first.Socks5ProxyEndpoint = "office.example.com:1080";

            var second = TestModels.ValidRule();
            second.Id = "vpn";
            second.AppNames = new List<string> { string.Empty };
            second.Socks5ProxyEndpoint = "vpn.example.com:1080";

            var configuration = TestModels.ValidConfiguration();
            configuration.Proxies = new List<ProxyRule> { first, second };
            configuration.Dns = new DnsSettings { Mode = "Proxy", ProxyId = "vpn" };
            return configuration;
        }

        // ---------------------------------------------------------------- 12. compatibility

        [Test]
        public void ConfigurationWithoutDnsSettingsDefaultsToDirectAndStaysUnchanged()
        {
            const string json = "{ \"logLevel\": \"Info\", \"bypassLan\": true, \"proxies\": [ { \"appNames\": [\"chrome\"], " +
                                "\"socks5ProxyEndpoint\": \"proxy.example.com:1080\" } ], \"excludes\": [] }";

            var configuration = _serializer.Deserialize(json);

            Assert.That(configuration.Dns, Is.Null);
            Assert.That(configuration.Proxies[0].Id, Is.Null);
            Assert.That(DnsConfiguration.GetMode(configuration.Dns), Is.EqualTo(DnsRoutingMode.Direct));
            Assert.That(_validator.Validate(configuration).HasErrors, Is.False);

            var saved = JObject.Parse(_serializer.Serialize(_normalizer.Normalize(configuration)));
            Assert.That(saved.Property("dns"), Is.Null, "A legacy configuration must not gain a dns section.");
            Assert.That(((JObject)saved["proxies"][0]).Property("id"), Is.Null, "Rules must not gain ids on load/save.");
        }

        [TestCase(null)]
        [TestCase("")]
        [TestCase("  ")]
        [TestCase("direct")]
        [TestCase("DIRECT")]
        public void MissingOrDirectModeIsDirect(string mode)
        {
            Assert.That(DnsConfiguration.GetMode(new DnsSettings { Mode = mode }), Is.EqualTo(DnsRoutingMode.Direct));
        }

        [Test]
        public void ProxyModeIsCaseInsensitive()
        {
            Assert.That(DnsConfiguration.GetMode(new DnsSettings { Mode = " proxy " }), Is.EqualTo(DnsRoutingMode.Proxy));
        }

        // ---------------------------------------------------------------- serialization

        [Test]
        public void DnsSettingsAndProxyIdsRoundTrip()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Dns.ServerOverride = "1.1.1.1";

            var json = _serializer.Serialize(configuration);
            var copy = _serializer.Deserialize(json);

            Assert.That(copy.Dns.Mode, Is.EqualTo("Proxy"));
            Assert.That(copy.Dns.ProxyId, Is.EqualTo("vpn"));
            Assert.That(copy.Dns.ServerOverride, Is.EqualTo("1.1.1.1"));
            CollectionAssert.AreEqual(new[] { "office", "vpn" }, copy.Proxies.Select(rule => rule.Id));

            var root = JObject.Parse(json);
            Assert.That(root["dns"]["mode"].Value<string>(), Is.EqualTo("Proxy"));
            Assert.That(root["dns"]["proxyId"].Value<string>(), Is.EqualTo("vpn"));
            Assert.That(root["dns"]["serverOverride"].Value<string>(), Is.EqualTo("1.1.1.1"));
            Assert.That(((JObject)root["proxies"][0]).Properties().First().Name, Is.EqualTo("id"));
        }

        [Test]
        public void UnknownDnsPropertiesSurviveRoundTrip()
        {
            const string json = "{ \"proxies\": [ { \"id\": \"p\", \"appNames\": [\"a\"], \"socks5ProxyEndpoint\": \"p.example.com:1080\" } ], " +
                                "\"dns\": { \"mode\": \"Proxy\", \"proxyId\": \"p\", \"futureSetting\": { \"x\": 1 } } }";

            var copy = JObject.Parse(_serializer.Serialize(_normalizer.Normalize(_serializer.Deserialize(json))));

            Assert.That(copy["dns"]["futureSetting"]["x"].Value<int>(), Is.EqualTo(1));
        }

        [Test]
        public void CloningARulePreservesItsId()
        {
            var rule = TestModels.ValidRule();
            rule.Id = "office";

            Assert.That(_serializer.CloneRule(rule).Id, Is.EqualTo("office"));
        }

        // ---------------------------------------------------------------- 5. explicit selection

        [Test]
        public void ProxySelectionUsesTheStableIdAndSurvivesReordering()
        {
            var configuration = TwoProxyConfiguration();
            Assert.That(DnsConfiguration.FindProxyRuleIndex(configuration.Proxies, "vpn"), Is.EqualTo(1));

            configuration.Proxies.Reverse();
            Assert.That(DnsConfiguration.FindProxyRuleIndex(configuration.Proxies, "vpn"), Is.EqualTo(0));
            Assert.That(configuration.Proxies[DnsConfiguration.FindProxyRuleIndex(configuration.Proxies, " VPN ")].Socks5ProxyEndpoint,
                Is.EqualTo("vpn.example.com:1080"));
            Assert.That(_validator.Validate(configuration).HasErrors, Is.False);

            var reloaded = _serializer.Deserialize(_serializer.Serialize(configuration));
            Assert.That(reloaded.Proxies[DnsConfiguration.FindProxyRuleIndex(reloaded.Proxies, reloaded.Dns.ProxyId)].Socks5ProxyEndpoint,
                Is.EqualTo("vpn.example.com:1080"));
        }

        [Test]
        public void GeneratedIdsAreUniqueAndValid()
        {
            var id = DnsConfiguration.CreateUniqueProxyId(new[] { "proxy-1", "PROXY-2", null, "office" });

            Assert.That(id, Is.EqualTo("proxy-3"));
            Assert.That(DnsConfiguration.IsValidProxyId(id), Is.True);
            Assert.That(DnsConfiguration.CreateUniqueProxyId(null), Is.EqualTo("proxy-1"));
        }

        // ---------------------------------------------------------------- 13. invalid references

        [Test]
        public void ValidProxyModeConfigurationHasNoErrors()
        {
            var result = _validator.Validate(TwoProxyConfiguration());

            Assert.That(result.HasErrors, Is.False, string.Join("; ", result.Errors.Select(issue => issue.Code)));
            Assert.That(result.Issues.Any(issue => issue.Code.StartsWith("DNS_")), Is.False);
        }

        [Test]
        public void ProxyModeRequiresAProxyId()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Dns.ProxyId = " ";

            HasError(_validator.Validate(configuration), "DNS_PROXY_ID_MISSING", "dns.proxyId");
        }

        [Test]
        public void UnknownProxyReferenceIsRejectedInsteadOfSwitchingProxies()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Dns.ProxyId = "removed-proxy";

            var issue = HasError(_validator.Validate(configuration), "DNS_PROXY_NOT_FOUND", "dns.proxyId");
            StringAssert.Contains("removed-proxy", issue.Message);
        }

        [Test]
        public void RemovingTheSelectedRuleLeavesADanglingReferenceThatIsReported()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Proxies.RemoveAt(1);

            HasError(_validator.Validate(configuration), "DNS_PROXY_NOT_FOUND", "dns.proxyId");
        }

        [Test]
        public void UnknownModeIsRejected()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Dns.Mode = "Tunnel";

            HasError(_validator.Validate(configuration), "DNS_MODE_UNKNOWN", "dns.mode");
        }

        [TestCase("TCP")]
        [TestCase("UDP")]
        public void SelectedProxyMustSupportTcpAndUdp(string onlyProtocol)
        {
            var configuration = TwoProxyConfiguration();
            configuration.Proxies[1].SupportedProtocols = new List<string> { onlyProtocol };

            HasError(_validator.Validate(configuration), "DNS_PROXY_PROTOCOLS_UNSUPPORTED", "dns.proxyId");
        }

        [Test]
        public void LegacyOmittedProtocolsMeanBothAndAreAccepted()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Proxies[1].SupportedProtocols = null;

            Assert.That(_validator.Validate(configuration).Issues.Any(issue => issue.Code == "DNS_PROXY_PROTOCOLS_UNSUPPORTED"), Is.False);
        }

        [TestCase("")]
        [TestCase("   ")]
        [TestCase("has space")]
        [TestCase("slash/id")]
        [TestCase("ünicode")]
        public void InvalidProxyIdsAreRejected(string id)
        {
            var configuration = TwoProxyConfiguration();
            configuration.Proxies[0].Id = id;

            HasError(_validator.Validate(configuration), "PROXY_ID_INVALID", "proxies[0].id");
        }

        [Test]
        public void TooLongProxyIdIsRejected()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Proxies[0].Id = new string('a', DnsConfiguration.MaximumProxyIdLength + 1);

            HasError(_validator.Validate(configuration), "PROXY_ID_INVALID", "proxies[0].id");
        }

        [Test]
        public void DuplicateProxyIdsAreRejectedCaseInsensitively()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Proxies[1].Id = "OFFICE";
            configuration.Dns.ProxyId = "office";

            var issue = HasError(_validator.Validate(configuration), "PROXY_ID_DUPLICATE", "proxies[1].id");
            Assert.That(issue.ProxyRuleIndex, Is.EqualTo(1));
        }

        [Test]
        public void ProxyIdsAreValidatedInDirectModeToo()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Dns = null;
            configuration.Proxies[1].Id = "office";

            HasError(_validator.Validate(configuration), "PROXY_ID_DUPLICATE", "proxies[1].id");
        }

        // ---------------------------------------------------------------- 6. server override

        [TestCase("1.1.1.1", "1.1.1.1", 53, false)]
        [TestCase(" 9.9.9.9:5353 ", "9.9.9.9", 5353, false)]
        [TestCase("192.168.1.1", "192.168.1.1", 53, false)]
        [TestCase("127.0.0.1", "127.0.0.1", 53, false)]
        [TestCase("2606:4700:4700::1111", "2606:4700:4700::1111", 53, true)]
        [TestCase("[2606:4700:4700::1111]", "2606:4700:4700::1111", 53, true)]
        [TestCase("[2001:4860:4860::8888]:853", "2001:4860:4860::8888", 853, true)]
        public void ServerOverrideLiteralsAreAccepted(string value, string address, int port, bool ipv6)
        {
            DnsServerOverride parsed;
            DnsServerOverrideParseError error;

            Assert.That(DnsConfiguration.TryParseServerOverride(value, out parsed, out error), Is.True, error.ToString());
            Assert.That(parsed.Address.ToString(), Is.EqualTo(address));
            Assert.That(parsed.Port, Is.EqualTo(port));
            Assert.That(parsed.IsIpv6, Is.EqualTo(ipv6));
        }

        [TestCase("dns.example.com", DnsServerOverrideParseError.NotAnIpLiteral)]
        [TestCase("dns.example.com:53", DnsServerOverrideParseError.NotAnIpLiteral)]
        [TestCase("1", DnsServerOverrideParseError.NotAnIpLiteral)]
        [TestCase("1.1", DnsServerOverrideParseError.NotAnIpLiteral)]
        [TestCase("010.1.1.1", DnsServerOverrideParseError.NotAnIpLiteral)]
        [TestCase("1.1.1.256", DnsServerOverrideParseError.NotAnIpLiteral)]
        [TestCase("1.1.1.1:0", DnsServerOverrideParseError.InvalidPort)]
        [TestCase("1.1.1.1:65536", DnsServerOverrideParseError.InvalidPort)]
        [TestCase("1.1.1.1:abc", DnsServerOverrideParseError.InvalidPort)]
        [TestCase("[::1]:0", DnsServerOverrideParseError.InvalidPort)]
        [TestCase("[::1", DnsServerOverrideParseError.NotAnIpLiteral)]
        [TestCase("[1.1.1.1]", DnsServerOverrideParseError.NotAnIpLiteral)]
        [TestCase("fe80::1%12", DnsServerOverrideParseError.NotAnIpLiteral)]
        [TestCase("0.0.0.0", DnsServerOverrideParseError.UnusableAddress)]
        [TestCase("255.255.255.255", DnsServerOverrideParseError.UnusableAddress)]
        [TestCase("224.0.0.251", DnsServerOverrideParseError.UnusableAddress)]
        [TestCase("::", DnsServerOverrideParseError.UnusableAddress)]
        [TestCase("ff02::fb", DnsServerOverrideParseError.UnusableAddress)]
        [TestCase("::ffff:1.1.1.1", DnsServerOverrideParseError.UnusableAddress)]
        public void InvalidServerOverridesAreRejected(string value, DnsServerOverrideParseError expected)
        {
            DnsServerOverride parsed;
            DnsServerOverrideParseError error;

            Assert.That(DnsConfiguration.TryParseServerOverride(value, out parsed, out error), Is.False);
            Assert.That(error, Is.EqualTo(expected));
        }

        [TestCase("dns.example.com", "DNS_SERVER_OVERRIDE_INVALID")]
        [TestCase("1.1.1.1:0", "DNS_SERVER_OVERRIDE_PORT_INVALID")]
        [TestCase("224.0.0.1", "DNS_SERVER_OVERRIDE_INVALID")]
        public void InvalidServerOverrideIsAnError(string value, string code)
        {
            var configuration = TwoProxyConfiguration();
            configuration.Dns.ServerOverride = value;

            HasError(_validator.Validate(configuration), code, "dns.serverOverride");
        }

        [Test]
        public void ServerOverrideFamilyMustBeSupportedByTheSelectedProxy()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Proxies[1].SupportedAddressFamilies = new List<string> { "IPv4" };
            configuration.Dns.ServerOverride = "2606:4700:4700::1111";

            HasError(_validator.Validate(configuration), "DNS_SERVER_OVERRIDE_FAMILY_UNSUPPORTED", "dns.serverOverride");
        }

        [Test]
        public void ServerOverrideWarnsThatTheOtherFamilyIsBlocked()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Dns.ServerOverride = "1.1.1.1";

            var result = _validator.Validate(configuration);
            Assert.That(result.HasErrors, Is.False);
            var warning = result.Warnings.Single(issue => issue.Code == "DNS_SERVER_OVERRIDE_OTHER_FAMILY_BLOCKED");
            StringAssert.Contains("IPv6", warning.Message);
        }

        [Test]
        public void ProxyWithoutIpv6WarnsThatIpv6DnsIsBlocked()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Proxies[1].SupportedAddressFamilies = new List<string> { "IPv4" };

            var result = _validator.Validate(configuration);
            Assert.That(result.HasErrors, Is.False);
            Assert.That(result.Warnings.Any(issue => issue.Code == "DNS_PROXY_FAMILY_BLOCKED"), Is.True);
        }

        [Test]
        public void ServerOverrideInDirectModeIsIgnoredWithAWarning()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Dns.Mode = "Direct";
            configuration.Dns.ProxyId = "does-not-exist";
            configuration.Dns.ServerOverride = "1.1.1.1";

            var result = _validator.Validate(configuration);
            Assert.That(result.HasErrors, Is.False, "Proxy-only settings are not validated against rules in Direct mode.");
            Assert.That(result.Warnings.Any(issue => issue.Code == "DNS_SERVER_OVERRIDE_IGNORED"), Is.True);
        }

        // ---------------------------------------------------------------- normalization

        [Test]
        public void NormalizationCanonicalizesDnsSettingsWithoutChangingMeaning()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Proxies[0].Id = "  office ";
            configuration.Dns = new DnsSettings { Mode = " proxy ", ProxyId = " vpn ", ServerOverride = "   " };

            var normalized = _normalizer.Normalize(configuration);

            Assert.That(normalized.Proxies[0].Id, Is.EqualTo("office"));
            Assert.That(normalized.Dns.Mode, Is.EqualTo("Proxy"));
            Assert.That(normalized.Dns.ProxyId, Is.EqualTo("vpn"));
            Assert.That(normalized.Dns.ServerOverride, Is.Null);
            Assert.That(_normalizer.Normalize(TestModels.ValidConfiguration()).Dns, Is.Null);
        }

        [TestCase("   ")]
        [TestCase("")]
        [TestCase("\t")]
        public void NormalizationTurnsABlankProxyIdIntoNoId(string id)
        {
            var configuration = TwoProxyConfiguration();
            configuration.Proxies[0].Id = id;

            var normalized = _normalizer.Normalize(configuration);

            Assert.That(normalized.Proxies[0].Id, Is.Null);
            Assert.That(((JObject)JObject.Parse(_serializer.Serialize(normalized))["proxies"][0]).Property("id"), Is.Null);
        }

        [Test]
        public void OtherFamilyWarningDoesNotPromiseAFallback()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Dns.ServerOverride = "2606:4700:4700::1111";

            var warning = _validator.Validate(configuration).Warnings
                .Single(issue => issue.Code == "DNS_SERVER_OVERRIDE_OTHER_FAMILY_BLOCKED");
            StringAssert.Contains("IPv4 servers are blocked", warning.Message);
            StringAssert.DoesNotContain("falls back", warning.Message);
        }

        [Test]
        public void UnknownModeIsNotAcceptedByTryGetMode()
        {
            DnsRoutingMode mode;
            Assert.That(DnsConfiguration.TryGetMode("Tunnel", out mode), Is.False);
            Assert.That(DnsConfiguration.TryGetMode("Proxy", out mode), Is.True);
            Assert.That(mode, Is.EqualTo(DnsRoutingMode.Proxy));
        }

        [Test]
        public void NormalizationKeepsAnUnknownModeVisibleForValidation()
        {
            var configuration = TwoProxyConfiguration();
            configuration.Dns.Mode = "Tunnel";

            Assert.That(_normalizer.Normalize(configuration).Dns.Mode, Is.EqualTo("Tunnel"));
        }

        private static ValidationIssue HasError(ValidationResult result, string code, string path)
        {
            var issue = result.Issues.FirstOrDefault(item => item.Code == code);
            Assert.That(issue, Is.Not.Null,
                "Expected " + code + "; found: " + string.Join(", ", result.Issues.Select(item => item.Code)));
            Assert.That(issue.Severity, Is.EqualTo(ValidationSeverity.Error));
            Assert.That(issue.Path, Is.EqualTo(path));
            return issue;
        }
    }
}
