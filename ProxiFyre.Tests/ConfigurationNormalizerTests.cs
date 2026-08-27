using Newtonsoft.Json.Linq;
using NUnit.Framework;
using ProxiFyre.Configuration;
using System.Collections.Generic;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class ConfigurationNormalizerTests
    {
        private readonly ConfigurationNormalizer _normalizer = new ConfigurationNormalizer();

        [Test]
        public void NormalizeReturnsCanonicalCopyAndPreservesOrderingAndExtensionData()
        {
            var configuration = new ProxiFyreConfiguration
            {
                LogLevel = " debug ",
                Excludes = new List<string> { null, " ", " Keep Exactly " },
                ExtensionData = new Dictionary<string, JToken> { { "future", new JObject(new JProperty("x", 1)) } },
                Proxies = new List<ProxyRule>
                {
                    new ProxyRule
                    {
                        AppNames = new List<string> { null, " ", "", "", " First " },
                        Socks5ProxyEndpoint = " proxy.example:1080 ",
                        Socks5Transport = "socks5_tls",
                        TlsPinnedSha256 = "AA:BB-CC " + new string('d', 58),
                        SupportedProtocols = new List<string> { "tcp", "UDP", "udp" },
                        SupportedAddressFamilies = new List<string> { "ipv6", "IPv4" },
                        ExtensionData = new Dictionary<string, JToken> { { "next", new JValue(42) } }
                    }
                }
            };

            var normalized = _normalizer.Normalize(configuration);

            Assert.That(normalized, Is.Not.SameAs(configuration));
            Assert.That(normalized.LogLevel, Is.EqualTo("Debug"));
            CollectionAssert.AreEqual(new[] { " Keep Exactly " }, normalized.Excludes);
            CollectionAssert.AreEqual(new[] { string.Empty, " First " }, normalized.Proxies[0].AppNames);
            Assert.That(normalized.Proxies[0].Socks5ProxyEndpoint, Is.EqualTo("proxy.example:1080"));
            Assert.That(normalized.Proxies[0].Socks5Transport, Is.EqualTo("TLS"));
            CollectionAssert.AreEqual(new[] { "TCP", "UDP" }, normalized.Proxies[0].SupportedProtocols);
            CollectionAssert.AreEqual(new[] { "IPv6", "IPv4" }, normalized.Proxies[0].SupportedAddressFamilies);
            Assert.That((int)normalized.ExtensionData["future"]["x"], Is.EqualTo(1));
            Assert.That((int)normalized.Proxies[0].ExtensionData["next"], Is.EqualTo(42));
            Assert.That(configuration.Proxies[0].AppNames.Count, Is.EqualTo(5), "The source must not be mutated.");
        }

        [Test]
        public void FingerprintNormalizationRemovesAllDocumentedSeparators()
        {
            Assert.That(
                ConfigurationNormalizer.NormalizeFingerprint("AA bb:CC-DD\tEE"),
                Is.EqualTo("aabbccddee"));
        }

        [Test]
        public void WhitespaceOnlyOptionalFingerprintNormalizesToMissing()
        {
            var rule = TestModels.ValidRule();
            rule.Socks5Transport = "TLS";
            rule.TlsPinnedSha256 = " : - \t ";

            Assert.That(_normalizer.NormalizeRule(rule).TlsPinnedSha256, Is.Null);
        }

        [TestCase(null, "TCP")]
        [TestCase("Plain", "TCP")]
        [TestCase("SOCKS5", "TCP")]
        [TestCase("SOCKS5TLS", "TLS")]
        [TestCase("SOCKS5-TLS", "TLS")]
        public void TransportAliasesCanonicalize(string input, string expected)
        {
            string canonical;
            Assert.That(ConfigurationNormalizer.TryGetCanonicalTransport(input, out canonical), Is.True);
            Assert.That(canonical, Is.EqualTo(expected));
        }

        [TestCase(null, ConfigurationLogLevel.Info)]
        [TestCase("", ConfigurationLogLevel.Info)]
        [TestCase("info", ConfigurationLogLevel.Info)]
        [TestCase("Warning", ConfigurationLogLevel.Warning)]
        [TestCase("255", ConfigurationLogLevel.Info)]
        [TestCase("Error, Debug", ConfigurationLogLevel.Info)]
        public void LogLevelParserAcceptsOnlySupportedNames(string input, ConfigurationLogLevel expected)
        {
            Assert.That(ConfigurationValueParser.GetLogLevel(input), Is.EqualTo(expected));
        }
    }
}
