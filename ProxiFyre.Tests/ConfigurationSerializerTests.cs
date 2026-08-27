using Newtonsoft.Json.Linq;
using NUnit.Framework;
using ProxiFyre.Configuration;
using System.Collections.Generic;
using System.IO;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class ConfigurationSerializerTests
    {
        private readonly ConfigurationSerializer _serializer = new ConfigurationSerializer();

        [Test]
        public void EveryCurrentPropertyRoundTrips()
        {
            var configuration = new ProxiFyreConfiguration
            {
                LogLevel = "Debug",
                BypassLan = true,
                Excludes = new List<string> { "direct-app", @"C:\Direct Apps\tool.exe" },
                Proxies = new List<ProxyRule>
                {
                    new ProxyRule
                    {
                        AppNames = new List<string> { "browser", @"C:\Apps\Browser.exe" },
                        Socks5ProxyEndpoint = "proxy.example.com:443",
                        Username = "user",
                        Password = "secret",
                        Socks5Transport = "TLS",
                        TlsServerName = "tls.example.com",
                        TlsPinnedSha256 = new string('a', 64),
                        TlsAllowInvalidCertificate = true,
                        SupportedProtocols = new List<string> { "TCP", "UDP" },
                        SupportedAddressFamilies = new List<string> { "IPv4", "IPv6" }
                    }
                }
            };

            var copy = _serializer.Deserialize(_serializer.Serialize(configuration));

            Assert.That(copy.LogLevel, Is.EqualTo("Debug"));
            Assert.That(copy.BypassLan, Is.True);
            CollectionAssert.AreEqual(configuration.Excludes, copy.Excludes);
            var rule = copy.Proxies[0];
            CollectionAssert.AreEqual(configuration.Proxies[0].AppNames, rule.AppNames);
            Assert.That(rule.Socks5ProxyEndpoint, Is.EqualTo("proxy.example.com:443"));
            Assert.That(rule.Username, Is.EqualTo("user"));
            Assert.That(rule.Password, Is.EqualTo("secret"));
            Assert.That(rule.Socks5Transport, Is.EqualTo("TLS"));
            Assert.That(rule.TlsServerName, Is.EqualTo("tls.example.com"));
            Assert.That(rule.TlsPinnedSha256, Is.EqualTo(new string('a', 64)));
            Assert.That(rule.TlsAllowInvalidCertificate, Is.True);
            CollectionAssert.AreEqual(new[] { "TCP", "UDP" }, rule.SupportedProtocols);
            CollectionAssert.AreEqual(new[] { "IPv4", "IPv6" }, rule.SupportedAddressFamilies);
        }

        [Test]
        public void UnknownRootAndRulePropertiesSurviveRoundTrip()
        {
            const string json = @"{
  ""logLevel"": ""Info"",
  ""proxies"": [{
    ""appNames"": [""browser""],
    ""socks5ProxyEndpoint"": ""127.0.0.1:1080"",
    ""futureRule"": { ""enabled"": true, ""values"": [1, 2, 3] }
  }],
  ""excludes"": [],
  ""futureRoot"": { ""mode"": ""new"" }
}";

            var configuration = _serializer.Deserialize(json);
            configuration.LogLevel = "Debug";
            var roundTrip = JObject.Parse(_serializer.Serialize(configuration));

            Assert.That((string)roundTrip["futureRoot"]["mode"], Is.EqualTo("new"));
            Assert.That((bool)roundTrip["proxies"][0]["futureRule"]["enabled"], Is.True);
            Assert.That((int)roundTrip["proxies"][0]["futureRule"]["values"][2], Is.EqualTo(3));
        }

        [Test]
        public void MissingOptionalPropertiesLoadWithBackwardCompatibleDefaults()
        {
            var configuration = _serializer.Deserialize(
                @"{""proxies"":[{""socks5ProxyEndpoint"":""127.0.0.1:1080""}]}" );

            Assert.That(configuration.LogLevel, Is.EqualTo("Info"));
            Assert.That(configuration.BypassLan, Is.False);
            Assert.That(configuration.Excludes, Is.Empty);
            Assert.That(configuration.Proxies[0].AppNames, Is.Empty);
            Assert.That(configuration.Proxies[0].SupportedProtocols, Is.Null);
            Assert.That(configuration.Proxies[0].SupportedAddressFamilies, Is.Null);
            Assert.That(configuration.Proxies[0].Socks5Transport, Is.Null);
        }

        [Test]
        public void MissingProxyPropertyRemainsDistinguishableFromEmptyProxyList()
        {
            var missing = _serializer.Deserialize(@"{""logLevel"":""Info""}");
            var empty = _serializer.Deserialize(@"{""logLevel"":""Info"",""proxies"":[]}");

            Assert.That(missing.Proxies, Is.Null);
            Assert.That(empty.Proxies, Is.Not.Null.And.Empty);
        }

        [Test]
        public void ExplicitCatchAllAndPasswordSurviveUnrelatedEdit()
        {
            var configuration = _serializer.Deserialize(
                @"{""proxies"":[{""appNames"":[""""],""socks5ProxyEndpoint"":""one.example:1080"",""username"":""u"",""password"":""do-not-drop""}],""excludes"":[]}" );

            configuration.Proxies[0].Socks5ProxyEndpoint = "two.example:1080";
            var copy = _serializer.Deserialize(_serializer.Serialize(configuration));

            Assert.That(copy.Proxies[0].AppNames, Is.EqualTo(new[] { string.Empty }));
            Assert.That(copy.Proxies[0].Password, Is.EqualTo("do-not-drop"));
        }

        [Test]
        public void SharedRuleClonePreservesPasswordCatchAllAndUnknownData()
        {
            var source = _serializer.Deserialize(
                @"{""proxies"":[{""appNames"":[""""],""socks5ProxyEndpoint"":""one.example:1080"",""username"":""u"",""password"":""clone-secret"",""futureRule"":{""mode"":""future""}}]}" )
                .Proxies[0];

            var clone = _serializer.CloneRule(source);
            clone.Socks5ProxyEndpoint = "two.example:1080";

            Assert.That(clone, Is.Not.SameAs(source));
            Assert.That(clone.AppNames, Is.EqualTo(new[] { string.Empty }));
            Assert.That(clone.Password, Is.EqualTo("clone-secret"));
            Assert.That((string)clone.ExtensionData["futureRule"]["mode"], Is.EqualTo("future"));
            Assert.That(source.Socks5ProxyEndpoint, Is.EqualTo("one.example:1080"));
        }

        [Test]
        public void SaveAndLoadUseUtf8WithoutLosingUnicode()
        {
            var path = Path.Combine(Path.GetTempPath(), "proxifyre-utf8-" + System.Guid.NewGuid().ToString("N") + ".json");
            try
            {
                var configuration = TestModels.ValidConfiguration();
                configuration.Excludes.Add(@"C:\Приложения\工具.exe");
                configuration.Proxies[0].Password = "пароль-密碼";

                _serializer.Save(path, configuration);
                var bytes = File.ReadAllBytes(path);
                var copy = _serializer.Load(path);

                Assert.That(bytes.Length, Is.GreaterThan(3));
                Assert.That(bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf, Is.False, "UTF-8 output should not gain a BOM.");
                Assert.That(copy.Excludes[0], Is.EqualTo(@"C:\Приложения\工具.exe"));
                Assert.That(copy.Proxies[0].Password, Is.EqualTo("пароль-密碼"));
            }
            finally
            {
                if (File.Exists(path))
                    File.Delete(path);
            }
        }
    }
}
