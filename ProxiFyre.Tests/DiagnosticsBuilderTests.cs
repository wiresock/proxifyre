using NUnit.Framework;
using ProxiFyreUI.Infrastructure;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class DiagnosticsBuilderTests
    {
        private DiagnosticsBuilder _diagnostics;

        [SetUp]
        public void SetUp()
        {
            _diagnostics = new DiagnosticsBuilder();
        }

        [TestCase("{\"password\":\"ordinary-secret\"}", "ordinary-secret")]
        [TestCase("{\"secret\":\"contains \\\"quoted\\\" text\"}", "contains \\\"quoted\\\" text")]
        [TestCase("{\"token\":\"slash\\\\and\\\"quote\"}", "slash\\\\and\\\"quote")]
        [TestCase("{\"password\":\"trailing-slash\\\\\"}", "trailing-slash")]
        [TestCase(@"{\""password\"":\""escaped-json-secret\""}", "escaped-json-secret")]
        [TestCase(@"{\""token\"":\""contains\\\""quoted\\\""text\""}", @"contains\\\""quoted\\\""text")]
        public void RedactHidesNormalAndEscapedJsonNamedSecrets(string input, string forbidden)
        {
            var result = _diagnostics.Redact(input, null);

            Assert.Multiple(() =>
            {
                Assert.That(result, Does.Contain("<redacted>"));
                Assert.That(result, Does.Not.Contain(forbidden));
            });
        }

        [Test]
        public void RedactFailsClosedForTruncatedQuotedSecret()
        {
            const string input = "ERROR {\"password\":\"secret cut off before closing quote";

            var result = _diagnostics.Redact(input, null);

            Assert.Multiple(() =>
            {
                Assert.That(result, Does.Contain("<redacted>"));
                Assert.That(result, Does.Not.Contain("secret cut off"));
            });
        }

        [TestCase("password=plain-value next", "plain-value")]
        [TestCase("passwd: 'single quoted value';", "single quoted value")]
        [TestCase("pwd=\"double quoted value\"", "double quoted value")]
        [TestCase("secret:unquoted-secret, other=true", "unquoted-secret")]
        [TestCase("token = 'quoted; token, value'", "quoted; token, value")]
        [TestCase("api_token=api-token-value&enabled=true", "api-token-value")]
        [TestCase("client-secret: client-secret-value", "client-secret-value")]
        public void RedactHidesQuotedAndUnquotedNamedValues(string input, string forbidden)
        {
            var result = _diagnostics.Redact(input, null);

            Assert.Multiple(() =>
            {
                Assert.That(result, Does.Contain("<redacted>"));
                Assert.That(result, Does.Not.Contain(forbidden));
            });
        }

        [Test]
        public void RedactHidesRawJsonEscapedDoubleEscapedAndUriEncodedSuppliedSecret()
        {
            const string secret = "pa\"ss\\word\n";
            var jsonEscaped = Newtonsoft.Json.JsonConvert.ToString(secret);
            jsonEscaped = jsonEscaped.Substring(1, jsonEscaped.Length - 2);
            var doubleEscaped = Newtonsoft.Json.JsonConvert.ToString(jsonEscaped);
            doubleEscaped = doubleEscaped.Substring(1, doubleEscaped.Length - 2);
            var uriEscaped = System.Uri.EscapeDataString(secret);
            const string unicodeSecret = "päss";
            const string unicodeEscaped = "p\\u00e4ss";
            var input = secret + " | " + jsonEscaped + " | " + doubleEscaped + " | " +
                        uriEscaped + " | " + unicodeEscaped;

            var result = _diagnostics.Redact(input, new[] { secret, unicodeSecret });

            Assert.Multiple(() =>
            {
                Assert.That(result, Does.Not.Contain(secret));
                Assert.That(result, Does.Not.Contain(jsonEscaped));
                Assert.That(result, Does.Not.Contain(doubleEscaped));
                Assert.That(result, Does.Not.Contain(uriEscaped));
                Assert.That(result, Does.Not.Contain(unicodeEscaped));
                Assert.That(result, Does.Contain("<redacted>"));
            });
        }

        [Test]
        public void RedactDoesNotTreatUnassignedKeyWordsAsSecrets()
        {
            const string input = "The password policy and token rotation both failed.";

            Assert.That(_diagnostics.Redact(input, null), Is.EqualTo(input));
        }
    }
}
