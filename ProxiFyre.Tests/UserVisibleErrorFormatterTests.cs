using NUnit.Framework;
using ProxiFyreUI.Infrastructure;
using System;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class UserVisibleErrorFormatterTests
    {
        private const string ConfiguredPassword = "a\" b/secret";

        [Test]
        public void ServiceDetailsNeverExposeNamedOrConfiguredPassword()
        {
            var result = ServiceOperationResult.Failed(
                new ServiceStatusInfo(ProxiFyreServiceState.Error),
                "Start failed for " + ConfiguredPassword,
                "password=details-secret; configured=" + ConfiguredPassword);

            var text = new UserVisibleErrorFormatter().FormatServiceFailure(
                result, null, new[] { ConfiguredPassword });

            AssertRedacted(text, "details-secret");
        }

        [Test]
        public void RecentLogTextNeverExposesConfiguredPassword()
        {
            var result = ServiceOperationResult.Failed(
                new ServiceStatusInfo(ProxiFyreServiceState.Stopped), "Start failed.");

            var text = new UserVisibleErrorFormatter().FormatServiceFailure(
                result,
                new[] { "ERROR upstream rejected credential " + ConfiguredPassword },
                new[] { ConfiguredPassword });

            AssertRedacted(text);
        }

        [Test]
        public void ExceptionMessageNeverExposesConfiguredOrNamedPassword()
        {
            var exception = new InvalidOperationException(
                "Cannot save " + ConfiguredPassword + "; token=exception-token");

            var text = new UserVisibleErrorFormatter().FormatException(
                "Operation failed.", exception, new[] { ConfiguredPassword });

            AssertRedacted(text, "exception-token");
        }

        private static void AssertRedacted(string text, string secondSecret = null)
        {
            Assert.Multiple(() =>
            {
                Assert.That(text, Does.Contain("<redacted>"));
                Assert.That(text, Does.Not.Contain(ConfiguredPassword));
                if (secondSecret != null)
                    Assert.That(text, Does.Not.Contain(secondSecret));
            });
        }
    }
}
