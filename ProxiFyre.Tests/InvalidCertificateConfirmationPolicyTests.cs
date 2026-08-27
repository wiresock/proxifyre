using NUnit.Framework;
using ProxiFyreUI.Infrastructure;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class InvalidCertificateConfirmationPolicyTests
    {
        [Test]
        public void PersistedTcpUnsafeFlagRequiresConfirmationWhenSwitchingToTls()
        {
            var confirmed = InvalidCertificateConfirmationPolicy.IsPersistedSelectionConfirmed(
                "TCP", true);

            Assert.Multiple(() =>
            {
                Assert.That(confirmed, Is.False);
                Assert.That(InvalidCertificateConfirmationPolicy.RequiresConfirmation(
                    true, true, confirmed), Is.True);
            });
        }

        [TestCase("TLS")]
        [TestCase("SOCKS5_TLS")]
        public void PersistedTlsUnsafeFlagRemainsConfirmed(string transport)
        {
            var confirmed = InvalidCertificateConfirmationPolicy.IsPersistedSelectionConfirmed(
                transport, true);

            Assert.That(confirmed, Is.True);
            Assert.That(InvalidCertificateConfirmationPolicy.RequiresConfirmation(
                true, true, confirmed), Is.False);
        }
    }
}
