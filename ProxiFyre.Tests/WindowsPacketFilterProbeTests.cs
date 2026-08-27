using NUnit.Framework;
using ProxiFyreUI.Infrastructure;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class WindowsPacketFilterProbeTests
    {
        [Test]
        public void VersionIoctlMatchesNdisrdHeader()
        {
            Assert.That(WindowsPacketFilterProbe.IoctlNdisrdGetVersion,
                Is.EqualTo(0x830020C0u));
        }

        [TestCase(0x06013000u)]
        [TestCase(0x06023000u)]
        [TestCase(0x07013000u)]
        public void MatchingMajorAtOrAboveMinimumMinorIsAccepted(uint driverVersion)
        {
            var status = WindowsPacketFilterProbe.EvaluateDriverVersion(driverVersion);

            Assert.Multiple(() =>
            {
                Assert.That(status.IsAvailable, Is.True);
                Assert.That(status.Details, Is.Null);
            });
        }

        [Test]
        public void MatchingMajorBelowMinimumMinorIsRejectedWithRequiredVersion()
        {
            var status = WindowsPacketFilterProbe.EvaluateDriverVersion(0x06003000u);

            Assert.Multiple(() =>
            {
                Assert.That(status.IsAvailable, Is.False);
                Assert.That(status.Details, Does.Contain("API minor 0x0600"));
                Assert.That(status.Details, Does.Contain("minimum API encoding 0x06013000"));
            });
        }

        [TestCase(0x06012000u, "API major 2")]
        [TestCase(0x06014000u, "API major 4")]
        [TestCase(0xFFFFFFFFu, "API major 15")]
        public void DifferentApiMajorIsRejectedEvenWhenEncodingIsNewer(uint driverVersion,
            string reportedMajor)
        {
            var status = WindowsPacketFilterProbe.EvaluateDriverVersion(driverVersion);

            Assert.Multiple(() =>
            {
                Assert.That(status.IsAvailable, Is.False);
                Assert.That(status.Details, Does.Contain(reportedMajor));
                Assert.That(status.Details, Does.Contain("supports API major 3 only"));
            });
        }

        [TestCase((int)WindowsPacketFilterServiceState.Stopped)]
        [TestCase((int)WindowsPacketFilterServiceState.StartPending)]
        public void InactiveDeviceStillDefersToStoppedOrStartingService(int serviceStateValue)
        {
            var probe = new WindowsPacketFilterProbe(
                () => WindowsPacketFilterStatus.Unavailable(2,
                    "The NDISRD device could not be opened."),
                () => (WindowsPacketFilterServiceState)serviceStateValue);

            Assert.That(probe.GetStatus().IsAvailable, Is.True);
        }

        [TestCase((int)WindowsPacketFilterServiceState.Stopped)]
        [TestCase((int)WindowsPacketFilterServiceState.StartPending)]
        public void ActiveIncompatibleDeviceIsNotMaskedByServiceTransition(int serviceStateValue)
        {
            var probe = new WindowsPacketFilterProbe(
                () => WindowsPacketFilterProbe.EvaluateDriverVersion(0x06014000u),
                () => (WindowsPacketFilterServiceState)serviceStateValue);

            var status = probe.GetStatus();

            Assert.Multiple(() =>
            {
                Assert.That(status.IsAvailable, Is.False);
                Assert.That(status.Details, Does.Contain("API major 4"));
                Assert.That(status.StartupMessage, Does.Contain("unavailable or incompatible"));
            });
        }
    }
}
