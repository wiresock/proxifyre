using NUnit.Framework;
using ProxiFyreUI.Infrastructure;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class ServiceManagementTests
    {
        [TestCase(ProxiFyreServiceState.Running, true, true)]
        [TestCase(ProxiFyreServiceState.Stopped, true, true)]
        [TestCase(ProxiFyreServiceState.NotInstalled, true, false)]
        [TestCase(ProxiFyreServiceState.Error, false, false)]
        [TestCase(ProxiFyreServiceState.Unknown, false, false)]
        public void LifecycleVerificationRequiresConcreteScmState(
            ProxiFyreServiceState state, bool installationKnown, bool confirmsInstalled)
        {
            var status = new ServiceStatusInfo(state, state == ProxiFyreServiceState.Error
                ? "SCM query failed"
                : null);

            Assert.Multiple(() =>
            {
                Assert.That(status.IsInstallationKnown, Is.EqualTo(installationKnown));
                Assert.That(status.IsInstalled, Is.EqualTo(confirmsInstalled));
                Assert.That(status.HasConcreteInstalledState, Is.EqualTo(confirmsInstalled));
            });
        }

        [Test]
        public void ErrorStateCannotConfirmEitherInstallOrUninstallSuccess()
        {
            var status = new ServiceStatusInfo(ProxiFyreServiceState.Error, "access denied");

            var confirmsInstall = status.HasConcreteInstalledState;
            var confirmsUninstall = status.IsInstallationKnown && !status.IsInstalled;

            Assert.That(confirmsInstall, Is.False);
            Assert.That(confirmsUninstall, Is.False);
        }
    }
}
