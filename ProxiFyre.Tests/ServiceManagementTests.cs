using NUnit.Framework;
using ProxiFyreUI.Infrastructure;
using System;
using System.ComponentModel;

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

        [TestCase(ProxiFyreServiceState.StartPending, ServiceStartupObservation.Pending)]
        [TestCase(ProxiFyreServiceState.Running, ServiceStartupObservation.Running)]
        [TestCase(ProxiFyreServiceState.Stopped, ServiceStartupObservation.Failed)]
        [TestCase(ProxiFyreServiceState.Paused, ServiceStartupObservation.Failed)]
        [TestCase(ProxiFyreServiceState.Error, ServiceStartupObservation.Failed)]
        public void StartupPollingTreatsOnlyStartPendingAsInProgress(
            ProxiFyreServiceState state, ServiceStartupObservation expected)
        {
            Assert.That(ServiceStartupStateClassifier.Classify(state), Is.EqualTo(expected));
        }

        [Test]
        public void MissingPacketFilterProducesActionableClassifiedFailure()
        {
            var dependency = WindowsPacketFilterStatus.Unavailable(2,
                "The NDISRD device could not be opened (Win32 error 2).");
            var result = ServiceOperationResult.Failed(
                new ServiceStatusInfo(ProxiFyreServiceState.Stopped),
                dependency.StartupMessage, dependency.Details, null, false,
                ServiceOperationFailureKind.DependencyUnavailable);

            Assert.Multiple(() =>
            {
                Assert.That(dependency.IsAvailable, Is.False);
                Assert.That(dependency.NativeErrorCode, Is.EqualTo(2));
                Assert.That(result.TimedOut, Is.False);
                Assert.That(result.FailureKind,
                    Is.EqualTo(ServiceOperationFailureKind.DependencyUnavailable));
                Assert.That(result.Message, Does.Contain("Windows Packet Filter"));
                Assert.That(result.Message, Does.Contain("NDISRD"));
                Assert.That(result.Message, Does.Contain(WindowsPacketFilterStatus.DownloadUrl));
            });
        }

        [TestCase(1068)]
        [TestCase(1075)]
        public void ScmPacketFilterDependencyErrorsRetainDependencyClassification(int nativeErrorCode)
        {
            var exception = new InvalidOperationException("SCM start failed",
                new Win32Exception(nativeErrorCode));

            Assert.That(ServiceOperationFailureClassifier.Classify(exception),
                Is.EqualTo(ServiceOperationFailureKind.DependencyUnavailable));
        }

        [Test]
        public void UnrelatedScmErrorRemainsGeneralFailure()
        {
            Assert.That(ServiceOperationFailureClassifier.Classify(new Win32Exception(5)),
                Is.EqualTo(ServiceOperationFailureKind.General));
        }
    }
}
