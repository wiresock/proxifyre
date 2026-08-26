using NUnit.Framework;
using ProxiFyreUI.Infrastructure;
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class ServiceManagementTests
    {
        private const uint DddRawTargetPath = 0x00000001;
        private const uint DddRemoveDefinition = 0x00000002;
        private const uint DddExactMatchOnRemove = 0x00000004;
        private const uint DddNoBroadcastSystem = 0x00000008;

        [TestCase(ProxiFyreServiceState.Running, true, true, true)]
        [TestCase(ProxiFyreServiceState.Stopped, true, true, true)]
        [TestCase(ProxiFyreServiceState.DeletionPending, true, true, false)]
        [TestCase(ProxiFyreServiceState.NotInstalled, true, false, false)]
        [TestCase(ProxiFyreServiceState.Error, false, false, false)]
        [TestCase(ProxiFyreServiceState.Unknown, false, false, false)]
        public void LifecycleVerificationRequiresConcreteScmState(
            ProxiFyreServiceState state, bool installationKnown, bool isInstalled,
            bool confirmsInstalled)
        {
            var status = new ServiceStatusInfo(state, state == ProxiFyreServiceState.Error
                ? "SCM query failed"
                : null);

            Assert.Multiple(() =>
            {
                Assert.That(status.IsInstallationKnown, Is.EqualTo(installationKnown));
                Assert.That(status.IsInstalled, Is.EqualTo(isInstalled));
                Assert.That(status.HasConcreteInstalledState, Is.EqualTo(confirmsInstalled));
            });
        }

        [TestCase(30, 5, 25)]
        [TestCase(30, 30, 0)]
        [TestCase(30, 45, 0)]
        [TestCase(0, 0, 0)]
        public void OperationBudgetUsesOneDeadlineAcrossWorkflow(
            int timeoutSeconds, int elapsedSeconds, int expectedSeconds)
        {
            Assert.That(ServiceOperationBudget.Remaining(
                    TimeSpan.FromSeconds(timeoutSeconds), TimeSpan.FromSeconds(elapsedSeconds)),
                Is.EqualTo(TimeSpan.FromSeconds(expectedSeconds)));
        }

        [Test]
        public void PreLaunchPolicyDoesNotRunRegistrationGuardAfterDeadline()
        {
            var guardCalls = 0;

            var decision = ServicePreLaunchPolicy.Evaluate(TimeSpan.FromSeconds(5),
                () => TimeSpan.FromSeconds(5), () =>
                {
                    guardCalls++;
                    return true;
                });

            Assert.Multiple(() =>
            {
                Assert.That(decision, Is.EqualTo(ServicePreLaunchDecision.TimedOut));
                Assert.That(guardCalls, Is.Zero);
            });
        }

        [Test]
        public void PreLaunchPolicyRejectsLaunchWhenGuardConsumesRemainingBudget()
        {
            var elapsed = TimeSpan.FromSeconds(1);

            var decision = ServicePreLaunchPolicy.Evaluate(TimeSpan.FromSeconds(5),
                () => elapsed, () =>
                {
                    elapsed = TimeSpan.FromSeconds(5);
                    return true;
                });

            Assert.That(decision, Is.EqualTo(ServicePreLaunchDecision.TimedOut));
        }

        [Test]
        public void PreLaunchPolicyFailsClosedWhenRegistrationCheckThrows()
        {
            var decision = ServicePreLaunchPolicy.Evaluate(TimeSpan.FromSeconds(5),
                () => TimeSpan.FromSeconds(1), () =>
                {
                    throw new IOException("Registry became unavailable.");
                });

            Assert.That(decision, Is.EqualTo(ServicePreLaunchDecision.GuardRejected));
        }

        [TestCase(ProxiFyreServiceState.NotInstalled, 0, true)]
        [TestCase(ProxiFyreServiceState.DeletionPending, 0, true)]
        [TestCase(ProxiFyreServiceState.Stopped, 0, true)]
        [TestCase(ProxiFyreServiceState.Running, 0, false)]
        [TestCase(ProxiFyreServiceState.Error, 0, false)]
        [TestCase(ProxiFyreServiceState.NotInstalled, 1, false)]
        public void UninstallCompletionRequiresSuccessfulCommandAndSafeFinalState(
            ProxiFyreServiceState state, int exitCode, bool expectedSuccess)
        {
            var status = new ServiceStatusInfo(state,
                state == ProxiFyreServiceState.Error ? "SCM query failed" : null);

            var result = ServiceUninstallCompletionEvaluator.Evaluate(status,
                "lifecycle output", exitCode);

            Assert.Multiple(() =>
            {
                Assert.That(result.Success, Is.EqualTo(expectedSuccess));
                Assert.That(result.Status, Is.SameAs(status));
                Assert.That(result.Details, Is.EqualTo("lifecycle output"));
                Assert.That(result.ExitCode, Is.EqualTo(exitCode));
            });
        }

        [TestCase(ProxiFyreServiceState.DeletionPending)]
        [TestCase(ProxiFyreServiceState.Stopped)]
        public void SuccessfulUninstallSurfacesPendingScmRemoval(ProxiFyreServiceState state)
        {
            var result = ServiceUninstallCompletionEvaluator.Evaluate(
                new ServiceStatusInfo(state), null, 0);

            Assert.That(result.Message, Does.Contain("Windows"));
            Assert.That(result.Message, Does.Contain("remov").IgnoreCase);
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
        public void StartupCompletionRequiresFinalRunningState()
        {
            var stopped = new ServiceStatusInfo(ProxiFyreServiceState.Stopped);

            var result = ServiceStartupCompletionEvaluator.Evaluate(stopped);

            Assert.Multiple(() =>
            {
                Assert.That(result.Success, Is.False);
                Assert.That(result.Status, Is.SameAs(stopped));
                Assert.That(result.FailureKind, Is.EqualTo(ServiceOperationFailureKind.StartupFailed));
                Assert.That(result.Message, Does.Contain("final Running state could not be confirmed"));
            });
        }

        [Test]
        public void StartupCompletionAcceptsFinalRunningState()
        {
            var running = new ServiceStatusInfo(ProxiFyreServiceState.Running);

            var result = ServiceStartupCompletionEvaluator.Evaluate(running);

            Assert.Multiple(() =>
            {
                Assert.That(result.Success, Is.True);
                Assert.That(result.Status, Is.SameAs(running));
                Assert.That(result.FailureKind, Is.EqualTo(ServiceOperationFailureKind.None));
                Assert.That(result.ConfirmsConfigurationReloaded, Is.True);
            });
        }

        [Test]
        public void GenericRunningSuccessDoesNotClaimConfigurationWasReloaded()
        {
            var result = ServiceOperationResult.Completed(
                new ServiceStatusInfo(ProxiFyreServiceState.Running), "Already running.");

            Assert.That(result.Success, Is.True);
            Assert.That(result.ConfirmsConfigurationReloaded, Is.False);
        }

        [Test]
        public void StartAndRestartRequireAnAbsoluteEngineIdentityAndRegistrationGuard()
        {
            using (var controller = new ProxiFyreServiceController())
            {
                var validShape = Path.Combine(Path.GetTempPath(), "folder with spaces",
                    ProxiFyre.Configuration.ProxiFyrePaths.EngineExecutableName);

                Assert.Multiple(() =>
                {
                    Assert.Throws<ArgumentException>(() => controller.StartAsync(
                        "ProxiFyre.exe", () => true, TimeSpan.FromSeconds(1),
                        default(System.Threading.CancellationToken)));
                    Assert.Throws<ArgumentNullException>(() => controller.RestartAsync(
                        validShape, null, TimeSpan.FromSeconds(1),
                        default(System.Threading.CancellationToken)));
                });
            }
        }

        [TestCase(ProxiFyreServiceState.Stopped, true)]
        [TestCase(ProxiFyreServiceState.NotInstalled, true)]
        [TestCase(ProxiFyreServiceState.Running, false)]
        [TestCase(ProxiFyreServiceState.DeletionPending, false)]
        [TestCase(ProxiFyreServiceState.Error, false)]
        public void StopCompletionRequiresSafeFinalState(ProxiFyreServiceState state,
            bool expectedSuccess)
        {
            var result = ServiceStopCompletionEvaluator.Evaluate(new ServiceStatusInfo(state));

            Assert.That(result.Success, Is.EqualTo(expectedSuccess));
            Assert.That(result.Status.State, Is.EqualTo(state));
        }

        [Test]
        public void LifecycleExecutableLeaseBlocksModificationAndReplacement()
        {
            var path = Path.Combine(Path.GetTempPath(),
                "ProxiFyre.LifecycleLease." + Guid.NewGuid().ToString("N") + ".exe");
            var dependencyPath = Path.ChangeExtension(path, ".dll");
            File.WriteAllText(path, "trusted bytes");
            File.WriteAllText(dependencyPath, "trusted dependency bytes");
            try
            {
                using (LifecycleExecutableLease.Acquire(new[] { path, dependencyPath },
                           candidate => candidate == path || candidate == dependencyPath))
                {
                    Assert.Throws<IOException>(() =>
                    {
                        using (File.Open(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
                        {
                        }
                    });
                    Assert.Throws<IOException>(() => File.Delete(path));
                    Assert.Throws<IOException>(() =>
                    {
                        using (File.Open(dependencyPath, FileMode.Open, FileAccess.Write,
                                   FileShare.ReadWrite))
                        {
                        }
                    });
                    Assert.Throws<IOException>(() => File.Delete(dependencyPath));
                    Assert.That(File.ReadAllText(path), Is.EqualTo("trusted bytes"));
                    Assert.That(File.ReadAllText(dependencyPath),
                        Is.EqualTo("trusted dependency bytes"));
                }

                Assert.DoesNotThrow(() => File.WriteAllText(path, "replacement bytes"));
                Assert.DoesNotThrow(() => File.WriteAllText(dependencyPath,
                    "replacement dependency bytes"));
                Assert.That(File.ReadAllText(path), Is.EqualTo("replacement bytes"));
                Assert.That(File.ReadAllText(dependencyPath),
                    Is.EqualTo("replacement dependency bytes"));
            }
            finally
            {
                if (File.Exists(path))
                    File.Delete(path);
                if (File.Exists(dependencyPath))
                    File.Delete(dependencyPath);
            }
        }

        [Test]
        public void LifecycleExecutableLeasePinsThePayloadDirectoryPath()
        {
            var root = Path.Combine(Path.GetTempPath(),
                "ProxiFyre.DirectoryLease." + Guid.NewGuid().ToString("N"));
            var payloadDirectory = Path.Combine(root, "payload");
            var renamedDirectory = Path.Combine(root, "renamed");
            Directory.CreateDirectory(payloadDirectory);
            var path = Path.Combine(payloadDirectory, "ProxiFyre.exe");
            File.WriteAllText(path, "trusted bytes");
            try
            {
                using (LifecycleExecutableLease.Acquire(path, candidate => candidate == path))
                {
                    Assert.Throws<IOException>(() =>
                        Directory.Move(payloadDirectory, renamedDirectory));
                    Assert.That(File.ReadAllText(path), Is.EqualTo("trusted bytes"));
                }

                Assert.DoesNotThrow(() => Directory.Move(payloadDirectory, renamedDirectory));
                Assert.That(File.ReadAllText(Path.Combine(renamedDirectory, "ProxiFyre.exe")),
                    Is.EqualTo("trusted bytes"));
            }
            finally
            {
                if (Directory.Exists(root))
                    Directory.Delete(root, true);
            }
        }

        [Test]
        [NonParallelizable]
        public void LifecycleExecutableLeaseRejectsMutableDirectVolumeDriveAlias()
        {
            var sourceRoot = Path.GetPathRoot(Path.GetFullPath(Path.GetTempPath()));
            Assert.That(sourceRoot, Has.Length.EqualTo(3),
                "The test temp directory must use a drive-letter root.");

            var aliasDeviceName = FindUnusedDosDriveName();
            if (aliasDeviceName == null)
                Assert.Ignore("No unused DOS drive letter is available for the alias test.");

            var rawTarget = new StringBuilder(1024);
            var sourceDeviceName = sourceRoot.Substring(0, 2);
            if (QueryDosDevice(sourceDeviceName, rawTarget, rawTarget.Capacity) == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "The test volume's native device path could not be queried.");

            var directory = Path.Combine(Path.GetTempPath(),
                "ProxiFyre.VolumeAlias." + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var payloadPath = Path.Combine(directory, "ProxiFyre.exe");
            File.WriteAllText(payloadPath, "trusted bytes");

            var aliasRoot = aliasDeviceName + Path.DirectorySeparatorChar;
            var aliasPayloadPath = Path.Combine(aliasRoot,
                payloadPath.Substring(sourceRoot.Length));
            var mappingCreated = false;
            var cleanupError = 0;
            try
            {
                var createFlags = DddRawTargetPath | DddNoBroadcastSystem;
                if (!DefineDosDevice(createFlags, aliasDeviceName, rawTarget.ToString()))
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "The temporary DOS drive alias could not be created.");
                mappingCreated = true;

                Assert.That(File.Exists(aliasPayloadPath), Is.True,
                    "The direct-volume DOS alias must resolve before testing the lease guard.");
                string policyFailure;
                Assert.That(ProxiFyre.Configuration.ServiceInstallLocationPolicy.IsProtected(
                    aliasPayloadPath, out policyFailure), Is.False);
                Assert.That(policyFailure, Does.Contain("fixed local volume"));
                Assert.Throws<IOException>(() =>
                {
                    using (LifecycleExecutableLease.Acquire(aliasPayloadPath, candidate => true))
                    {
                    }
                });
            }
            finally
            {
                if (mappingCreated)
                {
                    var removeFlags = DddRawTargetPath | DddRemoveDefinition |
                                      DddExactMatchOnRemove | DddNoBroadcastSystem;
                    if (!DefineDosDevice(removeFlags, aliasDeviceName, rawTarget.ToString()))
                        cleanupError = Marshal.GetLastWin32Error();
                }

                if (Directory.Exists(directory))
                    Directory.Delete(directory, true);
                if (cleanupError != 0)
                    Assert.Fail("The temporary DOS drive alias could not be removed (Win32 error " +
                                cleanupError + ").");
            }
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

        [Test]
        public void InstalledButStoppedPacketFilterDefersStartupToScm()
        {
            var probe = new WindowsPacketFilterProbe(
                () => WindowsPacketFilterStatus.Unavailable(2,
                    "The NDISRD device is not active."),
                () => WindowsPacketFilterServiceState.Stopped);

            var dependency = probe.GetStatus();

            Assert.Multiple(() =>
            {
                Assert.That(dependency.IsAvailable, Is.True);
                Assert.That(dependency.StartupMessage, Is.Null);
            });
        }

        [Test]
        public void MissingPacketFilterServiceRemainsAnActionableFailure()
        {
            var probe = new WindowsPacketFilterProbe(
                () => WindowsPacketFilterStatus.Unavailable(2,
                    "The NDISRD device could not be opened."),
                () => WindowsPacketFilterServiceState.Missing);

            var dependency = probe.GetStatus();

            Assert.Multiple(() =>
            {
                Assert.That(dependency.IsAvailable, Is.False);
                Assert.That(dependency.NativeErrorCode, Is.EqualTo(2));
                Assert.That(dependency.Details, Does.Contain("service is not installed"));
                Assert.That(dependency.StartupMessage,
                    Does.Contain(WindowsPacketFilterStatus.DownloadUrl));
            });
        }

        [Test]
        public void RemovedRegistrationFailsEvenWhileDeviceRemainsOpen()
        {
            var probe = new WindowsPacketFilterProbe(
                WindowsPacketFilterStatus.Available,
                () => WindowsPacketFilterServiceState.Missing);

            var dependency = probe.GetStatus();

            Assert.That(dependency.IsAvailable, Is.False);
            Assert.That(dependency.Details, Does.Contain("service is not installed"));
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

        [TestCase(ServiceOperationFailureKind.StartupFailed, ProxiFyreServiceState.Stopped, true)]
        [TestCase(ServiceOperationFailureKind.TimedOut, ProxiFyreServiceState.StartPending, true)]
        [TestCase(ServiceOperationFailureKind.TimedOut, ProxiFyreServiceState.Stopped, false)]
        [TestCase(ServiceOperationFailureKind.General, ProxiFyreServiceState.Stopped, false)]
        [TestCase(ServiceOperationFailureKind.DependencyUnavailable, ProxiFyreServiceState.Stopped, false)]
        public void EngineStartupBannerRequiresAClassifiedStartupFailure(
            ServiceOperationFailureKind failureKind, ProxiFyreServiceState serviceState, bool expected)
        {
            var result = ServiceOperationResult.Failed(new ServiceStatusInfo(serviceState),
                "Test failure", null, null,
                failureKind == ServiceOperationFailureKind.TimedOut, failureKind);

            Assert.That(ServiceOperationFailureClassifier.IsEngineStartupFailure(result),
                Is.EqualTo(expected));
        }

        private static string FindUnusedDosDriveName()
        {
            var target = new StringBuilder(2);
            for (var letter = 'Z'; letter >= 'D'; letter--)
            {
                target.Clear();
                if (QueryDosDevice(letter + ":", target, target.Capacity) == 0 &&
                    Marshal.GetLastWin32Error() == 2)
                    return letter + ":";
            }
            return null;
        }

        [DllImport("kernel32.dll", EntryPoint = "DefineDosDeviceW", CharSet = CharSet.Unicode,
            ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DefineDosDevice(uint flags, string deviceName,
            string targetPath);

        [DllImport("kernel32.dll", EntryPoint = "QueryDosDeviceW", CharSet = CharSet.Unicode,
            ExactSpelling = true, SetLastError = true)]
        private static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath,
            int maximumLength);
    }
}
