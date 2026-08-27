using NUnit.Framework;
using ProxiFyre.Configuration;
using ProxiFyreUI.Infrastructure;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class ApplicationServicesTests
    {
        private static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(1);

        private string _directory;
        private string _enginePath;
        private string _configurationPath;

        [SetUp]
        public void SetUp()
        {
            _directory = Path.Combine(Path.GetTempPath(),
                "ProxiFyre.ApplicationServicesTests." + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_directory);
            _enginePath = Path.Combine(_directory, "ProxiFyre.exe");
            File.WriteAllBytes(_enginePath, new byte[] { 0 });
            _configurationPath = ProxiFyrePaths.GetConfigurationPath(_enginePath);
        }

        [TearDown]
        public void TearDown()
        {
            if (Directory.Exists(_directory))
                Directory.Delete(_directory, true);
        }

        [Test]
        public void DirtyStateTransitionsFromLoadThroughEditAndSave()
        {
            var workspace = CreateLoadedWorkspace("original.example:1080");
            var dirtyChanges = new List<bool>();
            workspace.DirtyStateChanged += (sender, args) => dirtyChanges.Add(workspace.IsDirty);

            workspace.MarkDirty();
            workspace.MarkDirty();

            Assert.That(workspace.IsDirty, Is.True);
            CollectionAssert.AreEqual(new[] { true }, dirtyChanges,
                "Repeated edits while already dirty should not raise duplicate transitions.");

            var save = workspace.Save(false);

            Assert.Multiple(() =>
            {
                Assert.That(save.Status, Is.EqualTo(WorkspaceSaveStatus.Saved));
                Assert.That(workspace.IsDirty, Is.False);
                Assert.That(workspace.RestartRequired, Is.True);
                Assert.That(workspace.HasConfirmedApplied, Is.False);
            });
            CollectionAssert.AreEqual(new[] { true, false }, dirtyChanges);
        }

        [Test]
        public void MissingLiveConfigurationStartsDirtyUntilItIsSaved()
        {
            var workspace = new ConfigurationWorkspace();

            var loaded = workspace.Load(CreateEngineLocation());

            Assert.Multiple(() =>
            {
                Assert.That(loaded.LiveFileExists, Is.False);
                Assert.That(workspace.IsDirty, Is.True);
                Assert.That(workspace.RestartRequired, Is.False);
                Assert.That(workspace.HasConfirmedApplied, Is.False);
            });
        }

        [Test]
        public void FailedEngineLoadPreservesTheCompletePreviousWorkspace()
        {
            var workspace = CreateLoadedWorkspace("original.example:1080");
            workspace.Configuration.Proxies[0].Socks5ProxyEndpoint = "unsaved.example:2080";
            workspace.MarkDirty();
            var originalEnginePath = workspace.EnginePath;
            var originalConfigurationPath = workspace.ConfigurationPath;
            var originalConfiguration = workspace.Configuration;
            var originalFingerprint = workspace.CurrentFingerprint;

            var secondDirectory = Path.Combine(_directory, "second-engine");
            Directory.CreateDirectory(secondDirectory);
            var secondEngine = Path.Combine(secondDirectory, ProxiFyrePaths.EngineExecutableName);
            File.WriteAllBytes(secondEngine, new byte[] { 0 });
            File.WriteAllText(ProxiFyrePaths.GetConfigurationPath(secondEngine), "{ malformed json");

            Assert.Throws<ConfigurationFormatException>(() => workspace.Load(
                new EngineLocation(secondEngine,
                    ProxiFyreUI.Infrastructure.EngineLocationSource.UserSelection)));

            Assert.Multiple(() =>
            {
                Assert.That(workspace.EnginePath, Is.EqualTo(originalEnginePath));
                Assert.That(workspace.ConfigurationPath, Is.EqualTo(originalConfigurationPath));
                Assert.That(workspace.Configuration, Is.SameAs(originalConfiguration));
                Assert.That(workspace.Configuration.Proxies[0].Socks5ProxyEndpoint,
                    Is.EqualTo("unsaved.example:2080"));
                Assert.That(workspace.CurrentFingerprint, Is.EqualTo(originalFingerprint));
                Assert.That(workspace.IsDirty, Is.True);
            });
        }

        [Test]
        public void SaveDoesNotClaimConfigurationWasApplied()
        {
            var workspace = CreateEditedWorkspace("saved.example:2080");

            var save = workspace.Save(false);

            Assert.Multiple(() =>
            {
                Assert.That(save.Status, Is.EqualTo(WorkspaceSaveStatus.Saved));
                Assert.That(workspace.IsDirty, Is.False);
                Assert.That(workspace.RestartRequired, Is.True);
                Assert.That(workspace.HasConfirmedApplied, Is.False);
                Assert.That(ReadEndpoint(_configurationPath), Is.EqualTo("saved.example:2080"));
            });

            workspace.MarkApplied();

            Assert.Multiple(() =>
            {
                Assert.That(workspace.RestartRequired, Is.False);
                Assert.That(workspace.HasConfirmedApplied, Is.True);
            });
        }

        [Test]
        public void SaveReportsFingerprintReadFailureInsteadOfThrowing()
        {
            var initial = TestModels.ValidConfiguration();
            new ConfigurationSerializer().Save(_configurationPath, initial);
            var fileSystem = new ThrowingReadFileSystem();
            var workspace = new ConfigurationWorkspace(
                new ConfigurationFileStore(new ConfigurationSerializer(), fileSystem));
            workspace.Load(CreateEngineLocation());
            workspace.Configuration.Proxies[0].Socks5ProxyEndpoint = "edited.example:2180";
            workspace.MarkDirty();
            fileSystem.ThrowOnRead = true;

            WorkspaceSaveResult save = null;
            Assert.DoesNotThrow(() => save = workspace.Save(false));

            Assert.Multiple(() =>
            {
                Assert.That(save.Status, Is.EqualTo(WorkspaceSaveStatus.Failed));
                Assert.That(save.Error, Is.TypeOf<IOException>());
                Assert.That(workspace.IsDirty, Is.True);
                Assert.That(workspace.RestartRequired, Is.False);
            });
        }

        [Test]
        public void FingerprintReadFailureCannotConfirmAppliedConfiguration()
        {
            var initial = TestModels.ValidConfiguration();
            new ConfigurationSerializer().Save(_configurationPath, initial);
            var fileSystem = new ThrowingReadFileSystem();
            var workspace = new ConfigurationWorkspace(
                new ConfigurationFileStore(new ConfigurationSerializer(), fileSystem));
            workspace.Load(CreateEngineLocation());
            var expectedFingerprint = workspace.CurrentFingerprint;
            workspace.MarkApplied();
            fileSystem.ThrowOnRead = true;

            var isCurrent = true;
            var markedApplied = true;
            Assert.DoesNotThrow(() => isCurrent = workspace.IsFingerprintCurrent(expectedFingerprint));
            Assert.DoesNotThrow(() => markedApplied = workspace.TryMarkApplied(expectedFingerprint));

            Assert.Multiple(() =>
            {
                Assert.That(isCurrent, Is.False);
                Assert.That(markedApplied, Is.False);
                Assert.That(workspace.HasConfirmedApplied, Is.False);
            });
        }

        [Test]
        public async Task SuccessfulRestartMarksSavedConfigurationApplied()
        {
            var workspace = CreateEditedWorkspace("applied.example:3080");
            var registrationChecks = new List<string>();
            using (var service = FakeServiceController.Installed(
                ServiceOperationResult.Completed(RunningStatus(), "Restarted.",
                    confirmsConfigurationReloaded: true)))
            {
                var coordinator = new ConfigurationApplyCoordinator(workspace, service,
                    enginePath =>
                    {
                        registrationChecks.Add(enginePath);
                        return true;
                    });

                var result = await coordinator.SaveAndApplyAsync(false, _enginePath, false, false,
                    OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome, Is.EqualTo(ConfigurationApplyOutcome.Applied));
                    Assert.That(result.IsApplied, Is.True);
                    Assert.That(result.FinalConfigurationConfirmedRunning, Is.True);
                    Assert.That(result.WasRolledBack, Is.False);
                    Assert.That(service.GetStatusCalls, Is.EqualTo(1));
                    Assert.That(service.RestartCalls, Is.EqualTo(1));
                    Assert.That(service.LastRestartEnginePath, Is.EqualTo(_enginePath));
                    Assert.That(service.LastRestartPreLaunchGuard, Is.Not.Null);
                    Assert.That(service.LastRestartPreLaunchGuard(), Is.True);
                    Assert.That(registrationChecks, Is.All.EqualTo(_enginePath));
                    Assert.That(workspace.IsDirty, Is.False);
                    Assert.That(workspace.RestartRequired, Is.False);
                    Assert.That(workspace.HasConfirmedApplied, Is.True);
                    Assert.That(ReadEndpoint(_configurationPath), Is.EqualTo("applied.example:3080"));
                });
            }
        }

        [Test]
        public async Task RunningResultWithoutReloadDoesNotClaimConfigurationApplied()
        {
            var workspace = CreateEditedWorkspace("not-reloaded.example:3180");
            using (var service = FakeServiceController.Installed(
                ServiceOperationResult.Completed(RunningStatus(), "Already running.")))
            {
                var result = await new ConfigurationApplyCoordinator(workspace, service)
                    .SaveAndApplyAsync(false, _enginePath, false, false,
                        OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome,
                        Is.EqualTo(ConfigurationApplyOutcome.ConfigurationReloadNotConfirmed));
                    Assert.That(result.IsApplied, Is.False);
                    Assert.That(result.ServiceResult.Success, Is.True);
                    Assert.That(result.ServiceResult.ConfirmsConfigurationReloaded, Is.False);
                    Assert.That(workspace.RestartRequired, Is.True);
                    Assert.That(workspace.HasConfirmedApplied, Is.False);
                });
            }
        }

        [Test]
        public async Task FailedRestartLeavesSavedConfigurationPendingAndBackupRecoverable()
        {
            var workspace = CreateEditedWorkspace("failed.example:4080");
            using (var service = FakeServiceController.Installed(
                ServiceOperationResult.Failed(StoppedStatus(), "Engine startup failed.")))
            {
                var coordinator = new ConfigurationApplyCoordinator(workspace, service);

                var result = await coordinator.SaveAndApplyAsync(false, _enginePath, false, false,
                    OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome, Is.EqualTo(ConfigurationApplyOutcome.ServiceRestartFailed));
                    Assert.That(result.IsApplied, Is.False);
                    Assert.That(result.WasRolledBack, Is.False);
                    Assert.That(result.SaveResult.BackupCreated, Is.True);
                    Assert.That(File.Exists(result.SaveResult.BackupPath), Is.True);
                    Assert.That(ReadEndpoint(result.SaveResult.BackupPath), Is.EqualTo("original.example:1080"));
                    Assert.That(ReadEndpoint(_configurationPath), Is.EqualTo("failed.example:4080"));
                    Assert.That(service.RestartCalls, Is.EqualTo(1));
                    Assert.That(workspace.RestartRequired, Is.True);
                    Assert.That(workspace.HasConfirmedApplied, Is.False);
                });
            }
        }

        [Test]
        public async Task MissingPacketFilterNeverRollsBackConfigurationOrRetriesRestart()
        {
            var workspace = CreateEditedWorkspace("driver-missing.example:4580");
            var dependencyFailure = ServiceOperationResult.Failed(
                StoppedStatus(),
                "Windows Packet Filter is not available.",
                "The NDISRD device could not be opened.", null, false,
                ServiceOperationFailureKind.DependencyUnavailable);
            using (var service = FakeServiceController.Installed(dependencyFailure,
                       ServiceOperationResult.Completed(RunningStatus(), "Unexpected retry.")))
            {
                var coordinator = new ConfigurationApplyCoordinator(workspace, service);

                var result = await coordinator.SaveAndApplyAsync(false, _enginePath, false, true,
                    OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome,
                        Is.EqualTo(ConfigurationApplyOutcome.DependencyUnavailable));
                    Assert.That(result.RollbackAttempted, Is.False);
                    Assert.That(result.WasRolledBack, Is.False);
                    Assert.That(service.RestartCalls, Is.EqualTo(1));
                    Assert.That(ReadEndpoint(_configurationPath),
                        Is.EqualTo("driver-missing.example:4580"));
                    Assert.That(workspace.RestartRequired, Is.True);
                    Assert.That(workspace.HasConfirmedApplied, Is.False);
                });
            }
        }

        [Test]
        public async Task FailedRestartCanRollbackAndPerformsOnlyOneControlledRetry()
        {
            var workspace = CreateEditedWorkspace("bad.example:5080");
            using (var service = FakeServiceController.Installed(
                ServiceOperationResult.Failed(StoppedStatus(), "New configuration failed."),
                ServiceOperationResult.Completed(RunningStatus(), "Restored configuration started.",
                    confirmsConfigurationReloaded: true)))
            {
                var coordinator = new ConfigurationApplyCoordinator(workspace, service);

                var result = await coordinator.SaveAndApplyAsync(false, _enginePath, false, true,
                    OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome, Is.EqualTo(ConfigurationApplyOutcome.RolledBackAndRunning));
                    Assert.That(result.IsApplied, Is.False,
                        "The requested configuration failed; only the restored configuration is running.");
                    Assert.That(result.FinalConfigurationConfirmedRunning, Is.True);
                    Assert.That(result.WasRolledBack, Is.True);
                    Assert.That(service.RestartCalls, Is.EqualTo(2),
                        "One failed apply and one controlled restart after rollback are expected.");
                    Assert.That(ReadEndpoint(_configurationPath), Is.EqualTo("original.example:1080"));
                    Assert.That(workspace.Configuration.Proxies[0].Socks5ProxyEndpoint,
                        Is.EqualTo("original.example:1080"));
                    Assert.That(workspace.RestartRequired, Is.False);
                    Assert.That(workspace.HasConfirmedApplied, Is.True);
                });
            }
        }

        [Test]
        public async Task RollbackRefusesSaveResultSupersededByANewerSave()
        {
            var workspace = CreateEditedWorkspace("first-save.example:5180");
            var firstSave = workspace.Save(false);
            workspace.Configuration.Proxies[0].Socks5ProxyEndpoint = "newer-save.example:5280";
            workspace.MarkDirty();
            var newerSave = workspace.Save(false);
            using (var service = FakeServiceController.Installed())
            {
                var coordinator = new ConfigurationApplyCoordinator(workspace, service);

                var result = await coordinator.RollbackAndRestartAsync(firstSave,
                    OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(firstSave.Status, Is.EqualTo(WorkspaceSaveStatus.Saved));
                    Assert.That(newerSave.Status, Is.EqualTo(WorkspaceSaveStatus.Saved));
                    Assert.That(firstSave.SavedFingerprint, Is.Not.EqualTo(newerSave.SavedFingerprint));
                    Assert.That(result.Outcome, Is.EqualTo(ConfigurationApplyOutcome.RollbackFailed));
                    Assert.That(result.RollbackAttempted, Is.True);
                    Assert.That(result.WasRolledBack, Is.False,
                        "Refusing a stale rollback must not claim that files were restored.");
                    Assert.That(result.RollbackError, Is.TypeOf<ConfigurationFileChangedException>());
                    Assert.That(service.RestartCalls, Is.Zero);
                    Assert.That(ReadEndpoint(_configurationPath), Is.EqualTo("newer-save.example:5280"));
                    Assert.That(workspace.RestartRequired, Is.True);
                    Assert.That(workspace.HasConfirmedApplied, Is.False);
                });
            }
        }

        [Test]
        public async Task ApplyRefusesSaveResultSupersededByANewerSave()
        {
            var workspace = CreateEditedWorkspace("first-apply.example:5380");
            var firstSave = workspace.Save(false);
            workspace.Configuration.Proxies[0].Socks5ProxyEndpoint = "newer-apply.example:5480";
            workspace.MarkDirty();
            var newerSave = workspace.Save(false);
            using (var service = FakeServiceController.Installed())
            {
                var result = await new ConfigurationApplyCoordinator(workspace, service)
                    .ApplySavedConfigurationAsync(firstSave, _enginePath, false, false,
                        OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(newerSave.Status, Is.EqualTo(WorkspaceSaveStatus.Saved));
                    Assert.That(result.Outcome,
                        Is.EqualTo(ConfigurationApplyOutcome.SavedConfigurationChangedBeforeApply));
                    Assert.That(result.IsApplied, Is.False);
                    Assert.That(service.GetStatusCalls, Is.Zero);
                    Assert.That(service.RestartCalls, Is.Zero);
                    Assert.That(workspace.HasConfirmedApplied, Is.False);
                    Assert.That(ReadEndpoint(_configurationPath), Is.EqualTo("newer-apply.example:5480"));
                });
            }
        }

        [Test]
        public async Task ExternalEditDuringRestartPreventsAppliedClaim()
        {
            var workspace = CreateEditedWorkspace("requested.example:5580");
            var save = workspace.Save(false);
            using (var service = FakeServiceController.Installed(
                ServiceOperationResult.Completed(RunningStatus(), "Restarted.",
                    confirmsConfigurationReloaded: true)))
            {
                service.RestartAction = () =>
                {
                    var external = TestModels.ValidConfiguration();
                    external.Proxies[0].Socks5ProxyEndpoint = "external-during-restart.example:5680";
                    new ConfigurationSerializer().Save(_configurationPath, external);
                };

                var result = await new ConfigurationApplyCoordinator(workspace, service)
                    .ApplySavedConfigurationAsync(save, _enginePath, false, false,
                        OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome,
                        Is.EqualTo(ConfigurationApplyOutcome.SavedConfigurationChangedDuringApply));
                    Assert.That(result.IsApplied, Is.False);
                    Assert.That(result.FinalConfigurationConfirmedRunning, Is.False);
                    Assert.That(service.RestartCalls, Is.EqualTo(1));
                    Assert.That(workspace.RestartRequired, Is.True);
                    Assert.That(workspace.HasConfirmedApplied, Is.False);
                    Assert.That(ReadEndpoint(_configurationPath),
                        Is.EqualTo("external-during-restart.example:5680"));
                });
            }
        }

        [Test]
        public async Task ChangedServiceEngineStopsApplyBeforeRestart()
        {
            var workspace = CreateEditedWorkspace("requested.example:5780");
            var save = workspace.Save(false);
            using (var service = FakeServiceController.Installed())
            {
                var result = await new ConfigurationApplyCoordinator(workspace, service,
                        enginePath => false)
                    .ApplySavedConfigurationAsync(save, _enginePath, false, false,
                        OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome, Is.EqualTo(ConfigurationApplyOutcome.ServiceEngineChanged));
                    Assert.That(service.RestartCalls, Is.Zero);
                    Assert.That(workspace.RestartRequired, Is.True);
                    Assert.That(workspace.HasConfirmedApplied, Is.False);
                });
            }
        }

        [Test]
        public async Task ServiceEngineChangeDuringRestartPreventsAppliedClaim()
        {
            var workspace = CreateEditedWorkspace("requested.example:5880");
            var save = workspace.Save(false);
            var registrationChecks = new Queue<bool>(new[] { true, false });
            using (var service = FakeServiceController.Installed(
                ServiceOperationResult.Completed(RunningStatus(), "Restarted.",
                    confirmsConfigurationReloaded: true)))
            {
                var result = await new ConfigurationApplyCoordinator(workspace, service,
                        enginePath => registrationChecks.Dequeue())
                    .ApplySavedConfigurationAsync(save, _enginePath, false, false,
                        OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome, Is.EqualTo(ConfigurationApplyOutcome.ServiceEngineChanged));
                    Assert.That(service.RestartCalls, Is.EqualTo(1));
                    Assert.That(workspace.RestartRequired, Is.True);
                    Assert.That(workspace.HasConfirmedApplied, Is.False);
                });
            }
        }

        [Test]
        public async Task ServiceEngineChangeAfterRestorePreservesRolledBackState()
        {
            var workspace = CreateEditedWorkspace("requested.example:5980");
            var save = workspace.Save(false);
            var registrationChecks = new Queue<bool>(new[] { true, false });
            using (var service = FakeServiceController.Installed())
            {
                var result = await new ConfigurationApplyCoordinator(workspace, service,
                        enginePath => registrationChecks.Dequeue())
                    .RollbackAndRestartAsync(save, OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome,
                        Is.EqualTo(ConfigurationApplyOutcome.RolledBackServiceEngineChanged));
                    Assert.That(result.WasRolledBack, Is.True);
                    Assert.That(result.RollbackAttempted, Is.True);
                    Assert.That(service.RestartCalls, Is.Zero);
                    Assert.That(workspace.RestartRequired, Is.True);
                    Assert.That(workspace.HasConfirmedApplied, Is.False);
                    Assert.That(ReadEndpoint(_configurationPath), Is.EqualTo("original.example:1080"));
                });
            }
        }

        [Test]
        public async Task ServiceNotInstalledSavesWithoutPretendingApplySucceeded()
        {
            var workspace = CreateEditedWorkspace("saved-only.example:6080");
            using (var service = FakeServiceController.NotInstalled())
            {
                var coordinator = new ConfigurationApplyCoordinator(workspace, service);

                var result = await coordinator.SaveAndApplyAsync(false, _enginePath, false, false,
                    OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome, Is.EqualTo(ConfigurationApplyOutcome.SavedServiceNotInstalled));
                    Assert.That(result.IsApplied, Is.False);
                    Assert.That(service.InstallCalls, Is.Zero);
                    Assert.That(service.StartCalls, Is.Zero);
                    Assert.That(service.RestartCalls, Is.Zero);
                    Assert.That(workspace.IsDirty, Is.False);
                    Assert.That(workspace.RestartRequired, Is.True);
                    Assert.That(workspace.HasConfirmedApplied, Is.False);
                    Assert.That(ReadEndpoint(_configurationPath), Is.EqualTo("saved-only.example:6080"));
                });
            }
        }

        [TestCase(ProxiFyreServiceState.Error)]
        [TestCase(ProxiFyreServiceState.Unknown)]
        public async Task UnverifiableServiceStateStopsApplyBeforeAnyScmMutation(
            ProxiFyreServiceState state)
        {
            var workspace = CreateEditedWorkspace("unknown-service.example:5980");
            using (var service = FakeServiceController.WithStatus(
                new ServiceStatusInfo(state, "SCM status query failed")))
            {
                var result = await new ConfigurationApplyCoordinator(workspace, service)
                    .SaveAndApplyAsync(false, _enginePath, true, false,
                        OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome,
                        Is.EqualTo(ConfigurationApplyOutcome.ServiceStatusUnavailable));
                    Assert.That(result.IsApplied, Is.False);
                    Assert.That(result.ServiceResult.Success, Is.False);
                    Assert.That(service.GetStatusCalls, Is.EqualTo(1));
                    Assert.That(service.InstallCalls, Is.Zero);
                    Assert.That(service.StartCalls, Is.Zero);
                    Assert.That(service.RestartCalls, Is.Zero);
                    Assert.That(workspace.RestartRequired, Is.True);
                    Assert.That(workspace.HasConfirmedApplied, Is.False);
                });
            }
        }

        [Test]
        public async Task DeletionPendingServiceStopsApplyBeforeAnyScmMutation()
        {
            var workspace = CreateEditedWorkspace("deletion-pending.example:5980");
            using (var service = FakeServiceController.WithStatus(
                new ServiceStatusInfo(ProxiFyreServiceState.DeletionPending)))
            {
                var result = await new ConfigurationApplyCoordinator(workspace, service)
                    .SaveAndApplyAsync(false, _enginePath, true, false,
                        OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome,
                        Is.EqualTo(ConfigurationApplyOutcome.ServiceStatusUnavailable));
                    Assert.That(result.ServiceResult.Success, Is.False);
                    Assert.That(result.ServiceResult.Message, Does.Contain("marked for deletion"));
                    Assert.That(service.InstallCalls, Is.Zero);
                    Assert.That(service.StartCalls, Is.Zero);
                    Assert.That(service.RestartCalls, Is.Zero);
                    Assert.That(workspace.RestartRequired, Is.True);
                    Assert.That(workspace.HasConfirmedApplied, Is.False);
                });
            }
        }

        [Test]
        public async Task ServiceNotInstalledCanUseExplicitInstallAndStartFlow()
        {
            var workspace = CreateEditedWorkspace("installed.example:7080");
            using (var service = FakeServiceController.NotInstalled())
            {
                service.InstallResult = ServiceOperationResult.Completed(StoppedStatus(), "Installed.");
                service.StartResult = ServiceOperationResult.Completed(RunningStatus(), "Started.",
                    confirmsConfigurationReloaded: true);
                var coordinator = new ConfigurationApplyCoordinator(workspace, service);

                var result = await coordinator.SaveAndApplyAsync(false, _enginePath, true, false,
                    OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome, Is.EqualTo(ConfigurationApplyOutcome.Applied));
                    Assert.That(service.InstallCalls, Is.EqualTo(1));
                    Assert.That(service.LastInstallEnginePath, Is.EqualTo(_enginePath));
                    Assert.That(service.StartCalls, Is.EqualTo(1));
                    Assert.That(service.LastStartEnginePath, Is.EqualTo(_enginePath));
                    Assert.That(service.LastStartPreLaunchGuard, Is.Not.Null);
                    Assert.That(service.LastStartPreLaunchGuard(), Is.True);
                    Assert.That(service.RestartCalls, Is.Zero);
                    Assert.That(workspace.RestartRequired, Is.False);
                    Assert.That(workspace.HasConfirmedApplied, Is.True);
                });
            }
        }

        [Test]
        public async Task MissingPacketFilterPreventsPartialInstallAndStartWorkflow()
        {
            var workspace = CreateEditedWorkspace("driver-required.example:7130");
            using (var service = FakeServiceController.NotInstalled())
            {
                service.InstallResult = ServiceOperationResult.Failed(
                    new ServiceStatusInfo(ProxiFyreServiceState.NotInstalled),
                    "Windows Packet Filter is not available.", null, null, false,
                    ServiceOperationFailureKind.DependencyUnavailable);
                var coordinator = new ConfigurationApplyCoordinator(workspace, service);

                var result = await coordinator.SaveAndApplyAsync(false, _enginePath, true, false,
                    OperationTimeout, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome,
                        Is.EqualTo(ConfigurationApplyOutcome.DependencyUnavailable));
                    Assert.That(service.InstallCalls, Is.EqualTo(1));
                    Assert.That(service.StartCalls, Is.Zero);
                    Assert.That(service.RestartCalls, Is.Zero);
                    Assert.That(result.RollbackAttempted, Is.False);
                    Assert.That(workspace.RestartRequired, Is.True);
                    Assert.That(workspace.HasConfirmedApplied, Is.False);
                });
            }
        }

        [Test]
        public async Task InstallAndStartShareOneShrinkingOperationTimeoutBudget()
        {
            var workspace = CreateEditedWorkspace("budget.example:7180");
            using (var service = FakeServiceController.NotInstalled())
            {
                service.InstallResult = ServiceOperationResult.Completed(StoppedStatus(), "Installed.");
                service.StartResult = ServiceOperationResult.Completed(RunningStatus(), "Started.",
                    confirmsConfigurationReloaded: true);
                service.InstallDelay = TimeSpan.FromMilliseconds(80);
                var coordinator = new ConfigurationApplyCoordinator(workspace, service);
                var totalBudget = TimeSpan.FromSeconds(5);

                var result = await coordinator.SaveAndApplyAsync(false, _enginePath, true, false,
                    totalBudget, CancellationToken.None);

                Assert.Multiple(() =>
                {
                    Assert.That(result.Outcome, Is.EqualTo(ConfigurationApplyOutcome.Applied));
                    Assert.That(service.LastInstallTimeout, Is.GreaterThan(TimeSpan.Zero));
                    Assert.That(service.LastInstallTimeout, Is.LessThanOrEqualTo(totalBudget));
                    Assert.That(service.LastStartTimeout, Is.GreaterThan(TimeSpan.Zero));
                    Assert.That(service.LastStartTimeout, Is.LessThan(service.LastInstallTimeout),
                        "Start must receive only the budget remaining after installation.");
                });
            }
        }

        [Test]
        public void DiagnosticsRedactPasswordFormsUriCredentialsAndExplicitSecrets()
        {
            const string explicitSecret = "opaque-api-token";
            var diagnostics = new DiagnosticsBuilder();
            var context = new DiagnosticsContext
            {
                EnginePath = _enginePath,
                ConfigurationPath = _configurationPath,
                LogDirectoryPath = Path.Combine(_directory, "logs"),
                ServiceStatus = new ServiceStatusInfo(ProxiFyreServiceState.Error,
                    "ERROR password=service-secret; token=" + explicitSecret),
                Validation = new ValidationResult(new[]
                {
                    new ValidationIssue(ValidationSeverity.Warning, "TEST_WARNING",
                        "Warning contains " + explicitSecret, "proxies[0]")
                }),
                RecentMessages = new[]
                {
                    "INFO harmless message",
                    "ERROR {\"password\":\"json-secret\"} password=plain-secret " +
                    "socks5://alice:uri-secret@proxy.example " + explicitSecret
                },
                Secrets = new[] { explicitSecret }
            };

            var report = diagnostics.Build(context);

            Assert.Multiple(() =>
            {
                Assert.That(report, Does.Contain("<redacted>"));
                Assert.That(report, Does.Not.Contain("service-secret"));
                Assert.That(report, Does.Not.Contain("json-secret"));
                Assert.That(report, Does.Not.Contain("plain-secret"));
                Assert.That(report, Does.Not.Contain("alice"));
                Assert.That(report, Does.Not.Contain("uri-secret"));
                Assert.That(report, Does.Not.Contain(explicitSecret));
                Assert.That(report, Does.Not.Contain("harmless message"),
                    "Diagnostics include only recent warning/error messages.");
            });
        }

        private ConfigurationWorkspace CreateLoadedWorkspace(string endpoint)
        {
            var initial = TestModels.ValidConfiguration();
            initial.Proxies[0].Socks5ProxyEndpoint = endpoint;
            new ConfigurationSerializer().Save(_configurationPath, initial);

            var workspace = new ConfigurationWorkspace();
            var loaded = workspace.Load(CreateEngineLocation());
            Assert.That(loaded.LiveFileExists, Is.True);
            Assert.That(loaded.Validation.HasErrors, Is.False);
            Assert.That(workspace.IsDirty, Is.False);
            return workspace;
        }

        private ConfigurationWorkspace CreateEditedWorkspace(string endpoint)
        {
            var workspace = CreateLoadedWorkspace("original.example:1080");
            workspace.Configuration.Proxies[0].Socks5ProxyEndpoint = endpoint;
            workspace.MarkDirty();
            return workspace;
        }

        private EngineLocation CreateEngineLocation()
        {
            return new EngineLocation(_enginePath,
                ProxiFyreUI.Infrastructure.EngineLocationSource.UserSelection);
        }

        private static string ReadEndpoint(string path)
        {
            return new ConfigurationFileStore().Load(path).Configuration.Proxies[0].Socks5ProxyEndpoint;
        }

        private static ServiceStatusInfo RunningStatus()
        {
            return new ServiceStatusInfo(ProxiFyreServiceState.Running);
        }

        private static ServiceStatusInfo StoppedStatus()
        {
            return new ServiceStatusInfo(ProxiFyreServiceState.Stopped);
        }

        private sealed class FakeServiceController : IProxiFyreServiceController
        {
            private readonly Queue<ServiceOperationResult> _restartResults =
                new Queue<ServiceOperationResult>();

            private FakeServiceController(ServiceStatusInfo status,
                IEnumerable<ServiceOperationResult> restartResults)
            {
                Status = status;
                foreach (var result in restartResults)
                    _restartResults.Enqueue(result);
            }

            public ServiceStatusInfo Status { get; set; }
            public ServiceOperationResult InstallResult { get; set; }
            public ServiceOperationResult StartResult { get; set; }
            public TimeSpan InstallDelay { get; set; }
            public Action RestartAction { get; set; }
            public int GetStatusCalls { get; private set; }
            public int StartCalls { get; private set; }
            public int StopCalls { get; private set; }
            public int RestartCalls { get; private set; }
            public int InstallCalls { get; private set; }
            public int UninstallCalls { get; private set; }
            public string LastInstallEnginePath { get; private set; }
            public string LastStartEnginePath { get; private set; }
            public string LastRestartEnginePath { get; private set; }
            public Func<bool> LastStartPreLaunchGuard { get; private set; }
            public Func<bool> LastRestartPreLaunchGuard { get; private set; }
            public TimeSpan LastInstallTimeout { get; private set; }
            public TimeSpan LastStartTimeout { get; private set; }

            public static FakeServiceController Installed(params ServiceOperationResult[] restartResults)
            {
                return new FakeServiceController(RunningStatus(), restartResults);
            }

            public static FakeServiceController NotInstalled()
            {
                return new FakeServiceController(
                    new ServiceStatusInfo(ProxiFyreServiceState.NotInstalled),
                    new ServiceOperationResult[0]);
            }

            public static FakeServiceController WithStatus(ServiceStatusInfo status)
            {
                return new FakeServiceController(status, new ServiceOperationResult[0]);
            }

            public Task<ServiceStatusInfo> GetStatusAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                GetStatusCalls++;
                return Task.FromResult(Status);
            }

            public Task<ServiceOperationResult> StartAsync(string expectedEnginePath,
                Func<bool> preLaunchGuard, TimeSpan timeout, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                StartCalls++;
                LastStartEnginePath = expectedEnginePath;
                LastStartPreLaunchGuard = preLaunchGuard;
                LastStartTimeout = timeout;
                if (StartResult == null)
                    throw new InvalidOperationException("The test did not configure a start result.");
                return Task.FromResult(StartResult);
            }

            public Task<ServiceOperationResult> StopAsync(TimeSpan timeout, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                StopCalls++;
                throw new InvalidOperationException("Stop was not expected in this coordinator test.");
            }

            public Task<ServiceOperationResult> RestartAsync(string expectedEnginePath,
                Func<bool> preLaunchGuard, TimeSpan timeout, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                RestartCalls++;
                LastRestartEnginePath = expectedEnginePath;
                LastRestartPreLaunchGuard = preLaunchGuard;
                if (_restartResults.Count == 0)
                    throw new InvalidOperationException("The test did not configure another restart result.");
                var result = _restartResults.Dequeue();
                RestartAction?.Invoke();
                return Task.FromResult(result);
            }

            public async Task<ServiceOperationResult> InstallAsync(string enginePath, TimeSpan timeout,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                InstallCalls++;
                LastInstallEnginePath = enginePath;
                LastInstallTimeout = timeout;
                if (InstallResult == null)
                    throw new InvalidOperationException("The test did not configure an install result.");
                if (InstallDelay > TimeSpan.Zero)
                    await Task.Delay(InstallDelay, cancellationToken).ConfigureAwait(false);
                return InstallResult;
            }

            public Task<ServiceOperationResult> UninstallAsync(string enginePath,
                Func<bool> preLaunchGuard, TimeSpan timeout, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                UninstallCalls++;
                throw new InvalidOperationException("Uninstall was not expected in this coordinator test.");
            }

            public void Dispose()
            {
            }
        }

        private sealed class ThrowingReadFileSystem : IConfigurationFileSystem
        {
            private readonly PhysicalConfigurationFileSystem _inner =
                new PhysicalConfigurationFileSystem();

            public bool ThrowOnRead { get; set; }

            public bool FileExists(string path) => _inner.FileExists(path);

            public byte[] ReadAllBytes(string path)
            {
                if (ThrowOnRead)
                    throw new IOException("Deliberate fingerprint read failure.");
                return _inner.ReadAllBytes(path);
            }

            public long GetFileLength(string path) => _inner.GetFileLength(path);

            public DateTime GetLastWriteTimeUtc(string path) =>
                _inner.GetLastWriteTimeUtc(path);

            public void CreateDirectory(string path) => _inner.CreateDirectory(path);

            public void DeleteFile(string path) => _inner.DeleteFile(path);

            public void MoveFile(string sourcePath, string destinationPath) =>
                _inner.MoveFile(sourcePath, destinationPath);

            public void ReplaceFile(string sourcePath, string destinationPath, string backupPath) =>
                _inner.ReplaceFile(sourcePath, destinationPath, backupPath);

            public void WriteAllTextAndFlush(string path, string content) =>
                _inner.WriteAllTextAndFlush(path, content);
        }
    }
}
