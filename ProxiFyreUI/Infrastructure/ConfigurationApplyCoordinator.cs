using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace ProxiFyreUI.Infrastructure
{
    public enum ConfigurationApplyOutcome
    {
        Applied,
        SavedServiceNotInstalled,
        ValidationFailed,
        ExternalChangeDetected,
        SavedConfigurationChangedBeforeApply,
        SavedConfigurationChangedDuringApply,
        ServiceStatusUnavailable,
        DependencyUnavailable,
        SaveFailed,
        InstallFailed,
        ServiceRestartFailed,
        RolledBackAndRunning,
        RollbackFailed,
        RolledBackServiceRestartFailed,
        RolledBackConfigurationChanged
    }

    public sealed class ConfigurationApplyResult
    {
        public ConfigurationApplyOutcome Outcome { get; internal set; }
        public WorkspaceSaveResult SaveResult { get; internal set; }
        public ServiceOperationResult ServiceResult { get; internal set; }
        public Exception RollbackError { get; internal set; }
        public bool IsApplied => Outcome == ConfigurationApplyOutcome.Applied;
        public bool FinalConfigurationConfirmedRunning =>
            Outcome == ConfigurationApplyOutcome.Applied ||
            Outcome == ConfigurationApplyOutcome.RolledBackAndRunning;
        public bool WasRolledBack => Outcome == ConfigurationApplyOutcome.RolledBackAndRunning ||
                                     Outcome == ConfigurationApplyOutcome.RolledBackServiceRestartFailed ||
                                     Outcome == ConfigurationApplyOutcome.RolledBackConfigurationChanged;
        public bool RollbackAttempted => WasRolledBack || Outcome == ConfigurationApplyOutcome.RollbackFailed;
    }

    /// <summary>
    /// Coordinates save, service restart, and at most one controlled rollback/restart.
    /// User-facing confirmation policy remains in the form; this service keeps state changes testable.
    /// </summary>
    public sealed class ConfigurationApplyCoordinator
    {
        private readonly ConfigurationWorkspace _workspace;
        private readonly IProxiFyreServiceController _serviceController;

        public ConfigurationApplyCoordinator(ConfigurationWorkspace workspace,
            IProxiFyreServiceController serviceController)
        {
            _workspace = workspace ?? throw new ArgumentNullException(nameof(workspace));
            _serviceController = serviceController ?? throw new ArgumentNullException(nameof(serviceController));
        }

        public async Task<ConfigurationApplyResult> SaveAndApplyAsync(bool overwriteExternalChanges,
            string enginePath, bool installIfMissing, bool rollbackOnFailure, TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            var save = _workspace.Save(overwriteExternalChanges);
            if (save.Status != WorkspaceSaveStatus.Saved)
            {
                return new ConfigurationApplyResult
                {
                    SaveResult = save,
                    Outcome = MapSaveOutcome(save.Status)
                };
            }

            return await ApplySavedConfigurationAsync(save, enginePath, installIfMissing,
                rollbackOnFailure, timeout, cancellationToken).ConfigureAwait(false);
        }

        public async Task<ConfigurationApplyResult> ApplySavedConfigurationAsync(WorkspaceSaveResult save,
            string enginePath, bool installIfMissing, bool rollbackOnFailure, TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            if (save == null)
                throw new ArgumentNullException(nameof(save));
            if (save.Status != WorkspaceSaveStatus.Saved)
                return new ConfigurationApplyResult { SaveResult = save, Outcome = MapSaveOutcome(save.Status) };
            if (!_workspace.IsSaveCurrent(save))
                return ConfigurationChanged(save, null, false);

            var operationClock = Stopwatch.StartNew();
            var status = await _serviceController.GetStatusAsync(cancellationToken).ConfigureAwait(false);
            if (!_workspace.IsSaveCurrent(save))
                return ConfigurationChanged(save, null, false);
            if (!status.IsInstallationKnown)
            {
                return new ConfigurationApplyResult
                {
                    SaveResult = save,
                    ServiceResult = ServiceOperationResult.Failed(status,
                        "The ProxiFyre service installation state could not be verified."),
                    Outcome = ConfigurationApplyOutcome.ServiceStatusUnavailable
                };
            }
            if (!status.IsInstalled)
            {
                if (!installIfMissing)
                {
                    return new ConfigurationApplyResult
                    {
                        SaveResult = save,
                        Outcome = ConfigurationApplyOutcome.SavedServiceNotInstalled
                    };
                }

                var remaining = Remaining(timeout, operationClock);
                if (remaining <= TimeSpan.Zero)
                {
                    return new ConfigurationApplyResult
                    {
                        SaveResult = save,
                        ServiceResult = TimedOut(status, "Service installation did not start before the apply timeout."),
                        Outcome = ConfigurationApplyOutcome.InstallFailed
                    };
                }

                var install = await _serviceController.InstallAsync(enginePath, remaining, cancellationToken)
                    .ConfigureAwait(false);
                if (!install.Success)
                {
                    return new ConfigurationApplyResult
                    {
                        SaveResult = save,
                        ServiceResult = install,
                        Outcome = install.FailureKind == ServiceOperationFailureKind.DependencyUnavailable
                            ? ConfigurationApplyOutcome.DependencyUnavailable
                            : ConfigurationApplyOutcome.InstallFailed
                    };
                }

                if (!_workspace.IsSaveCurrent(save))
                    return ConfigurationChanged(save, install, false);

                remaining = Remaining(timeout, operationClock);
                var start = remaining <= TimeSpan.Zero
                    ? TimedOut(install.Status, "The service was installed, but start did not begin before the apply timeout.")
                    : await _serviceController.StartAsync(remaining, cancellationToken).ConfigureAwait(false);
                if (!_workspace.IsSaveCurrent(save))
                    return ConfigurationChanged(save, start, true);
                if (start.Success && start.Status?.IsRunning == true)
                {
                    if (!_workspace.TryMarkApplied(save.SavedFingerprint))
                        return ConfigurationChanged(save, start, true);
                    return new ConfigurationApplyResult
                    {
                        SaveResult = save,
                        ServiceResult = start,
                        Outcome = ConfigurationApplyOutcome.Applied
                    };
                }

                return await HandleRestartFailureAsync(save, start, rollbackOnFailure, timeout,
                    operationClock, cancellationToken).ConfigureAwait(false);
            }

            if (!_workspace.IsSaveCurrent(save))
                return ConfigurationChanged(save, null, false);
            var restartBudget = Remaining(timeout, operationClock);
            var restart = restartBudget <= TimeSpan.Zero
                ? TimedOut(status, "Service restart did not begin before the apply timeout.")
                : await _serviceController.RestartAsync(restartBudget, cancellationToken).ConfigureAwait(false);
            if (!_workspace.IsSaveCurrent(save))
                return ConfigurationChanged(save, restart, true);
            if (restart.Success && restart.Status?.IsRunning == true)
            {
                if (!_workspace.TryMarkApplied(save.SavedFingerprint))
                    return ConfigurationChanged(save, restart, true);
                return new ConfigurationApplyResult
                {
                    SaveResult = save,
                    ServiceResult = restart,
                    Outcome = ConfigurationApplyOutcome.Applied
                };
            }

            return await HandleRestartFailureAsync(save, restart, rollbackOnFailure, timeout,
                operationClock, cancellationToken).ConfigureAwait(false);
        }

        public async Task<ConfigurationApplyResult> RollbackAndRestartAsync(WorkspaceSaveResult save,
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            return await RollbackAndRestartAsync(save, timeout, Stopwatch.StartNew(), cancellationToken)
                .ConfigureAwait(false);
        }

        private async Task<ConfigurationApplyResult> RollbackAndRestartAsync(WorkspaceSaveResult save,
            TimeSpan timeout, Stopwatch operationClock, CancellationToken cancellationToken)
        {
            if (save == null)
                throw new ArgumentNullException(nameof(save));

            Exception rollbackError = null;
            if (!save.BackupCreated || string.IsNullOrWhiteSpace(save.BackupPath) ||
                !_workspace.TryRollback(save.BackupPath, save.BackupFingerprint,
                    save.SavedFingerprint, out rollbackError))
            {
                return new ConfigurationApplyResult
                {
                    SaveResult = save,
                    RollbackError = rollbackError ?? new InvalidOperationException(
                        "A backup from this save operation is not available."),
                    Outcome = ConfigurationApplyOutcome.RollbackFailed
                };
            }

            var restoredFingerprint = _workspace.CurrentFingerprint;
            if (!_workspace.IsFingerprintCurrent(restoredFingerprint))
            {
                return new ConfigurationApplyResult
                {
                    SaveResult = save,
                    Outcome = ConfigurationApplyOutcome.RolledBackConfigurationChanged
                };
            }

            var remaining = Remaining(timeout, operationClock);
            var restart = remaining <= TimeSpan.Zero
                ? TimedOut(null, "The previous configuration was restored, but restart did not begin before the apply timeout.")
                : await _serviceController.RestartAsync(remaining, cancellationToken).ConfigureAwait(false);
            if (!_workspace.IsFingerprintCurrent(restoredFingerprint))
            {
                return new ConfigurationApplyResult
                {
                    SaveResult = save,
                    ServiceResult = restart,
                    Outcome = ConfigurationApplyOutcome.RolledBackConfigurationChanged
                };
            }
            if (restart.Success && restart.Status?.IsRunning == true)
            {
                if (!_workspace.TryMarkApplied(restoredFingerprint))
                {
                    return new ConfigurationApplyResult
                    {
                        SaveResult = save,
                        ServiceResult = restart,
                        Outcome = ConfigurationApplyOutcome.RolledBackConfigurationChanged
                    };
                }
                return new ConfigurationApplyResult
                {
                    SaveResult = save,
                    ServiceResult = restart,
                    Outcome = ConfigurationApplyOutcome.RolledBackAndRunning
                };
            }

            return new ConfigurationApplyResult
            {
                SaveResult = save,
                ServiceResult = restart,
                Outcome = ConfigurationApplyOutcome.RolledBackServiceRestartFailed
            };
        }

        private async Task<ConfigurationApplyResult> HandleRestartFailureAsync(WorkspaceSaveResult save,
            ServiceOperationResult serviceResult, bool rollbackOnFailure, TimeSpan timeout,
            Stopwatch operationClock, CancellationToken cancellationToken)
        {
            if (serviceResult?.FailureKind == ServiceOperationFailureKind.DependencyUnavailable)
            {
                return new ConfigurationApplyResult
                {
                    SaveResult = save,
                    ServiceResult = serviceResult,
                    Outcome = ConfigurationApplyOutcome.DependencyUnavailable
                };
            }

            if (!rollbackOnFailure)
            {
                return new ConfigurationApplyResult
                {
                    SaveResult = save,
                    ServiceResult = serviceResult,
                    Outcome = ConfigurationApplyOutcome.ServiceRestartFailed
                };
            }

            return await RollbackAndRestartAsync(save, timeout, operationClock, cancellationToken)
                .ConfigureAwait(false);
        }

        private static TimeSpan Remaining(TimeSpan timeout, Stopwatch operationClock)
        {
            if (timeout <= TimeSpan.Zero)
                return TimeSpan.Zero;
            var remaining = timeout - operationClock.Elapsed;
            return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
        }

        private static ServiceOperationResult TimedOut(ServiceStatusInfo status, string message)
        {
            return ServiceOperationResult.Failed(
                status ?? new ServiceStatusInfo(ProxiFyreServiceState.Unknown),
                message, null, null, true);
        }

        private static ConfigurationApplyResult ConfigurationChanged(WorkspaceSaveResult save,
            ServiceOperationResult serviceResult, bool duringApply)
        {
            return new ConfigurationApplyResult
            {
                SaveResult = save,
                ServiceResult = serviceResult,
                Outcome = duringApply
                    ? ConfigurationApplyOutcome.SavedConfigurationChangedDuringApply
                    : ConfigurationApplyOutcome.SavedConfigurationChangedBeforeApply
            };
        }

        private static ConfigurationApplyOutcome MapSaveOutcome(WorkspaceSaveStatus status)
        {
            switch (status)
            {
                case WorkspaceSaveStatus.ValidationFailed:
                    return ConfigurationApplyOutcome.ValidationFailed;
                case WorkspaceSaveStatus.ExternalChangeDetected:
                    return ConfigurationApplyOutcome.ExternalChangeDetected;
                case WorkspaceSaveStatus.Failed:
                    return ConfigurationApplyOutcome.SaveFailed;
                default:
                    return ConfigurationApplyOutcome.SaveFailed;
            }
        }
    }
}
