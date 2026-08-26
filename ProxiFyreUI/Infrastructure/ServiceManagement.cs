using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using ProxiFyre.Configuration;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ProxiFyreUI.Infrastructure
{
    public enum ProxiFyreServiceState
    {
        NotInstalled,
        Stopped,
        StartPending,
        Running,
        StopPending,
        Paused,
        PausePending,
        ContinuePending,
        Unknown,
        Error,
        DeletionPending
    }

    public enum ServiceOperationFailureKind
    {
        None,
        General,
        TimedOut,
        DependencyUnavailable,
        StartupFailed
    }

    public enum ServiceStartupObservation
    {
        Pending,
        Running,
        Failed
    }

    public static class ServiceStartupStateClassifier
    {
        public static ServiceStartupObservation Classify(ProxiFyreServiceState state)
        {
            if (state == ProxiFyreServiceState.Running)
                return ServiceStartupObservation.Running;
            return state == ProxiFyreServiceState.StartPending
                ? ServiceStartupObservation.Pending
                : ServiceStartupObservation.Failed;
        }
    }

    public static class ServiceStartupCompletionEvaluator
    {
        public static ServiceOperationResult Evaluate(ServiceStatusInfo finalStatus)
        {
            if (finalStatus != null && finalStatus.IsRunning)
            {
                return ServiceOperationResult.Completed(finalStatus,
                    "The ProxiFyre service is running.", confirmsConfigurationReloaded: true);
            }

            var status = finalStatus ?? new ServiceStatusInfo(ProxiFyreServiceState.Error,
                "The final service state could not be read.");
            return ServiceOperationResult.Failed(status,
                "The service reached Running, but its final Running state could not be confirmed. " +
                "Review the recent engine logs for the underlying error.",
                null, null, false, ServiceOperationFailureKind.StartupFailed);
        }
    }

    public static class ServiceStopCompletionEvaluator
    {
        public static ServiceOperationResult Evaluate(ServiceStatusInfo finalStatus)
        {
            var status = finalStatus ?? new ServiceStatusInfo(ProxiFyreServiceState.Error,
                "The final service state could not be read.");
            if (status.State == ProxiFyreServiceState.Stopped)
            {
                return ServiceOperationResult.Completed(status,
                    "The ProxiFyre service is stopped.");
            }
            if (status.State == ProxiFyreServiceState.NotInstalled)
            {
                return ServiceOperationResult.Completed(status,
                    "The ProxiFyre service is no longer installed.");
            }

            return ServiceOperationResult.Failed(status,
                "The service reached Stopped, but its final stopped state could not be confirmed.");
        }
    }

    public static class ServiceOperationBudget
    {
        public static TimeSpan Remaining(TimeSpan timeout, TimeSpan elapsed)
        {
            if (timeout <= TimeSpan.Zero || elapsed >= timeout)
                return TimeSpan.Zero;
            return timeout - elapsed;
        }
    }

    public enum ServicePreLaunchDecision
    {
        Allowed,
        TimedOut,
        GuardRejected
    }

    /// <summary>
    /// Makes the final mutation decision against one shared operation clock. The second deadline
    /// check is intentional: registry/SCM identity verification can itself consume the budget.
    /// </summary>
    public static class ServicePreLaunchPolicy
    {
        public static ServicePreLaunchDecision Evaluate(TimeSpan timeout,
            Func<TimeSpan> elapsedProvider, Func<bool> registrationGuard)
        {
            if (elapsedProvider == null)
                throw new ArgumentNullException(nameof(elapsedProvider));
            if (ServiceOperationBudget.Remaining(timeout, elapsedProvider()) <= TimeSpan.Zero)
                return ServicePreLaunchDecision.TimedOut;

            if (registrationGuard != null)
            {
                try
                {
                    if (!registrationGuard())
                        return ServicePreLaunchDecision.GuardRejected;
                }
                catch
                {
                    return ServicePreLaunchDecision.GuardRejected;
                }
            }

            return ServiceOperationBudget.Remaining(timeout, elapsedProvider()) > TimeSpan.Zero
                ? ServicePreLaunchDecision.Allowed
                : ServicePreLaunchDecision.TimedOut;
        }
    }

    public static class ServiceUninstallCompletionEvaluator
    {
        public static ServiceOperationResult Evaluate(ServiceStatusInfo finalStatus,
            string details, int exitCode)
        {
            var status = finalStatus ?? new ServiceStatusInfo(ProxiFyreServiceState.Error,
                "The final service state could not be read.");
            if (exitCode != 0)
            {
                return ServiceOperationResult.Failed(status,
                    "The service uninstall command failed.", details, exitCode);
            }

            if (status.State == ProxiFyreServiceState.NotInstalled)
            {
                return ServiceOperationResult.Completed(status,
                    "The ProxiFyre service was uninstalled. Configuration and logs were preserved.",
                    details, exitCode);
            }

            if (status.State == ProxiFyreServiceState.DeletionPending)
            {
                return ServiceOperationResult.Completed(status,
                    "The ProxiFyre service is marked for deletion. Windows will finish removing it " +
                    "after open service-management handles close. Configuration and logs were preserved.",
                    details, exitCode);
            }

            // DeleteService succeeds before SCM necessarily removes the service record. If a
            // different process still owns an open service handle, a stopped record may remain
            // queryable until that handle closes even though the uninstall command succeeded.
            if (status.State == ProxiFyreServiceState.Stopped)
            {
                return ServiceOperationResult.Completed(status,
                    "The uninstall command succeeded, but Windows is still completing service removal. " +
                    "Close other service-management tools if the stopped service remains visible. " +
                    "Configuration and logs were preserved.", details, exitCode);
            }

            return ServiceOperationResult.Failed(status,
                "The service uninstall command completed, but Windows did not confirm that the " +
                "service was removed or pending deletion.", details, exitCode);
        }
    }

    public static class ServiceOperationFailureClassifier
    {
        public static ServiceOperationFailureKind Classify(Exception exception)
        {
            var native = exception as Win32Exception ?? exception?.InnerException as Win32Exception;
            return native != null && (native.NativeErrorCode == 1068 || native.NativeErrorCode == 1075)
                ? ServiceOperationFailureKind.DependencyUnavailable
                : ServiceOperationFailureKind.General;
        }

        public static bool IsEngineStartupFailure(ServiceOperationResult result)
        {
            if (result == null)
                return false;
            if (result.FailureKind == ServiceOperationFailureKind.StartupFailed)
                return true;

            // A timeout is an engine-start failure only while SCM still reports the start
            // transition. Restart can also time out while stopping or before Start begins.
            return result.FailureKind == ServiceOperationFailureKind.TimedOut &&
                   result.Status?.State == ProxiFyreServiceState.StartPending;
        }
    }

    public sealed class ServiceStatusInfo
    {
        public ServiceStatusInfo(ProxiFyreServiceState state, string error = null)
        {
            State = state;
            Error = error;
        }

        public ProxiFyreServiceState State { get; }
        public string Error { get; }
        public bool IsInstallationKnown => State != ProxiFyreServiceState.Error &&
                                           State != ProxiFyreServiceState.Unknown;
        public bool IsInstalled => IsInstallationKnown && State != ProxiFyreServiceState.NotInstalled;
        public bool HasConcreteInstalledState => IsInstalled &&
                                                 State != ProxiFyreServiceState.DeletionPending;
        public bool IsRunning => State == ProxiFyreServiceState.Running;

        public override string ToString()
        {
            switch (State)
            {
                case ProxiFyreServiceState.NotInstalled: return "Not installed";
                case ProxiFyreServiceState.Stopped: return "Stopped";
                case ProxiFyreServiceState.StartPending: return "Start pending";
                case ProxiFyreServiceState.Running: return "Running";
                case ProxiFyreServiceState.StopPending: return "Stop pending";
                case ProxiFyreServiceState.Paused: return "Paused";
                case ProxiFyreServiceState.PausePending: return "Pause pending";
                case ProxiFyreServiceState.ContinuePending: return "Continue pending";
                case ProxiFyreServiceState.DeletionPending: return "Deletion pending";
                case ProxiFyreServiceState.Error: return "Error";
                default: return "Unknown";
            }
        }
    }

    public sealed class ServiceOperationResult
    {
        private ServiceOperationResult(bool success, ServiceStatusInfo status, string message,
            string details, int? exitCode, bool timedOut, ServiceOperationFailureKind failureKind,
            bool confirmsConfigurationReloaded)
        {
            Success = success;
            Status = status;
            Message = message;
            Details = details;
            ExitCode = exitCode;
            TimedOut = timedOut;
            FailureKind = failureKind;
            ConfirmsConfigurationReloaded = confirmsConfigurationReloaded;
        }

        public bool Success { get; }
        public ServiceStatusInfo Status { get; }
        public string Message { get; }
        public string Details { get; }
        public int? ExitCode { get; }
        public bool TimedOut { get; }
        public ServiceOperationFailureKind FailureKind { get; }
        public bool ConfirmsConfigurationReloaded { get; }

        public static ServiceOperationResult Completed(ServiceStatusInfo status, string message,
            string details = null, int? exitCode = null,
            bool confirmsConfigurationReloaded = false)
        {
            return new ServiceOperationResult(true, status, message, details, exitCode, false,
                ServiceOperationFailureKind.None, confirmsConfigurationReloaded);
        }

        public static ServiceOperationResult Failed(ServiceStatusInfo status, string message,
            string details = null, int? exitCode = null, bool timedOut = false,
            ServiceOperationFailureKind failureKind = ServiceOperationFailureKind.General)
        {
            if (timedOut && failureKind == ServiceOperationFailureKind.General)
                failureKind = ServiceOperationFailureKind.TimedOut;
            return new ServiceOperationResult(false, status, message, details, exitCode, timedOut,
                failureKind, false);
        }
    }

    public interface IProxiFyreServiceController : IDisposable
    {
        Task<ServiceStatusInfo> GetStatusAsync(CancellationToken cancellationToken);
        Task<ServiceOperationResult> StartAsync(string expectedEnginePath,
            Func<bool> preLaunchGuard, TimeSpan timeout, CancellationToken cancellationToken);
        Task<ServiceOperationResult> StopAsync(TimeSpan timeout, CancellationToken cancellationToken);
        Task<ServiceOperationResult> RestartAsync(string expectedEnginePath,
            Func<bool> preLaunchGuard, TimeSpan timeout, CancellationToken cancellationToken);
        Task<ServiceOperationResult> InstallAsync(string enginePath, TimeSpan timeout, CancellationToken cancellationToken);
        Task<ServiceOperationResult> UninstallAsync(string enginePath,
            Func<bool> preLaunchGuard, TimeSpan timeout, CancellationToken cancellationToken);
    }

    public sealed class ProxiFyreServiceController : IProxiFyreServiceController
    {
        private readonly SemaphoreSlim _operationGate = new SemaphoreSlim(1, 1);
        private readonly IWindowsPacketFilterProbe _packetFilterProbe;
        private bool _disposed;

        public ProxiFyreServiceController()
            : this(new WindowsPacketFilterProbe())
        {
        }

        public ProxiFyreServiceController(IWindowsPacketFilterProbe packetFilterProbe)
        {
            _packetFilterProbe = packetFilterProbe ??
                                 throw new ArgumentNullException(nameof(packetFilterProbe));
        }

        public Task<ServiceStatusInfo> GetStatusAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            return Task.Run(() => GetStatusCore(cancellationToken), cancellationToken);
        }

        public Task<ServiceOperationResult> StartAsync(string expectedEnginePath,
            Func<bool> preLaunchGuard, TimeSpan timeout, CancellationToken cancellationToken)
        {
            ValidateServiceMutationRequest(expectedEnginePath, preLaunchGuard);
            return RunExclusiveAsync(() => StartCore(expectedEnginePath, preLaunchGuard,
                timeout, cancellationToken), cancellationToken);
        }

        public Task<ServiceOperationResult> StopAsync(TimeSpan timeout, CancellationToken cancellationToken)
        {
            return RunExclusiveAsync(() => StopCore(timeout, Stopwatch.StartNew(),
                cancellationToken), cancellationToken);
        }

        public Task<ServiceOperationResult> RestartAsync(string expectedEnginePath,
            Func<bool> preLaunchGuard, TimeSpan timeout, CancellationToken cancellationToken)
        {
            ValidateServiceMutationRequest(expectedEnginePath, preLaunchGuard);
            return RunExclusiveAsync(() => RestartCore(expectedEnginePath, preLaunchGuard,
                timeout, cancellationToken), cancellationToken);
        }

        public Task<ServiceOperationResult> InstallAsync(string enginePath, TimeSpan timeout, CancellationToken cancellationToken)
        {
            ValidateEnginePathArgument(enginePath);
            return RunExclusiveAsync(() => InstallCore(enginePath, timeout, cancellationToken), cancellationToken);
        }

        public Task<ServiceOperationResult> UninstallAsync(string enginePath,
            Func<bool> preLaunchGuard, TimeSpan timeout, CancellationToken cancellationToken)
        {
            ValidateEnginePathArgument(enginePath);
            if (preLaunchGuard == null)
                throw new ArgumentNullException(nameof(preLaunchGuard));
            return RunExclusiveAsync(() => UninstallCore(enginePath, preLaunchGuard, timeout,
                cancellationToken), cancellationToken);
        }

        private async Task<ServiceOperationResult> RunExclusiveAsync(Func<ServiceOperationResult> operation, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                return await Task.Run(operation, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _operationGate.Release();
            }
        }

        private ServiceOperationResult StartCore(string expectedEnginePath,
            Func<bool> preLaunchGuard, TimeSpan timeout, CancellationToken cancellationToken)
        {
            var operationClock = Stopwatch.StartNew();
            var status = GetStatusCore(cancellationToken);
            if (!status.IsInstallationKnown)
                return InstallationStateUnavailable(status);
            if (!status.IsInstalled)
                return ServiceOperationResult.Failed(status, "The ProxiFyre service is not installed.");
            if (status.State == ProxiFyreServiceState.Running)
                return ServiceOperationResult.Completed(status, "The ProxiFyre service is already running.");

            LifecycleExecutableLease payloadLease;
            try
            {
                payloadLease = AcquireTrustedEnginePayload(expectedEnginePath);
            }
            catch (Exception ex) when (IsPayloadValidationException(ex))
            {
                return FailureFromException("The service could not be started.", ex, cancellationToken);
            }

            using (payloadLease)
            {
                var locationFailure = GetUnprotectedServiceLocationFailure(status,
                    expectedEnginePath);
                if (locationFailure != null)
                    return locationFailure;

                var dependencyFailure = GetPacketFilterDependencyFailure(status);
                if (dependencyFailure != null)
                    return dependencyFailure;

                try
                {
                    return StartVerifiedCore(preLaunchGuard, timeout, operationClock,
                        cancellationToken);
                }
                catch (Exception ex) when (IsServiceException(ex))
                {
                    // Keep the verified payload leased while the final failure status is read.
                    return FailureFromException("The service could not be started.", ex,
                        cancellationToken);
                }
            }
        }

        private ServiceOperationResult StartVerifiedCore(Func<bool> preLaunchGuard,
            TimeSpan timeout, Stopwatch operationClock, CancellationToken cancellationToken)
        {
            var status = GetStatusCore(cancellationToken);
            if (!status.IsInstallationKnown)
                return InstallationStateUnavailable(status);
            if (!status.IsInstalled)
                return ServiceOperationResult.Failed(status, "The ProxiFyre service is not installed.");
            if (status.State == ProxiFyreServiceState.Running)
                return ServiceOperationResult.Completed(status, "The ProxiFyre service is already running.");

            using (var controller = new ServiceController(ProxiFyrePaths.ServiceName))
            {
                var launchDecision = ServicePreLaunchPolicy.Evaluate(timeout,
                    () => operationClock.Elapsed, preLaunchGuard);
                if (launchDecision == ServicePreLaunchDecision.TimedOut)
                    return ServiceOperationResult.Failed(status,
                        "The start operation timed out before the service could be started.",
                        null, null, true);
                if (launchDecision == ServicePreLaunchDecision.GuardRejected)
                {
                    return ServiceOperationResult.Failed(status,
                        "The registered ProxiFyre executable changed before the service could be started. " +
                        "No start request was sent.");
                }
                controller.Start();
                var remaining = ServiceOperationBudget.Remaining(timeout, operationClock.Elapsed);
                if (remaining <= TimeSpan.Zero)
                {
                    return ServiceOperationResult.Failed(GetStatusCore(cancellationToken),
                        "The service did not reach Running before the timeout.", null, null, true);
                }
                var startup = WaitForStartup(controller, remaining, cancellationToken);
                if (startup == ServiceStartupWaitResult.TimedOut)
                {
                    var current = GetStatusCore(cancellationToken);
                    return ServiceOperationResult.Failed(current,
                        "The service did not reach Running before the timeout.", null, null, true);
                }
                if (startup == ServiceStartupWaitResult.Failed)
                {
                    var current = GetStatusCore(cancellationToken);
                    return ServiceOperationResult.Failed(current,
                        "The service stopped during startup. Review the recent engine logs for the underlying error.",
                        null, null, false, ServiceOperationFailureKind.StartupFailed);
                }
            }

            return ServiceStartupCompletionEvaluator.Evaluate(GetStatusCore(cancellationToken));
        }

        private ServiceOperationResult StopCore(TimeSpan timeout, Stopwatch operationClock,
            CancellationToken cancellationToken, Func<bool> preStopGuard = null)
        {
            var status = GetStatusCore(cancellationToken);
            if (!status.IsInstallationKnown)
                return InstallationStateUnavailable(status);
            if (!status.IsInstalled)
                return ServiceOperationResult.Failed(status, "The ProxiFyre service is not installed.");
            if (status.State == ProxiFyreServiceState.Stopped)
                return ServiceOperationResult.Completed(status, "The ProxiFyre service is already stopped.");

            try
            {
                using (var controller = new ServiceController(ProxiFyrePaths.ServiceName))
                {
                    controller.Refresh();
                    // SCM accepts Stop directly for a paused service. Continuing first creates
                    // a ContinuePending race where a subsequent Stop can be rejected.
                    // Do not send a duplicate control when another caller has already started
                    // the stop transition, or when the service stopped after our first query.
                    if (controller.Status != ServiceControllerStatus.Stopped &&
                        controller.Status != ServiceControllerStatus.StopPending)
                    {
                        var stopDecision = ServicePreLaunchPolicy.Evaluate(timeout,
                            () => operationClock.Elapsed, preStopGuard);
                        if (stopDecision == ServicePreLaunchDecision.TimedOut)
                        {
                            return ServiceOperationResult.Failed(GetStatusCore(cancellationToken),
                                "The stop operation timed out before the service could be stopped.",
                                null, null, true);
                        }
                        if (stopDecision == ServicePreLaunchDecision.GuardRejected)
                        {
                            return ServiceOperationResult.Failed(GetStatusCore(cancellationToken),
                                "The registered ProxiFyre executable changed before the service could be stopped. " +
                                "No stop request was sent.");
                        }
                        controller.Stop();
                    }
                    var remaining = ServiceOperationBudget.Remaining(timeout,
                        operationClock.Elapsed);
                    if (remaining <= TimeSpan.Zero ||
                        !WaitForStatus(controller, ServiceControllerStatus.Stopped, remaining,
                            cancellationToken))
                    {
                        var current = GetStatusCore(cancellationToken);
                        return ServiceOperationResult.Failed(current,
                            "The service did not reach Stopped before the timeout.", null, null, true);
                    }
                }

                return ServiceStopCompletionEvaluator.Evaluate(GetStatusCore(cancellationToken));
            }
            catch (Exception ex) when (IsServiceException(ex))
            {
                return FailureFromException("The service could not be stopped.", ex, cancellationToken);
            }
        }

        private ServiceOperationResult RestartCore(string expectedEnginePath,
            Func<bool> preLaunchGuard, TimeSpan timeout, CancellationToken cancellationToken)
        {
            var started = Stopwatch.StartNew();
            var status = GetStatusCore(cancellationToken);
            if (!status.IsInstallationKnown)
                return InstallationStateUnavailable(status);
            if (!status.IsInstalled)
                return ServiceOperationResult.Failed(status, "The ProxiFyre service is not installed.");

            LifecycleExecutableLease payloadLease;
            try
            {
                payloadLease = AcquireTrustedEnginePayload(expectedEnginePath);
            }
            catch (Exception ex) when (IsPayloadValidationException(ex))
            {
                return FailureFromException("The service could not be restarted.", ex,
                    cancellationToken);
            }

            // Acquire before Stop so every executable/configuration file used by the service
            // remains the exact payload that was revalidated for the whole restart attempt.
            using (payloadLease)
            {
                var locationFailure = GetUnprotectedServiceLocationFailure(status,
                    expectedEnginePath);
                if (locationFailure != null)
                    return locationFailure;

                var dependencyFailure = GetPacketFilterDependencyFailure(status);
                if (dependencyFailure != null)
                    return dependencyFailure;

                try
                {
                    if (status.State != ProxiFyreServiceState.Stopped)
                    {
                        var stopBudget = ServiceOperationBudget.Remaining(timeout, started.Elapsed);
                        if (stopBudget <= TimeSpan.Zero)
                        {
                            return ServiceOperationResult.Failed(status,
                                "The restart operation timed out before the service could be stopped.",
                                null, null, true);
                        }
                        var stop = StopCore(timeout, started, cancellationToken, preLaunchGuard);
                        if (!stop.Success)
                            return stop;
                    }

                    var remaining = ServiceOperationBudget.Remaining(timeout, started.Elapsed);
                    if (remaining <= TimeSpan.Zero)
                        return ServiceOperationResult.Failed(GetStatusCore(cancellationToken),
                            "The restart operation timed out before the service could start.", null, null, true);

                    var start = StartVerifiedCore(preLaunchGuard, timeout, started,
                        cancellationToken);
                    return start.Success
                        ? ServiceOperationResult.Completed(start.Status,
                            "The ProxiFyre service restarted successfully.",
                            confirmsConfigurationReloaded: start.ConfirmsConfigurationReloaded)
                        : start;
                }
                catch (Exception ex) when (IsServiceException(ex))
                {
                    // Keep the verified payload leased while the final failure status is read.
                    return FailureFromException("The service could not be restarted.", ex,
                        cancellationToken);
                }
            }
        }

        private ServiceOperationResult InstallCore(string enginePath, TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            var operationClock = Stopwatch.StartNew();
            var status = GetStatusCore(cancellationToken);
            if (!status.IsInstallationKnown)
                return InstallationStateUnavailable(status);
            if (status.State == ProxiFyreServiceState.DeletionPending)
            {
                return ServiceOperationResult.Failed(status,
                    "The ProxiFyre service is marked for deletion. Wait for Windows to finish removing it before installing again.");
            }
            if (status.IsInstalled)
            {
                return ServiceOperationResult.Completed(status,
                    "The ProxiFyre service is already installed.");
            }

            LifecycleExecutableLease payloadLease;
            try
            {
                payloadLease = AcquireTrustedEnginePayload(enginePath);
            }
            catch (Exception ex) when (IsPayloadValidationException(ex))
            {
                return FailureFromException("The service could not be installed.", ex,
                    cancellationToken);
            }

            using (payloadLease)
            {
                var locationFailure = GetUnprotectedServiceLocationFailure(status, enginePath);
                if (locationFailure != null)
                    return locationFailure;

                var dependencyFailure = GetPacketFilterDependencyFailure(status);
                return dependencyFailure ??
                       RunLifecycleCommandCore(enginePath, "install", timeout, operationClock,
                           cancellationToken, payloadAlreadyLeased: true);
            }
        }

        private ServiceOperationResult UninstallCore(string enginePath, Func<bool> preLaunchGuard,
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            var started = Stopwatch.StartNew();
            var status = GetStatusCore(cancellationToken);
            if (!status.IsInstallationKnown)
                return InstallationStateUnavailable(status);
            if (status.State == ProxiFyreServiceState.NotInstalled)
            {
                return ServiceOperationResult.Completed(status,
                    "The ProxiFyre service is already uninstalled. Configuration and logs were preserved.");
            }
            if (status.State == ProxiFyreServiceState.DeletionPending)
            {
                return ServiceOperationResult.Completed(status,
                    "The ProxiFyre service is already marked for deletion. Windows will finish " +
                    "removing it after open service-management handles close.");
            }

            LifecycleExecutableLease payloadLease;
            try
            {
                payloadLease = AcquireTrustedEnginePayload(enginePath);
            }
            catch (Exception ex) when (IsPayloadValidationException(ex))
            {
                return FailureFromException("The service uninstall command could not be run.", ex,
                    cancellationToken);
            }

            using (payloadLease)
            {
                if (ServiceOperationBudget.Remaining(timeout, started.Elapsed) <= TimeSpan.Zero)
                    return LifecycleCommandTimedOut("uninstall", cancellationToken);

                if (status.State != ProxiFyreServiceState.Stopped)
                {
                    var stopBudget = ServiceOperationBudget.Remaining(timeout, started.Elapsed);
                    if (stopBudget <= TimeSpan.Zero)
                    {
                        return ServiceOperationResult.Failed(status,
                            "The uninstall operation timed out before the service could be stopped.",
                            null, null, true);
                    }

                    var stop = StopCore(timeout, started, cancellationToken, preLaunchGuard);
                    if (!stop.Success)
                        return stop;

                    status = stop.Status ?? GetStatusCore(cancellationToken);
                    if (status.State == ProxiFyreServiceState.NotInstalled ||
                        status.State == ProxiFyreServiceState.DeletionPending)
                    {
                        return ServiceOperationResult.Completed(status,
                            status.State == ProxiFyreServiceState.NotInstalled
                                ? "The ProxiFyre service is already uninstalled. Configuration and logs were preserved."
                                : "The ProxiFyre service is already marked for deletion. Windows will finish " +
                                  "removing it after open service-management handles close.");
                    }
                    if (status.State != ProxiFyreServiceState.Stopped)
                    {
                        return ServiceOperationResult.Failed(status,
                            "The service did not remain stopped, so the uninstall command was not run.");
                    }
                }

                if (ServiceOperationBudget.Remaining(timeout, started.Elapsed) <= TimeSpan.Zero)
                {
                    return ServiceOperationResult.Failed(status,
                        "The uninstall operation timed out before the uninstall command could be run.",
                        null, null, true);
                }

                return RunLifecycleCommandCore(enginePath, "uninstall", timeout, started,
                    cancellationToken, preLaunchGuard, true);
            }
        }

        private ServiceOperationResult GetPacketFilterDependencyFailure(ServiceStatusInfo serviceStatus)
        {
            var dependency = _packetFilterProbe.GetStatus();
            if (dependency.IsAvailable)
                return null;

            return ServiceOperationResult.Failed(serviceStatus, dependency.StartupMessage,
                dependency.Details, null, false, ServiceOperationFailureKind.DependencyUnavailable);
        }

        private ServiceOperationResult RunLifecycleCommandCore(string enginePath, string command,
            TimeSpan timeout, Stopwatch operationClock, CancellationToken cancellationToken,
            Func<bool> preLaunchGuard = null, bool payloadAlreadyLeased = false)
        {
            var output = new StringBuilder();
            var error = new StringBuilder();

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (ServiceOperationBudget.Remaining(timeout, operationClock.Elapsed) <=
                    TimeSpan.Zero)
                    return LifecycleCommandTimedOut(command, cancellationToken);

                var startInfo = new ProcessStartInfo
                {
                    FileName = enginePath,
                    Arguments = command,
                    WorkingDirectory = Path.GetDirectoryName(enginePath),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using (var executableLease = payloadAlreadyLeased
                           ? null
                           : AcquireTrustedEnginePayload(enginePath))
                using (var process = new Process { StartInfo = startInfo })
                {
                    process.OutputDataReceived += (sender, args) => { if (args.Data != null) lock (output) output.AppendLine(args.Data); };
                    process.ErrorDataReceived += (sender, args) => { if (args.Data != null) lock (error) error.AppendLine(args.Data); };
                    var launchDecision = ServicePreLaunchPolicy.Evaluate(timeout,
                        () => operationClock.Elapsed, preLaunchGuard);
                    if (launchDecision == ServicePreLaunchDecision.TimedOut)
                        return LifecycleCommandTimedOut(command, cancellationToken);
                    if (launchDecision == ServicePreLaunchDecision.GuardRejected)
                    {
                        return ServiceOperationResult.Failed(GetStatusCore(cancellationToken),
                            "The service registration changed before the uninstall command could run. " +
                            "No uninstall command was launched.");
                    }
                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    while (true)
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            TerminateLifecycleProcess(process);
                            cancellationToken.ThrowIfCancellationRequested();
                        }

                        var remaining = ServiceOperationBudget.Remaining(timeout,
                            operationClock.Elapsed);
                        if (remaining > TimeSpan.Zero)
                        {
                            var waitMilliseconds = Math.Max(1,
                                Math.Min(150, (int)Math.Ceiling(remaining.TotalMilliseconds)));
                            if (process.WaitForExit(waitMilliseconds))
                                break;
                            continue;
                        }

                        TerminateLifecycleProcess(process);
                        var timedOutStatus = GetStatusCore(CancellationToken.None);
                        return ServiceOperationResult.Failed(timedOutStatus,
                            $"The service {command} command timed out.", CombineOutput(output, error), null, true);
                    }

                    process.WaitForExit();
                    var exitCode = process.ExitCode;
                    var status = GetStatusCore(cancellationToken);
                    var details = CombineOutput(output, error);
                    if (command == "uninstall")
                        return ServiceUninstallCompletionEvaluator.Evaluate(status, details, exitCode);

                    // Never treat Error/Unknown as proof that a lifecycle command worked. The
                    // UI remains conservative on those states, while install success requires
                    // an actual installed state from SCM.
                    if (exitCode == 0 && status.HasConcreteInstalledState)
                    {
                        return ServiceOperationResult.Completed(status,
                            "The ProxiFyre service was installed.", details, exitCode);
                    }

                    return ServiceOperationResult.Failed(status,
                        $"The service {command} command failed.", details, exitCode);
                }
            }
            catch (Exception ex) when (IsServiceException(ex) || IsPayloadValidationException(ex))
            {
                return FailureFromException($"The service {command} command could not be run.", ex, cancellationToken);
            }
        }

        private ServiceOperationResult LifecycleCommandTimedOut(string command,
            CancellationToken cancellationToken)
        {
            return ServiceOperationResult.Failed(GetStatusCore(cancellationToken),
                $"The service {command} command timed out before it could be launched.",
                null, null, true);
        }

        private static void TerminateLifecycleProcess(Process process)
        {
            if (process == null)
                return;

            try
            {
                if (!process.HasExited)
                    process.Kill();
            }
            catch (InvalidOperationException)
            {
            }
            catch (Win32Exception)
            {
            }

            try
            {
                if (process.WaitForExit(5000))
                    process.WaitForExit(); // Drain asynchronous stdout/stderr callbacks.
            }
            catch (InvalidOperationException)
            {
            }
        }

        private static string CombineOutput(StringBuilder output, StringBuilder error)
        {
            lock (output)
            lock (error)
            {
                return (output.ToString() + error.ToString()).Trim();
            }
        }

        private static ServiceOperationResult InstallationStateUnavailable(ServiceStatusInfo status)
        {
            return ServiceOperationResult.Failed(status,
                "The ProxiFyre service installation state could not be verified.");
        }

        private ServiceOperationResult FailureFromException(string message, Exception exception, CancellationToken cancellationToken)
        {
            ServiceStatusInfo status;
            try { status = GetStatusCore(cancellationToken); }
            catch { status = new ServiceStatusInfo(ProxiFyreServiceState.Error, exception.Message); }

            return ServiceOperationResult.Failed(status, FriendlyServiceError(message, exception),
                exception.ToString(), null, false,
                ServiceOperationFailureClassifier.Classify(exception));
        }

        private static string FriendlyServiceError(string prefix, Exception exception)
        {
            var native = exception as Win32Exception ?? exception.InnerException as Win32Exception;
            if (native != null)
            {
                if (native.NativeErrorCode == 5)
                    return prefix + " Access was denied; run ProxiFyreUI as administrator.";
                if (native.NativeErrorCode == 1072)
                    return prefix + " The service is marked for deletion; close service-management tools and retry.";
                if (native.NativeErrorCode == 2)
                    return prefix + " The registered service executable could not be found.";
                if (native.NativeErrorCode == 1068 || native.NativeErrorCode == 1075)
                    return prefix + " The Windows Packet Filter (NDISRD) dependency is unavailable. " +
                           "Install WinpkFilter from " + WindowsPacketFilterStatus.DownloadUrl +
                           ", restart Windows if requested, and try again.";
            }

            return prefix + " " + exception.Message;
        }

        private static ServiceStatusInfo GetStatusCore(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using (var controller = new ServiceController(ProxiFyrePaths.ServiceName))
                {
                    var status = controller.Status;
                    return new ServiceStatusInfo(MapStatus(status));
                }
            }
            catch (Exception ex) when (IsMissingService(ex))
            {
                return new ServiceStatusInfo(ProxiFyreServiceState.NotInstalled);
            }
            catch (Exception ex) when (IsMarkedForDeletion(ex))
            {
                return new ServiceStatusInfo(ProxiFyreServiceState.DeletionPending);
            }
            catch (Exception ex) when (IsServiceException(ex))
            {
                return new ServiceStatusInfo(ProxiFyreServiceState.Error, ex.Message);
            }
        }

        private static bool WaitForStatus(ServiceController controller, ServiceControllerStatus target,
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            var stopwatch = Stopwatch.StartNew();
            while (stopwatch.Elapsed < timeout)
            {
                cancellationToken.ThrowIfCancellationRequested();
                controller.Refresh();
                if (controller.Status == target)
                    return true;
                Thread.Sleep(150);
            }

            controller.Refresh();
            return controller.Status == target;
        }

        private enum ServiceStartupWaitResult
        {
            Running,
            Failed,
            TimedOut
        }

        private static ServiceStartupWaitResult WaitForStartup(ServiceController controller,
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            var stopwatch = Stopwatch.StartNew();
            while (stopwatch.Elapsed < timeout)
            {
                cancellationToken.ThrowIfCancellationRequested();
                controller.Refresh();
                var observation = ServiceStartupStateClassifier.Classify(MapStatus(controller.Status));
                if (observation == ServiceStartupObservation.Running)
                    return ServiceStartupWaitResult.Running;
                if (observation == ServiceStartupObservation.Failed)
                    return ServiceStartupWaitResult.Failed;
                Thread.Sleep(150);
            }

            controller.Refresh();
            var finalObservation = ServiceStartupStateClassifier.Classify(MapStatus(controller.Status));
            if (finalObservation == ServiceStartupObservation.Running)
                return ServiceStartupWaitResult.Running;
            return finalObservation == ServiceStartupObservation.Failed
                ? ServiceStartupWaitResult.Failed
                : ServiceStartupWaitResult.TimedOut;
        }

        private static ProxiFyreServiceState MapStatus(ServiceControllerStatus status)
        {
            switch (status)
            {
                case ServiceControllerStatus.Stopped: return ProxiFyreServiceState.Stopped;
                case ServiceControllerStatus.StartPending: return ProxiFyreServiceState.StartPending;
                case ServiceControllerStatus.StopPending: return ProxiFyreServiceState.StopPending;
                case ServiceControllerStatus.Running: return ProxiFyreServiceState.Running;
                case ServiceControllerStatus.Paused: return ProxiFyreServiceState.Paused;
                case ServiceControllerStatus.PausePending: return ProxiFyreServiceState.PausePending;
                case ServiceControllerStatus.ContinuePending: return ProxiFyreServiceState.ContinuePending;
                default: return ProxiFyreServiceState.Unknown;
            }
        }

        private static bool IsMissingService(Exception exception)
        {
            var native = exception as Win32Exception ?? exception.InnerException as Win32Exception;
            return native != null && native.NativeErrorCode == 1060;
        }

        private static bool IsMarkedForDeletion(Exception exception)
        {
            var native = exception as Win32Exception ?? exception.InnerException as Win32Exception;
            return native != null && native.NativeErrorCode == 1072;
        }

        private static bool IsServiceException(Exception exception)
        {
            return exception is InvalidOperationException || exception is Win32Exception ||
                   exception is System.ServiceProcess.TimeoutException || exception is UnauthorizedAccessException;
        }

        private static bool IsPayloadValidationException(Exception exception)
        {
            return exception is IOException || exception is UnauthorizedAccessException ||
                   exception is ArgumentException || exception is NotSupportedException ||
                   exception is Win32Exception;
        }

        private static LifecycleExecutableLease AcquireTrustedEnginePayload(string enginePath)
        {
            return LifecycleExecutableLease.Acquire(
                EngineExecutableValidator.GetLifecyclePayloadPaths(enginePath),
                EngineExecutableValidator.IsTrustedPayloadFile);
        }

        private static ServiceOperationResult GetUnprotectedServiceLocationFailure(
            ServiceStatusInfo status, string enginePath)
        {
#if DEBUG
            // Repository builds intentionally run from a developer-writable output directory.
            return null;
#else
            string reason;
            if (ServiceInstallLocationPolicy.IsProtected(enginePath, out reason))
                return null;

            var remediation = status != null && status.IsInstalled
                ? "Stop and uninstall the existing service, exit this GUI, then copy or extract " +
                  "the complete release using a trusted installer into a protected per-machine " +
                  "directory (normally under Program Files). Launch the GUI from that copy and " +
                  "install the service again."
                : "Install the complete release with a trusted installer into a protected " +
                  "per-machine directory (normally under Program Files), launch the GUI from " +
                  "that copy, and install the service. The GUI will not rewrite permissions on " +
                  "a user-controlled directory in place.";
            return ServiceOperationResult.Failed(status,
                "The ProxiFyre service cannot run as LocalSystem from a location writable by " +
                "standard users. " + remediation, reason);
#endif
        }

        private static void ValidateServiceMutationRequest(string expectedEnginePath,
            Func<bool> preLaunchGuard)
        {
            ValidateEnginePathArgument(expectedEnginePath);
            if (preLaunchGuard == null)
                throw new ArgumentNullException(nameof(preLaunchGuard));
        }

        private static void ValidateEnginePathArgument(string enginePath)
        {
            if (string.IsNullOrWhiteSpace(enginePath) ||
                !ProxiFyrePaths.IsEngineExecutable(enginePath) ||
                !IsFullyQualifiedWindowsPath(enginePath))
            {
                throw new ArgumentException(
                    "A fully qualified ProxiFyre.exe path is required.", nameof(enginePath));
            }

            // Force the same canonicalization checks used by the payload lease without requiring
            // an SCM ImagePath representation. A direct executable path may legitimately contain
            // spaces without surrounding quotes.
            Path.GetFullPath(enginePath);
        }

        private static bool IsFullyQualifiedWindowsPath(string path)
        {
            if (path.Length >= 3 && char.IsLetter(path[0]) && path[1] == ':' &&
                (path[2] == Path.DirectorySeparatorChar ||
                 path[2] == Path.AltDirectorySeparatorChar))
                return true;

            return path.Length >= 3 &&
                   (path[0] == Path.DirectorySeparatorChar ||
                    path[0] == Path.AltDirectorySeparatorChar) &&
                   (path[1] == Path.DirectorySeparatorChar ||
                    path[1] == Path.AltDirectorySeparatorChar) &&
                   path[2] != Path.DirectorySeparatorChar &&
                   path[2] != Path.AltDirectorySeparatorChar;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ProxiFyreServiceController));
        }

        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            // The application can close while a background SCM wait is unwinding. Do not
            // dispose the semaphore here: RunExclusiveAsync must still be able to Release it.
            // It has no native resource until its WaitHandle is requested, which this class
            // never does, and the process is exiting after this lifetime-scoped controller.
        }
    }
}
