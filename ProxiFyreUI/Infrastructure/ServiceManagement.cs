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
        Error
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

    public static class ServiceOperationFailureClassifier
    {
        public static ServiceOperationFailureKind Classify(Exception exception)
        {
            var native = exception as Win32Exception ?? exception?.InnerException as Win32Exception;
            return native != null && (native.NativeErrorCode == 1068 || native.NativeErrorCode == 1075)
                ? ServiceOperationFailureKind.DependencyUnavailable
                : ServiceOperationFailureKind.General;
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
        public bool HasConcreteInstalledState => IsInstalled;
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
                case ProxiFyreServiceState.Error: return "Error";
                default: return "Unknown";
            }
        }
    }

    public sealed class ServiceOperationResult
    {
        private ServiceOperationResult(bool success, ServiceStatusInfo status, string message,
            string details, int? exitCode, bool timedOut, ServiceOperationFailureKind failureKind)
        {
            Success = success;
            Status = status;
            Message = message;
            Details = details;
            ExitCode = exitCode;
            TimedOut = timedOut;
            FailureKind = failureKind;
        }

        public bool Success { get; }
        public ServiceStatusInfo Status { get; }
        public string Message { get; }
        public string Details { get; }
        public int? ExitCode { get; }
        public bool TimedOut { get; }
        public ServiceOperationFailureKind FailureKind { get; }

        public static ServiceOperationResult Completed(ServiceStatusInfo status, string message, string details = null, int? exitCode = null)
        {
            return new ServiceOperationResult(true, status, message, details, exitCode, false,
                ServiceOperationFailureKind.None);
        }

        public static ServiceOperationResult Failed(ServiceStatusInfo status, string message,
            string details = null, int? exitCode = null, bool timedOut = false,
            ServiceOperationFailureKind failureKind = ServiceOperationFailureKind.General)
        {
            if (timedOut && failureKind == ServiceOperationFailureKind.General)
                failureKind = ServiceOperationFailureKind.TimedOut;
            return new ServiceOperationResult(false, status, message, details, exitCode, timedOut,
                failureKind);
        }
    }

    public interface IProxiFyreServiceController : IDisposable
    {
        Task<ServiceStatusInfo> GetStatusAsync(CancellationToken cancellationToken);
        Task<ServiceOperationResult> StartAsync(TimeSpan timeout, CancellationToken cancellationToken);
        Task<ServiceOperationResult> StopAsync(TimeSpan timeout, CancellationToken cancellationToken);
        Task<ServiceOperationResult> RestartAsync(TimeSpan timeout, CancellationToken cancellationToken);
        Task<ServiceOperationResult> InstallAsync(string enginePath, TimeSpan timeout, CancellationToken cancellationToken);
        Task<ServiceOperationResult> UninstallAsync(string enginePath, TimeSpan timeout, CancellationToken cancellationToken);
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

        public Task<ServiceOperationResult> StartAsync(TimeSpan timeout, CancellationToken cancellationToken)
        {
            return RunExclusiveAsync(() => StartCore(timeout, cancellationToken), cancellationToken);
        }

        public Task<ServiceOperationResult> StopAsync(TimeSpan timeout, CancellationToken cancellationToken)
        {
            return RunExclusiveAsync(() => StopCore(timeout, cancellationToken), cancellationToken);
        }

        public Task<ServiceOperationResult> RestartAsync(TimeSpan timeout, CancellationToken cancellationToken)
        {
            return RunExclusiveAsync(() => RestartCore(timeout, cancellationToken), cancellationToken);
        }

        public Task<ServiceOperationResult> InstallAsync(string enginePath, TimeSpan timeout, CancellationToken cancellationToken)
        {
            ValidateLifecycleExecutable(enginePath);
            return RunExclusiveAsync(() => InstallCore(enginePath, timeout, cancellationToken), cancellationToken);
        }

        public Task<ServiceOperationResult> UninstallAsync(string enginePath, TimeSpan timeout, CancellationToken cancellationToken)
        {
            ValidateLifecycleExecutable(enginePath);
            return RunExclusiveAsync(() => RunLifecycleCommandCore(enginePath, "uninstall", timeout, cancellationToken), cancellationToken);
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

        private ServiceOperationResult StartCore(TimeSpan timeout, CancellationToken cancellationToken)
        {
            var status = GetStatusCore(cancellationToken);
            if (!status.IsInstallationKnown)
                return InstallationStateUnavailable(status);
            if (!status.IsInstalled)
                return ServiceOperationResult.Failed(status, "The ProxiFyre service is not installed.");
            if (status.State == ProxiFyreServiceState.Running)
                return ServiceOperationResult.Completed(status, "The ProxiFyre service is already running.");

            var dependencyFailure = GetPacketFilterDependencyFailure(status);
            if (dependencyFailure != null)
                return dependencyFailure;

            try
            {
                using (var controller = new ServiceController(ProxiFyrePaths.ServiceName))
                {
                    controller.Start();
                    var startup = WaitForStartup(controller, timeout, cancellationToken);
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

                return ServiceOperationResult.Completed(GetStatusCore(cancellationToken), "The ProxiFyre service is running.");
            }
            catch (Exception ex) when (IsServiceException(ex))
            {
                return FailureFromException("The service could not be started.", ex, cancellationToken);
            }
        }

        private ServiceOperationResult StopCore(TimeSpan timeout, CancellationToken cancellationToken)
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
                    controller.Stop();
                    if (!WaitForStatus(controller, ServiceControllerStatus.Stopped, timeout, cancellationToken))
                    {
                        var current = GetStatusCore(cancellationToken);
                        return ServiceOperationResult.Failed(current,
                            "The service did not reach Stopped before the timeout.", null, null, true);
                    }
                }

                return ServiceOperationResult.Completed(GetStatusCore(cancellationToken), "The ProxiFyre service is stopped.");
            }
            catch (Exception ex) when (IsServiceException(ex))
            {
                return FailureFromException("The service could not be stopped.", ex, cancellationToken);
            }
        }

        private ServiceOperationResult RestartCore(TimeSpan timeout, CancellationToken cancellationToken)
        {
            var started = Stopwatch.StartNew();
            var status = GetStatusCore(cancellationToken);
            if (!status.IsInstallationKnown)
                return InstallationStateUnavailable(status);
            if (!status.IsInstalled)
                return ServiceOperationResult.Failed(status, "The ProxiFyre service is not installed.");

            var dependencyFailure = GetPacketFilterDependencyFailure(status);
            if (dependencyFailure != null)
                return dependencyFailure;

            if (status.State != ProxiFyreServiceState.Stopped)
            {
                var stop = StopCore(timeout, cancellationToken);
                if (!stop.Success)
                    return stop;
            }

            var remaining = timeout - started.Elapsed;
            if (remaining <= TimeSpan.Zero)
                return ServiceOperationResult.Failed(GetStatusCore(cancellationToken),
                    "The restart operation timed out before the service could start.", null, null, true);

            var start = StartCore(remaining, cancellationToken);
            return start.Success
                ? ServiceOperationResult.Completed(start.Status, "The ProxiFyre service restarted successfully.")
                : start;
        }

        private ServiceOperationResult InstallCore(string enginePath, TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            var status = GetStatusCore(cancellationToken);
            if (!status.IsInstallationKnown)
                return InstallationStateUnavailable(status);

            var dependencyFailure = GetPacketFilterDependencyFailure(status);
            return dependencyFailure ??
                   RunLifecycleCommandCore(enginePath, "install", timeout, cancellationToken);
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
            TimeSpan timeout, CancellationToken cancellationToken)
        {
            var output = new StringBuilder();
            var error = new StringBuilder();
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

            try
            {
                using (var process = new Process { StartInfo = startInfo })
                {
                    process.OutputDataReceived += (sender, args) => { if (args.Data != null) lock (output) output.AppendLine(args.Data); };
                    process.ErrorDataReceived += (sender, args) => { if (args.Data != null) lock (error) error.AppendLine(args.Data); };
                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    var stopwatch = Stopwatch.StartNew();
                    while (!process.WaitForExit(150))
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            TerminateLifecycleProcess(process);
                            cancellationToken.ThrowIfCancellationRequested();
                        }
                        if (stopwatch.Elapsed < timeout)
                            continue;

                        TerminateLifecycleProcess(process);
                        var timedOutStatus = GetStatusCore(CancellationToken.None);
                        return ServiceOperationResult.Failed(timedOutStatus,
                            $"The service {command} command timed out.", CombineOutput(output, error), null, true);
                    }

                    process.WaitForExit();
                    var exitCode = process.ExitCode;
                    var status = GetStatusCore(cancellationToken);
                    // Never treat Error/Unknown as proof that a lifecycle command worked. The
                    // UI remains conservative on those states, while success requires an actual
                    // installed state or the explicit NotInstalled state from SCM (1060).
                    var expected = command == "install"
                        ? status.HasConcreteInstalledState
                        : status.IsInstallationKnown && !status.IsInstalled;
                    if (exitCode == 0 && expected)
                    {
                        var message = command == "install"
                            ? "The ProxiFyre service was installed."
                            : "The ProxiFyre service was uninstalled. Configuration and logs were preserved.";
                        return ServiceOperationResult.Completed(status, message, CombineOutput(output, error), exitCode);
                    }

                    return ServiceOperationResult.Failed(status,
                        $"The service {command} command failed.", CombineOutput(output, error), exitCode);
                }
            }
            catch (Exception ex) when (IsServiceException(ex) || ex is IOException || ex is InvalidOperationException)
            {
                return FailureFromException($"The service {command} command could not be run.", ex, cancellationToken);
            }
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
            catch (InvalidOperationException ex) when (IsMissingService(ex))
            {
                return new ServiceStatusInfo(ProxiFyreServiceState.NotInstalled);
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

        private static bool IsServiceException(Exception exception)
        {
            return exception is InvalidOperationException || exception is Win32Exception ||
                   exception is System.ServiceProcess.TimeoutException || exception is UnauthorizedAccessException;
        }

        private static void ValidateLifecycleExecutable(string enginePath)
        {
            if (!EngineExecutableValidator.IsTrusted(enginePath))
                throw new FileNotFoundException("A trusted ProxiFyre.exe must be resolved before changing service installation.", enginePath);
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
