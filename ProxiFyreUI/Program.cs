using ProxiFyreUI.Infrastructure;
using System;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace ProxiFyreUI
{
    /// <summary>
    /// Native ProxiFyreUI.exe invokes this method only after validating and locking the managed
    /// payload, sanitizing CLR-control environment variables, and starting .NET Framework 4.
    /// </summary>
    public static class ManagedEntryPoint
    {
        internal const int ManagedStartupFailureExitCode = 0x50584601;

        [STAThread]
        public static int Run(string ignored)
        {
            try
            {
                Program.Run(Environment.GetCommandLineArgs().Skip(1).ToArray());
                return 0;
            }
            catch (Exception exception)
            {
                // This is the last managed boundary before control returns to the native host.
                // Do not expose or record exception messages because startup exceptions may
                // contain configuration values. The native host owns the one user-facing error
                // dialog and distinguishes this reserved exit code from CLR activation failures.
                TryWriteStartupFailure(exception);
                return ManagedStartupFailureExitCode;
            }
        }

        private static void TryWriteStartupFailure(Exception exception)
        {
            try
            {
                var assemblyDirectory = Path.GetDirectoryName(
                    Assembly.GetExecutingAssembly().Location);
                if (string.IsNullOrWhiteSpace(assemblyDirectory))
                    return;

                var logPath = Path.Combine(assemblyDirectory, "ProxiFyreUI.startup.log");
                using (var writer = new StreamWriter(logPath, false,
                    new UTF8Encoding(false)))
                {
                    writer.WriteLine("ProxiFyre UI managed startup failure");
                    writer.WriteLine("UTC: " + DateTime.UtcNow.ToString("O",
                        CultureInfo.InvariantCulture));
                    writer.WriteLine("CLR: " + Environment.Version);
                    writer.WriteLine("Process architecture: " +
                        (IntPtr.Size == 8 ? "x64" : "x86"));

                    var current = exception;
                    for (var depth = 0; current != null && depth < 8; depth++)
                    {
                        writer.WriteLine(string.Format(CultureInfo.InvariantCulture,
                            "Exception[{0}]: {1}; HRESULT=0x{2:X8}", depth,
                            current.GetType().FullName, current.HResult));
                        current = current.InnerException;
                    }

                    writer.WriteLine("Stack trace (messages omitted):");
                    writer.WriteLine(exception.StackTrace ?? "Not available");
                }
            }
            catch
            {
                // The native host still reports the reserved result if diagnostics cannot be
                // written (for example, when storage is unavailable).
            }
        }
    }

    internal static class Program
    {
        internal static void Run(string[] args)
        {
            Application.SetCompatibleTextRenderingDefault(false);
            Application.ThreadException += OnThreadException;
            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;

            IDisposable startupPayloadLease;
            try
            {
                startupPayloadLease = UiStartupPayload.Acquire(
                    Assembly.GetExecutingAssembly().Location);
            }
            catch
            {
                MessageBox.Show(
                    "The ProxiFyre UI payload is incomplete or failed its local integrity check. Reinstall it from an official ProxiFyre package.",
                    "ProxiFyre UI integrity check", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            using (startupPayloadLease)
            using (var singleInstance = SingleInstanceCoordinator.CreateForCurrentUser())
            {
                if (!singleInstance.IsPrimary)
                {
                    singleInstance.RequestActivation();
                    return;
                }

                RunVerifiedApplication(singleInstance);
            }
        }

        // Keep form/application type resolution behind the startup payload check. The CLR loads
        // referenced app-local assemblies lazily, so this method must not be inlined into Main.
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void RunVerifiedApplication(SingleInstanceCoordinator singleInstance)
        {
            WinFormsFontBootstrap.EnsureDefaultFont();
            Application.EnableVisualStyles();
            using (var mainForm = new Forms.MainForm())
            {
                // A request can arrive before the form is shown. The coordinator retains that
                // request until this callback is installed on the UI thread.
                mainForm.Shown += (sender, eventArgs) =>
                    singleInstance.SetActivationCallback(
                        () => RestoreFromSecondaryLaunch(mainForm));
                Application.Run(mainForm);
            }
        }

        private static void RestoreFromSecondaryLaunch(Forms.MainForm mainForm)
        {
            if (mainForm == null || mainForm.IsDisposed || mainForm.Disposing)
                return;
            if (mainForm.InvokeRequired)
            {
                try
                {
                    mainForm.BeginInvoke((Action)(() => RestoreFromSecondaryLaunch(mainForm)));
                }
                catch (ObjectDisposedException)
                {
                    // The primary window is already closing; a later launch can become primary.
                }
                catch (InvalidOperationException)
                {
                    // The primary window is already closing; a later launch can become primary.
                }
                return;
            }

            mainForm.RestoreFromSecondaryLaunch();
        }

        private static void OnThreadException(object sender, ThreadExceptionEventArgs e)
        {
            ShowFatalError(e.Exception);
        }

        private static void OnUnhandledException(object sender, System.UnhandledExceptionEventArgs e)
        {
            ShowFatalError(e.ExceptionObject as Exception);
        }

        private static void ShowFatalError(Exception exception)
        {
            // This global path has no reliable access to the active configuration's secret set.
            // Fail closed instead of surfacing arbitrary exception text that could contain a
            // password copied into a third-party/OS exception message.
            MessageBox.Show(
                "An unexpected ProxiFyre UI error occurred. Restart the application and review the redacted diagnostics and service logs.",
                "ProxiFyre UI", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

}
