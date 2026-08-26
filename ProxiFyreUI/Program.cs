using Microsoft.VisualBasic.ApplicationServices;
using ProxiFyreUI.Infrastructure;
using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Linq;
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
        [STAThread]
        public static int Run(string ignored)
        {
            Program.Run(Environment.GetCommandLineArgs().Skip(1).ToArray());
            return 0;
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
                    "The ProxiFyre UI payload is incomplete or failed its release-signature integrity check. Reinstall it from an official signed archive.",
                    "ProxiFyre UI integrity check", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            using (startupPayloadLease)
            {
                try
                {
                    RunVerifiedApplication(args);
                }
                catch (CantStartSingleInstanceException)
                {
                    MessageBox.Show(
                        "The existing ProxiFyre window is still starting or closing. Try again in a moment.",
                        "ProxiFyre", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }

        // Keep form/application type resolution behind the startup payload check. The CLR loads
        // referenced app-local assemblies lazily, so this method must not be inlined into Main.
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void RunVerifiedApplication(string[] args)
        {
            new ProxiFyreApplication().Run(args);
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

    internal sealed class ProxiFyreApplication : WindowsFormsApplicationBase
    {
        public ProxiFyreApplication()
        {
            IsSingleInstance = true;
            EnableVisualStyles = true;
            ShutdownStyle = ShutdownMode.AfterMainFormCloses;
        }

        protected override void OnCreateMainForm()
        {
            MainForm = new Forms.MainForm();
        }

        protected override void OnStartupNextInstance(StartupNextInstanceEventArgs eventArgs)
        {
            eventArgs.BringToForeground = true;
            var mainForm = MainForm as Forms.MainForm;
            mainForm?.RestoreFromSecondaryLaunch();
            base.OnStartupNextInstance(eventArgs);
        }
    }
}
