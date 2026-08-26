using Microsoft.VisualBasic.ApplicationServices;
using System;
using System.Threading;
using System.Windows.Forms;

namespace ProxiFyreUI
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            Application.SetCompatibleTextRenderingDefault(false);
            Application.ThreadException += OnThreadException;
            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;

            try
            {
                new ProxiFyreApplication().Run(args);
            }
            catch (CantStartSingleInstanceException)
            {
                MessageBox.Show(
                    "The existing ProxiFyre window is still starting or closing. Try again in a moment.",
                    "ProxiFyre", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
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
