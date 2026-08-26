using ProxiFyreUI.Forms;
using System;
using System.Threading;
using System.Windows.Forms;

namespace ProxiFyreUI
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.ThreadException += OnThreadException;
            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
            Application.Run(new MainForm());
        }

        private static void OnThreadException(object sender, ThreadExceptionEventArgs e)
        {
            ShowFatalError(e.Exception);
        }

        private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
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
