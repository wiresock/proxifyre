using System;
using System.ComponentModel;
using System.Drawing;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ProxiFyre
{
    public partial class MainForm : Form
    {
        readonly ProxiFyreService _service;
        bool _started;
        const int MaxLogChars = 3000;

        public MainForm(ProxiFyreService service)
        {
            _service = service;
            InitializeComponent();
            InitializeTray();

            var ico = LoadEmbeddedIcon("ProxiFyre.app.ico");
            if (ico != null)
            {
                Icon = ico;
                notifyIcon.Icon = ico;
            }

            var exe = Assembly.GetExecutingAssembly().Location;
            var dir = System.IO.Path.GetDirectoryName(exe) ?? AppDomain.CurrentDomain.BaseDirectory;
            AppendLogSafe($"UI started. BaseDir = {dir}");
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);

            ShowInTaskbar = true;
            Visible = true;
            WindowState = FormWindowState.Normal;

            Task.Run(StartServiceSafe);
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            try
            {
                Activate();
                TopMost = true; TopMost = false;
                BringToFront();
            }
            catch { }
        }

        async Task StartServiceSafe()
        {
            if (_started) return;
            _started = true;
            try
            {
                AppendLogSafe("Starting ProxiFyre service…");
                await Task.Run(() => _service.Start());
                AppendLogSafe("Service started.");
            }
            catch (Exception ex)
            {
                AppendLogSafe($"ERROR: {ex.Message}");
            }
        }

        void StopServiceSafe()
        {
            try
            {
                _service.Stop();
                AppendLogSafe("Service stopped.");
            }
            catch (Exception ex)
            {
                AppendLogSafe($"ERROR stopping: {ex.Message}");
            }
        }

        void InitializeTray()
        {
            notifyIcon.Visible = true;
            notifyIcon.DoubleClick += (_, __) => RestoreFromTray();
            notifyIcon.MouseDoubleClick += (_, __) => RestoreFromTray();

            var menu = new ContextMenuStrip();
            var showItem = new ToolStripMenuItem("Show");
            showItem.Click += (_, __) => RestoreFromTray();
            var quitItem = new ToolStripMenuItem("Quit");
            quitItem.Click += (_, __) => QuitApp();

            menu.Items.Add(showItem);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(quitItem);

            notifyIcon.ContextMenuStrip = menu;
        }

        Icon LoadEmbeddedIcon(string resourceName)
        {
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                using (var s = asm.GetManifestResourceStream(resourceName))
                {
                    if (s != null) return new Icon(s);
                }
            }
            catch { }
            return null;
        }

        void RestoreFromTray()
        {
            if (IsDisposed) return;

            if (InvokeRequired)
            {
                try { BeginInvoke(new Action(RestoreFromTray)); } catch { }
                return;
            }

            try
            {
                ShowInTaskbar = true;
                Visible = true;
                WindowState = FormWindowState.Normal;
                Show();
                Activate();
                TopMost = true; TopMost = false;
                BringToFront();
                Focus();
            }
            catch { }
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);

            if (WindowState == FormWindowState.Minimized)
            {
                ShowInTaskbar = false;
                Hide();
                try
                {
                    notifyIcon.BalloonTipTitle = "ProxiFyre";
                    notifyIcon.BalloonTipText = "Running in the system tray.";
                    notifyIcon.ShowBalloonTip(2000);
                }
                catch { }
            }
            else
            {
                ShowInTaskbar = true;
            }
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            notifyIcon.Visible = false;
            StopServiceSafe();
            base.OnClosing(e);
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            try { notifyIcon.Visible = false; } catch { }
            try { notifyIcon.Dispose(); } catch { }
            base.OnFormClosed(e);

            try { System.Windows.Forms.Application.ExitThread(); } catch { }
            try { System.Windows.Forms.Application.Exit(); } catch { }
            try { Environment.Exit(0); } catch { }
        }

        void QuitApp()
        {
            try { notifyIcon.Visible = false; } catch { }
            try { notifyIcon.Dispose(); } catch { }
            try { StopServiceSafe(); } catch { }

            try { Close(); } catch { }
            try { System.Windows.Forms.Application.Exit(); } catch { }
            try { Environment.Exit(0); } catch { }
        }

        public void AppendLogSafe(string line)
        {
            if (IsDisposed) return;

            if (logTextBox.InvokeRequired)
            {
                try { logTextBox.BeginInvoke(new Action<string>(AppendLogSafe), line); } catch { }
                return;
            }

            // Normalize appended text (ensure newline)
            var toAppend = line ?? string.Empty;
            if (!toAppend.EndsWith(Environment.NewLine))
                toAppend += Environment.NewLine;

            // If the new total would exceed MaxLogChars, trim from the beginning
            var newLength = logTextBox.TextLength + toAppend.Length;
            if (newLength > MaxLogChars)
            {
                var removeCount = newLength - MaxLogChars;

                // Try to cut on a line boundary to avoid half lines
                var cutAt = removeCount;
                var nl = logTextBox.Text.IndexOf(Environment.NewLine, removeCount);
                if (nl >= 0) cutAt = nl + Environment.NewLine.Length;

                logTextBox.Select(0, Math.Min(cutAt, logTextBox.TextLength));
                logTextBox.SelectedText = string.Empty;
            }

            logTextBox.AppendText(toAppend);

            // Keep caret at end and autoscroll
            logTextBox.SelectionStart = logTextBox.TextLength;
            logTextBox.ScrollToCaret();
        }
    }
}
