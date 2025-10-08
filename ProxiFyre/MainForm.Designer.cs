namespace ProxiFyre
{
    partial class MainForm
    {
        System.ComponentModel.IContainer components = null;
        System.Windows.Forms.TextBox logTextBox;
        System.Windows.Forms.NotifyIcon notifyIcon;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            logTextBox = new System.Windows.Forms.TextBox();
            notifyIcon = new System.Windows.Forms.NotifyIcon(components);

            SuspendLayout();

            // logTextBox
            logTextBox.Multiline = true;
            logTextBox.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            logTextBox.WordWrap = false;
            logTextBox.ReadOnly = true;
            logTextBox.Dock = System.Windows.Forms.DockStyle.Fill;
            logTextBox.Font = new System.Drawing.Font("Consolas", 9.75F);

            // notifyIcon
            notifyIcon.Text = "ProxiFyre";

            // MainForm
            AutoScaleDimensions = new System.Drawing.SizeF(96F, 96F);
            AutoScaleMode = System.Windows.Forms.AutoScaleMode.Dpi;
            ClientSize = new System.Drawing.Size(900, 520);
            Controls.Add(logTextBox);
            MinimumSize = new System.Drawing.Size(600, 300);
            Name = "MainForm";
            StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            Text = "ProxiFyre — Logs";
            ShowInTaskbar = true;

            ResumeLayout(false);
            PerformLayout();
        }
    }
}
