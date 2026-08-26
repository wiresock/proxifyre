using System;
using System.Windows.Forms;

namespace ProxiFyreUI.Forms
{
    internal partial class InputDialog : Form
    {
        public InputDialog(string title, string prompt, string initialValue = "")
        {
            InitializeComponent();
            Text = title;
            promptLabel.Text = prompt;
            valueTextBox.Text = initialValue ?? string.Empty;
            valueTextBox.SelectAll();
        }

        public string Value => valueTextBox.Text;

        private void ValueTextBox_TextChanged(object sender, EventArgs e)
        {
            okButton.Enabled = !string.IsNullOrWhiteSpace(valueTextBox.Text);
        }
    }
}
