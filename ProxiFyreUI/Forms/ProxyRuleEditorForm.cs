using ProxiFyre.Configuration;
using ProxiFyreUI.Infrastructure;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Windows.Forms;

namespace ProxiFyreUI.Forms
{
    internal partial class ProxyRuleEditorForm : Form
    {
        private readonly ConfigurationValidator _validator = new ConfigurationValidator();
        private readonly ConfigurationSerializer _serializer = new ConfigurationSerializer();
        private readonly int _ruleIndex;
        private readonly int _ruleCount;
        private bool _initializing;
        private bool _confirmedInvalidCertificate;
        private string[] _unsupportedProtocols = new string[0];
        private string[] _unsupportedAddressFamilies = new string[0];

        public ProxyRuleEditorForm(ProxyRule rule, int ruleIndex, int ruleCount)
        {
            _ruleIndex = Math.Max(0, ruleIndex);
            _ruleCount = Math.Max(ruleCount, _ruleIndex + 1);
            InitializeComponent();
            _initializing = true;
            LoadRule(rule ?? CreateDefaultRule());
            _initializing = false;
            ValidateInput();
        }

        public ProxyRule ResultRule { get; private set; }

        private static ProxyRule CreateDefaultRule()
        {
            return new ProxyRule
            {
                AppNames = new List<string>(),
                Socks5Transport = "TCP",
                SupportedProtocols = new List<string> { "TCP", "UDP" },
                SupportedAddressFamilies = new List<string> { "IPv4", "IPv6" }
            };
        }

        private void LoadRule(ProxyRule rule)
        {
            ResultRule = _serializer.CloneRule(rule);
            var applications = rule.AppNames ?? new List<string>();
            catchAllCheckBox.Checked = applications.Any(value => value != null && value.Length == 0);
            foreach (var application in applications.Where(value => !string.IsNullOrEmpty(value)))
                applicationsListBox.Items.Add(application);

            ParseEndpoint(rule.Socks5ProxyEndpoint, out var host, out var port);
            hostTextBox.Text = host;
            portNumeric.Value = Math.Max(portNumeric.Minimum, Math.Min(portNumeric.Maximum, port));
            usernameTextBox.Text = rule.Username ?? string.Empty;
            passwordTextBox.Text = rule.Password ?? string.Empty;
            _unsupportedProtocols = (rule.SupportedProtocols ?? new List<string>())
                .Where(value => !string.Equals(value, "TCP", StringComparison.OrdinalIgnoreCase) &&
                                !string.Equals(value, "UDP", StringComparison.OrdinalIgnoreCase))
                .Select(value => value ?? "<null>").ToArray();
            _unsupportedAddressFamilies = (rule.SupportedAddressFamilies ?? new List<string>())
                .Where(value => !string.Equals(value, "IPv4", StringComparison.OrdinalIgnoreCase) &&
                                !string.Equals(value, "IPv6", StringComparison.OrdinalIgnoreCase))
                .Select(value => value ?? "<null>").ToArray();
            tcpCheckBox.Checked = rule.SupportedProtocols == null ||
                                  rule.SupportedProtocols.Any(value => string.Equals(value, "TCP", StringComparison.OrdinalIgnoreCase));
            udpCheckBox.Checked = rule.SupportedProtocols == null ||
                                  rule.SupportedProtocols.Any(value => string.Equals(value, "UDP", StringComparison.OrdinalIgnoreCase));
            ipv4CheckBox.Checked = rule.SupportedAddressFamilies == null ||
                                   rule.SupportedAddressFamilies.Any(value => string.Equals(value, "IPv4", StringComparison.OrdinalIgnoreCase));
            ipv6CheckBox.Checked = rule.SupportedAddressFamilies == null ||
                                   rule.SupportedAddressFamilies.Any(value => string.Equals(value, "IPv6", StringComparison.OrdinalIgnoreCase));
            string canonicalTransport;
            if (ConfigurationNormalizer.TryGetCanonicalTransport(rule.Socks5Transport, out canonicalTransport))
            {
                transportComboBox.SelectedIndex = canonicalTransport == "TLS" ? 1 : 0;
            }
            else
            {
                transportComboBox.Items.Add("Unsupported value: " + rule.Socks5Transport);
                transportComboBox.SelectedIndex = 2;
            }
            tlsServerNameTextBox.Text = rule.TlsServerName ?? string.Empty;
            tlsPinTextBox.Text = rule.TlsPinnedSha256 ?? string.Empty;
            allowInvalidCertificateCheckBox.Checked = rule.TlsAllowInvalidCertificate;
            _confirmedInvalidCertificate = rule.TlsAllowInvalidCertificate;
            UpdateTransportControls();
            UpdateApplicationControls();
        }

        private ProxyRule BuildCandidate()
        {
            var candidate = ResultRule == null
                ? new ProxyRule()
                : _serializer.CloneRule(ResultRule);

            candidate.AppNames = applicationsListBox.Items.Cast<object>()
                .Select(item => item?.ToString())
                .Where(value => !string.IsNullOrEmpty(value))
                .ToList();
            if (catchAllCheckBox.Checked)
                candidate.AppNames.Add(string.Empty);
            candidate.Socks5ProxyEndpoint = hostTextBox.Text.Trim() + ":" + decimal.ToInt32(portNumeric.Value);
            candidate.Username = usernameTextBox.Text;
            candidate.Password = passwordTextBox.Text;
            candidate.Socks5Transport = transportComboBox.SelectedIndex == 1 ? "TLS" :
                transportComboBox.SelectedIndex == 0 ? "TCP" : ResultRule?.Socks5Transport;
            candidate.TlsServerName = EmptyToNull(tlsServerNameTextBox.Text);
            candidate.TlsPinnedSha256 = EmptyToNull(ConfigurationNormalizer.NormalizeFingerprint(tlsPinTextBox.Text));
            candidate.TlsAllowInvalidCertificate = allowInvalidCertificateCheckBox.Checked;
            candidate.SupportedProtocols = new List<string>();
            if (tcpCheckBox.Checked) candidate.SupportedProtocols.Add("TCP");
            if (udpCheckBox.Checked) candidate.SupportedProtocols.Add("UDP");
            candidate.SupportedAddressFamilies = new List<string>();
            if (ipv4CheckBox.Checked) candidate.SupportedAddressFamilies.Add("IPv4");
            if (ipv6CheckBox.Checked) candidate.SupportedAddressFamilies.Add("IPv6");
            return candidate;
        }

        private void ValidateInput()
        {
            if (_initializing)
                return;

            errorProvider.Clear();
            var blocking = false;
            var warnings = new List<string>();
            var host = hostTextBox.Text.Trim();
            if (host.Length == 0)
            {
                errorProvider.SetError(hostTextBox, "Enter the upstream SOCKS5 host.");
                blocking = true;
            }
            else
            {
                IPAddress address;
                if (IPAddress.TryParse(host.Trim('[', ']'), out address) && address.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    errorProvider.SetError(hostTextBox, "The current engine requires an IPv4 upstream endpoint. IPv6 literals are not supported.");
                    blocking = true;
                }
                if (host.Contains(":") || host.Contains("/") || host.Contains("\\"))
                {
                    errorProvider.SetError(hostTextBox, "Enter an IPv4 literal or hostname without a scheme or path.");
                    blocking = true;
                }
            }

            var hasUsername = !string.IsNullOrEmpty(usernameTextBox.Text);
            var hasPassword = !string.IsNullOrEmpty(passwordTextBox.Text);
            if (hasUsername != hasPassword)
            {
                var message = "Username and password must either both be entered or both be empty.";
                errorProvider.SetError(usernameTextBox, message);
                errorProvider.SetError(passwordTextBox, message);
                blocking = true;
            }

            if (!tcpCheckBox.Checked && !udpCheckBox.Checked)
            {
                errorProvider.SetError(udpCheckBox, "Select at least one traffic protocol.");
                blocking = true;
            }
            if (_unsupportedProtocols.Length > 0)
            {
                errorProvider.SetError(udpCheckBox,
                    "Unsupported protocol value(s): " + string.Join(", ", _unsupportedProtocols) +
                    ". Change a protocol checkbox to replace them with canonical values.");
                warnings.Add("Error: Unsupported protocol value(s): " + string.Join(", ", _unsupportedProtocols) + ".");
                blocking = true;
            }
            if (!ipv4CheckBox.Checked && !ipv6CheckBox.Checked)
            {
                errorProvider.SetError(ipv6CheckBox, "Select at least one destination address family.");
                blocking = true;
            }
            if (_unsupportedAddressFamilies.Length > 0)
            {
                errorProvider.SetError(ipv6CheckBox,
                    "Unsupported address-family value(s): " + string.Join(", ", _unsupportedAddressFamilies) +
                    ". Change an address-family checkbox to replace them with canonical values.");
                warnings.Add("Error: Unsupported address-family value(s): " +
                    string.Join(", ", _unsupportedAddressFamilies) + ".");
                blocking = true;
            }

            if (transportComboBox.SelectedIndex != 0 && transportComboBox.SelectedIndex != 1)
            {
                errorProvider.SetError(transportComboBox, "Choose TCP or TLS to replace the unsupported transport value.");
                warnings.Add("Error: The loaded SOCKS5 transport value is unsupported; choose TCP or TLS.");
                blocking = true;
            }

            var normalizedPin = ConfigurationNormalizer.NormalizeFingerprint(tlsPinTextBox.Text);
            if (transportComboBox.SelectedIndex == 1 && normalizedPin.Length > 0 &&
                (normalizedPin.Length != 64 || normalizedPin.Any(character => !Uri.IsHexDigit(character))))
            {
                errorProvider.SetError(tlsPinTextBox, "A certificate pin must contain exactly 64 hexadecimal SHA-256 characters.");
                blocking = true;
            }

            try
            {
                var validation = _validator.ValidateRule(BuildCandidate(), _ruleIndex);
                blocking |= validation.HasErrors;
                warnings.AddRange(validation.Issues.Select(issue => issue.Severity + ": " + issue.Message));
            }
            catch (Exception)
            {
                blocking = true;
                warnings.Add("Error: Rule validation could not be completed. Review the entered values.");
            }

            if (catchAllCheckBox.Checked && _ruleIndex < _ruleCount - 1)
                warnings.Add("Warning: This catch-all rule is not last and will shadow all later rules.");
            if (catchAllCheckBox.Checked && applicationsListBox.Items.Count > 0)
                warnings.Add("Warning: Named application entries in a catch-all rule are redundant because the empty match reaches every remaining application.");
            if (allowInvalidCertificateCheckBox.Checked)
                warnings.Add(string.IsNullOrWhiteSpace(normalizedPin)
                    ? "SECURITY WARNING: Normal certificate validation is disabled and no certificate pin authenticates the server."
                    : "SECURITY WARNING: Normal certificate validation is disabled; the configured certificate pin must be trusted explicitly.");

            validationLabel.Text = warnings.Count == 0
                ? "Rule is valid. No network connection is attempted during validation."
                : string.Join(Environment.NewLine, warnings.Distinct());
            validationLabel.ForeColor = blocking || allowInvalidCertificateCheckBox.Checked
                ? System.Drawing.Color.DarkRed
                : System.Drawing.SystemColors.ControlText;
            okButton.Enabled = !blocking;
        }

        private void AddRunningProcessButton_Click(object sender, EventArgs e)
        {
            using (var picker = new ProcessPickerForm())
            {
                if (picker.ShowDialog(this) != DialogResult.OK)
                    return;
                AddApplications(picker.SelectedEntries);
            }
        }

        private void AddExecutableButton_Click(object sender, EventArgs e)
        {
            using (var dialog = CreateExecutableDialog())
            {
                if (dialog.ShowDialog(this) == DialogResult.OK)
                    AddApplications(dialog.FileNames.Select(Path.GetFileName));
            }
        }

        private void AddFullPathButton_Click(object sender, EventArgs e)
        {
            using (var dialog = CreateExecutableDialog())
            {
                if (dialog.ShowDialog(this) == DialogResult.OK)
                    AddApplications(dialog.FileNames);
            }
        }

        private void AddManualButton_Click(object sender, EventArgs e)
        {
            using (var dialog = new InputDialog("Add application match",
                "Enter an executable name or full/path substring. The value is preserved exactly:"))
            {
                if (dialog.ShowDialog(this) == DialogResult.OK)
                    AddApplications(new[] { dialog.Value });
            }
        }

        private void RemoveApplicationButton_Click(object sender, EventArgs e)
        {
            while (applicationsListBox.SelectedIndices.Count > 0)
                applicationsListBox.Items.RemoveAt(applicationsListBox.SelectedIndices[0]);
            ValidateInput();
        }

        private void AddApplications(IEnumerable<string> values)
        {
            foreach (var value in values.Where(value => !string.IsNullOrWhiteSpace(value)))
            {
                if (!applicationsListBox.Items.Cast<object>().Any(item =>
                    string.Equals(item?.ToString(), value, StringComparison.OrdinalIgnoreCase)))
                    applicationsListBox.Items.Add(value);
            }
            ValidateInput();
        }

        private static OpenFileDialog CreateExecutableDialog()
        {
            return new OpenFileDialog
            {
                Title = "Select application executable",
                Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*",
                Multiselect = true,
                CheckFileExists = true
            };
        }

        private void CatchAllCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            UpdateApplicationControls();
            ValidateInput();
        }

        private void UpdateApplicationControls()
        {
            catchAllExplanationLabel.Visible = catchAllCheckBox.Checked;
        }

        private void TransportComboBox_SelectedIndexChanged(object sender, EventArgs e)
        {
            UpdateTransportControls();
            ValidateInput();
        }

        private void UpdateTransportControls()
        {
            var tls = transportComboBox.SelectedIndex == 1;
            tlsServerNameLabel.Enabled = tls;
            tlsServerNameTextBox.Enabled = tls;
            tlsPinLabel.Enabled = tls;
            tlsPinTextBox.Enabled = tls;
            allowInvalidCertificateCheckBox.Enabled = tls;
            tlsWarningLabel.Enabled = tls;
        }

        private void AllowInvalidCertificateCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            if (!_initializing && !allowInvalidCertificateCheckBox.Checked)
                _confirmedInvalidCertificate = false;
            if (!_initializing && allowInvalidCertificateCheckBox.Checked && !_confirmedInvalidCertificate)
            {
                var result = MessageBox.Show(this,
                    "Allowing invalid certificates disables normal certificate chain and hostname validation. " +
                    "Without a SHA-256 certificate pin, the upstream server is not authenticated.\r\n\r\n" +
                    "Enable this unsafe option?",
                    "Security warning", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2);
                if (result != DialogResult.Yes)
                {
                    _initializing = true;
                    allowInvalidCertificateCheckBox.Checked = false;
                    _initializing = false;
                }
                else
                {
                    _confirmedInvalidCertificate = true;
                }
            }
            ValidateInput();
        }

        private void ShowPasswordCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            passwordTextBox.UseSystemPasswordChar = !showPasswordCheckBox.Checked;
        }

        private void FieldChanged(object sender, EventArgs e)
        {
            ValidateInput();
        }

        private void ProtocolSelectionChanged(object sender, EventArgs e)
        {
            if (!_initializing)
                _unsupportedProtocols = new string[0];
            ValidateInput();
        }

        private void AddressFamilySelectionChanged(object sender, EventArgs e)
        {
            if (!_initializing)
                _unsupportedAddressFamilies = new string[0];
            ValidateInput();
        }

        private void TlsPinTextBox_Leave(object sender, EventArgs e)
        {
            if (!string.IsNullOrWhiteSpace(tlsPinTextBox.Text))
                tlsPinTextBox.Text = ConfigurationNormalizer.NormalizeFingerprint(tlsPinTextBox.Text);
            ValidateInput();
        }

        private void ApplicationsListBox_SelectedIndexChanged(object sender, EventArgs e)
        {
            removeApplicationButton.Enabled = applicationsListBox.SelectedIndices.Count > 0;
        }

        private void OkButton_Click(object sender, EventArgs e)
        {
            ValidateInput();
            if (!okButton.Enabled)
                return;
            ResultRule = BuildCandidate();
            DialogResult = DialogResult.OK;
            Close();
        }

        private static bool IsTlsTransport(string value)
        {
            return string.Equals(value, "TLS", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "SOCKS5TLS", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "SOCKS5_TLS", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "SOCKS5-TLS", StringComparison.OrdinalIgnoreCase);
        }

        private static void ParseEndpoint(string endpoint, out string host, out decimal port)
        {
            host = string.Empty;
            port = 1080;
            var value = (endpoint ?? string.Empty).Trim();
            if (value.StartsWith("[", StringComparison.Ordinal))
            {
                var endBracket = value.IndexOf(']');
                if (endBracket > 0)
                {
                    host = value.Substring(1, endBracket - 1);
                    int parsedPort;
                    if (endBracket + 2 < value.Length && value[endBracket + 1] == ':' &&
                        int.TryParse(value.Substring(endBracket + 2), out parsedPort) && parsedPort >= 1 && parsedPort <= 65535)
                        port = parsedPort;
                    return;
                }
            }

            var separator = value.LastIndexOf(':');
            int candidatePort;
            if (separator > 0 && int.TryParse(value.Substring(separator + 1), out candidatePort) &&
                candidatePort >= 1 && candidatePort <= 65535)
            {
                host = value.Substring(0, separator);
                port = candidatePort;
            }
            else
            {
                host = value;
            }
        }

        private static string EmptyToNull(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        }
    }
}
