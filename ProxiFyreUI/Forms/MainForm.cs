using ProxiFyre.Configuration;
using ProxiFyreUI.Infrastructure;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ProxiFyreUI.Forms
{
    internal partial class MainForm : Form
    {
        private readonly UiSettingsStore _settingsStore;
        private readonly IEngineLocator _engineLocator;
        private readonly IProxiFyreServiceController _serviceController;
        private readonly ConfigurationWorkspace _workspace;
        private readonly ILogTailer _logTailer;
        private readonly DiagnosticsBuilder _diagnosticsBuilder;
        private readonly UserVisibleErrorFormatter _errorFormatter;
        private readonly ConfigurationApplyCoordinator _applyCoordinator;
        private readonly CancellationTokenSource _lifetimeCancellation = new CancellationTokenSource();
        private readonly Queue<string> _logLines = new Queue<string>();
        private readonly Icon _applicationIcon;
        private readonly string _baseWindowTitle;
        private UiSettings _settings;
        private EngineLocation _engineLocation;
        private ServiceStatusInfo _serviceStatus = new ServiceStatusInfo(ProxiFyreServiceState.Unknown);
        private bool _suppressChanges;
        private bool _operationInProgress;
        private bool _applyWorkflowInProgress;
        private bool _engineStartupFailed;
        private bool _packetFilterUnavailable;
        private bool _exiting;
        private bool _exitRequested;
        private bool _exitCloseScheduled;
        private bool _cleanedUp;
        private int _operationDepth;
        private int _configurationDialogDepth;
        private int _refreshingStatus;
        private int _logViewGeneration;

        public MainForm()
            : this(new UiSettingsStore(), new EngineLocator(), new ProxiFyreServiceController(),
                  new ConfigurationWorkspace(), new LogTailer(), new DiagnosticsBuilder())
        {
        }

        internal MainForm(UiSettingsStore settingsStore, IEngineLocator engineLocator,
            IProxiFyreServiceController serviceController, ConfigurationWorkspace workspace,
            ILogTailer logTailer, DiagnosticsBuilder diagnosticsBuilder)
        {
            _settingsStore = settingsStore;
            _engineLocator = engineLocator;
            _serviceController = serviceController;
            _workspace = workspace;
            _logTailer = logTailer;
            _diagnosticsBuilder = diagnosticsBuilder;
            _errorFormatter = new UserVisibleErrorFormatter(_diagnosticsBuilder);
            _applyCoordinator = new ConfigurationApplyCoordinator(_workspace, _serviceController,
                IsRegisteredServiceEngine);
            _settings = _settingsStore.Load();

            InitializeComponent();
            _workspace.DirtyStateChanged += Workspace_DirtyStateChanged;
            _logTailer.LinesRead += LogTailer_LinesRead;
            _logTailer.StatusChanged += LogTailer_StatusChanged;
            followLogsCheckBox.Checked = _settings.FollowLogs;
            minimizeToTrayCheckBox.Checked = _settings.MinimizeToTray;
            var guiVersion = GetFileVersion(Assembly.GetExecutingAssembly().Location);
            guiVersionValueLabel.Text = guiVersion;
            _baseWindowTitle = string.Equals(guiVersion, "Not available", StringComparison.Ordinal)
                ? "ProxiFyre"
                : "ProxiFyre v" + guiVersion;
            Text = _baseWindowTitle;
            architectureValueLabel.Text = GetArchitectureDescription();
            _applicationIcon = LoadApplicationIcon();
            Icon = _applicationIcon;
            notifyIcon.Icon = _applicationIcon;
            serviceRefreshTimer.Start();
        }

        protected override async void OnShown(EventArgs e)
        {
            base.OnShown(e);
            await InitializeAsync();
        }

        private async Task InitializeAsync()
        {
            _engineLocation = _engineLocator.Resolve(_settings);
            UpdateResolvedPaths();
            if (_engineLocation.IsResolved)
            {
                try
                {
                    LoadWorkspace();
                }
                catch (Exception ex)
                {
                    ShowError("The configuration could not be loaded.", ex);
                }
            }
            else
            {
                configurationStateValueLabel.Text = "Engine not resolved";
                changesStateValueLabel.Text = "Select ProxiFyre.exe";
            }

            await RefreshServiceStatusAsync();
            UpdateAllStates();
        }

        private void LoadWorkspace()
        {
            var previousEnginePath = _workspace.EnginePath;
            var loaded = _workspace.Load(_engineLocation);
            CompleteWorkspaceLoad(loaded, previousEnginePath);
        }

        private void CompleteWorkspaceLoad(WorkspaceLoadResult loaded, string previousEnginePath)
        {
            BindConfiguration();
            if (!PathsEqual(previousEnginePath, _workspace.EnginePath))
            {
                ResetLogViewForEngineChange();
                StartLogTailerIfNeeded();
            }
            else if (followLogsCheckBox.Checked && !_logTailer.IsRunning)
            {
                StartLogTailerIfNeeded();
            }
            if (!loaded.LiveFileExists)
            {
                var source = loaded.LoadedFromSample
                    ? "The live app-config.json is missing. A sample was loaded as unsaved working configuration."
                    : "The live app-config.json is missing. A blank unsaved configuration was created.";
                MessageBox.Show(this, source + "\r\n\r\nAdd at least one valid proxy rule, then save before starting the service.",
                    "Configuration not yet saved", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void BindConfiguration()
        {
            var configuration = _workspace.Configuration;
            if (configuration == null)
                return;

            _suppressChanges = true;
            try
            {
                var logLevel = new[] { "Error", "Warning", "Info", "Debug", "All" }
                    .FirstOrDefault(value => string.Equals(value, configuration.LogLevel,
                        StringComparison.OrdinalIgnoreCase)) ?? "Info";
                logLevelComboBox.SelectedItem = logLevel;
                bypassLanCheckBox.Checked = configuration.BypassLan;
                RefreshRoutingGrid();
                RefreshExclusionsList();
            }
            finally
            {
                _suppressChanges = false;
            }
            UpdateAllStates();
        }

        private void ReadRootControlsIntoConfiguration()
        {
            if (_workspace.Configuration == null)
                return;
            _workspace.Configuration.LogLevel = logLevelComboBox.SelectedItem?.ToString() ?? "Info";
            _workspace.Configuration.BypassLan = bypassLanCheckBox.Checked;
        }

        private void RefreshRoutingGrid(int selectIndex = -1)
        {
            routingGrid.Rows.Clear();
            var configuration = _workspace.Configuration;
            if (configuration?.Proxies == null)
                return;

            var validation = _workspace.Validate();
            for (var index = 0; index < configuration.Proxies.Count; index++)
            {
                var rule = configuration.Proxies[index];
                var warnings = validation.Issues
                    .Where(issue => issue.ProxyRuleIndex == index)
                    .Select(issue => issue.Message)
                    .Distinct()
                    .ToArray();
                var rowIndex = routingGrid.Rows.Add(
                    index + 1,
                    FormatApplications(rule?.AppNames),
                    rule?.Socks5ProxyEndpoint ?? string.Empty,
                    FormatAuthentication(rule),
                    FormatTransport(rule?.Socks5Transport),
                    FormatValues(rule?.SupportedProtocols, "TCP, UDP (default)"),
                    FormatValues(rule?.SupportedAddressFamilies, "IPv4, IPv6 (default)"),
                    string.Join("; ", warnings));
                routingGrid.Rows[rowIndex].Tag = index;
                if (warnings.Length > 0)
                    routingGrid.Rows[rowIndex].DefaultCellStyle.BackColor = Color.FromArgb(255, 249, 222);
            }

            if (selectIndex >= 0 && selectIndex < routingGrid.Rows.Count)
            {
                routingGrid.ClearSelection();
                routingGrid.Rows[selectIndex].Selected = true;
                routingGrid.CurrentCell = routingGrid.Rows[selectIndex].Cells[0];
            }
            UpdateRoutingButtons();
        }

        private void RefreshExclusionsList(int selectIndex = -1)
        {
            exclusionsListBox.Items.Clear();
            var exclusions = _workspace.Configuration?.Excludes;
            if (exclusions == null)
                return;
            foreach (var exclusion in exclusions)
                exclusionsListBox.Items.Add(exclusion ?? "<null entry>");
            if (selectIndex >= 0 && selectIndex < exclusionsListBox.Items.Count)
                exclusionsListBox.SelectedIndex = selectIndex;
            UpdateExclusionButtons();
        }

        private void MarkConfigurationChanged()
        {
            // Busy-state checks belong before a mutation. Once the model has changed it must
            // always be marked dirty, including when a modal dialog's nested message loop let
            // a service operation begin between the initial guard and the commit.
            if (_suppressChanges)
                return;
            _workspace.MarkDirty();
            UpdateAllStates();
        }

        private bool CanCommitDialogMutation(ProxiFyreConfiguration configuration)
        {
            if (!ConfigurationMutationBlocked && ReferenceEquals(_workspace.Configuration, configuration))
                return true;

            statusStripLabel.Text =
                "The edit was not applied because a service or configuration operation occurred while the dialog was open.";
            return false;
        }

        private DialogResult ShowConfigurationDialog(Form dialog)
        {
            return ShowConfigurationDialog(() => dialog.ShowDialog(this));
        }

        private DialogResult ShowConfigurationDialog(CommonDialog dialog)
        {
            return ShowConfigurationDialog(() => dialog.ShowDialog(this));
        }

        private DialogResult ShowConfigurationDialog(Func<DialogResult> showDialog)
        {
            _configurationDialogDepth++;
            UpdateAllStates();
            try
            {
                return showDialog();
            }
            finally
            {
                _configurationDialogDepth--;
                UpdateAllStates();
                ScheduleDeferredExitIfReady();
            }
        }

        private void Workspace_DirtyStateChanged(object sender, EventArgs e)
        {
            UpdateAllStates();
        }

        private void RootConfigurationControlChanged(object sender, EventArgs e)
        {
            if (_suppressChanges || ConfigurationMutationBlocked || _workspace.Configuration == null)
                return;
            ReadRootControlsIntoConfiguration();
            MarkConfigurationChanged();
        }

        private int SelectedRuleIndex
        {
            get
            {
                if (routingGrid.SelectedRows.Count == 0)
                    return -1;
                return routingGrid.SelectedRows[0].Tag is int index ? index : -1;
            }
        }

        private void AddRuleButton_Click(object sender, EventArgs e)
        {
            if (ConfigurationMutationBlocked || !EnsureWorkspaceAvailable())
                return;
            var configuration = _workspace.Configuration;
            var count = configuration.Proxies.Count;
            using (var editor = new ProxyRuleEditorForm(null, count, count + 1))
            {
                editor.Text = "Add proxy rule";
                if (ShowConfigurationDialog(editor) != DialogResult.OK)
                    return;
                if (!CanCommitDialogMutation(configuration))
                    return;
                configuration.Proxies.Add(editor.ResultRule);
                MarkConfigurationChanged();
                RefreshRoutingGrid(configuration.Proxies.Count - 1);
            }
        }

        private void EditRuleButton_Click(object sender, EventArgs e)
        {
            if (ConfigurationMutationBlocked)
                return;
            var index = SelectedRuleIndex;
            if (index < 0 || _workspace.Configuration?.Proxies == null)
                return;
            var configuration = _workspace.Configuration;
            using (var editor = new ProxyRuleEditorForm(configuration.Proxies[index], index,
                configuration.Proxies.Count))
            {
                editor.Text = "Edit proxy rule";
                if (ShowConfigurationDialog(editor) != DialogResult.OK)
                    return;
                if (!CanCommitDialogMutation(configuration))
                    return;
                configuration.Proxies[index] = editor.ResultRule;
                MarkConfigurationChanged();
                RefreshRoutingGrid(index);
            }
        }

        private void DuplicateRuleButton_Click(object sender, EventArgs e)
        {
            if (ConfigurationMutationBlocked)
                return;
            var index = SelectedRuleIndex;
            if (index < 0 || _workspace.Configuration?.Proxies == null)
                return;
            var clone = new ConfigurationSerializer().CloneRule(
                _workspace.Configuration.Proxies[index]);
            _workspace.Configuration.Proxies.Insert(index + 1, clone);
            MarkConfigurationChanged();
            RefreshRoutingGrid(index + 1);
        }

        private void RemoveRuleButton_Click(object sender, EventArgs e)
        {
            if (ConfigurationMutationBlocked)
                return;
            var index = SelectedRuleIndex;
            if (index < 0 || _workspace.Configuration?.Proxies == null)
                return;
            var configuration = _workspace.Configuration;
            if (MessageBox.Show(this, "Remove the selected proxy rule?", "Remove proxy rule",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return;
            if (!CanCommitDialogMutation(configuration))
                return;
            configuration.Proxies.RemoveAt(index);
            MarkConfigurationChanged();
            RefreshRoutingGrid(Math.Min(index, configuration.Proxies.Count - 1));
        }

        private void MoveRule(int direction)
        {
            if (ConfigurationMutationBlocked)
                return;
            var index = SelectedRuleIndex;
            var target = index + direction;
            var rules = _workspace.Configuration?.Proxies;
            if (rules == null || index < 0 || target < 0 || target >= rules.Count)
                return;
            var rule = rules[index];
            rules.RemoveAt(index);
            rules.Insert(target, rule);
            MarkConfigurationChanged();
            RefreshRoutingGrid(target);
        }

        private void MoveUpRuleButton_Click(object sender, EventArgs e) => MoveRule(-1);
        private void MoveDownRuleButton_Click(object sender, EventArgs e) => MoveRule(1);

        private void RoutingGrid_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (!ConfigurationMutationBlocked && e.RowIndex >= 0)
                EditRuleButton_Click(sender, EventArgs.Empty);
        }

        private void RoutingGrid_SelectionChanged(object sender, EventArgs e)
        {
            UpdateRoutingButtons();
        }

        private void RoutingGrid_KeyDown(object sender, KeyEventArgs e)
        {
            if (ConfigurationMutationBlocked)
            {
                e.SuppressKeyPress = true;
                return;
            }
            if (e.KeyCode == Keys.Delete)
            {
                RemoveRuleButton_Click(sender, EventArgs.Empty);
                e.Handled = true;
            }
            else if (e.Alt && e.KeyCode == Keys.Up)
            {
                MoveRule(-1);
                e.Handled = true;
            }
            else if (e.Alt && e.KeyCode == Keys.Down)
            {
                MoveRule(1);
                e.Handled = true;
            }
        }

        private void UpdateRoutingButtons()
        {
            var index = SelectedRuleIndex;
            var count = _workspace.Configuration?.Proxies?.Count ?? 0;
            var canEdit = !ConfigurationMutationBlocked;
            editRuleButton.Enabled = canEdit && index >= 0;
            duplicateRuleButton.Enabled = canEdit && index >= 0;
            removeRuleButton.Enabled = canEdit && index >= 0;
            moveUpRuleButton.Enabled = canEdit && index > 0;
            moveDownRuleButton.Enabled = canEdit && index >= 0 && index < count - 1;
            addRuleButton.Enabled = canEdit && _workspace.Configuration != null;
            routingGrid.Enabled = canEdit;
        }

        private void AddRunningExclusionButton_Click(object sender, EventArgs e)
        {
            if (ConfigurationMutationBlocked || !EnsureWorkspaceAvailable())
                return;
            var configuration = _workspace.Configuration;
            using (var picker = new ProcessPickerForm())
            {
                if (ShowConfigurationDialog(picker) == DialogResult.OK)
                    AddExclusions(configuration, picker.SelectedEntries);
            }
        }

        private void AddExecutableExclusionButton_Click(object sender, EventArgs e)
        {
            if (ConfigurationMutationBlocked || !EnsureWorkspaceAvailable())
                return;
            var configuration = _workspace.Configuration;
            using (var dialog = CreateExecutableDialog())
            {
                if (ShowConfigurationDialog(dialog) == DialogResult.OK)
                    AddExclusions(configuration, dialog.FileNames.Select(Path.GetFileName));
            }
        }

        private void AddPathExclusionButton_Click(object sender, EventArgs e)
        {
            if (ConfigurationMutationBlocked || !EnsureWorkspaceAvailable())
                return;
            var configuration = _workspace.Configuration;
            using (var dialog = CreateExecutableDialog())
            {
                if (ShowConfigurationDialog(dialog) == DialogResult.OK)
                    AddExclusions(configuration, dialog.FileNames);
            }
        }

        private void AddManualExclusionButton_Click(object sender, EventArgs e)
        {
            if (ConfigurationMutationBlocked || !EnsureWorkspaceAvailable())
                return;
            var configuration = _workspace.Configuration;
            using (var dialog = new InputDialog("Add exclusion",
                "Enter a process name or path substring. Exclusion matching is deliberately permissive:"))
            {
                if (ShowConfigurationDialog(dialog) == DialogResult.OK)
                    AddExclusions(configuration, new[] { dialog.Value });
            }
        }

        private void AddExclusions(ProxiFyreConfiguration configuration, IEnumerable<string> values)
        {
            if (!CanCommitDialogMutation(configuration))
                return;
            var exclusions = configuration.Excludes;
            var added = false;
            foreach (var value in values.Where(value => !string.IsNullOrWhiteSpace(value)))
            {
                if (exclusions.Any(existing => string.Equals(existing, value, StringComparison.OrdinalIgnoreCase)))
                    continue;
                exclusions.Add(value);
                added = true;
            }
            if (!added)
                return;
            MarkConfigurationChanged();
            RefreshExclusionsList(exclusions.Count - 1);
        }

        private void RemoveExclusionButton_Click(object sender, EventArgs e)
        {
            if (ConfigurationMutationBlocked)
                return;
            var index = exclusionsListBox.SelectedIndex;
            if (index < 0 || _workspace.Configuration?.Excludes == null)
                return;
            var configuration = _workspace.Configuration;
            if (MessageBox.Show(this, "Remove the selected exclusion?", "Remove exclusion",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return;
            if (!CanCommitDialogMutation(configuration))
                return;
            configuration.Excludes.RemoveAt(index);
            MarkConfigurationChanged();
            RefreshExclusionsList(Math.Min(index, configuration.Excludes.Count - 1));
        }

        private void ExclusionsListBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (ConfigurationMutationBlocked)
            {
                e.SuppressKeyPress = true;
                return;
            }
            if (e.KeyCode == Keys.Delete)
            {
                RemoveExclusionButton_Click(sender, EventArgs.Empty);
                e.Handled = true;
            }
        }

        private void ExclusionsListBox_SelectedIndexChanged(object sender, EventArgs e) => UpdateExclusionButtons();

        private void UpdateExclusionButtons()
        {
            var canEdit = !ConfigurationMutationBlocked && _workspace.Configuration != null;
            addRunningExclusionButton.Enabled = canEdit;
            addExecutableExclusionButton.Enabled = canEdit;
            addPathExclusionButton.Enabled = canEdit;
            addManualExclusionButton.Enabled = canEdit;
            removeExclusionButton.Enabled = canEdit && exclusionsListBox.SelectedIndex >= 0;
            exclusionsListBox.Enabled = canEdit;
        }

        private async void StartServiceButton_Click(object sender, EventArgs e)
        {
            if (_operationInProgress)
                return;

            SetOperationState(true);
            try
            {
                if (!await EnsureInstalledServiceEngineCurrentAsync("start") ||
                    !CanUseSavedConfiguration("start"))
                    return;
                var expectedEnginePath = _workspace.EnginePath;
                Func<bool> registrationGuard = () =>
                    IsRegisteredServiceEngine(expectedEnginePath);
                await RunServiceOperationAsync(() => _serviceController.StartAsync(
                        expectedEnginePath, registrationGuard,
                        ApplicationConstants.ServiceOperationTimeout, _lifetimeCancellation.Token), true,
                    true, expectedEnginePath, registrationGuard);
            }
            finally
            {
                SetOperationState(false);
            }
        }

        private async void StopServiceButton_Click(object sender, EventArgs e)
        {
            await RunServiceOperationAsync(() => _serviceController.StopAsync(
                ApplicationConstants.ServiceOperationTimeout, _lifetimeCancellation.Token), false);
        }

        private async void RestartServiceButton_Click(object sender, EventArgs e)
        {
            if (_operationInProgress)
                return;

            SetOperationState(true);
            try
            {
                if (!await EnsureInstalledServiceEngineCurrentAsync("restart") ||
                    !CanUseSavedConfiguration("restart"))
                    return;
                var expectedEnginePath = _workspace.EnginePath;
                Func<bool> registrationGuard = () =>
                    IsRegisteredServiceEngine(expectedEnginePath);
                await RunServiceOperationAsync(() => _serviceController.RestartAsync(
                        expectedEnginePath, registrationGuard,
                        ApplicationConstants.ServiceOperationTimeout, _lifetimeCancellation.Token), true,
                    true, expectedEnginePath, registrationGuard);
            }
            finally
            {
                SetOperationState(false);
            }
        }

        private async void InstallServiceButton_Click(object sender, EventArgs e)
        {
            if (_operationInProgress)
                return;

            SetOperationState(true);
            try
            {
                await InstallServiceAsync();
            }
            finally
            {
                SetOperationState(false);
            }
        }

        private async Task<bool> InstallServiceAsync()
        {
            await RefreshServiceStatusAsync();
            if (!_serviceStatus.IsInstallationKnown)
            {
                MessageBox.Show(this,
                    "The Windows service installation state could not be verified. No installation command was run.",
                    "Service state unavailable", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            if (_serviceStatus.IsInstalled)
            {
                MessageBox.Show(this, "The ProxiFyre service is already installed.",
                    "Service already installed", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return false;
            }
            if (_engineLocation == null || !_engineLocation.IsResolved)
            {
                MessageBox.Show(this, "Resolve a trusted ProxiFyre.exe before installing the service.",
                    "Engine not resolved", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            var installed = await RunServiceOperationAsync(() => _serviceController.InstallAsync(
                _engineLocation.Path, ApplicationConstants.ServiceOperationTimeout, _lifetimeCancellation.Token), false);
            return installed;
        }

        private async void UninstallServiceButton_Click(object sender, EventArgs e)
        {
            if (_operationInProgress)
                return;

            SetOperationState(true);
            try
            {
                var verifiedStatus = await GetServiceStatusForMutationAsync();
                if (verifiedStatus == null)
                    return;
                if (!verifiedStatus.IsInstalled)
                {
                    MessageBox.Show(this, "The ProxiFyre service is not installed.",
                        "Service not installed", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                string registrationSnapshot;
                try
                {
                    registrationSnapshot = _engineLocator.GetRegisteredServiceImagePath();
                }
                catch (Exception ex)
                {
                    ShowError("The service registration could not be read. No uninstall command was run.", ex);
                    return;
                }
                EngineLocation registeredEngine;
                try
                {
                    registeredEngine = _engineLocator.Resolve(_settings);
                }
                catch (Exception ex)
                {
                    ShowError("The registered service executable could not be resolved. " +
                              "No uninstall command was run.", ex);
                    return;
                }
                var useRegisteredEngine = registeredEngine.Source ==
                                          ProxiFyreUI.Infrastructure.EngineLocationSource.ServiceRegistration &&
                                          registeredEngine.IsResolved;
                var uninstallEngine = registeredEngine;
                Func<bool> registrationSnapshotGuard;
                string expectedRegisteredEnginePath = null;

                if (useRegisteredEngine)
                {
                    registrationSnapshotGuard = () =>
                        IsServiceRegistrationSnapshotCurrent(registrationSnapshot);
                    expectedRegisteredEnginePath = registeredEngine.Path;
                    if (MessageBox.Show(this,
                        "Uninstall the ProxiFyre Windows service?\r\n\r\nThe configuration, backup, and log files will not be deleted.",
                        "Uninstall service", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                        MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                        return;
                }
                else
                {
                    uninstallEngine = _engineLocator.ResolveTrustedUninstallFallback(_settings,
                        _engineLocation?.Path);
                    if (!uninstallEngine.IsResolved)
                        uninstallEngine = BrowseForTrustedUninstallEngine();
                    if (uninstallEngine == null || !uninstallEngine.IsResolved)
                        return;

                    var registrationProblem = !string.IsNullOrWhiteSpace(registeredEngine.Error)
                        ? registeredEngine.Error
                        : "The installed service does not contain a usable registered executable path.";
                    var fallbackMessage = registrationProblem + "\r\n\r\n" +
                        "To remove the broken service registration, ProxiFyreUI can use this separately trusted executable:\r\n\r\n" +
                        uninstallEngine.Path + "\r\n\r\n" +
                        "It will be launched only with the single fixed argument: uninstall\r\n" +
                        "No command-line arguments from the service registration will be used. " +
                        "The configuration, backup, and log files will not be deleted.\r\n\r\nContinue?";
                    if (MessageBox.Show(this, fallbackMessage, "Use trusted fallback to uninstall service",
                        MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                        MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                        return;

                    var finalStatus = await GetServiceStatusForMutationAsync();
                    if (finalStatus == null || !finalStatus.IsInstalled)
                    {
                        MessageBox.Show(this,
                            "The service installation changed before uninstall could begin. No command was run.",
                            "Service state changed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                    if (!IsBrokenServiceRegistrationSnapshotCurrent(registrationSnapshot))
                    {
                        ShowServiceEngineChanged("The service registration or registered executable changed while " +
                                                 "uninstall was being confirmed. No command was run; review the " +
                                                 "current registration and try again.");
                        return;
                    }
                    registrationSnapshotGuard = () =>
                        IsBrokenServiceRegistrationSnapshotCurrent(registrationSnapshot);
                }

                await RunServiceOperationAsync(() => _serviceController.UninstallAsync(
                        uninstallEngine.Path, registrationSnapshotGuard,
                        ApplicationConstants.ServiceOperationTimeout, _lifetimeCancellation.Token),
                    false, true, expectedRegisteredEnginePath,
                    registrationSnapshotGuard);
            }
            finally
            {
                SetOperationState(false);
            }
        }

        private async Task<bool> RunServiceOperationAsync(Func<Task<ServiceOperationResult>> operation,
            bool marksAppliedOnSuccess, bool showSuccess = true,
            string expectedRegisteredEnginePath = null,
            Func<bool> serviceRegistrationGuard = null)
        {
            var expectedConfiguration = marksAppliedOnSuccess ? _workspace.CurrentFingerprint : null;
            SetOperationState(true);
            try
            {
                if (!string.IsNullOrWhiteSpace(expectedRegisteredEnginePath) &&
                    !IsRegisteredServiceEngine(expectedRegisteredEnginePath))
                {
                    ShowServiceEngineChanged("The service operation was not started because the registered " +
                                             "ProxiFyre executable changed. Refresh the engine location and try again.");
                    return false;
                }
                if (serviceRegistrationGuard != null && !serviceRegistrationGuard())
                {
                    ShowServiceEngineChanged("The service registration or registered executable changed before " +
                                             "the operation could begin. No command was run; review the current " +
                                             "registration and try again.");
                    return false;
                }

                var result = await operation();
                ObserveServiceStatus(result.Status ??
                    await _serviceController.GetStatusAsync(_lifetimeCancellation.Token));
                if (result.Success)
                {
                    ClearServiceFailureIndicators();
                    var engineStillCurrent = !marksAppliedOnSuccess ||
                                             IsRegisteredServiceEngine(expectedRegisteredEnginePath);
                    var appliedStateConfirmed = !marksAppliedOnSuccess ||
                                                (result.ConfirmsConfigurationReloaded &&
                                                 engineStillCurrent && _serviceStatus.IsRunning &&
                                                 _workspace.TryMarkApplied(expectedConfiguration));
                    if (!appliedStateConfirmed)
                    {
                        _workspace.InvalidateAppliedConfirmation();
                        statusStripLabel.Text = !engineStillCurrent
                            ? "The service operation completed, but the registered executable changed; apply state is unknown."
                            : !result.ConfirmsConfigurationReloaded
                                ? "The service is running, but this operation did not reload app-config.json. Restart it to apply and confirm the saved configuration."
                                : "The service operation completed, but the saved configuration could not be confirmed as applied.";
                    }
                    else if (showSuccess)
                    {
                        statusStripLabel.Text = result.Message;
                    }
                }
                else
                {
                    RecordServiceFailure(result);
                    statusStripLabel.Text = result.Message ?? "The service operation failed.";
                    ShowServiceFailure(result);
                }
                UpdateAllStates();
                return result.Success;
            }
            catch (OperationCanceledException)
            {
                return false;
            }
            catch (Exception ex)
            {
                ShowError("The service operation failed.", ex);
                return false;
            }
            finally
            {
                SetOperationState(false);
                await RefreshServiceStatusAsync();
            }
        }

        private void ShowServiceFailure(ServiceOperationResult result)
        {
            var recent = _logLines.Where(IsWarningOrError).TakeLastCompatible(8);
            var message = _errorFormatter.FormatServiceFailure(result, recent, CurrentSecrets());
            MessageBox.Show(this, message, "ProxiFyre service", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private void ReloadButton_Click(object sender, EventArgs e)
        {
            if (ConfigurationMutationBlocked)
                return;

            SetOperationState(true);
            try
            {
                if (!ConfirmDiscardUnsaved("reload the configuration from disk"))
                    return;
                LoadWorkspace();
                statusStripLabel.Text = "Configuration reloaded from disk.";
            }
            catch (Exception ex)
            {
                ShowError("The configuration could not be reloaded.", ex);
            }
            finally
            {
                SetOperationState(false);
            }
        }

        private void ValidateButton_Click(object sender, EventArgs e)
        {
            if (!EnsureWorkspaceAvailable())
                return;
            ReadRootControlsIntoConfiguration();
            var validation = _workspace.Validate();
            RefreshRoutingGrid(SelectedRuleIndex);
            MessageBox.Show(this, ConfigurationWorkspace.FormatValidation(validation),
                validation.HasErrors ? "Configuration is invalid" : "Configuration validation",
                MessageBoxButtons.OK, validation.HasErrors ? MessageBoxIcon.Error :
                    validation.HasWarnings ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            UpdateAllStates();
        }

        private void SaveButton_Click(object sender, EventArgs e)
        {
            if (ConfigurationMutationBlocked)
                return;

            SetOperationState(true);
            try
            {
                var save = SaveWithPrompts();
                if (save?.Status == WorkspaceSaveStatus.Saved)
                {
                    statusStripLabel.Text = _serviceStatus.IsRunning
                        ? "Configuration saved. Restart the service to apply it."
                        : "Configuration saved. It will be used on the next service start.";
                    UpdateAllStates();
                }
            }
            finally
            {
                SetOperationState(false);
            }
        }

        private async void ApplyRestartButton_Click(object sender, EventArgs e)
        {
            if (_operationInProgress || _applyWorkflowInProgress)
                return;

            // Acquire the UI-level apply gate before SaveWithPrompts. Saving creates/rotates the
            // sole recovery backup; a second click or Save during the first status refresh must
            // not overwrite it before the apply/rollback decision is complete.
            _applyWorkflowInProgress = true;
            SetOperationState(true);
            try
            {
                if (!await EnsureInstalledServiceEngineCurrentAsync("apply the configuration"))
                    return;

                var save = SaveWithPrompts();
                if (save == null || save.Status != WorkspaceSaveStatus.Saved)
                    return;

                await RefreshServiceStatusAsync();
                var installIfMissing = false;
                if (_serviceStatus.IsInstallationKnown && !_serviceStatus.IsInstalled)
                {
                    var install = MessageBox.Show(this,
                        "The configuration was saved, but the ProxiFyre service is not installed.\r\n\r\nInstall and start it now?",
                        "Saved but not applied", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                    installIfMissing = install == DialogResult.Yes;
                }

                ConfigurationApplyResult applied;
                try
                {
                    applied = await _applyCoordinator.ApplySavedConfigurationAsync(save,
                        _engineLocation?.Path, installIfMissing, false,
                        ApplicationConstants.ServiceOperationTimeout, _lifetimeCancellation.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    ShowError("The configuration was saved, but it could not be applied.", ex);
                    return;
                }
                finally
                {
                    await RefreshServiceStatusAsync();
                }

                if (applied.Outcome == ConfigurationApplyOutcome.Applied)
                {
                    ClearServiceFailureIndicators();
                    statusStripLabel.Text = "Configuration applied; the service reports Running.";
                    UpdateAllStates();
                    return;
                }

                if (applied.Outcome == ConfigurationApplyOutcome.SavedServiceNotInstalled)
                {
                    statusStripLabel.Text = "Configuration saved; install and start the service to apply it.";
                    UpdateAllStates();
                    return;
                }

                if (applied.Outcome == ConfigurationApplyOutcome.ServiceEngineChanged)
                {
                    ShowServiceEngineChanged(applied.ServiceResult == null
                        ? "The registered ProxiFyre executable changed before the service operation. No service change was attempted."
                        : "The registered ProxiFyre executable changed during the service operation. The saved configuration was not marked as applied.");
                    return;
                }

                if (applied.Outcome == ConfigurationApplyOutcome.ConfigurationReloadNotConfirmed)
                {
                    statusStripLabel.Text =
                        "The service is running, but it was already started elsewhere and this apply did not reload app-config.json. Run Apply & Restart again.";
                    UpdateAllStates();
                    return;
                }

                if (applied.Outcome == ConfigurationApplyOutcome.DependencyUnavailable)
                {
                    if (applied.ServiceResult != null)
                        ShowServiceFailure(applied.ServiceResult);
                    RecordServiceFailure(applied.ServiceResult);
                    statusStripLabel.Text =
                        "Configuration saved, but Windows Packet Filter is unavailable. No configuration rollback was attempted.";
                    UpdateAllStates();
                    return;
                }

                if (applied.Outcome == ConfigurationApplyOutcome.InstallFailed)
                {
                    if (applied.ServiceResult != null)
                        ShowServiceFailure(applied.ServiceResult);
                    RecordServiceFailure(applied.ServiceResult);
                    statusStripLabel.Text = "Configuration saved, but the service could not be installed. The backup was kept.";
                    UpdateAllStates();
                    return;
                }

                if (applied.Outcome == ConfigurationApplyOutcome.ServiceStatusUnavailable)
                {
                    if (applied.ServiceResult != null)
                        ShowServiceFailure(applied.ServiceResult);
                    RecordServiceFailure(applied.ServiceResult);
                    statusStripLabel.Text = applied.ServiceResult?.Message ??
                        "Configuration saved, but the Windows service state could not be verified. No service change was attempted.";
                    UpdateAllStates();
                    return;
                }

                if (applied.Outcome == ConfigurationApplyOutcome.SavedConfigurationChangedBeforeApply ||
                    applied.Outcome == ConfigurationApplyOutcome.SavedConfigurationChangedDuringApply)
                {
                    statusStripLabel.Text = applied.Outcome ==
                        ConfigurationApplyOutcome.SavedConfigurationChangedBeforeApply
                        ? "app-config.json changed before the service operation; the saved edit was not applied. Reload from disk."
                        : "app-config.json changed during the service operation; applied state is unknown. Reload from disk.";
                    UpdateAllStates();
                    return;
                }

                if (applied.Outcome != ConfigurationApplyOutcome.ServiceRestartFailed)
                {
                    statusStripLabel.Text = "Configuration saved, but it was not applied.";
                    UpdateAllStates();
                    return;
                }

                if (applied.ServiceResult != null)
                    ShowServiceFailure(applied.ServiceResult);
                RecordServiceFailure(applied.ServiceResult);

                if (!save.BackupCreated || string.IsNullOrWhiteSpace(save.BackupPath))
                {
                    statusStripLabel.Text = "Configuration saved, but the service restart failed. No previous live file was available to roll back.";
                    return;
                }

                var rollback = MessageBox.Show(this,
                    "The new configuration was saved, but the service did not restart successfully.\r\n\r\n" +
                    "Restore the previous configuration from its backup and attempt one controlled restart?",
                    "Apply failed", MessageBoxButtons.YesNo, MessageBoxIcon.Error,
                    MessageBoxDefaultButton.Button1);
                if (rollback != DialogResult.Yes)
                {
                    statusStripLabel.Text = "Configuration saved, but the service restart failed. The backup was kept for recovery.";
                    return;
                }

                ConfigurationApplyResult rolledBack;
                try
                {
                    rolledBack = await _applyCoordinator.RollbackAndRestartAsync(save,
                        ApplicationConstants.ServiceOperationTimeout, _lifetimeCancellation.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                finally
                {
                    await RefreshServiceStatusAsync();
                }

                if (rolledBack.Outcome == ConfigurationApplyOutcome.RollbackFailed)
                {
                    ShowError("The previous configuration could not be restored. The backup was not deleted.",
                        rolledBack.RollbackError);
                    statusStripLabel.Text = "Apply and rollback both failed; inspect the configuration and logs.";
                    return;
                }

                if (rolledBack.Outcome == ConfigurationApplyOutcome.RolledBackConfigurationChanged)
                {
                    // TryRollback already replaced the working model with the backup. Keep the
                    // controls in sync even though the live file then changed again externally.
                    BindConfiguration();
                    statusStripLabel.Text =
                        "The rollback file changed during restart; applied state is unknown. Reload from disk.";
                    UpdateAllStates();
                    return;
                }

                if (rolledBack.Outcome == ConfigurationApplyOutcome.ServiceEngineChanged)
                {
                    ShowServiceEngineChanged(
                        "The registered ProxiFyre executable changed before rollback. The saved configuration remains pending.");
                    BindConfiguration();
                    return;
                }

                if (rolledBack.Outcome == ConfigurationApplyOutcome.RolledBackServiceEngineChanged)
                {
                    ShowServiceEngineChanged(rolledBack.ServiceResult == null
                        ? "The previous configuration was restored, but the registered ProxiFyre executable changed before it could be restarted. Apply state is unknown."
                        : "The previous configuration was restored, but the registered ProxiFyre executable changed during the rollback restart. Apply state is unknown.");
                    BindConfiguration();
                    return;
                }

                if (rolledBack.Outcome ==
                    ConfigurationApplyOutcome.RolledBackConfigurationReloadNotConfirmed)
                {
                    BindConfiguration();
                    statusStripLabel.Text =
                        "The previous configuration was restored, but the running service did not reload it. Restart the service to confirm the restored configuration.";
                    UpdateAllStates();
                    return;
                }

                BindConfiguration();
                var rollbackRestarted = rolledBack.Outcome == ConfigurationApplyOutcome.RolledBackAndRunning;
                if (!rollbackRestarted && rolledBack.ServiceResult != null)
                    ShowServiceFailure(rolledBack.ServiceResult);
                if (rollbackRestarted)
                    ClearServiceFailureIndicators();
                else
                    RecordServiceFailure(rolledBack.ServiceResult);
                statusStripLabel.Text = rollbackRestarted
                    ? "The previous configuration was restored and the service is running."
                    : "The previous configuration was restored, but the service restart still failed.";
                UpdateAllStates();
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                ShowError("The apply workflow did not complete.", ex);
            }
            finally
            {
                _applyWorkflowInProgress = false;
                SetOperationState(false);
            }
        }

        private WorkspaceSaveResult SaveWithPrompts()
        {
            if (!EnsureWorkspaceAvailable())
                return null;
            ReadRootControlsIntoConfiguration();
            var validation = _workspace.Validate();
            RefreshRoutingGrid(SelectedRuleIndex);
            if (validation.HasErrors)
            {
                MessageBox.Show(this, ConfigurationWorkspace.FormatValidation(validation),
                    "Configuration was not saved", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return new WorkspaceSaveResult { Status = WorkspaceSaveStatus.ValidationFailed, Validation = validation };
            }
            if (validation.HasWarnings && MessageBox.Show(this,
                ConfigurationWorkspace.FormatValidation(validation) + "\r\n\r\nSave despite these warnings?",
                "Configuration warnings", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return null;

            var result = _workspace.Save(false);
            if (result.Status == WorkspaceSaveStatus.ExternalChangeDetected)
            {
                var choice = MessageBox.Show(this,
                    "app-config.json changed outside ProxiFyreUI after it was loaded.\r\n\r\n" +
                    "Yes — reload from disk and discard current edits\r\n" +
                    "No — overwrite the external version with current edits\r\n" +
                    "Cancel — leave both unchanged",
                    "External configuration change", MessageBoxButtons.YesNoCancel,
                    MessageBoxIcon.Warning, MessageBoxDefaultButton.Button3);
                if (choice == DialogResult.Yes)
                {
                    try { LoadWorkspace(); }
                    catch (Exception ex) { ShowError("The external configuration could not be loaded.", ex); }
                    return null;
                }
                if (choice == DialogResult.No)
                    result = _workspace.Save(true);
                else
                    return null;
            }

            if (result.Status == WorkspaceSaveStatus.Failed)
                ShowError("The live configuration was not changed.", result.Error);
            else if (result.Status == WorkspaceSaveStatus.Saved)
                BindConfiguration();
            UpdateAllStates();
            return result;
        }

        private async void BrowseEngineButton_Click(object sender, EventArgs e)
        {
            if (_operationInProgress)
                return;

            SetOperationState(true);
            try
            {
                var verifiedStatus = await GetServiceStatusForMutationAsync();
                if (verifiedStatus == null)
                    return;
                if (verifiedStatus.IsInstalled)
                {
                    MessageBox.Show(this,
                        "The GUI uses the executable registered for the installed service. Uninstall or re-register the service before selecting a different engine.",
                        "Installed service controls engine location", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                if (!ConfirmDiscardUnsaved("change the ProxiFyre engine location"))
                    return;

                using (var dialog = new OpenFileDialog
                {
                    Title = "Select ProxiFyre engine",
                    Filter = "ProxiFyre engine (" + ProxiFyrePaths.EngineExecutableName + ")|" +
                             ProxiFyrePaths.EngineExecutableName,
                    CheckFileExists = true,
                    Multiselect = false
                })
                {
                    if (dialog.ShowDialog(this) != DialogResult.OK)
                        return;
                    var location = _engineLocator.ValidateUserSelection(dialog.FileName);
                    if (!location.IsResolved)
                    {
                        MessageBox.Show(this, location.Error, "Invalid engine", MessageBoxButtons.OK,
                            MessageBoxIcon.Error);
                        return;
                    }

                    try
                    {
                        var previousEnginePath = _workspace.EnginePath;
                        var loaded = _workspace.Load(location);
                        _engineLocation = location;
                        _settings.SelectedEnginePath = location.Path;
                        TrySaveSettings();
                        UpdateResolvedPaths();
                        CompleteWorkspaceLoad(loaded, previousEnginePath);
                    }
                    catch (Exception ex)
                    {
                        ShowError("The selected engine configuration could not be loaded. " +
                                  "The previous engine and working configuration were preserved.", ex);
                    }
                }
            }
            finally
            {
                SetOperationState(false);
            }
        }

        private void OpenConfigurationFolderButton_Click(object sender, EventArgs e)
        {
            OpenFolder(Path.GetDirectoryName(_workspace.ConfigurationPath), "configuration");
        }

        private void OpenLogFolderButton_Click(object sender, EventArgs e)
        {
            OpenFolder(_workspace.LogDirectoryPath, "log");
        }

        private void OpenLogFileButton_Click(object sender, EventArgs e)
        {
            try
            {
                var filePath = _logTailer.CurrentFilePath;
                if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                    filePath = LogFileLocator.FindLatest(_workspace.LogDirectoryPath);

                if (string.IsNullOrWhiteSpace(filePath))
                {
                    MessageBox.Show(this,
                        "No ProxiFyre log file is available yet. Start the service or reload the Logs tab after a log is created.",
                        "Log file not available", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                Process.Start(new ProcessStartInfo { FileName = filePath, UseShellExecute = true });
                statusStripLabel.Text = "Opened " + Path.GetFileName(filePath) + ".";
            }
            catch (Exception ex)
            {
                ShowError("The current log file could not be opened.", ex);
            }
        }

        private void CopyDiagnosticsButton_Click(object sender, EventArgs e)
        {
            try
            {
                var diagnostics = _diagnosticsBuilder.Build(new DiagnosticsContext
                {
                    EnginePath = _workspace.EnginePath,
                    ConfigurationPath = _workspace.ConfigurationPath,
                    LogDirectoryPath = _workspace.LogDirectoryPath,
                    ServiceStatus = _serviceStatus,
                    Validation = _workspace.LastValidation,
                    RecentMessages = _logLines.ToArray(),
                    Secrets = _workspace.Configuration?.Proxies?
                        .Select(rule => rule?.Password)
                        .Where(password => !string.IsNullOrEmpty(password))
                });
                Clipboard.SetText(diagnostics);
                statusStripLabel.Text = "Redacted diagnostics copied to the clipboard.";
            }
            catch (Exception ex)
            {
                ShowError("Diagnostics could not be copied.", ex);
            }
        }

        private void StartLogTailerIfNeeded()
        {
            if (followLogsCheckBox.Checked && !string.IsNullOrWhiteSpace(_workspace.LogDirectoryPath))
                _logTailer.Start(_workspace.LogDirectoryPath);
        }

        private void ResetLogViewForEngineChange()
        {
            Interlocked.Increment(ref _logViewGeneration);
            _logTailer.Stop();
            _logLines.Clear();
            logRichTextBox.Clear();
            logStatusLabel.Text = followLogsCheckBox.Checked
                ? "Loading logs for the selected engine…"
                : "Following paused. Log view cleared for the selected engine.";
        }

        private void FollowLogsCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            _settings.FollowLogs = followLogsCheckBox.Checked;
            TrySaveSettings();
            if (followLogsCheckBox.Checked)
                StartLogTailerIfNeeded();
            else
            {
                _logTailer.Stop();
                logStatusLabel.Text = "Following paused. Existing view is retained.";
            }
        }

        private void LogTailer_LinesRead(object sender, LogLinesEventArgs e)
        {
            var viewGeneration = Volatile.Read(ref _logViewGeneration);
            TryPostToUi(() =>
            {
                if (viewGeneration != Volatile.Read(ref _logViewGeneration) ||
                    e.Generation != _logTailer.Generation ||
                    !PathsEqual(e.SourceDirectoryPath, _workspace.LogDirectoryPath) ||
                    !PathsEqual(Path.GetDirectoryName(e.FilePath), e.SourceDirectoryPath))
                    return;
                if (e.Reset)
                    _logLines.Clear();
                foreach (var line in e.Lines)
                {
                    _logLines.Enqueue(line);
                    while (_logLines.Count > ApplicationConstants.MaximumLogLines)
                        _logLines.Dequeue();
                }
                RenderLogs();
            });
        }

        private void LogTailer_StatusChanged(object sender, LogStatusEventArgs e)
        {
            var viewGeneration = Volatile.Read(ref _logViewGeneration);
            TryPostToUi(() =>
            {
                if (viewGeneration == Volatile.Read(ref _logViewGeneration) &&
                    e.Generation == _logTailer.Generation &&
                    PathsEqual(e.SourceDirectoryPath, _workspace.LogDirectoryPath))
                    logStatusLabel.Text = e.Status;
            });
        }

        private void TryPostToUi(Action action)
        {
            if (action == null || _cleanedUp || Disposing || IsDisposed || !IsHandleCreated)
                return;

            try
            {
                BeginInvoke((Action)(() =>
                {
                    if (!_cleanedUp && !Disposing && !IsDisposed)
                        action();
                }));
            }
            catch (ObjectDisposedException)
            {
                // The window handle was destroyed between the guard and BeginInvoke.
            }
            catch (InvalidOperationException)
            {
                // Form shutdown can remove the handle while a timer callback is scheduling.
            }
        }

        private void LogFilterChanged(object sender, EventArgs e) => RenderLogs();

        private void RenderLogs()
        {
            var filter = logSearchTextBox.Text.Trim();
            var level = logLevelFilterComboBox.SelectedItem?.ToString() ?? "All levels";
            var visible = _logLines.Where(line =>
                (filter.Length == 0 || line.IndexOf(filter, StringComparison.CurrentCultureIgnoreCase) >= 0) &&
                LogLevelMatcher.Matches(line, level));
            logRichTextBox.Lines = visible.ToArray();
            if (followLogsCheckBox.Checked && logRichTextBox.TextLength > 0)
            {
                logRichTextBox.SelectionStart = logRichTextBox.TextLength;
                logRichTextBox.ScrollToCaret();
            }
        }

        private void CopySelectedLogButton_Click(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(logRichTextBox.SelectedText))
                Clipboard.SetText(logRichTextBox.SelectedText);
        }

        private void CopyVisibleLogButton_Click(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(logRichTextBox.Text))
                Clipboard.SetText(logRichTextBox.Text);
        }

        private void ClearLogViewButton_Click(object sender, EventArgs e)
        {
            _logLines.Clear();
            logRichTextBox.Clear();
            logStatusLabel.Text = "View cleared. Service log files were not deleted.";
        }

        private void ReloadLogsButton_Click(object sender, EventArgs e)
        {
            _logTailer.Reload(_workspace.LogDirectoryPath);
        }

        private async Task<bool> EnsureInstalledServiceEngineCurrentAsync(string operation)
        {
            var verifiedStatus = await GetServiceStatusForMutationAsync();
            if (verifiedStatus == null)
                return false;
            if (verifiedStatus.State == ProxiFyreServiceState.DeletionPending)
            {
                MessageBox.Show(this,
                    "The ProxiFyre service is marked for deletion. Wait for Windows to finish removing it before attempting to " +
                    operation + ".",
                    "Service deletion pending", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return false;
            }
            if (!verifiedStatus.IsInstalled)
                return true;

            var registeredEngine = GetRegisteredServiceEngine();
            if (registeredEngine == null)
                return false;

            var workspaceMatches = PathsEqual(_workspace.EnginePath, registeredEngine.Path) &&
                                   _workspace.Configuration != null;
            var formMatches = PathsEqual(_engineLocation?.Path, registeredEngine.Path);
            if (workspaceMatches && formMatches)
                return true;

            if (_workspace.IsDirty && MessageBox.Show(this,
                "The installed service now points to a different ProxiFyre executable:\r\n\r\n" +
                registeredEngine.Path + "\r\n\r\nDiscard the unsaved edits for the previous engine and load the " +
                "registered engine before attempting to " + operation + "?",
                "Service engine changed", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            {
                statusStripLabel.Text = "The service operation was cancelled; unsaved edits were preserved.";
                return false;
            }

            try
            {
                var previousEnginePath = _workspace.EnginePath;
                var loaded = _workspace.Load(registeredEngine);
                _engineLocation = registeredEngine;
                UpdateResolvedPaths();
                CompleteWorkspaceLoad(loaded, previousEnginePath);
                statusStripLabel.Text = "Loaded the configuration for the executable registered by the service.";
                return true;
            }
            catch (Exception ex)
            {
                ShowError("The registered service engine configuration could not be loaded. " +
                          "The previous engine and working configuration were preserved, and no service change was attempted.",
                    ex);
                return false;
            }
        }

        private async Task<ServiceStatusInfo> GetServiceStatusForMutationAsync()
        {
            ServiceStatusInfo verifiedStatus;
            try
            {
                verifiedStatus = await _serviceController.GetStatusAsync(_lifetimeCancellation.Token);
                ObserveServiceStatus(verifiedStatus);
                UpdateAllStates();
            }
            catch (OperationCanceledException)
            {
                return null;
            }
            catch (Exception ex)
            {
                verifiedStatus = new ServiceStatusInfo(ProxiFyreServiceState.Error, ex.Message);
                ObserveServiceStatus(verifiedStatus);
                UpdateAllStates();
            }

            if (verifiedStatus.IsInstallationKnown)
                return verifiedStatus;

            MessageBox.Show(this,
                "The Windows service installation state could not be verified. No service change was attempted.",
                "Service state unavailable", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return null;
        }

        private EngineLocation GetRegisteredServiceEngine()
        {
            var location = _engineLocator.Resolve(_settings);
            if (location.Source == ProxiFyreUI.Infrastructure.EngineLocationSource.ServiceRegistration && location.IsResolved)
                return location;

            var detail = location.Source == ProxiFyreUI.Infrastructure.EngineLocationSource.ServiceRegistration &&
                         !string.IsNullOrWhiteSpace(location.Error)
                ? "\r\n\r\n" + location.Error
                : string.Empty;
            MessageBox.Show(this,
                "The executable registered for the installed ProxiFyre service could not be verified. " +
                "No service change was attempted." + detail,
                "Registered engine unavailable", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return null;
        }

        private EngineLocation BrowseForTrustedUninstallEngine()
        {
            using (var dialog = new OpenFileDialog
            {
                Title = "Select trusted ProxiFyre engine for service uninstall",
                Filter = "ProxiFyre engine (" + ProxiFyrePaths.EngineExecutableName + ")|" +
                         ProxiFyrePaths.EngineExecutableName,
                CheckFileExists = true,
                Multiselect = false
            })
            {
                if (dialog.ShowDialog(this) != DialogResult.OK)
                    return null;

                var location = _engineLocator.ValidateUserSelection(dialog.FileName);
                if (location.IsResolved)
                    return location;

                MessageBox.Show(this, location.Error,
                    "Untrusted uninstall executable", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return null;
            }
        }

        private bool IsServiceRegistrationSnapshotCurrent(string expectedImagePath)
        {
            try
            {
                return string.Equals(expectedImagePath,
                    _engineLocator.GetRegisteredServiceImagePath(), StringComparison.Ordinal);
            }
            catch
            {
                // A fallback executable is allowed only while the broken registration can be
                // shown to be the same one the user confirmed.
                return false;
            }
        }

        private bool IsBrokenServiceRegistrationSnapshotCurrent(string expectedImagePath)
        {
            if (!IsServiceRegistrationSnapshotCurrent(expectedImagePath))
                return false;
            try
            {
                var current = _engineLocator.Resolve(_settings);
                return current.Source !=
                           ProxiFyreUI.Infrastructure.EngineLocationSource.ServiceRegistration ||
                       !current.IsResolved;
            }
            catch
            {
                return false;
            }
        }

        private bool IsRegisteredServiceEngine(string expectedPath)
        {
            try
            {
                return _engineLocator.IsRegisteredServiceExecutable(expectedPath);
            }
            catch
            {
                // Registration access failures and malformed values must never preserve an
                // applied-state confirmation or authorize a lifecycle operation.
                return false;
            }
        }

        private void ShowServiceEngineChanged(string message)
        {
            statusStripLabel.Text = message;
            MessageBox.Show(this, message, "Service engine changed", MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            UpdateAllStates();
        }

        private void ObserveServiceStatus(ServiceStatusInfo status)
        {
            _serviceStatus = status ?? new ServiceStatusInfo(ProxiFyreServiceState.Unknown);
            if (!_serviceStatus.IsRunning ||
                (_workspace.HasConfirmedApplied &&
                 (!_workspace.IsFingerprintCurrent(_workspace.CurrentFingerprint) ||
                  !IsRegisteredServiceEngine(_workspace.EnginePath))))
                _workspace.InvalidateAppliedConfirmation();
            if (_serviceStatus.IsRunning ||
                _serviceStatus.State == ProxiFyreServiceState.NotInstalled ||
                _serviceStatus.State == ProxiFyreServiceState.DeletionPending)
                ClearServiceFailureIndicators();
        }

        private void RecordServiceFailure(ServiceOperationResult result)
        {
            if (_serviceStatus.IsRunning)
            {
                ClearServiceFailureIndicators();
                return;
            }

            _packetFilterUnavailable = result?.FailureKind ==
                                       ServiceOperationFailureKind.DependencyUnavailable;
            _engineStartupFailed = ServiceOperationFailureClassifier.IsEngineStartupFailure(result);
        }

        private void ClearServiceFailureIndicators()
        {
            _engineStartupFailed = false;
            _packetFilterUnavailable = false;
        }

        private async void ServiceRefreshTimer_Tick(object sender, EventArgs e)
        {
            await RefreshServiceStatusAsync();
        }

        private async Task RefreshServiceStatusAsync()
        {
            if (Interlocked.Exchange(ref _refreshingStatus, 1) != 0)
                return;
            try
            {
                ObserveServiceStatus(await _serviceController.GetStatusAsync(_lifetimeCancellation.Token));
                UpdateAllStates();
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                ObserveServiceStatus(new ServiceStatusInfo(ProxiFyreServiceState.Error, ex.Message));
                UpdateAllStates();
            }
            finally
            {
                Interlocked.Exchange(ref _refreshingStatus, 0);
            }
        }

        private void UpdateAllStates()
        {
            if (IsDisposed)
                return;
            serviceStateValueLabel.Text = _serviceStatus.ToString();
            serviceStateValueLabel.ForeColor = _serviceStatus.IsRunning ? Color.DarkGreen :
                _serviceStatus.State == ProxiFyreServiceState.Error ? Color.DarkRed : SystemColors.ControlText;
            trayServiceStatusMenuItem.Text = "Service: " + _serviceStatus;
            notifyIcon.Text = TruncateNotifyText("ProxiFyre — Service: " + _serviceStatus);

            var validation = _workspace.Configuration == null ? null : _workspace.Validate();
            configurationStateValueLabel.Text = validation == null ? "Not loaded" :
                validation.HasErrors ? "Configuration invalid" : "Configuration valid";
            configurationStateValueLabel.ForeColor = validation?.HasErrors == true ? Color.DarkRed :
                validation != null ? Color.DarkGreen : SystemColors.ControlText;

            if (_packetFilterUnavailable)
                changesStateValueLabel.Text = "Packet filter unavailable";
            else if (_engineStartupFailed)
                changesStateValueLabel.Text = "Engine startup failed";
            else if (_workspace.IsDirty)
                changesStateValueLabel.Text = "Unsaved changes";
            else if (_workspace.RestartRequired && _serviceStatus.IsRunning)
                changesStateValueLabel.Text = "Saved, restart required";
            else if (_workspace.RestartRequired)
                changesStateValueLabel.Text = "Saved; service not running";
            else if (_serviceStatus.IsRunning && validation?.HasErrors == false && _workspace.HasConfirmedApplied)
                changesStateValueLabel.Text = "Applied";
            else if (_serviceStatus.IsRunning && validation?.HasErrors == false)
                changesStateValueLabel.Text = "Running; apply state unknown";
            else
                changesStateValueLabel.Text = "Saved; service not running";

            Text = _baseWindowTitle + (_workspace.IsDirty ? " *" : string.Empty);
            var pending = _serviceStatus.State == ProxiFyreServiceState.StartPending ||
                          _serviceStatus.State == ProxiFyreServiceState.StopPending ||
                          _serviceStatus.State == ProxiFyreServiceState.PausePending ||
                          _serviceStatus.State == ProxiFyreServiceState.ContinuePending ||
                          _serviceStatus.State == ProxiFyreServiceState.DeletionPending;
            startServiceButton.Enabled = !_operationInProgress && !pending &&
                _serviceStatus.IsInstalled && _serviceStatus.State == ProxiFyreServiceState.Stopped;
            stopServiceButton.Enabled = !_operationInProgress && !pending &&
                (_serviceStatus.State == ProxiFyreServiceState.Running || _serviceStatus.State == ProxiFyreServiceState.Paused);
            restartServiceButton.Enabled = !_operationInProgress && !pending && _serviceStatus.IsInstalled;
            installServiceButton.Enabled = !_operationInProgress && _serviceStatus.IsInstallationKnown &&
                !_serviceStatus.IsInstalled &&
                _engineLocation?.IsResolved == true;
            var canUninstallService = !_operationInProgress && !pending && _serviceStatus.IsInstalled &&
                                      _serviceStatus.IsInstallationKnown;
            headerUninstallServiceButton.Enabled = canUninstallService;
            uninstallServiceButton.Enabled = canUninstallService;
            browseEngineButton.Enabled = !_operationInProgress && _serviceStatus.IsInstallationKnown &&
                !_serviceStatus.IsInstalled;
            trayStartMenuItem.Enabled = startServiceButton.Enabled;
            trayStopMenuItem.Enabled = stopServiceButton.Enabled;
            trayRestartMenuItem.Enabled = restartServiceButton.Enabled;
            saveButton.Enabled = !_operationInProgress && _workspace.Configuration != null;
            applyRestartButton.Enabled = saveButton.Enabled &&
                                         _serviceStatus.State != ProxiFyreServiceState.DeletionPending;
            reloadButton.Enabled = !_operationInProgress && _workspace.HasConfigurationPath;
            validateButton.Enabled = !_operationInProgress && _workspace.Configuration != null;
            logLevelComboBox.Enabled = !ConfigurationMutationBlocked && _workspace.Configuration != null;
            bypassLanCheckBox.Enabled = !ConfigurationMutationBlocked && _workspace.Configuration != null;
            trayExitMenuItem.Enabled = !_exitRequested && _configurationDialogDepth == 0;
            UpdateRoutingButtons();
            UpdateExclusionButtons();
        }

        private void SetOperationState(bool busy)
        {
            if (busy)
                _operationDepth++;
            else if (_operationDepth > 0)
                _operationDepth--;

            _operationInProgress = _operationDepth > 0 || _applyWorkflowInProgress;
            UseWaitCursor = _operationInProgress;
            operationProgressBar.Visible = _operationInProgress;
            UpdateAllStates();
            ScheduleDeferredExitIfReady();
        }

        private bool ConfigurationMutationBlocked => _operationInProgress || _applyWorkflowInProgress;

        private void UpdateResolvedPaths()
        {
            enginePathTextBox.Text = _engineLocation?.Path ?? "Not resolved";
            configurationPathTextBox.Text = _engineLocation?.ConfigurationPath ?? "Not resolved";
            logPathTextBox.Text = _engineLocation?.LogDirectoryPath ?? "Not resolved";
            engineVersionValueLabel.Text = GetFileVersion(_engineLocation?.Path);
        }

        private bool EnsureWorkspaceAvailable()
        {
            if (_workspace.Configuration != null)
                return true;
            MessageBox.Show(this, "Resolve ProxiFyre.exe and load a configuration first.",
                "Configuration unavailable", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return false;
        }

        private bool CanUseSavedConfiguration(string operation)
        {
            if (string.IsNullOrWhiteSpace(_workspace.ConfigurationPath) || !File.Exists(_workspace.ConfigurationPath))
            {
                MessageBox.Show(this, "Save a valid app-config.json before attempting to " + operation + " the service.",
                    "Configuration missing", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            ValidationResult liveValidation;
            bool hasExternalChanges;
            try
            {
                liveValidation = _workspace.ValidateLiveFile();
                hasExternalChanges = _workspace.HasExternalChanges();
            }
            catch (Exception ex)
            {
                ShowError("The saved configuration could not be read and the service was not " + operation + "ed.", ex);
                return false;
            }
            if (liveValidation.HasErrors)
            {
                MessageBox.Show(this,
                    "The saved app-config.json is invalid. The service was not " + operation + "ed.\r\n\r\n" +
                    ConfigurationWorkspace.FormatValidation(liveValidation, false),
                    "Saved configuration is invalid", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            if (hasExternalChanges && MessageBox.Show(this,
                "app-config.json changed outside ProxiFyreUI. The external file is valid, but this window is showing an older version.\r\n\r\n" +
                "Continue using the externally changed file?",
                "External configuration change", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return false;
            if (_workspace.IsDirty && MessageBox.Show(this,
                "There are unsaved edits. The service will use the configuration currently on disk, not these edits.\r\n\r\nContinue?",
                "Unsaved edits", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return false;
            return true;
        }

        private void SettingsPreferenceChanged(object sender, EventArgs e)
        {
            _settings.MinimizeToTray = minimizeToTrayCheckBox.Checked;
            TrySaveSettings();
        }

        private bool ConfirmDiscardUnsaved(string action)
        {
            return !_workspace.IsDirty || MessageBox.Show(this,
                "There are unsaved configuration changes. Continuing will discard them.\r\n\r\nContinue to " + action + "?",
                "Discard unsaved changes", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) == DialogResult.Yes;
        }

        private void OpenFolder(string path, string description)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path))
                    throw new DirectoryNotFoundException("The " + description + " folder is not resolved.");
                Directory.CreateDirectory(path);
                Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
            }
            catch (Exception ex)
            {
                ShowError("The " + description + " folder could not be opened.", ex);
            }
        }

        private void TrySaveSettings()
        {
            try { _settingsStore.Save(_settings); }
            catch (Exception ex) { statusStripLabel.Text = "UI preferences could not be saved: " + ex.Message; }
        }

        private void TrayOpenMenuItem_Click(object sender, EventArgs e)
        {
            ShowMainWindow();
        }

        internal void RestoreFromSecondaryLaunch()
        {
            if (Disposing || IsDisposed)
                return;

            ShowMainWindow();
            statusStripLabel.Text = "ProxiFyre was already running; the existing window was activated.";
        }

        private void ShowMainWindow()
        {
            Show();
            WindowState = FormWindowState.Normal;
            BringToFront();
            Activate();
        }

        private void NotifyIcon_DoubleClick(object sender, EventArgs e) => TrayOpenMenuItem_Click(sender, e);
        private void TrayStartMenuItem_Click(object sender, EventArgs e) => StartServiceButton_Click(sender, e);
        private void TrayStopMenuItem_Click(object sender, EventArgs e) => StopServiceButton_Click(sender, e);
        private void TrayRestartMenuItem_Click(object sender, EventArgs e) => RestartServiceButton_Click(sender, e);
        private void TrayOpenLogsMenuItem_Click(object sender, EventArgs e)
        {
            TrayOpenMenuItem_Click(sender, e);
            mainTabControl.SelectedTab = logsTabPage;
        }

        private void TrayExitMenuItem_Click(object sender, EventArgs e)
        {
            if (_operationInProgress || _applyWorkflowInProgress || _configurationDialogDepth > 0)
            {
                _exitRequested = true;
                trayExitMenuItem.Enabled = false;
                statusStripLabel.Text = _configurationDialogDepth > 0
                    ? "Exit requested. Finish the open editor; unsaved changes will be confirmed before ProxiFyreUI closes."
                    : "Exit requested. ProxiFyreUI will close after the current service operation finishes.";
                return;
            }

            _exiting = true;
            Close();
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (e.CloseReason == CloseReason.WindowsShutDown)
            {
                // Windows is already terminating the interactive session. Do not put a modal
                // unsaved-edits prompt in the shutdown path; just cancel local work and release
                // UI resources best-effort.
                Cleanup();
                return;
            }

            if (!_exiting && e.CloseReason == CloseReason.UserClosing && _settings.MinimizeToTray)
            {
                e.Cancel = true;
                Hide();
                statusStripLabel.Text = "ProxiFyreUI is still running in the notification area. The service was not stopped.";
                return;
            }

            if (_operationInProgress || _applyWorkflowInProgress || _configurationDialogDepth > 0)
            {
                e.Cancel = true;
                if (_exiting)
                    _exitRequested = true;
                _exiting = false;
                statusStripLabel.Text = _exitRequested
                    ? (_configurationDialogDepth > 0
                        ? "Exit requested. Finish the open editor; unsaved changes will be confirmed before ProxiFyreUI closes."
                        : "Exit requested. ProxiFyreUI will close after the current service operation finishes.")
                    : "Finish the open editor or wait for the current service operation before closing ProxiFyreUI.";
                UpdateAllStates();
                return;
            }

            if (!ConfirmDiscardUnsaved("exit ProxiFyreUI"))
            {
                e.Cancel = true;
                _exiting = false;
                _exitRequested = false;
                UpdateAllStates();
                return;
            }
            Cleanup();
        }

        private void MainForm_FormClosed(object sender, FormClosedEventArgs e) => Cleanup();

        private void Cleanup()
        {
            if (_cleanedUp)
                return;
            _cleanedUp = true;
            serviceRefreshTimer.Stop();
            _lifetimeCancellation.Cancel();
            _logTailer.Dispose();
            _serviceController.Dispose();
            notifyIcon.Visible = false;
            notifyIcon.Icon = null;
            Icon = null;
            notifyIcon.Dispose();
            _applicationIcon.Dispose();
            _lifetimeCancellation.Dispose();
        }

        private void ScheduleDeferredExitIfReady()
        {
            if (!_exitRequested || _operationInProgress || _applyWorkflowInProgress ||
                _configurationDialogDepth > 0 ||
                _exitCloseScheduled || _cleanedUp || Disposing || IsDisposed || !IsHandleCreated)
                return;

            _exitCloseScheduled = true;
            BeginInvoke((Action)(() =>
            {
                _exitCloseScheduled = false;
                if (!_exitRequested || _operationInProgress || _applyWorkflowInProgress ||
                    _configurationDialogDepth > 0 ||
                    _cleanedUp || Disposing || IsDisposed)
                    return;
                _exiting = true;
                Close();
            }));
        }

        private static string FormatApplications(IList<string> applications)
        {
            if (applications == null || applications.Count == 0)
                return "No application matches";
            var display = applications.Select(value => value != null && value.Length == 0
                ? "All unmatched applications"
                : string.IsNullOrWhiteSpace(value) ? "<invalid blank entry>" : value);
            return string.Join(", ", display);
        }

        private static string FormatAuthentication(ProxyRule rule)
        {
            return !string.IsNullOrEmpty(rule?.Username) || !string.IsNullOrEmpty(rule?.Password)
                ? "Credentials configured"
                : "None";
        }

        private static string FormatTransport(string transport)
        {
            return string.Equals(transport, "TLS", StringComparison.OrdinalIgnoreCase) ||
                   (!string.IsNullOrWhiteSpace(transport) && transport.IndexOf("TLS", StringComparison.OrdinalIgnoreCase) >= 0)
                ? "TLS"
                : "TCP";
        }

        private static string FormatValues(IList<string> values, string fallback)
        {
            return values == null ? fallback : values.Count == 0 ? "<none>" : string.Join(", ", values);
        }

        private static bool IsWarningOrError(string line)
        {
            string level;
            if (LogLevelMatcher.TryGetLevel(line, out level))
                return string.Equals(level, "Warning", StringComparison.OrdinalIgnoreCase) ||
                       string.Equals(level, "Error", StringComparison.OrdinalIgnoreCase);
            return line.IndexOf("warn", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   line.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   line.IndexOf("fail", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool PathsEqual(string first, string second)
        {
            if (string.IsNullOrWhiteSpace(first) || string.IsNullOrWhiteSpace(second))
                return false;
            try
            {
                return string.Equals(Path.GetFullPath(first).TrimEnd(Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar),
                    Path.GetFullPath(second).TrimEnd(Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException ||
                                       ex is PathTooLongException)
            {
                return false;
            }
        }

        private static OpenFileDialog CreateExecutableDialog()
        {
            return new OpenFileDialog
            {
                Title = "Select executable",
                Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*",
                Multiselect = true,
                CheckFileExists = true
            };
        }

        private static string GetFileVersion(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return "Not available";
            try { return FileVersionInfo.GetVersionInfo(path).FileVersion ?? "Not available"; }
            catch { return "Not available"; }
        }

        private static Icon LoadApplicationIcon()
        {
            try
            {
                return Icon.ExtractAssociatedIcon(Application.ExecutablePath) ??
                       (Icon)SystemIcons.Application.Clone();
            }
            catch (Exception ex) when (ex is ArgumentException || ex is IOException ||
                                       ex is UnauthorizedAccessException)
            {
                return (Icon)SystemIcons.Application.Clone();
            }
        }

        private static string GetArchitectureDescription()
        {
            var os = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITEW6432") ??
                     Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") ??
                     (Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit");
            var process = Environment.Is64BitProcess ?
                (string.Equals(Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE"), "ARM64",
                    StringComparison.OrdinalIgnoreCase) ? "ARM64" : "x64") : "x86";
            return os + " OS; " + process + " GUI";
        }

        private static string TruncateNotifyText(string value)
        {
            return value.Length <= 63 ? value : value.Substring(0, 63);
        }

        private void ShowError(string summary, Exception exception)
        {
            var message = _errorFormatter.FormatException(summary, exception, CurrentSecrets());
            MessageBox.Show(this, message, "ProxiFyre UI", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private IEnumerable<string> CurrentSecrets()
        {
            return _workspace.Configuration?.Proxies?
                       .Where(rule => rule != null && !string.IsNullOrEmpty(rule.Password))
                       .Select(rule => rule.Password) ?? Enumerable.Empty<string>();
        }
    }
}
