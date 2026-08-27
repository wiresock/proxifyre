using ProxiFyreUI.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ProxiFyreUI.Forms
{
    internal partial class ProcessPickerForm : Form
    {
        private readonly IProcessCatalog _processCatalog;
        private readonly CancellationTokenSource _cancellation = new CancellationTokenSource();
        private IReadOnlyList<ProcessEntry> _entries = new ProcessEntry[0];

        public ProcessPickerForm(IProcessCatalog processCatalog = null)
        {
            _processCatalog = processCatalog ?? new ProcessCatalog();
            InitializeComponent();
        }

        public IReadOnlyList<string> SelectedEntries
        {
            get
            {
                return processGrid.SelectedRows.Cast<DataGridViewRow>()
                    .Select(row => row.Tag as ProcessEntry)
                    .Where(entry => entry != null)
                    .Select(entry => useFullPathCheckBox.Checked && !string.IsNullOrWhiteSpace(entry.ExecutablePath)
                        ? entry.ExecutablePath
                        : entry.Name)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            _ = LoadProcessesAsync();
        }

        private async Task LoadProcessesAsync()
        {
            SetLoading(true, "Enumerating running processes…");
            try
            {
                _entries = await _processCatalog.GetProcessesAsync(_cancellation.Token);
                if (!IsDisposed)
                    ApplyFilter();
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception)
            {
                if (!IsDisposed)
                    MessageBox.Show(this, "Running processes could not be enumerated. Try again or add the application manually.",
                        "ProxiFyre UI", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                if (!IsDisposed)
                    SetLoading(false, $"{_entries.Count} process(es) available. Inaccessible paths are still listed by name.");
            }
        }

        private void ApplyFilter()
        {
            var filter = searchTextBox.Text.Trim();
            var selectedIds = processGrid.SelectedRows.Cast<DataGridViewRow>()
                .Select(row => row.Tag as ProcessEntry)
                .Where(entry => entry != null)
                .Select(entry => entry.ProcessId)
                .ToArray();

            processGrid.Rows.Clear();
            foreach (var entry in _entries.Where(entry => MatchesFilter(entry, filter)))
            {
                var index = processGrid.Rows.Add(entry.Name, entry.ProcessId, entry.DisplayPath);
                processGrid.Rows[index].Tag = entry;
                processGrid.Rows[index].Selected = selectedIds.Contains(entry.ProcessId);
            }
            UpdateSelection();
        }

        private static bool MatchesFilter(ProcessEntry entry, string filter)
        {
            return string.IsNullOrWhiteSpace(filter) ||
                   entry.Name.IndexOf(filter, StringComparison.CurrentCultureIgnoreCase) >= 0 ||
                   (!string.IsNullOrWhiteSpace(entry.ExecutablePath) &&
                    entry.ExecutablePath.IndexOf(filter, StringComparison.CurrentCultureIgnoreCase) >= 0) ||
                   entry.ProcessId.ToString().IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private void SetLoading(bool loading, string status)
        {
            progressBar.Visible = loading;
            refreshButton.Enabled = !loading;
            statusLabel.Text = status;
        }

        private void SearchTextBox_TextChanged(object sender, EventArgs e)
        {
            ApplyFilter();
        }

        private async void RefreshButton_Click(object sender, EventArgs e)
        {
            await LoadProcessesAsync();
        }

        private void ProcessGrid_SelectionChanged(object sender, EventArgs e)
        {
            UpdateSelection();
        }

        private void ProcessGrid_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0)
                return;
            processGrid.Rows[e.RowIndex].Selected = true;
            if (okButton.Enabled)
            {
                DialogResult = DialogResult.OK;
                Close();
            }
        }

        private void UpdateSelection()
        {
            okButton.Enabled = processGrid.SelectedRows.Count > 0;
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            _cancellation.Cancel();
            _cancellation.Dispose();
            base.OnFormClosed(e);
        }
    }
}
