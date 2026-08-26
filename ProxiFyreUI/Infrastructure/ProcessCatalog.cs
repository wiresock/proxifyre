using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace ProxiFyreUI.Infrastructure
{
    public sealed class ProcessEntry
    {
        public string Name { get; set; }
        public int ProcessId { get; set; }
        public string ExecutablePath { get; set; }
        public string DisplayPath => string.IsNullOrWhiteSpace(ExecutablePath) ? "Access unavailable" : ExecutablePath;
    }

    public interface IProcessCatalog
    {
        Task<IReadOnlyList<ProcessEntry>> GetProcessesAsync(CancellationToken cancellationToken);
    }

    public sealed class ProcessCatalog : IProcessCatalog
    {
        public Task<IReadOnlyList<ProcessEntry>> GetProcessesAsync(CancellationToken cancellationToken)
        {
            return Task.Run<IReadOnlyList<ProcessEntry>>(() =>
            {
                var entries = new List<ProcessEntry>();
                foreach (var process in Process.GetProcesses())
                {
                    using (process)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        string name;
                        try { name = process.ProcessName; }
                        catch { continue; }

                        string path = null;
                        try { path = process.MainModule?.FileName; }
                        catch (Exception ex) when (ex is InvalidOperationException ||
                                                   ex is System.ComponentModel.Win32Exception ||
                                                   ex is NotSupportedException)
                        {
                            path = null;
                        }

                        int id;
                        try { id = process.Id; }
                        catch { continue; }

                        entries.Add(new ProcessEntry
                        {
                            Name = name,
                            ProcessId = id,
                            ExecutablePath = path
                        });
                    }
                }

                return entries
                    .OrderBy(entry => entry.Name, StringComparer.CurrentCultureIgnoreCase)
                    .ThenBy(entry => entry.ProcessId)
                    .ToArray();
            }, cancellationToken);
        }
    }
}
