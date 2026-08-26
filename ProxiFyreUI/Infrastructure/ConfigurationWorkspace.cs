using ProxiFyre.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace ProxiFyreUI.Infrastructure
{
    public enum WorkspaceSaveStatus
    {
        Saved,
        ValidationFailed,
        ExternalChangeDetected,
        Failed
    }

    public sealed class WorkspaceLoadResult
    {
        public ProxiFyreConfiguration Configuration { get; set; }
        public bool LoadedFromSample { get; set; }
        public bool LiveFileExists { get; set; }
        public ValidationResult Validation { get; set; }
    }

    public sealed class WorkspaceSaveResult
    {
        public WorkspaceSaveStatus Status { get; set; }
        public ValidationResult Validation { get; set; }
        public string BackupPath { get; set; }
        public FileFingerprint BackupFingerprint { get; set; }
        public FileFingerprint SavedFingerprint { get; set; }
        public Exception Error { get; set; }
        public bool BackupCreated { get; set; }
    }

    public sealed class ConfigurationWorkspace
    {
        private readonly ConfigurationFileStore _fileStore;
        private readonly ConfigurationValidator _validator;
        private readonly ConfigurationNormalizer _normalizer;
        private FileFingerprint _fingerprint = FileFingerprint.Missing;
        private string _lastBackupPath;
        private FileFingerprint _lastBackupFingerprint;
        private FileFingerprint _lastSavedFingerprint;

        public ConfigurationWorkspace(ConfigurationFileStore fileStore = null,
            ConfigurationValidator validator = null, ConfigurationNormalizer normalizer = null)
        {
            _fileStore = fileStore ?? new ConfigurationFileStore();
            _validator = validator ?? new ConfigurationValidator();
            _normalizer = normalizer ?? new ConfigurationNormalizer();
        }

        public event EventHandler DirtyStateChanged;

        public string EnginePath { get; private set; }
        public string ConfigurationPath { get; private set; }
        public string LogDirectoryPath { get; private set; }
        public ProxiFyreConfiguration Configuration { get; private set; }
        public ValidationResult LastValidation { get; private set; }
        public bool IsDirty { get; private set; }
        public bool RestartRequired { get; private set; }
        public bool HasConfirmedApplied { get; private set; }
        public bool HasConfigurationPath => !string.IsNullOrWhiteSpace(ConfigurationPath);
        public string LastBackupPath => _lastBackupPath;
        public FileFingerprint CurrentFingerprint => _fingerprint;

        public WorkspaceLoadResult Load(EngineLocation engineLocation)
        {
            if (engineLocation == null || !engineLocation.IsResolved)
                throw new InvalidOperationException("Resolve ProxiFyre.exe before loading its configuration.");

            EnginePath = engineLocation.Path;
            ConfigurationPath = engineLocation.ConfigurationPath;
            LogDirectoryPath = engineLocation.LogDirectoryPath;

            var engineDirectory = Path.GetDirectoryName(EnginePath);
            var samplePath = Path.Combine(engineDirectory ?? string.Empty, ProxiFyrePaths.SampleConfigurationFileName);
            if (!File.Exists(samplePath))
            {
                var uiDirectory = Path.GetDirectoryName(typeof(ConfigurationWorkspace).Assembly.Location);
                var adjacentSample = Path.Combine(uiDirectory ?? string.Empty, ProxiFyrePaths.SampleConfigurationFileName);
                samplePath = File.Exists(adjacentSample) ? adjacentSample : null;
            }

            var loaded = _fileStore.LoadOrCreate(ConfigurationPath, samplePath);
            Configuration = loaded.Configuration ?? CreateBlankConfiguration();
            EnsureCollections(Configuration);
            _fingerprint = loaded.Fingerprint ?? FileFingerprint.Missing;
            _lastBackupPath = null;
            _lastBackupFingerprint = null;
            _lastSavedFingerprint = null;
            LastValidation = _validator.Validate(Configuration);
            RestartRequired = false;
            HasConfirmedApplied = false;
            SetDirty(!loaded.LiveFileExists);

            return new WorkspaceLoadResult
            {
                Configuration = Configuration,
                LoadedFromSample = loaded.LoadedFromSample,
                LiveFileExists = loaded.LiveFileExists,
                Validation = LastValidation
            };
        }

        public WorkspaceLoadResult Reload()
        {
            if (!HasConfigurationPath)
                throw new InvalidOperationException("No configuration path is currently resolved.");

            var location = new EngineLocation(EnginePath, EngineLocationSource.UserSelection);
            return Load(location);
        }

        public ValidationResult Validate()
        {
            if (Configuration == null)
                Configuration = CreateBlankConfiguration();
            EnsureCollections(Configuration);
            LastValidation = _validator.Validate(Configuration);
            return LastValidation;
        }

        public bool HasExternalChanges()
        {
            return HasConfigurationPath && _fileStore.HasExternalChanges(ConfigurationPath, _fingerprint);
        }

        public bool IsSaveCurrent(WorkspaceSaveResult save)
        {
            return save != null && save.Status == WorkspaceSaveStatus.Saved &&
                   save.SavedFingerprint != null &&
                   IsFingerprintCurrent(save.SavedFingerprint);
        }

        public bool IsFingerprintCurrent(FileFingerprint expectedFingerprint)
        {
            return HasConfigurationPath && expectedFingerprint != null &&
                   _fileStore.GetFingerprint(ConfigurationPath) == expectedFingerprint;
        }

        public ValidationResult ValidateLiveFile()
        {
            if (!HasConfigurationPath || !File.Exists(ConfigurationPath))
                throw new FileNotFoundException("The live app-config.json does not exist.", ConfigurationPath);
            return _validator.Validate(_fileStore.Load(ConfigurationPath).Configuration);
        }

        public WorkspaceSaveResult Save(bool overwriteExternalChanges)
        {
            var validation = Validate();
            if (validation.HasErrors)
            {
                return new WorkspaceSaveResult
                {
                    Status = WorkspaceSaveStatus.ValidationFailed,
                    Validation = validation
                };
            }

            if (!HasConfigurationPath)
            {
                return new WorkspaceSaveResult
                {
                    Status = WorkspaceSaveStatus.Failed,
                    Validation = validation,
                    Error = new InvalidOperationException("No configuration path is resolved.")
                };
            }

            if (!overwriteExternalChanges && HasExternalChanges())
            {
                return new WorkspaceSaveResult
                {
                    Status = WorkspaceSaveStatus.ExternalChangeDetected,
                    Validation = validation
                };
            }

            try
            {
                var normalized = _normalizer.Normalize(Configuration);
                var normalizedValidation = _validator.Validate(normalized);
                if (normalizedValidation.HasErrors)
                {
                    return new WorkspaceSaveResult
                    {
                        Status = WorkspaceSaveStatus.ValidationFailed,
                        Validation = normalizedValidation
                    };
                }

                var previousFingerprint = _fingerprint;
                var saved = _fileStore.SaveAtomic(ConfigurationPath, normalized, previousFingerprint,
                    overwriteExternalChanges);
                Configuration = normalized;
                LastValidation = normalizedValidation;
                _fingerprint = saved.Fingerprint;
                _lastBackupPath = saved.BackupCreated ? saved.BackupPath : null;
                _lastBackupFingerprint = saved.BackupFingerprint;
                _lastSavedFingerprint = saved.Fingerprint;
                SetDirty(false);
                RestartRequired = true;
                HasConfirmedApplied = false;
                return new WorkspaceSaveResult
                {
                    Status = WorkspaceSaveStatus.Saved,
                    Validation = validation,
                    BackupCreated = saved.BackupCreated,
                    BackupPath = saved.BackupPath,
                    BackupFingerprint = saved.BackupFingerprint,
                    SavedFingerprint = saved.Fingerprint
                };
            }
            catch (ConfigurationFileChangedException)
            {
                return new WorkspaceSaveResult
                {
                    Status = WorkspaceSaveStatus.ExternalChangeDetected,
                    Validation = validation
                };
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException ||
                                       ex is InvalidOperationException)
            {
                return new WorkspaceSaveResult
                {
                    Status = WorkspaceSaveStatus.Failed,
                    Validation = validation,
                    Error = ex
                };
            }
        }

        public bool TryRollback(out Exception error)
        {
            return TryRollback(_lastBackupPath, _lastBackupFingerprint, _lastSavedFingerprint, out error);
        }

        public bool TryRollback(string backupPath, out Exception error)
        {
            return TryRollback(backupPath, _lastBackupFingerprint, _lastSavedFingerprint, out error);
        }

        public bool TryRollback(string backupPath, FileFingerprint expectedBackupFingerprint,
            FileFingerprint expectedSavedFingerprint, out Exception error)
        {
            error = null;
            if (string.IsNullOrWhiteSpace(backupPath) || !File.Exists(backupPath) ||
                string.IsNullOrWhiteSpace(ConfigurationPath) || !File.Exists(ConfigurationPath))
            {
                error = new FileNotFoundException("A recoverable configuration backup is not available.", backupPath);
                return false;
            }

            if (expectedBackupFingerprint == null || expectedSavedFingerprint == null)
            {
                error = new InvalidOperationException(
                    "The rollback is not bound to a completed configuration save.");
                return false;
            }

            string expectedBackupPath;
            string actualBackupPath;
            try
            {
                expectedBackupPath = Path.GetFullPath(ConfigurationPath + ".bak");
                actualBackupPath = Path.GetFullPath(backupPath);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException ||
                                       ex is PathTooLongException)
            {
                error = ex;
                return false;
            }
            if (!string.Equals(actualBackupPath, expectedBackupPath, StringComparison.OrdinalIgnoreCase))
            {
                error = new InvalidOperationException("The rollback source is not the backup for the active configuration.");
                return false;
            }

            try
            {
                // Bind both sides of the rollback to the exact save result. A newer save or an
                // external editor may have changed either app-config.json or its .bak file.
                var currentFingerprint = _fileStore.GetFingerprint(ConfigurationPath);
                if (currentFingerprint != expectedSavedFingerprint)
                {
                    error = new ConfigurationFileChangedException(
                        ConfigurationPath, expectedSavedFingerprint, currentFingerprint);
                    return false;
                }

                var backup = _fileStore.Load(actualBackupPath);
                if (backup.Fingerprint != expectedBackupFingerprint)
                {
                    error = new ConfigurationFileChangedException(
                        actualBackupPath, expectedBackupFingerprint, backup.Fingerprint);
                    return false;
                }

                EnsureCollections(backup.Configuration);
                var rollbackValidation = _validator.Validate(backup.Configuration);
                if (rollbackValidation.HasErrors)
                {
                    error = new InvalidOperationException(
                        "The saved backup is no longer a valid ProxiFyre configuration.");
                    return false;
                }

                // Reuse the shared atomic writer. It rechecks expectedSavedFingerprint after
                // flushing its temp file, preserves ACL metadata, and performs no fallible I/O
                // after the commit. The resulting .bak becomes the failed configuration.
                var restored = _fileStore.SaveAtomic(
                    ConfigurationPath, backup.Configuration, expectedSavedFingerprint, false);
                Configuration = backup.Configuration;
                EnsureCollections(Configuration);
                _fingerprint = restored.Fingerprint;
                LastValidation = rollbackValidation;
                _lastBackupPath = restored.BackupCreated ? restored.BackupPath : null;
                _lastBackupFingerprint = restored.BackupCreated ? expectedSavedFingerprint : null;
                _lastSavedFingerprint = restored.Fingerprint;
                RestartRequired = true;
                HasConfirmedApplied = false;
                SetDirty(false);
                return true;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException ||
                                       ex is InvalidOperationException || ex is ArgumentException ||
                                       ex is ConfigurationFormatException)
            {
                error = ex;
                return false;
            }
        }

        public void MarkApplied()
        {
            RestartRequired = false;
            HasConfirmedApplied = true;
        }

        public bool TryMarkApplied(FileFingerprint expectedFingerprint)
        {
            if (!IsFingerprintCurrent(expectedFingerprint))
                return false;
            MarkApplied();
            return true;
        }

        public void MarkDirty()
        {
            SetDirty(true);
        }

        private void SetDirty(bool value)
        {
            if (IsDirty == value)
                return;
            IsDirty = value;
            DirtyStateChanged?.Invoke(this, EventArgs.Empty);
        }

        private static ProxiFyreConfiguration CreateBlankConfiguration()
        {
            return new ProxiFyreConfiguration
            {
                LogLevel = "Info",
                BypassLan = false,
                Proxies = new List<ProxyRule>(),
                Excludes = new List<string>()
            };
        }

        private static void EnsureCollections(ProxiFyreConfiguration configuration)
        {
            if (configuration.Proxies == null)
                configuration.Proxies = new List<ProxyRule>();
            if (configuration.Excludes == null)
                configuration.Excludes = new List<string>();
        }

        public static string FormatValidation(ValidationResult validation, bool includeWarnings = true)
        {
            if (validation == null)
                return "Configuration has not been validated.";

            var issues = includeWarnings ? validation.Issues : validation.Errors;
            if (issues == null || !issues.Any())
                return "Configuration is valid.";

            return string.Join(Environment.NewLine, issues.Select(issue =>
                $"{issue.Severity}: {issue.Message}" +
                (string.IsNullOrWhiteSpace(issue.Path) ? string.Empty : $" ({issue.Path})")));
        }
    }
}
