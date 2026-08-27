using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace ProxiFyre.Configuration
{
    public interface IConfigurationFileSystem
    {
        bool FileExists(string path);

        byte[] ReadAllBytes(string path);

        long GetFileLength(string path);

        DateTime GetLastWriteTimeUtc(string path);

        void CreateDirectory(string path);

        void DeleteFile(string path);

        void MoveFile(string sourcePath, string destinationPath);

        void ReplaceFile(string sourcePath, string destinationPath, string backupPath);

        void WriteAllTextAndFlush(string path, string content);
    }

    public sealed class PhysicalConfigurationFileSystem : IConfigurationFileSystem
    {
        private static readonly UTF8Encoding Utf8WithoutBom = new UTF8Encoding(false, true);

        public bool FileExists(string path) => File.Exists(path);

        public byte[] ReadAllBytes(string path) => File.ReadAllBytes(path);

        public long GetFileLength(string path) => new FileInfo(path).Length;

        public DateTime GetLastWriteTimeUtc(string path) => File.GetLastWriteTimeUtc(path);

        public void CreateDirectory(string path) => Directory.CreateDirectory(path);

        public void DeleteFile(string path) => File.Delete(path);

        public void MoveFile(string sourcePath, string destinationPath) => File.Move(sourcePath, destinationPath);

        public void ReplaceFile(string sourcePath, string destinationPath, string backupPath)
        {
            // Do not ignore metadata merge failures: app-config.json may contain plaintext
            // credentials, so a replacement must not silently weaken inherited ACL/security data.
            File.Replace(sourcePath, destinationPath, backupPath, false);
        }

        public void WriteAllTextAndFlush(string path, string content)
        {
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream, Utf8WithoutBom))
            {
                writer.Write(content);
                writer.Flush();
                stream.Flush(true);
            }
        }
    }

    public sealed class FileFingerprint : IEquatable<FileFingerprint>
    {
        public static readonly FileFingerprint Missing = new FileFingerprint(false, 0, DateTime.MinValue, null);

        public FileFingerprint(bool exists, long length, DateTime lastWriteTimeUtc, string contentSha256)
        {
            Exists = exists;
            Length = length;
            LastWriteTimeUtc = lastWriteTimeUtc.Kind == DateTimeKind.Utc
                ? lastWriteTimeUtc
                : lastWriteTimeUtc.ToUniversalTime();
            ContentSha256 = contentSha256;
        }

        public bool Exists { get; }

        public long Length { get; }

        public DateTime LastWriteTimeUtc { get; }

        public string ContentSha256 { get; }

        public bool Equals(FileFingerprint other)
        {
            if (ReferenceEquals(other, null))
                return false;
            if (!Exists || !other.Exists)
                return Exists == other.Exists;

            // The content hash is authoritative. Timestamp and length are retained for useful
            // diagnostics but not compared because copying can change timestamps without edits.
            return string.Equals(ContentSha256, other.ContentSha256, StringComparison.OrdinalIgnoreCase);
        }

        public override bool Equals(object obj) => Equals(obj as FileFingerprint);

        public override int GetHashCode()
        {
            return Exists
                ? StringComparer.OrdinalIgnoreCase.GetHashCode(ContentSha256 ?? string.Empty)
                : 0;
        }

        public static bool operator ==(FileFingerprint left, FileFingerprint right)
        {
            if (ReferenceEquals(left, null))
                return ReferenceEquals(right, null);
            return left.Equals(right);
        }

        public static bool operator !=(FileFingerprint left, FileFingerprint right) => !(left == right);
    }

    public sealed class ConfigurationLoadResult
    {
        internal ConfigurationLoadResult(
            ProxiFyreConfiguration configuration,
            FileFingerprint fingerprint,
            string sourcePath,
            bool liveFileExists,
            bool loadedFromSample)
        {
            Configuration = configuration;
            Fingerprint = fingerprint;
            SourcePath = sourcePath;
            LiveFileExists = liveFileExists;
            LoadedFromSample = loadedFromSample;
        }

        public ProxiFyreConfiguration Configuration { get; }

        public FileFingerprint Fingerprint { get; }

        public string SourcePath { get; }

        public bool LiveFileExists { get; }

        public bool LoadedFromSample { get; }
    }

    public sealed class ConfigurationSaveResult
    {
        internal ConfigurationSaveResult(FileFingerprint fingerprint, string backupPath,
            bool backupCreated, FileFingerprint backupFingerprint)
        {
            Fingerprint = fingerprint;
            BackupPath = backupPath;
            BackupCreated = backupCreated;
            BackupFingerprint = backupFingerprint;
        }

        public FileFingerprint Fingerprint { get; }

        public string BackupPath { get; }

        public bool BackupCreated { get; }

        public FileFingerprint BackupFingerprint { get; }
    }

    public sealed class ConfigurationFileChangedException : IOException
    {
        public ConfigurationFileChangedException(
            string filePath,
            FileFingerprint expectedFingerprint,
            FileFingerprint actualFingerprint)
            : base("The configuration file changed on disk after it was loaded: '" + filePath + "'.")
        {
            FilePath = filePath;
            ExpectedFingerprint = expectedFingerprint;
            ActualFingerprint = actualFingerprint;
        }

        public string FilePath { get; }

        public FileFingerprint ExpectedFingerprint { get; }

        public FileFingerprint ActualFingerprint { get; }
    }

    public sealed class ConfigurationPersistenceException : IOException
    {
        public ConfigurationPersistenceException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }

    /// <summary>
    /// Loads configurations with a fingerprint and writes same-directory temp files atomically.
    /// </summary>
    public sealed class ConfigurationFileStore
    {
        private readonly IConfigurationSerializer _serializer;
        private readonly IConfigurationFileSystem _fileSystem;

        public ConfigurationFileStore()
            : this(new ConfigurationSerializer(), new PhysicalConfigurationFileSystem())
        {
        }

        public ConfigurationFileStore(IConfigurationSerializer serializer, IConfigurationFileSystem fileSystem)
        {
            _serializer = serializer ?? throw new ArgumentNullException(nameof(serializer));
            _fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
        }

        public ConfigurationLoadResult Load(string filePath)
        {
            var fullPath = NormalizePath(filePath);
            if (!_fileSystem.FileExists(fullPath))
                throw new FileNotFoundException("The configuration file does not exist.", fullPath);

            var bytes = _fileSystem.ReadAllBytes(fullPath);
            var configuration = _serializer.Deserialize(ConfigurationSerializer.DecodeUtf8(bytes));
            var fingerprint = CreateFingerprint(fullPath, bytes);
            return new ConfigurationLoadResult(configuration, fingerprint, fullPath, true, false);
        }

        public ConfigurationLoadResult LoadOrCreate(string filePath, string samplePath = null)
        {
            var fullPath = NormalizePath(filePath);
            if (_fileSystem.FileExists(fullPath))
                return Load(fullPath);

            if (!string.IsNullOrWhiteSpace(samplePath))
            {
                var fullSamplePath = NormalizePath(samplePath);
                if (_fileSystem.FileExists(fullSamplePath))
                {
                    var bytes = _fileSystem.ReadAllBytes(fullSamplePath);
                    var configuration = _serializer.Deserialize(ConfigurationSerializer.DecodeUtf8(bytes));
                    return new ConfigurationLoadResult(
                        configuration,
                        FileFingerprint.Missing,
                        fullSamplePath,
                        false,
                        true);
                }
            }

            return new ConfigurationLoadResult(
                ProxiFyreConfiguration.CreateBlank(),
                FileFingerprint.Missing,
                null,
                false,
                false);
        }

        public ConfigurationSaveResult SaveAtomic(
            string filePath,
            ProxiFyreConfiguration configuration,
            FileFingerprint expectedFingerprint = null,
            bool overwriteExternalChanges = false)
        {
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration));

            var fullPath = NormalizePath(filePath);
            string json;
            FileFingerprint committedFingerprint;
            try
            {
                json = _serializer.Serialize(configuration);
                // Prepare every potentially fallible transform before the atomic commit. Once
                // ReplaceFile/MoveFile succeeds, this method must be able to report success
                // without performing more encoding, hashing, or filesystem I/O.
                committedFingerprint = CreateSerializedFingerprint(json);
            }
            catch (Exception ex)
            {
                throw new ConfigurationPersistenceException(
                    "The new configuration could not be serialized; the live file was not changed.",
                    ex);
            }

            var directory = Path.GetDirectoryName(fullPath);
            if (string.IsNullOrEmpty(directory))
                throw new ArgumentException("The configuration path must include a directory.", nameof(filePath));

            var temporaryPath = fullPath + ".tmp";
            var backupPath = fullPath + ".bak";
            using (var saveMutex = new Mutex(false, GetSaveMutexName(fullPath)))
            {
                var lockTaken = false;
                FileStream crossSessionLock = null;
                try
                {
                    try
                    {
                        lockTaken = saveMutex.WaitOne(TimeSpan.Zero);
                    }
                    catch (AbandonedMutexException)
                    {
                        // The previous owner terminated. The mutex is now owned by this thread;
                        // stale temporary state is cleaned below before any commit is attempted.
                        lockTaken = true;
                    }

                    if (!lockTaken)
                    {
                        throw new ConfigurationPersistenceException(
                            "Another ProxiFyreUI instance is saving this configuration. Retry after that save completes.",
                            new IOException("The configuration save lock is already held."));
                    }

                    _fileSystem.CreateDirectory(directory);

                    try
                    {
                        // A filesystem sharing lock also serializes elevated GUI instances in
                        // different Windows/RDP sessions, where a Local\ named mutex alone would
                        // not. The zero-byte lock file is intentionally persistent; a process
                        // crash releases the handle and the next save can safely reuse it.
                        crossSessionLock = new FileStream(
                            fullPath + ".save.lock",
                            FileMode.OpenOrCreate,
                            FileAccess.ReadWrite,
                            FileShare.None);
                    }
                    catch (IOException ex)
                    {
                        throw new ConfigurationPersistenceException(
                            "Another process is saving this configuration. Retry after that save completes.",
                            ex);
                    }

                    var actualFingerprint = GetFingerprint(fullPath);
                    ThrowIfExternallyChanged(
                        fullPath,
                        expectedFingerprint,
                        actualFingerprint,
                        overwriteExternalChanges);

                    if (_fileSystem.FileExists(temporaryPath))
                        _fileSystem.DeleteFile(temporaryPath);

                    _fileSystem.WriteAllTextAndFlush(temporaryPath, json);

                    // An editor that does not participate in our named mutex can still change the
                    // live file while the temp file is written. Recheck immediately before the
                    // atomic commit so that late changes are not silently overwritten.
                    actualFingerprint = GetFingerprint(fullPath);
                    ThrowIfExternallyChanged(
                        fullPath,
                        expectedFingerprint,
                        actualFingerprint,
                        overwriteExternalChanges);

                    var hadLiveFile = actualFingerprint.Exists;
                    if (hadLiveFile)
                        _fileSystem.ReplaceFile(temporaryPath, fullPath, backupPath);
                    else
                        _fileSystem.MoveFile(temporaryPath, fullPath);

                    // No fallible filesystem read occurs after the commit. The bytes serialized
                    // above are exactly those flushed to the temp file, and the content hash is
                    // authoritative for future external-change comparisons.
                    return new ConfigurationSaveResult(
                        committedFingerprint,
                        backupPath,
                        hadLiveFile,
                        hadLiveFile ? actualFingerprint : null);
                }
                catch (ConfigurationFileChangedException)
                {
                    TryDeleteTemporaryFile(temporaryPath);
                    throw;
                }
                catch (ConfigurationPersistenceException)
                {
                    TryDeleteTemporaryFile(temporaryPath);
                    throw;
                }
                catch (Exception ex)
                {
                    TryDeleteTemporaryFile(temporaryPath);
                    throw new ConfigurationPersistenceException(
                        "The configuration could not be committed atomically. No partial live file was written by this save.",
                        ex);
                }
                finally
                {
                    crossSessionLock?.Dispose();
                    if (lockTaken)
                        saveMutex.ReleaseMutex();
                }
            }
        }

        public FileFingerprint GetFingerprint(string filePath)
        {
            var fullPath = NormalizePath(filePath);
            if (!_fileSystem.FileExists(fullPath))
                return FileFingerprint.Missing;

            var bytes = _fileSystem.ReadAllBytes(fullPath);
            return CreateFingerprint(fullPath, bytes);
        }

        public bool HasExternalChanges(string filePath, FileFingerprint expectedFingerprint)
        {
            if (expectedFingerprint == null)
                throw new ArgumentNullException(nameof(expectedFingerprint));
            return GetFingerprint(filePath) != expectedFingerprint;
        }

        private FileFingerprint CreateFingerprint(string fullPath, byte[] bytes)
        {
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(bytes);
                var hashText = BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant();
                return new FileFingerprint(
                    true,
                    _fileSystem.GetFileLength(fullPath),
                    _fileSystem.GetLastWriteTimeUtc(fullPath),
                    hashText);
            }
        }

        private static FileFingerprint CreateSerializedFingerprint(string json)
        {
            var bytes = new UTF8Encoding(false, true).GetBytes(json);
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(bytes);
                return new FileFingerprint(
                    true,
                    bytes.LongLength,
                    DateTime.MinValue,
                    BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant());
            }
        }

        private static void ThrowIfExternallyChanged(
            string fullPath,
            FileFingerprint expectedFingerprint,
            FileFingerprint actualFingerprint,
            bool overwriteExternalChanges)
        {
            if (!overwriteExternalChanges && expectedFingerprint != null && actualFingerprint != expectedFingerprint)
                throw new ConfigurationFileChangedException(fullPath, expectedFingerprint, actualFingerprint);
        }

        private static string GetSaveMutexName(string fullPath)
        {
            var normalizedPath = fullPath.ToUpperInvariant();
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(normalizedPath));
                return @"Local\ProxiFyreUI.ConfigurationSave." +
                       BitConverter.ToString(hash).Replace("-", string.Empty);
            }
        }

        private void TryDeleteTemporaryFile(string path)
        {
            try
            {
                if (_fileSystem.FileExists(path))
                    _fileSystem.DeleteFile(path);
            }
            catch
            {
                // A cleanup failure must not mask the original persistence error.
            }
        }

        private static string NormalizePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentException("A file path is required.", nameof(path));
            return Path.GetFullPath(path);
        }
    }
}
