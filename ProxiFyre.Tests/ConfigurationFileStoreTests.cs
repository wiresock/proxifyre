using NUnit.Framework;
using ProxiFyre.Configuration;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class ConfigurationFileStoreTests
    {
        private string _directory;
        private string _configurationPath;

        [SetUp]
        public void SetUp()
        {
            _directory = Path.Combine(Path.GetTempPath(), "proxifyre-store-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_directory);
            _configurationPath = Path.Combine(_directory, ProxiFyrePaths.ConfigurationFileName);
        }

        [TearDown]
        public void TearDown()
        {
            if (Directory.Exists(_directory))
                Directory.Delete(_directory, true);
        }

        [Test]
        public void AtomicSaveCreatesLiveFileAndBacksUpPreviousVersion()
        {
            var store = new ConfigurationFileStore();
            var first = TestModels.ValidConfiguration();
            first.Proxies[0].Socks5ProxyEndpoint = "first.example:1080";

            var firstSave = store.SaveAtomic(_configurationPath, first, FileFingerprint.Missing);
            Assert.That(File.Exists(_configurationPath), Is.True);
            Assert.That(firstSave.BackupCreated, Is.False);

            var second = TestModels.ValidConfiguration();
            second.Proxies[0].Socks5ProxyEndpoint = "second.example:1080";
            var secondSave = store.SaveAtomic(_configurationPath, second, firstSave.Fingerprint);

            Assert.That(secondSave.BackupCreated, Is.True);
            Assert.That(File.Exists(_configurationPath + ".bak"), Is.True);
            Assert.That(store.Load(_configurationPath).Configuration.Proxies[0].Socks5ProxyEndpoint, Is.EqualTo("second.example:1080"));
            Assert.That(store.Load(_configurationPath + ".bak").Configuration.Proxies[0].Socks5ProxyEndpoint, Is.EqualTo("first.example:1080"));
            Assert.That(File.Exists(_configurationPath + ".tmp"), Is.False);
        }

        [Test]
        public void SerializationFailureLeavesOriginalUntouched()
        {
            var physicalStore = new ConfigurationFileStore();
            var original = TestModels.ValidConfiguration();
            original.Proxies[0].Socks5ProxyEndpoint = "original.example:1080";
            physicalStore.SaveAtomic(_configurationPath, original);
            var before = File.ReadAllBytes(_configurationPath);

            var failingStore = new ConfigurationFileStore(
                new ThrowingSerializer(),
                new PhysicalConfigurationFileSystem());

            Assert.Throws<ConfigurationPersistenceException>(
                () => failingStore.SaveAtomic(_configurationPath, TestModels.ValidConfiguration()));
            CollectionAssert.AreEqual(before, File.ReadAllBytes(_configurationPath));
        }

        [Test]
        public void ReplacementFailureLeavesOriginalAndCleansTemporaryFile()
        {
            var originalStore = new ConfigurationFileStore();
            var original = TestModels.ValidConfiguration();
            original.Proxies[0].Socks5ProxyEndpoint = "original.example:1080";
            originalStore.SaveAtomic(_configurationPath, original);
            var before = File.ReadAllBytes(_configurationPath);

            var failingStore = new ConfigurationFileStore(
                new ConfigurationSerializer(),
                new FailingReplaceFileSystem());

            Assert.Throws<ConfigurationPersistenceException>(
                () => failingStore.SaveAtomic(_configurationPath, TestModels.ValidConfiguration()));
            CollectionAssert.AreEqual(before, File.ReadAllBytes(_configurationPath));
            Assert.That(File.Exists(_configurationPath + ".tmp"), Is.False);
        }

        [Test]
        public void StaleTemporaryFileIsSafelyReplaced()
        {
            File.WriteAllText(_configurationPath + ".tmp", "stale and incomplete");
            var store = new ConfigurationFileStore();

            store.SaveAtomic(_configurationPath, TestModels.ValidConfiguration(), FileFingerprint.Missing);

            Assert.That(store.Load(_configurationPath).Configuration.Proxies, Has.Count.EqualTo(1));
            Assert.That(File.Exists(_configurationPath + ".tmp"), Is.False);
        }

        [Test]
        public void ExternalModificationIsDetectedAndNotSilentlyOverwritten()
        {
            var store = new ConfigurationFileStore();
            var initialSave = store.SaveAtomic(_configurationPath, TestModels.ValidConfiguration());
            var loaded = store.Load(_configurationPath);
            Assert.That(initialSave.Fingerprint, Is.EqualTo(loaded.Fingerprint));

            var external = TestModels.ValidConfiguration();
            external.Proxies[0].Socks5ProxyEndpoint = "external.example:1080";
            new ConfigurationSerializer().Save(_configurationPath, external);

            Assert.That(store.HasExternalChanges(_configurationPath, loaded.Fingerprint), Is.True);
            Assert.Throws<ConfigurationFileChangedException>(
                () => store.SaveAtomic(_configurationPath, TestModels.ValidConfiguration(), loaded.Fingerprint));
            Assert.That(store.Load(_configurationPath).Configuration.Proxies[0].Socks5ProxyEndpoint, Is.EqualTo("external.example:1080"));
        }

        [Test]
        public void MissingFingerprintDetectsAnotherProcessCreatingTheFile()
        {
            var store = new ConfigurationFileStore();
            var loaded = store.LoadOrCreate(_configurationPath);
            new ConfigurationSerializer().Save(_configurationPath, TestModels.ValidConfiguration());

            Assert.That(loaded.Fingerprint, Is.EqualTo(FileFingerprint.Missing));
            Assert.Throws<ConfigurationFileChangedException>(
                () => store.SaveAtomic(_configurationPath, TestModels.ValidConfiguration(), loaded.Fingerprint));
        }

        [Test]
        public void ExplicitOverwriteAllowsReplacingAnExternallyChangedFile()
        {
            var store = new ConfigurationFileStore();
            var first = store.SaveAtomic(_configurationPath, TestModels.ValidConfiguration());
            File.WriteAllText(_configurationPath, "{\"proxies\":[]}");
            var externalFingerprint = store.GetFingerprint(_configurationPath);
            var replacement = TestModels.ValidConfiguration();
            replacement.Proxies[0].Socks5ProxyEndpoint = "chosen.example:1080";

            var saved = store.SaveAtomic(_configurationPath, replacement, first.Fingerprint, true);

            Assert.That(store.Load(_configurationPath).Configuration.Proxies[0].Socks5ProxyEndpoint, Is.EqualTo("chosen.example:1080"));
            Assert.That(saved.BackupFingerprint, Is.EqualTo(externalFingerprint),
                "Rollback identity must describe the file actually replaced, not the stale loaded fingerprint.");
        }

        [Test]
        public void MissingConfigurationLoadsSampleWithoutPretendingLiveFileExists()
        {
            var samplePath = Path.Combine(_directory, ProxiFyrePaths.SampleConfigurationFileName);
            var sample = TestModels.ValidConfiguration();
            sample.Proxies[0].Socks5ProxyEndpoint = "sample.example:1080";
            new ConfigurationSerializer().Save(samplePath, sample);

            var result = new ConfigurationFileStore().LoadOrCreate(_configurationPath, samplePath);

            Assert.That(result.LiveFileExists, Is.False);
            Assert.That(result.LoadedFromSample, Is.True);
            Assert.That(result.Fingerprint, Is.EqualTo(FileFingerprint.Missing));
            Assert.That(result.SourcePath, Is.EqualTo(Path.GetFullPath(samplePath)));
            Assert.That(result.Configuration.Proxies[0].Socks5ProxyEndpoint, Is.EqualTo("sample.example:1080"));
        }

        [Test]
        public void MissingConfigurationWithoutSampleReturnsSensibleBlankModel()
        {
            var result = new ConfigurationFileStore().LoadOrCreate(
                _configurationPath,
                Path.Combine(_directory, "missing-sample.json"));

            Assert.That(result.LiveFileExists, Is.False);
            Assert.That(result.LoadedFromSample, Is.False);
            Assert.That(result.SourcePath, Is.Null);
            Assert.That(result.Configuration.LogLevel, Is.EqualTo("Info"));
            Assert.That(result.Configuration.Proxies, Is.Empty);
            Assert.That(result.Configuration.Excludes, Is.Empty);
        }

        [Test]
        public void SaveDoesNotPerformFallibleFingerprintIoAfterAtomicCommit()
        {
            var originalStore = new ConfigurationFileStore();
            var original = TestModels.ValidConfiguration();
            original.Proxies[0].Socks5ProxyEndpoint = "original.example:1080";
            var initial = originalStore.SaveAtomic(_configurationPath, original);

            var fileSystem = new ThrowAfterCommitFingerprintFileSystem();
            var store = new ConfigurationFileStore(new ConfigurationSerializer(), fileSystem);
            var replacement = TestModels.ValidConfiguration();
            replacement.Proxies[0].Socks5ProxyEndpoint = "replacement.example:1080";

            var saved = store.SaveAtomic(_configurationPath, replacement, initial.Fingerprint);

            Assert.That(saved.Fingerprint, Is.Not.Null);
            Assert.That(originalStore.Load(_configurationPath).Configuration.Proxies[0].Socks5ProxyEndpoint,
                Is.EqualTo("replacement.example:1080"));
            Assert.That(fileSystem.FingerprintReadAttemptedAfterCommit, Is.False);
        }

        [Test]
        public void ExternalEditDuringTempWriteIsDetectedBeforeCommit()
        {
            var physicalStore = new ConfigurationFileStore();
            var initial = physicalStore.SaveAtomic(_configurationPath, TestModels.ValidConfiguration());
            var external = TestModels.ValidConfiguration();
            external.Proxies[0].Socks5ProxyEndpoint = "external.example:1080";
            var fileSystem = new EditLiveFileAfterTempWriteFileSystem(
                _configurationPath,
                new ConfigurationSerializer().Serialize(external));
            var store = new ConfigurationFileStore(new ConfigurationSerializer(), fileSystem);

            Assert.Throws<ConfigurationFileChangedException>(() =>
                store.SaveAtomic(_configurationPath, TestModels.ValidConfiguration(), initial.Fingerprint));

            Assert.That(physicalStore.Load(_configurationPath).Configuration.Proxies[0].Socks5ProxyEndpoint,
                Is.EqualTo("external.example:1080"));
            Assert.That(File.Exists(_configurationPath + ".tmp"), Is.False);
        }

        [Test]
        public void ConcurrentCooperatingSaveFailsFastWithoutSharingTemporaryBytes()
        {
            var initialStore = new ConfigurationFileStore();
            var initial = initialStore.SaveAtomic(_configurationPath, TestModels.ValidConfiguration());
            using (var fileSystem = new BlockingTempWriteFileSystem())
            {
                var firstStore = new ConfigurationFileStore(new ConfigurationSerializer(), fileSystem);
                var firstConfiguration = TestModels.ValidConfiguration();
                firstConfiguration.Proxies[0].Socks5ProxyEndpoint = "first-writer.example:1080";
                var firstSave = Task.Run(() =>
                    firstStore.SaveAtomic(_configurationPath, firstConfiguration, initial.Fingerprint));

                Assert.That(fileSystem.TempWriteStarted.Wait(TimeSpan.FromSeconds(5)), Is.True,
                    "The first save did not reach its temp write.");

                var secondStore = new ConfigurationFileStore();
                var secondConfiguration = TestModels.ValidConfiguration();
                secondConfiguration.Proxies[0].Socks5ProxyEndpoint = "second-writer.example:1080";
                var error = Assert.Throws<ConfigurationPersistenceException>(() =>
                    secondStore.SaveAtomic(_configurationPath, secondConfiguration, initial.Fingerprint));
                StringAssert.Contains("Another ProxiFyreUI instance", error.Message);

                fileSystem.AllowTempWrite.Set();
                Assert.That(firstSave.Wait(TimeSpan.FromSeconds(5)), Is.True,
                    "The first save did not finish after its temp write was released.");
                Assert.That(initialStore.Load(_configurationPath).Configuration.Proxies[0].Socks5ProxyEndpoint,
                    Is.EqualTo("first-writer.example:1080"));
            }
        }

        private sealed class ThrowingSerializer : IConfigurationSerializer
        {
            public string Serialize(ProxiFyreConfiguration configuration)
            {
                throw new InvalidOperationException("Deliberate test failure.");
            }

            public ProxiFyreConfiguration Deserialize(string json)
            {
                return new ConfigurationSerializer().Deserialize(json);
            }
        }

        private sealed class FailingReplaceFileSystem : IConfigurationFileSystem
        {
            private readonly PhysicalConfigurationFileSystem _inner = new PhysicalConfigurationFileSystem();

            public bool FileExists(string path) => _inner.FileExists(path);
            public byte[] ReadAllBytes(string path) => _inner.ReadAllBytes(path);
            public long GetFileLength(string path) => _inner.GetFileLength(path);
            public DateTime GetLastWriteTimeUtc(string path) => _inner.GetLastWriteTimeUtc(path);
            public void CreateDirectory(string path) => _inner.CreateDirectory(path);
            public void DeleteFile(string path) => _inner.DeleteFile(path);
            public void MoveFile(string sourcePath, string destinationPath) => _inner.MoveFile(sourcePath, destinationPath);
            public void WriteAllTextAndFlush(string path, string content) => _inner.WriteAllTextAndFlush(path, content);

            public void ReplaceFile(string sourcePath, string destinationPath, string backupPath)
            {
                throw new IOException("Deliberate replacement failure.");
            }
        }

        private sealed class ThrowAfterCommitFingerprintFileSystem : IConfigurationFileSystem
        {
            private readonly PhysicalConfigurationFileSystem _inner = new PhysicalConfigurationFileSystem();
            private bool _committed;

            public bool FingerprintReadAttemptedAfterCommit { get; private set; }
            public bool FileExists(string path) => _inner.FileExists(path);
            public byte[] ReadAllBytes(string path) => _inner.ReadAllBytes(path);
            public DateTime GetLastWriteTimeUtc(string path) => _inner.GetLastWriteTimeUtc(path);
            public void CreateDirectory(string path) => _inner.CreateDirectory(path);
            public void DeleteFile(string path) => _inner.DeleteFile(path);
            public void MoveFile(string sourcePath, string destinationPath)
            {
                _inner.MoveFile(sourcePath, destinationPath);
                _committed = true;
            }
            public void ReplaceFile(string sourcePath, string destinationPath, string backupPath)
            {
                _inner.ReplaceFile(sourcePath, destinationPath, backupPath);
                _committed = true;
            }
            public void WriteAllTextAndFlush(string path, string content) => _inner.WriteAllTextAndFlush(path, content);
            public long GetFileLength(string path)
            {
                if (_committed)
                {
                    FingerprintReadAttemptedAfterCommit = true;
                    throw new IOException("Deliberate post-commit metadata failure.");
                }
                return _inner.GetFileLength(path);
            }
        }

        private sealed class EditLiveFileAfterTempWriteFileSystem : IConfigurationFileSystem
        {
            private readonly PhysicalConfigurationFileSystem _inner = new PhysicalConfigurationFileSystem();
            private readonly string _livePath;
            private readonly string _externalJson;

            public EditLiveFileAfterTempWriteFileSystem(string livePath, string externalJson)
            {
                _livePath = livePath;
                _externalJson = externalJson;
            }

            public bool FileExists(string path) => _inner.FileExists(path);
            public byte[] ReadAllBytes(string path) => _inner.ReadAllBytes(path);
            public long GetFileLength(string path) => _inner.GetFileLength(path);
            public DateTime GetLastWriteTimeUtc(string path) => _inner.GetLastWriteTimeUtc(path);
            public void CreateDirectory(string path) => _inner.CreateDirectory(path);
            public void DeleteFile(string path) => _inner.DeleteFile(path);
            public void MoveFile(string sourcePath, string destinationPath) => _inner.MoveFile(sourcePath, destinationPath);
            public void ReplaceFile(string sourcePath, string destinationPath, string backupPath) =>
                _inner.ReplaceFile(sourcePath, destinationPath, backupPath);
            public void WriteAllTextAndFlush(string path, string content)
            {
                _inner.WriteAllTextAndFlush(path, content);
                if (path.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
                    File.WriteAllText(_livePath, _externalJson);
            }
        }

        private sealed class BlockingTempWriteFileSystem : IConfigurationFileSystem, IDisposable
        {
            private readonly PhysicalConfigurationFileSystem _inner = new PhysicalConfigurationFileSystem();

            public ManualResetEventSlim TempWriteStarted { get; } = new ManualResetEventSlim(false);
            public ManualResetEventSlim AllowTempWrite { get; } = new ManualResetEventSlim(false);
            public bool FileExists(string path) => _inner.FileExists(path);
            public byte[] ReadAllBytes(string path) => _inner.ReadAllBytes(path);
            public long GetFileLength(string path) => _inner.GetFileLength(path);
            public DateTime GetLastWriteTimeUtc(string path) => _inner.GetLastWriteTimeUtc(path);
            public void CreateDirectory(string path) => _inner.CreateDirectory(path);
            public void DeleteFile(string path) => _inner.DeleteFile(path);
            public void MoveFile(string sourcePath, string destinationPath) => _inner.MoveFile(sourcePath, destinationPath);
            public void ReplaceFile(string sourcePath, string destinationPath, string backupPath) =>
                _inner.ReplaceFile(sourcePath, destinationPath, backupPath);
            public void WriteAllTextAndFlush(string path, string content)
            {
                if (path.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
                {
                    TempWriteStarted.Set();
                    if (!AllowTempWrite.Wait(TimeSpan.FromSeconds(10)))
                        throw new TimeoutException("The test did not release the blocked temp write.");
                }
                _inner.WriteAllTextAndFlush(path, content);
            }

            public void Dispose()
            {
                AllowTempWrite.Set();
                TempWriteStarted.Dispose();
                AllowTempWrite.Dispose();
            }
        }
    }
}
