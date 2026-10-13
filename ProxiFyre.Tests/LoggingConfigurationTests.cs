using NLog;
using NLog.Config;
using NLog.Targets;
using NUnit.Framework;
using ProxiFyreUI.Infrastructure;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class LoggingConfigurationTests
    {
        private const long FiftyMiB = 50L * 1024 * 1024;
        private string _directory;
        private string Logs => Path.Combine(_directory, "logs");
        private string ActiveLog => Path.Combine(Logs, "logfile.txt");
        private string Archives => Path.Combine(Logs, "archive");
        private static string ShippedConfiguration =>
            Path.Combine(TestContext.CurrentContext.TestDirectory, "NLog.config");

        [SetUp]
        public void SetUp()
        {
            _directory = Path.Combine(Path.GetTempPath(),
                "ProxiFyre-LoggingTests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Logs);
        }

        [TearDown]
        public void TearDown()
        {
            // Timer disposal can leave a poll briefly holding a delete-shared handle.
            for (var attempt = 0; Directory.Exists(_directory); attempt++)
            {
                try { Directory.Delete(_directory, true); }
                catch (IOException) when (attempt < 10) { Thread.Sleep(50); }
            }
        }

        [Test]
        public void ShippedConfigurationRotatesAtFiftyMiBAndRetainsThreeArchivesAcrossRestarts()
        {
            var legacyLog = Path.Combine(Logs, "logfile_2020-01-01.txt");
            File.WriteAllText(legacyLog, "legacy diagnostics");

            for (var generation = 0; generation < 4; generation++)
            {
                // Preallocate close to the real shipped limit to exercise the boundary
                // without generating millions of log messages.
                using (var stream = new FileStream(ActiveLog, FileMode.Create, FileAccess.Write))
                {
                    var marker = Encoding.UTF8.GetBytes("generation-" + generation + "\n");
                    stream.Write(marker, 0, marker.Length);
                    stream.SetLength(FiftyMiB - 256);
                }

                using (var factory = CreateFactory())
                {
                    var logger = factory.GetLogger("rotation-test");
                    logger.Info("below threshold");
                    factory.Flush();
                    Assert.That(ArchiveCount(), Is.EqualTo(Math.Min(generation, 3)),
                        "A write below 50 MiB must not rotate the active log.");

                    logger.Info(new string('x', 512));
                    factory.Flush();
                    Assert.That(ArchiveCount(), Is.EqualTo(Math.Min(generation + 1, 3)),
                        "Crossing 50 MiB must rotate and prune older archives.");
                    Assert.That(new FileInfo(ActiveLog).Length, Is.LessThan(2048));
                }
            }

            var archives = Directory.GetFiles(Archives, "*.txt");
            Assert.That(archives.Select(path => File.ReadLines(path).First()),
                Is.EquivalentTo(new[] { "generation-1", "generation-2", "generation-3" }));
            Assert.That(archives.Sum(path => new FileInfo(path).Length) +
                new FileInfo(ActiveLog).Length, Is.LessThanOrEqualTo(4 * FiftyMiB));
            Assert.That(File.ReadAllText(legacyLog), Is.EqualTo("legacy diagnostics"),
                "Retention must not delete files from the previous daily naming scheme.");
            File.SetLastWriteTimeUtc(archives[0], DateTime.UtcNow.AddDays(1));
            Assert.That(LogFileLocator.FindLatest(Logs), Is.EqualTo(ActiveLog),
                "The GUI must ignore the archive subdirectory.");
        }

        [Test]
        public void GuiFollowsActiveFileAfterNLogRenamesItAndCreatesTheSameFilename()
        {
            using (var factory = CreateFactory(1024))
            using (var tailer = new LogTailer())
            using (var initialRead = new ManualResetEventSlim())
            using (var rotatedRead = new ManualResetEventSlim())
            using (var resetRead = new ManualResetEventSlim())
            {
                LogLinesEventArgs rotated = null;
                var rotationStarted = 0;
                tailer.LinesRead += (sender, args) =>
                {
                    if (Volatile.Read(ref rotationStarted) != 0 && args.Reset)
                        resetRead.Set();
                    if (args.Lines.Any(line => line.Contains("before rotation")))
                        initialRead.Set();
                    if (args.Lines.Any(line => line.Contains("after rotation")))
                    {
                        rotated = args;
                        rotatedRead.Set();
                    }
                };

                var logger = factory.GetLogger("tail-test");
                logger.Info("before rotation");
                factory.Flush();
                tailer.Start(Logs);
                Assert.That(initialRead.Wait(TimeSpan.FromSeconds(5)), Is.True);

                Volatile.Write(ref rotationStarted, 1);
                for (var index = 0; index < 50; index++)
                    logger.Info(new string('x', 80));
                logger.Info("after rotation");
                factory.Flush();

                Assert.That(rotatedRead.Wait(TimeSpan.FromSeconds(5)), Is.True);
                Assert.That(rotated.FilePath, Is.EqualTo(ActiveLog));
                Assert.That(resetRead.Wait(TimeSpan.FromSeconds(5)), Is.True,
                    "Following must reset after rotation, even if a poll precedes the final marker.");
                Assert.That(ArchiveCount(), Is.EqualTo(3));
                tailer.Stop();
            }
        }

        [Test]
        public void ShippedLoggingConfigurationMatchesIntegrityPinAndChangesAreRejected()
        {
            Assert.That(PayloadHashValidator.HasExpectedSha256(ShippedConfiguration,
                EngineExecutableValidator.LoggingConfigurationSha256), Is.True);
            var changed = Path.Combine(_directory, "NLog.config");
            File.Copy(ShippedConfiguration, changed);
            File.AppendAllText(changed, "<!-- changed -->");
            Assert.That(PayloadHashValidator.HasExpectedSha256(changed,
                EngineExecutableValidator.LoggingConfigurationSha256), Is.False);
        }

        private LogFactory CreateFactory(long? smallerTestLimit = null)
        {
            var factory = new LogFactory { ThrowExceptions = true };
            try
            {
                var configuration = new XmlLoggingConfiguration(ShippedConfiguration, factory);
                var target = (FileTarget)configuration.FindTargetByName("file");
                target.FileName = target.FileName.ToString().Replace("${basedir}", _directory);
                if (target.ArchiveFileName != null)
                    target.ArchiveFileName = target.ArchiveFileName.ToString()
                        .Replace("${basedir}", _directory);
                if (smallerTestLimit.HasValue)
                    target.ArchiveAboveSize = smallerTestLimit.Value;
                factory.Configuration = configuration;
                return factory;
            }
            catch
            {
                factory.Dispose();
                throw;
            }
        }

        private int ArchiveCount()
        {
            return Directory.Exists(Archives) ? Directory.GetFiles(Archives, "*.txt").Length : 0;
        }
    }
}
