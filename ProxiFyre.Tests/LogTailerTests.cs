using NUnit.Framework;
using ProxiFyreUI.Infrastructure;
using System;
using System.IO;
using System.Text;
using System.Threading;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class LogTailerTests
    {
        private string _temporaryDirectory;

        [SetUp]
        public void SetUp()
        {
            _temporaryDirectory = Path.Combine(Path.GetTempPath(),
                "ProxiFyre-LogTailerTests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_temporaryDirectory);
        }

        [TearDown]
        public void TearDown()
        {
            if (Directory.Exists(_temporaryDirectory))
                Directory.Delete(_temporaryDirectory, true);
        }

        [Test]
        public void FindLatestReturnsNullForMissingOrEmptyDirectories()
        {
            Assert.That(LogFileLocator.FindLatest(null), Is.Null);
            Assert.That(LogFileLocator.FindLatest(Path.Combine(_temporaryDirectory, "missing")), Is.Null);
            Assert.That(LogFileLocator.FindLatest(_temporaryDirectory), Is.Null);
        }

        [Test]
        public void FindLatestSelectsNewestSupportedLogFile()
        {
            var olderLog = CreateFile("older.log", DateTime.UtcNow.AddMinutes(-10));
            var newerTextLog = CreateFile("newer.txt", DateTime.UtcNow.AddMinutes(-5));
            CreateFile("newest.json", DateTime.UtcNow);

            Assert.That(LogFileLocator.FindLatest(_temporaryDirectory), Is.EqualTo(newerTextLog));
            Assert.That(LogFileLocator.FindLatest(_temporaryDirectory), Is.Not.EqualTo(olderLog));
        }

        [Test]
        public void ReloadReadsLatestFileWithoutStartingFollow()
        {
            using (var tailer = new LogTailer())
            using (var linesRead = new ManualResetEventSlim())
            {
                var logPath = Path.Combine(_temporaryDirectory, "manual-reload.log");
                File.WriteAllText(logPath, "line loaded while paused" + Environment.NewLine);
                LogLinesEventArgs observed = null;
                var callingThread = Thread.CurrentThread.ManagedThreadId;
                var callbackThread = callingThread;
                tailer.LinesRead += (sender, args) =>
                {
                    observed = args;
                    callbackThread = Thread.CurrentThread.ManagedThreadId;
                    linesRead.Set();
                };

                tailer.Reload(_temporaryDirectory);

                Assert.That(linesRead.Wait(TimeSpan.FromSeconds(5)), Is.True,
                    "The one-shot reload did not read the paused log file.");
                Assert.That(tailer.IsRunning, Is.False);
                Assert.That(observed, Is.Not.Null);
                Assert.That(observed.Reset, Is.True);
                Assert.That(observed.FilePath, Is.EqualTo(logPath));
                Assert.That(observed.SourceDirectoryPath, Is.EqualTo(_temporaryDirectory));
                Assert.That(observed.Generation, Is.EqualTo(tailer.Generation));
                Assert.That(observed.Lines, Is.EqualTo(new[] { "line loaded while paused" }));
                Assert.That(callbackThread, Is.Not.EqualTo(callingThread),
                    "Manual reload should not perform file I/O on its caller's UI thread.");
            }
        }

        [Test]
        public void ReloadDrainsBoundedInitialTailThroughSnapshotEndWhilePaused()
        {
            using (var tailer = new LogTailer())
            using (var linesRead = new ManualResetEventSlim())
            {
                const string newestTimestamp = "2099-12-31 23:59:59.9999";
                var newestLine = newestTimestamp + "|INFO|newest entry";
                var contents = new StringBuilder(2 * 1024 * 1024);
                for (var index = 0; index < 16000; index++)
                {
                    contents.Append("2026-08-26 12:00:00.0000|INFO|historical-entry-")
                        .Append(index.ToString("D5"))
                        .Append('|')
                        .Append('x', 80)
                        .AppendLine();
                }
                contents.AppendLine(newestLine);

                var logPath = Path.Combine(_temporaryDirectory, "large-manual-reload.log");
                File.WriteAllText(logPath, contents.ToString(), new UTF8Encoding(false));
                Assert.That(new FileInfo(logPath).Length, Is.GreaterThan(1024 * 1024),
                    "The fixture must exceed both the per-poll cap and the bounded initial tail.");

                LogLinesEventArgs observed = null;
                tailer.LinesRead += (sender, args) =>
                {
                    observed = args;
                    linesRead.Set();
                };

                tailer.Reload(_temporaryDirectory);

                Assert.That(linesRead.Wait(TimeSpan.FromSeconds(5)), Is.True,
                    "The one-shot reload did not finish reading the bounded initial tail.");
                Assert.That(tailer.IsRunning, Is.False);
                Assert.That(observed, Is.Not.Null);
                Assert.That(observed.Reset, Is.True);
                Assert.That(observed.Lines.Count, Is.GreaterThan(0));
                Assert.That(observed.Lines[observed.Lines.Count - 1], Is.EqualTo(newestLine),
                    "A paused reload must reach the snapshot EOF instead of stopping at one poll cap.");
            }
        }

        [Test]
        public void FollowResetsWhenCurrentFileIsTruncatedAndRegrowsPastPreviousOffset()
        {
            using (var tailer = new LogTailer())
            using (var initialRead = new ManualResetEventSlim())
            using (var rewrittenRead = new ManualResetEventSlim())
            {
                var logPath = Path.Combine(_temporaryDirectory, "truncate-regrow.log");
                var initialContents = "old entry one" + Environment.NewLine +
                                      "old entry two" + Environment.NewLine;
                File.WriteAllText(logPath, initialContents, new UTF8Encoding(false));

                LogLinesEventArgs initial = null;
                LogLinesEventArgs rewritten = null;
                tailer.LinesRead += (sender, args) =>
                {
                    if (!args.Reset)
                        return;
                    if (initial == null)
                    {
                        initial = args;
                        initialRead.Set();
                    }
                    else
                    {
                        rewritten = args;
                        rewrittenRead.Set();
                    }
                };

                tailer.Start(_temporaryDirectory);
                Assert.That(initialRead.Wait(TimeSpan.FromSeconds(5)), Is.True,
                    "The initial follow snapshot was not read.");

                var firstNewLine = "new prefix that starts before the stale offset";
                var rewrittenContents = firstNewLine + Environment.NewLine +
                                        new string('x', initialContents.Length * 3) +
                                        Environment.NewLine;
                Assert.That(Encoding.UTF8.GetByteCount(rewrittenContents),
                    Is.GreaterThan(Encoding.UTF8.GetByteCount(initialContents)),
                    "The rewritten file must regrow beyond the prior read offset.");

                // Deny the tailer a read handle while the file is temporarily short. Its next
                // successful poll therefore sees only the final, larger length and must use the
                // prior-position sentinel to recognize the rewrite.
                using (var stream = OpenExclusiveForRewrite(logPath))
                {
                    stream.SetLength(0);
                    var bytes = new UTF8Encoding(false).GetBytes(rewrittenContents);
                    stream.Write(bytes, 0, bytes.Length);
                    stream.Flush(true);
                }

                Assert.That(rewrittenRead.Wait(TimeSpan.FromSeconds(5)), Is.True,
                    "The truncate-and-regrow rewrite was not published as a reset snapshot.");
                Assert.That(rewritten, Is.Not.Null);
                Assert.That(rewritten.Reset, Is.True);
                Assert.That(rewritten.Lines, Does.Contain(firstNewLine),
                    "The new prefix must not be skipped by reusing the stale file offset.");
            }
        }

        private static FileStream OpenExclusiveForRewrite(string path)
        {
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (true)
            {
                try
                {
                    return new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None);
                }
                catch (IOException) when (DateTime.UtcNow < deadline)
                {
                    Thread.Sleep(10);
                }
            }
        }

        [Test]
        public void StopInvalidatesEventsFromThePreviousFollowGeneration()
        {
            using (var tailer = new LogTailer())
            using (var statusChanged = new ManualResetEventSlim())
            {
                LogStatusEventArgs observed = null;
                tailer.StatusChanged += (sender, args) =>
                {
                    observed = args;
                    statusChanged.Set();
                };

                tailer.Start(_temporaryDirectory);

                Assert.That(statusChanged.Wait(TimeSpan.FromSeconds(5)), Is.True,
                    "The follow operation did not publish its initial status.");
                Assert.That(observed, Is.Not.Null);
                Assert.That(observed.SourceDirectoryPath, Is.EqualTo(_temporaryDirectory));
                Assert.That(observed.Generation, Is.EqualTo(tailer.Generation));

                var stoppedGeneration = observed.Generation;
                tailer.Stop();

                Assert.That(tailer.Generation, Is.GreaterThan(stoppedGeneration),
                    "Stopping must invalidate callbacks already queued by the old follow operation.");
            }
        }

        [Test]
        public void DisposedTailerCannotBeRestartedOrReloaded()
        {
            var tailer = new LogTailer();
            tailer.Dispose();

            Assert.Multiple(() =>
            {
                Assert.That(tailer.IsRunning, Is.False);
                Assert.Throws<ObjectDisposedException>(() => tailer.Start(_temporaryDirectory));
                Assert.Throws<ObjectDisposedException>(() => tailer.Reload(_temporaryDirectory));
                Assert.That(tailer.IsRunning, Is.False);
            });
        }

        private string CreateFile(string name, DateTime lastWriteTimeUtc)
        {
            var path = Path.Combine(_temporaryDirectory, name);
            File.WriteAllText(path, name);
            File.SetLastWriteTimeUtc(path, lastWriteTimeUtc);
            return path;
        }
    }
}
