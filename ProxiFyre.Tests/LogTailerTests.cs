using NUnit.Framework;
using ProxiFyreUI.Infrastructure;
using System;
using System.IO;

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

        private string CreateFile(string name, DateTime lastWriteTimeUtc)
        {
            var path = Path.Combine(_temporaryDirectory, name);
            File.WriteAllText(path, name);
            File.SetLastWriteTimeUtc(path, lastWriteTimeUtc);
            return path;
        }
    }
}
