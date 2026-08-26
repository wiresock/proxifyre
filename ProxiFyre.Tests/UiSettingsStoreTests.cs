using NUnit.Framework;
using ProxiFyreUI.Infrastructure;
using System;
using System.IO;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class UiSettingsStoreTests
    {
        private string _directory;
        private string _path;

        [SetUp]
        public void SetUp()
        {
            _directory = Path.Combine(Path.GetTempPath(), "proxifyre-ui-settings-" +
                Guid.NewGuid().ToString("N"));
            _path = Path.Combine(_directory, "ui-settings.json");
        }

        [TearDown]
        public void TearDown()
        {
            if (Directory.Exists(_directory))
                Directory.Delete(_directory, true);
        }

        [Test]
        public void FrameworkJsonRoundTripUsesGuiOnlyPropertyNames()
        {
            var store = new UiSettingsStore(_path);
            store.Save(new UiSettings
            {
                SelectedEnginePath = @"C:\Program Files\ProxiFyre\ProxiFyre.exe",
                MinimizeToTray = false,
                FollowLogs = false
            });

            var loaded = store.Load();
            var json = File.ReadAllText(_path);

            Assert.Multiple(() =>
            {
                Assert.That(loaded.SelectedEnginePath,
                    Is.EqualTo(@"C:\Program Files\ProxiFyre\ProxiFyre.exe"));
                Assert.That(loaded.MinimizeToTray, Is.False);
                Assert.That(loaded.FollowLogs, Is.False);
                Assert.That(json, Does.Contain("\"selectedEnginePath\""));
                Assert.That(json, Does.Contain("\"minimizeToTray\""));
                Assert.That(json, Does.Contain("\"followLogs\""));
                Assert.That(json, Does.Not.Contain("password"));
            });
        }

        [Test]
        public void MalformedSettingsFailClosedToDefaults()
        {
            Directory.CreateDirectory(_directory);
            File.WriteAllText(_path, "{not valid json");

            var loaded = new UiSettingsStore(_path).Load();

            Assert.That(loaded.SelectedEnginePath, Is.Null);
            Assert.That(loaded.MinimizeToTray, Is.True);
            Assert.That(loaded.FollowLogs, Is.True);
        }
    }
}
