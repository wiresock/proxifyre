using NUnit.Framework;
using ProxiFyre.Configuration;
using ProxiFyreUI.Infrastructure;
using System;
using System.IO;
using UiEngineLocationSource = ProxiFyreUI.Infrastructure.EngineLocationSource;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class EngineLocatorTests
    {
        private string _directory;

        [SetUp]
        public void SetUp()
        {
            _directory = Path.Combine(Path.GetTempPath(), "proxifyre-engine-locator-" +
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_directory);
        }

        [TearDown]
        public void TearDown()
        {
            if (Directory.Exists(_directory))
                Directory.Delete(_directory, true);
        }

        [Test]
        public void ProductionLocatorPrefersInstalledServiceAndDiscardsFixedArguments()
        {
            var serviceEngine = CreatePlaceholder("service", ProxiFyrePaths.EngineExecutableName);
            var uiExecutable = CreatePlaceholder("ui", "ProxiFyreUI.exe");
            CreatePlaceholder("ui", ProxiFyrePaths.EngineExecutableName);
            var savedEngine = CreatePlaceholder("saved", ProxiFyrePaths.EngineExecutableName);
            var locator = CreateLocator(
                () => "\"" + serviceEngine + "\" install", uiExecutable);

            var result = locator.Resolve(new UiSettings { SelectedEnginePath = savedEngine });

            Assert.That(result.IsResolved, Is.True);
            Assert.That(result.Source, Is.EqualTo(UiEngineLocationSource.ServiceRegistration));
            Assert.That(result.Path, Is.EqualTo(serviceEngine));
        }

        [Test]
        public void ProductionLocatorUsesEngineBesideUiBeforeSavedSelection()
        {
            var uiExecutable = CreatePlaceholder("portable", "ProxiFyreUI.exe");
            var besideUi = CreatePlaceholder("portable", ProxiFyrePaths.EngineExecutableName);
            var savedEngine = CreatePlaceholder("saved", ProxiFyrePaths.EngineExecutableName);
            var locator = CreateLocator(() => null, uiExecutable);

            var result = locator.Resolve(new UiSettings { SelectedEnginePath = savedEngine });

            Assert.That(result.Source, Is.EqualTo(UiEngineLocationSource.BesideUserInterface));
            Assert.That(result.Path, Is.EqualTo(besideUi));
        }

        [Test]
        public void ProductionLocatorSupportsGuiInstalledSeparatelyFromSavedEngine()
        {
            var uiExecutable = CreatePlaceholder("ui-only", "ProxiFyreUI.exe");
            var savedEngine = CreatePlaceholder("separate-engine", ProxiFyrePaths.EngineExecutableName);
            var locator = CreateLocator(() => null, uiExecutable);

            var result = locator.Resolve(new UiSettings { SelectedEnginePath = savedEngine });

            Assert.That(result.IsResolved, Is.True);
            Assert.That(result.Source, Is.EqualTo(UiEngineLocationSource.UserSelection));
            Assert.That(result.Path, Is.EqualTo(savedEngine));
        }

        [Test]
        public void InvalidInstalledServiceIsReportedWithoutFallingBackToAnotherEngine()
        {
            var untrustedService = CreatePlaceholder("service", ProxiFyrePaths.EngineExecutableName);
            var uiExecutable = CreatePlaceholder("portable", "ProxiFyreUI.exe");
            CreatePlaceholder("portable", ProxiFyrePaths.EngineExecutableName);
            var locator = new EngineLocator(
                () => "\"" + untrustedService + "\" run",
                path => !string.Equals(path, untrustedService, StringComparison.OrdinalIgnoreCase) &&
                        File.Exists(path),
                uiExecutable);

            var result = locator.Resolve(new UiSettings());

            Assert.That(result.IsResolved, Is.False);
            Assert.That(result.Source, Is.EqualTo(UiEngineLocationSource.ServiceRegistration));
            StringAssert.Contains("installed service executable", result.Error);
        }

        [Test]
        public void RealIdentityCheckRejectsArbitraryExeRenamedToProxiFyre()
        {
            var renamedUi = Path.Combine(_directory, ProxiFyrePaths.EngineExecutableName);
            File.Copy(typeof(EngineLocator).Assembly.Location, renamedUi);

            var result = new EngineLocator().ValidateUserSelection(renamedUi);

            Assert.That(File.Exists(renamedUi), Is.True);
            Assert.That(result.IsResolved, Is.False,
                "A matching filename must not bypass the version-resource identity check.");
            Assert.That(result.Error, Is.Not.Null.And.Not.Empty);
        }

        private EngineLocator CreateLocator(Func<string> servicePathReader, string uiExecutable)
        {
            return new EngineLocator(
                servicePathReader,
                path => File.Exists(path) && ProxiFyrePaths.IsEngineExecutable(path),
                uiExecutable);
        }

        private string CreatePlaceholder(string subdirectory, string fileName)
        {
            var directory = Path.Combine(_directory, subdirectory);
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, fileName);
            File.WriteAllText(path, "test placeholder");
            return path;
        }
    }
}
