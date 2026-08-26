using NUnit.Framework;
using ProxiFyre.Configuration;
using System;
using System.Collections.Generic;
using System.IO;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class PathUtilitiesTests
    {
        [Test]
        public void QuotedServiceImagePathExtractsOnlyExecutable()
        {
            var result = ServiceImagePathParser.GetExecutablePath(
                @"""C:\Program Files\ProxiFyre\ProxiFyre.exe"" --service --fixed");

            Assert.That(result, Is.EqualTo(@"C:\Program Files\ProxiFyre\ProxiFyre.exe"));
        }

        [Test]
        public void UnquotedEnginePathWithSpacesIsRejectedAsAmbiguous()
        {
            string result;

            Assert.That(ServiceImagePathParser.TryGetExecutablePath(
                @"C:\Program Files\ProxiFyre\ProxiFyre.exe run-as-service", out result), Is.False);
            Assert.That(result, Is.Null);
        }

        [Test]
        public void UnquotedEnginePathWithoutSpacesCanIncludeFixedArguments()
        {
            var result = ServiceImagePathParser.GetExecutablePath(
                @"C:\ProxiFyre\ProxiFyre.exe run-as-service");

            Assert.That(result, Is.EqualTo(@"C:\ProxiFyre\ProxiFyre.exe"));
        }

        [TestCase("ProxiFyre.exe")]
        [TestCase(@".\ProxiFyre.exe")]
        [TestCase(@"C:ProxiFyre.exe")]
        [TestCase(@"\Program Files\ProxiFyre\ProxiFyre.exe")]
        public void RelativeServiceImagePathsAreRejected(string value)
        {
            string result;

            Assert.That(ServiceImagePathParser.TryGetExecutablePath(value, out result), Is.False);
            Assert.That(result, Is.Null);
        }

        [TestCase("")]
        [TestCase(@"""C:\Program Files\ProxiFyre\ProxiFyre.exe --broken")]
        [TestCase(@"""C:\Program Files\ProxiFyre\ProxiFyre.exe""unexpected")]
        [TestCase(@"C:\Program Files\ProxiFyre\not-an-executable.dll --service")]
        public void InvalidServiceImagePathIsRejected(string value)
        {
            string result;
            Assert.That(ServiceImagePathParser.TryGetExecutablePath(value, out result), Is.False);
            Assert.That(result, Is.Null);
        }

        [Test]
        public void InstalledServicePathTakesPrecedence()
        {
            var servicePath = @"C:\Service Engine\ProxiFyre.exe";
            var besideUi = @"D:\Gui\ProxiFyre.exe";
            var saved = @"E:\Saved\ProxiFyre.exe";
            var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                servicePath,
                besideUi,
                saved
            };
            var resolver = new EnginePathResolver(existing.Contains);

            var result = resolver.Resolve(
                @"""C:\Service Engine\ProxiFyre.exe"" --service",
                @"D:\Gui\ProxiFyreUI.exe",
                saved);

            Assert.That(result.Found, Is.True);
            Assert.That(result.Source, Is.EqualTo(EngineLocationSource.InstalledService));
            Assert.That(result.EnginePath, Is.EqualTo(servicePath));
        }

        [Test]
        public void EngineBesideUiIsUsedWhenNoInstalledServiceExists()
        {
            var besideUi = @"D:\Portable ProxiFyre\ProxiFyre.exe";
            var resolver = new EnginePathResolver(
                path => string.Equals(path, besideUi, StringComparison.OrdinalIgnoreCase));

            var result = resolver.Resolve(null, @"D:\Portable ProxiFyre\ProxiFyreUI.exe", null);

            Assert.That(result.Source, Is.EqualTo(EngineLocationSource.BesideUi));
            Assert.That(result.EnginePath, Is.EqualTo(besideUi));
            Assert.That(result.ConfigurationPath, Is.EqualTo(@"D:\Portable ProxiFyre\app-config.json"));
        }

        [Test]
        public void SavedEngineCanBeLocatedWhenGuiIsInstalledSeparately()
        {
            var saved = @"E:\Engines\ProxiFyre\ProxiFyre.exe";
            var resolver = new EnginePathResolver(
                path => string.Equals(path, saved, StringComparison.OrdinalIgnoreCase));

            var result = resolver.Resolve(null, @"C:\Tools\ProxiFyreUI.exe", saved);

            Assert.That(result.Source, Is.EqualTo(EngineLocationSource.SavedSetting));
            Assert.That(result.EnginePath, Is.EqualTo(saved));
        }

        [Test]
        public void MissingEngineExecutableProducesUnresolvedResult()
        {
            var resolver = new EnginePathResolver(path => false);

            var result = resolver.Resolve(
                @"""C:\Missing\ProxiFyre.exe"" --service",
                @"D:\Missing Gui\ProxiFyreUI.exe",
                @"E:\Also Missing\ProxiFyre.exe");

            Assert.That(result.Found, Is.False);
            Assert.That(result.Source, Is.EqualTo(EngineLocationSource.None));
            Assert.That(result.EnginePath, Is.Null);
            Assert.That(result.ConfigurationPath, Is.Null);
        }

        [Test]
        public void LocalAppDataSettingsRemainSeparateFromEngineConfiguration()
        {
            var settings = ProxiFyrePaths.GetUiSettingsPath(@"C:\Users\Test\AppData\Local");
            var configuration = ProxiFyrePaths.GetConfigurationPath(@"D:\Engine Folder\ProxiFyre.exe");

            Assert.That(settings, Is.EqualTo(@"C:\Users\Test\AppData\Local\ProxiFyreUI\ui-settings.json"));
            Assert.That(configuration, Is.EqualTo(@"D:\Engine Folder\app-config.json"));
            Assert.That(settings, Is.Not.EqualTo(configuration));
        }

        [Test]
        public void EngineValidationRequiresExpectedExecutableName()
        {
            Assert.That(ProxiFyrePaths.IsEngineExecutable(@"C:\Engine\ProxiFyre.exe"), Is.True);
            Assert.That(ProxiFyrePaths.IsEngineExecutable(@"C:\Engine\Other.exe"), Is.False);
        }
    }
}
