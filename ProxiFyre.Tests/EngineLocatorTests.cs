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
            var invalidService = CreatePlaceholder("service", ProxiFyrePaths.EngineExecutableName);
            var uiExecutable = CreatePlaceholder("portable", "ProxiFyreUI.exe");
            CreatePlaceholder("portable", ProxiFyrePaths.EngineExecutableName);
            var locator = new EngineLocator(
                () => "\"" + invalidService + "\" run",
                path => !string.Equals(path, invalidService, StringComparison.OrdinalIgnoreCase) &&
                        File.Exists(path),
                uiExecutable);

            var result = locator.Resolve(new UiSettings());

            Assert.That(result.IsResolved, Is.False);
            Assert.That(result.Source, Is.EqualTo(UiEngineLocationSource.ServiceRegistration));
            StringAssert.Contains("installed service executable", result.Error);
        }

        [Test]
        public void ServiceRegistrationAccessFailureDoesNotFallBackToAnotherEngine()
        {
            var uiExecutable = CreatePlaceholder("portable", "ProxiFyreUI.exe");
            CreatePlaceholder("portable", ProxiFyrePaths.EngineExecutableName);
            var locator = new EngineLocator(
                () => throw new UnauthorizedAccessException("registry denied"),
                path => File.Exists(path), uiExecutable);

            var result = locator.Resolve(new UiSettings());

            Assert.Multiple(() =>
            {
                Assert.That(result.IsResolved, Is.False);
                Assert.That(result.Source,
                    Is.EqualTo(UiEngineLocationSource.ServiceRegistration));
                Assert.That(result.Error, Does.Contain("could not be read"));
                Assert.Throws<UnauthorizedAccessException>(() =>
                    locator.GetRegisteredServiceImagePath());
            });
        }

        [Test]
        public void InvalidExistingServiceImagePathDoesNotFallBackToAnotherEngine()
        {
            var uiExecutable = CreatePlaceholder("portable", "ProxiFyreUI.exe");
            CreatePlaceholder("portable", ProxiFyrePaths.EngineExecutableName);
            var locator = new EngineLocator(
                () => throw new InvalidDataException("ImagePath is missing"),
                path => File.Exists(path), uiExecutable);

            var result = locator.Resolve(new UiSettings());

            Assert.Multiple(() =>
            {
                Assert.That(result.IsResolved, Is.False);
                Assert.That(result.Source,
                    Is.EqualTo(UiEngineLocationSource.ServiceRegistration));
                Assert.That(result.Error, Does.Contain("could not be read"));
            });
        }

        [TestCase(null)]
        [TestCase("")]
        [TestCase("   ")]
        [TestCase(42)]
        public void ExistingServiceRequiresAValidStringImagePath(object value)
        {
            Assert.Throws<InvalidDataException>(() =>
                EngineLocator.RequireValidServiceImagePathValue(value));
        }

        [Test]
        public void ExistingServiceAcceptsANonEmptyStringImagePath()
        {
            const string imagePath = "\"C:\\Program Files\\ProxiFyre\\ProxiFyre.exe\" install";

            Assert.That(EngineLocator.RequireValidServiceImagePathValue(imagePath),
                Is.EqualTo(imagePath));
        }

        [Test]
        public void RegisteredServiceMatchRequiresTheSameValidatedExecutable()
        {
            var registeredEngine = CreatePlaceholder("service", ProxiFyrePaths.EngineExecutableName);
            var otherEngine = CreatePlaceholder("other", ProxiFyrePaths.EngineExecutableName);
            var uiExecutable = CreatePlaceholder("ui", "ProxiFyreUI.exe");
            var accepted = new EngineLocator(() => "\"" + registeredEngine + "\" run",
                path => string.Equals(path, registeredEngine, StringComparison.OrdinalIgnoreCase),
                uiExecutable);
            var rejected = new EngineLocator(() => "\"" + registeredEngine + "\" run",
                path => false, uiExecutable);

            Assert.Multiple(() =>
            {
                Assert.That(accepted.IsRegisteredServiceExecutable(registeredEngine), Is.True);
                Assert.That(accepted.IsRegisteredServiceExecutable(otherEngine), Is.False);
                Assert.That(rejected.IsRegisteredServiceExecutable(registeredEngine), Is.False);
            });
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

        [Test]
        public void UnsignedManagedDependenciesAreAcceptedWhenPresent()
        {
            var engineDependency = CreatePlaceholder("engine", "NLog.dll");
            var uiDependency = CreatePlaceholder("ui", "ProxiFyre.Configuration.dll");

            Assert.Multiple(() =>
            {
                Assert.That(EngineExecutableValidator.IsTrustedPayloadFile(engineDependency),
                    Is.True, "unsigned engine dependencies are supported");
                Assert.That(UiStartupPayload.IsTrustedUiPayloadFile(uiDependency), Is.True,
                    "unsigned UI dependencies are supported");
                Assert.That(EngineExecutableValidator.IsTrustedPayloadFile(
                    Path.Combine(_directory, "missing", "NLog.dll")), Is.False);
            });
        }

        [Test]
        public void LifecyclePayloadIncludesEveryLoadableModuleAndPinnedConfiguration()
        {
            var enginePath = Path.Combine(_directory, ProxiFyrePaths.EngineExecutableName);

            var names = Array.ConvertAll(
                EngineExecutableValidator.GetLifecyclePayloadPaths(enginePath),
                Path.GetFileName);

            Assert.That(names, Is.EqualTo(new[]
            {
                "ProxiFyre.exe",
                "ProxiFyre.Configuration.dll",
                "socksify.dll",
                "Newtonsoft.Json.dll",
                "NLog.dll",
                "Topshelf.dll",
                "ProxiFyre.exe.config",
                "NLog.config"
            }));
        }

        [Test]
        public void UiStartupPayloadIncludesItsTransitiveJsonDependency()
        {
            var uiPath = Path.Combine(_directory, "ProxiFyreUI.Managed.dll");

            var names = Array.ConvertAll(UiStartupPayload.GetStartupPayloadPaths(uiPath),
                Path.GetFileName);

            Assert.That(names, Is.EqualTo(new[]
            {
                "ProxiFyreUI.Managed.dll",
                "ProxiFyre.Configuration.dll",
                "Newtonsoft.Json.dll",
                "ProxiFyreUI.exe.config"
            }));
        }

        [Test]
        public void PayloadHashValidationFailsAfterContentChanges()
        {
            var path = Path.Combine(_directory, "payload.config");
            File.WriteAllText(path, "payload");

            Assert.That(PayloadHashValidator.HasExpectedSha256(path,
                "239F59ED55E737C77147CF55AD0C1B030B6D7EE748A7426952F9B852D5A935E5"),
                Is.True);

            File.AppendAllText(path, " changed");

            Assert.That(PayloadHashValidator.HasExpectedSha256(path,
                "239F59ED55E737C77147CF55AD0C1B030B6D7EE748A7426952F9B852D5A935E5"),
                Is.False);
        }

        [Test]
        public void BuiltUiConfigurationMatchesTheRuntimeIntegrityPin()
        {
            var path = Path.Combine(Path.GetDirectoryName(typeof(EngineLocator).Assembly.Location),
                "ProxiFyreUI.exe.config");

            Assert.That(File.Exists(path), Is.True);
            Assert.That(UiStartupPayload.IsTrustedUiPayloadFile(path), Is.True);
        }

        [Test]
        public void UninstallFallbackPrefersCurrentValidatedEngine()
        {
            var current = CreatePlaceholder("current", ProxiFyrePaths.EngineExecutableName);
            var uiExecutable = CreatePlaceholder("portable", "ProxiFyreUI.exe");
            CreatePlaceholder("portable", ProxiFyrePaths.EngineExecutableName);
            var saved = CreatePlaceholder("saved", ProxiFyrePaths.EngineExecutableName);
            var locator = CreateLocator(() => @"C:\missing\ProxiFyre.exe", uiExecutable);

            var result = locator.ResolveProtectedUninstallFallback(
                new UiSettings { SelectedEnginePath = saved }, current);

            Assert.Multiple(() =>
            {
                Assert.That(result.IsResolved, Is.True);
                Assert.That(result.Path, Is.EqualTo(current));
                Assert.That(result.Source, Is.EqualTo(UiEngineLocationSource.UserSelection));
            });
        }

        [Test]
        public void UninstallFallbackUsesAdjacentEngineBeforeSavedSelection()
        {
            var uiExecutable = CreatePlaceholder("portable", "ProxiFyreUI.exe");
            var adjacent = CreatePlaceholder("portable", ProxiFyrePaths.EngineExecutableName);
            var saved = CreatePlaceholder("saved", ProxiFyrePaths.EngineExecutableName);
            var locator = CreateLocator(() => @"C:\missing\ProxiFyre.exe", uiExecutable);

            var result = locator.ResolveProtectedUninstallFallback(
                new UiSettings { SelectedEnginePath = saved }, @"C:\also-missing\ProxiFyre.exe");

            Assert.Multiple(() =>
            {
                Assert.That(result.IsResolved, Is.True);
                Assert.That(result.Path, Is.EqualTo(adjacent));
                Assert.That(result.Source, Is.EqualTo(UiEngineLocationSource.BesideUserInterface));
            });
        }

        [Test]
        public void UninstallFallbackUsesSavedSelectionWhenOtherCandidatesAreUnavailable()
        {
            var uiExecutable = CreatePlaceholder("ui-only", "ProxiFyreUI.exe");
            var saved = CreatePlaceholder("saved", ProxiFyrePaths.EngineExecutableName);
            var locator = CreateLocator(() => @"C:\missing\ProxiFyre.exe", uiExecutable);

            var result = locator.ResolveProtectedUninstallFallback(
                new UiSettings { SelectedEnginePath = saved }, null);

            Assert.That(result.Path, Is.EqualTo(saved));
            Assert.That(result.IsResolved, Is.True);
        }

        [Test]
        public void UninstallFallbackDoesNotMakeNormalBrokenRegistrationResolutionPermissive()
        {
            var uiExecutable = CreatePlaceholder("portable", "ProxiFyreUI.exe");
            var adjacent = CreatePlaceholder("portable", ProxiFyrePaths.EngineExecutableName);
            var locator = CreateLocator(() => @"C:\missing\ProxiFyre.exe", uiExecutable);

            var normal = locator.Resolve(new UiSettings());
            var uninstallFallback = locator.ResolveProtectedUninstallFallback(new UiSettings(), null);

            Assert.Multiple(() =>
            {
                Assert.That(normal.IsResolved, Is.False);
                Assert.That(normal.Source, Is.EqualTo(UiEngineLocationSource.ServiceRegistration));
                Assert.That(uninstallFallback.IsResolved, Is.True);
                Assert.That(uninstallFallback.Path, Is.EqualTo(adjacent));
            });
        }

        [Test]
        public void UninstallFallbackReportsWhenBrowsingIsRequired()
        {
            var uiExecutable = CreatePlaceholder("ui-only", "ProxiFyreUI.exe");
            var locator = CreateLocator(() => @"C:\missing\ProxiFyre.exe", uiExecutable);

            var result = locator.ResolveProtectedUninstallFallback(new UiSettings(), null);

            Assert.Multiple(() =>
            {
                Assert.That(result.IsResolved, Is.False);
                Assert.That(result.Source, Is.EqualTo(UiEngineLocationSource.None));
                Assert.That(result.Error, Does.Contain("valid ProxiFyre.exe"));
            });
        }

        [Test]
        public void UninstallFallbackRejectsEngineOutsideProtectedLocation()
        {
            var current = CreatePlaceholder("current", ProxiFyrePaths.EngineExecutableName);
            var uiExecutable = CreatePlaceholder("ui-only", "ProxiFyreUI.exe");
            var locator = new EngineLocator(
                () => @"C:\missing\ProxiFyre.exe",
                path => File.Exists(path) && ProxiFyrePaths.IsEngineExecutable(path),
                uiExecutable,
                path => "The directory grants standard users write access.");

            var result = locator.ResolveProtectedUninstallFallback(new UiSettings(), current);

            Assert.Multiple(() =>
            {
                Assert.That(result.IsResolved, Is.False);
                Assert.That(result.Error, Does.Contain("protected per-machine location"));
            });
        }

        [Test]
        public void ProtectedUninstallSelectionReportsLocationPolicyReason()
        {
            var engine = CreatePlaceholder("selected", ProxiFyrePaths.EngineExecutableName);
            var uiExecutable = CreatePlaceholder("ui-only", "ProxiFyreUI.exe");
            var locator = new EngineLocator(
                () => null,
                path => File.Exists(path) && ProxiFyrePaths.IsEngineExecutable(path),
                uiExecutable,
                path => "The file owner is not a trusted machine identity.");

            var result = locator.ValidateProtectedUninstallSelection(engine);

            Assert.Multiple(() =>
            {
                Assert.That(result.IsResolved, Is.False);
                Assert.That(result.Error, Does.Contain("privileged service uninstall"));
                Assert.That(result.Error, Does.Contain("file owner"));
            });
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
