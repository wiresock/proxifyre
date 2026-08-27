using Microsoft.Win32;
using ProxiFyre.Configuration;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace ProxiFyreUI.Infrastructure
{
    public enum EngineLocationSource
    {
        None,
        ServiceRegistration,
        BesideUserInterface,
        UserSelection
    }

    public sealed class EngineLocation
    {
        public EngineLocation(string path, EngineLocationSource source, string error = null)
        {
            Path = path;
            Source = source;
            Error = error;
        }

        public string Path { get; }
        public EngineLocationSource Source { get; }
        public string Error { get; }
        public bool IsResolved => string.IsNullOrWhiteSpace(Error) &&
                                  !string.IsNullOrWhiteSpace(Path) && File.Exists(Path);
        public string ConfigurationPath => IsResolved ? ProxiFyrePaths.GetConfigurationPath(Path) : null;
        public string LogDirectoryPath => IsResolved ? ProxiFyrePaths.GetLogDirectoryPath(Path) : null;
    }

    public interface IEngineLocator
    {
        EngineLocation Resolve(UiSettings settings);
        EngineLocation ResolveProtectedUninstallFallback(UiSettings settings, string currentEnginePath);
        EngineLocation ValidateUserSelection(string path);
        EngineLocation ValidateProtectedUninstallSelection(string path);
        string GetRegisteredServiceImagePath();
        bool IsRegisteredServiceExecutable(string expectedPath);
    }

    public sealed class EngineLocator : IEngineLocator
    {
        private const string ServiceRegistryPath = @"SYSTEM\CurrentControlSet\Services\" +
                                                   ProxiFyrePaths.ServiceName;
        private readonly Func<string> _registeredServiceImagePathReader;
        private readonly Func<string, bool> _engineValidator;
        private readonly Func<string, string> _protectedLocationFailureReader;
        private readonly string _userInterfaceExecutablePath;

        public EngineLocator()
            : this(ReadRegisteredServiceImagePath, EngineExecutableValidator.IsTrusted,
                Assembly.GetExecutingAssembly().Location, GetProtectedLocationFailure)
        {
        }

        /// <summary>
        /// Test seam for the SCM registry value, elevated-engine identity check, and UI path.
        /// Production callers should use the parameterless constructor.
        /// </summary>
        public EngineLocator(Func<string> registeredServiceImagePathReader,
            Func<string, bool> engineValidator, string userInterfaceExecutablePath)
            : this(registeredServiceImagePathReader, engineValidator,
                userInterfaceExecutablePath, path => null)
        {
        }

        /// <summary>
        /// Test seam for the protected per-machine location policy used by privileged
        /// uninstall fallback execution. Production callers should use the parameterless
        /// constructor.
        /// </summary>
        internal EngineLocator(Func<string> registeredServiceImagePathReader,
            Func<string, bool> engineValidator, string userInterfaceExecutablePath,
            Func<string, string> protectedLocationFailureReader)
        {
            _registeredServiceImagePathReader = registeredServiceImagePathReader ??
                                                throw new ArgumentNullException(nameof(registeredServiceImagePathReader));
            _engineValidator = engineValidator ?? throw new ArgumentNullException(nameof(engineValidator));
            _protectedLocationFailureReader = protectedLocationFailureReader ??
                                               throw new ArgumentNullException(nameof(protectedLocationFailureReader));
            _userInterfaceExecutablePath = userInterfaceExecutablePath;
        }

        public EngineLocation Resolve(UiSettings settings)
        {
            string registered;
            try
            {
                registered = GetRegisteredServiceImagePath();
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException || ex is IOException ||
                                       ex is InvalidDataException ||
                                       ex is System.Security.SecurityException)
            {
                return new EngineLocation(null, EngineLocationSource.ServiceRegistration,
                    "The installed service registration could not be read. " + ex.Message);
            }
            if (!string.IsNullOrWhiteSpace(registered))
            {
                string executable;
                if (!ServiceImagePathParser.TryGetExecutablePath(registered, out executable))
                    return new EngineLocation(null, EngineLocationSource.ServiceRegistration,
                        "The installed service registration contains an invalid executable path.");

                executable = Environment.ExpandEnvironmentVariables(executable);
                if (_engineValidator(executable))
                    return new EngineLocation(Path.GetFullPath(executable), EngineLocationSource.ServiceRegistration);

                return new EngineLocation(executable, EngineLocationSource.ServiceRegistration,
                    "The installed service executable could not be found or does not have a valid ProxiFyre identity.");
            }

            var userInterfaceDirectory = string.IsNullOrWhiteSpace(_userInterfaceExecutablePath)
                ? null
                : Path.GetDirectoryName(Path.GetFullPath(_userInterfaceExecutablePath));
            if (!string.IsNullOrWhiteSpace(userInterfaceDirectory))
            {
                var adjacent = Path.Combine(userInterfaceDirectory, ProxiFyrePaths.EngineExecutableName);
                if (_engineValidator(adjacent))
                    return new EngineLocation(Path.GetFullPath(adjacent), EngineLocationSource.BesideUserInterface);
            }

            if (settings != null && !string.IsNullOrWhiteSpace(settings.SelectedEnginePath))
            {
                var selection = ValidateUserSelection(settings.SelectedEnginePath);
                if (selection.IsResolved)
                    return selection;
            }

            return new EngineLocation(null, EngineLocationSource.None,
                "ProxiFyre.exe was not found. Select the engine executable to continue.");
        }

        public EngineLocation ValidateUserSelection(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return new EngineLocation(null, EngineLocationSource.None, "No engine executable was selected.");

            string fullPath;
            try { fullPath = Path.GetFullPath(path); }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException)
            {
                return new EngineLocation(path, EngineLocationSource.UserSelection, "The selected path is invalid.");
            }

            if (!_engineValidator(fullPath))
                return new EngineLocation(fullPath, EngineLocationSource.UserSelection,
                    "Select an existing ProxiFyre.exe with a valid ProxiFyre engine identity.");

            return new EngineLocation(fullPath, EngineLocationSource.UserSelection);
        }

        public EngineLocation ValidateProtectedUninstallSelection(string path)
        {
            var validated = ValidateUserSelection(path);
            if (!validated.IsResolved)
                return validated;

            string locationFailure;
            try
            {
                locationFailure = _protectedLocationFailureReader(validated.Path);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException ||
                                       ex is ArgumentException || ex is NotSupportedException ||
                                       ex is System.Security.SecurityException)
            {
                locationFailure = ex.Message;
            }
            if (!string.IsNullOrWhiteSpace(locationFailure))
            {
                return new EngineLocation(validated.Path, EngineLocationSource.UserSelection,
                    "This ProxiFyre.exe cannot be used for a privileged service " +
                    "uninstall because it is not in a protected per-machine location. " +
                    locationFailure);
            }

            return validated;
        }

        /// <summary>
        /// Finds a validated executable that can host the fixed service-uninstall command when
        /// the registered executable itself is missing or invalid. This deliberately does not
        /// participate in normal engine resolution, which remains fail-closed on a broken
        /// installed-service registration.
        /// </summary>
        public EngineLocation ResolveProtectedUninstallFallback(UiSettings settings,
            string currentEnginePath)
        {
            var candidates = new[]
            {
                new { Path = currentEnginePath, Source = EngineLocationSource.UserSelection },
                new { Path = GetAdjacentEnginePath(), Source = EngineLocationSource.BesideUserInterface },
                new
                {
                    Path = settings?.SelectedEnginePath,
                    Source = EngineLocationSource.UserSelection
                }
            };
            var seen = new System.Collections.Generic.HashSet<string>(
                StringComparer.OrdinalIgnoreCase);
            foreach (var candidate in candidates)
            {
                if (string.IsNullOrWhiteSpace(candidate.Path))
                    continue;

                var validated = ValidateProtectedUninstallSelection(candidate.Path);
                if (!validated.IsResolved || !seen.Add(validated.Path))
                    continue;
                return new EngineLocation(validated.Path, candidate.Source);
            }

            return new EngineLocation(null, EngineLocationSource.None,
                "No valid ProxiFyre.exe in a protected per-machine location is available to " +
                "run the privileged service uninstall command.");
        }

        public string GetRegisteredServiceImagePath()
        {
            return _registeredServiceImagePathReader();
        }

        public bool IsRegisteredServiceExecutable(string expectedPath)
        {
            if (string.IsNullOrWhiteSpace(expectedPath))
                return false;

            string registeredExecutable;
            if (!ServiceImagePathParser.TryGetExecutablePath(
                    GetRegisteredServiceImagePath(), out registeredExecutable))
                return false;

            string expectedFullPath;
            try
            {
                expectedFullPath = Path.GetFullPath(expectedPath);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException ||
                                       ex is PathTooLongException)
            {
                return false;
            }

            return string.Equals(registeredExecutable, expectedFullPath,
                       StringComparison.OrdinalIgnoreCase) &&
                   _engineValidator(registeredExecutable);
        }

        private string GetAdjacentEnginePath()
        {
            if (string.IsNullOrWhiteSpace(_userInterfaceExecutablePath))
                return null;
            try
            {
                var directory = Path.GetDirectoryName(Path.GetFullPath(_userInterfaceExecutablePath));
                return string.IsNullOrWhiteSpace(directory)
                    ? null
                    : Path.Combine(directory, ProxiFyrePaths.EngineExecutableName);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException ||
                                       ex is PathTooLongException)
            {
                return null;
            }
        }

        private static string ReadRegisteredServiceImagePath()
        {
            using (var key = Registry.LocalMachine.OpenSubKey(ServiceRegistryPath, false))
            {
                if (key == null)
                    return null;
                return RequireValidServiceImagePathValue(key.GetValue("ImagePath", null,
                    RegistryValueOptions.DoNotExpandEnvironmentNames));
            }
        }

        private static string GetProtectedLocationFailure(string enginePath)
        {
#if DEBUG
            // Repository builds intentionally run from a developer-writable output directory.
            return null;
#else
            string reason;
            return ServiceInstallLocationPolicy.IsProtected(enginePath, out reason)
                ? null
                : reason;
#endif
        }

        internal static string RequireValidServiceImagePathValue(object value)
        {
            var imagePath = value as string;
            if (string.IsNullOrWhiteSpace(imagePath))
                throw new InvalidDataException(
                    "The installed service registration has no valid ImagePath value.");
            return imagePath;
        }

    }

    internal static class EngineExecutableValidator
    {
        internal const string EngineConfigurationSha256 =
            "FEB7B159597D51A915D659A56599AA74D8B2104056B9E77F7FD9E1992600EEB4";
        internal const string LoggingConfigurationSha256 =
            "BB92B3CF996D7DBCF1B94B34228F80478DD569E2CC84D44BDD994D08018917DC";
        private static readonly string[] DependencyFileNames =
        {
            "ProxiFyre.Configuration.dll",
            "socksify.dll",
            "Newtonsoft.Json.dll",
            "NLog.dll",
            "Topshelf.dll"
        };

        public static bool IsTrusted(string path)
        {
            string[] payloadPaths;
            try
            {
                payloadPaths = GetLifecyclePayloadPaths(path);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException ||
                                       ex is PathTooLongException)
            {
                return false;
            }

            foreach (var payloadPath in payloadPaths)
            {
                if (!IsTrustedPayloadFile(payloadPath))
                    return false;
            }
            return true;
        }

        internal static string[] GetLifecyclePayloadPaths(string enginePath)
        {
            var fullEnginePath = Path.GetFullPath(enginePath);
            var directory = Path.GetDirectoryName(fullEnginePath);
            if (string.IsNullOrWhiteSpace(directory))
                throw new ArgumentException("The engine executable must have a directory.",
                    nameof(enginePath));

            var payload = new string[DependencyFileNames.Length + 3];
            payload[0] = fullEnginePath;
            for (var index = 0; index < DependencyFileNames.Length; index++)
                payload[index + 1] = Path.Combine(directory, DependencyFileNames[index]);
            payload[payload.Length - 2] = fullEnginePath + ".config";
            payload[payload.Length - 1] = Path.Combine(directory, "NLog.config");
            return payload;
        }

        internal static bool IsTrustedPayloadFile(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return false;
            var fileName = Path.GetFileName(path);
            if (string.Equals(fileName, ProxiFyrePaths.EngineExecutableName,
                    StringComparison.OrdinalIgnoreCase))
                return IsTrustedEngineExecutable(path);
            foreach (var dependencyFileName in DependencyFileNames)
            {
                if (string.Equals(fileName, dependencyFileName,
                        StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            if (string.Equals(fileName, "ProxiFyre.exe.config",
                    StringComparison.OrdinalIgnoreCase))
            {
#if DEBUG
                return true;
#else
                return PayloadHashValidator.HasExpectedSha256(path, EngineConfigurationSha256);
#endif
            }
            if (string.Equals(fileName, "NLog.config", StringComparison.OrdinalIgnoreCase))
            {
#if DEBUG
                return true;
#else
                return PayloadHashValidator.HasExpectedSha256(path, LoggingConfigurationSha256);
#endif
            }
            return false;
        }

        private static bool IsTrustedEngineExecutable(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path) ||
                !string.Equals(Path.GetFileName(path), ProxiFyrePaths.EngineExecutableName,
                    StringComparison.OrdinalIgnoreCase))
                return false;

            try
            {
                var info = FileVersionInfo.GetVersionInfo(path);
                // A matching basename alone is not an adequate execution boundary: lifecycle
                // commands run elevated. Require the version resource emitted by the engine
                // project as a second identity check before launching install/uninstall.
                if (!string.Equals(info.OriginalFilename, ProxiFyrePaths.EngineExecutableName,
                        StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(info.ProductName, "ProxiFyre", StringComparison.Ordinal))
                    return false;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException ||
                                       ex is ArgumentException)
            {
                return false;
            }

            // ProxiFyre is distributed unsigned. Keep the elevated lifecycle boundary tied to
            // the engine's filename and version-resource identity; the complete app-local
            // payload is separately opened without write/delete sharing before execution.
            return true;
        }
    }

}
