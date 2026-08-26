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
        EngineLocation ValidateUserSelection(string path);
        string GetRegisteredServiceImagePath();
    }

    public sealed class EngineLocator : IEngineLocator
    {
        private const string ServiceRegistryPath = @"SYSTEM\CurrentControlSet\Services\" +
                                                   ProxiFyrePaths.ServiceName;
        private readonly Func<string> _registeredServiceImagePathReader;
        private readonly Func<string, bool> _engineValidator;
        private readonly string _userInterfaceExecutablePath;

        public EngineLocator()
            : this(ReadRegisteredServiceImagePath, EngineExecutableValidator.IsTrusted,
                Assembly.GetExecutingAssembly().Location)
        {
        }

        /// <summary>
        /// Test seam for the SCM registry value, elevated-engine identity check, and UI path.
        /// Production callers should use the parameterless constructor.
        /// </summary>
        public EngineLocator(Func<string> registeredServiceImagePathReader,
            Func<string, bool> engineValidator, string userInterfaceExecutablePath)
        {
            _registeredServiceImagePathReader = registeredServiceImagePathReader ??
                                                throw new ArgumentNullException(nameof(registeredServiceImagePathReader));
            _engineValidator = engineValidator ?? throw new ArgumentNullException(nameof(engineValidator));
            _userInterfaceExecutablePath = userInterfaceExecutablePath;
        }

        public EngineLocation Resolve(UiSettings settings)
        {
            var registered = GetRegisteredServiceImagePath();
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
                    "The installed service executable could not be found or is not ProxiFyre.exe.");
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

        public string GetRegisteredServiceImagePath()
        {
            return _registeredServiceImagePathReader();
        }

        private static string ReadRegisteredServiceImagePath()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(ServiceRegistryPath, false))
                    return key?.GetValue("ImagePath") as string;
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
            catch (System.Security.SecurityException)
            {
                return null;
            }
        }

    }

    internal static class EngineExecutableValidator
    {
        public static bool IsTrusted(string path)
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

            return true;
        }
    }
}
