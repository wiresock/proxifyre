using System;
using System.IO;

namespace ProxiFyre.Configuration
{
    public static class ProxiFyrePaths
    {
        public const string ServiceName = "ProxiFyreService";
        public const string WindowsPacketFilterServiceName = "NDISRD";
        public const string EngineExecutableName = "ProxiFyre.exe";
        public const string ConfigurationFileName = "app-config.json";
        public const string SampleConfigurationFileName = "app-config.sample.json";
        public const string UiSettingsDirectoryName = "ProxiFyreUI";
        public const string UiSettingsFileName = "ui-settings.json";
        public const string LogDirectoryName = "logs";

        public static string GetConfigurationPath(string engineExecutablePath)
        {
            return Path.Combine(GetEngineDirectory(engineExecutablePath), ConfigurationFileName);
        }

        public static string GetSampleConfigurationPath(string engineExecutablePath)
        {
            return Path.Combine(GetEngineDirectory(engineExecutablePath), SampleConfigurationFileName);
        }

        public static string GetLogDirectoryPath(string engineExecutablePath)
        {
            return Path.Combine(GetEngineDirectory(engineExecutablePath), LogDirectoryName);
        }

        public static string GetUiSettingsPath(string localApplicationDataOverride = null)
        {
            var localApplicationData = string.IsNullOrWhiteSpace(localApplicationDataOverride)
                ? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
                : localApplicationDataOverride;
            if (string.IsNullOrWhiteSpace(localApplicationData))
                throw new InvalidOperationException("The LocalApplicationData folder could not be resolved.");

            return Path.Combine(Path.GetFullPath(localApplicationData), UiSettingsDirectoryName, UiSettingsFileName);
        }

        public static bool IsEngineExecutable(string path)
        {
            return !string.IsNullOrWhiteSpace(path) &&
                   string.Equals(Path.GetFileName(path), EngineExecutableName, StringComparison.OrdinalIgnoreCase);
        }

        private static string GetEngineDirectory(string engineExecutablePath)
        {
            if (string.IsNullOrWhiteSpace(engineExecutablePath))
                throw new ArgumentException("An engine executable path is required.", nameof(engineExecutablePath));

            var fullPath = Path.GetFullPath(engineExecutablePath);
            var directory = Path.GetDirectoryName(fullPath);
            if (string.IsNullOrEmpty(directory))
                throw new ArgumentException("The engine executable path must include a directory.", nameof(engineExecutablePath));
            return directory;
        }
    }

    /// <summary>
    /// Extracts only the executable portion of an SCM ImagePath and discards fixed arguments.
    /// </summary>
    public static class ServiceImagePathParser
    {
        public static string GetExecutablePath(string serviceImagePath)
        {
            string executablePath;
            if (!TryGetExecutablePath(serviceImagePath, out executablePath))
                throw new FormatException("The service image path does not contain a valid executable path.");
            return executablePath;
        }

        public static bool TryGetExecutablePath(string serviceImagePath, out string executablePath)
        {
            executablePath = null;
            if (string.IsNullOrWhiteSpace(serviceImagePath))
                return false;

            var value = Environment.ExpandEnvironmentVariables(serviceImagePath.Trim());
            string candidate;
            if (value.StartsWith("\"", StringComparison.Ordinal))
            {
                var closingQuote = value.IndexOf('"', 1);
                if (closingQuote <= 1)
                    return false;
                candidate = value.Substring(1, closingQuote - 1);
            }
            else
            {
                var executableEnd = FindExecutableEnd(value);
                if (executableEnd < 0)
                    return false;
                candidate = value.Substring(0, executableEnd);
            }

            candidate = candidate.Trim();
            if (!candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || candidate.IndexOf('"') >= 0)
                return false;

            try
            {
                executablePath = Path.GetFullPath(candidate);
                return true;
            }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException)
            {
                return false;
            }
        }

        private static int FindExecutableEnd(string value)
        {
            var searchFrom = 0;
            while (searchFrom < value.Length)
            {
                var extension = value.IndexOf(".exe", searchFrom, StringComparison.OrdinalIgnoreCase);
                if (extension < 0)
                    return -1;
                var end = extension + 4;
                if (end == value.Length || char.IsWhiteSpace(value[end]))
                    return end;
                searchFrom = end;
            }
            return -1;
        }
    }

    public enum EngineLocationSource
    {
        None,
        InstalledService,
        BesideUi,
        SavedSetting
    }

    public sealed class EnginePathResolution
    {
        internal EnginePathResolution(string enginePath, EngineLocationSource source)
        {
            EnginePath = enginePath;
            Source = source;
        }

        public string EnginePath { get; }

        public EngineLocationSource Source { get; }

        public bool Found => !string.IsNullOrEmpty(EnginePath);

        public string ConfigurationPath => Found ? ProxiFyrePaths.GetConfigurationPath(EnginePath) : null;
    }

    /// <summary>
    /// Applies the non-interactive portion of the documented engine-location precedence.
    /// </summary>
    public sealed class EnginePathResolver
    {
        private readonly Func<string, bool> _fileExists;

        public EnginePathResolver()
            : this(File.Exists)
        {
        }

        public EnginePathResolver(Func<string, bool> fileExists)
        {
            _fileExists = fileExists ?? throw new ArgumentNullException(nameof(fileExists));
        }

        public EnginePathResolution Resolve(
            string installedServiceImagePath,
            string uiExecutablePath,
            string savedEnginePath)
        {
            string serviceExecutable;
            if (ServiceImagePathParser.TryGetExecutablePath(installedServiceImagePath, out serviceExecutable) &&
                IsExistingEngine(serviceExecutable))
            {
                return new EnginePathResolution(serviceExecutable, EngineLocationSource.InstalledService);
            }

            if (!string.IsNullOrWhiteSpace(uiExecutablePath))
            {
                try
                {
                    var uiDirectory = Path.GetDirectoryName(Path.GetFullPath(uiExecutablePath));
                    if (!string.IsNullOrEmpty(uiDirectory))
                    {
                        var besideUi = Path.Combine(uiDirectory, ProxiFyrePaths.EngineExecutableName);
                        if (IsExistingEngine(besideUi))
                            return new EnginePathResolution(besideUi, EngineLocationSource.BesideUi);
                    }
                }
                catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException)
                {
                    // Continue to the saved path.
                }
            }

            if (!string.IsNullOrWhiteSpace(savedEnginePath))
            {
                try
                {
                    var fullSavedPath = Path.GetFullPath(savedEnginePath);
                    if (IsExistingEngine(fullSavedPath))
                        return new EnginePathResolution(fullSavedPath, EngineLocationSource.SavedSetting);
                }
                catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException)
                {
                    // A stale setting is treated as unresolved.
                }
            }

            return new EnginePathResolution(null, EngineLocationSource.None);
        }

        private bool IsExistingEngine(string path)
        {
            return ProxiFyrePaths.IsEngineExecutable(path) && _fileExists(path);
        }
    }
}
