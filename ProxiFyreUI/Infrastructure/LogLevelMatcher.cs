using System;
using ProxiFyre.Configuration;

namespace ProxiFyreUI.Infrastructure
{
    /// <summary>
    /// Matches the level selector against the structured level emitted by NLog. The leading
    /// native severity token takes precedence so legacy logs that wrapped every native entry
    /// as INFO remain filterable alongside severity-preserving records.
    /// </summary>
    public static class LogLevelMatcher
    {
        public static bool Matches(string line, string selectedLevel)
        {
            if (string.Equals(selectedLevel, "All levels", StringComparison.OrdinalIgnoreCase))
                return true;
            if (string.IsNullOrWhiteSpace(line) || string.IsNullOrWhiteSpace(selectedLevel))
                return false;

            string actualLevel;
            return TryGetLevel(line, out actualLevel) &&
                   string.Equals(actualLevel, NormalizeLevel(selectedLevel),
                       StringComparison.OrdinalIgnoreCase);
        }

        public static bool TryGetLevel(string line, out string level)
        {
            level = null;
            if (string.IsNullOrWhiteSpace(line))
                return false;

            var firstSeparator = line.IndexOf('|');
            if (firstSeparator < 0)
                return TryGetLeadingNativeLevel(line, out level);

            var secondSeparator = line.IndexOf('|', firstSeparator + 1);
            if (secondSeparator < 0)
                return false;

            var thirdSeparator = line.IndexOf('|', secondSeparator + 1);
            if (thirdSeparator >= 0)
            {
                var message = line.Substring(thirdSeparator + 1).TrimStart();
                if (TryGetLeadingNativeLevel(message, out level))
                    return true;
            }

            var nlogLevel = line.Substring(firstSeparator + 1,
                secondSeparator - firstSeparator - 1).Trim();
            level = NormalizeLevel(nlogLevel);
            return level != null;
        }

        private static bool TryGetLeadingNativeLevel(string value, out string level)
        {
            level = null;
            LogMessageLevel nativeLevel;
            if (!LogMessageLevelParser.TryGetLeadingNativeLevel(value, out nativeLevel))
                return false;
            level = nativeLevel.ToString();
            return true;
        }

        private static string NormalizeLevel(string level)
        {
            if (string.IsNullOrWhiteSpace(level))
                return null;

            switch (level.Trim().ToUpperInvariant())
            {
                case "FATAL":
                case "ERROR":
                    return "Error";
                case "WARN":
                case "WARNING":
                    return "Warning";
                case "INFO":
                case "INFORMATION":
                    return "Info";
                case "TRACE":
                case "DEBUG":
                    return "Debug";
                default:
                    return null;
            }
        }
    }
}
