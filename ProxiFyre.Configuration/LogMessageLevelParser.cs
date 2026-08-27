using System;

namespace ProxiFyre.Configuration
{
    /// <summary>
    /// Represents the severity carried by a native netlib log message.
    /// </summary>
    public enum LogMessageLevel
    {
        Error,
        Warning,
        Info,
        Debug
    }

    /// <summary>
    /// Parses the leading severity token emitted by the native logging pipeline.
    /// </summary>
    public static class LogMessageLevelParser
    {
        public static bool TryGetLeadingNativeLevel(string value, out LogMessageLevel level)
        {
            level = LogMessageLevel.Info;
            if (string.IsNullOrWhiteSpace(value))
                return false;

            var trimmed = value.TrimStart();
            if (trimmed.Length < 3 || trimmed[0] != '[')
                return false;

            var close = trimmed.IndexOf(']');
            if (close <= 1)
                return false;

            var token = trimmed.Substring(1, close - 1);
            if (string.Equals(token, "error", StringComparison.OrdinalIgnoreCase))
            {
                level = LogMessageLevel.Error;
                return true;
            }
            if (string.Equals(token, "warning", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(token, "warn", StringComparison.OrdinalIgnoreCase))
            {
                level = LogMessageLevel.Warning;
                return true;
            }
            if (string.Equals(token, "info", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(token, "information", StringComparison.OrdinalIgnoreCase))
            {
                level = LogMessageLevel.Info;
                return true;
            }
            if (string.Equals(token, "debug", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(token, "trace", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(token, "all", StringComparison.OrdinalIgnoreCase))
            {
                level = LogMessageLevel.Debug;
                return true;
            }

            return false;
        }
    }
}
