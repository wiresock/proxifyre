using System;
using System.Collections.Generic;
using System.Linq;

namespace ProxiFyreUI.Infrastructure
{
    /// <summary>Produces credential-safe text for user-visible error surfaces.</summary>
    public sealed class UserVisibleErrorFormatter
    {
        private readonly DiagnosticsBuilder _redactor;

        public UserVisibleErrorFormatter(DiagnosticsBuilder redactor = null)
        {
            _redactor = redactor ?? new DiagnosticsBuilder();
        }

        public string FormatServiceFailure(ServiceOperationResult result,
            IEnumerable<string> recentWarningOrErrorLines, IEnumerable<string> secrets)
        {
            if (result == null)
                throw new ArgumentNullException(nameof(result));

            var recent = (recentWarningOrErrorLines ?? Enumerable.Empty<string>()).ToArray();
            var message = result.Message ?? "The service operation failed.";
            if (!string.IsNullOrWhiteSpace(result.Details))
            {
                message += "\r\n\r\nService operation details:\r\n" + result.Details;
            }
            if (recent.Length > 0)
            {
                message += "\r\n\r\nRecent warning/error log lines:\r\n" +
                           string.Join(Environment.NewLine, recent);
            }

            return _redactor.Redact(message, secrets);
        }

        public string FormatException(string summary, Exception exception, IEnumerable<string> secrets)
        {
            var message = summary ?? string.Empty;
            if (exception != null && !string.IsNullOrWhiteSpace(exception.Message))
                message += "\r\n\r\n" + exception.Message;
            return _redactor.Redact(message, secrets);
        }
    }
}
