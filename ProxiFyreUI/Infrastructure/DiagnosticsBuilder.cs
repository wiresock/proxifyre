using ProxiFyre.Configuration;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace ProxiFyreUI.Infrastructure
{
    public sealed class DiagnosticsContext
    {
        public string EnginePath { get; set; }
        public string ConfigurationPath { get; set; }
        public string LogDirectoryPath { get; set; }
        public ServiceStatusInfo ServiceStatus { get; set; }
        public ValidationResult Validation { get; set; }
        public IEnumerable<string> RecentMessages { get; set; }
        public IEnumerable<string> Secrets { get; set; }
    }

    public sealed class DiagnosticsBuilder
    {
        private static readonly Regex NamedSecretKey = new Regex(
            @"\b(?:password|passwd|pwd|secret|token|api[_-]?token|access[_-]?token|auth[_-]?token|client[_-]?secret)\b",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex UriCredentials = new Regex(
            "(?<=://)[^/@\\s:]+:[^/@\\s]+@",
            RegexOptions.CultureInvariant);

        public string Build(DiagnosticsContext context)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            var secrets = (context.Secrets ?? Enumerable.Empty<string>())
                .Where(value => !string.IsNullOrEmpty(value))
                .Distinct(StringComparer.Ordinal)
                .OrderByDescending(value => value.Length)
                .ToArray();

            var assembly = Assembly.GetExecutingAssembly();
            var builder = new StringBuilder();
            builder.AppendLine("ProxiFyre diagnostics");
            builder.AppendLine("Generated (UTC): " + DateTime.UtcNow.ToString("O"));
            builder.AppendLine("GUI version: " + GetVersion(assembly.Location));
            builder.AppendLine("Engine version: " + GetVersion(context.EnginePath));
            builder.AppendLine("OS: " + Environment.OSVersion.VersionString);
            builder.AppendLine("OS architecture: " + GetOperatingSystemArchitecture());
            builder.AppendLine("GUI process architecture: " + GetProcessArchitecture());
            builder.AppendLine("Service name: " + ProxiFyrePaths.ServiceName);
            builder.AppendLine("Service state: " + (context.ServiceStatus?.ToString() ?? "Unknown"));
            if (!string.IsNullOrWhiteSpace(context.ServiceStatus?.Error))
                builder.AppendLine("Service error: " + Redact(context.ServiceStatus.Error, secrets));
            builder.AppendLine("Engine path: " + (context.EnginePath ?? "Not resolved"));
            builder.AppendLine("Configuration path: " + (context.ConfigurationPath ?? "Not resolved"));
            builder.AppendLine("Log directory: " + (context.LogDirectoryPath ?? "Not resolved"));

            if (context.Validation == null)
            {
                builder.AppendLine("Configuration validation: Not run");
            }
            else
            {
                builder.AppendLine("Configuration validation: " +
                    (context.Validation.HasErrors ? "Invalid" : "Valid") +
                    $" ({context.Validation.Errors.Count()} error(s), {context.Validation.Warnings.Count()} warning(s))");
                foreach (var issue in context.Validation.Issues)
                    builder.AppendLine($"  {issue.Severity} [{issue.Code}] " + Redact(issue.Message, secrets));
            }

            var messages = (context.RecentMessages ?? Enumerable.Empty<string>())
                .Where(IsWarningOrError)
                .TakeLastCompatible(20)
                .ToArray();
            if (messages.Length > 0)
            {
                builder.AppendLine("Recent warnings/errors (redacted):");
                foreach (var message in messages)
                    builder.AppendLine("  " + Redact(message, secrets));
            }

            return builder.ToString();
        }

        public string Redact(string value, IEnumerable<string> secrets)
        {
            if (string.IsNullOrEmpty(value))
                return value ?? string.Empty;

            var redacted = RedactNamedSecrets(value);
            redacted = UriCredentials.Replace(redacted, "<redacted>@");
            foreach (var secret in GetSecretVariants(secrets))
                redacted = redacted.Replace(secret, "<redacted>");
            return redacted;
        }

        private static string RedactNamedSecrets(string value)
        {
            var spans = new List<RedactionSpan>();
            var protectedUntil = -1;

            foreach (Match match in NamedSecretKey.Matches(value))
            {
                if (match.Index < protectedUntil)
                    continue;

                var cursor = match.Index + match.Length;
                cursor = SkipClosingKeyQuote(value, cursor);
                cursor = SkipWhiteSpace(value, cursor);
                if (cursor >= value.Length || (value[cursor] != ':' && value[cursor] != '='))
                    continue;

                cursor = SkipWhiteSpace(value, cursor + 1);
                if (cursor >= value.Length)
                    continue;

                var delimiter = ReadQuoteDelimiter(value, cursor);
                if (delimiter != null)
                {
                    var contentStart = cursor + delimiter.Length;
                    var closingStart = FindClosingQuote(value, contentStart, delimiter);
                    if (closingStart < 0)
                    {
                        // Diagnostics can contain a line truncated in the middle of a JSON value.
                        // Once a secret assignment is recognized, fail closed instead of exposing
                        // the unterminated value.
                        spans.Add(new RedactionSpan(contentStart, value.Length - contentStart));
                        protectedUntil = value.Length;
                        continue;
                    }

                    spans.Add(new RedactionSpan(contentStart, closingStart - contentStart));
                    protectedUntil = closingStart + delimiter.Length;
                    continue;
                }

                var contentEnd = cursor;
                while (contentEnd < value.Length && !IsUnquotedValueTerminator(value[contentEnd]))
                    contentEnd++;

                if (contentEnd == cursor)
                    continue;

                spans.Add(new RedactionSpan(cursor, contentEnd - cursor));
                protectedUntil = contentEnd;
            }

            if (spans.Count == 0)
                return value;

            var builder = new StringBuilder(value);
            for (var index = spans.Count - 1; index >= 0; index--)
            {
                var span = spans[index];
                builder.Remove(span.Start, span.Length);
                builder.Insert(span.Start, "<redacted>");
            }
            return builder.ToString();
        }

        private static int SkipClosingKeyQuote(string value, int index)
        {
            if (index >= value.Length)
                return index;

            if (value[index] == '"' || value[index] == '\'')
                return index + 1;

            var cursor = index;
            while (cursor < value.Length && value[cursor] == '\\')
                cursor++;
            if (cursor > index && cursor < value.Length &&
                (value[cursor] == '"' || value[cursor] == '\''))
                return cursor + 1;

            return index;
        }

        private static int SkipWhiteSpace(string value, int index)
        {
            while (index < value.Length && char.IsWhiteSpace(value[index]))
                index++;
            return index;
        }

        private static QuoteDelimiter ReadQuoteDelimiter(string value, int index)
        {
            if (value[index] == '"' || value[index] == '\'')
                return new QuoteDelimiter(value[index], 0);

            var cursor = index;
            while (cursor < value.Length && value[cursor] == '\\')
                cursor++;
            if (cursor > index && cursor < value.Length &&
                (value[cursor] == '"' || value[cursor] == '\''))
                return new QuoteDelimiter(value[cursor], cursor - index);

            return null;
        }

        private static int FindClosingQuote(string value, int contentStart, QuoteDelimiter delimiter)
        {
            for (var index = contentStart; index < value.Length; index++)
            {
                if (value[index] != delimiter.Quote)
                    continue;

                var slashCount = 0;
                for (var slash = index - 1; slash >= contentStart && value[slash] == '\\'; slash--)
                    slashCount++;

                // At JSON nesting level N, a structural quote has (2^N - 1)
                // backslashes before it. Backslashes at the end of the value add
                // multiples of 2^(N + 1), while a quote inside the value does not.
                var structuralPeriod = (delimiter.BackslashCount + 1) * 2;
                if (slashCount % structuralPeriod == delimiter.BackslashCount)
                    return index - slashCount;
            }
            return -1;
        }

        private static bool IsUnquotedValueTerminator(char value)
        {
            return char.IsWhiteSpace(value) || value == ',' || value == ';' || value == '&' ||
                   value == '}' || value == ']' || value == ')';
        }

        private static IEnumerable<string> GetSecretVariants(IEnumerable<string> secrets)
        {
            var variants = new HashSet<string>(StringComparer.Ordinal);
            foreach (var secret in secrets ?? Enumerable.Empty<string>())
            {
                if (string.IsNullOrEmpty(secret))
                    continue;

                AddJsonEscapeVariants(variants, secret, false);
                AddJsonEscapeVariants(variants, secret, true);
                AddJsonEscapeVariants(variants, secret, true, true);

                try
                {
                    var uriEscaped = Uri.EscapeDataString(secret);
                    variants.Add(uriEscaped);
                    variants.Add(uriEscaped.Replace("%20", "+"));
                    variants.Add(LowercasePercentEscapes(uriEscaped));
                }
                catch (UriFormatException)
                {
                    // The raw and JSON-escaped forms are still redacted for unusually long values.
                }
            }

            return variants
                .Where(value => !string.IsNullOrEmpty(value))
                .OrderByDescending(value => value.Length)
                .ThenBy(value => value, StringComparer.Ordinal);
        }

        private static void AddJsonEscapeVariants(HashSet<string> variants, string secret,
            bool escapeNonAscii, bool uppercaseHex = false)
        {
            variants.Add(secret);
            var escaped = EscapeJsonStringContent(secret, escapeNonAscii, uppercaseHex);
            variants.Add(escaped);
            variants.Add(EscapeJsonStringContent(escaped, escapeNonAscii, uppercaseHex));
        }

        private static string EscapeJsonStringContent(string value, bool escapeNonAscii, bool uppercaseHex)
        {
            var builder = new StringBuilder(value.Length);
            foreach (var character in value)
            {
                switch (character)
                {
                    case '"': builder.Append("\\\""); break;
                    case '\\': builder.Append("\\\\"); break;
                    case '\b': builder.Append("\\b"); break;
                    case '\f': builder.Append("\\f"); break;
                    case '\n': builder.Append("\\n"); break;
                    case '\r': builder.Append("\\r"); break;
                    case '\t': builder.Append("\\t"); break;
                    default:
                        if (character < ' ' || (escapeNonAscii && character > 0x7f))
                        {
                            builder.Append("\\u");
                            builder.Append(((int)character).ToString(uppercaseHex ? "X4" : "x4"));
                        }
                        else
                        {
                            builder.Append(character);
                        }
                        break;
                }
            }
            return builder.ToString();
        }

        private static string LowercasePercentEscapes(string value)
        {
            var characters = value.ToCharArray();
            for (var index = 0; index + 2 < characters.Length; index++)
            {
                if (characters[index] != '%')
                    continue;
                characters[index + 1] = char.ToLowerInvariant(characters[index + 1]);
                characters[index + 2] = char.ToLowerInvariant(characters[index + 2]);
                index += 2;
            }
            return new string(characters);
        }

        private sealed class QuoteDelimiter
        {
            public QuoteDelimiter(char quote, int backslashCount)
            {
                Quote = quote;
                BackslashCount = backslashCount;
            }

            public char Quote { get; }
            public int BackslashCount { get; }
            public int Length => BackslashCount + 1;
        }

        private struct RedactionSpan
        {
            public RedactionSpan(int start, int length)
            {
                Start = start;
                Length = length;
            }

            public int Start { get; }
            public int Length { get; }
        }

        private static bool IsWarningOrError(string line)
        {
            return !string.IsNullOrWhiteSpace(line) &&
                   (line.IndexOf("warn", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    line.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    line.IndexOf("fail", StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static string GetVersion(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return "Not available";
            try
            {
                var version = FileVersionInfo.GetVersionInfo(path).FileVersion;
                return string.IsNullOrWhiteSpace(version) ? "Not available" : version;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return "Not available";
            }
        }

        private static string GetOperatingSystemArchitecture()
        {
            var value = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITEW6432") ??
                        Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            return string.IsNullOrWhiteSpace(value)
                ? (Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit")
                : value;
        }

        private static string GetProcessArchitecture()
        {
            if (!Environment.Is64BitProcess)
                return "x86";
            var architecture = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            return string.Equals(architecture, "ARM64", StringComparison.OrdinalIgnoreCase) ? "ARM64" : "x64";
        }
    }

    internal static class EnumerableCompatibilityExtensions
    {
        public static IEnumerable<T> TakeLastCompatible<T>(this IEnumerable<T> source, int count)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            if (count <= 0)
                return Enumerable.Empty<T>();

            var queue = new Queue<T>(count);
            foreach (var item in source)
            {
                if (queue.Count == count)
                    queue.Dequeue();
                queue.Enqueue(item);
            }
            return queue;
        }
    }
}
