using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace ProxiFyre.Configuration
{
    public enum ValidationSeverity
    {
        Warning,
        Error
    }

    public sealed class ValidationIssue
    {
        public ValidationIssue(
            ValidationSeverity severity,
            string code,
            string message,
            string path,
            int? proxyRuleIndex = null)
        {
            if (string.IsNullOrWhiteSpace(code))
                throw new ArgumentException("A validation code is required.", nameof(code));
            if (string.IsNullOrWhiteSpace(message))
                throw new ArgumentException("A validation message is required.", nameof(message));

            Severity = severity;
            Code = code;
            Message = message;
            Path = path;
            ProxyRuleIndex = proxyRuleIndex;
        }

        public ValidationSeverity Severity { get; }

        public string Code { get; }

        public string Message { get; }

        public string Path { get; }

        public int? ProxyRuleIndex { get; }

        public override string ToString()
        {
            return string.IsNullOrEmpty(Path)
                ? Message
                : Path + ": " + Message;
        }
    }

    public sealed class ValidationResult
    {
        private readonly ReadOnlyCollection<ValidationIssue> _issues;

        public ValidationResult(IEnumerable<ValidationIssue> issues)
        {
            _issues = new ReadOnlyCollection<ValidationIssue>((issues ?? Enumerable.Empty<ValidationIssue>()).ToList());
        }

        public IReadOnlyList<ValidationIssue> Issues => _issues;

        public bool IsValid => !_issues.Any(issue => issue.Severity == ValidationSeverity.Error);

        public bool HasErrors => !IsValid;

        public bool HasWarnings => _issues.Any(issue => issue.Severity == ValidationSeverity.Warning);

        public IEnumerable<ValidationIssue> Errors => _issues.Where(issue => issue.Severity == ValidationSeverity.Error);

        public IEnumerable<ValidationIssue> Warnings => _issues.Where(issue => issue.Severity == ValidationSeverity.Warning);
    }
}
