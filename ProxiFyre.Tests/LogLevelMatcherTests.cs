using NUnit.Framework;
using ProxiFyre.Configuration;
using ProxiFyreUI.Infrastructure;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class LogLevelMatcherTests
    {
        [TestCase("2026-08-26 13:17:24.0896|INFO|ProxiFyre.Service|Request failed with an error", "Info", true)]
        [TestCase("2026-08-26 13:17:24.0896|INFO|ProxiFyre.Service|Request failed with an error", "Error", false)]
        [TestCase("2026-08-26 13:17:24.0896|WARN|ProxiFyre.Service|Configuration warning", "Warning", true)]
        [TestCase("2026-08-26 13:17:24.0896|ERROR|ProxiFyre.Service|Failure", "Error", true)]
        [TestCase("2026-08-26 13:17:24.0896|FATAL|ProxiFyre.Service|Failure", "Error", true)]
        public void MatchesStructuredNLogLevel(string line, string selectedLevel, bool expected)
        {
            Assert.That(LogLevelMatcher.Matches(line, selectedLevel), Is.EqualTo(expected));
        }

        [TestCase("[warning] Native message containing info", "Warning", true)]
        [TestCase("[warning] Native message containing info", "Info", false)]
        [TestCase("2026-08-26 13:17:24.0896|INFO|ProxiFyre.Service|[error] Native failure", "Error", true)]
        [TestCase("2026-08-26 13:17:24.0896|INFO|ProxiFyre.Service|[error] Native failure", "Info", false)]
        [TestCase("2026-08-27 01:00:00.0000|DEBUG|ProxiFyre.Service|[debug] Redirecting UDP", "Debug", true)]
        public void NativeLevelTokenTakesPrecedence(string line, string selectedLevel, bool expected)
        {
            Assert.That(LogLevelMatcher.Matches(line, selectedLevel), Is.EqualTo(expected));
        }

        [TestCase("[error] Failure", LogMessageLevel.Error)]
        [TestCase("  [warning] Warning", LogMessageLevel.Warning)]
        [TestCase("[info] Startup", LogMessageLevel.Info)]
        [TestCase("[debug] Flow detail", LogMessageLevel.Debug)]
        [TestCase("[all] Maximum detail", LogMessageLevel.Debug)]
        public void ParsesLeadingNativeLevel(string line, LogMessageLevel expected)
        {
            LogMessageLevel actual;
            Assert.That(LogMessageLevelParser.TryGetLeadingNativeLevel(line, out actual), Is.True);
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCase("message [debug]")]
        [TestCase("[unknown] message")]
        [TestCase("")]
        public void RejectsMissingOrUnknownLeadingNativeLevel(string line)
        {
            LogMessageLevel actual;
            Assert.That(LogMessageLevelParser.TryGetLeadingNativeLevel(line, out actual), Is.False);
        }

        [Test]
        public void AllLevelsIncludesUnstructuredLines()
        {
            Assert.That(LogLevelMatcher.Matches("legacy message without a level", "All levels"), Is.True);
        }
    }
}
