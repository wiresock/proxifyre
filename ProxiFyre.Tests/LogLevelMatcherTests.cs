using NUnit.Framework;
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
        public void NativeLevelTokenOverridesOuterNLogInfo(string line, string selectedLevel, bool expected)
        {
            Assert.That(LogLevelMatcher.Matches(line, selectedLevel), Is.EqualTo(expected));
        }

        [Test]
        public void AllLevelsIncludesUnstructuredLines()
        {
            Assert.That(LogLevelMatcher.Matches("legacy message without a level", "All levels"), Is.True);
        }
    }
}
