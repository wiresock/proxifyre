using NUnit.Framework;
using ProxiFyre.Configuration;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class EngineCommandLinePolicyTests
    {
        [Test]
        public void StandardUserRequiresExplicitOptInForInteractiveRun()
        {
            var decision = EngineCommandLinePolicy.Evaluate(new string[0], true, false);

            Assert.Multiple(() =>
            {
                Assert.That(decision.CanRun, Is.False);
                Assert.That(decision.UseLimitedMode, Is.False);
                Assert.That(decision.Denial,
                    Is.EqualTo(EngineCommandLineDenial.AdministratorPrivilegesRequired));
            });
        }

        [Test]
        public void ExactOptInEnablesLimitedInteractiveRunForStandardUser()
        {
            var decision = EngineCommandLinePolicy.Evaluate(
                new[] { "--allow-not-admin" }, true, false);

            Assert.Multiple(() =>
            {
                Assert.That(decision.CanRun, Is.True);
                Assert.That(decision.AllowNotAdministratorRequested, Is.True);
                Assert.That(decision.UseLimitedMode, Is.True);
                Assert.That(decision.IsLifecycleCommand, Is.False);
                Assert.That(decision.RequiresProtectedServiceLocation, Is.False);
            });
        }

        [Test]
        public void ExplicitRunCommandCanUseLimitedInteractiveMode()
        {
            var decision = EngineCommandLinePolicy.Evaluate(
                new[] { "run", "--allow-not-admin" }, true, false);

            Assert.Multiple(() =>
            {
                Assert.That(decision.CanRun, Is.True);
                Assert.That(decision.UseLimitedMode, Is.True);
                Assert.That(decision.IsLifecycleCommand, Is.False);
            });
        }

        [TestCase("--ALLOW-NOT-ADMIN")]
        [TestCase("--Allow-Not-Admin")]
        [TestCase("--allow-not-admin ")]
        public void OptInSwitchIsCaseAndWhitespaceSensitive(string argument)
        {
            var decision = EngineCommandLinePolicy.Evaluate(
                new[] { argument }, true, false);

            Assert.Multiple(() =>
            {
                Assert.That(decision.CanRun, Is.False);
                Assert.That(decision.AllowNotAdministratorRequested, Is.False);
                Assert.That(decision.Denial,
                    Is.EqualTo(EngineCommandLineDenial.AdministratorPrivilegesRequired));
            });
        }

        [Test]
        public void ElevatedRunDoesNotNeedLimitedModeEvenWhenSwitchIsPresent()
        {
            var decision = EngineCommandLinePolicy.Evaluate(
                new[] { "--allow-not-admin" }, true, true);

            Assert.Multiple(() =>
            {
                Assert.That(decision.CanRun, Is.True);
                Assert.That(decision.AllowNotAdministratorRequested, Is.True);
                Assert.That(decision.UseLimitedMode, Is.False);
            });
        }

        [TestCase("install", true)]
        [TestCase("uninstall", false)]
        [TestCase("start", true)]
        [TestCase("stop", false)]
        public void OptInCannotBeCombinedWithLifecycleCommandInEitherOrder(
            string command, bool requiresProtectedLocation)
        {
            foreach (var arguments in new[]
                     {
                         new[] { command, "--allow-not-admin" },
                         new[] { "--allow-not-admin", command }
                     })
            {
                var decision = EngineCommandLinePolicy.Evaluate(arguments, true, false);

                Assert.Multiple(() =>
                {
                    Assert.That(decision.CanRun, Is.False);
                    Assert.That(decision.UseLimitedMode, Is.False);
                    Assert.That(decision.LifecycleCommand, Is.EqualTo(command));
                    Assert.That(decision.RequiresProtectedServiceLocation,
                        Is.EqualTo(requiresProtectedLocation));
                    Assert.That(decision.Denial, Is.EqualTo(
                        EngineCommandLineDenial.AllowNotAdministratorWithLifecycleCommand));
                });
            }
        }

        [TestCase("install")]
        [TestCase("uninstall")]
        [TestCase("start")]
        [TestCase("stop")]
        public void LifecycleCommandsRetainTopshelfPrivilegeHandling(string command)
        {
            var decision = EngineCommandLinePolicy.Evaluate(
                new[] { command }, true, false);

            Assert.Multiple(() =>
            {
                Assert.That(decision.CanRun, Is.True);
                Assert.That(decision.IsLifecycleCommand, Is.True);
                Assert.That(decision.UseLimitedMode, Is.False);
                Assert.That(decision.LifecycleCommand, Is.EqualTo(command));
            });
        }

        [Test]
        public void NonInteractiveInvocationCannotEnableLimitedMode()
        {
            var decision = EngineCommandLinePolicy.Evaluate(
                new[] { "--allow-not-admin" }, false, false);

            Assert.Multiple(() =>
            {
                Assert.That(decision.CanRun, Is.False);
                Assert.That(decision.UseLimitedMode, Is.False);
                Assert.That(decision.RequiresProtectedServiceLocation, Is.True);
                Assert.That(decision.Denial, Is.EqualTo(
                    EngineCommandLineDenial.AllowNotAdministratorRequiresInteractiveSession));
            });
        }

        [Test]
        public void UnelevatedNonInteractiveRunWithoutSwitchRemainsDenied()
        {
            var decision = EngineCommandLinePolicy.Evaluate(new string[0], false, false);

            Assert.Multiple(() =>
            {
                Assert.That(decision.CanRun, Is.False);
                Assert.That(decision.UseLimitedMode, Is.False);
                Assert.That(decision.RequiresProtectedServiceLocation, Is.True);
                Assert.That(decision.Denial,
                    Is.EqualTo(EngineCommandLineDenial.AdministratorPrivilegesRequired));
            });
        }

        [Test]
        public void ElevatedNonInteractiveServiceRunKeepsNormalMode()
        {
            var decision = EngineCommandLinePolicy.Evaluate(new string[0], false, true);

            Assert.Multiple(() =>
            {
                Assert.That(decision.CanRun, Is.True);
                Assert.That(decision.UseLimitedMode, Is.False);
                Assert.That(decision.RequiresProtectedServiceLocation, Is.True);
            });
        }

        [TestCase("help")]
        [TestCase("--help")]
        [TestCase("-h")]
        [TestCase("/?")]
        public void HelpRemainsAvailableWithoutElevation(string helpArgument)
        {
            var decision = EngineCommandLinePolicy.Evaluate(
                new[] { "--allow-not-admin", helpArgument }, true, false);

            Assert.Multiple(() =>
            {
                Assert.That(decision.CanRun, Is.True);
                Assert.That(decision.IsHelpCommand, Is.True);
                Assert.That(decision.UseLimitedMode, Is.False);
            });
        }

        [Test]
        public void NonInteractiveHelpDoesNotRequireProtectedServiceLocation()
        {
            var decision = EngineCommandLinePolicy.Evaluate(
                new[] { "--allow-not-admin", "--help" }, false, false);

            Assert.Multiple(() =>
            {
                Assert.That(decision.CanRun, Is.True);
                Assert.That(decision.IsHelpCommand, Is.True);
                Assert.That(decision.UseLimitedMode, Is.False);
                Assert.That(decision.RequiresProtectedServiceLocation, Is.False);
            });
        }

        [TestCase("run", "--help")]
        [TestCase("unknown", "help")]
        public void HelpTokenDoesNotBypassElevationForAnotherInvocation(
            string otherArgument, string helpArgument)
        {
            var decision = EngineCommandLinePolicy.Evaluate(
                new[] { otherArgument, helpArgument }, true, false);

            Assert.Multiple(() =>
            {
                Assert.That(decision.CanRun, Is.False);
                Assert.That(decision.IsHelpCommand, Is.False);
                Assert.That(decision.Denial,
                    Is.EqualTo(EngineCommandLineDenial.AdministratorPrivilegesRequired));
            });
        }

        [Test]
        public void ProtectedInstallAndStartAreDetectedRegardlessOfArgumentOrder()
        {
            var install = EngineCommandLinePolicy.Evaluate(
                new[] { "--instance", "portable", "INSTALL" }, true, true);
            var start = EngineCommandLinePolicy.Evaluate(
                new[] { "ignored", "Start" }, true, true);

            Assert.Multiple(() =>
            {
                Assert.That(install.RequiresProtectedServiceLocation, Is.True);
                Assert.That(install.LifecycleCommand, Is.EqualTo("install"));
                Assert.That(start.RequiresProtectedServiceLocation, Is.True);
                Assert.That(start.LifecycleCommand, Is.EqualTo("start"));
            });
        }
    }
}
