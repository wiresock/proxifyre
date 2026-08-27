using NUnit.Framework;
using ProxiFyreUI.Infrastructure;
using System;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class SingleInstanceCoordinatorTests
    {
        [Test]
        public void SecondCoordinatorSignalsThePrimaryCoordinator()
        {
            var prefix = CreateUniquePrefix();
            using (var primary = SingleInstanceCoordinator.Create(prefix))
            using (var secondary = SingleInstanceCoordinator.Create(prefix))
            using (var activated = new ManualResetEventSlim(false))
            {
                Assert.Multiple(() =>
                {
                    Assert.That(primary.IsPrimary, Is.True);
                    Assert.That(secondary.IsPrimary, Is.False);
                });

                primary.SetActivationCallback(activated.Set);
                secondary.RequestActivation();

                Assert.That(activated.Wait(TimeSpan.FromSeconds(2)), Is.True,
                    "The primary instance did not receive the activation request.");
            }
        }

        [Test]
        public void ActivationBeforeCallbackRegistrationIsDelivered()
        {
            var prefix = CreateUniquePrefix();
            using (var primary = SingleInstanceCoordinator.Create(prefix))
            using (var secondary = SingleInstanceCoordinator.Create(prefix))
            using (var activated = new ManualResetEventSlim(false))
            {
                secondary.RequestActivation();
                primary.SetActivationCallback(activated.Set);

                Assert.That(activated.Wait(TimeSpan.FromSeconds(2)), Is.True,
                    "An activation requested during startup was not delivered.");
            }
        }

        [Test]
        public void DisposingPrimaryAllowsAReplacementPrimary()
        {
            var prefix = CreateUniquePrefix();
            var primary = SingleInstanceCoordinator.Create(prefix);
            Assert.That(primary.IsPrimary, Is.True);

            primary.Dispose();

            using (var replacement = SingleInstanceCoordinator.Create(prefix))
                Assert.That(replacement.IsPrimary, Is.True);
        }

        [Test]
        public void LingeringSecondaryHandleDoesNotPreventPrimaryReplacement()
        {
            var prefix = CreateUniquePrefix();
            var primary = SingleInstanceCoordinator.Create(prefix);
            using (var lingeringSecondary = SingleInstanceCoordinator.Create(prefix))
            {
                Assert.Multiple(() =>
                {
                    Assert.That(primary.IsPrimary, Is.True);
                    Assert.That(lingeringSecondary.IsPrimary, Is.False);
                });

                primary.Dispose();

                using (var replacement = SingleInstanceCoordinator.Create(prefix))
                    Assert.That(replacement.IsPrimary, Is.True,
                        "An open secondary handle must not keep a departed primary advertised.");
            }
        }

        [Test]
        public void DefaultObjectNamesAreScopedByUserAndTerminalSession()
        {
            var user = new SecurityIdentifier("S-1-5-21-1-2-3-1001");

            var prefix = SingleInstanceCoordinator.BuildObjectNamePrefix(user, 17);

            Assert.That(prefix, Is.EqualTo(
                @"Local\ProxiFyreUI.7790e7d3-66f9-4e93-a9db-967ddcecc76d.S-1-5-21-1-2-3-1001.Session-17"));
        }

        [Test]
        public void NamedObjectsGrantAccessOnlyToTheCurrentUser()
        {
            var prefix = CreateUniquePrefix();
            var currentUser = WindowsIdentity.GetCurrent().User;

            using (var primary = SingleInstanceCoordinator.Create(prefix))
            using (var activationEvent = EventWaitHandle.OpenExisting(prefix + ".Activation",
                EventWaitHandleRights.ReadPermissions))
            using (var instanceMutex = Mutex.OpenExisting(prefix + ".Instance",
                MutexRights.ReadPermissions))
            {
                Assert.That(primary.IsPrimary, Is.True);
                AssertEventSecurity(activationEvent.GetAccessControl(), currentUser);
                AssertMutexSecurity(instanceMutex.GetAccessControl(), currentUser);
            }
        }

        private static void AssertEventSecurity(EventWaitHandleSecurity security,
            SecurityIdentifier currentUser)
        {
            var rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier))
                .Cast<EventWaitHandleAccessRule>().ToArray();
            Assert.Multiple(() =>
            {
                Assert.That(security.AreAccessRulesProtected, Is.True);
                Assert.That(rules, Has.Length.EqualTo(1));
                Assert.That(rules[0].IdentityReference, Is.EqualTo(currentUser));
                Assert.That(rules[0].AccessControlType, Is.EqualTo(AccessControlType.Allow));
                Assert.That(rules[0].EventWaitHandleRights,
                    Is.EqualTo(EventWaitHandleRights.FullControl));
            });
        }

        private static void AssertMutexSecurity(MutexSecurity security,
            SecurityIdentifier currentUser)
        {
            var rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier))
                .Cast<MutexAccessRule>().ToArray();
            Assert.Multiple(() =>
            {
                Assert.That(security.AreAccessRulesProtected, Is.True);
                Assert.That(rules, Has.Length.EqualTo(1));
                Assert.That(rules[0].IdentityReference, Is.EqualTo(currentUser));
                Assert.That(rules[0].AccessControlType, Is.EqualTo(AccessControlType.Allow));
                Assert.That(rules[0].MutexRights, Is.EqualTo(MutexRights.FullControl));
            });
        }

        private static string CreateUniquePrefix()
        {
            return @"Local\ProxiFyreUI.Tests." + Guid.NewGuid().ToString("N");
        }
    }
}
