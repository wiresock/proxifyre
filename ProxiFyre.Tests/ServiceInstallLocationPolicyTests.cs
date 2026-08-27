using NUnit.Framework;
using ProxiFyre.Configuration;
using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class ServiceInstallLocationPolicyTests
    {
        [Test]
        public void OnlyMachineControlPrincipalsAreTrustedOwners()
        {
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var administrators = new SecurityIdentifier(
                WellKnownSidType.BuiltinAdministratorsSid, null);
            var world = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

            Assert.Multiple(() =>
            {
                Assert.That(ServiceInstallLocationPolicy.IsTrustedOwner(system), Is.True);
                Assert.That(ServiceInstallLocationPolicy.IsTrustedOwner(administrators), Is.True);
                Assert.That(ServiceInstallLocationPolicy.IsTrustedOwner(world), Is.False);
            });
        }

        [Test]
        public void StandardUserWriteRuleIsDangerousButReadRuleIsNot()
        {
            var world = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            var write = new FileSystemAccessRule(world, FileSystemRights.Write,
                AccessControlType.Allow);
            var read = new FileSystemAccessRule(world, FileSystemRights.ReadAndExecute,
                AccessControlType.Allow);

            Assert.Multiple(() =>
            {
                Assert.That(ServiceInstallLocationPolicy.GrantsDangerousAccess(write,
                    FileSystemRights.Write | FileSystemRights.Delete, true), Is.True);
                Assert.That(ServiceInstallLocationPolicy.GrantsDangerousAccess(read,
                    FileSystemRights.Write | FileSystemRights.Delete, true), Is.False);
            });
        }

        [Test]
        public void InheritOnlyRuleIsIgnoredForAncestorButAppliedToPayloadChildren()
        {
            var world = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            var inheritedWrite = new FileSystemAccessRule(world, FileSystemRights.Write,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.InheritOnly, AccessControlType.Allow);

            Assert.Multiple(() =>
            {
                Assert.That(ServiceInstallLocationPolicy.GrantsDangerousAccess(inheritedWrite,
                    FileSystemRights.Write, false), Is.False);
                Assert.That(ServiceInstallLocationPolicy.GrantsDangerousAccess(inheritedWrite,
                    FileSystemRights.Write, true), Is.True);
            });
        }

        [Test]
        public void CreatorOwnerWriteInheritanceIsUnsafeForFuturePayloadFiles()
        {
            var creatorOwner = new SecurityIdentifier(WellKnownSidType.CreatorOwnerSid, null);
            var inheritedWrite = new FileSystemAccessRule(creatorOwner,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.InheritOnly, AccessControlType.Allow);

            Assert.Multiple(() =>
            {
                Assert.That(ServiceInstallLocationPolicy.GrantsDangerousAccess(inheritedWrite,
                    FileSystemRights.Write, false), Is.False);
                Assert.That(ServiceInstallLocationPolicy.GrantsDangerousAccess(inheritedWrite,
                    FileSystemRights.Write, true), Is.True);
            });
        }

        [TestCase("ProxiFyre.exe", true)]
        [TestCase("ProxiFyreUI.Managed.dll", true)]
        [TestCase("mscoree.dll", false)]
        [TestCase("helper.exe", false)]
        public void PortableExecutableAllowListIsExact(string fileName, bool expected)
        {
            Assert.That(ServiceInstallLocationPolicy.IsAllowedPortableExecutable(fileName),
                Is.EqualTo(expected));
        }

        [Test]
        public void UserOwnedTemporaryDirectoryCannotHostLocalSystemService()
        {
            var directory = Path.Combine(Path.GetTempPath(),
                "ProxiFyre.ServiceLocation." + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var enginePath = Path.Combine(directory, ProxiFyrePaths.EngineExecutableName);
            File.WriteAllBytes(enginePath, new byte[] { 1 });
            try
            {
                string reason;
                Assert.That(ServiceInstallLocationPolicy.IsProtected(enginePath, out reason),
                    Is.False);
                Assert.That(reason, Is.Not.Null.And.Not.Empty);
            }
            finally
            {
                File.Delete(enginePath);
                Directory.Delete(directory);
            }
        }

        [Test]
        public void StandardProgramFilesAncestorChainIsAccepted()
        {
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            Assert.That(programFiles, Is.Not.Null.And.Not.Empty);
            Assert.That(Directory.Exists(programFiles), Is.True);

            string reason;
            Assert.That(ServiceInstallLocationPolicy.HasProtectedDirectoryChain(programFiles,
                false, out reason), Is.True, reason);
        }
    }
}
