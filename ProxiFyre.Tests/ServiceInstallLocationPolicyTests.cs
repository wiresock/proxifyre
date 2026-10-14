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
                    FileSystemRights.Write | FileSystemRights.Delete, true, false), Is.True);
                Assert.That(ServiceInstallLocationPolicy.GrantsDangerousAccess(read,
                    FileSystemRights.Write | FileSystemRights.Delete, true, false), Is.False);
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
                    FileSystemRights.Write, false, false), Is.False);
                Assert.That(ServiceInstallLocationPolicy.GrantsDangerousAccess(inheritedWrite,
                    FileSystemRights.Write, true, false), Is.True);
            });
        }

        [Test]
        public void AuthenticatedUsersModifyAceApplyingToAncestorIsRejectedForDelete()
        {
            var authenticatedUsers = new SecurityIdentifier(
                WellKnownSidType.AuthenticatedUserSid, null);
            var reportedRule = new FileSystemAccessRule(authenticatedUsers,
                (FileSystemRights)0x001301bf, AccessControlType.Allow);
            var ancestorDangerousRights =
                FileSystemRights.Delete |
                FileSystemRights.DeleteSubdirectoriesAndFiles |
                FileSystemRights.ChangePermissions |
                FileSystemRights.TakeOwnership;

            Assert.Multiple(() =>
            {
                Assert.That(reportedRule.FileSystemRights & FileSystemRights.Delete,
                    Is.EqualTo(FileSystemRights.Delete));
                Assert.That(ServiceInstallLocationPolicy.GrantsDangerousAccess(reportedRule,
                    ancestorDangerousRights, false, false), Is.True);
            });
        }

        [Test]
        public void CreatorOwnerInheritanceIsAcceptedBecauseOwnershipAlreadyImpliesIt()
        {
            var creatorOwner = new SecurityIdentifier(WellKnownSidType.CreatorOwnerSid, null);
            var inheritedFullControl = new FileSystemAccessRule(creatorOwner,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.InheritOnly, AccessControlType.Allow);

            Assert.Multiple(() =>
            {
                Assert.That(ServiceInstallLocationPolicy.GrantsDangerousAccess(
                    inheritedFullControl, ServiceInstallLocationPolicy.PayloadDangerousRights,
                    true, false), Is.False);
                Assert.That(ServiceInstallLocationPolicy.GrantsDangerousAccess(
                    inheritedFullControl, ServiceInstallLocationPolicy.PayloadDangerousRights,
                    true, true), Is.True,
                    "OWNER RIGHTS removes the implicit owner rights that CREATOR OWNER would restore.");
            });
        }

        [Test]
        public void CreatorGroupInheritanceRemainsDangerousForFuturePayloadFiles()
        {
            var creatorGroup = new SecurityIdentifier(WellKnownSidType.CreatorGroupSid, null);
            var inheritedWrite = new FileSystemAccessRule(creatorGroup,
                FileSystemRights.Write,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.InheritOnly, AccessControlType.Allow);

            Assert.That(ServiceInstallLocationPolicy.GrantsDangerousAccess(inheritedWrite,
                ServiceInstallLocationPolicy.PayloadDangerousRights, true, false), Is.True);
        }

        [Test]
        public void DefaultProgramFilesSubdirectoryIsAcceptedAsPayloadDirectory()
        {
            // The inherited DACL Windows gives a directory that an elevated administrator
            // creates under Program Files, as reported in issue #184.
            var security = CreateDirectorySecurity(DefaultProgramFilesSubdirectorySddl);

            string reason;
            Assert.That(ServiceInstallLocationPolicy.HasProtectedSecurity(security,
                    @"C:\Program Files\ProxiFyre",
                    ServiceInstallLocationPolicy.PayloadDangerousRights, true, out reason),
                Is.True, reason);
        }

        [Test]
        public void OwnerRightsRestrictionKeepsCreatorOwnerInheritanceDangerous()
        {
            var security = CreateDirectorySecurity(DefaultProgramFilesSubdirectorySddl +
                                                   "(A;OICI;RC;;;OW)");

            string reason;
            Assert.Multiple(() =>
            {
                Assert.That(ServiceInstallLocationPolicy.HasProtectedSecurity(security,
                        @"C:\Program Files\ProxiFyre",
                        ServiceInstallLocationPolicy.PayloadDangerousRights, true, out reason),
                    Is.False);
                Assert.That(reason, Does.Contain("CREATOR OWNER (S-1-3-0)"));
                Assert.That(reason, Does.Contain("applies only to new files and subdirectories"));
            });
        }

        [TestCase("(A;;RC;;;OW)")]
        [TestCase("(D;;WD;;;OW)")]
        public void NonInheritableOwnerRightsEntryKeepsCreatorOwnerExemption(string ownerRights)
        {
            // An entry that applies only to the directory never reaches new items, so their
            // owners keep the implicit rights the CREATOR OWNER entry repeats.
            var security = CreateDirectorySecurity(DefaultProgramFilesSubdirectorySddl +
                                                   ownerRights);

            string reason;
            Assert.That(ServiceInstallLocationPolicy.HasProtectedSecurity(security,
                    @"C:\Program Files\ProxiFyre",
                    ServiceInstallLocationPolicy.PayloadDangerousRights, true, out reason),
                Is.True, reason);
        }

        [Test]
        public void UntrustedInheritOnlyWriteRejectionNamesTrusteeAndOrigin()
        {
            var security = CreateDirectorySecurity(
                "O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;0x116;;;BU)");

            string reason;
            Assert.Multiple(() =>
            {
                Assert.That(ServiceInstallLocationPolicy.HasProtectedSecurity(security,
                        @"C:\Program Files\ProxiFyre",
                        ServiceInstallLocationPolicy.PayloadDangerousRights, true, out reason),
                    Is.False);
                Assert.That(reason, Does.Contain("Users (S-1-5-32-545)"));
                Assert.That(reason, Does.Contain("inherited from a parent directory"));
                Assert.That(reason, Does.Contain("applies only to new files and subdirectories"));
            });
        }

        [Test]
        public void UnknownTrusteeIsReportedBySid()
        {
            var user = new SecurityIdentifier(
                "S-1-5-21-1004336348-1177238915-682003330-1001");

            Assert.That(ServiceInstallLocationPolicy.DescribeIdentity(user),
                Is.EqualTo("'S-1-5-21-1004336348-1177238915-682003330-1001'"));
        }

        private const string TrustedInstallerSid =
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

        private const string DefaultProgramFilesSubdirectorySddl =
            "O:BAG:SYD:AI" +
            "(A;ID;FA;;;" + TrustedInstallerSid + ")" +
            "(A;CIIOID;GA;;;" + TrustedInstallerSid + ")" +
            "(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)" +
            "(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)" +
            "(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)" +
            "(A;OICIIOID;GA;;;CO)" +
            "(A;ID;0x1200a9;;;S-1-15-2-1)(A;OICIIOID;GXGR;;;S-1-15-2-1)" +
            "(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)";

        private static DirectorySecurity CreateDirectorySecurity(string sddl)
        {
            var security = new DirectorySecurity();
            security.SetSecurityDescriptorSddlForm(sddl);
            return security;
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
