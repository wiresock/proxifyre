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
            const FileSystemRights dangerousRights =
                FileSystemRights.Write | FileSystemRights.Delete;

            Assert.Multiple(() =>
            {
                Assert.That(IsAccepted("O:SYD:P(A;;FA;;;SY)(A;;FW;;;WD)", dangerousRights, true),
                    Is.False);
                Assert.That(IsAccepted("O:SYD:P(A;;FA;;;SY)(A;;0x1200a9;;;WD)", dangerousRights,
                    true), Is.True);
            });
        }

        [Test]
        public void InheritOnlyRuleIsIgnoredForAncestorButAppliedToPayloadChildren()
        {
            const string sddl = "O:SYD:P(A;;FA;;;SY)(A;OICIIO;FW;;;WD)";

            Assert.Multiple(() =>
            {
                Assert.That(IsAccepted(sddl, FileSystemRights.Write, false), Is.True);
                Assert.That(IsAccepted(sddl, FileSystemRights.Write, true), Is.False);
            });
        }

        [Test]
        public void AuthenticatedUsersModifyAceApplyingToAncestorIsRejectedForDelete()
        {
            // The effective, inherited Program Files entry reported in issue #169. It
            // intersects the ancestor policy only through DELETE.
            Assert.Multiple(() =>
            {
                Assert.That((FileSystemRights)0x001301bf &
                            ServiceInstallLocationPolicy.AncestorDangerousRights,
                    Is.EqualTo(FileSystemRights.Delete));
                Assert.That(IsAccepted("O:SYD:AI(A;ID;FA;;;SY)(A;ID;0x1301bf;;;AU)",
                    ServiceInstallLocationPolicy.AncestorDangerousRights, false), Is.False);
            });
        }

        [Test]
        public void CreatorOwnerInheritanceIsAcceptedBecauseOwnershipAlreadyImpliesIt()
        {
            const string sddl = "O:SYD:P(A;;FA;;;SY)(A;OICIIO;FA;;;CO)";

            Assert.Multiple(() =>
            {
                Assert.That(IsAccepted(sddl, ServiceInstallLocationPolicy.PayloadDangerousRights,
                    true), Is.True);
                Assert.That(IsAccepted(sddl + "(A;OICI;RC;;;OW)",
                        ServiceInstallLocationPolicy.PayloadDangerousRights, true), Is.False,
                    "OWNER RIGHTS removes the implicit owner rights that CREATOR OWNER would restore.");
            });
        }

        [Test]
        public void CreatorGroupInheritanceRemainsDangerousForFuturePayloadFiles()
        {
            Assert.That(IsAccepted("O:SYD:P(A;;FA;;;SY)(A;OICIIO;FW;;;CG)",
                ServiceInstallLocationPolicy.PayloadDangerousRights, true), Is.False);
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

        // Object or container inheritance alone is enough: new files or new subdirectories
        // would receive both entries.
        [TestCase("(A;OICI;RC;;;OW)")]
        [TestCase("(A;CIIO;RC;;;OW)")]
        [TestCase("(A;OI;RC;;;OW)")]
        public void OwnerRightsRestrictionKeepsCreatorOwnerInheritanceDangerous(
            string ownerRights)
        {
            var security = CreateDirectorySecurity(DefaultProgramFilesSubdirectorySddl +
                                                   ownerRights);

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

        // GetAccessRules omits object ACEs that carry a GUID, so the policy must read the DACL
        // itself. Each case grants Users write access through an entry type other than a plain
        // allow ACE.
        [TestCase("(OA;;FW;;11111111-2222-3333-4444-555555555555;BU)")]
        [TestCase("(OA;;FW;11111111-2222-3333-4444-555555555555;;BU)")]
        [TestCase("(OA;;FW;11111111-2222-3333-4444-555555555555;" +
                  "66666666-7777-8888-9999-000000000000;BU)")]
        [TestCase("(XA;;FW;;;BU;(Member_of {SID(BA)}))")]
        [TestCase("(ZA;;FW;11111111-2222-3333-4444-555555555555;;BU;(Member_of {SID(BA)}))")]
        public void ObjectAndCallbackAllowEntriesAreEvaluated(string entry)
        {
            var security = CreateDirectorySecurity("O:SYD:P(A;;FA;;;SY)" + entry);

            string reason;
            Assert.Multiple(() =>
            {
                Assert.That(ServiceInstallLocationPolicy.HasProtectedSecurity(security,
                        @"C:\Program Files\ProxiFyre",
                        ServiceInstallLocationPolicy.PayloadDangerousRights, true, out reason),
                    Is.False);
                Assert.That(reason, Does.Contain("Users (S-1-5-32-545)"));
            });
        }

        [TestCase("(OD;;FA;;11111111-2222-3333-4444-555555555555;WD)")]
        [TestCase("(XD;;FA;;;WD;(Member_of {SID(BA)}))")]
        public void ObjectAndCallbackDenyEntriesAreIgnored(string entry)
        {
            var security = CreateDirectorySecurity("O:SYD:P" + entry + "(A;;FA;;;SY)");

            string reason;
            Assert.That(ServiceInstallLocationPolicy.HasProtectedSecurity(security,
                    @"C:\Program Files\ProxiFyre",
                    ServiceInstallLocationPolicy.PayloadDangerousRights, true, out reason),
                Is.True, reason);
        }

        [Test]
        public void UnsupportedEntryTypeIsRejected()
        {
            var security = CreateSecurityWithMandatoryLabelEntry(AceFlags.None);

            string reason;
            Assert.Multiple(() =>
            {
                Assert.That(ServiceInstallLocationPolicy.HasProtectedSecurity(security,
                        @"C:\Program Files\ProxiFyre",
                        ServiceInstallLocationPolicy.PayloadDangerousRights, true, out reason),
                    Is.False);
                Assert.That(reason, Does.Contain("entry of type 0x11 at index 1"));
            });
        }

        [Test]
        public void UnsupportedInheritOnlyEntryIsSkippedOnlyForAncestors()
        {
            // Matches the native launcher: an ancestor check ignores inherit-only entries before
            // reading them, while a payload directory check must evaluate them.
            var security = CreateSecurityWithMandatoryLabelEntry(
                AceFlags.ContainerInherit | AceFlags.InheritOnly);

            string ancestorReason;
            string payloadReason;
            Assert.Multiple(() =>
            {
                Assert.That(ServiceInstallLocationPolicy.HasProtectedSecurity(security,
                        @"C:\Program Files",
                        ServiceInstallLocationPolicy.AncestorDangerousRights, false,
                        out ancestorReason),
                    Is.True, ancestorReason);
                Assert.That(ServiceInstallLocationPolicy.HasProtectedSecurity(security,
                        @"C:\Program Files\ProxiFyre",
                        ServiceInstallLocationPolicy.PayloadDangerousRights, true,
                        out payloadReason),
                    Is.False);
            });
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

        // A SYSTEM full-control entry followed by a mandatory-label entry, which belongs in the
        // SACL and grants nothing the policy can reason about. SDDL cannot place it in a DACL.
        private static DirectorySecurity CreateSecurityWithMandatoryLabelEntry(AceFlags flags)
        {
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var dacl = new RawAcl(GenericAcl.AclRevision, 2);
            dacl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed,
                unchecked((int)FileSystemRights.FullControl), system, false, null));
            dacl.InsertAce(1, new CustomAce((AceType)0x11, flags, new byte[8]));
            var descriptor = new RawSecurityDescriptor(
                ControlFlags.DiscretionaryAclPresent | ControlFlags.SelfRelative,
                system, null, null, dacl);
            var binary = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(binary, 0);
            var security = new DirectorySecurity();
            security.SetSecurityDescriptorBinaryForm(binary);
            return security;
        }

        private static bool IsAccepted(string sddl, FileSystemRights dangerousRights,
            bool includeInheritedChildRights)
        {
            string reason;
            return ServiceInstallLocationPolicy.HasProtectedSecurity(
                CreateDirectorySecurity(sddl), @"C:\Program Files\ProxiFyre", dangerousRights,
                includeInheritedChildRights, out reason);
        }

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
