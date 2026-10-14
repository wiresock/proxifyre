// Native coverage for the ProxiFyreUI launcher's owner and DACL policy
// (ProxiFyreUILauncher/SecurityPolicy.h). The launcher only runs these checks in Release builds
// against real directory handles; here the same evaluation runs against security descriptors
// built from SDDL, so each case pins one rule without touching the file system.
//
// The Program Files descriptors below are the stock Windows 11 ones: the directory itself and a
// subdirectory created under it, which inherits every inheritable entry with the ID flag.

#include "pch.h"

#include <sddl.h>

#include "../ProxiFyreUILauncher/SecurityPolicy.h"

namespace
{
    using ProxiFyre::Launcher::EvaluateSecurity;
    using ProxiFyre::Launcher::FormatSid;
    using ProxiFyre::Launcher::kAncestorDangerousRights;
    using ProxiFyre::Launcher::kPayloadDangerousRights;

    constexpr wchar_t test_path[] = L"C:\\Program Files\\ProxiFyre";

    const std::wstring trusted_installer =
        L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    // C:\Program Files: owned by TrustedInstaller, protected DACL.
    const std::wstring program_files_sddl =
        L"O:" + trusted_installer + L"G:" + trusted_installer +
        L"D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)"
        L"(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;" +
        trusted_installer + L")(A;;FA;;;" + trusted_installer +
        L")(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)"
        L"(A;OICIIO;GXGR;;;S-1-15-2-2)";

    // A subdirectory an administrator creates under C:\Program Files.
    const std::wstring program_files_child_dacl =
        L"D:AI(A;ID;FA;;;" + trusted_installer + L")(A;CIIOID;GA;;;" + trusted_installer +
        L")(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)"
        L"(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)"
        L"(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)";

    const std::wstring program_files_child_sddl = L"O:BA" + program_files_child_dacl;

    class security_descriptor
    {
    public:
        explicit security_descriptor(const std::wstring& sddl)
        {
            if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.c_str(), SDDL_REVISION_1, &descriptor_, nullptr))
                return;

            BOOL owner_defaulted = FALSE;
            BOOL dacl_present = FALSE;
            BOOL dacl_defaulted = FALSE;
            valid_ = ::GetSecurityDescriptorOwner(descriptor_, &owner_, &owner_defaulted) &&
                ::GetSecurityDescriptorDacl(descriptor_, &dacl_present, &dacl_, &dacl_defaulted);
            if (!dacl_present)
                dacl_ = nullptr;
        }

        ~security_descriptor()
        {
            if (descriptor_ != nullptr)
                ::LocalFree(descriptor_);
        }

        security_descriptor(const security_descriptor&) = delete;
        security_descriptor& operator=(const security_descriptor&) = delete;

        bool valid() const { return valid_; }
        PSID owner() const { return owner_; }
        PACL dacl() const { return dacl_; }

    private:
        PSECURITY_DESCRIPTOR descriptor_{};
        PSID owner_{};
        PACL dacl_{};
        bool valid_{ false };
    };

    struct well_known_sid
    {
        explicit well_known_sid(WELL_KNOWN_SID_TYPE type)
        {
            DWORD size = sizeof(bytes);
            ok = ::CreateWellKnownSid(type, nullptr, bytes, &size) != FALSE;
        }

        PSID get() const { return const_cast<BYTE*>(bytes); }

        BYTE bytes[SECURITY_MAX_SID_SIZE]{};
        bool ok{ false };
    };

    // A one-entry ACL written byte by byte, for layouts the Add*Ace functions refuse to build.
    // Its last byte sits directly before a PAGE_NOACCESS page, so a parser that reads past the
    // declared sizes faults instead of silently reading zeroed memory. ace_size and acl_size
    // must be multiples of four so the ACL stays DWORD-aligned.
    class raw_acl
    {
    public:
        raw_acl(BYTE ace_type, WORD ace_size, WORD acl_size = 0)
        {
            const size_t declared_size = acl_size != 0 ? acl_size : sizeof(ACL) + ace_size;
            const size_t written_size = (std::max)(declared_size, sizeof(ACL) + ace_size);

            SYSTEM_INFO system_info{};
            ::GetSystemInfo(&system_info);
            const size_t page_size = system_info.dwPageSize;
            base_ = static_cast<BYTE*>(::VirtualAlloc(nullptr, 2 * page_size,
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            DWORD old_protection = 0;
            if (base_ == nullptr || written_size % sizeof(DWORD) != 0 ||
                !::VirtualProtect(base_ + page_size, page_size, PAGE_NOACCESS, &old_protection))
                return;

            bytes_ = base_ + page_size - written_size;
            const auto acl = reinterpret_cast<ACL*>(bytes_);
            acl->AclRevision = ACL_REVISION_DS;
            acl->AclSize = static_cast<WORD>(declared_size);
            acl->AceCount = 1;
            const auto header = reinterpret_cast<ACE_HEADER*>(bytes_ + sizeof(ACL));
            header->AceType = ace_type;
            header->AceSize = ace_size;
        }

        ~raw_acl()
        {
            if (base_ != nullptr)
                ::VirtualFree(base_, 0, MEM_RELEASE);
        }

        raw_acl(const raw_acl&) = delete;
        raw_acl& operator=(const raw_acl&) = delete;

        bool valid() const { return bytes_ != nullptr; }
        PACL get() { return reinterpret_cast<PACL>(bytes_); }
        BYTE* body() { return bytes_ + sizeof(ACL) + sizeof(ACE_HEADER); }

    private:
        BYTE* base_{};
        BYTE* bytes_{};
    };

    struct evaluation
    {
        bool accepted{ false };
        std::wstring reason;
    };

    evaluation evaluate(const std::wstring& sddl, ACCESS_MASK dangerous_rights,
        bool include_inherited_child_rights)
    {
        const security_descriptor descriptor(sddl);
        EXPECT_TRUE(descriptor.valid()) << "SDDL did not parse: " << sddl;
        evaluation result;
        if (descriptor.valid())
        {
            result.accepted = EvaluateSecurity(descriptor.owner(), descriptor.dacl(), test_path,
                dangerous_rights, include_inherited_child_rights, result.reason);
        }
        return result;
    }

    evaluation evaluate_payload(const std::wstring& sddl)
    {
        return evaluate(sddl, kPayloadDangerousRights, true);
    }

    bool contains(const std::wstring& text, const std::wstring& fragment)
    {
        return text.find(fragment) != std::wstring::npos;
    }

    TEST(LauncherSecurityPolicyTest, ProgramFilesIsAcceptedAsAncestor)
    {
        const auto result = evaluate(program_files_sddl, kAncestorDangerousRights, false);
        EXPECT_TRUE(result.accepted) << result.reason;
        EXPECT_TRUE(result.reason.empty());
    }

    TEST(LauncherSecurityPolicyTest, DefaultProgramFilesSubdirectoryIsAcceptedAsPayloadDirectory)
    {
        // Regression for the inherited (A;OICIIOID;GA;;;CO) entry every new Program Files
        // subdirectory carries: it must not be reported as an untrusted trustee.
        const auto result = evaluate_payload(program_files_child_sddl);
        EXPECT_TRUE(result.accepted) << result.reason;
    }

    TEST(LauncherSecurityPolicyTest, ExplicitCreatorOwnerEntryIsAccepted)
    {
        const auto result = evaluate_payload(L"O:SYD:P(A;;FA;;;SY)(A;OICI;FA;;;CO)");
        EXPECT_TRUE(result.accepted) << result.reason;
    }

    TEST(LauncherSecurityPolicyTest, OwnerRightsRestrictionKeepsCreatorOwnerInheritanceDangerous)
    {
        // Object or container inheritance alone is enough: new files or new subdirectories
        // would receive both entries.
        for (const wchar_t* owner_rights :
            { L"(A;OICI;RC;;;OW)", L"(A;CIIO;RC;;;OW)", L"(A;OI;RC;;;OW)" })
        {
            const auto result = evaluate_payload(program_files_child_sddl + owner_rights);
            EXPECT_FALSE(result.accepted) << owner_rights;
            EXPECT_TRUE(contains(result.reason, L"S-1-3-0 (CREATOR OWNER)")) << result.reason;
            EXPECT_TRUE(contains(result.reason, L"inherit-only")) << result.reason;
        }
    }

    TEST(LauncherSecurityPolicyTest, DenyOwnerRightsEntryAlsoKeepsCreatorOwnerInheritanceDangerous)
    {
        const auto result = evaluate_payload(
            L"O:SYD:P(A;;FA;;;SY)(D;OI;WD;;;OW)(A;OICIIO;GA;;;CO)");
        EXPECT_FALSE(result.accepted);
        EXPECT_TRUE(contains(result.reason, L"S-1-3-0 (CREATOR OWNER)")) << result.reason;
    }

    TEST(LauncherSecurityPolicyTest, NonInheritableOwnerRightsEntryKeepsCreatorOwnerExemption)
    {
        // An entry that applies only to the directory never reaches new items, so their owners
        // keep the implicit rights the CREATOR OWNER entry repeats.
        for (const wchar_t* owner_rights : { L"(A;;RC;;;OW)", L"(D;;WD;;;OW)" })
        {
            const auto result = evaluate_payload(program_files_child_sddl + owner_rights);
            EXPECT_TRUE(result.accepted) << owner_rights << L": " << result.reason;
        }
    }

    TEST(LauncherSecurityPolicyTest, CreatorGroupInheritanceRemainsDangerousForPayloadChildren)
    {
        const auto result = evaluate_payload(L"O:SYD:P(A;;FA;;;SY)(A;OICIIO;GA;;;CG)");
        EXPECT_FALSE(result.accepted);
        EXPECT_TRUE(contains(result.reason, L"S-1-3-1 (CREATOR GROUP)")) << result.reason;
    }

    TEST(LauncherSecurityPolicyTest, InheritOnlyRuleIsIgnoredForAncestorButAppliedToPayloadChildren)
    {
        const std::wstring sddl = L"O:SYD:P(A;;FA;;;SY)(A;OICIIO;FW;;;BU)";

        const auto ancestor = evaluate(sddl, kAncestorDangerousRights, false);
        EXPECT_TRUE(ancestor.accepted) << ancestor.reason;

        const auto payload = evaluate(sddl, kPayloadDangerousRights, true);
        EXPECT_FALSE(payload.accepted);
        EXPECT_TRUE(contains(payload.reason, L"Trustee SID: S-1-5-32-545 (Users)"))
            << payload.reason;
        EXPECT_TRUE(contains(payload.reason,
            L"ACE origin: explicit, inherit-only (applies to new files and subdirectories)"))
            << payload.reason;
    }

    TEST(LauncherSecurityPolicyTest, AddFileRightIsDangerousOnlyForPayloadDirectories)
    {
        const std::wstring sddl = L"O:SYD:P(A;;FA;;;SY)(A;;0x1200af;;;AU)";

        EXPECT_TRUE(evaluate(sddl, kAncestorDangerousRights, false).accepted);

        const auto payload = evaluate(sddl, kPayloadDangerousRights, false);
        EXPECT_FALSE(payload.accepted);
        EXPECT_TRUE(contains(payload.reason, L"S-1-5-11 (Authenticated Users)")) << payload.reason;
        EXPECT_TRUE(contains(payload.reason, L"FILE_WRITE_DATA/FILE_ADD_FILE")) << payload.reason;
    }

    TEST(LauncherSecurityPolicyTest, InheritedModifyEntryIsRejectedWithItsOrigin)
    {
        const auto result = evaluate(L"O:BAD:AI(A;ID;FA;;;SY)(A;ID;0x1301bf;;;AU)",
            kAncestorDangerousRights, false);
        EXPECT_FALSE(result.accepted);
        EXPECT_TRUE(contains(result.reason, L"Prohibited rights: 0x00010000 (DELETE)"))
            << result.reason;
        EXPECT_TRUE(contains(result.reason, L"ACE origin: inherited")) << result.reason;
        EXPECT_FALSE(contains(result.reason, L"inherit-only")) << result.reason;
    }

    TEST(LauncherSecurityPolicyTest, DenyEntriesAreIgnored)
    {
        const auto result = evaluate_payload(L"O:SYD:P(D;OICI;FA;;;WD)(A;OICI;FA;;;SY)");
        EXPECT_TRUE(result.accepted) << result.reason;
    }

    TEST(LauncherSecurityPolicyTest, OnlyMachineControlPrincipalsAreTrustedOwners)
    {
        for (const wchar_t* owner : { L"SY", L"BA" })
        {
            const auto result = evaluate_payload(
                std::wstring(L"O:") + owner + L"D:P(A;;FA;;;SY)");
            EXPECT_TRUE(result.accepted) << owner << L": " << result.reason;
        }
        EXPECT_TRUE(evaluate_payload(L"O:" + trusted_installer + L"D:P(A;;FA;;;SY)").accepted);

        for (const wchar_t* owner : { L"BU", L"AU", L"WD", L"CO" })
        {
            const auto result = evaluate_payload(
                std::wstring(L"O:") + owner + L"D:P(A;;FA;;;SY)");
            EXPECT_FALSE(result.accepted) << owner;
            EXPECT_TRUE(contains(result.reason, L"is not a trusted machine identity."))
                << result.reason;
        }
    }

    TEST(LauncherSecurityPolicyTest, NullDaclIsRejected)
    {
        const auto result = evaluate_payload(L"O:SYD:NO_ACCESS_CONTROL");
        EXPECT_FALSE(result.accepted);
        EXPECT_TRUE(contains(result.reason, L"no discretionary access-control list"))
            << result.reason;
    }

    TEST(LauncherSecurityPolicyTest, UnsupportedAceTypeIsRejected)
    {
        BYTE system_sid[SECURITY_MAX_SID_SIZE]{};
        BYTE low_label_sid[SECURITY_MAX_SID_SIZE]{};
        DWORD system_sid_size = sizeof(system_sid);
        DWORD low_label_sid_size = sizeof(low_label_sid);
        ASSERT_TRUE(::CreateWellKnownSid(WinLocalSystemSid, nullptr, system_sid, &system_sid_size));
        ASSERT_TRUE(::CreateWellKnownSid(WinLowLabelSid, nullptr, low_label_sid,
            &low_label_sid_size));

        alignas(DWORD) BYTE buffer[256]{};
        const auto dacl = reinterpret_cast<PACL>(buffer);
        ASSERT_TRUE(::InitializeAcl(dacl, sizeof(buffer), ACL_REVISION));
        ASSERT_TRUE(::AddAccessAllowedAce(dacl, ACL_REVISION, FILE_ALL_ACCESS, system_sid));
        ASSERT_TRUE(::AddMandatoryAce(dacl, ACL_REVISION, 0,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, low_label_sid));

        std::wstring reason;
        EXPECT_FALSE(EvaluateSecurity(system_sid, dacl, test_path, kPayloadDangerousRights, true,
            reason));
        EXPECT_TRUE(contains(reason, L"unsupported or malformed ACE at index 1")) << reason;
    }

    TEST(LauncherSecurityPolicyTest, ObjectAceTrusteeIsReadAfterOptionalGuids)
    {
        const well_known_sid system(WinLocalSystemSid);
        const well_known_sid users(WinBuiltinUsersSid);
        const well_known_sid everyone(WinWorldSid);
        ASSERT_TRUE(system.ok && users.ok && everyone.ok);

        GUID object_type{ 0x11111111, 0x2222, 0x3333, { 4, 4, 4, 4, 4, 4, 4, 4 } };
        GUID inherited_object_type{ 0x55555555, 0x6666, 0x7777, { 8, 8, 8, 8, 8, 8, 8, 8 } };
        const struct
        {
            GUID* object;
            GUID* inherited;
        } layouts[] = {
            { nullptr, nullptr },
            { &object_type, nullptr },
            { nullptr, &inherited_object_type },
            { &object_type, &inherited_object_type },
        };
        for (const auto& layout : layouts)
        {
            alignas(DWORD) BYTE buffer[256]{};
            const auto dacl = reinterpret_cast<PACL>(buffer);
            ASSERT_TRUE(::InitializeAcl(dacl, sizeof(buffer), ACL_REVISION_DS));
            ASSERT_TRUE(::AddAccessAllowedAce(dacl, ACL_REVISION_DS, FILE_ALL_ACCESS, system.get()));
            ASSERT_TRUE(::AddAccessDeniedObjectAce(dacl, ACL_REVISION_DS, 0, FILE_ALL_ACCESS,
                layout.object, layout.inherited, everyone.get()));
            ASSERT_TRUE(::AddAccessAllowedObjectAce(dacl, ACL_REVISION_DS, 0, FILE_GENERIC_WRITE,
                layout.object, layout.inherited, users.get()));

            // The deny entry must parse to be skipped, and the allow entry must resolve its
            // trustee past whichever GUIDs are present.
            std::wstring reason;
            EXPECT_FALSE(EvaluateSecurity(system.get(), dacl, test_path, kPayloadDangerousRights,
                true, reason));
            EXPECT_TRUE(contains(reason, L"Trustee SID: S-1-5-32-545 (Users)")) << reason;
        }
    }

    TEST(LauncherSecurityPolicyTest, CallbackAceTrusteeIsReadBeforeApplicationData)
    {
        const std::wstring conditional_deny = L"(XD;;FA;;;WD;(Member_of {SID(BA)}))";
        const std::wstring conditional_allow = L"(XA;;FW;;;BU;(Member_of {SID(BA)}))";

        const auto denied = evaluate_payload(L"O:SYD:P(A;;FA;;;SY)" + conditional_deny);
        EXPECT_TRUE(denied.accepted) << denied.reason;

        const auto allowed = evaluate_payload(
            L"O:SYD:P(A;;FA;;;SY)" + conditional_deny + conditional_allow);
        EXPECT_FALSE(allowed.accepted);
        EXPECT_TRUE(contains(allowed.reason, L"Trustee SID: S-1-5-32-545 (Users)"))
            << allowed.reason;
    }

    TEST(LauncherSecurityPolicyTest, CallbackObjectAceTrusteeIsReadAfterGuidsAndBeforeData)
    {
        // Callback object entries take the object layout and append application data.
        const auto result = evaluate_payload(L"O:SYD:P(A;;FA;;;SY)"
            L"(ZA;;FW;11111111-2222-3333-4444-555555555555;;BU;(Member_of {SID(BA)}))");
        EXPECT_FALSE(result.accepted);
        EXPECT_TRUE(contains(result.reason, L"Trustee SID: S-1-5-32-545 (Users)"))
            << result.reason;
    }

    TEST(LauncherSecurityPolicyTest, TruncatedAcesAreRejected)
    {
        const well_known_sid system(WinLocalSystemSid);
        ASSERT_TRUE(system.ok);

        // Header only, no mask.
        raw_acl no_mask(ACCESS_ALLOWED_ACE_TYPE, 4);
        // Mask present, no room for a SID.
        raw_acl no_sid(ACCESS_ALLOWED_ACE_TYPE, 8);
        // Object ACE ending before its Flags field.
        raw_acl no_object_flags(ACCESS_ALLOWED_OBJECT_ACE_TYPE, 8);
        // Object ACE whose flags announce both GUIDs, but the entry ends after the flags.
        raw_acl missing_guids(ACCESS_ALLOWED_OBJECT_ACE_TYPE, 12);
        // SID header claims two sub-authorities, but the entry ends after the header.
        raw_acl short_sid(ACCESS_ALLOWED_ACE_TYPE, 16);
        ASSERT_TRUE(no_mask.valid() && no_sid.valid() && no_object_flags.valid() &&
            missing_guids.valid() && short_sid.valid());
        missing_guids.body()[4] = ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT;
        short_sid.body()[4] = SID_REVISION;
        short_sid.body()[5] = 2;
        short_sid.body()[11] = 5;

        for (raw_acl* acl : { &no_mask, &no_sid, &no_object_flags, &missing_guids, &short_sid })
        {
            std::wstring reason;
            EXPECT_FALSE(EvaluateSecurity(system.get(), acl->get(), test_path,
                kPayloadDangerousRights, true, reason));
            EXPECT_TRUE(contains(reason, L"unsupported or malformed ACE at index 0")) << reason;
        }
    }

    TEST(LauncherSecurityPolicyTest, AceExtendingPastTheAclIsRejected)
    {
        const well_known_sid system(WinLocalSystemSid);
        ASSERT_TRUE(system.ok);

        // A well-formed SYSTEM full-control entry whose ACL claims to end four bytes early.
        const WORD ace_size = static_cast<WORD>(
            offsetof(ACCESS_ALLOWED_ACE, SidStart) + ::GetLengthSid(system.get()));
        raw_acl acl(ACCESS_ALLOWED_ACE_TYPE, ace_size, static_cast<WORD>(sizeof(ACL) + ace_size - 4));
        ASSERT_TRUE(acl.valid());
        *reinterpret_cast<ACCESS_MASK*>(acl.body()) = FILE_ALL_ACCESS;
        ASSERT_TRUE(::CopySid(::GetLengthSid(system.get()), acl.body() + sizeof(ACCESS_MASK),
            system.get()));

        std::wstring reason;
        EXPECT_FALSE(EvaluateSecurity(system.get(), acl.get(), test_path, kPayloadDangerousRights,
            true, reason));
        EXPECT_TRUE(contains(reason, L"unreadable ACE at index 0")) << reason;
    }

    TEST(LauncherSecurityPolicyTest, WellKnownTrusteesAreNamedAndOthersAreReportedBySid)
    {
        const struct
        {
            const wchar_t* sid;
            const wchar_t* expected;
        } cases[] = {
            { L"S-1-3-0", L"S-1-3-0 (CREATOR OWNER)" },
            { L"S-1-3-4", L"S-1-3-4 (OWNER RIGHTS)" },
            { L"S-1-15-2-1", L"S-1-15-2-1 (ALL APPLICATION PACKAGES)" },
            { L"S-1-15-2-2", L"S-1-15-2-2 (ALL RESTRICTED APPLICATION PACKAGES)" },
            { L"S-1-5-21-1-2-3-1001", L"S-1-5-21-1-2-3-1001" },
        };
        for (const auto& item : cases)
        {
            PSID sid = nullptr;
            ASSERT_TRUE(::ConvertStringSidToSidW(item.sid, &sid)) << item.sid;
            EXPECT_EQ(std::wstring(item.expected), FormatSid(sid));
            ::LocalFree(sid);
        }
        EXPECT_EQ(std::wstring(L"<missing or invalid>"), FormatSid(nullptr));
    }
}
