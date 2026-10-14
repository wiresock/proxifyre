// Ownership and DACL policy for the directories and files the launcher loads the managed UI from.
// Kept free of handle and file-system access so native tests can exercise it with security
// descriptors built from SDDL.
#pragma once

#include <windows.h>
#include <sddl.h>

#include <cwchar>
#include <string>

namespace ProxiFyre::Launcher
{
    constexpr ACCESS_MASK kPayloadDangerousRights =
        GENERIC_ALL | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER |
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
        FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD;
    constexpr ACCESS_MASK kAncestorDangerousRights =
        GENERIC_ALL | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER |
        FILE_DELETE_CHILD;
    constexpr wchar_t kTrustedInstallerSid[] =
        L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    inline std::wstring FormatAccessMask(ACCESS_MASK mask)
    {
        wchar_t hexadecimal[16]{};
        swprintf_s(hexadecimal, L"0x%08lX", static_cast<unsigned long>(mask));

        struct NamedRight
        {
            ACCESS_MASK mask;
            const wchar_t* name;
        };
        constexpr NamedRight namedRights[] = {
            { GENERIC_ALL, L"GENERIC_ALL" },
            { GENERIC_WRITE, L"GENERIC_WRITE" },
            { DELETE, L"DELETE" },
            { WRITE_DAC, L"WRITE_DAC" },
            { WRITE_OWNER, L"WRITE_OWNER" },
            { FILE_DELETE_CHILD, L"FILE_DELETE_CHILD" },
            { FILE_WRITE_DATA, L"FILE_WRITE_DATA/FILE_ADD_FILE" },
            { FILE_APPEND_DATA, L"FILE_APPEND_DATA/FILE_ADD_SUBDIRECTORY" },
            { FILE_WRITE_EA, L"FILE_WRITE_EA" },
            { FILE_WRITE_ATTRIBUTES, L"FILE_WRITE_ATTRIBUTES" }
        };

        std::wstring result(hexadecimal);
        std::wstring names;
        for (const auto& right : namedRights)
        {
            if ((mask & right.mask) == 0)
                continue;
            if (!names.empty())
                names += L", ";
            names += right.name;
        }
        if (!names.empty())
        {
            result += L" (";
            result += names;
            result += L")";
        }
        return result;
    }

    inline bool IsSidString(PSID identity, const wchar_t* sidString)
    {
        PSID expected = nullptr;
        const bool converted = ConvertStringSidToSidW(sidString, &expected) != FALSE;
        const bool matches = converted && EqualSid(identity, expected) != FALSE;
        if (expected != nullptr)
            LocalFree(expected);
        return matches;
    }

    // Names common well-known trustees without an account lookup, which could block on a
    // domain controller while the failure dialog is being prepared.
    inline const wchar_t* GetWellKnownSidName(PSID identity)
    {
        struct NamedSid
        {
            WELL_KNOWN_SID_TYPE type;
            const wchar_t* name;
        };
        constexpr NamedSid namedSids[] = {
            { WinCreatorOwnerSid, L"CREATOR OWNER" },
            { WinCreatorGroupSid, L"CREATOR GROUP" },
            { WinCreatorOwnerRightsSid, L"OWNER RIGHTS" },
            { WinWorldSid, L"Everyone" },
            { WinAuthenticatedUserSid, L"Authenticated Users" },
            { WinBuiltinUsersSid, L"Users" },
            { WinBuiltinPowerUsersSid, L"Power Users" },
            { WinBuiltinGuestsSid, L"Guests" },
            { WinInteractiveSid, L"INTERACTIVE" },
            { WinAnonymousSid, L"ANONYMOUS LOGON" },
            { WinLocalServiceSid, L"LOCAL SERVICE" },
            { WinNetworkServiceSid, L"NETWORK SERVICE" }
        };
        for (const auto& namedSid : namedSids)
        {
            if (IsWellKnownSid(identity, namedSid.type))
                return namedSid.name;
        }
        if (IsSidString(identity, L"S-1-15-2-1"))
            return L"ALL APPLICATION PACKAGES";
        if (IsSidString(identity, L"S-1-15-2-2"))
            return L"ALL RESTRICTED APPLICATION PACKAGES";
        return nullptr;
    }

    inline std::wstring FormatSid(PSID identity)
    {
        if (identity == nullptr || !IsValidSid(identity))
            return L"<missing or invalid>";

        LPWSTR value = nullptr;
        if (!ConvertSidToStringSidW(identity, &value) || value == nullptr)
            return L"<unavailable>";
        std::wstring result(value);
        LocalFree(value);

        const wchar_t* name = GetWellKnownSidName(identity);
        if (name != nullptr)
        {
            result += L" (";
            result += name;
            result += L")";
        }
        return result;
    }

    inline std::wstring RejectedPathPrefix(const std::wstring& path)
    {
        return L"Rejected path: " + path + L"\r\nReason: ";
    }

    inline bool IsTrustedMachineIdentity(PSID identity)
    {
        if (identity == nullptr || !IsValidSid(identity))
            return false;
        if (IsWellKnownSid(identity, WinLocalSystemSid) ||
            IsWellKnownSid(identity, WinBuiltinAdministratorsSid))
            return true;

        return IsSidString(identity, kTrustedInstallerSid);
    }

    // Reads the trustee and access mask of a supported allow or deny ACE. All allow and deny
    // variants share the same fixed layouts; callback variants append application data after
    // the SID. An unfamiliar entry fails so callers can reject it instead of assuming it cannot
    // grant mutation access.
    inline bool TryGetAce(const ACE_HEADER* header, bool& allows, ACCESS_MASK& mask, PSID& identity)
    {
        allows = false;
        mask = 0;
        identity = nullptr;
        if (header == nullptr || header->AceSize < sizeof(ACE_HEADER))
            return false;

        bool objectAce = false;
        switch (header->AceType)
        {
        case ACCESS_ALLOWED_ACE_TYPE:
        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
            allows = true;
            break;
        case ACCESS_DENIED_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_ACE_TYPE:
            break;
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
            allows = true;
            objectAce = true;
            break;
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
            objectAce = true;
            break;
        default:
            return false;
        }

        const BYTE* begin = reinterpret_cast<const BYTE*>(header);
        const BYTE* end = begin + header->AceSize;
        const BYTE* sid = nullptr;
        if (objectAce)
        {
            const auto ace = reinterpret_cast<const ACCESS_ALLOWED_OBJECT_ACE*>(header);
            mask = ace->Mask;
            sid = reinterpret_cast<const BYTE*>(&ace->ObjectType);
            if ((ace->Flags & ACE_OBJECT_TYPE_PRESENT) != 0)
                sid += sizeof(GUID);
            if ((ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0)
                sid += sizeof(GUID);
        }
        else
        {
            const auto ace = reinterpret_cast<const ACCESS_ALLOWED_ACE*>(header);
            mask = ace->Mask;
            sid = reinterpret_cast<const BYTE*>(&ace->SidStart);
        }

        if (sid < begin || sid >= end || !IsValidSid(const_cast<BYTE*>(sid)))
            return false;
        const DWORD sidLength = GetLengthSid(const_cast<BYTE*>(sid));
        if (sidLength == 0 || sidLength > static_cast<DWORD>(end - sid))
            return false;
        identity = const_cast<BYTE*>(sid);
        return true;
    }

    // An OWNER RIGHTS entry replaces the implicit READ_CONTROL and WRITE_DAC rights of an
    // object's owner. An entry that cannot be read is treated as such a restriction, which only
    // keeps the stricter CREATOR OWNER rule in force.
    inline bool DaclRestrictsOwnerRights(PACL dacl)
    {
        for (DWORD index = 0; index < dacl->AceCount; ++index)
        {
            void* rawAce = nullptr;
            bool allows = false;
            ACCESS_MASK mask = 0;
            PSID identity = nullptr;
            if (!GetAce(dacl, index, &rawAce) || rawAce == nullptr ||
                !TryGetAce(static_cast<const ACE_HEADER*>(rawAce), allows, mask, identity) ||
                IsWellKnownSid(identity, WinCreatorOwnerRightsSid))
                return true;
        }
        return false;
    }

    // Accepts an owner and DACL only when the owner is a trusted machine identity and no
    // untrusted allow ACE grants any of dangerousRights. Inherit-only ACEs are evaluated only when
    // includeInheritedChildRights is set. A rejection is explained in failureReason.
    inline bool EvaluateSecurity(PSID owner, PACL dacl, const std::wstring& path,
        ACCESS_MASK dangerousRights, bool includeInheritedChildRights,
        std::wstring& failureReason)
    {
        failureReason.clear();
        bool protectedSecurity = IsTrustedMachineIdentity(owner);
        if (!protectedSecurity)
        {
            failureReason = RejectedPathPrefix(path) + L"owner SID " + FormatSid(owner) +
                L" is not a trusted machine identity.";
        }
        else if (dacl == nullptr)
        {
            protectedSecurity = false;
            failureReason = RejectedPathPrefix(path) +
                L"the object has no discretionary access-control list.";
        }
        if (protectedSecurity)
        {
            const bool daclRestrictsOwnerRights = DaclRestrictsOwnerRights(dacl);
            for (DWORD index = 0; index < dacl->AceCount; ++index)
            {
                void* rawAce = nullptr;
                if (!GetAce(dacl, index, &rawAce) || rawAce == nullptr)
                {
                    protectedSecurity = false;
                    failureReason = RejectedPathPrefix(path) +
                        L"the DACL contains an unreadable ACE at index " +
                        std::to_wstring(index) + L".";
                    break;
                }

                const auto header = static_cast<const ACE_HEADER*>(rawAce);
                if (!includeInheritedChildRights &&
                    (header->AceFlags & INHERIT_ONLY_ACE) != 0)
                    continue;

                bool allows = false;
                ACCESS_MASK mask = 0;
                PSID identity = nullptr;
                if (!TryGetAce(header, allows, mask, identity))
                {
                    protectedSecurity = false;
                    failureReason = RejectedPathPrefix(path) +
                        L"the DACL contains an unsupported or malformed ACE at index " +
                        std::to_wstring(index) + L".";
                    break;
                }
                // A deny ACE does not grant the mutation rights this check is looking for.
                if (!allows)
                    continue;

                // CREATOR OWNER never matches an access token. Windows only turns it into an
                // entry for the owner of a new file or subdirectory, and that owner already
                // holds implicit READ_CONTROL and WRITE_DAC. New payload files must still have
                // a trusted owner, and only trusted identities may create them. Every new
                // Program Files subdirectory inherits this entry. It stays prohibited when an
                // OWNER RIGHTS entry removes the implicit owner rights it would restore.
                if (!daclRestrictsOwnerRights && IsWellKnownSid(identity, WinCreatorOwnerSid))
                    continue;

                if (identity != nullptr && (mask & dangerousRights) != 0 &&
                    !IsTrustedMachineIdentity(identity))
                {
                    protectedSecurity = false;
                    failureReason = RejectedPathPrefix(path) +
                        L"an untrusted allow ACE grants prohibited mutation access.\r\n"
                        L"Trustee SID: " + FormatSid(identity) +
                        L"\r\nACE mask: " + FormatAccessMask(mask) +
                        L"\r\nProhibited rights: " +
                        FormatAccessMask(mask & dangerousRights) +
                        L"\r\nACE origin: " +
                        ((header->AceFlags & INHERITED_ACE) != 0
                            ? std::wstring(L"inherited")
                            : std::wstring(L"explicit")) +
                        ((header->AceFlags & INHERIT_ONLY_ACE) != 0
                            ? std::wstring(L", inherit-only (applies to new files and subdirectories)")
                            : std::wstring());
                    break;
                }
            }
        }
        return protectedSecurity;
    }
}
