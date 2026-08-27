#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <metahost.h>
#include <sddl.h>

#include <algorithm>
#include <array>
#include <cwchar>
#include <cwctype>
#include <string>
#include <vector>

namespace
{
    constexpr DWORD kLoadWithAlteredSearchPath = 0x00000008;
    constexpr DWORD kLoadLibrarySearchSystem32 = 0x00000800;

    enum class ManagedUiStage
    {
        None,
        LoadMscoree,
        ResolveClrCreateInstance,
        CreateMetaHost,
        GetRuntime,
        IsLoadable,
        GetRuntimeHost,
        StartRuntime,
        ExecuteEntryPoint
    };

    constexpr std::array<BYTE, 32> kExpectedUiConfigurationSha256 = {
        0xEC, 0xEB, 0x47, 0x26, 0x9D, 0xB5, 0xD3, 0xE2,
        0x27, 0x28, 0xF6, 0xDC, 0x60, 0xEC, 0x05, 0x45,
        0x07, 0x83, 0xF8, 0xB3, 0xC2, 0x90, 0x74, 0x66,
        0x68, 0x37, 0xB3, 0xE7, 0x63, 0xE8, 0xF4, 0xA6
    };

#ifndef _DEBUG
    constexpr ACCESS_MASK kPayloadDangerousRights =
        GENERIC_ALL | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER |
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
        FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD;
    constexpr ACCESS_MASK kAncestorDangerousRights =
        GENERIC_ALL | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER |
        FILE_DELETE_CHILD;
    constexpr wchar_t kTrustedInstallerSid[] =
        L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    bool IsTrustedMachineIdentity(PSID identity)
    {
        if (identity == nullptr || !IsValidSid(identity))
            return false;
        if (IsWellKnownSid(identity, WinLocalSystemSid) ||
            IsWellKnownSid(identity, WinBuiltinAdministratorsSid))
            return true;

        PSID trustedInstaller = nullptr;
        const bool converted = ConvertStringSidToSidW(kTrustedInstallerSid, &trustedInstaller) != FALSE;
        const bool matches = converted && EqualSid(identity, trustedInstaller) != FALSE;
        if (trustedInstaller != nullptr)
            LocalFree(trustedInstaller);
        return matches;
    }

    bool TryGetAllowedAce(const ACE_HEADER* header, ACCESS_MASK& mask, PSID& identity)
    {
        mask = 0;
        identity = nullptr;
        if (header == nullptr || header->AceSize < sizeof(ACE_HEADER))
            return false;

        const BYTE* begin = reinterpret_cast<const BYTE*>(header);
        const BYTE* end = begin + header->AceSize;
        const BYTE* sid = nullptr;
        switch (header->AceType)
        {
        case ACCESS_ALLOWED_ACE_TYPE:
        {
            const auto ace = reinterpret_cast<const ACCESS_ALLOWED_ACE*>(header);
            mask = ace->Mask;
            sid = reinterpret_cast<const BYTE*>(&ace->SidStart);
            break;
        }
        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
        {
            const auto ace = reinterpret_cast<const ACCESS_ALLOWED_CALLBACK_ACE*>(header);
            mask = ace->Mask;
            sid = reinterpret_cast<const BYTE*>(&ace->SidStart);
            break;
        }
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        {
            const auto ace = reinterpret_cast<const ACCESS_ALLOWED_OBJECT_ACE*>(header);
            mask = ace->Mask;
            sid = reinterpret_cast<const BYTE*>(&ace->ObjectType);
            if ((ace->Flags & ACE_OBJECT_TYPE_PRESENT) != 0)
                sid += sizeof(GUID);
            if ((ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0)
                sid += sizeof(GUID);
            break;
        }
        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
        {
            const auto ace = reinterpret_cast<const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE*>(header);
            mask = ace->Mask;
            sid = reinterpret_cast<const BYTE*>(&ace->ObjectType);
            if ((ace->Flags & ACE_OBJECT_TYPE_PRESENT) != 0)
                sid += sizeof(GUID);
            if ((ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0)
                sid += sizeof(GUID);
            break;
        }
        case ACCESS_DENIED_ACE_TYPE:
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
            // A deny ACE does not grant the mutation rights this check is looking for.
            return true;
        default:
            // Fail closed for an unfamiliar DACL entry instead of assuming it cannot grant
            // mutation access.
            return false;
        }

        if (sid < begin || sid >= end || !IsValidSid(const_cast<BYTE*>(sid)))
            return false;
        const DWORD sidLength = GetLengthSid(const_cast<BYTE*>(sid));
        if (sidLength == 0 || sidLength > static_cast<DWORD>(end - sid))
            return false;
        identity = const_cast<BYTE*>(sid);
        return true;
    }

    bool HasProtectedSecurity(HANDLE handle, ACCESS_MASK dangerousRights,
        bool includeInheritedChildRights)
    {
        PSID owner = nullptr;
        PACL dacl = nullptr;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        const DWORD result = GetSecurityInfo(handle, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &owner, nullptr, &dacl, nullptr, &descriptor);
        if (result != ERROR_SUCCESS || descriptor == nullptr)
            return false;

        bool protectedSecurity = IsTrustedMachineIdentity(owner) && dacl != nullptr;
        if (protectedSecurity)
        {
            for (DWORD index = 0; index < dacl->AceCount; ++index)
            {
                void* rawAce = nullptr;
                if (!GetAce(dacl, index, &rawAce) || rawAce == nullptr)
                {
                    protectedSecurity = false;
                    break;
                }

                const auto header = static_cast<const ACE_HEADER*>(rawAce);
                if (!includeInheritedChildRights &&
                    (header->AceFlags & INHERIT_ONLY_ACE) != 0)
                    continue;

                ACCESS_MASK mask = 0;
                PSID identity = nullptr;
                if (!TryGetAllowedAce(header, mask, identity))
                {
                    protectedSecurity = false;
                    break;
                }
                if (identity != nullptr && (mask & dangerousRights) != 0 &&
                    !IsTrustedMachineIdentity(identity))
                {
                    protectedSecurity = false;
                    break;
                }
            }
        }

        LocalFree(descriptor);
        return protectedSecurity;
    }
#endif

    class Module final
    {
    public:
        Module() = default;
        explicit Module(HMODULE value) : value_(value) {}
        ~Module()
        {
            if (value_ != nullptr)
                FreeLibrary(value_);
        }
        Module(const Module&) = delete;
        Module& operator=(const Module&) = delete;
        Module(Module&& other) noexcept : value_(other.value_)
        {
            other.value_ = nullptr;
        }
        Module& operator=(Module&& other) noexcept
        {
            if (this != &other)
            {
                if (value_ != nullptr)
                    FreeLibrary(value_);
                value_ = other.value_;
                other.value_ = nullptr;
            }
            return *this;
        }
        HMODULE Get() const { return value_; }
        explicit operator bool() const { return value_ != nullptr; }

    private:
        HMODULE value_ = nullptr;
    };

    class LeaseSet final
    {
    public:
        ~LeaseSet()
        {
            for (auto iterator = handles_.rbegin(); iterator != handles_.rend(); ++iterator)
                CloseHandle(*iterator);
        }

        bool OpenDirectoryChain(const std::wstring& directory)
        {
            if (directory.size() < 3 || directory[1] != L':' ||
                (directory[2] != L'\\' && directory[2] != L'/'))
                return false;

            std::wstring root = directory.substr(0, 3);
            root[0] = static_cast<wchar_t>(std::towupper(root[0]));
            root[2] = L'\\';
            std::array<wchar_t, MAX_PATH + 1> volumeName{};
            if (GetDriveTypeW(root.c_str()) != DRIVE_FIXED ||
                !GetVolumeNameForVolumeMountPointW(root.c_str(), volumeName.data(),
                    static_cast<DWORD>(volumeName.size())) ||
                !IsRegisteredVolumeRoot(root, volumeName.data()))
                return false;

            std::wstring current = root;
#ifndef _DEBUG
            if (!OpenDirectory(current, directory.size() == root.size()))
                return false;
#endif
            size_t position = 3;
            while (position < directory.size())
            {
                while (position < directory.size() &&
                    (directory[position] == L'\\' || directory[position] == L'/'))
                    ++position;
                if (position >= directory.size())
                    break;
                const size_t separator = directory.find_first_of(L"\\/", position);
                const std::wstring component = directory.substr(position,
                    separator == std::wstring::npos ? std::wstring::npos : separator - position);
                if (component.empty() || component == L"." || component == L"..")
                    return false;
                if (current.back() != L'\\')
                    current.push_back(L'\\');
                current.append(component);
                const bool isPayloadDirectory = separator == std::wstring::npos;
                if (!OpenDirectory(current, isPayloadDirectory))
                    return false;
                if (separator == std::wstring::npos)
                    break;
                position = separator + 1;
            }
            return true;
        }

        bool Open(const std::wstring& path, HANDLE& handle)
        {
            handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (handle == INVALID_HANDLE_VALUE)
                return false;

            BY_HANDLE_FILE_INFORMATION information{};
            if (!GetFileInformationByHandle(handle, &information) ||
                (information.dwFileAttributes &
                    (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
            {
                CloseHandle(handle);
                handle = INVALID_HANDLE_VALUE;
                return false;
            }
#ifndef _DEBUG
            if (!HasProtectedSecurity(handle, kPayloadDangerousRights, false))
            {
                CloseHandle(handle);
                handle = INVALID_HANDLE_VALUE;
                return false;
            }
#endif
            handles_.push_back(handle);
            return true;
        }

    private:
        static bool IsRegisteredVolumeRoot(const std::wstring& root, const wchar_t* volumeName)
        {
            std::vector<wchar_t> volumePaths(MAX_PATH + 1, L'\0');
            for (;;)
            {
                DWORD requiredLength = 0;
                if (GetVolumePathNamesForVolumeNameW(volumeName, volumePaths.data(),
                        static_cast<DWORD>(volumePaths.size()), &requiredLength))
                    break;

                if (GetLastError() != ERROR_MORE_DATA || requiredLength <= volumePaths.size())
                    return false;
                volumePaths.assign(requiredLength, L'\0');
            }

            const wchar_t* registeredPath = volumePaths.data();
            while (*registeredPath != L'\0')
            {
                if (_wcsicmp(registeredPath, root.c_str()) == 0)
                    return true;
                registeredPath += wcslen(registeredPath) + 1;
            }
            return false;
        }

        bool OpenDirectory(const std::wstring& path, bool isPayloadDirectory)
        {
            const HANDLE handle = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (handle == INVALID_HANDLE_VALUE)
                return false;

            BY_HANDLE_FILE_INFORMATION information{};
            if (!GetFileInformationByHandle(handle, &information) ||
                (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                CloseHandle(handle);
                return false;
            }
#ifndef _DEBUG
            const ACCESS_MASK dangerousRights = isPayloadDirectory
                ? kPayloadDangerousRights
                : kAncestorDangerousRights;
            if (!HasProtectedSecurity(handle, dangerousRights, isPayloadDirectory))
            {
                CloseHandle(handle);
                return false;
            }
#else
            (void)isPayloadDirectory;
#endif
            handles_.push_back(handle);
            return true;
        }

        std::vector<HANDLE> handles_;
    };

    std::wstring JoinPath(const std::wstring& directory, const wchar_t* name)
    {
        return directory + L"\\" + name;
    }

    std::wstring GetExecutablePath()
    {
        std::vector<wchar_t> buffer(512);
        for (;;)
        {
            const DWORD length = GetModuleFileNameW(nullptr, buffer.data(),
                static_cast<DWORD>(buffer.size()));
            if (length == 0)
                return {};
            if (length < buffer.size() - 1)
                return std::wstring(buffer.data(), length);
            buffer.resize(buffer.size() * 2);
        }
    }

    bool GetExecutableDirectory(const std::wstring& executablePath, std::wstring& directory)
    {
        const auto separator = executablePath.find_last_of(L"\\/");
        if (separator == std::wstring::npos || separator == 0)
            return false;
        directory = executablePath.substr(0, separator);
        return true;
    }

    Module LoadSystemModule(const wchar_t* name)
    {
        std::array<wchar_t, MAX_PATH + 1> systemDirectory{};
        const UINT length = GetSystemDirectoryW(systemDirectory.data(),
            static_cast<UINT>(systemDirectory.size()));
        if (length == 0 || length >= systemDirectory.size())
            return Module();
        const std::wstring path = JoinPath(std::wstring(systemDirectory.data(), length), name);
        return Module(LoadLibraryExW(path.c_str(), nullptr, kLoadWithAlteredSearchPath));
    }

    bool ConfigureNativeSearchPath()
    {
        using SetDefaultDllDirectoriesFunction = BOOL(WINAPI*)(DWORD);
        const auto kernel = GetModuleHandleW(L"kernel32.dll");
        const auto function = reinterpret_cast<SetDefaultDllDirectoriesFunction>(
            GetProcAddress(kernel, "SetDefaultDllDirectories"));
        return function == nullptr || function(kLoadLibrarySearchSystem32) != FALSE;
    }

    bool StartsWith(const std::wstring& value, const wchar_t* prefix)
    {
        const size_t length = wcslen(prefix);
        return value.size() >= length && value.compare(0, length, prefix) == 0;
    }

    bool IsClrControlVariable(const std::wstring& name)
    {
        std::wstring upper(name);
        std::transform(upper.begin(), upper.end(), upper.begin(),
            [](wchar_t value) { return static_cast<wchar_t>(towupper(value)); });
        return StartsWith(upper, L"COR_") || StartsWith(upper, L"COMPLUS_") ||
               StartsWith(upper, L"CORECLR_") || StartsWith(upper, L"DOTNET_") ||
               StartsWith(upper, L"_DOTNET_") ||
               upper == L"APPDOMAIN_MANAGER_ASM" ||
               upper == L"APPDOMAIN_MANAGER_TYPE";
    }

    bool SanitizeClrEnvironment()
    {
        const LPWCH environment = GetEnvironmentStringsW();
        if (environment == nullptr)
            return false;
        std::vector<std::wstring> names;
        for (const wchar_t* current = environment; *current != L'\0';
             current += wcslen(current) + 1)
        {
            const std::wstring entry(current);
            const size_t equals = entry.find(L'=', entry.empty() || entry[0] != L'=' ? 0 : 1);
            if (equals != std::wstring::npos)
            {
                const std::wstring name = entry.substr(0, equals);
                if (IsClrControlVariable(name))
                    names.push_back(name);
            }
        }
        FreeEnvironmentStringsW(environment);
        for (const auto& name : names)
        {
            if (!SetEnvironmentVariableW(name.c_str(), nullptr))
                return false;
        }
        return true;
    }

    class Sha256 final
    {
    public:
        Sha256()
            : module_(LoadSystemModule(L"bcrypt.dll"))
        {
            if (!module_)
                return;
            open_ = Get<OpenFunction>("BCryptOpenAlgorithmProvider");
            close_ = Get<CloseFunction>("BCryptCloseAlgorithmProvider");
            getProperty_ = Get<GetPropertyFunction>("BCryptGetProperty");
            create_ = Get<CreateFunction>("BCryptCreateHash");
            hash_ = Get<HashFunction>("BCryptHashData");
            finish_ = Get<FinishFunction>("BCryptFinishHash");
            destroy_ = Get<DestroyFunction>("BCryptDestroyHash");
        }

        bool IsAvailable() const
        {
            return open_ && close_ && getProperty_ && create_ && hash_ && finish_ && destroy_;
        }

        bool HashFile(HANDLE file, std::array<BYTE, 32>& result) const
        {
            if (!IsAvailable())
                return false;
            LARGE_INTEGER beginning{};
            if (!SetFilePointerEx(file, beginning, nullptr, FILE_BEGIN))
                return false;

            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_HASH_HANDLE hashHandle = nullptr;
            std::vector<BYTE> object;
            bool success = false;
            if (open_(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
                return false;
            ULONG objectLength = 0;
            ULONG copied = 0;
            if (getProperty_(algorithm, BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &copied, 0) >= 0)
            {
                object.resize(objectLength);
                if (create_(algorithm, &hashHandle, object.data(), objectLength,
                        nullptr, 0, 0) >= 0)
                {
                    std::array<BYTE, 64 * 1024> buffer{};
                    success = true;
                    for (;;)
                    {
                        DWORD bytesRead = 0;
                        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()),
                                &bytesRead, nullptr))
                        {
                            success = false;
                            break;
                        }
                        if (bytesRead == 0)
                            break;
                        if (hash_(hashHandle, buffer.data(), bytesRead, 0) < 0)
                        {
                            success = false;
                            break;
                        }
                    }
                    if (success && finish_(hashHandle, result.data(),
                            static_cast<ULONG>(result.size()), 0) < 0)
                        success = false;
                }
            }
            if (hashHandle != nullptr)
                destroy_(hashHandle);
            close_(algorithm, 0);
            return success;
        }

    private:
        template<typename Function>
        Function Get(const char* name) const
        {
            return reinterpret_cast<Function>(GetProcAddress(module_.Get(), name));
        }

        using OpenFunction = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
        using CloseFunction = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE, ULONG);
        using GetPropertyFunction = NTSTATUS(WINAPI*)(BCRYPT_HANDLE, LPCWSTR, PUCHAR,
            ULONG, ULONG*, ULONG);
        using CreateFunction = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*,
            PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
        using HashFunction = NTSTATUS(WINAPI*)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
        using FinishFunction = NTSTATUS(WINAPI*)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
        using DestroyFunction = NTSTATUS(WINAPI*)(BCRYPT_HASH_HANDLE);

        Module module_;
        OpenFunction open_ = nullptr;
        CloseFunction close_ = nullptr;
        GetPropertyFunction getProperty_ = nullptr;
        CreateFunction create_ = nullptr;
        HashFunction hash_ = nullptr;
        FinishFunction finish_ = nullptr;
        DestroyFunction destroy_ = nullptr;
    };

    bool IsAllowedPortableExecutable(const std::wstring& name)
    {
        static const wchar_t* allowed[] = {
            L"ProxiFyreUI.exe", L"ProxiFyreUI.Managed.dll", L"ProxiFyre.exe",
            L"ProxiFyre.Configuration.dll", L"socksify.dll", L"Newtonsoft.Json.dll",
            L"NLog.dll", L"Topshelf.dll"
        };
        return std::any_of(std::begin(allowed), std::end(allowed),
            [&name](const wchar_t* candidate) { return _wcsicmp(name.c_str(), candidate) == 0; });
    }

    bool HasUnexpectedPortableExecutable(const std::wstring& directory)
    {
        WIN32_FIND_DATAW data{};
        const HANDLE search = FindFirstFileW(JoinPath(directory, L"*").c_str(), &data);
        if (search == INVALID_HANDLE_VALUE)
            return true;
        bool unexpected = false;
        do
        {
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                continue;
            std::wstring name(data.cFileName);
            std::wstring lower(name);
            std::transform(lower.begin(), lower.end(), lower.begin(),
                [](wchar_t value) { return static_cast<wchar_t>(towlower(value)); });
            if ((lower.size() >= 4 && lower.compare(lower.size() - 4, 4, L".dll") == 0) ||
                (lower.size() >= 4 && lower.compare(lower.size() - 4, 4, L".exe") == 0))
            {
                if (!IsAllowedPortableExecutable(name))
                {
                    unexpected = true;
                    break;
                }
            }
        } while (FindNextFileW(search, &data));
        FindClose(search);
        return unexpected;
    }

    bool HasUiLoaderRedirection(const std::wstring& directory)
    {
        return GetFileAttributesW(JoinPath(directory, L"ProxiFyreUI.exe.local").c_str()) !=
                   INVALID_FILE_ATTRIBUTES ||
               GetFileAttributesW(JoinPath(directory, L"ProxiFyreUI.exe.manifest").c_str()) !=
                   INVALID_FILE_ATTRIBUTES;
    }

    bool VerifyAndLeasePayload(const std::wstring& executablePath,
        const std::wstring& directory, LeaseSet& leases, std::wstring& managedAssembly)
    {
        // Pin every normal directory component without delete sharing before opening any
        // payload path. Otherwise a user-writable junction can be redirected after validation
        // and before the CLR reopens the managed assembly by name.
        if (!leases.OpenDirectoryChain(directory))
            return false;
        const auto executableNameOffset = executablePath.find_last_of(L"\\/");
        const std::wstring executableName = executableNameOffset == std::wstring::npos
            ? executablePath
            : executablePath.substr(executableNameOffset + 1);
        if (_wcsicmp(executableName.c_str(), L"ProxiFyreUI.exe") != 0 ||
            HasUiLoaderRedirection(directory) || HasUnexpectedPortableExecutable(directory))
            return false;
#ifndef _DEBUG
        // The running launcher is part of the same elevated code boundary. Inspect and lease
        // its directory entry as well so a permissive per-file ACL cannot bypass a protected
        // parent directory.
        HANDLE launcherHandle = INVALID_HANDLE_VALUE;
        if (!leases.Open(executablePath, launcherHandle))
            return false;
#endif
        // ProxiFyre releases are deliberately unsigned. Require and lease the complete managed
        // startup chain, while the installer-protected directory and module allow-list prevent
        // app-local code from being added or replaced during startup.
        const wchar_t* requiredManagedFiles[] = {
            L"ProxiFyreUI.Managed.dll", L"ProxiFyre.Configuration.dll", L"Newtonsoft.Json.dll"
        };
        for (const auto name : requiredManagedFiles)
        {
            const std::wstring path = JoinPath(directory, name);
            HANDLE handle = INVALID_HANDLE_VALUE;
            if (!leases.Open(path, handle))
                return false;
            if (wcscmp(name, L"ProxiFyreUI.Managed.dll") == 0)
                managedAssembly = path;
        }

        const std::wstring configuration = JoinPath(directory, L"ProxiFyreUI.exe.config");
        HANDLE configurationHandle = INVALID_HANDLE_VALUE;
        if (!leases.Open(configuration, configurationHandle))
            return false;
#ifndef _DEBUG
        const Sha256 sha256;
        if (!sha256.IsAvailable())
            return false;
        std::array<BYTE, 32> configurationHash{};
        if (!sha256.HashFile(configurationHandle, configurationHash) ||
            configurationHash != kExpectedUiConfigurationSha256)
            return false;
#endif
        return !managedAssembly.empty();
    }

    const wchar_t* GetManagedUiStageName(ManagedUiStage stage)
    {
        switch (stage)
        {
        case ManagedUiStage::LoadMscoree: return L"Load mscoree.dll";
        case ManagedUiStage::ResolveClrCreateInstance: return L"Resolve CLRCreateInstance";
        case ManagedUiStage::CreateMetaHost: return L"Create CLR meta-host";
        case ManagedUiStage::GetRuntime: return L"Locate CLR v4.0.30319";
        case ManagedUiStage::IsLoadable: return L"Validate CLR loadability";
        case ManagedUiStage::GetRuntimeHost: return L"Create CLR runtime host";
        case ManagedUiStage::StartRuntime: return L"Start CLR";
        case ManagedUiStage::ExecuteEntryPoint: return L"Execute managed entry point";
        default: return L"Unknown CLR stage";
        }
    }

    bool TryGetNetFrameworkRelease(DWORD& release)
    {
        release = 0;
        HKEY key = nullptr;
        const LONG opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full", 0,
            KEY_QUERY_VALUE | KEY_WOW64_32KEY, &key);
        if (opened != ERROR_SUCCESS)
            return false;

        DWORD type = 0;
        DWORD size = sizeof(release);
        const LONG queried = RegQueryValueExW(key, L"Release", nullptr, &type,
            reinterpret_cast<BYTE*>(&release), &size);
        RegCloseKey(key);
        return queried == ERROR_SUCCESS && type == REG_DWORD && size == sizeof(release);
    }

    HRESULT RunManagedUi(const std::wstring& managedAssembly, DWORD& returnValue,
        ManagedUiStage& failedStage)
    {
        failedStage = ManagedUiStage::LoadMscoree;
        using ClrCreateInstanceFunction = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, LPVOID*);
        Module mscoree = LoadSystemModule(L"mscoree.dll");
        if (!mscoree)
            return HRESULT_FROM_WIN32(GetLastError());
        failedStage = ManagedUiStage::ResolveClrCreateInstance;
        const auto createInstance = reinterpret_cast<ClrCreateInstanceFunction>(
            GetProcAddress(mscoree.Get(), "CLRCreateInstance"));
        if (createInstance == nullptr)
            return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);

        ICLRMetaHost* metaHost = nullptr;
        ICLRRuntimeInfo* runtimeInfo = nullptr;
        ICLRRuntimeHost* runtimeHost = nullptr;
        failedStage = ManagedUiStage::CreateMetaHost;
        HRESULT result = createInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost,
            reinterpret_cast<void**>(&metaHost));
        if (SUCCEEDED(result))
        {
            failedStage = ManagedUiStage::GetRuntime;
            result = metaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo,
                reinterpret_cast<void**>(&runtimeInfo));
        }
        BOOL loadable = FALSE;
        if (SUCCEEDED(result))
        {
            failedStage = ManagedUiStage::IsLoadable;
            result = runtimeInfo->IsLoadable(&loadable);
        }
        if (SUCCEEDED(result) && !loadable)
            result = HRESULT_FROM_WIN32(ERROR_BAD_ENVIRONMENT);
        if (SUCCEEDED(result))
        {
            failedStage = ManagedUiStage::GetRuntimeHost;
            result = runtimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost,
                reinterpret_cast<void**>(&runtimeHost));
        }
        if (SUCCEEDED(result))
        {
            failedStage = ManagedUiStage::StartRuntime;
            result = runtimeHost->Start();
        }
        if (SUCCEEDED(result))
        {
            failedStage = ManagedUiStage::ExecuteEntryPoint;
            result = runtimeHost->ExecuteInDefaultAppDomain(managedAssembly.c_str(),
                L"ProxiFyreUI.ManagedEntryPoint", L"Run", L"", &returnValue);
        }

        if (runtimeHost != nullptr)
            runtimeHost->Release();
        if (runtimeInfo != nullptr)
            runtimeInfo->Release();
        if (metaHost != nullptr)
            metaHost->Release();
        if (SUCCEEDED(result))
            failedStage = ManagedUiStage::None;
        return result;
    }

    void ShowFailure(const wchar_t* message)
    {
        MessageBoxW(nullptr, message, L"ProxiFyre UI", MB_OK | MB_ICONERROR | MB_TASKMODAL);
    }

    void ShowManagedHostFailure(ManagedUiStage stage, HRESULT result)
    {
        wchar_t resultText[16]{};
        swprintf_s(resultText, L"0x%08lX", static_cast<unsigned long>(result));
        std::wstring message =
            L"The validated ProxiFyre managed UI could not be started.\r\n\r\nStage: ";
        message += GetManagedUiStageName(stage);
        message += L"\r\nHRESULT: ";
        message += resultText;

        DWORD release = 0;
        if (TryGetNetFrameworkRelease(release))
        {
            wchar_t releaseText[16]{};
            swprintf_s(releaseText, L"%lu", static_cast<unsigned long>(release));
            message += L"\r\n.NET Framework Release: ";
            message += releaseText;
        }
        else
        {
            message += L"\r\n.NET Framework Release: not found";
        }
        message += L"\r\n\r\nRepair or install .NET Framework 4.7.2 or later only if the reported release is missing or older than 461808.";
        ShowFailure(message.c_str());
    }

    void ShowManagedEntryPointFailure(DWORD result)
    {
        wchar_t resultText[16]{};
        swprintf_s(resultText, L"0x%08lX", static_cast<unsigned long>(result));
        std::wstring message =
            L"The CLR started, but the ProxiFyre UI reported a managed startup failure.\r\n\r\nManaged result: ";
        message += resultText;
        message += L"\r\n\r\nReview ProxiFyreUI.startup.log in the installation directory if it was created.";
        ShowFailure(message.c_str());
    }
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    if (!ConfigureNativeSearchPath())
    {
        ShowFailure(L"Windows could not establish a secure system DLL search path.");
        return ERROR_INVALID_FUNCTION;
    }
    if (!SanitizeClrEnvironment())
    {
        ShowFailure(L"Windows could not sanitize the CLR startup environment.");
        return ERROR_ENVVAR_NOT_FOUND;
    }

    const std::wstring executablePath = GetExecutablePath();
    std::wstring directory;
    LeaseSet leases;
    std::wstring managedAssembly;
    if (executablePath.empty() || !GetExecutableDirectory(executablePath, directory) ||
        !VerifyAndLeasePayload(executablePath, directory, leases, managedAssembly))
    {
#ifdef _DEBUG
        ShowFailure(L"The ProxiFyre UI payload is incomplete, contains an unexpected executable module, or failed its fixed integrity checks.");
#else
        ShowFailure(L"The ProxiFyre UI payload is incomplete, contains an unexpected executable module, failed its fixed integrity checks, or is not in a protected per-machine directory. Install it with the official setup. A Release ZIP must be placed in an administrator-protected fixed-volume directory before the elevated GUI can run.");
#endif
        return ERROR_INVALID_DATA;
    }

    const HRESULT apartment = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(apartment))
    {
        ShowFailure(L"Windows could not initialize the ProxiFyre UI thread.");
        return static_cast<int>(apartment);
    }

    DWORD managedResult = 0;
    ManagedUiStage failedStage = ManagedUiStage::None;
    const HRESULT result = RunManagedUi(managedAssembly, managedResult, failedStage);
    CoUninitialize();
    if (FAILED(result))
    {
        ShowManagedHostFailure(failedStage, result);
        return static_cast<int>(result);
    }
    if (managedResult != 0)
    {
        ShowManagedEntryPointFailure(managedResult);
        return static_cast<int>(managedResult);
    }
    return static_cast<int>(managedResult);
}
