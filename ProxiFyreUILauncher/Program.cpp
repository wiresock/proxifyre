#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <metahost.h>
#include <softpub.h>
#include <VersionHelpers.h>
#include <wintrust.h>

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
    constexpr DWORD kTrustUiNone = 2;
    constexpr DWORD kRevokeNone = 0;
    constexpr DWORD kChoiceFile = 1;
    constexpr DWORD kStateActionVerify = 1;
    constexpr DWORD kStateActionClose = 2;
    constexpr DWORD kCacheOnlyUrlRetrieval = 0x00001000;
    constexpr DWORD kVerifySpecificSignature = 0x00000001;
    constexpr DWORD kGetSecondarySignatureCount = 0x00000002;
    constexpr DWORD kMaximumSecondarySignatures = 16;

    constexpr std::array<BYTE, 32> kExpectedPublicKeySha256 = {
        0x07, 0xD1, 0x2F, 0x0A, 0xBE, 0xA8, 0x0E, 0x9A,
        0x9A, 0x71, 0x89, 0x9B, 0x68, 0xE1, 0xB6, 0xCB,
        0x94, 0x0E, 0x58, 0xB2, 0xCA, 0xF3, 0x78, 0x74,
        0xCD, 0x0A, 0x62, 0xEB, 0x2E, 0x2E, 0x4C, 0x5A
    };

    constexpr std::array<BYTE, 32> kExpectedUiConfigurationSha256 = {
        0xEC, 0xEB, 0x47, 0x26, 0x9D, 0xB5, 0xD3, 0xE2,
        0x27, 0x28, 0xF6, 0xDC, 0x60, 0xEC, 0x05, 0x45,
        0x07, 0x83, 0xF8, 0xB3, 0xC2, 0x90, 0x74, 0x66,
        0x68, 0x37, 0xB3, 0xE7, 0x63, 0xE8, 0xF4, 0xA6
    };

    struct TrustFileInfo
    {
        DWORD StructSize;
        LPCWSTR FilePath;
        HANDLE FileHandle;
        GUID* KnownSubject;
    };

    struct TrustSignatureSettings
    {
        DWORD StructSize;
        DWORD Index;
        DWORD Flags;
        DWORD SecondarySignatureCount;
        DWORD VerifiedSignatureIndex;
        void* CryptoPolicy;
    };

    struct TrustData
    {
        DWORD StructSize;
        void* PolicyCallbackData;
        void* SipClientData;
        DWORD UiChoice;
        DWORD RevocationChecks;
        DWORD UnionChoice;
        void* FileInfo;
        DWORD StateAction;
        HANDLE StateData;
        LPCWSTR UrlReference;
        DWORD ProviderFlags;
        DWORD UiContext;
        TrustSignatureSettings* SignatureSettings;
    };

    struct LegacyTrustData
    {
        DWORD StructSize;
        void* PolicyCallbackData;
        void* SipClientData;
        DWORD UiChoice;
        DWORD RevocationChecks;
        DWORD UnionChoice;
        void* FileInfo;
        DWORD StateAction;
        HANDLE StateData;
        LPCWSTR UrlReference;
        DWORD ProviderFlags;
        DWORD UiContext;
    };

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
                if (!OpenDirectory(current))
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

        bool OpenDirectory(const std::wstring& path)
        {
            const HANDLE handle = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
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
            handles_.push_back(handle);
            return true;
        }

        std::vector<HANDLE> handles_;
    };

    std::wstring JoinPath(const std::wstring& directory, const wchar_t* name)
    {
        return directory + L"\\" + name;
    }

    std::wstring GetExecutableDirectory()
    {
        std::vector<wchar_t> buffer(512);
        for (;;)
        {
            const DWORD length = GetModuleFileNameW(nullptr, buffer.data(),
                static_cast<DWORD>(buffer.size()));
            if (length == 0)
                return {};
            if (length < buffer.size() - 1)
            {
                std::wstring path(buffer.data(), length);
                const auto separator = path.find_last_of(L"\\/");
                return separator == std::wstring::npos ? std::wstring() : path.substr(0, separator);
            }
            buffer.resize(buffer.size() * 2);
        }
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

        bool HashBuffer(const BYTE* data, ULONG length, std::array<BYTE, 32>& result) const
        {
            if (!IsAvailable())
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
                        nullptr, 0, 0) >= 0 &&
                    hash_(hashHandle, const_cast<PUCHAR>(data), length, 0) >= 0 &&
                    finish_(hashHandle, result.data(), static_cast<ULONG>(result.size()), 0) >= 0)
                    success = true;
            }
            if (hashHandle != nullptr)
                destroy_(hashHandle);
            close_(algorithm, 0);
            return success;
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

    class AuthenticodeVerifier final
    {
    public:
        explicit AuthenticodeVerifier(const Sha256& sha256)
            : sha256_(sha256), module_(LoadSystemModule(L"wintrust.dll"))
        {
            if (!module_)
                return;
            verify_ = Get<VerifyFunction>("WinVerifyTrust");
            providerData_ = Get<ProviderDataFunction>("WTHelperProvDataFromStateData");
            providerSigner_ = Get<ProviderSignerFunction>("WTHelperGetProvSignerFromChain");
            providerCertificate_ = Get<ProviderCertificateFunction>("WTHelperGetProvCertFromChain");
        }

        bool Verify(const std::wstring& path, HANDLE fileHandle) const
        {
            if (!verify_ || !providerData_ || !providerSigner_ || !providerCertificate_)
                return false;
            if (!IsWindows8OrGreater())
                return VerifyLegacy(path, fileHandle);

            DWORD secondaryCount = 0;
            if (VerifyModern(path, fileHandle, 0, true, secondaryCount))
                return true;
            if (secondaryCount > kMaximumSecondarySignatures)
                return false;
            for (DWORD index = 1; index <= secondaryCount; ++index)
            {
                DWORD ignored = 0;
                if (VerifyModern(path, fileHandle, index, false, ignored))
                    return true;
            }
            return false;
        }

    private:
        template<typename Function>
        Function Get(const char* name) const
        {
            return reinterpret_cast<Function>(GetProcAddress(module_.Get(), name));
        }

        bool IsExpectedSigner(HANDLE state) const
        {
            if (state == nullptr)
                return false;
            const auto data = providerData_(state);
            if (data == nullptr)
                return false;
            const auto signer = providerSigner_(data, 0, FALSE, 0);
            if (signer == nullptr)
                return false;
            const auto providerCertificate = providerCertificate_(signer, 0);
            if (providerCertificate == nullptr || providerCertificate->pCert == nullptr ||
                providerCertificate->pCert->pCertInfo == nullptr)
                return false;
            const auto& publicKey = providerCertificate->pCert->pCertInfo->
                SubjectPublicKeyInfo.PublicKey;
            std::array<BYTE, 32> hash{};
            return publicKey.pbData != nullptr &&
                   sha256_.HashBuffer(publicKey.pbData, publicKey.cbData, hash) &&
                   hash == kExpectedPublicKeySha256;
        }

        bool VerifyModern(const std::wstring& path, HANDLE fileHandle, DWORD index,
            bool getCount, DWORD& secondaryCount) const
        {
            TrustFileInfo fileInfo{ sizeof(fileInfo), path.c_str(), fileHandle, nullptr };
            TrustSignatureSettings signatureSettings{};
            signatureSettings.StructSize = sizeof(signatureSettings);
            signatureSettings.Index = index;
            signatureSettings.Flags = kVerifySpecificSignature |
                (getCount ? kGetSecondarySignatureCount : 0);
            TrustData data{};
            data.StructSize = sizeof(data);
            data.UiChoice = kTrustUiNone;
            data.RevocationChecks = kRevokeNone;
            data.UnionChoice = kChoiceFile;
            data.FileInfo = &fileInfo;
            data.StateAction = kStateActionVerify;
            data.ProviderFlags = kCacheOnlyUrlRetrieval;
            data.SignatureSettings = &signatureSettings;

            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            const LONG result = verify_(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE),
                &action, &data);
            secondaryCount = getCount ? signatureSettings.SecondarySignatureCount : 0;
            const bool valid = result == ERROR_SUCCESS &&
                signatureSettings.VerifiedSignatureIndex == index &&
                IsExpectedSigner(data.StateData);
            data.StateAction = kStateActionClose;
            verify_(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
            return valid;
        }

        bool VerifyLegacy(const std::wstring& path, HANDLE fileHandle) const
        {
            TrustFileInfo fileInfo{ sizeof(fileInfo), path.c_str(), fileHandle, nullptr };
            LegacyTrustData data{};
            data.StructSize = sizeof(data);
            data.UiChoice = kTrustUiNone;
            data.RevocationChecks = kRevokeNone;
            data.UnionChoice = kChoiceFile;
            data.FileInfo = &fileInfo;
            data.StateAction = kStateActionVerify;
            data.ProviderFlags = kCacheOnlyUrlRetrieval;

            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            const LONG result = verify_(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE),
                &action, &data);
            const bool valid = result == ERROR_SUCCESS && IsExpectedSigner(data.StateData);
            data.StateAction = kStateActionClose;
            verify_(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
            return valid;
        }

        using VerifyFunction = LONG(WINAPI*)(HWND, GUID*, void*);
        using ProviderDataFunction = CRYPT_PROVIDER_DATA*(WINAPI*)(HANDLE);
        using ProviderSignerFunction = CRYPT_PROVIDER_SGNR*(WINAPI*)(CRYPT_PROVIDER_DATA*,
            DWORD, BOOL, DWORD);
        using ProviderCertificateFunction = CRYPT_PROVIDER_CERT*(WINAPI*)(
            CRYPT_PROVIDER_SGNR*, DWORD);

        const Sha256& sha256_;
        Module module_;
        VerifyFunction verify_ = nullptr;
        ProviderDataFunction providerData_ = nullptr;
        ProviderSignerFunction providerSigner_ = nullptr;
        ProviderCertificateFunction providerCertificate_ = nullptr;
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

    bool VerifyAndLeasePayload(const std::wstring& directory, LeaseSet& leases,
        std::wstring& managedAssembly)
    {
        // Pin every normal directory component without delete sharing before opening any
        // payload path. Otherwise a user-writable junction can be redirected after signature
        // verification and before the CLR reopens the managed assembly by name.
        if (!leases.OpenDirectoryChain(directory))
            return false;
        if (HasUnexpectedPortableExecutable(directory))
            return false;
        const Sha256 sha256;
        if (!sha256.IsAvailable())
            return false;
        const AuthenticodeVerifier authenticode(sha256);
        const wchar_t* signedFiles[] = {
            L"ProxiFyreUI.Managed.dll", L"ProxiFyre.Configuration.dll", L"Newtonsoft.Json.dll"
        };
        for (const auto name : signedFiles)
        {
            const std::wstring path = JoinPath(directory, name);
            HANDLE handle = INVALID_HANDLE_VALUE;
            if (!leases.Open(path, handle))
                return false;
#ifndef _DEBUG
            if (!authenticode.Verify(path, handle))
                return false;
#endif
            if (wcscmp(name, L"ProxiFyreUI.Managed.dll") == 0)
                managedAssembly = path;
        }

        const std::wstring configuration = JoinPath(directory, L"ProxiFyreUI.exe.config");
        HANDLE configurationHandle = INVALID_HANDLE_VALUE;
        if (!leases.Open(configuration, configurationHandle))
            return false;
#ifndef _DEBUG
        std::array<BYTE, 32> configurationHash{};
        if (!sha256.HashFile(configurationHandle, configurationHash) ||
            configurationHash != kExpectedUiConfigurationSha256)
            return false;
#endif
        return !managedAssembly.empty();
    }

    HRESULT RunManagedUi(const std::wstring& managedAssembly, DWORD& returnValue)
    {
        using ClrCreateInstanceFunction = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, LPVOID*);
        Module mscoree = LoadSystemModule(L"mscoree.dll");
        if (!mscoree)
            return HRESULT_FROM_WIN32(GetLastError());
        const auto createInstance = reinterpret_cast<ClrCreateInstanceFunction>(
            GetProcAddress(mscoree.Get(), "CLRCreateInstance"));
        if (createInstance == nullptr)
            return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);

        ICLRMetaHost* metaHost = nullptr;
        ICLRRuntimeInfo* runtimeInfo = nullptr;
        ICLRRuntimeHost* runtimeHost = nullptr;
        HRESULT result = createInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost,
            reinterpret_cast<void**>(&metaHost));
        if (SUCCEEDED(result))
            result = metaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo,
                reinterpret_cast<void**>(&runtimeInfo));
        BOOL loadable = FALSE;
        if (SUCCEEDED(result))
            result = runtimeInfo->IsLoadable(&loadable);
        if (SUCCEEDED(result) && !loadable)
            result = HRESULT_FROM_WIN32(ERROR_BAD_ENVIRONMENT);
        if (SUCCEEDED(result))
            result = runtimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost,
                reinterpret_cast<void**>(&runtimeHost));
        if (SUCCEEDED(result))
            result = runtimeHost->Start();
        if (SUCCEEDED(result))
            result = runtimeHost->ExecuteInDefaultAppDomain(managedAssembly.c_str(),
                L"ProxiFyreUI.ManagedEntryPoint", L"Run", L"", &returnValue);

        if (runtimeHost != nullptr)
            runtimeHost->Release();
        if (runtimeInfo != nullptr)
            runtimeInfo->Release();
        if (metaHost != nullptr)
            metaHost->Release();
        return result;
    }

    void ShowFailure(const wchar_t* message)
    {
        MessageBoxW(nullptr, message, L"ProxiFyre UI", MB_OK | MB_ICONERROR | MB_TASKMODAL);
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

    const std::wstring directory = GetExecutableDirectory();
    LeaseSet leases;
    std::wstring managedAssembly;
    if (directory.empty() || !VerifyAndLeasePayload(directory, leases, managedAssembly))
    {
        ShowFailure(L"The ProxiFyre UI payload is incomplete, contains an unexpected executable module, or failed its release integrity check. Reinstall it from an official signed archive.");
        return ERROR_INVALID_DATA;
    }

    const HRESULT apartment = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(apartment))
    {
        ShowFailure(L"Windows could not initialize the ProxiFyre UI thread.");
        return static_cast<int>(apartment);
    }

    DWORD managedResult = 0;
    const HRESULT result = RunManagedUi(managedAssembly, managedResult);
    CoUninitialize();
    if (FAILED(result))
    {
        ShowFailure(L"The verified ProxiFyre managed UI could not be started. Ensure .NET Framework 4.7.2 is installed.");
        return static_cast<int>(result);
    }
    return static_cast<int>(managedResult);
}
