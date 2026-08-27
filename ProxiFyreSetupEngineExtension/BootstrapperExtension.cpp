#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>

#include <cstdio>
#include <cstring>
#include <new>
#include <type_traits>

#include "BootstrapperExtensionTypes.h"

namespace
{
    constexpr wchar_t kInternetSettingsKey[] =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    constexpr wchar_t kInternetSettingsPolicyKey[] =
        L"Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    constexpr wchar_t kInternetConnectionsKey[] =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections";
    constexpr DWORD kConnectionBlobMarkerLegacy = 0x3C;
    constexpr DWORD kConnectionBlobMarkerCurrent = 0x46;
    constexpr DWORD kMaximumConnectionBlobBytes = 64 * 1024;
    constexpr DWORD kKnownProxyRouteFlags = PROXY_TYPE_DIRECT |
        PROXY_TYPE_PROXY | PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_AUTO_DETECT;

    PFN_BOOTSTRAPPER_EXTENSION_ENGINE_PROC g_engineProc = nullptr;
    LPVOID g_engineContext = nullptr;

    void Log(BOOTSTRAPPER_EXTENSION_LOG_LEVEL level, const wchar_t* message)
    {
        if (g_engineProc == nullptr || message == nullptr)
            return;

        BOOTSTRAPPER_EXTENSION_ENGINE_LOG_ARGS arguments{};
        arguments.cbSize = sizeof(arguments);
        arguments.level = level;
        arguments.wzMessage = message;

        BOOTSTRAPPER_EXTENSION_ENGINE_LOG_RESULTS results{};
        results.cbSize = sizeof(results);
        (void)g_engineProc(BOOTSTRAPPER_EXTENSION_ENGINE_MESSAGE_LOG,
            &arguments, &results, g_engineContext);
    }

    void LogWin32Failure(const wchar_t* operation, DWORD error)
    {
        wchar_t message[384]{};
        (void)_snwprintf_s(message, sizeof(message) / sizeof(message[0]), _TRUNCATE,
            L"ProxiFyre setup WinINet compatibility check could not %ls "
            L"(error 0x%08lX); leaving Burn's normal proxy behavior unchanged.",
            operation, static_cast<unsigned long>(error));
        Log(BOOTSTRAPPER_EXTENSION_LOG_LEVEL_ERROR, message);
    }

    bool QueryPerConnectionDword(DWORD optionId, DWORD* value)
    {
        INTERNET_PER_CONN_OPTIONW option{};
        option.dwOption = optionId;

        INTERNET_PER_CONN_OPTION_LISTW list{};
        list.dwSize = sizeof(list);
        list.pszConnection = nullptr;
        list.dwOptionCount = 1;
        list.pOptions = &option;

        DWORD size = sizeof(list);
        if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION,
                &list, &size))
        {
            return false;
        }

        *value = option.Value.dwValue;
        return true;
    }

    bool QueryPerConnectionStringIsEmpty(DWORD optionId, bool* empty)
    {
        INTERNET_PER_CONN_OPTIONW option{};
        option.dwOption = optionId;

        INTERNET_PER_CONN_OPTION_LISTW list{};
        list.dwSize = sizeof(list);
        list.pszConnection = nullptr;
        list.dwOptionCount = 1;
        list.pOptions = &option;

        DWORD size = sizeof(list);
        const BOOL queried = InternetQueryOptionW(nullptr,
            INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &size);
        const DWORD error = queried ? ERROR_SUCCESS : GetLastError();

        if (queried)
        {
            *empty = option.Value.pszValue == nullptr ||
                option.Value.pszValue[0] == L'\0';
        }

        if (option.Value.pszValue != nullptr)
            GlobalFree(option.Value.pszValue);

        if (!queried)
        {
            SetLastError(error);
            return false;
        }

        return true;
    }

    bool QueryPerUserProxyDisabled(bool* disabled)
    {
        DWORD proxyEnabled = 0;
        DWORD size = sizeof(proxyEnabled);
        const LSTATUS status = RegGetValueW(HKEY_CURRENT_USER,
            kInternetSettingsKey, L"ProxyEnable", RRF_RT_REG_DWORD, nullptr,
            &proxyEnabled, &size);
        if (status != ERROR_SUCCESS)
        {
            SetLastError(status);
            return false;
        }

        *disabled = size == sizeof(proxyEnabled) && proxyEnabled == 0;
        return true;
    }

    bool QueryRawInternetSettingStringIsEmpty(
        const wchar_t* valueName,
        bool* empty)
    {
        DWORD type = REG_NONE;
        DWORD size = 0;
        LSTATUS status = RegGetValueW(HKEY_CURRENT_USER, kInternetSettingsKey,
            valueName, RRF_RT_REG_SZ, &type, nullptr, &size);
        if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
        {
            *empty = true;
            return true;
        }
        if (status != ERROR_SUCCESS || type != REG_SZ)
        {
            SetLastError(status == ERROR_SUCCESS ? ERROR_INVALID_DATA : status);
            return false;
        }
        if (size != sizeof(wchar_t))
        {
            *empty = false;
            return true;
        }

        wchar_t value = L'\1';
        DWORD actualSize = size;
        status = RegGetValueW(HKEY_CURRENT_USER, kInternetSettingsKey,
            valueName, RRF_RT_REG_SZ, &type, &value, &actualSize);
        if (status != ERROR_SUCCESS || type != REG_SZ ||
            actualSize != sizeof(wchar_t))
        {
            SetLastError(status == ERROR_SUCCESS ? ERROR_INVALID_DATA : status);
            return false;
        }

        *empty = value == L'\0';
        return true;
    }

    bool QueryProxyPolicyAllowsPerUserSettings(bool* allowsPerUserSettings)
    {
        DWORD perUser = 0;
        DWORD size = sizeof(perUser);
        const LSTATUS status = RegGetValueW(HKEY_LOCAL_MACHINE,
            kInternetSettingsPolicyKey, L"ProxySettingsPerUser",
            RRF_RT_REG_DWORD, nullptr, &perUser, &size);
        if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
        {
            *allowsPerUserSettings = true;
            return true;
        }
        if (status != ERROR_SUCCESS)
        {
            SetLastError(status);
            return false;
        }

        // Only the documented per-user value is safe. Zero makes proxy
        // configuration machine-wide, while any other value is ambiguous.
        *allowsPerUserSettings = size == sizeof(perUser) && perUser == 1;
        return true;
    }

    bool QueryAutoDetectValue(bool* present, bool* enabled)
    {
        DWORD autoDetect = 0;
        DWORD size = sizeof(autoDetect);
        const LSTATUS status = RegGetValueW(HKEY_CURRENT_USER,
            kInternetSettingsKey, L"AutoDetect", RRF_RT_REG_DWORD, nullptr,
            &autoDetect, &size);
        if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
        {
            *present = false;
            *enabled = false;
            return true;
        }
        if (status != ERROR_SUCCESS || size != sizeof(autoDetect))
        {
            SetLastError(status == ERROR_SUCCESS ? ERROR_INVALID_DATA : status);
            return false;
        }

        *present = true;
        *enabled = autoDetect != 0;
        return true;
    }

    bool ReadBlobDword(const BYTE* value, DWORD size, DWORD offset, DWORD* result)
    {
        if (value == nullptr || result == nullptr || offset > size ||
            size - offset < sizeof(*result))
        {
            return false;
        }

        std::memcpy(result, value + offset, sizeof(*result));
        return true;
    }

    bool ParseLengthPrefixedBlobString(
        const BYTE* value,
        DWORD size,
        DWORD* offset,
        bool* empty)
    {
        DWORD length = 0;
        if (offset == nullptr || empty == nullptr ||
            !ReadBlobDword(value, size, *offset, &length))
        {
            return false;
        }
        *offset += sizeof(length);
        if (length > size - *offset)
            return false;

        *empty = length == 0;
        *offset += length;
        return true;
    }

    bool QueryConnectionBlobDirectIntent(
        const wchar_t* valueName,
        bool* confirmsDirectIntent)
    {
        *confirmsDirectIntent = false;
        DWORD size = 0;
        LSTATUS status = RegGetValueW(HKEY_CURRENT_USER,
            kInternetConnectionsKey, valueName, RRF_RT_REG_BINARY, nullptr,
            nullptr, &size);
        if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
            return true;
        if (status != ERROR_SUCCESS || size < 12 ||
            size > kMaximumConnectionBlobBytes)
        {
            SetLastError(status == ERROR_SUCCESS ? ERROR_INVALID_DATA : status);
            return false;
        }

        auto value = new (std::nothrow) BYTE[size];
        if (value == nullptr)
        {
            SetLastError(ERROR_OUTOFMEMORY);
            return false;
        }

        DWORD actualSize = size;
        status = RegGetValueW(HKEY_CURRENT_USER, kInternetConnectionsKey,
            valueName, RRF_RT_REG_BINARY, nullptr, value, &actualSize);
        if (status != ERROR_SUCCESS || actualSize != size)
        {
            delete[] value;
            SetLastError(status == ERROR_SUCCESS ? ERROR_INVALID_DATA : status);
            return false;
        }

        DWORD marker = 0;
        DWORD rawFlags = 0;
        DWORD stringOffset = 12;
        bool rawProxyEmpty = false;
        bool rawBypassEmpty = false;
        bool rawAutoConfigUrlEmpty = false;
        const bool parsed = ReadBlobDword(value, actualSize, 0, &marker) &&
            ReadBlobDword(value, actualSize, 8, &rawFlags) &&
            ParseLengthPrefixedBlobString(value, actualSize, &stringOffset,
                &rawProxyEmpty) &&
            ParseLengthPrefixedBlobString(value, actualSize, &stringOffset,
                &rawBypassEmpty) &&
            ParseLengthPrefixedBlobString(value, actualSize, &stringOffset,
                &rawAutoConfigUrlEmpty);
        delete[] value;

        // The bypass string is parsed for bounds safety but is not a route.
        (void)rawBypassEmpty;
        if (!parsed)
        {
            SetLastError(ERROR_INVALID_DATA);
            return false;
        }

        const bool supportedMarker = marker == kConnectionBlobMarkerLegacy ||
            marker == kConnectionBlobMarkerCurrent;
        const bool knownRoute = (rawFlags & ~kKnownProxyRouteFlags) == 0;
        const bool disallowedRoute = (rawFlags & (PROXY_TYPE_PROXY |
            PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_AUTO_DETECT)) != 0;
        *confirmsDirectIntent = supportedMarker && knownRoute &&
            !disallowedRoute &&
            (rawFlags == 0 || rawFlags == PROXY_TYPE_DIRECT) &&
            rawProxyEmpty && rawAutoConfigUrlEmpty;
        return true;
    }

    bool QueryRawSettingsDirectIntent(bool* confirmsDirectIntent)
    {
        *confirmsDirectIntent = false;
        bool present = false;
        bool settingEnabled = false;
        if (!QueryAutoDetectValue(&present, &settingEnabled))
            return false;
        if (present && settingEnabled)
            return true;

        constexpr const wchar_t* connectionValues[] = {
            L"DefaultConnectionSettings",
            L"SavedLegacySettings",
        };
        for (const wchar_t* valueName : connectionValues)
        {
            bool blobConfirmsDirectIntent = false;
            if (!QueryConnectionBlobDirectIntent(valueName,
                    &blobConfirmsDirectIntent))
            {
                return false;
            }
            if (!blobConfirmsDirectIntent)
                return true;
        }

        *confirmsDirectIntent = true;
        return true;
    }

    bool ShouldApplyDirectWorkaround()
    {
        DWORD connectedFlags = 0;
        if (!InternetGetConnectedState(&connectedFlags, 0) ||
            (connectedFlags & INTERNET_CONNECTION_LAN) == 0 ||
            (connectedFlags & (INTERNET_CONNECTION_MODEM |
                INTERNET_CONNECTION_PROXY | INTERNET_CONNECTION_OFFLINE)) != 0)
        {
            Log(BOOTSTRAPPER_EXTENSION_LOG_LEVEL_VERBOSE,
                L"ProxiFyre setup WinINet compatibility override was not needed: "
                L"the current connection is not an online direct LAN connection.");
            return false;
        }

        bool policyAllowsPerUserSettings = false;
        if (!QueryProxyPolicyAllowsPerUserSettings(
                &policyAllowsPerUserSettings))
        {
            LogWin32Failure(L"query machine-wide proxy policy", GetLastError());
            return false;
        }
        if (!policyAllowsPerUserSettings)
        {
            Log(BOOTSTRAPPER_EXTENSION_LOG_LEVEL_VERBOSE,
                L"ProxiFyre setup WinINet compatibility override was not applied "
                L"because ProxySettingsPerUser is present but is not exactly 1.");
            return false;
        }

        bool perUserProxyDisabled = false;
        if (!QueryPerUserProxyDisabled(&perUserProxyDisabled))
        {
            LogWin32Failure(L"query the current user's ProxyEnable value",
                GetLastError());
            return false;
        }
        if (!perUserProxyDisabled)
        {
            Log(BOOTSTRAPPER_EXTENSION_LOG_LEVEL_VERBOSE,
                L"ProxiFyre setup WinINet compatibility override was not applied "
                L"because the current user's proxy is not explicitly disabled.");
            return false;
        }

        bool rawProxyServerEmpty = false;
        if (!QueryRawInternetSettingStringIsEmpty(L"ProxyServer",
                &rawProxyServerEmpty))
        {
            LogWin32Failure(L"query the raw current-user proxy server setting",
                GetLastError());
            return false;
        }

        bool rawAutoConfigUrlEmpty = false;
        if (!QueryRawInternetSettingStringIsEmpty(L"AutoConfigURL",
                &rawAutoConfigUrlEmpty))
        {
            LogWin32Failure(L"query the raw current-user automatic "
                L"configuration URL setting", GetLastError());
            return false;
        }
        if (!rawProxyServerEmpty || !rawAutoConfigUrlEmpty)
        {
            Log(BOOTSTRAPPER_EXTENSION_LOG_LEVEL_VERBOSE,
                L"ProxiFyre setup WinINet compatibility override was not applied "
                L"because the raw current-user settings contain a proxy server "
                L"or automatic configuration URL.");
            return false;
        }

        bool rawSettingsConfirmDirectIntent = false;
        if (!QueryRawSettingsDirectIntent(&rawSettingsConfirmDirectIntent))
        {
            LogWin32Failure(L"parse the raw current-user connection settings",
                GetLastError());
            return false;
        }
        if (!rawSettingsConfirmDirectIntent)
        {
            Log(BOOTSTRAPPER_EXTENSION_LOG_LEVEL_VERBOSE,
                L"ProxiFyre setup WinINet compatibility override was not applied "
                L"because the raw current-user settings do not unambiguously "
                L"encode a direct route.");
            return false;
        }

        DWORD flagsUi = 0;
        if (!QueryPerConnectionDword(INTERNET_PER_CONN_FLAGS_UI, &flagsUi))
        {
            LogWin32Failure(L"query INTERNET_PER_CONN_FLAGS_UI", GetLastError());
            return false;
        }

        DWORD flags = 0;
        if (!QueryPerConnectionDword(INTERNET_PER_CONN_FLAGS, &flags))
        {
            LogWin32Failure(L"query INTERNET_PER_CONN_FLAGS", GetLastError());
            return false;
        }

        if (flagsUi != 0 || flags != 0)
        {
            Log(BOOTSTRAPPER_EXTENSION_LOG_LEVEL_VERBOSE,
                L"ProxiFyre setup WinINet compatibility override was not needed: "
                L"WinINet already has explicit connection flags.");
            return false;
        }

        bool proxyServerEmpty = false;
        if (!QueryPerConnectionStringIsEmpty(INTERNET_PER_CONN_PROXY_SERVER,
                &proxyServerEmpty))
        {
            LogWin32Failure(L"query the WinINet proxy server", GetLastError());
            return false;
        }

        bool autoConfigUrlEmpty = false;
        if (!QueryPerConnectionStringIsEmpty(INTERNET_PER_CONN_AUTOCONFIG_URL,
                &autoConfigUrlEmpty))
        {
            LogWin32Failure(L"query the WinINet automatic configuration URL",
                GetLastError());
            return false;
        }

        if (!proxyServerEmpty || !autoConfigUrlEmpty)
        {
            Log(BOOTSTRAPPER_EXTENSION_LOG_LEVEL_VERBOSE,
                L"ProxiFyre setup WinINet compatibility override was not applied "
                L"because WinINet reports a proxy server or PAC URL.");
            return false;
        }

        return true;
    }

    void ApplyDirectWorkaround()
    {
        if (!ShouldApplyDirectWorkaround())
            return;

        HINTERNET internet = InternetOpenW(
            L"ProxiFyre Setup WinINet compatibility",
            INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (internet == nullptr)
        {
            LogWin32Failure(L"open a WinINet session", GetLastError());
            return;
        }

        // Re-read every global and registry gate after creating the process
        // root. A route or policy change during the first inspection must not
        // be overwritten by the process-scoped DIRECT setting.
        if (!ShouldApplyDirectWorkaround())
        {
            InternetCloseHandle(internet);
            Log(BOOTSTRAPPER_EXTENSION_LOG_LEVEL_VERBOSE,
                L"ProxiFyre setup WinINet compatibility override was not applied "
                L"because its guarded inputs changed before the process setting.");
            return;
        }

        INTERNET_PER_CONN_OPTIONW option{};
        option.dwOption = INTERNET_PER_CONN_FLAGS;
        option.Value.dwValue = PROXY_TYPE_DIRECT;

        INTERNET_PER_CONN_OPTION_LISTW list{};
        list.dwSize = sizeof(list);
        list.pszConnection = nullptr;
        list.dwOptionCount = 1;
        list.pOptions = &option;

        if (!InternetSetOptionW(internet, INTERNET_OPTION_PER_CONNECTION_OPTION,
                &list, sizeof(list)))
        {
            const DWORD error = GetLastError();
            InternetCloseHandle(internet);
            LogWin32Failure(L"set process-scoped direct connection flags", error);
            return;
        }

        InternetCloseHandle(internet);
        Log(BOOTSTRAPPER_EXTENSION_LOG_LEVEL_STANDARD,
            L"Applied a process-scoped WinINet DIRECT compatibility override for "
            L"Burn because the current user's connection flags were empty. No "
            L"system or user Internet Options were changed.");
    }

    HRESULT WINAPI BootstrapperExtensionProc(
        BOOTSTRAPPER_EXTENSION_MESSAGE,
        const LPVOID,
        LPVOID,
        LPVOID)
    {
        return E_NOTIMPL;
    }
}

extern "C" HRESULT WINAPI BootstrapperExtensionCreate(
    const BOOTSTRAPPER_EXTENSION_CREATE_ARGS* arguments,
    BOOTSTRAPPER_EXTENSION_CREATE_RESULTS* results)
{
    if (arguments == nullptr || results == nullptr ||
        arguments->cbSize < sizeof(*arguments) ||
        results->cbSize < sizeof(*results) ||
        arguments->pfnBootstrapperExtensionEngineProc == nullptr)
    {
        return E_INVALIDARG;
    }

    g_engineProc = arguments->pfnBootstrapperExtensionEngineProc;
    g_engineContext = arguments->pvBootstrapperExtensionEngineProcContext;

    results->pfnBootstrapperExtensionProc = BootstrapperExtensionProc;
    results->pvBootstrapperExtensionProcContext = nullptr;

    // This extension runs inside the Burn engine process. A non-NULL WinINet
    // root handle therefore changes proxy information only for Burn's process,
    // and WinINet retains that process state after the root handle is closed.
    ApplyDirectWorkaround();
    return S_OK;
}

extern "C" void WINAPI BootstrapperExtensionDestroy()
{
    g_engineProc = nullptr;
    g_engineContext = nullptr;
}

static_assert(std::is_same_v<decltype(&BootstrapperExtensionCreate),
    PFN_BOOTSTRAPPER_EXTENSION_CREATE>,
    "BootstrapperExtensionCreate must match the WiX 6 API signature.");
static_assert(std::is_same_v<decltype(&BootstrapperExtensionDestroy),
    PFN_BOOTSTRAPPER_EXTENSION_DESTROY>,
    "BootstrapperExtensionDestroy must match the WiX 6 API signature.");
