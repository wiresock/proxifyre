#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <msiquery.h>
#include <objbase.h>
#include <strsafe.h>

#include <cwchar>
#include <new>

#include "dutil.h"
#include "dictutil.h"
#include "BootstrapperApplicationBase.h"
#include "balutil.h"
#include "BAFunctions.h"
#include "IBAFunctions.h"
#include "BalBaseBAFunctions.h"
#include "BalBaseBAFunctionsProc.h"

namespace
{
    constexpr wchar_t kInternetSettingsKey[] =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    constexpr wchar_t kSecureProtocolsValue[] = L"SecureProtocols";
    constexpr DWORD kTls12Protocol = 0x00000800;
    constexpr DWORD kWindows7DefaultProtocols = 0x000000A0;
    constexpr wchar_t kVisualCppRuntimeId[] = L"VisualCppRuntime";
    constexpr wchar_t kVisualCppDownloadHttpsPrefix[] =
        L"https://download.visualstudio.microsoft.com/download/pr/";
    constexpr wchar_t kVisualCppDownloadHttpPrefix[] =
        L"http://download.visualstudio.microsoft.com/download/pr/";

    class ProxiFyreSetupFunctions;

    HMODULE g_module = nullptr;
    ProxiFyreSetupFunctions* g_functions = nullptr;

    void NotifyInternetSettingsChanged()
    {
        if (!InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED,
                nullptr, 0))
        {
            BalLog(BOOTSTRAPPER_LOG_LEVEL_ERROR,
                "Failed to notify WinINet that Internet settings changed: 0x%08lX",
                static_cast<unsigned long>(HRESULT_FROM_WIN32(GetLastError())));
        }
    }

    bool IsWindows7()
    {
        using RtlGetVersionFunction = LONG(WINAPI*)(OSVERSIONINFOW*);
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
            return false;

        const auto rtlGetVersion = reinterpret_cast<RtlGetVersionFunction>(
            GetProcAddress(ntdll, "RtlGetVersion"));
        if (rtlGetVersion == nullptr)
            return false;

        OSVERSIONINFOEXW version{};
        version.dwOSVersionInfoSize = sizeof(version);
        return rtlGetVersion(reinterpret_cast<OSVERSIONINFOW*>(&version)) == 0 &&
            version.dwMajorVersion == 6 && version.dwMinorVersion == 1 &&
            version.wProductType == VER_NT_WORKSTATION;
    }

    bool IsHttpsUrl(const wchar_t* value)
    {
        constexpr wchar_t prefix[] = L"https://";
        if (value == nullptr)
            return false;
        for (DWORD index = 0; prefix[index] != L'\0'; ++index)
        {
            wchar_t character = value[index];
            if (character >= L'A' && character <= L'Z')
                character += L'a' - L'A';
            if (character != prefix[index])
                return false;
        }
        return true;
    }

    bool IsSameOrdinalIgnoreCase(const wchar_t* left, const wchar_t* right)
    {
        return left != nullptr && right != nullptr && _wcsicmp(left, right) == 0;
    }

    bool StartsWithOrdinalIgnoreCase(
        const wchar_t* value, const wchar_t* prefix)
    {
        return value != nullptr && prefix != nullptr &&
            _wcsnicmp(value, prefix, wcslen(prefix)) == 0;
    }

    class ProxiFyreSetupFunctions final : public CBalBaseBAFunctions
    {
    public:
        explicit ProxiFyreSetupFunctions(HMODULE module) : CBalBaseBAFunctions(module)
        {
        }

        ~ProxiFyreSetupFunctions() override
        {
            RestoreSecureProtocols();
        }

        STDMETHODIMP OnCacheAcquireBegin(
            __in_z LPCWSTR packageOrContainerId,
            __in_z_opt LPCWSTR payloadId,
            __in_z LPCWSTR source,
            __in_z_opt LPCWSTR downloadUrl,
            __in_z_opt LPCWSTR payloadContainerId,
            BOOTSTRAPPER_CACHE_OPERATION recommendation,
            __inout BOOTSTRAPPER_CACHE_OPERATION* action,
            __inout BOOL* cancel) override
        {
            HRESULT result = PrepareVisualCppHttpFallbackForWindows7(
                packageOrContainerId, payloadId, downloadUrl);
            if (FAILED(result))
                return result;

            if (IsHttpsUrl(downloadUrl))
            {
                result = EnableTls12ForWindows7();
                if (FAILED(result))
                {
                    BalLog(BOOTSTRAPPER_LOG_LEVEL_ERROR,
                        "Failed to enable TLS 1.2 for Windows 7 prerequisite downloads: 0x%08lX",
                        static_cast<unsigned long>(result));
                    return result;
                }
            }
            return __super::OnCacheAcquireBegin(packageOrContainerId, payloadId,
                source, downloadUrl, payloadContainerId, recommendation, action,
                cancel);
        }

        STDMETHODIMP OnCacheAcquireResolving(
            __in_z_opt LPCWSTR packageOrContainerId,
            __in_z_opt LPCWSTR payloadId,
            __in_z LPCWSTR* searchPaths,
            DWORD searchPathCount,
            BOOL foundLocal,
            DWORD recommendedSearchPath,
            __in_z_opt LPCWSTR downloadUrl,
            __in_z_opt LPCWSTR payloadContainerId,
            BOOTSTRAPPER_CACHE_RESOLVE_OPERATION recommendation,
            __inout DWORD* chosenSearchPath,
            __inout BOOTSTRAPPER_CACHE_RESOLVE_OPERATION* action,
            __inout BOOL* cancel) override
        {
            const HRESULT result = __super::OnCacheAcquireResolving(
                packageOrContainerId, payloadId, searchPaths, searchPathCount,
                foundLocal, recommendedSearchPath, downloadUrl,
                payloadContainerId, recommendation, chosenSearchPath, action,
                cancel);
            if (FAILED(result))
                return result;
            if (action == nullptr)
                return E_INVALIDARG;

            // WiX 6.0.2 drops wzDownloadUrl while dispatching this callback
            // (wixtoolset/issues#9275). The URL was retained during acquire
            // begin; this callback contributes only the resolved operation.
            return ArmVisualCppHttpFallbackForWindows7(
                packageOrContainerId, payloadId, *action);
        }

        STDMETHODIMP OnCacheAcquireComplete(
            __in_z LPCWSTR packageOrContainerId,
            __in_z_opt LPCWSTR payloadId,
            HRESULT status,
            BOOTSTRAPPER_CACHEACQUIRECOMPLETE_ACTION recommendation,
            __inout BOOTSTRAPPER_CACHEACQUIRECOMPLETE_ACTION* action) override
        {
            const HRESULT result = RetryVisualCppOverHttpForWindows7(
                packageOrContainerId, payloadId, status, action);
            if (FAILED(result))
                return result;

            return __super::OnCacheAcquireComplete(packageOrContainerId,
                payloadId, status, recommendation, action);
        }

        STDMETHODIMP OnCacheComplete(HRESULT status) override
        {
            ResetVisualCppHttpFallback();
            RestoreSecureProtocols();
            return __super::OnCacheComplete(status);
        }

        STDMETHODIMP OnCacheVerifyComplete(
            __in_z LPCWSTR packageOrContainerId,
            __in_z LPCWSTR payloadId,
            HRESULT status,
            BOOTSTRAPPER_CACHEVERIFYCOMPLETE_ACTION recommendation,
            __inout BOOTSTRAPPER_CACHEVERIFYCOMPLETE_ACTION* action) override
        {
            if (action == nullptr)
                return E_INVALIDARG;

            if (visualCppHttpFallbackAttempted_ &&
                IsSameOrdinalIgnoreCase(
                    packageOrContainerId, kVisualCppRuntimeId) &&
                IsSameOrdinalIgnoreCase(payloadId, kVisualCppRuntimeId))
            {
                if (FAILED(status) &&
                    *action ==
                        BOOTSTRAPPER_CACHEVERIFYCOMPLETE_ACTION_RETRYACQUISITION)
                {
                    *action = BOOTSTRAPPER_CACHEVERIFYCOMPLETE_ACTION_NONE;
                }

                if (SUCCEEDED(status) ||
                    *action == BOOTSTRAPPER_CACHEVERIFYCOMPLETE_ACTION_NONE)
                {
                    ResetVisualCppHttpFallback();
                }
            }

            return __super::OnCacheVerifyComplete(packageOrContainerId,
                payloadId, status, recommendation, action);
        }

        STDMETHODIMP OnApplyComplete(
            HRESULT status,
            BOOTSTRAPPER_APPLY_RESTART restart,
            BOOTSTRAPPER_APPLYCOMPLETE_ACTION recommendation,
            __inout BOOTSTRAPPER_APPLYCOMPLETE_ACTION* action) override
        {
            RestoreSecureProtocols();
            return __super::OnApplyComplete(
                status, restart, recommendation, action);
        }

        STDMETHODIMP OnShutdown(
            __inout BOOTSTRAPPER_SHUTDOWN_ACTION* action) override
        {
            RestoreSecureProtocols();
            return __super::OnShutdown(action);
        }

    private:
        HRESULT PrepareVisualCppHttpFallbackForWindows7(
            const wchar_t* packageOrContainerId,
            const wchar_t* payloadId,
            const wchar_t* downloadUrl)
        {
            if (!IsWindows7() ||
                !IsSameOrdinalIgnoreCase(
                    packageOrContainerId, kVisualCppRuntimeId) ||
                !IsSameOrdinalIgnoreCase(payloadId, kVisualCppRuntimeId))
            {
                return S_OK;
            }

            // SetDownloadSource persists for the retry. Never re-arm this
            // package during the same acquisition after consuming the fallback.
            if (visualCppHttpFallbackAttempted_)
                return S_OK;

            ResetVisualCppHttpFallback();
            if (!StartsWithOrdinalIgnoreCase(
                    downloadUrl, kVisualCppDownloadHttpsPrefix))
            {
                BalLog(BOOTSTRAPPER_LOG_LEVEL_STANDARD,
                    "Windows 7 Visual C++ compatibility transport was not applied because the download is not the pinned Microsoft content-addressed endpoint.");
                return S_OK;
            }

            HRESULT result = StringCchCopyW(visualCppHttpFallbackUrl_,
                ARRAYSIZE(visualCppHttpFallbackUrl_),
                kVisualCppDownloadHttpPrefix);
            if (SUCCEEDED(result))
            {
                result = StringCchCatW(visualCppHttpFallbackUrl_,
                    ARRAYSIZE(visualCppHttpFallbackUrl_), downloadUrl +
                    ARRAYSIZE(kVisualCppDownloadHttpsPrefix) - 1);
            }
            if (FAILED(result))
            {
                ResetVisualCppHttpFallback();
                return result;
            }

            visualCppHttpFallbackPrepared_ = true;
            return S_OK;
        }

        HRESULT ArmVisualCppHttpFallbackForWindows7(
            const wchar_t* packageOrContainerId,
            const wchar_t* payloadId,
            BOOTSTRAPPER_CACHE_RESOLVE_OPERATION operation)
        {
            if (!IsWindows7() || visualCppHttpFallbackAttempted_ ||
                !IsSameOrdinalIgnoreCase(
                    packageOrContainerId, kVisualCppRuntimeId) ||
                !IsSameOrdinalIgnoreCase(payloadId, kVisualCppRuntimeId))
            {
                return S_OK;
            }

            visualCppHttpFallbackArmed_ =
                visualCppHttpFallbackPrepared_ &&
                operation == BOOTSTRAPPER_CACHE_RESOLVE_DOWNLOAD;
            return S_OK;
        }

        HRESULT RetryVisualCppOverHttpForWindows7(
            const wchar_t* packageOrContainerId,
            const wchar_t* payloadId,
            HRESULT status,
            BOOTSTRAPPER_CACHEACQUIRECOMPLETE_ACTION* action)
        {
            if (action == nullptr)
                return E_INVALIDARG;

            if (SUCCEEDED(status) && !visualCppHttpFallbackAttempted_ &&
                IsSameOrdinalIgnoreCase(
                    packageOrContainerId, kVisualCppRuntimeId) &&
                IsSameOrdinalIgnoreCase(payloadId, kVisualCppRuntimeId))
            {
                ResetVisualCppHttpFallback();
                return S_OK;
            }

            if (!visualCppHttpFallbackArmed_ ||
                !IsSameOrdinalIgnoreCase(
                    packageOrContainerId, kVisualCppRuntimeId) ||
                !IsSameOrdinalIgnoreCase(payloadId, kVisualCppRuntimeId))
            {
                return S_OK;
            }

            // The compatibility source gets exactly one acquisition attempt,
            // even if WixStdBA would otherwise recommend another normal retry.
            if (visualCppHttpFallbackAttempted_)
            {
                *action = BOOTSTRAPPER_CACHEACQUIRECOMPLETE_ACTION_NONE;
                return S_OK;
            }

            // Preserve WixStdBA's ordinary HTTPS retry budget. Add the fallback
            // only after those retries are exhausted for the observed failure.
            if (status != HRESULT_FROM_WIN32(ERROR_INTERNET_CANNOT_CONNECT) ||
                *action == BOOTSTRAPPER_CACHEACQUIRECOMPLETE_ACTION_RETRY)
            {
                return S_OK;
            }

            visualCppHttpFallbackAttempted_ = true;
            const HRESULT result = m_pEngine->SetDownloadSource(
                packageOrContainerId, payloadId, visualCppHttpFallbackUrl_,
                nullptr, nullptr, nullptr);
            if (FAILED(result))
            {
                BalLog(BOOTSTRAPPER_LOG_LEVEL_ERROR,
                    "Failed to select the Windows 7 Visual C++ compatibility transport: 0x%08lX",
                    static_cast<unsigned long>(result));
                // Preserve WixStdBA's existing recommendation when the source
                // cannot be changed; the original HTTPS path may still recover.
                return S_OK;
            }

            *action = BOOTSTRAPPER_CACHEACQUIRECOMPLETE_ACTION_RETRY;
            BalLog(BOOTSTRAPPER_LOG_LEVEL_STANDARD,
                "Windows 7 exhausted the normal Visual C++ HTTPS retries after WinINet 12029; making one final attempt over Microsoft's HTTP endpoint. Burn will verify the bundle's exact SHA-512 before execution.");
            return S_OK;
        }

        void ResetVisualCppHttpFallback()
        {
            visualCppHttpFallbackPrepared_ = false;
            visualCppHttpFallbackArmed_ = false;
            visualCppHttpFallbackAttempted_ = false;
            visualCppHttpFallbackUrl_[0] = L'\0';
        }

        HRESULT EnableTls12ForWindows7()
        {
            if (!IsWindows7())
                return S_OK;
            if (changedProtocols_)
                return S_OK;

            HKEY key = nullptr;
            const LSTATUS opened = RegCreateKeyExW(HKEY_CURRENT_USER,
                kInternetSettingsKey, 0, nullptr, REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE, nullptr, &key, nullptr);
            if (opened != ERROR_SUCCESS)
                return HRESULT_FROM_WIN32(opened);

            DWORD type = 0;
            DWORD size = sizeof(originalProtocols_);
            LSTATUS queried = RegQueryValueExW(key, kSecureProtocolsValue,
                nullptr, &type, reinterpret_cast<BYTE*>(&originalProtocols_), &size);
            if (queried == ERROR_FILE_NOT_FOUND)
            {
                originalValueExisted_ = false;
                originalProtocols_ = kWindows7DefaultProtocols;
            }
            else if (queried != ERROR_SUCCESS)
            {
                RegCloseKey(key);
                return HRESULT_FROM_WIN32(queried);
            }
            else if (type != REG_DWORD || size != sizeof(originalProtocols_))
            {
                RegCloseKey(key);
                return HRESULT_FROM_WIN32(ERROR_DATATYPE_MISMATCH);
            }
            else
            {
                originalValueExisted_ = true;
            }

            if ((originalProtocols_ & kTls12Protocol) != 0)
            {
                BalLog(BOOTSTRAPPER_LOG_LEVEL_STANDARD,
                    "Windows 7 WinINet TLS 1.2 support is already enabled.");
                RegCloseKey(key);
                return S_OK;
            }

            writtenProtocols_ = originalProtocols_ | kTls12Protocol;
            const LSTATUS written = RegSetValueExW(key, kSecureProtocolsValue, 0,
                REG_DWORD, reinterpret_cast<const BYTE*>(&writtenProtocols_),
                sizeof(writtenProtocols_));
            RegCloseKey(key);
            if (written != ERROR_SUCCESS)
                return HRESULT_FROM_WIN32(written);

            changedProtocols_ = true;
            NotifyInternetSettingsChanged();
            BalLog(BOOTSTRAPPER_LOG_LEVEL_STANDARD,
                "Temporarily enabled TLS 1.2 in the current user's Windows 7 WinINet settings for prerequisite downloads.");
            return S_OK;
        }

        void RestoreSecureProtocols()
        {
            if (!changedProtocols_)
                return;

            HKEY key = nullptr;
            const LSTATUS opened = RegOpenKeyExW(HKEY_CURRENT_USER,
                kInternetSettingsKey, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key);
            if (opened != ERROR_SUCCESS)
            {
                BalLog(BOOTSTRAPPER_LOG_LEVEL_ERROR,
                    "Failed to reopen Windows 7 WinINet settings for restoration: 0x%08lX",
                    static_cast<unsigned long>(HRESULT_FROM_WIN32(opened)));
                return;
            }

            DWORD current = 0;
            DWORD type = 0;
            DWORD size = sizeof(current);
            const LSTATUS queried = RegQueryValueExW(key, kSecureProtocolsValue,
                nullptr, &type, reinterpret_cast<BYTE*>(&current), &size);
            if (queried != ERROR_SUCCESS && queried != ERROR_FILE_NOT_FOUND)
            {
                RegCloseKey(key);
                BalLog(BOOTSTRAPPER_LOG_LEVEL_ERROR,
                    "Failed to read Windows 7 WinINet settings for restoration: 0x%08lX",
                    static_cast<unsigned long>(HRESULT_FROM_WIN32(queried)));
                return;
            }
            if (queried == ERROR_FILE_NOT_FOUND || type != REG_DWORD ||
                size != sizeof(current) || current != writtenProtocols_)
            {
                // Do not overwrite a concurrent Internet Options change.
                RegCloseKey(key);
                changedProtocols_ = false;
                BalLog(BOOTSTRAPPER_LOG_LEVEL_STANDARD,
                    "Windows 7 WinINet settings changed while setup was open; leaving the current value unchanged.");
                return;
            }

            const LSTATUS restored = originalValueExisted_
                ? RegSetValueExW(key, kSecureProtocolsValue, 0, REG_DWORD,
                    reinterpret_cast<const BYTE*>(&originalProtocols_),
                    sizeof(originalProtocols_))
                : RegDeleteValueW(key, kSecureProtocolsValue);
            RegCloseKey(key);
            if (restored == ERROR_SUCCESS || restored == ERROR_FILE_NOT_FOUND)
            {
                changedProtocols_ = false;
                NotifyInternetSettingsChanged();
                BalLog(BOOTSTRAPPER_LOG_LEVEL_STANDARD,
                    "Restored the current user's Windows 7 WinINet protocol settings.");
            }
            else
            {
                BalLog(BOOTSTRAPPER_LOG_LEVEL_ERROR,
                    "Failed to restore Windows 7 WinINet settings: 0x%08lX",
                    static_cast<unsigned long>(HRESULT_FROM_WIN32(restored)));
            }
        }

        bool changedProtocols_ = false;
        bool originalValueExisted_ = false;
        DWORD originalProtocols_ = 0;
        DWORD writtenProtocols_ = 0;
        bool visualCppHttpFallbackPrepared_ = false;
        bool visualCppHttpFallbackArmed_ = false;
        bool visualCppHttpFallbackAttempted_ = false;
        wchar_t visualCppHttpFallbackUrl_[INTERNET_MAX_URL_LENGTH]{};
    };
}

extern "C" BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(instance);
        g_module = instance;
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        g_module = nullptr;
    }
    return TRUE;
}

extern "C" HRESULT WINAPI BAFunctionsCreate(
    const BA_FUNCTIONS_CREATE_ARGS* arguments,
    BA_FUNCTIONS_CREATE_RESULTS* results)
{
    if (arguments == nullptr || results == nullptr)
        return E_INVALIDARG;
    if (g_functions != nullptr)
        return E_UNEXPECTED;

    BalInitialize(arguments->pEngine);
    auto functions = new (std::nothrow) ProxiFyreSetupFunctions(g_module);
    if (functions == nullptr)
    {
        BalUninitialize();
        return E_OUTOFMEMORY;
    }

    const HRESULT created = functions->OnCreate(
        arguments->pEngine, arguments->pCommand);
    if (FAILED(created))
    {
        functions->Release();
        BalUninitialize();
        return created;
    }

    results->pfnBAFunctionsProc = BalBaseBAFunctionsProc;
    results->pvBAFunctionsProcContext = functions;
    g_functions = functions;
    return S_OK;
}

extern "C" void WINAPI BAFunctionsDestroy(
    const BA_FUNCTIONS_DESTROY_ARGS*,
    BA_FUNCTIONS_DESTROY_RESULTS*)
{
    if (g_functions != nullptr)
    {
        g_functions->Release();
        g_functions = nullptr;
    }
    BalUninitialize();
}
