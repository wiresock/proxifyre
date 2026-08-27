#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <msiquery.h>
#include <objbase.h>

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

        OSVERSIONINFOW version{};
        version.dwOSVersionInfoSize = sizeof(version);
        return rtlGetVersion(&version) == 0 &&
            version.dwMajorVersion == 6 && version.dwMinorVersion == 1;
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
            if (IsHttpsUrl(downloadUrl))
            {
                const HRESULT result = EnableTls12ForWindows7();
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

        STDMETHODIMP OnCacheComplete(HRESULT status) override
        {
            RestoreSecureProtocols();
            return __super::OnCacheComplete(status);
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
