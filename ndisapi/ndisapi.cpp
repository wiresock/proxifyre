/*************************************************************************/
/*                    Copyright (c) 2000-2024 NT KERNEL.                 */
/*                           All Rights Reserved.                        */
/*                          https://www.ntkernel.com                     */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  ndisapi.cpp                                             */
/*                                                                       */
/* Description: API exported C++ class and C API definitions             */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/

#include "precomp.h"

#if _MSC_VER >= 1800 && !defined(_USING_V110_SDK71_)
#include <mutex>
#include <shared_mutex>
#endif // _MSC_VER >= 1800 && !defined(_USING_V110_SDK71_)

#define DEVICE_NDISWANIP "\\DEVICE\\NDISWANIP"
#define USER_NDISWANIP "WAN Network Interface (IP)"
#define DEVICE_NDISWANBH "\\DEVICE\\NDISWANBH"
#define USER_NDISWANBH "WAN Network Interface (BH)"
#define DEVICE_NDISWANIPV6 "\\DEVICE\\NDISWANIPV6"
#define USER_NDISWANIPV6 "WAN Network Interface (IPv6)"
#define REGSTR_COMPONENTID_NDISWANIP "ms_ndiswanip"
#define REGSTR_COMPONENTID_NDISWANIPV6 "ms_ndiswanipv6"
#define REGSTR_COMPONENTID_NDISWANBH "ms_ndiswanbh"
#define REGSTR_VAL_CONNECTION "\\Connection"
#define REGSTR_VAL_NAME "Name"
#define REGSTR_VAL_SERVICE_NAME "ServiceName"
#define REGSTR_VAL_DRIVER_DESC "DriverDesc"
#define REGSTR_VAL_TITLE "Title"

#define REGSTR_NETWORK_CONTROL_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\"
#define REGSTR_NETWORK_CARDS TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards")
#define REGSTR_MSTCP_CLASS_NET "SYSTEM\\CurrentControlSet\\Services\\Class\\Net\\"
#define REGSTR_NETWORK_CONTROL_CLASS TEXT("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}")

#define OID_GEN_CURRENT_PACKET_FILTER            0x0001010E

// OS version information
CVersionInfo CNdisApi::ms_Version;

/**
 * @class CNdisApi::CWow64Helper
 * @brief A helper class to manage conversion of handles between 32-bit and 64-bit applications in WOW64 mode.
 *
 * This class is designed as a singleton and provides methods for updating handle mappings and converting
 * handles between 32-bit and 64-bit representations. It is useful when a 32-bit application interacts with
 * a 64-bit driver on a 64-bit operating system.
 *
 * Usage:
 * auto& wow64Helper = CNdisApi::CWow64Helper::getInstance();
 * unsigned int handle32 = wow64Helper.From64to32Handle(handle64);
 */
class CNdisApi::CWow64Helper
{
public:
#if _MSC_VER < 1800 || defined(_USING_V110_SDK71_)
    /**
     * @brief Destructor that releases the Win32 mutex.
     */
    ~CWow64Helper()
    {
        ::CloseHandle(m_hWin32Mutex);
    }
#endif //_MSC_VER < 1800 || defined(_USING_V110_SDK71_)

    /**
     * @brief Returns a reference to the singleton instance of CWow64Helper.
     * @return A reference to the singleton instance.
     */
    static CWow64Helper& getInstance()
    {
        static CWow64Helper    instance;    // Guaranteed to be destroyed.
        // Instantiated on first use.
        return instance;
    }

#if _MSC_VER >= 1800 && !defined(_USING_V110_SDK71_)
    CWow64Helper(const CWow64Helper& other) = delete;
    CWow64Helper& operator=(const CWow64Helper& other) = delete;
    CWow64Helper(CWow64Helper&& other) = delete;
    CWow64Helper& operator=(CWow64Helper&& other) = delete;
    ~CWow64Helper() = default;
#endif // _MSC_VER >= 1800 && !defined(_USING_V110_SDK71_)

    /**
     * @brief Updates the handle mappings based on the provided TCP_AdapterList_WOW64.
     * @param adapterListWow64 A reference to the TCP_AdapterList_WOW64 structure.
     */
    void Update(const TCP_AdapterList_WOW64& adapterListWow64);

    /**
     * @brief Converts a 32-bit handle to its 64-bit equivalent.
     * @param handle The 32-bit handle to convert.
     * @return The corresponding 64-bit handle.
     */
    ULONGLONG From32to64Handle(const unsigned int handle)
    {
#if _MSC_VER >= 1800 && !defined(_USING_V110_SDK71_)
        std::shared_lock <std::shared_mutex> lock(m_SharedLock);
#else
        InternalLock();
#endif // _MSC_VER >= 1800 && !defined(_USING_V110_SDK71_)

        const ULONGLONG result = m_Handle32to64[handle];

#if _MSC_VER < 1800 || defined(_USING_V110_SDK71_)
        InternalUnlock();
#endif //_MSC_VER < 1800 || defined(_USING_V110_SDK71_)

        return result;
    }

    /**
     * @brief Converts a 64-bit handle to its 32-bit equivalent.
     * @param handle The 64-bit handle to convert.
     * @return The corresponding 32-bit handle.
     */
    unsigned int From64to32Handle(const ULONGLONG handle)
    {
        unsigned int result = 0;

#if _MSC_VER >= 1800 && !defined(_USING_V110_SDK71_)
        std::shared_lock <std::shared_mutex> lock(m_SharedLock);
#else
        InternalLock();
#endif // _MSC_VER >= 1800 && !defined(_USING_V110_SDK71_)

        for (unsigned int i = 1; i < ADAPTER_LIST_SIZE + 1; ++i)
        {
            if (m_Handle32to64[i] == handle)
            {
                result = i;
                break;
            }
        }

#if _MSC_VER < 1800 || defined(_USING_V110_SDK71_)
        InternalUnlock();
#endif //_MSC_VER < 1800 || defined(_USING_V110_SDK71_)
        return result;
    }

private:
#if _MSC_VER >= 1800 && !defined(_USING_V110_SDK71_)
    CWow64Helper() = default;
#else
    CWow64Helper() : m_hWin32Mutex(::CreateMutex(NULL, FALSE, NULL))
    {
        memset((void*)m_Handle32to64, 0, sizeof(m_Handle32to64));
    }

    // Synchronize an access to m_Handle32to64 using Win32 mutex
    DWORD InternalLock() { return ::WaitForSingleObject(m_hWin32Mutex, INFINITE); }
    void InternalUnlock() { ::ReleaseMutex(m_hWin32Mutex); }

    CWow64Helper(CWow64Helper const&);                // Don't Implement
    CWow64Helper& operator=(CWow64Helper const&);    // Don't implement
#endif // _MSC_VER >= 1800 && !defined(_USING_V110_SDK71_)

#if _MSC_VER >= 1800 && !defined(_USING_V110_SDK71_)
    std::shared_mutex                m_SharedLock;
    ULONGLONG                        m_Handle32to64[ADAPTER_LIST_SIZE + 1]{};
#else
    HANDLE                            m_hWin32Mutex;
    ULONGLONG                        m_Handle32to64[ADAPTER_LIST_SIZE + 1];
#endif //_MSC_VER >= 1800 && !defined(_USING_V110_SDK71_)
};

/**
 * @brief Updates the handle mappings based on the provided TCP_AdapterList_WOW64.
 *
 * This method updates the internal handle mapping table to ensure it reflects the current state
 * of the adapter list in the system. This should be called whenever the adapter list changes.
 *
 * @param adapterListWow64 A reference to the TCP_AdapterList_WOW64 structure containing the
 *                         current adapter handles.
 */
void CNdisApi::CWow64Helper::Update(const TCP_AdapterList_WOW64& adapterListWow64)
{
#if _MSC_VER >= 1800 && !defined(_USING_V110_SDK71_)
    std::unique_lock <std::shared_mutex> _lock(m_SharedLock);
#else
    InternalLock();
#endif // _MSC_VER >= 1800 && !defined(_USING_V110_SDK71_)

    if (m_Handle32to64[0] == 0)
    {
        // First call to GetTcpipBoundAdaptersInfo, initialize m_Handle32to64
        m_Handle32to64[0] = (-1);

        for (unsigned i = 0; i < adapterListWow64.m_nAdapterCount; ++i)
        {
            m_Handle32to64[i + 1] = adapterListWow64.m_nAdapterHandle[i].QuadPart;
        }
    }
    else
    {
        for (unsigned i = 0; i < adapterListWow64.m_nAdapterCount; ++i)
        {
            // Check if we already have adapterListWow64.m_nAdapterHandle[i] adapter in the translation table
            bool bAlreadyExists = false;

            for (unsigned j = 1; j < ADAPTER_LIST_SIZE + 1; ++j)
            {
                if (m_Handle32to64[j] == adapterListWow64.m_nAdapterHandle[i].QuadPart)
                {
                    bAlreadyExists = true;
                    break;
                }
            }

            if (!bAlreadyExists)
            {
                // This is a new interface, not present in the table
                // Search through the table for the first entry which can be replaced

                unsigned pos = 0;

                for (unsigned j = 1; j < ADAPTER_LIST_SIZE + 1; ++j)
                {
                    for (unsigned k = 0; k < adapterListWow64.m_nAdapterCount; ++k)
                    {
                        if (m_Handle32to64[j] == adapterListWow64.m_nAdapterHandle[k].QuadPart)
                            break;

                        // We are at the last element and m_Handle32to64[j] is not found
                        if (k == (adapterListWow64.m_nAdapterCount - 1))
                        {
                            pos = j;
                        }

                        if (pos)
                            break;
                    }
                }

                if (pos)
                {
                    m_Handle32to64[pos] = adapterListWow64.m_nAdapterHandle[i].QuadPart;
                }
            }
        }
    }

#if _MSC_VER < 1800 || defined(_USING_V110_SDK71_)
    InternalUnlock();
#endif //_MSC_VER < 1800 || defined(_USING_V110_SDK71_)
}

/**
 * @brief CNdisApi constructor that opens the specified driver file and initializes internal structures.
 *
 * This constructor attempts to open the driver file specified by pszFileName, and initializes internal
 * structures including the OVERLAPPED structure and the CWow64Helper instance. It also checks if the
 * process is running in WOW64 mode and initializes handle mapping if necessary.
 *
 * @param pszFileName A const TCHAR pointer to the name of the driver file to be opened.
 */
CNdisApi::CNdisApi(const TCHAR* pszFileName) :
    m_ovlp(),
    m_pfnIsWow64Process(NULL),
    m_Wow64Helper(CWow64Helper::getInstance())
{
    TCHAR pszFullName[FILE_NAME_SIZE];

    // Format full file name
#if _MSC_VER >= 1700
    _tcscpy_s(pszFullName, FILE_NAME_SIZE, _T("\\\\.\\"));
    _tcscat_s(pszFullName, FILE_NAME_SIZE, pszFileName);
#else
    _tcscpy(pszFullName, _T("\\\\.\\"));
    _tcscat(pszFullName, pszFileName);
#endif //_MSC_VER >= 1700

    m_bIsLoadSuccessfully = FALSE;

    // We open driver for overlapped I/O, though none of current driver services are processed asynchronously
    m_hFileHandle = ::CreateFile(pszFullName, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED, 0);

    // If driver is opened successfully we initialize our OVERLAPPED structure
    if (m_hFileHandle == INVALID_HANDLE_VALUE)
    {
        m_ovlp.hEvent = 0;
    }
    else
    {
        m_ovlp.hEvent = CreateEvent(0, TRUE, FALSE, NULL);
        if (m_ovlp.hEvent)
        {
            m_bIsLoadSuccessfully = TRUE;
        }
    }

    m_BytesReturned = 0;

    //
    // Check if we are running in WOW64
    //
    m_bIsWow64Process = FALSE;

    if (ms_Version.IsWindowsXPOrGreater())
    {
        const HMODULE hKernel32 = ::GetModuleHandle(TEXT("kernel32.dll"));
        if (hKernel32)
        {
            m_pfnIsWow64Process = reinterpret_cast<IsWow64ProcessPtr>(::GetProcAddress(hKernel32, "IsWow64Process"));
            if (m_pfnIsWow64Process)
            {
                m_pfnIsWow64Process(GetCurrentProcess(), &m_bIsWow64Process);
            }
        }
    }

    if (m_bIsWow64Process)
    {
        // Initialize CWow64Helper::m_Handle32to64
        TCP_AdapterList AdaptersList = { 0 };  // NOLINT(clang-diagnostic-missing-field-initializers)
        GetTcpipBoundAdaptersInfo(&AdaptersList);
    }
}

/**
 * @brief CNdisApi destructor that closes the driver file handle and the event handle of the OVERLAPPED structure.
 *
 * This destructor ensures that the driver file handle and the event handle associated with the
 * OVERLAPPED structure are properly closed when the CNdisApi instance is destroyed.
 */
CNdisApi::~CNdisApi()
{
    if (m_hFileHandle != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(m_hFileHandle);
    }

    if (m_ovlp.hEvent)
    {
        ::CloseHandle(m_ovlp.hEvent);
    }
}

/**
 * @brief Sends a control code directly to the NDISAPI driver.
 *
 * @param dwService The control code for the operation.
 * @param BuffIn A pointer to the input buffer that contains the data required to perform the operation.
 * @param SizeIn The size of the input buffer, in bytes.
 * @param BuffOut A pointer to the output buffer that is to receive the data returned by the operation.
 * @param SizeOut The size of the output buffer, in bytes.
 * @param SizeRet A pointer to a variable that receives the size of the data stored in the output buffer, in bytes.
 * @param povlp A pointer to an OVERLAPPED structure. Use NULL for synchronous operation.
 * @return BOOL Returns TRUE if the operation completes successfully, FALSE otherwise.
 *
 * This function sends a control code to the NDISAPI driver, either in a synchronous or asynchronous manner,
 * depending on the value of the 'povlp' parameter.
 */
BOOL CNdisApi::DeviceIoControl(DWORD dwService, void* BuffIn, int SizeIn, void* BuffOut, int SizeOut, LPDWORD SizeRet, LPOVERLAPPED povlp) const
{
    BOOL Ret = 0;

    // Supports overlapped and non-overlapped IO

    if (!SizeRet) SizeRet = &m_BytesReturned;

    if (m_hFileHandle != INVALID_HANDLE_VALUE)
    {
        if (povlp == NULL)
            Ret = ::DeviceIoControl(m_hFileHandle, dwService, BuffIn, SizeIn, BuffOut, SizeOut, SizeRet, &m_ovlp);
        else
            Ret = ::DeviceIoControl(m_hFileHandle, dwService, BuffIn, SizeIn, BuffOut, SizeOut, SizeRet, povlp);

    }

    return Ret;
}

/**
 * @brief Retrieves the NDISAPI driver version.
 *
 * @return ULONG Returns the NDISAPI driver version if successful, or 0xFFFFFFFF if unsuccessful.
 *
 * This function retrieves the version number of the NDISAPI driver by sending an IOCTL_NDISRD_GET_VERSION control code
 * to the driver using DeviceIoControl.
 */
ULONG CNdisApi::GetVersion() const
{
    ULONG nDriverAPIVersion = 0xFFFFFFFF;

    DeviceIoControl(
        IOCTL_NDISRD_GET_VERSION,
        &nDriverAPIVersion,
        sizeof(ULONG),
        &nDriverAPIVersion,
        sizeof(ULONG),
        NULL,   // Bytes Returned
        NULL
    );

    return nDriverAPIVersion;
}

/**
 * @brief Retrieves the list of TCPIP-bound adapters.
 *
 * @param pAdapters Pointer to a TCP_AdapterList structure that receives the adapter list.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function retrieves the list of network adapters available to Windows Packet Filter by sending an
 * IOCTL_NDISRD_GET_TCPIP_INTERFACES control code to the NDISAPI driver using DeviceIoControl.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function retrieves the 64-bit adapter
 * handles and converts them to 32-bit handles using the Wow64Helper.
 */
BOOL CNdisApi::GetTcpipBoundAdaptersInfo(PTCP_AdapterList pAdapters) const
{
    BOOL bIOResult;

#ifndef _WIN64
    TCP_AdapterList_WOW64 adaptersList = { 0 };  // NOLINT(clang-diagnostic-missing-field-initializers)

    if (m_bIsWow64Process)
    {
        // In case of WOW64 process pass our own structure to driver
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_GET_TCPIP_INTERFACES,
            &adaptersList,
            sizeof(TCP_AdapterList_WOW64),
            &adaptersList,
            sizeof(TCP_AdapterList_WOW64),
            NULL,   // Bytes Returned
            NULL
        );

        if (bIOResult)
        {
            // Update WOW64 handle conversion helper
            m_Wow64Helper.Update(adaptersList);

            // Zero-initialize
            ZeroMemory(pAdapters, sizeof(TCP_AdapterList));

            // Simply copy all the fields except adapters handles
            pAdapters->m_nAdapterCount = adaptersList.m_nAdapterCount;
            memmove(pAdapters->m_szAdapterNameList, adaptersList.m_szAdapterNameList, sizeof(pAdapters->m_szAdapterNameList));
            memmove(pAdapters->m_nAdapterMediumList, adaptersList.m_nAdapterMediumList, sizeof(pAdapters->m_nAdapterMediumList));
            memmove(pAdapters->m_czCurrentAddress, adaptersList.m_czCurrentAddress, sizeof(pAdapters->m_czCurrentAddress));
            memmove(pAdapters->m_usMTU, adaptersList.m_usMTU, sizeof(pAdapters->m_usMTU));

            // Convert 64 bit handles to 32 bit ones
            for (size_t i = 0; i < pAdapters->m_nAdapterCount; ++i)
            {
                pAdapters->m_nAdapterHandle[i] = reinterpret_cast<HANDLE>(m_Wow64Helper.From64to32Handle(
                    adaptersList.m_nAdapterHandle[i].QuadPart));
            }
        }
    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_GET_TCPIP_INTERFACES,
            pAdapters,
            sizeof(TCP_AdapterList),
            pAdapters,
            sizeof(TCP_AdapterList),
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Sends a packet to the Microsoft TCP/IP stack.
 *
 * @param pPacket Pointer to an ETH_REQUEST structure that contains the packet to be sent.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sends a packet to the Microsoft TCP/IP stack by sending an IOCTL_NDISRD_SEND_PACKET_TO_MSTCP
 * control code to the NDISAPI driver using DeviceIoControl.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function converts the adapter handle
 * and buffer pointer using the Wow64Helper before sending the IOCTL.
 */
BOOL CNdisApi::SendPacketToMstcp(PETH_REQUEST pPacket) const
{
    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        ETH_REQUEST_WOW64 EthRequest;
        INTERMEDIATE_BUFFER_WOW64 Buffer;

        // Initialize INTERMEDIATE_BUFFER_WOW64
        Buffer.m_dwDeviceFlags = pPacket->EthPacket.Buffer->m_dwDeviceFlags;
        Buffer.m_Flags = pPacket->EthPacket.Buffer->m_Flags;
        Buffer.m_8021q = pPacket->EthPacket.Buffer->m_8021q;
        Buffer.m_FilterID = pPacket->EthPacket.Buffer->m_FilterID;
        memmove(Buffer.m_Reserved, pPacket->EthPacket.Buffer->m_Reserved, sizeof(ULONG) * 4);
        Buffer.m_Length = pPacket->EthPacket.Buffer->m_Length;
        memmove(Buffer.m_IBuffer, pPacket->EthPacket.Buffer->m_IBuffer, Buffer.m_Length);

        // Initialize ETH_REQUEST_WOW64
        EthRequest.hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pPacket->hAdapterHandle);
        EthRequest.EthPacket.Buffer.HighPart = 0;
        EthRequest.EthPacket.Buffer.LowPart = (ULONG_PTR)&Buffer;

        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SEND_PACKET_TO_MSTCP,
            &EthRequest,
            sizeof(ETH_REQUEST_WOW64),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );

    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SEND_PACKET_TO_MSTCP,
            pPacket,
            sizeof(ETH_REQUEST),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Sends a packet to the network adapter.
 *
 * @param pPacket Pointer to an ETH_REQUEST structure that contains the packet to be sent.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sends a packet to the network adapter by sending an IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER
 * control code to the NDISAPI driver using DeviceIoControl.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function converts the adapter handle
 * and buffer pointer using the Wow64Helper before sending the IOCTL.
 */
BOOL CNdisApi::SendPacketToAdapter(PETH_REQUEST pPacket) const
{
    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        ETH_REQUEST_WOW64 EthRequest;
        INTERMEDIATE_BUFFER_WOW64 Buffer;

        // Initialize INTERMEDIATE_BUFFER_WOW64
        Buffer.m_dwDeviceFlags = pPacket->EthPacket.Buffer->m_dwDeviceFlags;
        Buffer.m_Flags = pPacket->EthPacket.Buffer->m_Flags;
        Buffer.m_8021q = pPacket->EthPacket.Buffer->m_8021q;
        Buffer.m_FilterID = pPacket->EthPacket.Buffer->m_FilterID;
        memmove(Buffer.m_Reserved, pPacket->EthPacket.Buffer->m_Reserved, sizeof(ULONG) * 4);
        Buffer.m_Length = pPacket->EthPacket.Buffer->m_Length;
        memmove(Buffer.m_IBuffer, pPacket->EthPacket.Buffer->m_IBuffer, Buffer.m_Length);

        // Initialize ETH_REQUEST_WOW64
        EthRequest.hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pPacket->hAdapterHandle);
        EthRequest.EthPacket.Buffer.HighPart = 0;
        EthRequest.EthPacket.Buffer.LowPart = (ULONG_PTR)&Buffer;

        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER,
            &EthRequest,
            sizeof(ETH_REQUEST_WOW64),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );

    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER,
            pPacket,
            sizeof(ETH_REQUEST),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Reads a packet from the Windows Packet Filter driver.
 *
 * @param pPacket Pointer to an ETH_REQUEST structure that will receive the read packet.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function reads a packet from the NDISAPI driver by sending an IOCTL_NDISRD_READ_PACKET
 * control code to the NDISAPI driver using DeviceIoControl.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function converts the adapter handle
 * and buffer pointer using the Wow64Helper before sending the IOCTL, and copies the resulting packet from
 * INTERMEDIATE_BUFFER_WOW64 to INTERMEDIATE_BUFFER.
 */
BOOL CNdisApi::ReadPacket(PETH_REQUEST pPacket) const
{
    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        ETH_REQUEST_WOW64 EthRequest;
        INTERMEDIATE_BUFFER_WOW64 Buffer;

        // Initialize ETH_REQUEST_WOW64
        EthRequest.hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pPacket->hAdapterHandle);
        EthRequest.EthPacket.Buffer.HighPart = 0;
        EthRequest.EthPacket.Buffer.LowPart = (ULONG_PTR)&Buffer;

        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_READ_PACKET,
            &EthRequest,
            sizeof(ETH_REQUEST_WOW64),
            &EthRequest,
            sizeof(ETH_REQUEST_WOW64),
            NULL,   // Bytes Returned
            NULL
        );

        if (bIOResult)
        {
            // Copy the resulting packet from INTERMEDIATE_BUFFER_WOW64 to INTERMEDIATE_BUFFER
            pPacket->EthPacket.Buffer->m_dwDeviceFlags = Buffer.m_dwDeviceFlags;
            pPacket->EthPacket.Buffer->m_Flags = Buffer.m_Flags;
            pPacket->EthPacket.Buffer->m_8021q = Buffer.m_8021q;
            pPacket->EthPacket.Buffer->m_FilterID = Buffer.m_FilterID;
            memmove(pPacket->EthPacket.Buffer->m_Reserved, Buffer.m_Reserved, sizeof(ULONG) * 4);
            pPacket->EthPacket.Buffer->m_Length = Buffer.m_Length;
            memmove(pPacket->EthPacket.Buffer->m_IBuffer, Buffer.m_IBuffer, Buffer.m_Length);
        }
    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_READ_PACKET,
            pPacket,
            sizeof(ETH_REQUEST),
            pPacket,
            sizeof(ETH_REQUEST),
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Sends multiple packets to the MSTCP (TCP/IP stack) from the Windows Packet Filter driver.
 *
 * @param pPackets Pointer to an ETH_M_REQUEST structure containing an array of packets to be sent.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sends multiple packets to the MSTCP (TCP/IP stack) from the Windows Packet Filter driver
 * by sending an IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP control code to the Windows Packet Filter driver
 * using DeviceIoControl.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function converts the adapter handle
 * and buffer pointer using the Wow64Helper before sending the IOCTL. It also allocates and initializes
 * ETH_M_REQUEST_WOW64 and INTERMEDIATE_BUFFER_WOW64 structures for the IOCTL call.
 */
BOOL CNdisApi::SendPacketsToMstcp(PETH_M_REQUEST pPackets) const
{
    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        PINTERMEDIATE_BUFFER_WOW64 Buffers;

        const PETH_M_REQUEST_WOW64 pEthRequest = static_cast<PETH_M_REQUEST_WOW64>(malloc(
            sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64) * (pPackets->dwPacketsNumber - 1)));
        Buffers = static_cast<PINTERMEDIATE_BUFFER_WOW64>(malloc(pPackets->dwPacketsNumber * sizeof(INTERMEDIATE_BUFFER_WOW64)));

        if (Buffers && pEthRequest)
        {
            memset(pEthRequest, 0, sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64) * (pPackets->dwPacketsNumber - 1));
            memset(Buffers, 0, pPackets->dwPacketsNumber * sizeof(INTERMEDIATE_BUFFER_WOW64));
            pEthRequest->hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle(reinterpret_cast<unsigned>(pPackets->hAdapterHandle));
            pEthRequest->dwPacketsNumber = pPackets->dwPacketsNumber;

            for (unsigned i = 0; i < pPackets->dwPacketsNumber; ++i)
            {
                // Initialize INTERMEDIATE_BUFFER_WOW64
                Buffers[i].m_dwDeviceFlags = pPackets->EthPacket[i].Buffer->m_dwDeviceFlags;
                Buffers[i].m_Flags = pPackets->EthPacket[i].Buffer->m_Flags;
                Buffers[i].m_8021q = pPackets->EthPacket[i].Buffer->m_8021q;
                Buffers[i].m_FilterID = pPackets->EthPacket[i].Buffer->m_FilterID;
                memmove(Buffers[i].m_Reserved, pPackets->EthPacket[i].Buffer->m_Reserved, sizeof(ULONG) * 4);
                Buffers[i].m_Length = pPackets->EthPacket[i].Buffer->m_Length;
                memmove(Buffers[i].m_IBuffer, pPackets->EthPacket[i].Buffer->m_IBuffer, Buffers[i].m_Length);

                // Initialize ETH_REQUEST_WOW64
                pEthRequest->EthPacket[i].Buffer.HighPart = 0;
                pEthRequest->EthPacket[i].Buffer.LowPart = reinterpret_cast<ULONG_PTR>(&Buffers[i]);
            }

            bIOResult = DeviceIoControl(
                IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP,
                pEthRequest,
                sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64) * (pPackets->dwPacketsNumber - 1),
                NULL,
                0,
                NULL,   // Bytes Returned
                NULL
            );

            free(Buffers);
            free(pEthRequest);
        }
        else
        {
            if (Buffers)
                free(Buffers);

            if (pEthRequest)
                free(pEthRequest);

            return FALSE;
        }
    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP,
            pPackets,
            sizeof(ETH_M_REQUEST) + sizeof(NDISRD_ETH_Packet) * (pPackets->dwPacketsNumber - 1),  // NOLINT(bugprone-narrowing-conversions, cppcoreguidelines-narrowing-conversions)
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Sends multiple packets to the network adapter from the Windows Packet Filter driver.
 *
 * @param pPackets Pointer to an ETH_M_REQUEST structure containing an array of packets to be sent.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sends multiple packets to the network adapter from the Windows Packet Filter driver
 * by sending an IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER control code to the Windows Packet Filter driver
 * using DeviceIoControl.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function converts the adapter handle
 * and buffer pointer using the Wow64Helper before sending the IOCTL. It also allocates and initializes
 * ETH_M_REQUEST_WOW64 and INTERMEDIATE_BUFFER_WOW64 structures for the IOCTL call.
 */
BOOL CNdisApi::SendPacketsToAdapter(PETH_M_REQUEST pPackets) const
{
    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        PINTERMEDIATE_BUFFER_WOW64 Buffers;

        const PETH_M_REQUEST_WOW64 pEthRequest = static_cast<PETH_M_REQUEST_WOW64>(malloc(
            sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64) * (pPackets->dwPacketsNumber - 1)));
        Buffers = static_cast<PINTERMEDIATE_BUFFER_WOW64>(malloc(pPackets->dwPacketsNumber * sizeof(INTERMEDIATE_BUFFER_WOW64)));

        if (Buffers && pEthRequest)
        {
            memset(pEthRequest, 0, sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64) * (pPackets->dwPacketsNumber - 1));
            memset(Buffers, 0, pPackets->dwPacketsNumber * sizeof(INTERMEDIATE_BUFFER_WOW64));
            pEthRequest->hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle(reinterpret_cast<unsigned>(pPackets->hAdapterHandle));
            pEthRequest->dwPacketsNumber = pPackets->dwPacketsNumber;

            for (unsigned i = 0; i < pPackets->dwPacketsNumber; ++i)
            {
                // Initialize INTERMEDIATE_BUFFER_WOW64
                Buffers[i].m_dwDeviceFlags = pPackets->EthPacket[i].Buffer->m_dwDeviceFlags;
                Buffers[i].m_Flags = pPackets->EthPacket[i].Buffer->m_Flags;
                Buffers[i].m_8021q = pPackets->EthPacket[i].Buffer->m_8021q;
                Buffers[i].m_FilterID = pPackets->EthPacket[i].Buffer->m_FilterID;
                memmove(Buffers[i].m_Reserved, pPackets->EthPacket[i].Buffer->m_Reserved, sizeof(ULONG) * 4);
                Buffers[i].m_Length = pPackets->EthPacket[i].Buffer->m_Length;
                memmove(Buffers[i].m_IBuffer, pPackets->EthPacket[i].Buffer->m_IBuffer, Buffers[i].m_Length);

                // Initialize ETH_REQUEST_WOW64
                pEthRequest->EthPacket[i].Buffer.HighPart = 0;
                pEthRequest->EthPacket[i].Buffer.LowPart = reinterpret_cast<ULONG_PTR>(&Buffers[i]);
            }

            bIOResult = DeviceIoControl(
                IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER,
                pEthRequest,
                sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64) * (pPackets->dwPacketsNumber - 1),
                NULL,
                0,
                NULL,   // Bytes Returned
                NULL
            );

            free(Buffers);
            free(pEthRequest);
        }
        else
        {
            if (Buffers)
                free(Buffers);

            if (pEthRequest)
                free(pEthRequest);

            return FALSE;
        }
    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER,
            pPackets,
            sizeof(ETH_M_REQUEST) + sizeof(NDISRD_ETH_Packet) * (pPackets->dwPacketsNumber - 1),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Reads multiple packets from the network adapter through the Windows Packet Filter driver.
 *
 * @param pPackets Pointer to an ETH_M_REQUEST structure containing an array of packets to be read.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function reads multiple packets from the network adapter through the Windows Packet Filter
 * driver by sending an IOCTL_NDISRD_READ_PACKETS control code to the Windows Packet Filter driver
 * using DeviceIoControl.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function allocates and initializes
 * ETH_M_REQUEST_WOW64 and INTERMEDIATE_BUFFER_WOW64 structures for the IOCTL call. It also converts the adapter
 * handle and buffer pointer using the Wow64Helper before sending the IOCTL.
 */
BOOL CNdisApi::ReadPackets(PETH_M_REQUEST pPackets) const
{
    BOOL bIOResult = FALSE;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        PETH_M_REQUEST_WOW64 pEthRequest = (PETH_M_REQUEST_WOW64)malloc(sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64) * (pPackets->dwPacketsNumber - 1));

        if (!pEthRequest)
            return bIOResult;

        PINTERMEDIATE_BUFFER_WOW64 Buffers = (PINTERMEDIATE_BUFFER_WOW64)malloc(pPackets->dwPacketsNumber * sizeof(INTERMEDIATE_BUFFER_WOW64));

        if (!Buffers)
        {
            if (pEthRequest)
                free(pEthRequest);

            return bIOResult;
        }

        memset(pEthRequest, 0, sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64) * (pPackets->dwPacketsNumber - 1));
        memset(Buffers, 0, pPackets->dwPacketsNumber * sizeof(INTERMEDIATE_BUFFER_WOW64));

        if (Buffers && pEthRequest)
        {
            pEthRequest->hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pPackets->hAdapterHandle);
            pEthRequest->dwPacketsNumber = pPackets->dwPacketsNumber;

            for (unsigned i = 0; i < pPackets->dwPacketsNumber; ++i)
            {
                // Initialize ETH_REQUEST_WOW64
                pEthRequest->EthPacket[i].Buffer.HighPart = 0;
                pEthRequest->EthPacket[i].Buffer.LowPart = (ULONG_PTR)&Buffers[i];
            }

            bIOResult = DeviceIoControl(
                IOCTL_NDISRD_READ_PACKETS,
                pEthRequest,
                sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64) * (pPackets->dwPacketsNumber - 1),
                pEthRequest,
                sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64) * (pPackets->dwPacketsNumber - 1),
                NULL,   // Bytes Returned
                NULL
            );

            if (bIOResult)
            {
                pPackets->dwPacketsSuccess = pEthRequest->dwPacketsSuccess;

                for (unsigned i = 0; i < pEthRequest->dwPacketsSuccess; ++i)
                {
                    // Copy back
                    pPackets->EthPacket[i].Buffer->m_dwDeviceFlags = Buffers[i].m_dwDeviceFlags;
                    pPackets->EthPacket[i].Buffer->m_Flags = Buffers[i].m_Flags;
                    pPackets->EthPacket[i].Buffer->m_8021q = Buffers[i].m_8021q;
                    pPackets->EthPacket[i].Buffer->m_FilterID = Buffers[i].m_FilterID;
                    memmove(pPackets->EthPacket[i].Buffer->m_Reserved, Buffers[i].m_Reserved, sizeof(ULONG) * 4);
                    pPackets->EthPacket[i].Buffer->m_Length = Buffers[i].m_Length;
                    memmove(pPackets->EthPacket[i].Buffer->m_IBuffer, Buffers[i].m_IBuffer, Buffers[i].m_Length);
                }
            }

            free(Buffers);
            free(pEthRequest);
        }
        else
        {
            if (Buffers)
                free(Buffers);

            if (pEthRequest)
                free(pEthRequest);

            return FALSE;
        }
    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_READ_PACKETS,
            pPackets,
            sizeof(ETH_M_REQUEST) + sizeof(NDISRD_ETH_Packet) * (pPackets->dwPacketsNumber - 1),
            pPackets,
            sizeof(ETH_M_REQUEST) + sizeof(NDISRD_ETH_Packet) * (pPackets->dwPacketsNumber - 1),
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Sets the filter mode of the network adapter for the Windows Packet Filter driver.
 *
 * @param pMode Pointer to an ADAPTER_MODE structure containing the adapter handle and the flags for the desired mode.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sets the filter mode of the network adapter for the Windows Packet Filter driver by sending an
 * IOCTL_NDISRD_SET_ADAPTER_MODE control code to the Windows Packet Filter driver using DeviceIoControl.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function initializes an
 * ADAPTER_MODE_WOW64 structure with the mode flags and the converted adapter handle using Wow64Helper
 * before sending the IOCTL.
 */
BOOL CNdisApi::SetAdapterMode(PADAPTER_MODE pMode) const
{
    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        ADAPTER_MODE_WOW64 AdapterMode;
        AdapterMode.dwFlags = pMode->dwFlags;
        AdapterMode.hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle(reinterpret_cast<unsigned>(pMode->hAdapterHandle));

        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SET_ADAPTER_MODE,
            &AdapterMode,
            sizeof(ADAPTER_MODE_WOW64),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SET_ADAPTER_MODE,
            pMode,
            sizeof(ADAPTER_MODE),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Retrieves the filter mode of the network adapter for the Windows Packet Filter driver.
 *
 * @param pMode Pointer to an ADAPTER_MODE structure containing the adapter handle. On success, the structure will be updated with the adapter mode flags.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function retrieves the filter mode of the network adapter for the Windows Packet Filter driver by sending an
 * IOCTL_NDISRD_GET_ADAPTER_MODE control code to the Windows Packet Filter driver using DeviceIoControl.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function initializes an
 * ADAPTER_MODE_WOW64 structure with the converted adapter handle using Wow64Helper before sending the IOCTL.
 * If the operation is successful, the mode flags are copied back to the input ADAPTER_MODE structure.
 */
BOOL CNdisApi::GetAdapterMode(PADAPTER_MODE pMode) const
{
    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        ADAPTER_MODE_WOW64 AdapterMode;
        AdapterMode.hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pMode->hAdapterHandle);

        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_GET_ADAPTER_MODE,
            &AdapterMode,
            sizeof(ADAPTER_MODE_WOW64),
            &AdapterMode,
            sizeof(ADAPTER_MODE_WOW64),
            NULL,   // Bytes Returned
            NULL
        );

        if (bIOResult)
            pMode->dwFlags = AdapterMode.dwFlags;

    }
    else
#endif // _WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_GET_ADAPTER_MODE,
            pMode,
            sizeof(ADAPTER_MODE),
            pMode,
            sizeof(ADAPTER_MODE),
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Flushes the packet queue of the specified network adapter.
 *
 * @param hAdapter The handle of the network adapter.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function flushes the packet queue of the specified network adapter by sending an
 * IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE control code to the Windows Packet Filter driver using DeviceIoControl.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function converts the adapter handle using Wow64Helper
 * before sending the IOCTL.
 */
BOOL CNdisApi::FlushAdapterPacketQueue(HANDLE hAdapter) const
{
    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        ULARGE_INTEGER h64Adapter;
        h64Adapter.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)hAdapter);

        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE,
            &h64Adapter,
            sizeof(ULARGE_INTEGER),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE,
            &hAdapter,
            sizeof(HANDLE),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Retrieves the size of the packet queue for the specified network adapter.
 *
 * @param hAdapter The handle of the network adapter.
 * @param pdwSize Pointer to a DWORD variable that receives the packet queue size.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function retrieves the size of the packet queue for the specified network adapter by sending an
 * IOCTL_NDISRD_ADAPTER_QUEUE_SIZE control code to the Windows Packet Filter driver using DeviceIoControl.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function converts the adapter handle using Wow64Helper
 * before sending the IOCTL.
 */
BOOL CNdisApi::GetAdapterPacketQueueSize(HANDLE hAdapter, PDWORD pdwSize) const
{
    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        ULARGE_INTEGER h64Adapter;
        h64Adapter.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)hAdapter);

        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_ADAPTER_QUEUE_SIZE,
            &h64Adapter,
            sizeof(ULARGE_INTEGER),
            pdwSize,
            sizeof(DWORD),
            NULL,   // Bytes Returned
            NULL
        );
    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_ADAPTER_QUEUE_SIZE,
            &hAdapter,
            sizeof(HANDLE),
            pdwSize,
            sizeof(DWORD),
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Sets a Win32 event to be signaled when a packet arrives at the specified network adapter.
 *
 * @param hAdapter The handle of the network adapter.
 * @param hWin32Event The handle of the Win32 event to be signaled when a packet arrives.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sets a Win32 event to be signaled when a packet arrives at the specified network adapter by
 * sending an IOCTL_NDISRD_SET_EVENT control code to the Windows Packet Filter driver using DeviceIoControl.
 *
 * The function converts the event handle to a Ring0 event handle for Windows NT platforms, and to a VxD event handle
 * for Windows 9x/ME platforms.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function initializes an ADAPTER_EVENT_WOW64
 * structure with the converted adapter and event handles using Wow64Helper before sending the IOCTL.
 */
BOOL CNdisApi::SetPacketEvent(HANDLE hAdapter, HANDLE hWin32Event) const
{
    HANDLE hRing0Event;
    ADAPTER_EVENT AdapterEvent;

    AdapterEvent.hAdapterHandle = hAdapter;

    if (ms_Version.IsWindowsNTPlatform())
    {
        // Windows NT
        hRing0Event = hWin32Event;
    }
    else
    {
        // Windows 9x/ME
        const HINSTANCE hKernel32Dll = LoadLibrary(TEXT("kernel32.dll"));

        if (!hKernel32Dll)
            return FALSE;

        HANDLE(WINAPI * pfOpenVxDHandle)(HANDLE) = reinterpret_cast<HANDLE(__stdcall*)(HANDLE)>(GetProcAddress(
            hKernel32Dll, "OpenVxDHandle"));

        if (!pfOpenVxDHandle)
            return FALSE;

        if (hWin32Event)
            hRing0Event = pfOpenVxDHandle(hWin32Event);
        else
            hRing0Event = NULL;

        FreeLibrary(hKernel32Dll);
    }

    AdapterEvent.hEvent = hRing0Event;

    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        ADAPTER_EVENT_WOW64 AdapterEvent64;
        AdapterEvent64.hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)AdapterEvent.hAdapterHandle);
        AdapterEvent64.hEvent.HighPart = 0;
        AdapterEvent64.hEvent.LowPart = (ULONG_PTR)AdapterEvent.hEvent;

        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SET_EVENT,
            &AdapterEvent64,
            sizeof(ADAPTER_EVENT_WOW64),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SET_EVENT,
            &AdapterEvent,
            sizeof(ADAPTER_EVENT),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Sets a Win32 event to be signaled when a NDISWAN adapter connect/disconnect occurs.
 *
 * @param hWin32Event The handle of the Win32 event to be signaled when a NDISWAN adapter connect/disconnect occurs.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sets a Win32 event to be signaled when a NDISWAN adapter connect/disconnect occurs by sending an
 * IOCTL_NDISRD_SET_WAN_EVENT control code to the Windows Packet Filter driver using DeviceIoControl.
 *
 * The function converts the event handle to a Ring0 event handle for Windows NT platforms, and to a VxD event handle
 * for Windows 9x/ME platforms.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function initializes an ULARGE_INTEGER
 * structure with the converted event handle before sending the IOCTL.
 */
BOOL CNdisApi::SetWANEvent(HANDLE hWin32Event) const
{
    HANDLE hRing0Event;

    if (ms_Version.IsWindowsNTPlatform())
    {
        // Windows NT
        hRing0Event = hWin32Event;
    }
    else
    {
        // Windows 9x/ME
        const HINSTANCE hKernel32Dll = LoadLibrary(TEXT("kernel32.dll"));

        if (!hKernel32Dll)
            return FALSE;

        HANDLE(WINAPI * pfOpenVxDHandle)(HANDLE) = reinterpret_cast<HANDLE(__stdcall*)(HANDLE)>(GetProcAddress(hKernel32Dll, "OpenVxDHandle"));

        if (!pfOpenVxDHandle)
            return FALSE;

        if (hWin32Event)
            hRing0Event = pfOpenVxDHandle(hWin32Event);
        else
            hRing0Event = NULL;

        FreeLibrary(hKernel32Dll);
    }

    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        ULARGE_INTEGER ulRing0Event;
        ulRing0Event.HighPart = 0;
        ulRing0Event.LowPart = (ULONG_PTR)hRing0Event;

        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SET_WAN_EVENT,
            &ulRing0Event,
            sizeof(ULARGE_INTEGER),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SET_WAN_EVENT,
            &hRing0Event,
            sizeof(HANDLE),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Sets a Win32 event to be signaled when a network adapter list change occurs.
 *
 * @param hWin32Event The handle of the Win32 event to be signaled when a network adapter list change occurs.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sets a Win32 event to be signaled when a network adapter list change occurs by sending an
 * IOCTL_NDISRD_SET_ADAPTER_EVENT control code to the Windows Packet Filter driver using DeviceIoControl.
 *
 * The function converts the event handle to a Ring0 event handle for Windows NT platforms, and to a VxD event handle
 * for Windows 9x/ME platforms.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function initializes an ULARGE_INTEGER
 * structure with the converted event handle before sending the IOCTL.
 */
BOOL CNdisApi::SetAdapterListChangeEvent(HANDLE hWin32Event) const
{
    HANDLE hRing0Event;

    if (ms_Version.IsWindowsNTPlatform())
    {
        // Windows NT
        hRing0Event = hWin32Event;
    }
    else
    {
        // Windows 9x/ME
        const HINSTANCE hKernel32Dll = LoadLibrary(TEXT("kernel32.dll"));

        if (!hKernel32Dll)
            return FALSE;

        HANDLE(WINAPI * pfOpenVxDHandle)(HANDLE) = reinterpret_cast<HANDLE(__stdcall*)(HANDLE)>(GetProcAddress(hKernel32Dll, "OpenVxDHandle"));

        if (!pfOpenVxDHandle)
            return FALSE;

        if (hWin32Event)
            hRing0Event = pfOpenVxDHandle(hWin32Event);
        else
            hRing0Event = NULL;

        FreeLibrary(hKernel32Dll);
    }

    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        ULARGE_INTEGER ulRing0Event;
        ulRing0Event.HighPart = 0;
        ulRing0Event.LowPart = (ULONG_PTR)hRing0Event;

        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SET_ADAPTER_EVENT,
            &ulRing0Event,
            sizeof(ULARGE_INTEGER),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SET_ADAPTER_EVENT,
            &hRing0Event,
            sizeof(HANDLE),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Sends an NDIS request to the network adapter through the Windows Packet Filter driver.
 *
 * @param OidData A pointer to the PACKET_OID_DATA structure that contains the NDIS request data.
 * @param Set A boolean value that indicates whether the request is a set (TRUE) or get (FALSE) operation.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sends an NDIS request to the network adapter through the Windows Packet Filter driver
 * using DeviceIoControl.
 * The request can be either a set or a get operation, depending on the value of the Set parameter.
 * The function uses an OVERLAPPED structure to handle asynchronous I/O operations.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function allocates and initializes
 * a PACKET_OID_DATA_WOW64 structure with the original PACKET_OID_DATA structure's data, and sends the IOCTL
 * using the PACKET_OID_DATA_WOW64 structure.
 *
 * If the operation is not successful, the function returns FALSE.
 */
BOOL CNdisApi::NdisrdRequest(PPACKET_OID_DATA OidData, BOOL Set) const
{
    OVERLAPPED Overlap;
    const DWORD dwLength = OidData->Length;

    Overlap.Offset = 0;
    Overlap.OffsetHigh = 0;
    Overlap.hEvent = CreateEvent(
        NULL,
        FALSE,
        FALSE,
        NULL
    );

    if (Overlap.hEvent == NULL)
    {
        return FALSE;
    }

    if (!ResetEvent(Overlap.hEvent))
    {
        ::CloseHandle(Overlap.hEvent);
        return FALSE;
    }

    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        PPACKET_OID_DATA_WOW64 OidData64 = (PPACKET_OID_DATA_WOW64)malloc(sizeof(PACKET_OID_DATA_WOW64) + OidData->Length - 1);
        if (OidData64)
        {
            OidData64->hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)OidData->hAdapterHandle);
            OidData64->Oid = OidData->Oid;
            OidData64->Length = OidData->Length;
            if (Set)
                memmove(OidData64->Data, OidData->Data, OidData->Length);

            bIOResult = DeviceIoControl(
                (DWORD)Set ? IOCTL_NDISRD_NDIS_SET_REQUEST : IOCTL_NDISRD_NDIS_GET_REQUEST,
                OidData64,
                sizeof(PACKET_OID_DATA_WOW64) - 1 + OidData->Length,
                OidData64,
                sizeof(PACKET_OID_DATA_WOW64) - 1 + OidData->Length,
                NULL,   // Bytes Returned
                &Overlap
            );

            if ((!bIOResult) && (ERROR_IO_PENDING == GetLastError()))
            {
                WaitForSingleObject(Overlap.hEvent, INFINITE);

                if (!Set)
                {
                    memmove(OidData->Data, OidData64->Data, OidData64->Length);
                    OidData->Length = OidData64->Length;
                }
            }
            else
                if (!bIOResult)
                {
                    ::CloseHandle(Overlap.hEvent);
                    free(OidData64);
                    return FALSE;
                }

            free(OidData64);
        }
    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            static_cast<DWORD>(Set) ? IOCTL_NDISRD_NDIS_SET_REQUEST : IOCTL_NDISRD_NDIS_GET_REQUEST,
            OidData,
            sizeof(PACKET_OID_DATA) - 1 + OidData->Length,
            OidData,
            sizeof(PACKET_OID_DATA) - 1 + OidData->Length,
            NULL,   // Bytes Returned
            &Overlap
        );

        if ((!bIOResult) && (ERROR_IO_PENDING == GetLastError()))
            WaitForSingleObject(Overlap.hEvent, INFINITE);
        else
            if (!bIOResult)
            {
                ::CloseHandle(Overlap.hEvent);
                return FALSE;
            }
    }

    ::CloseHandle(Overlap.hEvent);

    if (dwLength == OidData->Length)
        return TRUE;

    return FALSE;
}

/**
 * @brief Retrieves the RAS links associated with a network adapter.
 *
 * @param hAdapter A handle to the network adapter for which the RAS links are to be retrieved.
 * @param pLinks A pointer to a RAS_LINKS structure that will receive the RAS links information.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function retrieves the RAS links associated with a network adapter by sending an
 * IOCTL_NDISRD_GET_RAS_LINKS control code to the Windows Packet Filter driver using DeviceIoControl.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function initializes an
 * ULARGE_INTEGER structure with the adapter handle before sending the IOCTL.
 */
BOOL CNdisApi::GetRasLinks(HANDLE hAdapter, PRAS_LINKS pLinks) const
{
    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        ULARGE_INTEGER h64Adapter;
        h64Adapter.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)hAdapter);

        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_GET_RAS_LINKS,
            &h64Adapter,
            sizeof(ULARGE_INTEGER),
            pLinks,
            sizeof(RAS_LINKS),
            NULL,   // Bytes Returned
            NULL
        );
    }
    else
#endif // _WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_GET_RAS_LINKS,
            &hAdapter,
            sizeof(HANDLE),
            pLinks,
            sizeof(RAS_LINKS),
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Sets the hardware packet filter for the network adapter.
 *
 * @param hAdapter The handle of the network adapter.
 * @param Filter The packet filter bitmask to be set.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sets the hardware packet filter for the network adapter by sending an NDIS set request
 * with OID_GEN_CURRENT_PACKET_FILTER. It uses the CNdisApi::NdisrdRequest function to send the request.
 *
 * The function allocates memory for the PACKET_OID_DATA structure, initializes it with the provided
 * filter bitmask, and sends the set request. After the operation, the memory for PACKET_OID_DATA is freed.
 */
BOOL CNdisApi::SetHwPacketFilter(HANDLE hAdapter, const DWORD Filter) const
{
    BOOL bRet = FALSE;
    const PPACKET_OID_DATA pPacket = static_cast<PPACKET_OID_DATA>(malloc(sizeof(PACKET_OID_DATA) + sizeof(DWORD) - 1));

    if (pPacket)
    {
        pPacket->Length = sizeof(DWORD);
        pPacket->Oid = OID_GEN_CURRENT_PACKET_FILTER;
        pPacket->hAdapterHandle = hAdapter;

        *reinterpret_cast<PDWORD>(pPacket->Data) = Filter;
        bRet = NdisrdRequest(pPacket, TRUE);

        free(pPacket);
    }

    return bRet;
}

/**
 * @brief Gets the hardware packet filter for the network adapter.
 *
 * @param hAdapter The handle of the network adapter.
 * @param pFilter A pointer to a DWORD variable that will receive the current packet filter bitmask.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function retrieves the hardware packet filter for the network adapter by sending an NDIS get request
 * with OID_GEN_CURRENT_PACKET_FILTER. It uses the CNdisApi::NdisrdRequest function to send the request.
 *
 * The function allocates memory for the PACKET_OID_DATA structure, initializes it, and sends the get request.
 * If the operation is successful, the function copies the retrieved packet filter bitmask to the pFilter
 * parameter. After the operation, the memory for PACKET_OID_DATA is freed.
 */
BOOL CNdisApi::GetHwPacketFilter(HANDLE hAdapter, PDWORD pFilter) const
{
    BOOL bRet = FALSE;

    const PPACKET_OID_DATA pPacket = static_cast<PPACKET_OID_DATA>(malloc(sizeof(PACKET_OID_DATA) + sizeof(DWORD) - 1));

    if (pPacket)
    {
        pPacket->Length = sizeof(DWORD);
        pPacket->Oid = OID_GEN_CURRENT_PACKET_FILTER;
        pPacket->hAdapterHandle = hAdapter;

        if (NdisrdRequest(pPacket, FALSE))
        {
            *pFilter = *reinterpret_cast<PDWORD>(pPacket->Data);

            bRet = TRUE;
        }

        free(pPacket);
    }
    return bRet;
}

/**
 * @brief Sets the hardware packet filter change event for the network adapter.
 *
 * @param hAdapter The handle of the network adapter.
 * @param hWin32Event The Win32 event handle to be signaled when a hardware filter on the adapter changes.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sets the hardware packet filter change event for the network adapter. The specified event will
 * be signaled when a hardware filter on the adapter changes. It uses DeviceIoControl
 * with the IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT code to perform the operation.
 *
 * The function first checks if the operating system is Windows NT or Windows 9x/ME. On Windows NT, the
 * ring 0 event is set to the provided Win32 event. On Windows 9x/ME, the function loads the kernel32.dll
 * library, resolves the OpenVxDHandle function, and calls it to obtain a ring 0 event from the provided
 * Win32 event. The function then initializes an ADAPTER_EVENT structure and sends the IOCTL using
 * DeviceIoControl.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function initializes an
 * ADAPTER_EVENT_WOW64 structure with the original ADAPTER_EVENT structure's data, and sends the IOCTL
 * using the ADAPTER_EVENT_WOW64 structure.
 */
BOOL CNdisApi::SetHwPacketFilterEvent(HANDLE hAdapter, HANDLE hWin32Event) const
{
    HANDLE hRing0Event;
    ADAPTER_EVENT AdapterEvent;

    AdapterEvent.hAdapterHandle = hAdapter;

    if (ms_Version.IsWindowsNTPlatform())
    {
        // Windows NT
        hRing0Event = hWin32Event;
    }
    else
    {
        // Windows 9x/ME
        const HINSTANCE hKernel32Dll = LoadLibrary(TEXT("kernel32.dll"));

        if (!hKernel32Dll)
            return FALSE;

        HANDLE(WINAPI * pfOpenVxDHandle)(HANDLE) = reinterpret_cast<HANDLE(__stdcall*)(HANDLE)>(GetProcAddress(hKernel32Dll, "OpenVxDHandle"));

        if (!pfOpenVxDHandle)
            return FALSE;

        if (hWin32Event)
            hRing0Event = pfOpenVxDHandle(hWin32Event);
        else
            hRing0Event = NULL;

        FreeLibrary(hKernel32Dll);
    }

    AdapterEvent.hEvent = hRing0Event;

    BOOL bIOResult;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        ADAPTER_EVENT_WOW64 AdapterEvent64;
        AdapterEvent64.hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)AdapterEvent.hAdapterHandle);
        AdapterEvent64.hEvent.HighPart = 0;
        AdapterEvent64.hEvent.LowPart = (ULONG_PTR)AdapterEvent.hEvent;

        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT,
            &AdapterEvent64,
            sizeof(ADAPTER_EVENT_WOW64),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }
    else
#endif //_WIN64
    {
        bIOResult = DeviceIoControl(
            IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT,
            &AdapterEvent,
            sizeof(ADAPTER_EVENT),
            NULL,
            0,
            NULL,   // Bytes Returned
            NULL
        );
    }

    return bIOResult;
}

/**
 * @brief Sets the static packet filter table for the Windows Packet Filter driver.
 *
 * @param pFilterList A pointer to the STATIC_FILTER_TABLE structure containing the packet filter rules.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sets the static packet filter table for the Windows Packet Filter driver. The table
 * contains a list of packet filter rules that determine which packets should be processed by the driver,
 * e.g. passed, dropped or redirected to user-mode application for further processing.
 * It uses DeviceIoControl with the IOCTL_NDISRD_SET_PACKET_FILTERS code to perform the operation.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function iterates through the
 * filter list and updates the adapter handle values using the From32to64Handle method from the WOW64 helper
 * before passing the filter list to the driver.
 */
BOOL CNdisApi::SetPacketFilterTable(PSTATIC_FILTER_TABLE pFilterList) const
{
    BOOL bIOResult = FALSE;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        // Adapter handle values in the table contain values which are not valid for the driver
        // and we need to pre-process filter table before passing it to the driver

        for (unsigned i = 0; i < pFilterList->m_TableSize; ++i)
        {
            if (pFilterList->m_StaticFilters[i].m_Adapter.QuadPart)
                pFilterList->m_StaticFilters[i].m_Adapter.QuadPart =
                m_Wow64Helper.From32to64Handle((unsigned)pFilterList->m_StaticFilters[i].m_Adapter.LowPart);
        }
    }
#endif //_WIN64

    bIOResult = DeviceIoControl(
        IOCTL_NDISRD_SET_PACKET_FILTERS,
        pFilterList,
        sizeof(STATIC_FILTER_TABLE) + (pFilterList->m_TableSize - ANY_SIZE) * sizeof(STATIC_FILTER),
        NULL,
        0,
        NULL,   // Bytes Returned
        NULL
    );

    return bIOResult;
}

/**
 * @brief Adds a static filter to the front of the filter list in the Windows Packet Filter driver.
 *
 * @param pFilter A pointer to the STATIC_FILTER structure containing the filter to be added.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function adds a static filter to the front of the filter list in the Windows Packet Filter driver.
 * The filter determines how packets are processed by the driver, e.g., passed, dropped, or redirected
 * to user-mode application for further processing. It uses DeviceIoControl with the
 * IOCTL_NDISRD_ADD_PACKET_FILTER_FRONT code to perform the operation.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function updates the adapter
 * handle value in the filter using the From32to64Handle method from the WOW64 helper before passing
 * the filter to the driver.
 */
BOOL CNdisApi::AddStaticFilterFront(PSTATIC_FILTER pFilter) const
{
    BOOL bIOResult = FALSE;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        // Adapter handle values in the filter contain values which are not valid for the driver
        // and we need to pre-process filter before passing it to the driver

        if (pFilter->m_Adapter.QuadPart)
            pFilter->m_Adapter.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pFilter->m_Adapter.LowPart);
    }
#endif //_WIN64

    bIOResult = DeviceIoControl(
        IOCTL_NDISRD_ADD_PACKET_FILTER_FRONT,
        pFilter,
        sizeof(STATIC_FILTER),
        NULL,
        0,
        NULL,   // Bytes Returned
        NULL
    );

    return bIOResult;
}

/**
 * @brief Adds a static filter to the end of the filter chain.
 *
 * This method appends a static filter to the end of the existing filter chain for packet processing.
 * In a 32-bit process on a 64-bit system, it converts the adapter handle from 32-bit to 64-bit using
 * the WOW64 helper before passing the filter to the driver. This ensures compatibility across different
 * system architectures. The filter is defined by the PSTATIC_FILTER structure, which includes details
 * such as the filter action, direction, and conditions.
 *
 * @param pFilter Pointer to the STATIC_FILTER structure that defines the filter to be added.
 * @return TRUE if the operation was successful, FALSE otherwise.
 */
BOOL CNdisApi::AddStaticFilterBack(PSTATIC_FILTER pFilter) const
{
    BOOL bIOResult = FALSE;

#ifndef _WIN64
    if (m_bIsWow64Process)
    {
        // Adapter handle values in the filter contain values which are not valid for the driver
        // and we need to pre-process filter before passing it to the driver

        if (pFilter->m_Adapter.QuadPart)
            pFilter->m_Adapter.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pFilter->m_Adapter.LowPart);
    }
#endif //_WIN64

    bIOResult = DeviceIoControl(
        IOCTL_NDISRD_ADD_PACKET_FILTER_BACK,
        pFilter,
        sizeof(STATIC_FILTER),
        NULL,
        0,
        NULL,   // Bytes Returned
        NULL
    );

    return bIOResult;
}

/**
 * @brief Inserts a static filter at a specified position in the filter chain.
 *
 * This method inserts a static filter into the filter chain at the specified position. The position
 * determines the order in which filters are applied, with lower values indicating higher priority.
 * In a 32-bit process on a 64-bit system, it converts the adapter handle from 32-bit to 64-bit using
 * the WOW64 helper before passing the filter to the driver. This ensures compatibility across different
 * system architectures. The filter is defined by the PSTATIC_FILTER structure, which includes details
 * such as the filter action, direction, and conditions.
 *
 * @param pFilter Pointer to the STATIC_FILTER structure that defines the filter to be inserted.
 * @param Position The position in the filter chain where the filter should be inserted.
 * @return TRUE if the operation was successful, FALSE otherwise.
 */
BOOL CNdisApi::InsertStaticFilter(PSTATIC_FILTER pFilter, unsigned long Position) const
{
    BOOL bIOResult = FALSE;

#ifndef _WIN64
    if (m_bIsWow64Process) {
        // Adapter handle values in the filter contain values which are not valid for the driver
        // and we need to pre-process filter before passing it to the driver

        if (pFilter->m_Adapter.QuadPart)
            pFilter->m_Adapter.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pFilter->m_Adapter.LowPart);
    }
#endif //_WIN64

    STATIC_FILTER_WITH_POSITION DriverData;
    DriverData.m_StaticFilter = *pFilter;
    DriverData.m_Position = Position;

    bIOResult = DeviceIoControl(
        IOCTL_NDISRD_INSERT_FILTER_BY_INDEX,
        &DriverData,
        sizeof(STATIC_FILTER_WITH_POSITION),
        NULL,
        0,
        NULL,   // Bytes Returned
        NULL
    );

    return bIOResult;
}

/**
 * @brief Removes a static filter by its unique identifier.
 *
 * This method removes a previously added static filter from the filter chain based on its unique identifier.
 * The identifier is a DWORD value that uniquely identifies the filter to be removed. This operation directly
 * communicates with the driver using the IOCTL_NDISRD_REMOVE_FILTER_BY_INDEX control code to perform the removal.
 * If the operation is successful, the filter is no longer applied to the network packets.
 *
 * @param dwFilterId The unique identifier of the filter to be removed.
 * @return TRUE if the operation was successful, FALSE otherwise.
 */
BOOL CNdisApi::RemoveStaticFilter(DWORD dwFilterId) const
{
    BOOL bIOResult = DeviceIoControl(
        IOCTL_NDISRD_REMOVE_FILTER_BY_INDEX,
        &dwFilterId,
        sizeof(DWORD),
        NULL,
        0,
        NULL, // Bytes Returned
        NULL
    );

    return bIOResult;
}

/**
 * @brief Resets the static packet filter table for the Windows Packet Filter driver.
 *
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function resets the static packet filter table for the Windows Packet Filter driver,
 * effectively removing all the packet filter rules previously set.
 * It uses DeviceIoControl with the IOCTL_NDISRD_RESET_PACKET_FILTERS code to perform the operation.
 */
BOOL CNdisApi::ResetPacketFilterTable() const
{
    const BOOL bIOResult = DeviceIoControl(
        IOCTL_NDISRD_RESET_PACKET_FILTERS,
        NULL,
        0,
        NULL,
        0,
        NULL, // Bytes Returned
        NULL
    );

    return bIOResult;
}

/**
 * @brief Retrieves the size of the currently loaded static packet filter table from the Windows Packet Filter driver.
 *
 * @param pdwTableSize A pointer to a DWORD variable that receives the size of the packet filter table.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function retrieves the size of the static packet filter table from the Windows Packet Filter driver.
 * The table contains a list of packet filter rules that determine which packets should be processed by the driver.
 * It uses DeviceIoControl with the IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE code to perform the operation.
 */
BOOL CNdisApi::GetPacketFilterTableSize(PDWORD pdwTableSize) const
{
    const BOOL bIOResult = DeviceIoControl(
        IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE,
        NULL,
        0,
        pdwTableSize,
        sizeof(DWORD),
        NULL, // Bytes Returned
        NULL
    );

    return bIOResult;
}

/**
 * @brief Retrieves the static packet filter table from the Windows Packet Filter driver.
 *
 * @param pFilterList A pointer to the STATIC_FILTER_TABLE structure that receives the packet filter rules.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function retrieves the static packet filter table from the Windows Packet Filter driver. The table
 * contains a list of packet filter rules that determine which packets should be processed by the driver,
 * e.g. passed, dropped or redirected to user-mode application for further processing.
 * It uses DeviceIoControl with the IOCTL_NDISRD_GET_PACKET_FILTERS code to perform the operation.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function iterates through the
 * filter list and updates the adapter handle values using the From64to32Handle method from the WOW64 helper
 * after receiving the filter list from the driver.
 */
BOOL CNdisApi::GetPacketFilterTable(PSTATIC_FILTER_TABLE pFilterList) const
{
    BOOL bIOResult = DeviceIoControl(
        IOCTL_NDISRD_GET_PACKET_FILTERS,
        NULL,
        0,
        pFilterList,
        sizeof(STATIC_FILTER_TABLE) + (pFilterList->m_TableSize - ANY_SIZE) * sizeof(STATIC_FILTER),
        NULL, // Bytes Returned
        NULL
    );
#ifndef _WIN64
    if (bIOResult && m_bIsWow64Process)
    {
        // Adapter handle values in the table contain values which are not valid for the client
        // and we need to post-process filter table before passing it to the client

        for (unsigned i = 0; i < pFilterList->m_TableSize; ++i)
        {
            pFilterList->m_StaticFilters[i].m_Adapter.QuadPart =
                m_Wow64Helper.From64to32Handle(pFilterList->m_StaticFilters[i].m_Adapter.QuadPart);
        }
    }
#endif //_WIN64

    return bIOResult;
}

/**
 * @brief Retrieves the static packet filter table and resets statistics for the Windows Packet Filter driver.
 *
 * @param pFilterList A pointer to the STATIC_FILTER_TABLE structure that receives the packet filter rules.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function retrieves the static packet filter table from the Windows Packet Filter driver and resets
 * the packet filtering statistics. The table contains a list of packet filter rules that determine which
 * packets should be processed by the driver, e.g. passed, dropped or redirected to user-mode application
 * for further processing. It uses DeviceIoControl with the IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS code
 * to perform the operation.
 *
 * For 32-bit processes running on a 64-bit operating system (WOW64), the function iterates through the
 * filter list and updates the adapter handle values using the From64to32Handle method from the WOW64 helper
 * after receiving the filter list from the driver.
 */
BOOL CNdisApi::GetPacketFilterTableResetStats(PSTATIC_FILTER_TABLE pFilterList) const
{
    BOOL bIOResult = DeviceIoControl(
        IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS,
        NULL,
        0,
        pFilterList,
        sizeof(STATIC_FILTER_TABLE) + (pFilterList->m_TableSize - ANY_SIZE) * sizeof(STATIC_FILTER),
        NULL, // Bytes Returned
        NULL
    );

#ifndef _WIN64
    if (bIOResult && m_bIsWow64Process)
    {
        // Adapter handle values in the table contain values which are not valid for the client
        // and we need to post-process filter table before passing it to the client

        for (unsigned i = 0; i < pFilterList->m_TableSize; ++i)
        {
            pFilterList->m_StaticFilters[i].m_Adapter.QuadPart =
                m_Wow64Helper.From64to32Handle(pFilterList->m_StaticFilters[i].m_Adapter.QuadPart);
        }
    }
#endif //_WIN64

    return bIOResult;
}

/**
 * @brief Sets the state of the packet filter cache.
 *
 * This method enables or disables the packet filter cache based on the provided state. The packet filter cache
 * is used to temporarily store packet filter information to improve performance. Enabling the cache can lead to
 * faster packet processing, while disabling it may be useful for debugging or in scenarios where the most up-to-date
 * filter information is required. The state is set by sending the IOCTL_NDISRD_SET_FILTER_CACHE_STATE control code
 * to the driver.
 *
 * @param dwState The desired state of the packet filter cache. TRUE to enable, FALSE to disable.
 * @return TRUE if the operation was successful, FALSE otherwise.
 */
BOOL CNdisApi::SetPacketFilterCacheState(BOOL bState) const
{
    DWORD dwState = static_cast<DWORD>(bState);

    return  DeviceIoControl(
        IOCTL_NDISRD_SET_FILTER_CACHE_STATE,
        &dwState,
        sizeof(DWORD),
        NULL,
        0,
        NULL,   // Bytes Returned
        NULL
    );
}

/**
 * @brief Sets the state of the packet fragment cache.
 *
 * This function enables or disables the packet fragment cache. The packet fragment cache is used to improve
 * performance by caching packet fragments. Enabling the cache can improve packet processing speed, while
 * disabling it may be useful for debugging or in scenarios where caching is not desirable.
 *
 * @param bState A BOOL value where TRUE enables the cache and FALSE disables it.
 * @return TRUE if the operation was successful, FALSE otherwise.
 */
BOOL CNdisApi::SetPacketFragmentCacheState(BOOL bState) const
{
    DWORD dwState = static_cast<DWORD>(bState);

    return  DeviceIoControl(
        IOCTL_NDISRD_SET_FRAGMENT_CACHE_STATE,
        &dwState,
        sizeof(DWORD),
        NULL,
        0,
        NULL,   // Bytes Returned
        NULL
    );
}

/**
 * @brief Enables the packet filter cache.
 *
 * This method enables the packet filter cache, which is used to temporarily store packet filter information
 * to improve performance. Enabling the cache can lead to faster packet processing. The cache is enabled by
 * setting its state to TRUE using the SetPacketFilterCacheState method.
 *
 * @return TRUE if the operation was successful, FALSE otherwise.
 */
BOOL CNdisApi::EnablePacketFilterCache() const
{
    return SetPacketFilterCacheState(TRUE);
}

/**
 * @brief Disables the packet filter cache.
 *
 * This method disables the packet filter cache. Disabling the cache may be useful for debugging or in scenarios
 * where the most up-to-date filter information is required. The cache is disabled by setting its state to FALSE
 * using the SetPacketFilterCacheState method.
 *
 * @return TRUE if the operation was successful, FALSE otherwise.
 */
BOOL CNdisApi::DisablePacketFilterCache() const
{
    return SetPacketFilterCacheState(FALSE);
}

/**
 * @brief Enables the packet fragment cache.
 *
 * This function enables the packet fragment cache by calling SetPacketFragmentCacheState with TRUE.
 * Enabling the cache can improve performance by caching packet fragments, which can be beneficial
 * for packet processing speed.
 *
 * @return TRUE if the cache was successfully enabled, FALSE otherwise.
 */
BOOL CNdisApi::EnablePacketFragmentCache() const
{
    return SetPacketFragmentCacheState(TRUE);
}

/**
 * @brief Disables the packet fragment cache.
 *
 * This function disables the packet fragment cache by calling SetPacketFragmentCacheState with FALSE.
 * Disabling the cache may be useful for debugging or in scenarios where caching is not desirable.
 *
 * @return TRUE if the cache was successfully disabled, FALSE otherwise.
 */
BOOL CNdisApi::DisablePacketFragmentCache() const
{
    return SetPacketFragmentCacheState(FALSE);
}

/**
 * @brief Checks if the Windows Packet Filter driver is loaded successfully.
 *
 * @return BOOL Returns TRUE if the driver is loaded successfully, or FALSE otherwise.
 *
 * This function checks if the Windows Packet Filter driver is loaded successfully during the
 * initialization of the CNdisApi object. If the driver is not loaded, the CNdisApi object
 * will not be able to perform operations on the driver.
 */
BOOL CNdisApi::IsDriverLoaded() const
{
    return m_bIsLoadSuccessfully;
}

/**
 * @brief Initializes the Fast I/O shared memory section.
 *
 * @param pFastIo Pointer to user allocated memory to be used as a shared section.
 * @param dwSize Size in bytes of allocated memory.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function initializes the Fast I/O shared memory section for the Windows Packet Filter driver.
 * Fast I/O provides a more efficient way to transfer data between user mode and kernel mode,
 * improving the performance of packet processing. It is supported only for Windows Vista and later,
 * and not available in WOW64 mode.
 *
 * The function uses DeviceIoControl with the IOCTL_NDISRD_INITIALIZE_FAST_IO code to perform the operation.
 */
BOOL CNdisApi::InitializeFastIo(PFAST_IO_SECTION pFastIo, DWORD dwSize) const
{
    // Only supported for Vista and later. Can't be used in WOW64 mode.
    if (!IsWindowsVistaOrLater() || m_bIsWow64Process || (dwSize < sizeof(FAST_IO_SECTION)))
        return FALSE;

    INITIALIZE_FAST_IO_PARAMS params = { pFastIo, dwSize };

    const BOOL bIOResult = DeviceIoControl(
        IOCTL_NDISRD_INITIALIZE_FAST_IO,
        &params,
        sizeof(INITIALIZE_FAST_IO_PARAMS),
        NULL,
        0,
        NULL,   // Bytes Returned
        NULL
    );

    return bIOResult;
}

/**
 * @brief Adds a secondary Fast I/O shared memory section.
 *
 * @param pFastIo Pointer to user allocated memory to be used as a shared section.
 * @param dwSize Size in bytes of allocated memory.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function adds a secondary Fast I/O shared memory section for the Windows Packet Filter driver.
 * Fast I/O provides a more efficient way to transfer data between user mode and kernel mode,
 * improving the performance of packet processing. It is supported only for Windows Vista and later,
 * and not available in WOW64 mode.
 *
 * The function uses DeviceIoControl with the IOCTL_NDISRD_ADD_SECOND_FAST_IO_SECTION code to
 * perform the operation.
 */
BOOL CNdisApi::AddSecondaryFastIo(PFAST_IO_SECTION pFastIo, DWORD dwSize) const
{
    // Only supported for Vista and later. Can't be used in WOW64 mode.
    if (!IsWindowsVistaOrLater() || m_bIsWow64Process || (dwSize < sizeof(FAST_IO_SECTION)))
        return FALSE;

    INITIALIZE_FAST_IO_PARAMS params = { pFastIo, dwSize };

    const BOOL bIOResult = DeviceIoControl(
        IOCTL_NDISRD_ADD_SECOND_FAST_IO_SECTION,
        &params,
        sizeof(INITIALIZE_FAST_IO_PARAMS),
        NULL,
        0,
        NULL,   // Bytes Returned
        NULL
    );

    return bIOResult;
}

/**
 * @brief Reads a bunch of packets from the driver packet queues without sorting by network adapter.
 *
 * @param Packets Array of INTERMEDIATE_BUFFER pointers.
 * @param dwPacketsNum Number of packets in the array above. The associated adapter handle will be stored
 * in the INTERMEDIATE_BUFFER.m_hAdapter field.
 * @param pdwPacketsSuccess Pointer to store the number of packets successfully read from the driver.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function reads a bunch of packets from the driver packet queues without sorting by network adapter.
 * The associated adapter handle will be stored in the INTERMEDIATE_BUFFER.m_hAdapter field.
 * The function is not available in WOW64 mode.
 *
 * The function uses DeviceIoControl with the IOCTL_NDISRD_READ_PACKETS_UNSORTED code to perform the operation.
 */
BOOL CNdisApi::ReadPacketsUnsorted(PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketsSuccess) const
{
    if (m_bIsWow64Process)
        return FALSE;

    UNSORTED_READ_SEND_REQUEST request = { Packets, dwPacketsNum };

    const BOOL bIOResult = DeviceIoControl(
        IOCTL_NDISRD_READ_PACKETS_UNSORTED,
        &request,
        sizeof(UNSORTED_READ_SEND_REQUEST),
        &request,
        sizeof(UNSORTED_READ_SEND_REQUEST),
        NULL,   // Bytes Returned
        NULL
    );

    *pdwPacketsSuccess = request.packets_num;

    return bIOResult;
}

/**
 * @brief Sends a bunch of packets to the network adapters.
 *
 * @param Packets Array of INTERMEDIATE_BUFFER pointers. The target adapter handle should be set
 * in the INTERMEDIATE_BUFFER.m_hAdapter field.
 * @param dwPacketsNum Number of packets in the array above.
 * @param pdwPacketSuccess Pointer to store the number of packets successfully sent to the adapters.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sends a bunch of packets to the network adapters. The target adapter handle
 * should be set in the INTERMEDIATE_BUFFER.m_hAdapter field. The function is not available in WOW64 mode.
 *
 * The function uses DeviceIoControl with the IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED code to perform the operation.
 */
BOOL CNdisApi::SendPacketsToAdaptersUnsorted(PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketSuccess) const
{
    if (m_bIsWow64Process)
        return FALSE;

    UNSORTED_READ_SEND_REQUEST request = { Packets, dwPacketsNum };

    const BOOL bIOResult = DeviceIoControl(
        IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED,
        &request,
        sizeof(UNSORTED_READ_SEND_REQUEST),
        &request,
        sizeof(UNSORTED_READ_SEND_REQUEST),
        NULL,   // Bytes Returned
        NULL
    );

    *pdwPacketSuccess = request.packets_num;

    return bIOResult;
}

/**
 * @brief Indicates a bunch of packets to the MSTCP (and other upper layer network protocols).
 *
 * @param Packets Array of INTERMEDIATE_BUFFER pointers. The associated adapter handle should be stored
 * in the INTERMEDIATE_BUFFER.m_hAdapter field.
 * @param dwPacketsNum Number of packets in the array above.
 * @param pdwPacketSuccess Pointer to store the number of packets successfully sent to the MSTCP.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function Indicates a bunch of packets to the MSTCP (and other upper layer network protocols).
 * The associated adapter handle is stored in the INTERMEDIATE_BUFFER.m_hAdapter field. The function is not available in WOW64 mode.
 *
 * The function uses DeviceIoControl with the IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED code to perform the operation.
 */
BOOL CNdisApi::SendPacketsToMstcpUnsorted(PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketSuccess) const
{
    if (m_bIsWow64Process)
        return FALSE;

    UNSORTED_READ_SEND_REQUEST request = { Packets, dwPacketsNum };

    const BOOL bIOResult = DeviceIoControl(
        IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED,
        &request,
        sizeof(UNSORTED_READ_SEND_REQUEST),
        &request,
        sizeof(UNSORTED_READ_SEND_REQUEST),
        NULL,   // Bytes Returned
        NULL
    );

    *pdwPacketSuccess = request.packets_num;

    return bIOResult;
}

/**
 * @brief Retrieves the effective size of the Windows Packet Filter internal intermediate buffer pool.
 *
 * @param pdwSize Pointer to store the size of the intermediate buffer pool.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function retrieves the size of the intermediate buffer pool used by the driver.
 * It uses DeviceIoControl with the IOCTL_NDISRD_QUERY_IB_POOL_SIZE code to perform the operation.
 */
BOOL CNdisApi::GetIntermediateBufferPoolSize(PDWORD pdwSize) const
{
    const BOOL bIOResult = DeviceIoControl(
        IOCTL_NDISRD_QUERY_IB_POOL_SIZE,
        pdwSize,
        sizeof(DWORD),
        pdwSize,
        sizeof(DWORD),
        NULL,   // Bytes Returned
        NULL
    );

    return bIOResult;
}

/**
 * @brief Retrieves the number of bytes returned by the last DeviceIoControl operation.
 *
 * @return DWORD The number of bytes returned by the last DeviceIoControl operation.
 *
 * This function returns the number of bytes returned by the last DeviceIoControl operation
 * performed by the CNdisApi instance. This can be useful for obtaining additional information
 * about the result of the operation.
 */
DWORD CNdisApi::GetBytesReturned() const
{
    return m_BytesReturned;
}

/**
 * @brief Sets the system wide MTU decrement value in the system registry.
 *
 * @param dwMTUDecrement The MTU decrement value to be set.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sets the MTU decrement value in the system registry. The MTU decrement value
 * is used by the Windows Packet Filter driver to decrease the maximum transmission unit (MTU)
 * size for network packets.
 *
 * For Windows NT/2000/XP, the registry key is created under HKEY_LOCAL_MACHINE with the path
 * defined in WINNT_REG_PARAM. For Windows 9x/ME, the registry key is created under
 * HKEY_LOCAL_MACHINE with the path defined in WIN9X_REG_PARAM.
 */
BOOL CNdisApi::SetMTUDecrement(const DWORD dwMTUDecrement)
{
    HKEY hKey;

    if (ms_Version.IsWindowsNTPlatform())
    {
        // Windows NT, 2000 or XP
        if (ERROR_SUCCESS == RegCreateKey(HKEY_LOCAL_MACHINE, WINNT_REG_PARAM, &hKey))
        {
            if (ERROR_SUCCESS == RegSetValueEx(hKey, TEXT("MTUDecrement"), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwMTUDecrement), sizeof(DWORD)))
            {
                RegCloseKey(hKey);
                return TRUE;
            }

            RegCloseKey(hKey);
            return FALSE;
        }
        return FALSE;
    }

    // Windows 9x/ME
    if (ERROR_SUCCESS == RegCreateKeyA(HKEY_LOCAL_MACHINE, WIN9X_REG_PARAM, &hKey))
    {
        if (ERROR_SUCCESS == RegSetValueEx(hKey, TEXT("MTUDecrement"), 0, REG_DWORD, (CONST BYTE*) & dwMTUDecrement, sizeof(DWORD)))
        {
            RegCloseKey(hKey);
            return TRUE;
        }

        RegCloseKey(hKey);
        return FALSE;
    }
    return FALSE;
}

/**
 * @brief Retrieves the MTU decrement value from the system registry.
 *
 * @return DWORD Returns the MTU decrement value if the operation is successful, or 0 otherwise.
 *
 * This function retrieves the MTU decrement value from the system registry. The MTU decrement value
 * is used by the Windows Packet Filter driver to decrease the maximum transmission unit (MTU)
 * size for network packets.
 *
 * For Windows NT/2000/XP, the registry key is read from HKEY_LOCAL_MACHINE with the path
 * defined in WINNT_REG_PARAM. For Windows 9x/ME, the registry key is read from
 * HKEY_LOCAL_MACHINE with the path defined in WIN9X_REG_PARAM.
 */
DWORD CNdisApi::GetMTUDecrement()
{
    HKEY hKey;
    DWORD dwMTUDecrement;
    DWORD dwSize = sizeof(DWORD);

    if (ms_Version.IsWindowsNTPlatform())
    {
        // Windows NT, 2000 or XP
        if (ERROR_SUCCESS == RegCreateKey(HKEY_LOCAL_MACHINE, WINNT_REG_PARAM, &hKey))
        {
            if (ERROR_SUCCESS == RegQueryValueEx(hKey, TEXT("MTUDecrement"), 0, NULL, reinterpret_cast<BYTE*>(&dwMTUDecrement), &dwSize))
            {
                RegCloseKey(hKey);
                return dwMTUDecrement;
            }

            RegCloseKey(hKey);
            return 0;
        }
        return 0;
    }

    // Windows 9x/ME
    if (ERROR_SUCCESS == RegCreateKeyA(HKEY_LOCAL_MACHINE, WIN9X_REG_PARAM, &hKey))
    {
        if (ERROR_SUCCESS == RegQueryValueEx(hKey, TEXT("MTUDecrement"), 0, NULL, reinterpret_cast<BYTE*>(&dwMTUDecrement), &dwSize))
        {
            RegCloseKey(hKey);
            return dwMTUDecrement;
        }

        RegCloseKey(hKey);
        return 0;
    }
    return 0;
}

/**
 * @brief Sets the startup filter mode for the network adapters.
 *
 * @param dwStartupMode A combination of flags that determine the startup mode.
 * @return BOOL Returns TRUE if the operation is successful, or FALSE otherwise.
 *
 * This function sets the startup filter mode for network adapters in the system registry. The startup mode
 * determines the initial state of the network adapters when the Windows Packet Filter driver is
 * loaded.
 *
 * The dwStartupMode parameter must be a combination of the XXX_LISTEN or XXX_TUNNEL flags:
 * - MSTCP_FLAG_SENT_TUNNEL: Queue all packets sent from MSTCP to the network interface. The original packet is dropped.
 * - MSTCP_FLAG_RECV_TUNNEL: Queue all packets indicated by the network interface to MSTCP. The original packet is dropped.
 * - MSTCP_FLAG_SENT_LISTEN: Queue all packets sent from MSTCP to the network interface. The original packet goes ahead.
 * - MSTCP_FLAG_RECV_LISTEN: Queue all packets indicated by the network interface to MSTCP. The original packet goes ahead.
 * - MSTCP_FLAG_FILTER_DIRECT: In promiscuous mode, TCP/IP stack receives all packets in the Ethernet segment and replies with various ICMP packets. To prevent this, set this flag. All packets with destination MAC different from FF-FF-FF-FF-FF-FF and the network interface's current MAC will never reach MSTCP.
 *
 * By default, loopback packets are passed to the original MSTCP handlers without processing. To change this behavior, use these additional flags:
 * - MSTCP_FLAG_LOOPBACK_FILTER: Pass loopback packets for processing by the helper driver routines (redirected to user-mode if requested).
 * - MSTCP_FLAG_LOOPBACK_BLOCK: Silently drop loopback packets. This flag is recommended for usage with promiscuous mode to avoid multiple processing of one packet.
 *
 * Remarks:
 * This routine sets the default mode to be applied to each adapter when it appears in the system. It can be useful when you need to prevent a network interface from starting operation before your application has started. Note that this API call requires a system reboot to take effect.
 */
BOOL CNdisApi::SetAdaptersStartupMode(const DWORD dwStartupMode)
{
    HKEY hKey;

    if (ms_Version.IsWindowsNTPlatform())
    {
        // Windows NT, 2000 or XP
        if (ERROR_SUCCESS == RegCreateKey(HKEY_LOCAL_MACHINE, WINNT_REG_PARAM, &hKey))
        {
            if (ERROR_SUCCESS == RegSetValueEx(hKey, TEXT("StartupMode"), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwStartupMode), sizeof(DWORD)))
            {
                RegCloseKey(hKey);
                return TRUE;
            }

            RegCloseKey(hKey);
            return FALSE;
        }
        return FALSE;
    }

    // Windows 9x/ME
    if (ERROR_SUCCESS == RegCreateKeyA(HKEY_LOCAL_MACHINE, WIN9X_REG_PARAM, &hKey))
    {
        if (ERROR_SUCCESS == RegSetValueEx(hKey, TEXT("StartupMode"), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwStartupMode), sizeof(DWORD)))
        {
            RegCloseKey(hKey);
            return TRUE;
        }

        RegCloseKey(hKey);
        return FALSE;
    }
    return FALSE;
}

/**
 * @brief Retrieves the network adapters' startup filter mode from the system registry.
 *
 * @return DWORD The current startup mode for network adapters.
 *
 * This function retrieves the startup filter mode for network adapters stored in the system registry.
 * The startup mode determines the initial state of network adapters when the Windows Packet Filter
 * driver is loaded.
 *
 * The returned value is a combination of the XXX_LISTEN or XXX_TUNNEL flags. See the
 * SetAdaptersStartupMode() function documentation for more information about these flags.
 */
DWORD CNdisApi::GetAdaptersStartupMode()
{
    HKEY hKey;
    DWORD dwStartupMode;
    DWORD dwSize = sizeof(DWORD);

    if (ms_Version.IsWindowsNTPlatform())
    {
        // Windows NT, 2000 or XP
        if (ERROR_SUCCESS == RegCreateKey(HKEY_LOCAL_MACHINE, WINNT_REG_PARAM, &hKey))
        {
            if (ERROR_SUCCESS == RegQueryValueEx(hKey, TEXT("StartupMode"), 0, NULL, reinterpret_cast<BYTE*>(&dwStartupMode), &dwSize))
            {
                RegCloseKey(hKey);
                return dwStartupMode;
            }

            RegCloseKey(hKey);
            return 0;
        }
        return 0;
    }

    // Windows 9x/ME
    if (ERROR_SUCCESS == RegCreateKeyA(HKEY_LOCAL_MACHINE, WIN9X_REG_PARAM, &hKey))
    {
        if (ERROR_SUCCESS == RegQueryValueEx(hKey, TEXT("StartupMode"), 0, NULL, reinterpret_cast<BYTE*>(&dwStartupMode), &dwSize))
        {
            RegCloseKey(hKey);
            return dwStartupMode;
        }

        RegCloseKey(hKey);
        return 0;
    }
    return 0;
}

/**
 * @brief Sets the pool size multiplier for Windows Packet Filter driver in the Windows registry.
 *
 * This function creates or modifies the PoolSize value in the registry based on the
 * given value. The appropriate registry key is selected depending on the
 * Windows platform (NT/2000/XP or 9x/ME). The resulting internal packet pool size
 * will be equal to 2048 (512 for Windows version before Vista) * PoolSize packets. The maximum
 * effective PoolSize is 10.
 *
 * @param dwPoolSize The desired pool size multiplier to be set in the registry.
 * @return BOOL Returns TRUE if the pool size multiplier is successfully set, FALSE otherwise.
 */
BOOL CNdisApi::SetPoolSize(const DWORD dwPoolSize)
{
    HKEY hKey;

    if (ms_Version.IsWindowsNTPlatform())
    {
        // Windows NT, 2000 or XP
        if (ERROR_SUCCESS == RegCreateKey(HKEY_LOCAL_MACHINE, WINNT_REG_PARAM, &hKey))
        {
            if (ERROR_SUCCESS == RegSetValueEx(hKey, TEXT("PoolSize"), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwPoolSize), sizeof(DWORD)))
            {
                RegCloseKey(hKey);
                return TRUE;
            }

            RegCloseKey(hKey);
            return FALSE;
        }
        return FALSE;
    }

    // Windows 9x/ME
    if (ERROR_SUCCESS == RegCreateKeyA(HKEY_LOCAL_MACHINE, WIN9X_REG_PARAM, &hKey))
    {
        if (ERROR_SUCCESS == RegSetValueEx(hKey, TEXT("PoolSize"), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwPoolSize), sizeof(DWORD)))
        {
            RegCloseKey(hKey);
            return TRUE;
        }

        RegCloseKey(hKey);
        return FALSE;
    }
    return FALSE;
}

/**
 * @brief Retrieves the pool size multiplier for the Windows Packet Filter driver from the Windows registry.
 *
 * This function queries the registry for the PoolSize value and returns it.
 * The appropriate registry key is used depending on the Windows platform
 * (NT/2000/XP or 9x/ME). The internal packet pool size is determined by
 * 2048 * PoolSize packets. The maximum effective PoolSize is 10.
 *
 * @return DWORD The pool size multiplier retrieved from the registry, or 0 if the value is not found or an error occurs.
 */
DWORD CNdisApi::GetPoolSize()
{
    HKEY hKey;
    DWORD dwStartupMode;
    DWORD dwSize = sizeof(DWORD);

    if (ms_Version.IsWindowsNTPlatform())
    {
        // Windows NT, 2000 or XP
        if (ERROR_SUCCESS == RegCreateKey(HKEY_LOCAL_MACHINE, WINNT_REG_PARAM, &hKey))
        {
            if (ERROR_SUCCESS == RegQueryValueEx(hKey, TEXT("PoolSize"), 0, NULL, reinterpret_cast<BYTE*>(&dwStartupMode), &dwSize))
            {
                RegCloseKey(hKey);
                return dwStartupMode;
            }

            RegCloseKey(hKey);
            return 0;
        }
        return 0;
    }

    // Windows 9x/ME
    if (ERROR_SUCCESS == RegCreateKeyA(HKEY_LOCAL_MACHINE, WIN9X_REG_PARAM, &hKey))
    {
        if (ERROR_SUCCESS == RegQueryValueEx(hKey, TEXT("PoolSize"), 0, NULL, reinterpret_cast<BYTE*>(&dwStartupMode), &dwSize))
        {
            RegCloseKey(hKey);
            return dwStartupMode;
        }

        RegCloseKey(hKey);
        return 0;
    }
    return 0;
}

/**
 * @brief Determines if the given adapter is an NDISWAN interface with the specified component ID.
 *
 * This function enumerates all subkeys of the registry key
 * HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}
 * and checks for the component ID value matching the provided ndiswanName.
 * If a match is found, it grabs the linkage subkey and the export string
 * to verify if the adapter name matches. The function works for both
 * Windows 7 and Windows 10.
 *
 * Possible component ID values:
 * - ms_ndiswanip
 * - ms_ndiswanipv6
 * - ms_ndiswanbh
 *
 * @param adapterName The adapter name to check.
 * @param ndiswanName The NDISWAN component ID to look for.
 * @return BOOL Returns TRUE if the adapter is an NDISWAN interface with the specified component ID, FALSE otherwise.
 */
BOOL CNdisApi::IsNdiswanInterface(LPCSTR adapterName, LPCSTR ndiswanName)
{
    HKEY TargetKey = NULL;
    HKEY ConnectionKey = NULL;
    HKEY LinkageKey = NULL;
    int i = 0;
    TCHAR Buffer[MAX_PATH] = { 0 };
    char TempBuffer[MAX_PATH] = { 0 };
    DWORD BufferLength = MAX_PATH;
    DWORD TempBufferLength = MAX_PATH;
    DWORD RegType = 0;
    BOOL isNdiswanInterface = FALSE;

    LONG lStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REGSTR_NETWORK_CONTROL_CLASS, 0, KEY_READ, &TargetKey);

    if (lStatus == ERROR_SUCCESS)
    {
        while (!isNdiswanInterface && ERROR_NO_MORE_ITEMS != RegEnumKeyEx(TargetKey, i, Buffer, &BufferLength, 0, 0, 0, 0))
        {
            lStatus = RegOpenKeyEx(TargetKey, Buffer, 0, KEY_READ, &ConnectionKey);
            if (lStatus == ERROR_SUCCESS)
            {
                lStatus = RegQueryValueExA(ConnectionKey, "ComponentId", 0, &RegType, reinterpret_cast<LPBYTE>(TempBuffer), &TempBufferLength);
                TempBufferLength = MAX_PATH;

                if (lStatus == ERROR_SUCCESS && 0 == _stricmp(TempBuffer, ndiswanName))
                {
                    lStatus = RegOpenKeyEx(ConnectionKey, TEXT("Linkage"), 0, KEY_READ, &LinkageKey);
                    if (lStatus == ERROR_SUCCESS)
                    {
                        lStatus = RegQueryValueExA(LinkageKey, "Export", 0, &RegType, reinterpret_cast<LPBYTE>(TempBuffer), &TempBufferLength);
                        TempBufferLength = MAX_PATH;

                        if (lStatus == ERROR_SUCCESS && 0 == _stricmp(TempBuffer, adapterName))
                        {
                            isNdiswanInterface = TRUE;
                        }
                        RegCloseKey(LinkageKey);
                    }
                }
                RegCloseKey(ConnectionKey);
            }
            ++i;
            BufferLength = MAX_PATH;
        }
        RegCloseKey(TargetKey);
    }

    return isNdiswanInterface;
}

/**
 * @brief Determines if the given adapter is an NDISWANIP interface.
 *
 * This function checks if the adapter name matches the internal name for
 * NDISWANIP on systems prior to Windows 10. On Windows 10 and later systems,
 * it calls the IsNdiswanInterface function to check if the adapter is an
 * NDISWAN interface with the specified component ID (REGSTR_COMPONENTID_NDISWANIP).
 *
 * @param adapterName The adapter name to check.
 * @return BOOL Returns TRUE if the adapter is an NDISWANIP interface, FALSE otherwise.
 */
BOOL CNdisApi::IsNdiswanIp(LPCSTR adapterName)
{
    // Before Windows 10, NDISWANIP can be identified by the internal name
    if (!ms_Version.IsWindows10OrGreater() /* before Windows 10 */)
    {
        if (_stricmp(adapterName, DEVICE_NDISWANIP) == 0)
        {
            return TRUE;
        }
    }

    return IsNdiswanInterface(adapterName, REGSTR_COMPONENTID_NDISWANIP);
}

/**
 * @brief Determines if the given adapter is an NDISWANIPV6 interface.
 *
 * This function checks if the adapter name matches the internal name for
 * NDISWANIPV6 on systems prior to Windows 10. On Windows 10 and later systems,
 * it calls the IsNdiswanInterface function to check if the adapter is an
 * NDISWAN interface with the specified component ID (REGSTR_COMPONENTID_NDISWANIPV6).
 *
 * @param adapterName The adapter name to check.
 * @return BOOL Returns TRUE if the adapter is an NDISWANIPV6 interface, FALSE otherwise.
 */
BOOL CNdisApi::IsNdiswanIpv6(LPCSTR adapterName)
{
    // Before Windows 10, NDISWANIPV6 can be identified by the internal name
    if (!ms_Version.IsWindows10OrGreater() /* before Windows 10 */)
    {
        if (_stricmp(adapterName, DEVICE_NDISWANIPV6) == 0)
        {
            return TRUE;
        }
    }

    return IsNdiswanInterface(adapterName, REGSTR_COMPONENTID_NDISWANIPV6);
}

/**
 * @brief Determines if the given adapter is an NDISWANBH interface.
 *
 * This function checks if the adapter name matches the internal name for
 * NDISWANBH on systems prior to Windows 10. On Windows 10 and later systems,
 * it calls the IsNdiswanInterface function to check if the adapter is an
 * NDISWAN interface with the specified component ID (REGSTR_COMPONENTID_NDISWANBH).
 *
 * @param adapterName The adapter name to check.
 * @return BOOL Returns TRUE if the adapter is an NDISWANBH interface, FALSE otherwise.
 */
BOOL CNdisApi::IsNdiswanBh(LPCSTR adapterName)
{
    // Before Windows 10, NDISWANBH can be identified by the internal name
    if (!ms_Version.IsWindows10OrGreater() /* before Windows 10 */)
    {
        if (_stricmp(adapterName, DEVICE_NDISWANBH) == 0)
        {
            return TRUE;
        }
    }

    return IsNdiswanInterface(adapterName, REGSTR_COMPONENTID_NDISWANBH);
}

/**
 * @brief Converts an adapter's internal name to a user-friendly name on Windows NT 4.0.
 *
 * This function searches the registry to find the corresponding user-friendly name
 * for the specified adapter name on Windows NT 4.0 systems. It locates the adapter
 * by comparing the service name with the adapter name and retrieves the user-friendly
 * name from the registry.
 *
 * @param szAdapterName The adapter name to convert.
 * @param szUserFriendlyName A buffer to store the user-friendly name.
 * @param dwUserFriendlyNameLength The length of the buffer for the user-friendly name.
 * @return BOOL Returns TRUE if the conversion is successful, FALSE otherwise.
 */
BOOL CNdisApi::ConvertWindowsNTAdapterName(
    LPCSTR szAdapterName,
    LPSTR szUserFriendlyName,
    DWORD dwUserFriendlyNameLength
)
{
    HKEY        hKeyAdapters, hKeyAdapter;
    DWORD       dwType, dwIndex = 0;
    FILETIME    time;
    char        szSubKey[MAX_PATH * 2], szServiceName[MAX_PATH * 2];
    DWORD       dwSubKeyLength = MAX_PATH * 2;
    DWORD       dwServiceNameLength = MAX_PATH * 2;
    BOOL        bRet = TRUE;

    LONG lResult = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        REGSTR_NETWORK_CARDS,
        0,
        KEY_READ,
        &hKeyAdapters
    );

    if (lResult == ERROR_SUCCESS)
    {
        // Enumerate bound interfaces
        while (RegEnumKeyExA(hKeyAdapters, dwIndex, szSubKey, &dwSubKeyLength, NULL, NULL, NULL, &time) == ERROR_SUCCESS)
        {
            // Subkey retrieved, open subkey
            lResult = RegOpenKeyExA(
                hKeyAdapters,
                szSubKey,
                0,
                KEY_READ,
                &hKeyAdapter
            );

            if (lResult == ERROR_SUCCESS)
            {
                lResult = RegQueryValueExA(hKeyAdapter, REGSTR_VAL_SERVICE_NAME, NULL, &dwType, reinterpret_cast<LPBYTE>(szServiceName), &dwServiceNameLength);
                if (lResult == ERROR_SUCCESS)
                {
                    if (_stricmp(szServiceName, &szAdapterName[strlen("\\Device\\")]) == 0)
                    {
                        lResult = RegQueryValueExA(hKeyAdapter, REGSTR_VAL_TITLE, 0, &dwType, reinterpret_cast<LPBYTE>(szUserFriendlyName), &dwUserFriendlyNameLength);

                        RegCloseKey(hKeyAdapter);
                        RegCloseKey(hKeyAdapters);

                        if (lResult == ERROR_SUCCESS)
                        {
                            return TRUE;
                        }
                        return FALSE;
                    }
                }
                else
                {
                    bRet = FALSE;
                }
                RegCloseKey(hKeyAdapter);
                dwServiceNameLength = MAX_PATH * 2;
            }
            else
            {
                bRet = FALSE;
            }

            dwIndex++;
            dwSubKeyLength = MAX_PATH;
        }

        RegCloseKey(hKeyAdapters);

    }
    else
    {
        bRet = FALSE;
    }

    return bRet;
}

/**
 * @brief Converts an adapter's internal name to a user-friendly name on Windows 2000 and later.
 *
 * This function identifies NDISWAN adapters (IP, BH, and IPv6) and retrieves the
 * corresponding user-friendly name for the specified adapter name on Windows 2000 (and later) systems.
 * For other adapters, it searches the registry for the appropriate user-friendly name.
 *
 * @param szAdapterName The Windows 2000 (and later) adapter name to convert.
 * @param szUserFriendlyName A buffer to store the user-friendly name.
 * @param dwUserFriendlyNameLength The length of the buffer for the user-friendly name.
 * @return BOOL Returns TRUE if the conversion is successful, FALSE otherwise.
 */
BOOL CNdisApi::ConvertWindows2000AdapterName(
    LPCSTR szAdapterName,
    LPSTR szUserFriendlyName,
    DWORD dwUserFriendlyNameLength
)
{
    HKEY hKey;
    char szFriendlyNameKey[MAX_PATH * 2];
    DWORD dwType;

#if _MSC_VER >= 1700
    if (IsNdiswanIp(szAdapterName))
    {
        strcpy_s(szUserFriendlyName, dwUserFriendlyNameLength, USER_NDISWANIP);
        return TRUE;
    }

    if (IsNdiswanBh(szAdapterName))
    {
        strcpy_s(szUserFriendlyName, dwUserFriendlyNameLength, USER_NDISWANBH);
        return TRUE;
    }

    if (IsNdiswanIpv6(szAdapterName))
    {
        strcpy_s(szUserFriendlyName, dwUserFriendlyNameLength, USER_NDISWANIPV6);
        return TRUE;
    }

    strcpy_s(szFriendlyNameKey, MAX_PATH * 2, REGSTR_NETWORK_CONTROL_KEY);
    strcpy_s(static_cast<char*>(szFriendlyNameKey) + strlen(szFriendlyNameKey), MAX_PATH * 2 - strlen(szFriendlyNameKey), &szAdapterName[strlen("\\Device\\")]);
    strcpy_s(static_cast<char*>(szFriendlyNameKey) + strlen(szFriendlyNameKey), MAX_PATH * 2 - strlen(szFriendlyNameKey), REGSTR_VAL_CONNECTION);
#else
    if (IsNdiswanIp(szAdapterName))
    {
        strcpy(szUserFriendlyName, USER_NDISWANIP);
        return TRUE;
    }

    if (IsNdiswanBh(szAdapterName))
    {
        strcpy(szUserFriendlyName, USER_NDISWANBH);
        return TRUE;
    }

    if (IsNdiswanIpv6(szAdapterName))
    {
        strcpy(szUserFriendlyName, USER_NDISWANIPV6);
        return TRUE;
    }

    strcpy(szFriendlyNameKey, REGSTR_NETWORK_CONTROL_KEY);
    strcpy(static_cast<char*>(szFriendlyNameKey) + strlen(szFriendlyNameKey), &szAdapterName[strlen("\\Device\\")]);
    strcpy(static_cast<char*>(szFriendlyNameKey) + strlen(szFriendlyNameKey), REGSTR_VAL_CONNECTION);

#endif //_MSC_VER >= 1700

    LONG lResult = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        szFriendlyNameKey,
        0,
        KEY_READ,
        &hKey
    );

    if (lResult == ERROR_SUCCESS)
    {
        lResult = RegQueryValueExA(hKey, REGSTR_VAL_NAME, 0, &dwType, reinterpret_cast<LPBYTE>(szUserFriendlyName), &dwUserFriendlyNameLength);

        RegCloseKey(hKey);

        if (lResult == ERROR_SUCCESS)
            return TRUE;
    }

    return FALSE;
}

/**
 * @brief Converts the given Windows 9x adapter name to a user-friendly name.
 *
 * This function retrieves the user-friendly name for the specified adapter name on
 * Windows 9x systems by searching the registry.
 *
 * @param szAdapterName The Windows 9x adapter name to convert.
 * @param szUserFriendlyName A buffer to store the user-friendly name.
 * @param dwUserFriendlyNameLength The length of the buffer for the user-friendly name.
 * @return BOOL Returns TRUE if the conversion is successful, FALSE otherwise.
 */
BOOL
CNdisApi::ConvertWindows9xAdapterName(
    LPCSTR szAdapterName,
    LPSTR szUserFriendlyName,
    DWORD dwUserFriendlyNameLength
)
{
    HKEY        hKey;
    char        szFriendlyNameKey[MAX_PATH * 2];
    DWORD        dwType;
    BOOL        bRet = FALSE;

#if _MSC_VER >= 1700
    strcpy_s(szFriendlyNameKey, MAX_PATH * 2, REGSTR_MSTCP_CLASS_NET);
    strcpy_s(static_cast<PCHAR>(szFriendlyNameKey) + strlen(szFriendlyNameKey), MAX_PATH * 2 - strlen(szFriendlyNameKey), szAdapterName);
#else
    strcpy(szFriendlyNameKey, REGSTR_MSTCP_CLASS_NET);
    strcpy((PCHAR)szFriendlyNameKey + strlen(szFriendlyNameKey), szAdapterName);
#endif //_MSC_VER >= 1700

    LONG lResult = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        szFriendlyNameKey,
        0,
        KEY_READ,
        &hKey
    );

    if (lResult == ERROR_SUCCESS)
    {
        lResult = RegQueryValueExA(hKey, REGSTR_VAL_DRIVER_DESC, 0, &dwType, reinterpret_cast<LPBYTE>(szUserFriendlyName), &dwUserFriendlyNameLength);
        if (lResult == ERROR_SUCCESS)
        {
            bRet = TRUE;
        }
        RegCloseKey(hKey);
    }

    return bRet;
}

/**
 * @brief Recalculates the IPv4 checksum of a given packet.
 *
 * @param pPacket Pointer to the packet's INTERMEDIATE_BUFFER structure.
 *
 * This function recalculates the IP checksum for the given packet. The IP checksum
 * is a 16-bit value used to verify the integrity of the IP header in an IP packet.
 * The checksum must be recalculated if any changes are made to the IP header.
 * This function should be called after modifying any field in the IP header
 * to ensure the packet's integrity.
 */
void CNdisApi::RecalculateIPChecksum(PINTERMEDIATE_BUFFER pPacket)
{
    unsigned int sum = 0;

    // Get a pointer to the IP header within the packet
    const iphdr_ptr pIpHeader = reinterpret_cast<iphdr_ptr>(&pPacket->m_IBuffer[sizeof(ether_header)]);

    // Initialize checksum to zero
    pIpHeader->ip_sum = 0;
    const PUCHAR buff = reinterpret_cast<PUCHAR>(pIpHeader);

    // Calculate IP header checksum
    for (unsigned int i = 0; i < pIpHeader->ip_hl * sizeof(DWORD); i += 2)
    {
        const unsigned short word16 = ((buff[i] << 8) & 0xFF00) + (buff[i + 1] & 0xFF);
        sum += word16;
    }

    // Keep only the last 16 bits of the 32-bit calculated sum and add the carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // Take the one's complement of sum
    sum = ~sum;

    // Store the recalculated checksum in the IP header
    pIpHeader->ip_sum = htons(static_cast<unsigned short>(sum));
}

/**
 * @brief Recalculates the ICMPv4 checksum of a given packet.
 *
 * @param pPacket Pointer to the packet's INTERMEDIATE_BUFFER structure.
 */
void CNdisApi::RecalculateICMPChecksum(PINTERMEDIATE_BUFFER pPacket)
{
    unsigned short padd = 0;
    unsigned int sum = 0;
    icmphdr_ptr pIcmpHeader;
    const iphdr_ptr pIpHeader = reinterpret_cast<iphdr_ptr>(&pPacket->m_IBuffer[sizeof(ether_header)]);

    // Sanity check
    if (pIpHeader->ip_p == IPPROTO_ICMP)
    {
        pIcmpHeader = reinterpret_cast<icmphdr_ptr>(reinterpret_cast<PUCHAR>(pIpHeader) + sizeof(DWORD) * pIpHeader->ip_hl);
    }
    else
        return;

    const DWORD dwIcmpLen = ntohs(pIpHeader->ip_len) - pIpHeader->ip_hl * 4;

    if ((dwIcmpLen / 2) * 2 != dwIcmpLen)
    {
        padd = 1;
        pPacket->m_IBuffer[dwIcmpLen + pIpHeader->ip_hl * 4 + static_cast<DWORD>(sizeof(ether_header))] = 0;
    }

    const PUCHAR buff = reinterpret_cast<PUCHAR>(pIcmpHeader);
    pIcmpHeader->checksum = 0;

    // Make 16-bit words out of every two adjacent 8-bit words and calculate the sum of all 16-bit words
    for (unsigned int i = 0; i < dwIcmpLen + padd; i = i + 2)
    {
        const unsigned short word16 = ((buff[i] << 8) & 0xFF00) + (buff[i + 1] & 0xFF);
        sum = sum + static_cast<unsigned long>(word16);
    }

    // Keep only the last 16 bits of the 32-bit calculated sum and add the carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // Take the one's complement of sum
    sum = ~sum;

    pIcmpHeader->checksum = ntohs(static_cast<unsigned short>(sum));
}

/**
 * @brief Recalculates the TCP checksum of a given IPv4 packet.
 *
 * @param pPacket Pointer to the packet's INTERMEDIATE_BUFFER structure.
 */
void CNdisApi::RecalculateTCPChecksum(PINTERMEDIATE_BUFFER pPacket)
{
    tcphdr_ptr pTcpHeader;
    unsigned short padd = 0;
    unsigned int sum = 0;

    const iphdr_ptr pIpHeader = reinterpret_cast<iphdr_ptr>(&pPacket->m_IBuffer[sizeof(ether_header)]);

    // Sanity check
    if (pIpHeader->ip_p == IPPROTO_TCP)
    {
        pTcpHeader = reinterpret_cast<tcphdr_ptr>(reinterpret_cast<PUCHAR>(pIpHeader) + sizeof(DWORD) * pIpHeader->ip_hl);
    }
    else
        return;

    const DWORD dwTcpLen = ntohs(pIpHeader->ip_len) - pIpHeader->ip_hl * 4;

    if ((dwTcpLen / 2) * 2 != dwTcpLen)
    {
        padd = 1;
        pPacket->m_IBuffer[dwTcpLen + pIpHeader->ip_hl * 4 + static_cast<DWORD>(sizeof(ether_header))] = 0;
    }

    const PUCHAR buff = reinterpret_cast<PUCHAR>(pTcpHeader);
    pTcpHeader->th_sum = 0;

    // Make 16-bit words out of every two adjacent 8-bit words and calculate the sum of all 16-bit words
    for (unsigned int i = 0; i < dwTcpLen + padd; i = i + 2)
    {
        const unsigned short word16 = ((buff[i] << 8) & 0xFF00) + (buff[i + 1] & 0xFF);
        sum = sum + static_cast<unsigned long>(word16);
    }

    // Add the TCP pseudo header which contains:
    // the IP source and destination addresses
    sum = sum + ntohs(pIpHeader->ip_src.S_un.S_un_w.s_w1) + ntohs(pIpHeader->ip_src.S_un.S_un_w.s_w2);
    sum = sum + ntohs(pIpHeader->ip_dst.S_un.S_un_w.s_w1) + ntohs(pIpHeader->ip_dst.S_un.S_un_w.s_w2);

    // The protocol number and the length of the TCP packet
    sum = sum + IPPROTO_TCP + static_cast<unsigned short>(dwTcpLen);

    // Keep only the last 16 bits of the 32-bit calculated sum and add the carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // Take the one's complement of sum
    sum = ~sum;

    pTcpHeader->th_sum = htons(static_cast<unsigned short>(sum));
}

/**
 * @brief Recalculates the UDP checksum for a given IPv4 packet.
 * @param pPacket The packet for which the UDP checksum needs to be recalculated.
 *
 * This function recalculates the UDP checksum for a packet by considering the pseudo-header,
 * which includes the IP source and destination addresses, protocol number, and the length of
 * the UDP packet. The calculated checksum is stored in the UDP header of the packet.
 */
void CNdisApi::RecalculateUDPChecksum(PINTERMEDIATE_BUFFER pPacket) {
    unsigned short padd = 0;
    unsigned int sum = 0;

    const iphdr_ptr pIpHeader = reinterpret_cast<iphdr_ptr>(&pPacket->m_IBuffer[sizeof(ether_header)]);

    // Sanity check: Ensure the packet is a UDP packet
    if (pIpHeader->ip_p != IPPROTO_UDP) {
        return;
    }

    const udphdr_ptr pUdpHeader = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(pIpHeader) + sizeof(DWORD) * pIpHeader
        ->ip_hl);

    const DWORD dwUdpLen = ntohs(pIpHeader->ip_len) - pIpHeader->ip_hl * 4;

    // Check if padding is needed
    if ((dwUdpLen / 2) * 2 != dwUdpLen) {
        padd = 1;
        pPacket->m_IBuffer[dwUdpLen + pIpHeader->ip_hl * 4 + static_cast<DWORD>(sizeof(ether_header))] = 0;
    }

    const PUCHAR buff = reinterpret_cast<PUCHAR>(pUdpHeader);
    pUdpHeader->th_sum = 0;

    // Calculate the sum of 16-bit words of the UDP packet
    for (unsigned int i = 0; i < dwUdpLen + padd; i = i + 2) {
        const unsigned short word16 = ((buff[i] << 8) & 0xFF00) + (buff[i + 1] & 0xFF);
        sum = sum + static_cast<unsigned long>(word16);
    }

    // Add the UDP pseudo-header to the sum
    sum = sum + ntohs(pIpHeader->ip_src.S_un.S_un_w.s_w1) + ntohs(pIpHeader->ip_src.S_un.S_un_w.s_w2);
    sum = sum + ntohs(pIpHeader->ip_dst.S_un.S_un_w.s_w1) + ntohs(pIpHeader->ip_dst.S_un.S_un_w.s_w2);
    sum = sum + IPPROTO_UDP + static_cast<unsigned short>(dwUdpLen);

    // Keep only the last 16 bits of the calculated sum and add the carries
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take the one's complement of sum
    sum = ~sum;

    // Store the recalculated checksum in the UDP header
    pUdpHeader->th_sum = ntohs(static_cast<unsigned short>(sum));
}

/**
 * @brief Opens the filter driver with the specified file name.
 * @param pszFileName The file name of the filter driver to be opened.
 * @return A handle to the opened filter driver, represented as a CNdisApi object.
 *
 * This function creates a new CNdisApi object with the given file name and returns its handle.
 * The handle can be used to perform operations with the opened filter driver.
 */
HANDLE __stdcall OpenFilterDriver(const TCHAR* pszFileName) {
    return new CNdisApi(pszFileName);
}

/**
 * @brief Closes the filter driver associated with the given handle.
 * @param hOpen The handle to the filter driver to be closed.
 *
 * This function deallocates the CNdisApi object associated with the provided handle,
 * effectively closing the filter driver.
 */
VOID __stdcall CloseFilterDriver(HANDLE hOpen) {
    delete static_cast<CNdisApi*>(hOpen);
}

/**
 * @brief Retrieves the version of the filter driver associated with the given handle.
 * @param hOpen The handle to the filter driver for which the version is requested.
 * @return The version of the filter driver as a DWORD, or 0 if the handle is invalid.
 *
 * This function retrieves the version of the filter driver associated with the provided handle
 * by calling the GetVersion() method of the CNdisApi object.
 */
DWORD __stdcall GetDriverVersion(HANDLE hOpen) {
    if (!hOpen) {
        return 0;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->GetVersion();
}

/**
 * @brief Retrieves information about the TCP/IP bound adapters using the given filter driver handle.
 * @param hOpen The handle to the filter driver for which the TCP/IP bound adapters information is requested.
 * @param pAdapters A pointer to a TCP_AdapterList structure that receives the information about the adapters.
 * @return TRUE if the information is successfully retrieved, or FALSE if the handle is invalid or the operation fails.
 *
 * This function retrieves information about the TCP/IP bound adapters associated with the provided filter driver handle
 * by calling the GetTcpipBoundAdaptersInfo() method of the CNdisApi object.
 */
BOOL __stdcall GetTcpipBoundAdaptersInfo(HANDLE hOpen, PTCP_AdapterList pAdapters) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->GetTcpipBoundAdaptersInfo(pAdapters);
}

/**
 * @brief Sends a packet to the Microsoft TCP/IP stack using the given filter driver handle.
 * @param hOpen The handle to the filter driver.
 * @param pPacket A pointer to an ETH_REQUEST structure containing the packet to be sent.
 * @return TRUE if the packet is successfully sent, or FALSE if the handle is invalid or the operation fails.
 *
 * This function sends a packet to the Microsoft TCP/IP stack using the provided filter driver handle
 * by calling the SendPacketToMstcp() method of the CNdisApi object.
 */
BOOL __stdcall SendPacketToMstcp(HANDLE hOpen, PETH_REQUEST pPacket) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->SendPacketToMstcp(pPacket);
}

/**
 * @brief Sends a packet to the network adapter using the given filter driver handle.
 * @param hOpen The handle to the filter driver.
 * @param pPacket A pointer to an ETH_REQUEST structure containing the packet to be sent.
 * @return TRUE if the packet is successfully sent, or FALSE if the handle is invalid or the operation fails.
 *
 * This function sends a packet to the network adapter using the provided filter driver handle
 * by calling the SendPacketToAdapter() method of the CNdisApi object.
 */
BOOL __stdcall SendPacketToAdapter(HANDLE hOpen, PETH_REQUEST pPacket) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->SendPacketToAdapter(pPacket);
}

/**
 * @brief Reads a packet from the network adapter using the given filter driver handle.
 * @param hOpen The handle to the filter driver from which the packet is to be read.
 * @param pPacket A pointer to an ETH_REQUEST structure that receives the packet information.
 * @return TRUE if the packet is successfully read, or FALSE if the handle is invalid or the operation fails.
 *
 * This function reads a packet from the network adapter using the provided filter driver handle
 * by calling the ReadPacket() method of the CNdisApi object.
 */
BOOL __stdcall ReadPacket(HANDLE hOpen, PETH_REQUEST pPacket) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->ReadPacket(pPacket);
}

/**
 * @brief Sends multiple packets to the Microsoft TCP/IP stack using the given filter driver handle.
 * @param hOpen The handle to the filter driver.
 * @param pPackets A pointer to an ETH_M_REQUEST structure containing the packets to be sent.
 * @return TRUE if the packets are successfully sent, or FALSE if the handle is invalid or the operation fails.
 *
 * This function sends multiple packets to the Microsoft TCP/IP stack using the provided filter driver handle
 * by calling the SendPacketsToMstcp() method of the CNdisApi object.
 */
BOOL __stdcall SendPacketsToMstcp(HANDLE hOpen, PETH_M_REQUEST pPackets) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->SendPacketsToMstcp(pPackets);
}

/**
 * @brief Sends multiple packets to the network adapter using the given filter driver handle.
 * @param hOpen The handle to the filter driver.
 * @param pPackets A pointer to an ETH_M_REQUEST structure containing the packets to be sent.
 * @return TRUE if the packets are successfully sent, or FALSE if the handle is invalid or the operation fails.
 *
 * This function sends multiple packets to the network adapter using the provided filter driver handle
 * by calling the SendPacketsToAdapter() method of the CNdisApi object.
 */
BOOL __stdcall SendPacketsToAdapter(HANDLE hOpen, PETH_M_REQUEST pPackets) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->SendPacketsToAdapter(pPackets);
}

/**
 * @brief Reads multiple packets from the network adapter using the given filter driver handle.
 * @param hOpen The handle to the filter driver from which the packets are to be read.
 * @param pPackets A pointer to an ETH_M_REQUEST structure that receives the packet information.
 * @return TRUE if the packets are successfully read, or FALSE if the handle is invalid or the operation fails.
 *
 * This function reads multiple packets from the network adapter using the provided filter driver handle
 * by calling the ReadPackets() method of the CNdisApi object.
 */
BOOL __stdcall ReadPackets(HANDLE hOpen, PETH_M_REQUEST pPackets) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->ReadPackets(pPackets);
}

/**
 * @brief Sets the filter mode of the network adapter using the given filter driver handle.
 * @param hOpen The handle to the filter driver.
 * @param pMode A pointer to an ADAPTER_MODE structure containing the adapter handle and new filter mode settings.
 * @return TRUE if the mode is successfully set, or FALSE if the handle is invalid or the operation fails.
 *
 * This function sets the filter mode of the network adapter using the provided filter driver handle
 * by calling the SetAdapterMode() method of the CNdisApi object.
 */
BOOL __stdcall SetAdapterMode(HANDLE hOpen, PADAPTER_MODE pMode) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->SetAdapterMode(pMode);
}

/**
 * @brief Retrieves the filter mode of the network adapter using the given filter driver handle.
 * @param hOpen The handle to the filter driver.
 * @param pMode A pointer to an ADAPTER_MODE structure containing the adapter handle that receives the mode settings.
 * @return TRUE if the mode is successfully retrieved, or FALSE if the handle is invalid or the operation fails.
 *
 * This function retrieves the operating mode of the network adapter using the provided filter driver handle
 * by calling the GetAdapterMode() method of the CNdisApi object.
 */
BOOL __stdcall GetAdapterMode(HANDLE hOpen, PADAPTER_MODE pMode) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->GetAdapterMode(pMode);
}

/**
 * @brief Flushes the packet queue of the network adapter using the given filter driver handle.
 * @param hOpen The handle to the filter driver.
 * @param hAdapter The handle to the network adapter whose packet queue is to be flushed.
 * @return TRUE if the packet queue is successfully flushed, or FALSE if the handle is invalid or the operation fails.
 *
 * This function flushes the packet queue of the network adapter using the provided filter driver handle
 * by calling the FlushAdapterPacketQueue() method of the CNdisApi object.
 */
BOOL __stdcall FlushAdapterPacketQueue(HANDLE hOpen, HANDLE hAdapter) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->FlushAdapterPacketQueue(hAdapter);
}

/**
 * @brief Retrieves the packet queue size of the network adapter using the given filter driver handle.
 * @param hOpen The handle to the filter driver.
 * @param hAdapter The handle to the network adapter whose packet queue size is to be retrieved.
 * @param pdwSize A pointer to a DWORD variable that receives the size of the packet queue.
 * @return TRUE if the packet queue size is successfully retrieved, or FALSE if the handle is invalid or the operation fails.
 *
 * This function retrieves the packet queue size of the network adapter usingh the provided filter driver handle
 * by calling the GetAdapterPacketQueueSize() method of the CNdisApi object.
 */
BOOL __stdcall GetAdapterPacketQueueSize(HANDLE hOpen, HANDLE hAdapter, PDWORD pdwSize) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->GetAdapterPacketQueueSize(hAdapter, pdwSize);
}

/**
 * @brief Associates a Win32 event with the packet queue of the network adapter using the given filter driver handle.
 * @param hOpen The handle to the filter driver.
 * @param hAdapter The handle to the network adapter whose packet queue is to be associated with the event.
 * @param hWin32Event The handle to a Win32 event to be associated with the packet queue.
 * @return TRUE if the event is successfully set, or FALSE if the handle is invalid or the operation fails.
 *
 * This function associates a Win32 event with the packet queue of the network adapter using the provided filter driver handle
 * by calling the SetPacketEvent() method of the CNdisApi object.
 */
BOOL __stdcall SetPacketEvent(HANDLE hOpen, HANDLE hAdapter, HANDLE hWin32Event) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->SetPacketEvent(hAdapter, hWin32Event);
}

/**
 * @brief Associates a Win32 event with the WAN connect/disconnect events of the network adapters using the given filter driver handle.
 * @param hOpen The handle to the filter driver.
 * @param hWin32Event The handle to a Win32 event to be associated with the WAN connect/disconnect events.
 * @return TRUE if the event is successfully set, or FALSE if the handle is invalid or the operation fails.
 *
 * This function associates a Win32 event with the WAN events of the network adapters using the provided filter driver handle
 * by calling the SetWANEvent() method of the CNdisApi object.
 */
BOOL __stdcall SetWANEvent(HANDLE hOpen, HANDLE hWin32Event) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->SetWANEvent(hWin32Event);
}

/**
 * @brief Associates a Win32 event with the network adapter list change events for the given filter driver handle.
 * @param hOpen The handle to the filter driver for which the adapter list change event is to be set.
 * @param hWin32Event The handle to a Win32 event to be associated with the adapter list change events.
 * @return TRUE if the event is successfully set, or FALSE if the handle is invalid or the operation fails.
 *
 * This function associates a Win32 event with the network adapter list change events associated with the provided filter driver handle
 * by calling the SetAdapterListChangeEvent() method of the CNdisApi object.
 */
BOOL __stdcall SetAdapterListChangeEvent(HANDLE hOpen, HANDLE hWin32Event) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->SetAdapterListChangeEvent(hWin32Event);
}

/**
 * @brief Sends an OID request to the filter driver associated with the given handle.
 * @param hOpen The handle to the filter driver.
 * @param OidData A pointer to a PACKET_OID_DATA structure containing the OID data and adapter handle associated with OID request.
 * @param Set A boolean value specifying whether the request is a set (TRUE) or query (FALSE) operation.
 * @return TRUE if the OID request is successfully sent, or FALSE if the handle is invalid or the operation fails.
 *
 * This function sends an OID request to the filter driver associated with the provided handle
 * by calling the NdisrdRequest() method of the CNdisApi object.
 */
BOOL __stdcall NdisrdRequest(HANDLE hOpen, PPACKET_OID_DATA OidData, BOOL Set) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->NdisrdRequest(OidData, Set);
}

/**
 * @brief Retrieves RAS links information for the network adapter using the given filter driver handle.
 * @param hOpen The handle to the filter driver.
 * @param hAdapter The handle to the network adapter whose RAS links information is to be retrieved.
 * @param pLinks A pointer to a RAS_LINKS structure that receives the RAS links information.
 * @return TRUE if the RAS links information is successfully retrieved, or FALSE if the handle is invalid or the operation fails.
 *
 * This function retrieves RAS links information for the network adapter using the provided filter driver handle
 * by calling the GetRasLinks() method of the CNdisApi object.
 */
BOOL __stdcall GetRasLinks(HANDLE hOpen, HANDLE hAdapter, PRAS_LINKS pLinks) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->GetRasLinks(hAdapter, pLinks);
}

/**
 * @brief Sets the hardware packet filter for the network adapter using the given filter driver handle.
 * @param hOpen The handle to the filter driver.
 * @param hAdapter The handle to the network adapter whose hardware packet filter is to be set.
 * @param Filter A DWORD value specifying the hardware packet filter to be set.
 * @return TRUE if the hardware packet filter is successfully set, or FALSE if the handle is invalid or the operation fails.
 *
 * This function sets the hardware packet filter for the network adapter using the provided filter driver handle
 * by calling the SetHwPacketFilter() method of the CNdisApi object.
 */
BOOL __stdcall SetHwPacketFilter(HANDLE hOpen, HANDLE hAdapter, DWORD Filter) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->SetHwPacketFilter(hAdapter, Filter);
}

/**
 * @brief Retrieves the hardware packet filter for the network adapter using the given filter driver handle.
 * @param hOpen The handle to the filter driver.
 * @param hAdapter The handle to the network adapter whose hardware packet filter is to be retrieved.
 * @param pFilter A pointer to a DWORD variable that receives the hardware packet filter value.
 * @return TRUE if the hardware packet filter is successfully retrieved, or FALSE if the handle is invalid or the operation fails.
 *
 * This function retrieves the hardware packet filter for the network adapter using the provided filter driver handle
 * by calling the GetHwPacketFilter() method of the CNdisApi object.
 */
BOOL __stdcall GetHwPacketFilter(HANDLE hOpen, HANDLE hAdapter, PDWORD pFilter) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->GetHwPacketFilter(hAdapter, pFilter);
}

/**
 * @brief Sets a hardware packet filter change event for the network adapter using the given filter driver handle.
 * @param hOpen The handle to the filter driver.
 * @param hAdapter The handle to the network adapter whose hardware packet filter change event is to be set.
 * @param hWin32Event The Win32 event to be associated with the hardware packet filter event.
 * @return TRUE if the hardware packet filter event is successfully set, or FALSE if the handle is invalid or the operation fails.
 *
 * This function sets a hardware packet filter event for the network adapter using the provided filter driver handle
 * by calling the SetHwPacketFilterEvent() method of the CNdisApi object.
 */
BOOL __stdcall SetHwPacketFilterEvent(HANDLE hOpen, HANDLE hAdapter, HANDLE hWin32Event) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->SetHwPacketFilterEvent(hAdapter, hWin32Event);
}

/**
 * @brief Sets the packet filter table for the filter driver associated with the given handle.
 * @param hOpen The handle to the filter driver for which the packet filter table is to be set.
 * @param pFilterList A pointer to a STATIC_FILTER_TABLE structure containing the packet filter rules to be applied.
 * @return TRUE if the packet filter table is successfully set, or FALSE if the handle is invalid or the operation fails.
 *
 * This function sets the packet filter table for the filter driver associated with the provided handle
 * by calling the SetPacketFilterTable() method of the CNdisApi object.
 */
BOOL __stdcall SetPacketFilterTable(HANDLE hOpen, PSTATIC_FILTER_TABLE pFilterList) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->SetPacketFilterTable(pFilterList);
}

/**
 * @brief Adds a static filter to the beginning of the filter list.
 *
 * This function adds a new static filter to the front of the filter list managed by the NDISAPI driver.
 * The filter is specified by the pFilter parameter. This operation is only successful if the handle to the
 * driver (hOpen) is valid.
 *
 * @param hOpen Handle to the NDISAPI driver.
 * @param pFilter Pointer to the STATIC_FILTER structure that defines the filter to be added.
 * @return TRUE if the filter was successfully added, FALSE otherwise.
 */
BOOL __stdcall AddStaticFilterFront(HANDLE hOpen, PSTATIC_FILTER pFilter)
{
    if (!hOpen)
        return FALSE;

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->AddStaticFilterFront(pFilter);
}

/**
 * @brief Adds a static filter to the end of the filter list.
 *
 * This function adds a new static filter to the back of the filter list managed by the NDISAPI driver.
 * The filter is specified by the pFilter parameter. This operation is only successful if the handle to the
 * driver (hOpen) is valid.
 *
 * @param hOpen Handle to the NDISAPI driver.
 * @param pFilter Pointer to the STATIC_FILTER structure that defines the filter to be added.
 * @return TRUE if the filter was successfully added, FALSE otherwise.
 */
BOOL __stdcall AddStaticFilterBack(HANDLE hOpen, PSTATIC_FILTER pFilter)
{
    if (!hOpen)
        return FALSE;

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->AddStaticFilterBack(pFilter);
}

/**
 * @brief Inserts a static filter at a specified position in the filter list.
 *
 * This function inserts a new static filter at the specified position in the filter list managed by the NDISAPI driver.
 * The position is zero-based. The filter is specified by the pFilter parameter. This operation is only successful if
 * the handle to the driver (hOpen) is valid.
 *
 * @param hOpen Handle to the NDISAPI driver.
 * @param pFilter Pointer to the STATIC_FILTER structure that defines the filter to be inserted.
 * @param Position The zero-based position at which to insert the new filter.
 * @return TRUE if the filter was successfully inserted, FALSE otherwise.
 */
BOOL __stdcall InsertStaticFilter(HANDLE hOpen, PSTATIC_FILTER pFilter, unsigned long Position) {
    if (!hOpen)
        return FALSE;

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->InsertStaticFilter(pFilter, Position);
}

/**
 * @brief Removes a static filter from the filter list by its unique identifier.
 *
 * This function removes a static filter from the filter list managed by the NDISAPI driver. The filter to be removed
 * is identified by its unique identifier (dwFilterId). This operation is only successful if the handle to the driver
 * (hOpen) is valid.
 *
 * @param hOpen Handle to the NDISAPI driver.
 * @param dwFilterId The unique identifier of the filter to be removed.
 * @return TRUE if the filter was successfully removed, FALSE otherwise.
 */
BOOL __stdcall RemoveStaticFilter(HANDLE hOpen, DWORD dwFilterId)
{
    if (!hOpen)
        return FALSE;

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->RemoveStaticFilter(dwFilterId);
}

/**
 * @brief Resets the packet filter table for the filter driver associated with the given handle.
 * @param hOpen The handle to the filter driver for which the packet filter table is to be reset.
 * @return TRUE if the packet filter table is successfully reset, or FALSE if the handle is invalid or the operation fails.
 *
 * This function resets the packet filter table for the filter driver associated with the provided handle
 * by calling the ResetPacketFilterTable() method of the CNdisApi object.
 */
BOOL __stdcall ResetPacketFilterTable(HANDLE hOpen) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->ResetPacketFilterTable();
}

/**
 * @brief Retrieves the packet filter table size for the filter driver associated with the given handle.
 * @param hOpen The handle to the filter driver for which the packet filter table size is to be retrieved.
 * @param pdwTableSize A pointer to a DWORD variable that receives the size of the packet filter table.
 * @return TRUE if the packet filter table size is successfully retrieved, or FALSE if the handle is invalid or the operation fails.
 *
 * This function retrieves the packet filter table size for the filter driver associated with the provided handle
 * by calling the GetPacketFilterTableSize() method of the CNdisApi object.
 */
BOOL __stdcall GetPacketFilterTableSize(HANDLE hOpen, PDWORD pdwTableSize) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->GetPacketFilterTableSize(pdwTableSize);
}

/**
 * @brief Retrieves the packet filter table for the filter driver associated with the given handle.
 * @param hOpen The handle to the filter driver for which the packet filter table is to be retrieved.
 * @param pFilterList A pointer to a STATIC_FILTER_TABLE structure that receives the packet filter rules.
 * @return TRUE if the packet filter table is successfully retrieved, or FALSE if the handle is invalid or the operation fails.
 *
 * This function retrieves the packet filter table for the filter driver associated with the provided handle
 * by calling the GetPacketFilterTable() method of the CNdisApi object.
 */
BOOL __stdcall GetPacketFilterTable(HANDLE hOpen, PSTATIC_FILTER_TABLE pFilterList) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->GetPacketFilterTable(pFilterList);
}

/**
 * @brief Retrieves the packet filter table with reset statistics for the filter driver associated with the given handle.
 * @param hOpen The handle to the filter driver for which the packet filter table with reset statistics is to be retrieved.
 * @param pFilterList A pointer to a STATIC_FILTER_TABLE structure that receives the packet filter rules with reset statistics.
 * @return TRUE if the packet filter table with reset statistics is successfully retrieved, or FALSE if the handle is invalid or the operation fails.
 *
 * This function retrieves the packet filter table with reset statistics for the filter driver associated with the provided handle
 * by calling the GetPacketFilterTableResetStats() method of the CNdisApi object.
 */
BOOL __stdcall GetPacketFilterTableResetStats(HANDLE hOpen, PSTATIC_FILTER_TABLE pFilterList) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->GetPacketFilterTableResetStats(pFilterList);
}

/**
 * @brief Enables the packet filter cache.
 *
 * This function enables the packet filter cache for the filter driver associated with the given handle.
 * The packet filter cache is used to improve performance by caching packet filters. Enabling the cache
 * can improve packet processing speed, while disabling it may be useful for debugging or in scenarios
 * where caching is not desirable.
 *
 * @param hOpen A handle to the open object for which the packet filter cache will be enabled.
 * @return TRUE if the operation was successful, FALSE otherwise.
 */
BOOL __stdcall EnablePacketFilterCache(HANDLE hOpen) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->EnablePacketFilterCache();
}

/**
 * @brief Disables the packet filter cache.
 *
 * This function disables the packet filter cache for the filter driver associated with the given handle.
 * Disabling the cache may be useful for debugging or in scenarios where caching is not desirable.
 *
 * @param hOpen A handle to the open object for which the packet filter cache will be disabled.
 * @return TRUE if the operation was successful, FALSE otherwise.
 */
BOOL __stdcall DisablePacketFilterCache(HANDLE hOpen) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->DisablePacketFilterCache();
}

/**
 * @brief Enables the packet fragment cache.
 *
 * This function enables the packet fragment cache for the filter driver associated with the given handle.
 * The packet fragment cache is used to improve performance by caching packet fragments. Enabling the cache
 * can improve packet processing speed, while disabling it may be useful for debugging or in scenarios where
 * caching is not desirable.
 *
 * @param hOpen A handle to the open object for which the packet fragment cache will be enabled.
 * @return TRUE if the operation was successful, FALSE otherwise.
 */
BOOL __stdcall EnablePacketFragmentCache(HANDLE hOpen) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->EnablePacketFragmentCache();
}

/**
 * @brief Disables the packet fragment cache.
 *
 * This function disables the packet fragment cache for the filter driver associated with the given handle.
 * Disabling the cache may be useful for debugging or in scenarios where caching is not desirable.
 *
 * @param hOpen A handle to the open object for which the packet fragment cache will be disabled.
 * @return TRUE if the operation was successful, FALSE otherwise.
 */
BOOL __stdcall DisablePacketFragmentCache(HANDLE hOpen) {
    if (!hOpen) {
        return FALSE;
    }

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->DisablePacketFragmentCache();
}

/**
 * @brief Sets the MTU decrement value.
 * @param dwMTUDecrement The value to decrement the MTU by.
 * @return TRUE if the MTU decrement is successfully set, or FALSE if the operation fails.
 *
 * This function sets the MTU decrement value by calling the SetMTUDecrement() method of the CNdisApi class.
 */
BOOL __stdcall SetMTUDecrement(DWORD dwMTUDecrement) {
    return CNdisApi::SetMTUDecrement(dwMTUDecrement);
}

/**
 * @brief Retrieves the current MTU decrement value.
 * @return The current MTU decrement value.
 *
 * This function retrieves the current MTU decrement value by calling the GetMTUDecrement() method of the CNdisApi class.
 */
DWORD __stdcall GetMTUDecrement() {
    return CNdisApi::GetMTUDecrement();
}

/**
 * @brief Sets the startup filter mode for network adapters.
 * @param dwStartupMode The startup filter mode value to be set.
 * @return TRUE if the adapter's startup filter mode is successfully set, or FALSE if the operation fails.
 *
 * This function sets the startup mode for network adapters by calling the SetAdaptersStartupMode() method of the CNdisApi class.
 */
BOOL __stdcall SetAdaptersStartupMode(DWORD dwStartupMode) {
    return CNdisApi::SetAdaptersStartupMode(dwStartupMode);
}

/**
 * @brief Retrieves the current startup filter mode for network adapters.
 * @return The current startup filter mode value.
 *
 * This function retrieves the current startup filter mode for network adapters by calling the GetAdaptersStartupMode() method of the CNdisApi class.
 */
DWORD __stdcall GetAdaptersStartupMode() {
    return CNdisApi::GetAdaptersStartupMode();
}

/**
 * @brief Sets the intermediate buffer pool size multiplier for Windows Packet Filter driver in the Windows registry.
 * @param dwPoolSize The desired pool size multiplier to be set in the registry.
 * @return TRUE if the pool size is successfully set, or FALSE if the operation fails.
 *
 * This function sets the pool size multiplier for Windows Packet Filter driver by calling the SetPoolSize()
 * method of the CNdisApi class.
 */
BOOL __stdcall SetPoolSize(DWORD dwPoolSize) {
    return CNdisApi::SetPoolSize(dwPoolSize);
}

/**
 * @brief Retrieves the pool size multiplier for the Windows Packet Filter driver from the Windows registry.
 *
 * This function gets the pool size multiplier for Windows Packet Filter driver by calling the SetPoolSize()
 * method of the CNdisApi class.
 *
 * @return DWORD The pool size multiplier retrieved from the registry, or 0 if the value is not found or an error occurs.
 */
DWORD __stdcall GetPoolSize()
{
    return CNdisApi::GetPoolSize();
}

/**
 * @brief Checks if the Windows Packet Filter driver is loaded.
 * @param hOpen The handle to the CNdisApi instance.
 * @return TRUE if the driver is loaded, or FALSE if the driver is not loaded or the handle is invalid.
 *
 * This function checks if the driver is loaded by calling the IsDriverLoaded() method of the CNdisApi class.
 * It returns FALSE if the handle provided is invalid.
 */
BOOL __stdcall IsDriverLoaded(HANDLE hOpen) {
    if (!hOpen)
        return FALSE;

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->IsDriverLoaded();
}

/**
 * @brief This function initializes the Fast I/O shared memory section for the Windows Packet Filter driver.
 * @param hOpen The handle to the CNdisApi instance.
 * @param pFastIo Pointer to a FAST_IO_SECTION structure that holds the Fast I/O section information.
 * @param dwSize The size of the FAST_IO_SECTION structure.
 * @return TRUE if the Fast I/O section is successfully initialized, or FALSE if the operation fails or the handle is invalid.
 *
 * This function initializes the Fast I/O section by calling the InitializeFastIo() method of the CNdisApi class.
 * It returns FALSE if the handle provided is invalid.
 */
BOOL __stdcall InitializeFastIo(HANDLE hOpen, PFAST_IO_SECTION pFastIo, DWORD dwSize) {
    if (!hOpen)
        return FALSE;

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->InitializeFastIo(pFastIo, dwSize);
}

/**
 * @brief This function adds a secondary Fast I/O shared memory section for the Windows Packet Filter driver.
 * @param hOpen The handle to the CNdisApi instance.
 * @param pFastIo Pointer to a FAST_IO_SECTION structure that holds the secondary Fast I/O section information.
 * @param dwSize The size of the FAST_IO_SECTION structure.
 * @return TRUE if the secondary Fast I/O section is successfully added, or FALSE if the operation fails or the handle is invalid.
 *
 * This function adds a secondary Fast I/O section by calling the AddSecondaryFastIo() method of the CNdisApi class.
 * It returns FALSE if the handle provided is invalid.
 */
BOOL __stdcall AddSecondaryFastIo(HANDLE hOpen, PFAST_IO_SECTION pFastIo, DWORD dwSize) {
    if (!hOpen)
        return FALSE;

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->AddSecondaryFastIo(pFastIo, dwSize);
}

/**
 * @brief Reads a bunch of packets from the driver packet queues without sorting.
 * @param hOpen The handle to the CNdisApi instance.
 * @param Packets Pointer to an array of PINTERMEDIATE_BUFFER pointers that will receive the packet data.
 * The associated adapter handle will be stored in the INTERMEDIATE_BUFFER.m_hAdapter field.
 * @param dwPacketsNum The number of packets to read.
 * @param pdwPacketsSuccess Pointer to a DWORD that will receive the number of successfully read packets.
 * @return TRUE if the function is successful, or FALSE if the operation fails or the handle is invalid.
 *
 * This function reads unsorted packets by calling the ReadPacketsUnsorted() method of the CNdisApi class.
 * It returns FALSE if the handle provided is invalid.The function is not available in WOW64 mode.
 */
BOOL __stdcall ReadPacketsUnsorted(HANDLE hOpen, PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketsSuccess) {
    if (!hOpen)
        return FALSE;

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->ReadPacketsUnsorted(Packets, dwPacketsNum, pdwPacketsSuccess);
}

/**
 * @brief Sends a bunch of packets to the network adapters.
 * @param hOpen The handle to the CNdisApi instance.
 * @param Packets Pointer to an array of PINTERMEDIATE_BUFFER pointers containing the packet data to send. The target
 * adapter handle should be set in the INTERMEDIATE_BUFFER.m_hAdapter field.
 * @param dwPacketsNum The number of packets to send.
 * @param pdwPacketSuccess Pointer to a DWORD that will receive the number of successfully sent packets.
 * @return TRUE if the function is successful, or FALSE if the operation fails or the handle is invalid.
 *
 * This function sends unsorted packets to the network adapters by calling the SendPacketsToAdaptersUnsorted() method of
 * the CNdisApi class. It returns FALSE if the handle provided is invalid.
 */
BOOL __stdcall SendPacketsToAdaptersUnsorted(HANDLE hOpen, PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketSuccess) {
    if (!hOpen)
        return FALSE;

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->SendPacketsToAdaptersUnsorted(Packets, dwPacketsNum, pdwPacketSuccess);
}

/**
 * @brief Sends unsorted packets to the MSTCP (and other upper layer network protocols) using the CNdisApi instance.
 * @param hOpen The handle to the CNdisApi instance.
 * @param Packets Pointer to an array of PINTERMEDIATE_BUFFER pointers containing the packet data to send. The associated
 * adapter handle should be stored in the INTERMEDIATE_BUFFER.m_hAdapter field.
 * @param dwPacketsNum The number of packets to send.
 * @param pdwPacketSuccess Pointer to a DWORD that will receive the number of successfully sent packets.
 * @return TRUE if the function is successful, or FALSE if the operation fails or the handle is invalid.
 *
 * This function sends unsorted packets to the MSTCP (and other upper layer network protocols) by calling
 * the SendPacketsToMstcpUnsorted() method of the CNdisApi class. It returns FALSE if the handle provided is invalid.
 */
BOOL __stdcall SendPacketsToMstcpUnsorted(HANDLE hOpen, PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketSuccess) {
    if (!hOpen)
        return FALSE;

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->SendPacketsToMstcpUnsorted(Packets, dwPacketsNum, pdwPacketSuccess);
}

/**
 * @brief Retrieves the effective size of the Windows Packet Filter internal intermediate buffer pool using the CNdisApi instance.
 * @param hOpen The handle to the CNdisApi instance.
 * @param pdwSize Pointer to a DWORD that will receive the size of the intermediate buffer pool.
 * @return TRUE if the function is successful, or FALSE if the operation fails or the handle is invalid.
 *
 * This function retrieves the size of the intermediate buffer pool used by the driver by calling the GetIntermediateBufferPoolSize()
 * method of the CNdisApi class. It returns FALSE if the handle provided is invalid.
 */
BOOL __stdcall GetIntermediateBufferPoolSize(HANDLE hOpen, PDWORD pdwSize) {
    if (!hOpen)
        return FALSE;

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->GetIntermediateBufferPoolSize(pdwSize);
}

/**
 * @brief Retrieves the number of bytes returned by the last operation that used an IOCTL code requiring a returned byte count using the CNdisApi instance.
 * @param hOpen The handle to the CNdisApi instance.
 * @return The number of bytes returned by the last operation if the function is successful, or FALSE if the handle is invalid.
 *
 * This function retrieves the number of bytes returned by the last operation that used an IOCTL code requiring a returned byte count.
 * It returns FALSE if the handle provided is invalid.
 */
DWORD __stdcall GetBytesReturned(HANDLE hOpen) {
    if (!hOpen)
        return FALSE;

    const CNdisApi* pApi = static_cast<CNdisApi*>(hOpen);

    return pApi->GetBytesReturned();
}

/**
 * @brief Determines if the given adapter is an NDISWANIP interface.
 *
 * @param adapterName The adapter name to check.
 * @return BOOL Returns TRUE if the adapter is an NDISWANIP interface, or FALSE otherwise.
 *
 * This function checks if the adapter name matches the internal name for
 * NDISWANIP on systems prior to Windows 10. On Windows 10 and later systems,
 * it calls the IsNdiswanInterface function to check if the adapter is an
 * NDISWAN interface with the specified component ID (REGSTR_COMPONENTID_NDISWANIP).
 */
BOOL __stdcall IsNdiswanIp(LPCSTR adapterName) {
    return CNdisApi::IsNdiswanIp(adapterName);
}

/**
 * @brief Determines if the given adapter is an NDISWANIPV6 interface.
 *
 * @param adapterName The adapter name to check.
 * @return BOOL Returns TRUE if the adapter is an NDISWANIPV6 interface, or FALSE otherwise.
 *
 * This function checks if the adapter name matches the internal name for
 * NDISWANIPV6 on systems prior to Windows 10. On Windows 10 and later systems,
 * it calls the IsNdiswanInterface function to check if the adapter is an
 * NDISWAN interface with the specified component ID (REGSTR_COMPONENTID_NDISWANIPV6).
 */
BOOL __stdcall IsNdiswanIpv6(LPCSTR adapterName) {
    return CNdisApi::IsNdiswanIpv6(adapterName);
}

/**
 * @brief Determines if the given adapter is an NDISWANBH interface.
 *
 * @param adapterName The adapter name to check.
 * @return BOOL Returns TRUE if the adapter is an NDISWANBH interface, or FALSE otherwise.
 *
 * This function checks if the adapter name matches the internal name for
 * NDISWANBH on systems prior to Windows 10. On Windows 10 and later systems,
 * it calls the IsNdiswanInterface function to check if the adapter is an
 * NDISWAN interface with the specified component ID (REGSTR_COMPONENTID_NDISWANBH).
 */
BOOL __stdcall IsNdiswanBh(LPCSTR adapterName) {
    return CNdisApi::IsNdiswanBh(adapterName);
}

/**
 * @brief Converts an adapter's internal name to a user-friendly name on Windows NT 4.0.
 *
 * @param szAdapterName The internal adapter name to convert.
 * @param szUserFriendlyName A pointer to a buffer to store the resulting user-friendly name.
 * @param dwUserFriendlyNameLength The length of the buffer pointed to by szUserFriendlyName.
 * @return BOOL Returns TRUE if the conversion is successful, or FALSE otherwise.
 *
 * This function converts an adapter's internal name to a user-friendly name
 * that is easier to understand. The user-friendly name is stored in the buffer
 * pointed to by szUserFriendlyName. The function returns TRUE if the conversion is
 * successful and FALSE otherwise. The length of the buffer is specified by the
 * dwUserFriendlyNameLength parameter.
 */
BOOL
__stdcall
ConvertWindowsNTAdapterName(
    LPCSTR szAdapterName,
    LPSTR szUserFriendlyName,
    DWORD dwUserFriendlyNameLength
)
{
    return CNdisApi::ConvertWindowsNTAdapterName(
        szAdapterName,
        szUserFriendlyName,
        dwUserFriendlyNameLength
    );
}

/**
 * @brief Converts an adapter's internal name to a user-friendly name on Windows 2000 and later.
 *
 * @param szAdapterName The internal adapter name to convert.
 * @param szUserFriendlyName A pointer to a buffer to store the resulting user-friendly name.
 * @param dwUserFriendlyNameLength The length of the buffer pointed to by szUserFriendlyName.
 * @return BOOL Returns TRUE if the conversion is successful, or FALSE otherwise.
 *
 * This function converts an adapter's internal name to a user-friendly name
 * that is easier to understand. The user-friendly name is stored in the buffer
 * pointed to by szUserFriendlyName. The function returns TRUE if the conversion is
 * successful and FALSE otherwise. The length of the buffer is specified by the
 * dwUserFriendlyNameLength parameter.
 */
BOOL
__stdcall
ConvertWindows2000AdapterName(
    LPCSTR szAdapterName,
    LPSTR szUserFriendlyName,
    DWORD dwUserFriendlyNameLength
)
{
    return CNdisApi::ConvertWindows2000AdapterName(
        szAdapterName,
        szUserFriendlyName,
        dwUserFriendlyNameLength
    );
}

/**
 * @brief Converts an adapter's internal name to a user-friendly name on Windows 95/98/ME.
 *
 * @param szAdapterName The internal adapter name to convert.
 * @param szUserFriendlyName A pointer to a buffer to store the resulting user-friendly name.
 * @param dwUserFriendlyNameLength The length of the buffer pointed to by szUserFriendlyName.
 * @return BOOL Returns TRUE if the conversion is successful, or FALSE otherwise.
 *
 * This function converts an adapter's internal name to a user-friendly name
 * that is easier to understand. The user-friendly name is stored in the buffer
 * pointed to by szUserFriendlyName. The function returns TRUE if the conversion is
 * successful and FALSE otherwise. The length of the buffer is specified by the
 * dwUserFriendlyNameLength parameter.
 */
BOOL
__stdcall
ConvertWindows9xAdapterName(
    LPCSTR szAdapterName,
    LPSTR szUserFriendlyName,
    DWORD dwUserFriendlyNameLength
)
{
    return CNdisApi::ConvertWindows9xAdapterName(
        szAdapterName,
        szUserFriendlyName,
        dwUserFriendlyNameLength
    );
}

/**
 * @brief Recalculates the IPv4 checksum of a given packet.
 *
 * @param pPacket Pointer to the packet's INTERMEDIATE_BUFFER structure.
 *
 * This function recalculates the IP checksum for the given packet. The IP checksum
 * is a 16-bit value used to verify the integrity of the IP header in an IP packet.
 * The checksum must be recalculated if any changes are made to the IP header.
 * This function should be called after modifying any field in the IP header
 * to ensure the packet's integrity.
 */
void
__stdcall
RecalculateIPChecksum(
    PINTERMEDIATE_BUFFER pPacket
)
{
    CNdisApi::RecalculateIPChecksum(pPacket);
}

/**
 * @brief Recalculates the ICMPv4 checksum of a given packet.
 *
 * @param pPacket Pointer to the packet's INTERMEDIATE_BUFFER structure.
 */
void
__stdcall
RecalculateICMPChecksum(
    PINTERMEDIATE_BUFFER pPacket
)
{
    CNdisApi::RecalculateICMPChecksum(pPacket);
}

/**
 * @brief Recalculates the TCP checksum of a given IPv4 packet.
 *
 * @param pPacket Pointer to the packet's INTERMEDIATE_BUFFER structure.
 */
void
__stdcall
RecalculateTCPChecksum(
    PINTERMEDIATE_BUFFER pPacket
)
{
    CNdisApi::RecalculateTCPChecksum(pPacket);
}

/**
 * @brief Recalculates the UDP checksum for a given IPv4 packet.
 * @param pPacket The packet for which the UDP checksum needs to be recalculated.
 *
 * This function recalculates the UDP checksum for a packet by considering the pseudo-header,
 * which includes the IP source and destination addresses, protocol number, and the length of
 * the UDP packet. The calculated checksum is stored in the UDP header of the packet.
 */
void
__stdcall
RecalculateUDPChecksum(
    PINTERMEDIATE_BUFFER pPacket
)
{
    CNdisApi::RecalculateUDPChecksum(pPacket);
}

