/**************************************************************************/
/*                   Copyright (c) 2000-2024 NT KERNEL.                   */
/*                           All Rights Reserved.                         */
/*                          https://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                          */
/*                                                                        */
/* Module Name:  common.h                                                 */
/*                                                                        */
/* Abstract: Definitions common to kernel-mode driver and Win32 app.      */
/*                                                                        */
/* Environment:                                                           */
/*   User mode, Kernel mode                                               */
/*                                                                        */
/* Description: This header file contains definitions and data structures */
/*              that are common to both the kernel-mode driver and the    */
/*              Win32 application. This includes constants, structure     */
/*              definitions, and function prototypes.                     */
/*                                                                        */
/**************************************************************************/

#ifndef COMMON_H
#define COMMON_H

#ifdef _WINDOWS
#include <WinIoctl.h>   // Compiling Win32 Applications Or DLL's
#endif // _WINDOWS

#ifndef ANY_SIZE
#define ANY_SIZE 1
#endif

// NDISRD_VERSION is the version number of the NDISRD driver
#define NDISRD_VERSION             0x06013000

// NDISRD_MAJOR_VERSION is the major version number of the NDISRD driver
#define NDISRD_MAJOR_VERSION       0x0003

// NDISRD_MINOR_VERSION is the minor version number of the NDISRD driver
#define NDISRD_MINOR_VERSION       0x0601

// DRIVER_NAME_A is the ASCII name of the NDISRD driver
#define DRIVER_NAME_A              "NDISRD"

// DRIVER_NAME_U is the Unicode name of the NDISRD driver
#define DRIVER_NAME_U              L"NDISRD"

// DEVICE_NAME is the device name of the NDISRD driver in the device namespace
#define DEVICE_NAME                L"\\Device\\NDISRD"

// SYMLINK_NAME is the symbolic link name of the NDISRD driver in the DOS namespace
#define SYMLINK_NAME               L"\\DosDevices\\NDISRD"

// WIN9X_REG_PARAM is the registry path for the NDISRD driver parameters on Windows 9x systems
#define WIN9X_REG_PARAM            "System\\CurrentControlSet\\Services\\VxD\\ndisrd\\Parameters"

// WINNT_REG_PARAM is the registry path for the NDISRD driver parameters on Windows NT systems
#define WINNT_REG_PARAM            TEXT("SYSTEM\\CurrentControlSet\\Services\\ndisrd\\Parameters")

// FILTER_FRIENDLY_NAME is the friendly name of the NDISRD filter
#define FILTER_FRIENDLY_NAME       L"WinpkFilter NDIS LightWeight Filter"

// FILTER_UNIQUE_NAME is the unique name (GUID) of the NDISRD filter
#define FILTER_UNIQUE_NAME         L"{CD75C963-E19F-4139-BC3B-14019EF72F19}"

// FILTER_SERVICE_NAME is the service name of the NDISRD filter
#define FILTER_SERVICE_NAME        L"NDISRD"

// Some size constants
#define ADAPTER_NAME_SIZE          256 // Maximum size of the adapter name
#define ADAPTER_LIST_SIZE          32  // Maximum number of adapters in the list
#define ETHER_ADDR_LENGTH          6   // Length of the Ethernet address

#ifdef JUMBO_FRAME_SUPPORTED
#define MAX_ETHER_FRAME            9014 // Maximum size of the Ethernet frame when Jumbo Frames are supported
#else
#define MAX_ETHER_FRAME            1514 // Maximum size of the Ethernet frame when Jumbo Frames are not supported
#endif 

// Adapter flags
#define MSTCP_FLAG_SENT_TUNNEL     0x00000001 // Flag to receive packets sent by MSTCP
#define MSTCP_FLAG_RECV_TUNNEL     0x00000002 // Flag to receive packets instead of MSTCP
#define MSTCP_FLAG_SENT_LISTEN     0x00000004 // Flag to receive packets sent by MSTCP, original ones delivered to the network
#define MSTCP_FLAG_RECV_LISTEN     0x00000008 // Flag to receive packets received by MSTCP

#define MSTCP_FLAG_FILTER_DIRECT   0x00000010 // Flag to filter packets in promiscuous mode. 
                                              // In promiscuous mode, TCP/IP stack receives all packets in the ethernet segment. 
                                              // To prevent this, set this flag. 
                                              // All packets with destination MAC different from FF-FF-FF-FF-FF-FF and
                                              // network interface current MAC will be blocked

// By default, loopback packets are passed to original MSTCP handlers without processing.
// To change this behavior, use the flags below
#define MSTCP_FLAG_LOOPBACK_FILTER 0x00000020 // Flag to pass loopback packet for processing 
#define MSTCP_FLAG_LOOPBACK_BLOCK  0x00000040 // Flag to silently drop loopback packets. 
                                              // This flag is recommended for usage in combination with promiscuous mode

// Device flags for intermediate buffer
#define PACKET_FLAG_ON_SEND        0x00000001 // Flag to indicate packet is on send
#define PACKET_FLAG_ON_RECEIVE     0x00000002 // Flag to indicate packet is on receive

// Specify Structure Packing
#pragma pack(push,1)

/**
 * @brief TCP_AdapterList structure is used for requesting information about currently bound TCPIP adapters.
 *
 * @param m_nAdapterCount This field stores the number of adapters.
 * @param m_szAdapterNameList This is an array of adapter names. The size of the array is defined by the ADAPTER_LIST_SIZE constant,
 * and each name is a string of characters with a maximum length defined by the ADAPTER_NAME_SIZE constant.
 * @param m_nAdapterHandle This is an array of adapter handles. These handles are key for any adapter relative operation.
 * @param m_nAdapterMediumList This is a list of adapter mediums. Each medium is represented as an unsigned integer.
 * @param m_czCurrentAddress This is an array of current (configured) Ethernet addresses. Each address is represented as an array of bytes
 * with a length defined by the ETHER_ADDR_LENGTH constant.
 * @param m_usMTU This is an array of the current MTU (Maximum Transmission Unit) for each adapter. Each MTU is represented as an unsigned short.
 */
typedef struct _TCP_AdapterList
{
    DWORD           m_nAdapterCount;
    unsigned char   m_szAdapterNameList[ADAPTER_LIST_SIZE][ADAPTER_NAME_SIZE];
    HANDLE          m_nAdapterHandle[ADAPTER_LIST_SIZE];
    unsigned int    m_nAdapterMediumList[ADAPTER_LIST_SIZE];
    unsigned char   m_czCurrentAddress[ADAPTER_LIST_SIZE][ETHER_ADDR_LENGTH];
    unsigned short  m_usMTU[ADAPTER_LIST_SIZE];
} TCP_AdapterList, * PTCP_AdapterList;

/**
 * @brief TCP_AdapterList_WOW64 structure is similar to TCP_AdapterList, but it's used in a WOW64 environment.
 * WOW64 is a subsystem of the Windows operating system capable of running 32-bit applications and is included on all 64-bit versions of Windows.
 * In the TCP_AdapterList_WOW64 structure, the m_nAdapterHandle field is an array of ULARGE_INTEGER to accommodate the larger pointer size
 * in a 64-bit environment.
 *
 * @param m_nAdapterCount This field stores the number of adapters.
 * @param m_szAdapterNameList This is an array of adapter names. The size of the array is defined by the ADAPTER_LIST_SIZE constant,
 * and each name is a string of characters with a maximum length defined by the ADAPTER_NAME_SIZE constant.
 * @param m_nAdapterHandle This is an array of adapter handles. These handles are key for any adapter relative operation.
 * @param m_nAdapterMediumList This is a list of adapter mediums. Each medium is represented as an unsigned integer.
 * @param m_czCurrentAddress This is an array of current (configured) Ethernet addresses. Each address is represented as an array of bytes
 * with a length defined by the ETHER_ADDR_LENGTH constant.
 * @param m_usMTU This is an array of the current MTU (Maximum Transmission Unit) for each adapter. Each MTU is represented as an unsigned short.
 */
typedef struct _TCP_AdapterList_WOW64
{
    DWORD           m_nAdapterCount;
    unsigned char   m_szAdapterNameList[ADAPTER_LIST_SIZE][ADAPTER_NAME_SIZE];
    ULARGE_INTEGER  m_nAdapterHandle[ADAPTER_LIST_SIZE];
    unsigned int    m_nAdapterMediumList[ADAPTER_LIST_SIZE];
    unsigned char   m_czCurrentAddress[ADAPTER_LIST_SIZE][ETHER_ADDR_LENGTH];
    unsigned short  m_usMTU[ADAPTER_LIST_SIZE];
} TCP_AdapterList_WOW64, * PTCP_AdapterList_WOW64;

/**
 * @brief INTERMEDIATE_BUFFER structure is used for storing packet data and related information.
 *
 * @param m_hAdapter/m_qLink This is a union of two fields. m_hAdapter is a handle to the adapter. m_qLink is a link to the next packet in the queue.
 * @param m_dwDeviceFlags This field stores device-specific flags. These flags can be used to indicate whether the packet is on send or receive.
 * @param m_Length This field stores the length of the packet.
 * @param m_Flags This field stores NDIS_PACKET flags. These flags provide information about the packet, such as whether it's a loopback
 * packet or a broadcast packet.
 * @param m_8021q This field stores 802.1q information. 802.1q is a networking standard that supports virtual LANs (VLANs) on an Ethernet network.
 * @param m_FilterID This field stores the filter ID. This can be used to identify the filter that the packet passed through.
 * @param m_Reserved This field is reserved for future use.
 * @param m_IBuffer This field is a buffer that contains the packet data. The size of the buffer is defined by the MAX_ETHER_FRAME constant.
 */
typedef struct _INTERMEDIATE_BUFFER
{
    union {
        HANDLE          m_hAdapter;
        LIST_ENTRY      m_qLink;
    };
    DWORD               m_dwDeviceFlags;
    DWORD               m_Length;
    DWORD               m_Flags; // NDIS_PACKET flags
    DWORD               m_8021q; // 802.1q info
    DWORD               m_FilterID;
    DWORD               m_Reserved[4];
    UCHAR               m_IBuffer[MAX_ETHER_FRAME];
} INTERMEDIATE_BUFFER, * PINTERMEDIATE_BUFFER;

/**
 * @brief INTERMEDIATE_BUFFER_WOW64 structure is similar to INTERMEDIATE_BUFFER, but it's used in a WOW64 environment.
 * WOW64 is a subsystem of the Windows operating system capable of running 32-bit applications and is included on all 64-bit versions of Windows.
 * In the INTERMEDIATE_BUFFER_WOW64 structure, the m_hAdapter and m_qLink fields are arrays of two handles to accommodate the larger pointer
 * size in a 64-bit environment.
 *
 * @param m_hAdapter/m_qLink This is a union of two fields. m_hAdapter is a handle to the adapter. m_qLink is a link to the next packet in the queue.
 * @param m_dwDeviceFlags This field stores device-specific flags. These flags can be used to indicate whether the packet is on send or receive.
 * @param m_Length This field stores the length of the packet.
 * @param m_Flags This field stores NDIS_PACKET flags. These flags provide information about the packet, such as whether it's a loopback packet
 * or a broadcast packet.
 * @param m_8021q This field stores 802.1q information. 802.1q is a networking standard that supports virtual LANs (VLANs) on an Ethernet network.
 * @param m_FilterID This field stores the filter ID. This can be used to identify the filter that the packet passed through.
 * @param m_Reserved This field is reserved for future use.
 * @param m_IBuffer This field is a buffer that contains the packet data. The size of the buffer is defined by the MAX_ETHER_FRAME constant.
 */
typedef struct _INTERMEDIATE_BUFFER_WOW64
{
    union {
        HANDLE          m_hAdapter[2];
        LIST_ENTRY      m_qLink[2];
    };
    DWORD               m_dwDeviceFlags;
    DWORD               m_Length;
    DWORD               m_Flags; // NDIS_PACKET flags
    DWORD               m_8021q; // 802.1q tag
    DWORD               m_FilterID;
    DWORD               m_Reserved[4];
    UCHAR               m_IBuffer[MAX_ETHER_FRAME];
} INTERMEDIATE_BUFFER_WOW64, * PINTERMEDIATE_BUFFER_WOW64;

/**
 * @brief NDISRD_ETH_Packet structure is a container for INTERMEDIATE_BUFFER pointer.
 * This structure can be extended in future versions.
 *
 * @param Buffer This field is a pointer to an INTERMEDIATE_BUFFER structure that contains the packet data and related information.
 */
typedef struct _NDISRD_ETH_Packet
{
    PINTERMEDIATE_BUFFER Buffer;
} NDISRD_ETH_Packet, * PNDISRD_ETH_Packet;

/**
 * @brief NDISRD_ETH_Packet_WOW64 structure is similar to NDISRD_ETH_Packet, but it's used in a WOW64 environment.
 * WOW64 is a subsystem of the Windows operating system capable of running 32-bit applications and is included on all 64-bit versions of Windows.
 *
 * @param Buffer This field is a ULARGE_INTEGER that contains the address of an INTERMEDIATE_BUFFER structure that contains the packet data
 * and related information.
 */
typedef struct _NDISRD_ETH_Packet_WOW64
{
    ULARGE_INTEGER Buffer;
} NDISRD_ETH_Packet_WOW64, * PNDISRD_ETH_Packet_WOW64;

/**
 * @brief ETH_REQUEST structure is used for both reading a single packet from the driver and sending packets to the driver.
 *
 * @param hAdapterHandle This field is a handle to the adapter. It's used to identify the adapter that the packet is being read from or sent to.
 * @param EthPacket This field is an NDISRD_ETH_Packet structure that contains the packet data and related information. When reading, this
 * structure will be filled with the packet data retrieved from the driver. When sending, this structure should be filled with the packet data to be sent.
 */
typedef struct _ETH_REQUEST
{
    HANDLE hAdapterHandle;
    NDISRD_ETH_Packet EthPacket;
} ETH_REQUEST, * PETH_REQUEST;

/**
 * @brief ETH_REQUEST_WOW64 structure is similar to ETH_REQUEST, but it's used in a WOW64 environment.
 * WOW64 is a subsystem of the Windows operating system capable of running 32-bit applications and is included on all 64-bit versions of Windows.
 * In the ETH_REQUEST_WOW64 structure, the hAdapterHandle field is a ULARGE_INTEGER and the EthPacket field is an NDISRD_ETH_Packet_WOW64 structure
 * to accommodate the larger pointer size in a 64-bit environment.
 *
 * @param hAdapterHandle This field is a ULARGE_INTEGER that represents a handle to the adapter. It's used to identify the adapter that the packet
 * is being read from or sent to.
 * @param EthPacket This field is an NDISRD_ETH_Packet_WOW64 structure that contains the packet data and related information. When reading, this
 * structure will be filled with the packet data retrieved from the driver. When sending, this structure should be filled with the packet data to be sent.
 */
typedef struct _ETH_REQUEST_WOW64
{
    ULARGE_INTEGER hAdapterHandle;
    NDISRD_ETH_Packet_WOW64 EthPacket;
} ETH_REQUEST_WOW64, * PETH_REQUEST_WOW64;
/**
 * @brief ETH_M_REQUEST structure is used for both reading multiple packets from the driver and sending multiple packets to the driver.
 *
 * @param hAdapterHandle This field is a handle to the adapter. It's used to identify the adapter that the packets are being read from or sent to.
 * @param dwPacketsNumber This field stores the number of packets.
 * @param dwPacketsSuccess This field stores the number of successfully processed packets.
 * @param EthPacket This is an array of NDISRD_ETH_Packet structures that contain the packet data and related information. When reading, these
 * structures will be filled with the packet data retrieved from the driver. When sending, these structures should be filled with the packet data
 * to be sent.
 */
typedef struct _ETH_M_REQUEST
{
    HANDLE              hAdapterHandle;
    unsigned            dwPacketsNumber;
    unsigned            dwPacketsSuccess;
    NDISRD_ETH_Packet   EthPacket[ANY_SIZE];
} ETH_M_REQUEST, * PETH_M_REQUEST;

/**
 * @brief ETH_M_REQUEST_WOW64 structure is similar to ETH_M_REQUEST, but it's used in a WOW64 environment.
 * WOW64 is a subsystem of the Windows operating system capable of running 32-bit applications and is included on all 64-bit versions of Windows.
 * In the ETH_M_REQUEST_WOW64 structure, the hAdapterHandle field is a ULARGE_INTEGER and the EthPacket field is an array of NDISRD_ETH_Packet_WOW64
 * structures to accommodate the larger pointer size in a 64-bit environment.
 *
 * @param hAdapterHandle This field is a ULARGE_INTEGER that represents a handle to the adapter. It's used to identify the adapter that the packets
 * are being read from or sent to.
 * @param dwPacketsNumber This field stores the number of packets.
 * @param dwPacketsSuccess This field stores the number of successfully processed packets.
 * @param EthPacket This is an array of NDISRD_ETH_Packet_WOW64 structures that contain the packet data and related information. When reading,
 * these structures will be filled with the packet data retrieved from the driver. When sending, these structures should be filled with the packet
 * data to be sent.
 */
typedef struct _ETH_M_REQUEST_WOW64
{
    ULARGE_INTEGER          hAdapterHandle;
    unsigned                dwPacketsNumber;
    unsigned                dwPacketsSuccess;
    NDISRD_ETH_Packet_WOW64 EthPacket[ANY_SIZE];
} ETH_M_REQUEST_WOW64, * PETH_M_REQUEST_WOW64;

/**
 * @brief ADAPTER_MODE structure is used for setting the working mode of the network adapter.
 *
 * @param hAdapterHandle This field is a handle to the adapter. It's used to identify the adapter that the mode is being set for.
 * @param dwFlags This field stores the mode flags. These flags determine the working mode of the adapter. The flags can be a combination of
 * the following values: MSTCP_FLAG_SENT_TUNNEL, MSTCP_FLAG_RECV_TUNNEL, MSTCP_FLAG_SENT_LISTEN, MSTCP_FLAG_RECV_LISTEN, MSTCP_FLAG_FILTER_DIRECT,
 * MSTCP_FLAG_TUNNEL, MSTCP_FLAG_LISTEN, and MSTCP_FLAG_FILTER.
 */
typedef struct _ADAPTER_MODE
{
    HANDLE          hAdapterHandle;
    DWORD           dwFlags;
} ADAPTER_MODE, * PADAPTER_MODE;

/**
 * @brief ADAPTER_MODE_WOW64 structure is similar to ADAPTER_MODE, but it's used in a WOW64 environment.
 * WOW64 is a subsystem of the Windows operating system capable of running 32-bit applications and is included on all 64-bit versions of Windows.
 * In the ADAPTER_MODE_WOW64 structure, the hAdapterHandle field is a ULARGE_INTEGER to accommodate the larger pointer size in a 64-bit environment.
 *
 * @param hAdapterHandle This field is a ULARGE_INTEGER that represents a handle to the adapter. It's used to identify the adapter that the mode
 * is being set for.
 * @param dwFlags This field stores the mode flags. These flags determine the working mode of the adapter. The flags can be a combination of the
 * following values: MSTCP_FLAG_SENT_TUNNEL, MSTCP_FLAG_RECV_TUNNEL, MSTCP_FLAG_SENT_LISTEN, MSTCP_FLAG_RECV_LISTEN, MSTCP_FLAG_FILTER_DIRECT,
 * MSTCP_FLAG_TUNNEL, MSTCP_FLAG_LISTEN, and MSTCP_FLAG_FILTER.
 */
typedef struct _ADAPTER_MODE_WOW64
{
    ULARGE_INTEGER  hAdapterHandle;
    DWORD           dwFlags;
} ADAPTER_MODE_WOW64, * PADAPTER_MODE_WOW64;

/**
 * @brief ADAPTER_EVENT structure is used for setting up the event which driver sets once having packet in the queue for the processing.
 *
 * @param hAdapterHandle This field is a handle to the adapter. It's used to identify the adapter that the event is being set for.
 * @param hEvent This field is a handle to the event that will be signaled when a packet is received.
 */
typedef struct _ADAPTER_EVENT
{
    HANDLE  hAdapterHandle;
    HANDLE  hEvent;
} ADAPTER_EVENT, * PADAPTER_EVENT;

/**
 * @brief ADAPTER_EVENT_WOW64 structure is similar to ADAPTER_EVENT, but it's used in a WOW64 environment.
 * WOW64 is a subsystem of the Windows operating system capable of running 32-bit applications and is included on all 64-bit versions of Windows.
 * In the ADAPTER_EVENT_WOW64 structure, the hAdapterHandle and hEvent fields are ULARGE_INTEGER to accommodate the larger pointer size in a
 * 64-bit environment.
 *
 * @param hAdapterHandle This field is a ULARGE_INTEGER that represents a handle to the adapter. It's used to identify the adapter that the
 * event is being set for.
 * @param hEvent This field is a ULARGE_INTEGER that represents a handle to the event that will be signaled when a packet is received.
 */
typedef struct _ADAPTER_EVENT_WOW64
{
    ULARGE_INTEGER  hAdapterHandle;
    ULARGE_INTEGER  hEvent;
} ADAPTER_EVENT_WOW64, * PADAPTER_EVENT_WOW64;

/**
 * @brief PACKET_OID_DATA structure is used for making query or set requests on the underlying network adapter driver.
 *
 * @param hAdapterHandle This field is a handle to the adapter. It's used to identify the adapter that the request is being made on.
 * @param Oid This field stores the OID (Object Identifier) of the request. The OID is a code that identifies the network parameter that
 * is being queried or set.
 * @param Length This field stores the length of the data being queried or set.
 * @param Data This is an array of bytes that contains the data being queried or set. The size of the array is defined by the ANY_SIZE constant.
 */
typedef struct _PACKET_OID_DATA
{
    HANDLE      hAdapterHandle;
    DWORD       Oid;
    DWORD       Length;
    UCHAR       Data[ANY_SIZE];
} PACKET_OID_DATA, * PPACKET_OID_DATA;

/**
 * @brief PACKET_OID_DATA_WOW64 structure is similar to PACKET_OID_DATA, but it's used in a WOW64 environment.
 * WOW64 is a subsystem of the Windows operating system capable of running 32-bit applications and is included on all 64-bit versions of Windows.
 * In the PACKET_OID_DATA_WOW64 structure, the hAdapterHandle field is a ULARGE_INTEGER to accommodate the larger pointer size in a
 * 64-bit environment.
 *
 * @param hAdapterHandle This field is a ULARGE_INTEGER that represents a handle to the adapter. It's used to identify the adapter that
 * the request is being made on.
 * @param Oid This field stores the OID (Object Identifier) of the request. The OID is a code that identifies the network parameter that
 * is being queried or set.
 * @param Length This field stores the length of the data being queried or set.
 * @param Data This is an array of bytes that contains the data being queried or set. The size of the array is defined by the ANY_SIZE constant.
 */
typedef struct _PACKET_OID_DATA_WOW64
{
    ULARGE_INTEGER  hAdapterHandle;
    DWORD           Oid;
    DWORD           Length;
    UCHAR           Data[ANY_SIZE];
} PACKET_OID_DATA_WOW64, * PPACKET_OID_DATA_WOW64;


/**
 * @brief RAS_LINK_INFO structure is used to provide information about a RAS (Remote Access Service) link.
 *
 * @param LinkSpeed This field stores the link speed in units of 100 bps. Zero indicates no change from the speed returned when the protocol
 * called NdisRequest with OID_GEN_LINK_SPEED.
 * @param MaximumTotalSize This field stores the maximum number of bytes per packet that the protocol can send over the network. Zero indicates
 * no change from the value returned when the protocol called NdisRequest with OID_GEN_MAXIMUM_TOTAL_SIZE.
 * @param RemoteAddress This field stores the remote address for the link in Ethernet-style format. NDISWAN supplies this value.
 * @param LocalAddress This field stores the local address for the link in Ethernet-style format.
 * @param ProtocolBufferLength This field specifies the number of bytes in the buffer at ProtocolBuffer.
 * @param ProtocolBuffer This field is a buffer containing protocol-specific information supplied by a higher-level component that makes
 * connections through NDISWAN to the appropriate protocol(s). Maximum observed size is 600 bytes on Windows Vista, 1200 on Windows 10.
 */
typedef struct _RAS_LINK_INFO
{
#define RAS_LINK_BUFFER_LENGTH 2048
    DWORD  LinkSpeed;
    DWORD  MaximumTotalSize;
    UCHAR  RemoteAddress[ETHER_ADDR_LENGTH];
    UCHAR  LocalAddress[ETHER_ADDR_LENGTH];
    DWORD  ProtocolBufferLength;
    UCHAR  ProtocolBuffer[RAS_LINK_BUFFER_LENGTH];
} RAS_LINK_INFO, * PRAS_LINK_INFO;

/**
 * @brief RAS_LINKS structure is used to store an array of RAS_LINK_INFO structures.
 *
 * @param nNumberOfLinks This field stores the number of RAS_LINK_INFO structures in the RasLinks array.
 * @param RasLinks This is an array of RAS_LINK_INFO structures.
 */
typedef struct _RAS_LINKS
{
#define RAS_LINKS_MAX    256
    DWORD nNumberOfLinks;
    RAS_LINK_INFO RasLinks[RAS_LINKS_MAX];
} RAS_LINKS, * PRAS_LINKS;

/**********************************************************************************
                        Static packet filter definitions
***********************************************************************************/

/**
 * @brief ETH_802_3_FILTER structure is used to set the Ethernet 802.3 filter for the network adapter.
 *
 * @param m_ValidFields This field stores the valid fields flags. These flags determine which fields in the structure are valid. The flags
 * can be a combination of the following values: ETH_802_3_SRC_ADDRESS, ETH_802_3_DEST_ADDRESS, ETH_802_3_PROTOCOL.
 * @param m_SrcAddress This field stores the source address for the filter. It is an array of bytes representing the MAC address.
 * @param m_DestAddress This field stores the destination address for the filter. It is an array of bytes representing the MAC address.
 * @param m_Protocol This field stores the protocol for the filter. It is a 16-bit value representing the EtherType of the protocol.
 */
typedef struct _ETH_802_3_FILTER
{
#define ETH_802_3_SRC_ADDRESS    0x00000001
#define ETH_802_3_DEST_ADDRESS   0x00000002
#define ETH_802_3_PROTOCOL       0x00000004
    DWORD           m_ValidFields;                    // Specifies which of the fields below contain valid values and should be matched against the packet
    unsigned char   m_SrcAddress[ETHER_ADDR_LENGTH];  // Source MAC address
    unsigned char   m_DestAddress[ETHER_ADDR_LENGTH]; // Destination MAC address
    unsigned short  m_Protocol;                       // EtherType
    unsigned short  Padding;
} ETH_802_3_FILTER, * PETH_802_3_FILTER;

/**
 * @brief IP_SUBNET_V4 structure is used to represent an IPv4 subnet.
 *
 * @param m_Ip This field stores the IPv4 address expressed as an DWORD.
 * @param m_IpMask This field stores the IPv4 subnet mask expressed as an DWORD.
 */
typedef struct _IP_SUBNET_V4
{
    DWORD   m_Ip;       // IPv4 address expressed as DWORD
    DWORD   m_IpMask;   // IPv4 mask expressed as DWORD
} IP_SUBNET_V4, * PIP_SUBNET_V4;

/**
 * @brief IP_RANGE_V4 structure is used to represent a range of IPv4 addresses.
 *
 * @param m_StartIp This field stores the starting IPv4 address of the range expressed as an DWORD.
 * @param m_EndIp This field stores the ending IPv4 address of the range expressed as an DWORD.
 */
typedef struct _IP_RANGE_V4
{
    DWORD   m_StartIp;  // Start of IPv4 address range expressed as DWORD
    DWORD   m_EndIp;    // End of IPv4 address range expressed as DWORD
} IP_RANGE_V4, * PIP_RANGE_V4;

/**
 * @brief IP_ADDRESS_V4 structure is used to represent an IPv4 address which can be either a subnet or a range.
 *
 * @param m_AddressType This field specifies the type of the IPv4 address. It can be either IP_SUBNET_V4_TYPE or IP_RANGE_V4_TYPE.
 * @param m_IpSubnet This field is an IP_SUBNET_V4 structure that represents an IPv4 subnet.
 * @param m_IpRange This field is an IP_RANGE_V4 structure that represents a range of IPv4 addresses.
 */
typedef struct _IP_ADDRESS_V4
{
#define IP_SUBNET_V4_TYPE    0x00000001
#define IP_RANGE_V4_TYPE     0x00000002
    DWORD m_AddressType; // Specifies which of the IP v4 address types is used below
    union
    {
        IP_SUBNET_V4    m_IpSubnet;
        IP_RANGE_V4     m_IpRange;
    };
} IP_ADDRESS_V4, * PIP_ADDRESS_V4;

/**
 * @brief IP_V4_FILTER structure is used to set the IPv4 filter for the network adapter.
 *
 * @param m_ValidFields This field stores the valid fields flags. These flags determine which fields in the structure are valid. The flags
 * can be a combination of the following values: IP_V4_FILTER_SRC_ADDRESS, IP_V4_FILTER_DEST_ADDRESS, IP_V4_FILTER_PROTOCOL.
 * @param m_SrcAddress This field is an IP_ADDRESS_V4 structure that stores the source address for the filter.
 * @param m_DestAddress This field is an IP_ADDRESS_V4 structure that stores the destination address for the filter.
 * @param m_Protocol This field stores the protocol for the filter. It is an unsigned char representing the protocol number.
 */
typedef struct _IP_V4_FILTER
{
#define IP_V4_FILTER_SRC_ADDRESS    0x00000001
#define IP_V4_FILTER_DEST_ADDRESS   0x00000002
#define IP_V4_FILTER_PROTOCOL       0x00000004
    DWORD           m_ValidFields;   // Specifies which of the fields below contain valid values and should be matched against the packet
    IP_ADDRESS_V4   m_SrcAddress;    // IP v4 source address
    IP_ADDRESS_V4   m_DestAddress;   // IP v4 destination address
    unsigned char   m_Protocol;      // Specifies next protocol
    unsigned char   Padding[3];
} IP_V4_FILTER, * PIP_V4_FILTER;

/**
 * @brief IP_SUBNET_V6 structure is used to represent an IPv6 subnet.
 *
 * @param m_Ip This field stores the IPv6 address expressed as an IN6_ADDR structure.
 * @param m_IpMask This field stores the IPv6 subnet mask expressed as an IN6_ADDR structure.
 */
typedef struct _IP_SUBNET_V6
{
    IN6_ADDR        m_Ip;       // IPv6 address
    IN6_ADDR        m_IpMask;   // IPv6 mask
} IP_SUBNET_V6, * PIP_SUBNET_V6;

/**
 * @brief IP_RANGE_V6 structure is used to represent a range of IPv6 addresses.
 *
 * @param m_StartIp This field stores the starting IPv6 address of the range expressed as an IN6_ADDR structure.
 * @param m_EndIp This field stores the ending IPv6 address of the range expressed as an IN6_ADDR structure.
 */
typedef struct _IP_RANGE_V6
{
    IN6_ADDR        m_StartIp;  // Start of IPv6 address range
    IN6_ADDR        m_EndIp;    // End of IPv6 address range
} IP_RANGE_V6, * PIP_RANGE_V6;

/**
 * @brief IP_ADDRESS_V6 structure is used to represent an IPv6 address which can be either a subnet or a range.
 *
 * @param m_AddressType This field specifies the type of the IPv6 address. It can be either IP_SUBNET_V6_TYPE or IP_RANGE_V6_TYPE.
 * @param m_IpSubnet This field is an IP_SUBNET_V6 structure that represents an IPv6 subnet.
 * @param m_IpRange This field is an IP_RANGE_V6 structure that represents a range of IPv6 addresses.
 */
typedef struct _IP_ADDRESS_V6
{
#define IP_SUBNET_V6_TYPE    0x00000001
#define IP_RANGE_V6_TYPE     0x00000002
    DWORD   m_AddressType; // Specifies which of the IP v6 address types is used below
    union
    {
        IP_SUBNET_V6    m_IpSubnet;
        IP_RANGE_V6     m_IpRange;
    };
} IP_ADDRESS_V6, * PIP_ADDRESS_V6;

/**
 * @brief IP_V6_FILTER structure is used to set the IPv6 filter for the network adapter.
 *
 * @param m_ValidFields This field stores the valid fields flags. These flags determine which fields in the structure are valid. The flags
 * can be a combination of the following values: IP_V6_FILTER_SRC_ADDRESS, IP_V6_FILTER_DEST_ADDRESS, IP_V6_FILTER_PROTOCOL.
 * @param m_SrcAddress This field is an IP_ADDRESS_V6 structure that stores the source address for the filter.
 * @param m_DestAddress This field is an IP_ADDRESS_V6 structure that stores the destination address for the filter.
 * @param m_Protocol This field stores the protocol for the filter. It is an unsigned char representing the protocol number.
 */
typedef struct _IP_V6_FILTER
{
#define IP_V6_FILTER_SRC_ADDRESS    0x00000001
#define IP_V6_FILTER_DEST_ADDRESS   0x00000002
#define IP_V6_FILTER_PROTOCOL       0x00000004
    DWORD           m_ValidFields;   // Specifies which of the fields below contain valid values and should be matched against the packet
    IP_ADDRESS_V6   m_SrcAddress;    // IP v6 source address
    IP_ADDRESS_V6   m_DestAddress;   // IP v6 destination address
    unsigned char   m_Protocol;      // Specifies next protocol
    unsigned char   Padding[3];
} IP_V6_FILTER, * PIP_V6_FILTER;

/**
 * @brief PORT_RANGE structure is used to represent a range of ports.
 *
 * @param m_StartRange This field stores the starting port of the range. It is an unsigned short. The port is specified in host byte order.
 * @param m_EndRange This field stores the ending port of the range. It is also an unsigned short. The port is specified in host byte order.
 */
typedef struct _PORT_RANGE
{
    unsigned short  m_StartRange;  // Starting port of the range in host byte order
    unsigned short  m_EndRange;    // Ending port of the range in host byte order
} PORT_RANGE, * PPORT_RANGE;

/**
 * @brief TCPUDP_FILTER structure is used to set the TCP/UDP filter for the network adapter.
 *
 * @param m_ValidFields This field stores the valid fields flags. These flags determine which fields in the structure are valid. The flags
 * can be a combination of the following values: TCPUDP_SRC_PORT, TCPUDP_DEST_PORT, TCPUDP_TCP_FLAGS.
 * @param m_SourcePort This field is a PORT_RANGE structure that stores the source port range for the filter.
 * @param m_DestPort This field is a PORT_RANGE structure that stores the destination port range for the filter.
 * @param m_TCPFlags This field stores the TCP flags for the filter. It is an unsigned char representing the TCP flags combination.
 */
typedef struct _TCPUDP_FILTER
{
#define TCPUDP_SRC_PORT   0x00000001
#define TCPUDP_DEST_PORT  0x00000002
#define TCPUDP_TCP_FLAGS  0x00000004
    DWORD           m_ValidFields;  // Specifies which of the fields below contain valid values and should be matched against the packet
    PORT_RANGE      m_SourcePort;   // Source port
    PORT_RANGE      m_DestPort;     // Destination port
    unsigned char   m_TCPFlags;     // TCP flags combination
    unsigned char   Padding[3];
} TCPUDP_FILTER, * PTCPUDP_FILTER;

/**
 * @brief BYTE_RANGE structure is used to represent a range of bytes.
 *
 * @param m_StartRange This field stores the starting byte of the range. It is an unsigned char.
 * @param m_EndRange This field stores the ending byte of the range. It is also an unsigned char.
 */
typedef struct _BYTE_RANGE
{
    unsigned char m_StartRange;  // Starting byte of the range
    unsigned char m_EndRange;    // Ending byte of the range
} BYTE_RANGE, * PBYTE_RANGE;

/**
 * @brief ICMP_FILTER structure is used to set the ICMP filter for the network adapter.
 *
 * @param m_ValidFields This field stores the valid fields flags. These flags determine which fields in the structure are valid. The flags
 * can be a combination of the following values: ICMP_TYPE, ICMP_CODE.
 * @param m_TypeRange This field is a BYTE_RANGE structure that stores the ICMP Type range for the filter.
 * @param m_CodeRange This field is a BYTE_RANGE structure that stores the ICMP Code range for the filter.
 */
typedef struct _ICMP_FILTER
{
#define ICMP_TYPE        0x00000001
#define ICMP_CODE        0x00000002
    DWORD           m_ValidFields;  // Specifies which of the fields below contain valid values and should be matched against the packet
    BYTE_RANGE      m_TypeRange;    // ICMP Type range
    BYTE_RANGE      m_CodeRange;    // ICMP Code range
} ICMP_FILTER, * PICMP_FILTER;

/**
 * @brief DATA_LINK_LAYER_FILTER structure is used to set the data link layer filter for the network adapter.
 *
 * @param m_dwUnionSelector This field stores the valid fields flags. These flags determine which fields in the structure are valid. The flags
 * can be a combination of the following values: ETH_802_3.
 * @param m_Eth8023Filter This field is an ETH_802_3_FILTER structure that stores the Ethernet 802.3 filter.
 */
typedef struct _DATA_LINK_LAYER_FILTER
{
#define ETH_802_3    0x00000001
    DWORD    m_dwUnionSelector; // Specifies which of the fields below contain valid values and should be matched against the packet
    union
    {
        ETH_802_3_FILTER   m_Eth8023Filter; // Ethernet 802.3 filter
    };
} DATA_LINK_LAYER_FILTER, * PDATA_LINK_LAYER_FILTER;

/**
 * @brief NETWORK_LAYER_FILTER structure is used to set the network layer filter for the network adapter.
 *
 * @param m_dwUnionSelector This field stores the valid fields flags. These flags determine which fields in the structure are valid. The flags
 * can be a combination of the following values: IPV4, IPV6.
 * @param m_IPv4 This field is an IP_V4_FILTER structure that stores the IPv4 filter.
 * @param m_IPv6 This field is an IP_V6_FILTER structure that stores the IPv6 filter.
 */
typedef struct _NETWORK_LAYER_FILTER
{
#define IPV4    0x00000001
#define IPV6    0x00000002
    DWORD    m_dwUnionSelector; // Specifies which of the fields below contain valid values and should be matched against the packet
    union
    {
        IP_V4_FILTER   m_IPv4; // IPv4 filter
        IP_V6_FILTER   m_IPv6; // IPv6 filter
    };
} NETWORK_LAYER_FILTER, * PNETWORK_LAYER_FILTER;

/**
 * @brief TRANSPORT_LAYER_FILTER structure is used to set the transport layer filter for the network adapter.
 *
 * @param m_dwUnionSelector This field stores the valid fields flags. These flags determine which fields in the structure are valid. The flags
 * can be a combination of the following values: TCPUDP, ICMP.
 * @param m_TcpUdp This field is a TCPUDP_FILTER structure that stores the TCP/UDP filter.
 * @param m_Icmp This field is an ICMP_FILTER structure that stores the ICMP filter.
 */
typedef struct _TRANSPORT_LAYER_FILTER
{
#define TCPUDP  0x00000001
#define ICMP    0x00000002
    DWORD    m_dwUnionSelector; // Specifies which of the fields below contain valid values and should be matched against the packet
    union
    {
        TCPUDP_FILTER    m_TcpUdp; // TCP/UDP filter
        ICMP_FILTER      m_Icmp;   // ICMP filter
    };
} TRANSPORT_LAYER_FILTER, * PTRANSPORT_LAYER_FILTER;

/**
 * @brief STATIC_FILTER structure is used to define a static filter for the network adapter.
 *
 * @param m_Adapter This field is a handle to the adapter. It's used to identify the adapter that the filter is associated with.
 * @param m_dwDirectionFlags This field stores direction flags. These flags can be used to indicate whether the filter applies to sent packets,
 * received packets, or both.
 * @param m_FilterAction This field specifies the action to be taken when the filter conditions are met. It can be one of the following values:
 * FILTER_PACKET_PASS, FILTER_PACKET_DROP, FILTER_PACKET_REDIRECT, FILTER_PACKET_PASS_RDR, FILTER_PACKET_DROP_RDR.
 * @param m_ValidFields This field stores the valid fields flags. These flags determine which fields in the structure are valid. The flags can
 * be a combination of the following values: DATA_LINK_LAYER_VALID, NETWORK_LAYER_VALID, TRANSPORT_LAYER_VALID.
 * @param m_LastReset This field stores the time of the last counters reset in seconds passed since 1 Jan 1980.
 * @param m_PacketsIn This field stores the number of incoming packets that passed through this filter.
 * @param m_BytesIn This field stores the number of incoming bytes that passed through this filter.
 * @param m_PacketsOut This field stores the number of outgoing packets that passed through this filter.
 * @param m_BytesOut This field stores the number of outgoing bytes that passed through this filter.
 * @param m_DataLinkFilter This field is a DATA_LINK_LAYER_FILTER structure that stores the data link layer filter.
 * @param m_NetworkFilter This field is a NETWORK_LAYER_FILTER structure that stores the network layer filter.
 * @param m_TransportFilter This field is a TRANSPORT_LAYER_FILTER structure that stores the transport layer filter.
 */
typedef struct _STATIC_FILTER
{
#define FILTER_PACKET_PASS      0x00000001 // Pass packet if it matches the filter
#define FILTER_PACKET_DROP      0x00000002 // Drop packet if it matches the filter
#define FILTER_PACKET_REDIRECT  0x00000003 // Redirect packet to WinpkFilter client application
#define FILTER_PACKET_PASS_RDR  0x00000004 // Redirect packet to WinpkFilter client application and pass over network (listen mode)
#define FILTER_PACKET_DROP_RDR  0x00000005 // Redirect packet to WinpkFilter client application and drop it, e.g. log but remove from the flow (listen mode)

#define DATA_LINK_LAYER_VALID   0x00000001 // Match packet against data link layer filter
#define NETWORK_LAYER_VALID     0x00000002 // Match packet against network layer filter
#define TRANSPORT_LAYER_VALID   0x00000004 // Match packet against transport layer filter

    ULARGE_INTEGER   m_Adapter; // Adapter handle extended to 64 bit size for structure compatibility across x64 and x86
    DWORD            m_dwDirectionFlags; // PACKET_FLAG_ON_SEND or/and PACKET_FLAG_ON_RECEIVE
    DWORD            m_FilterAction; // FILTER_PACKET_XXX
    DWORD            m_ValidFields; // Specifies which of the fields below contain valid values and should be matched against the packet

    // Statistics for the filter
    DWORD            m_LastReset; // Time of the last counters reset (in seconds passed since 1 Jan 1980)
    ULARGE_INTEGER   m_PacketsIn; // Incoming packets passed through this filter
    ULARGE_INTEGER   m_BytesIn; // Incoming bytes passed through this filter
    ULARGE_INTEGER   m_PacketsOut; // Outgoing packets passed through this filter
    ULARGE_INTEGER   m_BytesOut; // Outgoing bytes passed through this filter

    DATA_LINK_LAYER_FILTER   m_DataLinkFilter;
    NETWORK_LAYER_FILTER     m_NetworkFilter;
    TRANSPORT_LAYER_FILTER   m_TransportFilter;
} STATIC_FILTER, * PSTATIC_FILTER;

/**
 * @brief Defines a table of static filters to be applied on network traffic.
 *
 * This structure is used to hold a collection of static filters that determine how network packets are processed.
 * Each filter in the table can specify actions like pass, drop, or redirect packets based on various criteria such as
 * source and destination IP addresses, port numbers, and protocol types. The table size is dynamic, allowing for
 * a variable number of filters to be defined based on the needs of the application.
 *
 * @param m_TableSize The number of STATIC_FILTER entries in the table. This determines the number of filters
 *                    currently defined and active for processing network packets.
 * @param Padding     Reserved for future use, ensuring proper alignment of the structure in memory.
 * @param m_StaticFilters An array of STATIC_FILTER structures, each defining a specific filter with its own
 *                        set of criteria and actions. The size of this array is determined by m_TableSize.
 */
typedef struct _STATIC_FILTER_TABLE
{
    DWORD          m_TableSize; // number of STATIC_FILTER entries
    DWORD          Padding;
    STATIC_FILTER  m_StaticFilters[ANY_SIZE];
} STATIC_FILTER_TABLE, * PSTATIC_FILTER_TABLE;

/**
 * @brief Structure to define a static filter with a specific insertion position.
 *
 * This structure combines a STATIC_FILTER with a position value to specify where in the filter list the static filter should be inserted.
 * The position determines the order of filter application, with lower values indicating higher priority. This allows for precise control
 * over the packet filtering process, enabling the insertion of filters at specific points in the filter chain.
 *
 * @param m_Position The position in the filter list where the new filter should be inserted. Filters are processed in ascending order based
 * on this value.
 * @param m_StaticFilter The STATIC_FILTER structure that defines the filter criteria and actions. This includes details such as the direction
 * of traffic to filter, the protocol to filter, and the action to take when a packet matches the filter criteria.
 */
typedef struct _STATIC_FILTER_WITH_POSITION
{
    unsigned long   m_Position; // position to insert new filter
    STATIC_FILTER   m_StaticFilter;
} STATIC_FILTER_WITH_POSITION, * PSTATIC_FILTER_WITH_POSITION;

/**********************************************************************************
                        Fast I/O structures definitions
***********************************************************************************/

/**
 * @brief FAST_IO_WRITE_UNION structure is used to store the number of packets and the write-in-progress flag in a union.
 *
 * @param union_ This is a union of two fields. The split field is a structure that contains the number_of_packets and write_in_progress_flag fields.
 * The join field is an DWORD that can store the combined value of the two fields in the split structure.
 */
typedef struct _FAST_IO_WRITE_UNION {
    union {
        struct {
            USHORT number_of_packets;
            USHORT write_in_progress_flag;
        } split;
        DWORD join;
    } union_;
}FAST_IO_WRITE_UNION, * PFAST_IO_WRITE_UNION;

/**
 * @brief FAST_IO_SECTION_HEADER structure is used to store the fast I/O write union and the read in progress flag.
 *
 * @param fast_io_write_union This field is a FAST_IO_WRITE_UNION structure that stores the number of packets and the write-in-progress flag.
 * @param read_in_progress_flag This field is an DWORD that stores the read in progress flag.
 */
typedef struct _FAST_IO_SECTION_HEADER {
    FAST_IO_WRITE_UNION fast_io_write_union;
    DWORD               read_in_progress_flag;
} FAST_IO_SECTION_HEADER, * PFAST_IO_SECTION_HEADER;

/**
 * @brief FAST_IO_SECTION structure is used to store the fast I/O section header and the fast I/O packets.
 *
 * @param fast_io_header This field is a volatile FAST_IO_SECTION_HEADER structure that stores the fast I/O write union and the
 * read-in-progress flag.
 * @param fast_io_packets This field is an array of INTERMEDIATE_BUFFER structures that store the fast I/O packets. The size of the array
 * is defined by the ANY_SIZE constant.
 */
typedef struct _FAST_IO_SECTION
{
    volatile FAST_IO_SECTION_HEADER fast_io_header;
    INTERMEDIATE_BUFFER            fast_io_packets[ANY_SIZE];
} FAST_IO_SECTION, * PFAST_IO_SECTION;

/**
 * @brief INITIALIZE_FAST_IO_PARAMS structure is used to store the header pointer and the data size for initializing fast I/O.
 *
 * @param header_ptr This field is a pointer to a FAST_IO_SECTION structure that stores the fast I/O section header and the fast I/O packets.
 * @param data_size This field is an DWORD that stores the data size.
 */
typedef struct _INITIALIZE_FAST_IO_PARAMS
{
    PFAST_IO_SECTION header_ptr;
    DWORD            data_size;
}INITIALIZE_FAST_IO_PARAMS, * PINITIALIZE_FAST_IO_PARAMS;

/**********************************************************************************
                            Unsorted Read/Send packets
***********************************************************************************/

/**
 * @brief UNSORTED_READ_SEND_REQUEST structure is used for storing an array of packets for reading or sending.
 *
 * @param packets This field is a pointer to an array of PINTERMEDIATE_BUFFER structures. Each PINTERMEDIATE_BUFFER structure contains the
 * packet data and related information.
 * @param packets_num This field stores the number of packets in the array.
 */
typedef struct _UNSORTED_READ_SEND_REQUEST
{
    PINTERMEDIATE_BUFFER* packets;
    DWORD                 packets_num;
} UNSORTED_READ_SEND_REQUEST, * PUNSORTED_READ_SEND_REQUEST;

// Restore Default Structure Packing
#pragma pack(pop)

/**********************************************************************************
                 IOCTL Codes For NDIS Packet Redirector Driver
***********************************************************************************/

#define FILE_DEVICE_NDISRD  0x00008300
#define NDISRD_IOCTL_INDEX  0x830

#define IOCTL_NDISRD_GET_VERSION\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_GET_TCPIP_INTERFACES\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+1, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_SEND_PACKET_TO_MSTCP\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+3, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_READ_PACKET\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+4, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_SET_ADAPTER_MODE\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+5, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+6, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_SET_EVENT\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+7, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_NDIS_SET_REQUEST\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+8, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_NDIS_GET_REQUEST\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+9, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_SET_WAN_EVENT\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+10, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_SET_ADAPTER_EVENT\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+11, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_ADAPTER_QUEUE_SIZE\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+12, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_GET_ADAPTER_MODE\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+13, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_SET_PACKET_FILTERS\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+14, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_RESET_PACKET_FILTERS\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+15, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+16, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_GET_PACKET_FILTERS\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+17, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+18, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_GET_RAS_LINKS\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+19, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+20, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+21, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_READ_PACKETS\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+22, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+23, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_INITIALIZE_FAST_IO\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+24, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_READ_PACKETS_UNSORTED\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+25, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+26, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+27, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_ADD_SECOND_FAST_IO_SECTION\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+28, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_QUERY_IB_POOL_SIZE\
   CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+29, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_ADD_PACKET_FILTER_FRONT\
    CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+30, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_ADD_PACKET_FILTER_BACK\
    CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+31, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_REMOVE_FILTER_BY_INDEX\
    CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+32, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_GET_ADP_FILTERS_LIST\
    CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+33, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_INSERT_FILTER_BY_INDEX\
    CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+34, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_SET_FILTER_CACHE_STATE\
    CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+35, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDISRD_SET_FRAGMENT_CACHE_STATE\
    CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+36, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif // COMMON_H