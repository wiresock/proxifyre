/*************************************************************************/
/*                Copyright (c) 2000-2023 NT Kernel Resources.           */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  common.h                                                */
/*                                                                       */
/* Abstract: Definitions common to kernel-mode driver and Win32 app.     */
/*                                                                       */
/* Environment:                                                          */
/*   User mode, Kernel mode                                              */
/*                                                                       */
/*************************************************************************/

#ifndef __COMMON_H__
#define __COMMON_H__

#ifdef _WINDOWS
#include <WinIoctl.h>   // Compiling Win32 Applications Or DLL's
#endif // _WINDOWS

#define NDISRD_VERSION			0x04033000
#define NDISRD_MAJOR_VERSION	0x0003
#define NDISRD_MINOR_VERSION	0x0403

// Common strings set
#define DRIVER_NAME_A "NDISRD"
#define DRIVER_NAME_U L"NDISRD"
#define DEVICE_NAME L"\\Device\\NDISRD"
#define SYMLINK_NAME L"\\DosDevices\\NDISRD"
#define WIN9X_REG_PARAM	"System\\CurrentControlSet\\Services\\VxD\\ndisrd\\Parameters"
#define WINNT_REG_PARAM TEXT("SYSTEM\\CurrentControlSet\\Services\\ndisrd\\Parameters")

#define FILTER_FRIENDLY_NAME        L"WinpkFilter NDIS LightWeight Filter"
#define FILTER_UNIQUE_NAME          L"{CD75C963-E19F-4139-BC3B-14019EF72F19}" //unique name, quid name
#define FILTER_SERVICE_NAME         L"NDISRD"

// Some size constants
#define ADAPTER_NAME_SIZE	256
#define ADAPTER_LIST_SIZE	32
#define ETHER_ADDR_LENGTH	6
#ifdef JUMBO_FRAME_SUPPORTED
#define	MAX_ETHER_FRAME		9014 
#else
#define	MAX_ETHER_FRAME		1514
#endif

// Adapter flags
#define MSTCP_FLAG_SENT_TUNNEL		0x00000001	// Receive packets sent by MSTCP
#define MSTCP_FLAG_RECV_TUNNEL		0x00000002	// Receive packets instead MSTCP
#define MSTCP_FLAG_SENT_LISTEN		0x00000004	// Receive packets sent by MSTCP, original ones delivered to the network
#define MSTCP_FLAG_RECV_LISTEN		0x00000008	// Receive packets received by MSTCP

#define MSTCP_FLAG_FILTER_DIRECT	0x00000010	// In promiscuous mode TCP/IP stack receives all
// all packets in the ethernet segment, to prevent this set this flag
// All packets with destination MAC different from FF-FF-FF-FF-FF-FF and
// network interface current MAC will be blocked

// By default loopback packets are passed to original MSTCP handlers without processing,
// to change this behavior use the flags below
#define MSTCP_FLAG_LOOPBACK_FILTER	0x00000020  // Pass loopback packet for processing 
#define MSTCP_FLAG_LOOPBACK_BLOCK	0x00000040  // Silently drop loopback packets, this flag
// is recommended for usage in combination with 
// promiscuous mode

// Device flags for intermediate buffer
#define PACKET_FLAG_ON_SEND		0x00000001
#define PACKET_FLAG_ON_RECEIVE	0x00000002

// Specify Structure Packing
#pragma pack(push,1)

/* Specify here packed structures for data exchange with driver */
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
//
// TCP_AdapterList structure used for requesting information about currently bound TCPIP adapters
//
typedef
	struct _TCP_AdapterList
{
	unsigned long m_nAdapterCount; // Number of adapters
	unsigned char m_szAdapterNameList[ADAPTER_LIST_SIZE][ADAPTER_NAME_SIZE]; // Array of adapter names
	HANDLE m_nAdapterHandle[ADAPTER_LIST_SIZE];
	// Array of adapter handles, this are key handles for any adapter relative operation 
	unsigned int m_nAdapterMediumList[ADAPTER_LIST_SIZE]; // List of adapter mediums
	unsigned char m_czCurrentAddress[ADAPTER_LIST_SIZE][ETHER_ADDR_LENGTH]; // current (configured) ethernet address
	unsigned short m_usMTU[ADAPTER_LIST_SIZE]; // current adapter MTU
} TCP_AdapterList, *PTCP_AdapterList;

typedef
	struct _TCP_AdapterList_WOW64
{
	unsigned long m_nAdapterCount; // Number of adapters
	unsigned char m_szAdapterNameList[ADAPTER_LIST_SIZE][ADAPTER_NAME_SIZE]; // Array of adapter names
	ULARGE_INTEGER m_nAdapterHandle[ADAPTER_LIST_SIZE];
	// Array of adapter handles, this are key handles for any adapter relative operation 
	unsigned int m_nAdapterMediumList[ADAPTER_LIST_SIZE]; // List of adapter mediums
	unsigned char m_czCurrentAddress[ADAPTER_LIST_SIZE][ETHER_ADDR_LENGTH]; // current (configured) ethernet address
	unsigned short m_usMTU[ADAPTER_LIST_SIZE]; // current adapter MTU
} TCP_AdapterList_WOW64, *PTCP_AdapterList_WOW64;

//
// INTERMEDIATE_BUFFER contains packet buffer, packet NDIS flags, WinpkFilter specific flags
//
typedef
	struct _INTERMEDIATE_BUFFER
{
	union
	{
		HANDLE m_hAdapter;
		LIST_ENTRY m_qLink;
	};

	ULONG m_dwDeviceFlags;
	ULONG m_Length;
	ULONG m_Flags; // NDIS_PACKET flags
	ULONG m_8021q; // 802.1q info
	ULONG m_FilterID;
	ULONG m_Reserved[4];
	UCHAR m_IBuffer[MAX_ETHER_FRAME];
} INTERMEDIATE_BUFFER, *PINTERMEDIATE_BUFFER;

typedef
	struct _INTERMEDIATE_BUFFER_WOW64
{
	union
	{
		HANDLE m_hAdapter[2];
		LIST_ENTRY m_qLink[2];
	};

	ULONG m_dwDeviceFlags;
	ULONG m_Length;
	ULONG m_Flags; // NDIS_PACKET flags
	ULONG m_8021q; // 802.1q tag
	ULONG m_FilterID;
	ULONG m_Reserved[4];
	UCHAR m_IBuffer[MAX_ETHER_FRAME];
} INTERMEDIATE_BUFFER_WOW64, *PINTERMEDIATE_BUFFER_WOW64;

//
// NDISRD_ETH_Packet is a container for INTERMEDIATE_BUFFER pointer
// This structure can be extended in the future versions
//
typedef
	struct _NDISRD_ETH_Packet
{
	PINTERMEDIATE_BUFFER Buffer;
}
	NDISRD_ETH_Packet, *PNDISRD_ETH_Packet;

typedef
	struct _NDISRD_ETH_Packet_WOW64
{
	ULARGE_INTEGER Buffer;
}
	NDISRD_ETH_Packet_WOW64, *PNDISRD_ETH_Packet_WOW64;

//
// ETH_REQUEST used for passing the "read packet" request to driver
//
typedef
	struct _ETH_REQUEST
{
	HANDLE hAdapterHandle;
	NDISRD_ETH_Packet EthPacket;
}
	ETH_REQUEST, *PETH_REQUEST;

typedef
	struct _ETH_REQUEST_WOW64
{
	ULARGE_INTEGER hAdapterHandle;
	NDISRD_ETH_Packet_WOW64 EthPacket;
}
	ETH_REQUEST_WOW64, *PETH_REQUEST_WOW64;

//
// ETH_M_REQUEST used for passing the "read packet" request to driver
//

#ifndef ANY_SIZE
#define ANY_SIZE 1
#endif

typedef
	struct _ETH_M_REQUEST
{
	HANDLE hAdapterHandle;
	unsigned dwPacketsNumber;
	unsigned dwPacketsSuccess;
	NDISRD_ETH_Packet EthPacket[ANY_SIZE];
}
	ETH_M_REQUEST, *PETH_M_REQUEST;

typedef
	struct _ETH_M_REQUEST_WOW64
{
	ULARGE_INTEGER hAdapterHandle;
	unsigned dwPacketsNumber;
	unsigned dwPacketsSuccess;
	NDISRD_ETH_Packet_WOW64 EthPacket[ANY_SIZE];
}
	ETH_M_REQUEST_WOW64, *PETH_M_REQUEST_WOW64;

//
// ADAPTER_MODE used for setting adapter mode
//
typedef
	struct _ADAPTER_MODE
{
	HANDLE hAdapterHandle;
	unsigned long dwFlags;
}
	ADAPTER_MODE, *PADAPTER_MODE;

typedef
	struct _ADAPTER_MODE_WOW64
{
	ULARGE_INTEGER hAdapterHandle;
	unsigned long dwFlags;
}
	ADAPTER_MODE_WOW64, *PADAPTER_MODE_WOW64;

//
// ADAPTER_EVENT used for setting up the event which driver sets once having packet in the queue for the processing
//
typedef
	struct _ADAPTER_EVENT
{
	HANDLE hAdapterHandle;
	HANDLE hEvent;
} ADAPTER_EVENT, *PADAPTER_EVENT;

typedef
	struct _ADAPTER_EVENT_WOW64
{
	ULARGE_INTEGER hAdapterHandle;
	ULARGE_INTEGER hEvent;
} ADAPTER_EVENT_WOW64, *PADAPTER_EVENT_WOW64;

//
// PACKET_OID_DATA used for passing NDIS_REQUEST to driver
//
typedef
	struct _PACKET_OID_DATA
{
	HANDLE hAdapterHandle;
	ULONG Oid;
	ULONG Length;
	UCHAR Data[1];
} PACKET_OID_DATA, *PPACKET_OID_DATA;

typedef
	struct _PACKET_OID_DATA_WOW64
{
	ULARGE_INTEGER hAdapterHandle;
	ULONG Oid;
	ULONG Length;
	UCHAR Data[1];
} PACKET_OID_DATA_WOW64, *PPACKET_OID_DATA_WOW64;

typedef
	struct _RAS_LINK_INFO
{
#define RAS_LINK_BUFFER_LENGTH 2048
	ULONG LinkSpeed; // Specifies the speed of the link, in units of 100 bps.
	// Zero indicates no change from the speed returned when the protocol called NdisRequest with OID_GEN_LINK_SPEED. 
	ULONG MaximumTotalSize;
	// Specifies the maximum number of bytes per packet that the protocol can send over the network.
	// Zero indicates no change from the value returned when the protocol called NdisRequest with OID_GEN_MAXIMUM_TOTAL_SIZE. 
	UCHAR RemoteAddress[ETHER_ADDR_LENGTH];
	// Represents the address of the remote node on the link in Ethernet-style format. NDISWAN supplies this value.
	UCHAR LocalAddress[ETHER_ADDR_LENGTH];
	// Represents the protocol-determined context for indications on this link in Ethernet-style format.
	ULONG ProtocolBufferLength; // Specifies the number of bytes in the buffer at ProtocolBuffer
	UCHAR ProtocolBuffer[RAS_LINK_BUFFER_LENGTH];
	// Containing protocol-specific information supplied by a higher-level component that makes connections through NDISWAN
	// to the appropriate protocol(s). Maximum observed size is 600 bytes on Windows Vista, 1200 on Windows 10
} RAS_LINK_INFO, *PRAS_LINK_INFO;

typedef
	struct _RAS_LINKS
{
#define RAS_LINKS_MAX	256
	ULONG nNumberOfLinks;
	RAS_LINK_INFO RasLinks[RAS_LINKS_MAX];
} RAS_LINKS, *PRAS_LINKS;

//
// Packet filter definitions
//

//
// Ethernet 802.3 filter type
//
typedef
	struct _ETH_802_3_FILTER
{
#define ETH_802_3_SRC_ADDRESS	0x00000001
#define ETH_802_3_DEST_ADDRESS	0x00000002
#define ETH_802_3_PROTOCOL		0x00000004
	unsigned long m_ValidFields;
	// Specifies which of the fields below contain valid values and should be matched against the packet
	unsigned char m_SrcAddress[ETHER_ADDR_LENGTH]; // Source MAC address
	unsigned char m_DestAddress[ETHER_ADDR_LENGTH]; // Destination MAC address
	unsigned short m_Protocol; // EtherType
	unsigned short Padding;
} ETH_802_3_FILTER, *PETH_802_3_FILTER;

typedef
	struct _IP_SUBNET_V4
{
	unsigned long m_Ip; // IPv4 address expressed as ULONG
	unsigned long m_IpMask; // IPv4 mask expressed as ULONG
} IP_SUBNET_V4, *PIP_SUBNET_V4;

typedef
	struct _IP_RANGE_V4
{
	unsigned long m_StartIp; // IPv4 address expressed as ULONG
	unsigned long m_EndIp; // IPv4 address expressed as ULONG
} IP_RANGE_V4, *PIP_RANGE_V4;

typedef
	struct _IP_ADDRESS_V4
{
#define IP_SUBNET_V4_TYPE	0x00000001
#define IP_RANGE_V4_TYPE	0x00000002
	unsigned long m_AddressType; // Specifies which of the IP v4 address types is used below
	union
	{
		IP_SUBNET_V4 m_IpSubnet;
		IP_RANGE_V4 m_IpRange;
	};
} IP_ADDRESS_V4, *PIP_ADDRESS_V4;

//
// IP version 4 filter type
//
typedef
	struct _IP_V4_FILTER
{
#define IP_V4_FILTER_SRC_ADDRESS	0x00000001
#define IP_V4_FILTER_DEST_ADDRESS	0x00000002
#define IP_V4_FILTER_PROTOCOL		0x00000004
	unsigned long m_ValidFields;
	// Specifies which of the fields below contain valid values and should be matched against the packet
	IP_ADDRESS_V4 m_SrcAddress; // IP v4 source address
	IP_ADDRESS_V4 m_DestAddress; // IP v4 destination address
	unsigned char m_Protocol; // Specifies next protocol
	unsigned char Padding[3];
} IP_V4_FILTER, *PIP_V4_FILTER;

typedef
	struct _IP_SUBNET_V6
{
	IN6_ADDR m_Ip; // IPv6 address
	IN6_ADDR m_IpMask; // IPv6 mask
} IP_SUBNET_V6, *PIP_SUBNET_V6;

typedef
	struct _IP_RANGE_V6
{
	IN6_ADDR m_StartIp; // IPv6 address
	IN6_ADDR m_EndIp; // IPv6 address
} IP_RANGE_V6, *PIP_RANGE_V6;

typedef
	struct _IP_ADDRESS_V6
{
#define IP_SUBNET_V6_TYPE	0x00000001
#define IP_RANGE_V6_TYPE	0x00000002
	unsigned long m_AddressType; // Specifies which of the IP v4 address types is used below
	union
	{
		IP_SUBNET_V6 m_IpSubnet;
		IP_RANGE_V6 m_IpRange;
	};
} IP_ADDRESS_V6, *PIP_ADDRESS_V6;

//
// IP version 6 filter type
//
typedef
	struct _IP_V6_FILTER
{
#define IP_V6_FILTER_SRC_ADDRESS	0x00000001
#define IP_V6_FILTER_DEST_ADDRESS	0x00000002
#define IP_V6_FILTER_PROTOCOL		0x00000004
	unsigned long m_ValidFields;
	// Specifies which of the fields below contain valid values and should be matched against the packet
	IP_ADDRESS_V6 m_SrcAddress; // IP v4 source address
	IP_ADDRESS_V6 m_DestAddress; // IP v4 destination address
	unsigned char m_Protocol; // Specifies next protocol
	unsigned char Padding[3];
} IP_V6_FILTER, *PIP_V6_FILTER;

typedef
	struct _PORT_RANGE
{
	unsigned short m_StartRange;
	unsigned short m_EndRange;
} PORT_RANGE, *PPORT_RANGE;

//
// TCP & UDP filter
//
typedef
	struct _TCPUDP_FILTER
{
#define TCPUDP_SRC_PORT		0x00000001
#define TCPUDP_DEST_PORT	0x00000002
#define TCPUDP_TCP_FLAGS	0x00000004
	unsigned long m_ValidFields;
	// Specifies which of the fields below contain valid values and should be matched against the packet
	PORT_RANGE m_SourcePort; // Source port
	PORT_RANGE m_DestPort; // Destination port
	unsigned char m_TCPFlags; // TCP flags combination
	unsigned char Padding[3];
} TCPUDP_FILTER, *PTCPUDP_FILTER;

typedef
	struct _BYTE_RANGE
{
	unsigned char m_StartRange;
	unsigned char m_EndRange;
} BYTE_RANGE, *PBYTE_RANGE;

//
// ICMP filter
//
typedef struct _ICMP_FILTER
{
#define ICMP_TYPE		0x00000001
#define ICMP_CODE		0x00000002
	unsigned long m_ValidFields;
	// Specifies which of the fields below contain valid values and should be matched against the packet
	BYTE_RANGE m_TypeRange; // ICMP Type
	BYTE_RANGE m_CodeRange; // ICMP Code
} ICMP_FILTER, *PICMP_FILTER;

//
// Represents data link layer (OSI-7) filter level
//
typedef
	struct _DATA_LINK_LAYER_FILTER
{
#define ETH_802_3	0x00000001
	unsigned long m_dwUnionSelector;

	union
	{
		ETH_802_3_FILTER m_Eth8023Filter;
	};
} DATA_LINK_LAYER_FILTER, *PDATA_LINK_LAYER_FILTER;

//
// Represents network layer (OSI-7) filter level
//
typedef
	struct _NETWORK_LAYER_FILTER
{
#define IPV4	0x00000001
#define IPV6	0x00000002
	unsigned long m_dwUnionSelector;

	union
	{
		IP_V4_FILTER m_IPv4;
		IP_V6_FILTER m_IPv6;
	};
} NETWORK_LAYER_FILTER, *PNETWORK_LAYER_FILTER;

// Represents transport layer (OSI-7) filter level
typedef
	struct _TRANSPORT_LAYER_FILTER
{
#define TCPUDP	0x00000001
#define ICMP	0x00000002
	unsigned long m_dwUnionSelector;

	union
	{
		TCPUDP_FILTER m_TcpUdp;
		ICMP_FILTER m_Icmp;
	};
} TRANSPORT_LAYER_FILTER, *PTRANSPORT_LAYER_FILTER;

//
// Defines static filter entry
//
typedef
	struct _STATIC_FILTER
{
#define FILTER_PACKET_PASS		0x00000001 // Pass packet if if matches the filter
#define FILTER_PACKET_DROP		0x00000002 // Drop packet if it matches the filter
#define FILTER_PACKET_REDIRECT	0x00000003 // Redirect packet to WinpkFilter client application
#define FILTER_PACKET_PASS_RDR	0x00000004 // Redirect packet to WinpkFilter client application and pass over network (listen mode)

#define FILTER_PACKET_DROP_RDR	0x00000005 // Redirect packet to WinpkFilter client application and drop it, e.g. log but remove from the flow (listen mode)


#define DATA_LINK_LAYER_VALID	0x00000001 // Match packet against data link layer filter
#define NETWORK_LAYER_VALID		0x00000002 // Match packet against network layer filter
#define TRANSPORT_LAYER_VALID	0x00000004 // Match packet against transport layer filter

	ULARGE_INTEGER m_Adapter; // Adapter handle extended to 64 bit size for structure compatibility across x64 and x86
	unsigned long m_dwDirectionFlags; // PACKET_FLAG_ON_SEND or/and PACKET_FLAG_ON_RECEIVE
	unsigned long m_FilterAction; // FILTER_PACKET_XXX
	unsigned long m_ValidFields;
	// Specifies which of the fields below contain valid values and should be matched against the packet

	// Statistics for the filter
	unsigned long m_LastReset; // Time of the last counters reset (in seconds passed since 1 Jan 1980)
	ULARGE_INTEGER m_PacketsIn; // Incoming packets passed through this filter
	ULARGE_INTEGER m_BytesIn; // Incoming bytes passed through this filter
	ULARGE_INTEGER m_PacketsOut; // Outgoing packets passed through this filter
	ULARGE_INTEGER m_BytesOut; // Outgoing bytes passed through this filter

	DATA_LINK_LAYER_FILTER m_DataLinkFilter;
	NETWORK_LAYER_FILTER m_NetworkFilter;
	TRANSPORT_LAYER_FILTER m_TransportFilter;
} STATIC_FILTER, *PSTATIC_FILTER;

//
// Static filters table to be passed to WinpkFilter driver
//
typedef
	struct _STATIC_FILTER_TABLE
{
	unsigned long m_TableSize; // number of STATIC_FILTER entries
	unsigned long Padding;
	STATIC_FILTER m_StaticFilters[ANY_SIZE];
} STATIC_FILTER_TABLE, *PSTATIC_FILTER_TABLE;

// ********************************************************************************
/// <summary>
/// WinpkFilter fast I/O definitions
/// </summary>
// ********************************************************************************

typedef struct _FAST_IO_WRITE_UNION
{
	union
	{
		struct
		{
			USHORT number_of_packets, write_in_progress_flag;
		} split;

		ULONG join;
	} union_;
} FAST_IO_WRITE_UNION, *PFAST_IO_WRITE_UNION;

typedef struct _FAST_IO_SECTION_HEADER
{
	FAST_IO_WRITE_UNION fast_io_write_union;
	ULONG read_in_progress_flag;
} FAST_IO_SECTION_HEADER, *PFAST_IO_SECTION_HEADER;

typedef struct _FAST_IO_SECTION
{
	volatile FAST_IO_SECTION_HEADER fast_io_header;
	INTERMEDIATE_BUFFER fast_io_packets[ANY_SIZE];
} FAST_IO_SECTION, *PFAST_IO_SECTION;

typedef struct _INITIALIZE_FAST_IO_PARAMS
{
	PFAST_IO_SECTION header_ptr;
	ULONG data_size;
} INITIALIZE_FAST_IO_PARAMS, *PINITIALIZE_FAST_IO_PARAMS;

// --------------------------------------------------------------------------------
/// <summary>
/// Unsorted Read/Send packets
/// </summary>
// --------------------------------------------------------------------------------

typedef struct _UNSORTED_READ_SEND_REQUEST
{
	PINTERMEDIATE_BUFFER* packets;
	ULONG packets_num;
} UNSORTED_READ_SEND_REQUEST, *PUNSORTED_READ_SEND_REQUEST;

// Restore Default Structure Packing
#pragma pack(pop)

//**********************************************************************************
//					IOCTL Codes For NDIS Packet Redirector Driver
//**********************************************************************************

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

#endif // __COMMON_H__
