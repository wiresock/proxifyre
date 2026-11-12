// winshim.h: the small subset of Windows SDK and Windows Packet Filter API declarations needed
// to compile netlib's packet-rewriting headers (tcp_local_redirect.h,
// socks5_udp_local_redirect.h) on a non-Windows host for the portable packet tests.
//
// Only types, byte-order helpers, the address-string conversions used by net/ip_address.h and
// the three CNdisApi checksum routines are provided. Structure layouts match the Windows SDK so
// the netlib packet code operates on the same bytes it does on Windows. Nothing here is used by
// the product build.

#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <gsl/gsl>

typedef uint32_t DWORD, *PDWORD;
typedef uint32_t ULONG;
typedef int32_t LONG;
typedef int INT;
typedef int BOOL;
typedef unsigned char UCHAR, *PUCHAR, BYTE;
typedef unsigned short USHORT, WORD;
typedef uint64_t ULONGLONG;
typedef void* HANDLE;
typedef unsigned short ADDRESS_FAMILY;
typedef const char* PCSTR;
typedef char* PSTR;
typedef const wchar_t* LPCWSTR;
typedef wchar_t* PWSTR;
typedef uintptr_t ULONG_PTR;

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#define AF_INET 2
#define AF_INET6 23

typedef union _ULARGE_INTEGER
{
    struct { DWORD LowPart; DWORD HighPart; } u;
    ULONGLONG QuadPart;
} ULARGE_INTEGER;

typedef struct _LIST_ENTRY
{
    _LIST_ENTRY* Flink;
    _LIST_ENTRY* Blink;
} LIST_ENTRY;

struct in_addr
{
    union
    {
        struct { UCHAR s_b1, s_b2, s_b3, s_b4; } S_un_b;
        struct { USHORT s_w1, s_w2; } S_un_w;
        ULONG S_addr;
    } S_un;
};

struct in6_addr
{
    union
    {
        UCHAR Byte[16];
        USHORT Word[8];
    } u;
};
typedef in6_addr IN6_ADDR, in_addr6;

constexpr uint16_t htons(const uint16_t v) noexcept { return static_cast<uint16_t>((v << 8) | (v >> 8)); }
constexpr uint16_t ntohs(const uint16_t v) noexcept { return htons(v); }
constexpr uint32_t htonl(const uint32_t v) noexcept { return __builtin_bswap32(v); }
constexpr uint32_t ntohl(const uint32_t v) noexcept { return htonl(v); }

namespace winshim
{
    // Host C library address conversions, declared here so the host's own in_addr/in6_addr
    // definitions (which differ from the Windows ones above) are never included.
    extern "C" int inet_pton(int, const char*, void*);
    extern "C" const char* inet_ntop(int, const void*, char*, unsigned);
    inline constexpr int host_af_inet = 2;
    inline constexpr int host_af_inet6 = 10;
}

inline LONG RtlIpv4StringToAddressA(const char* s, BOOL, PCSTR* terminator, in_addr* address)
{
    if (terminator) *terminator = s + std::strlen(s);
    return winshim::inet_pton(winshim::host_af_inet, s, address) == 1 ? 0 : -1;
}
inline LONG RtlIpv6StringToAddressA(const char* s, PCSTR* terminator, in6_addr* address)
{
    if (terminator) *terminator = s + std::strlen(s);
    return winshim::inet_pton(winshim::host_af_inet6, s, address) == 1 ? 0 : -1;
}
inline PSTR RtlIpv4AddressToStringA(const in_addr* address, PSTR s)
{
    winshim::inet_ntop(winshim::host_af_inet, address, s, 16);
    return s + std::strlen(s);
}
inline PSTR RtlIpv6AddressToStringA(const in6_addr* address, PSTR s)
{
    winshim::inet_ntop(winshim::host_af_inet6, address, s, 46);
    return s + std::strlen(s);
}
// Wide variants are compiled into net/ip_address.h but unused by the tests.
inline LONG RtlIpv4StringToAddressW(LPCWSTR, BOOL, LPCWSTR*, in_addr*) { return -1; }
inline LONG RtlIpv6StringToAddressW(LPCWSTR, LPCWSTR*, in6_addr*) { return -1; }
inline PWSTR RtlIpv4AddressToStringW(const in_addr*, PWSTR s) { if (s) *s = 0; return s; }
inline PWSTR RtlIpv6AddressToStringW(const in6_addr*, PWSTR s) { if (s) *s = 0; return s; }

#define IN6ADDR_LOOPBACK_INIT { { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } }

// CNdisApi: only the static checksum routines used by the redirect headers. Their definitions
// are extracted verbatim from ndisapi/ndisapi.cpp by run-portable-tests.sh, so the tests run the
// product implementations.
struct _INTERMEDIATE_BUFFER;
class CNdisApi
{
public:
    static void RecalculateIPChecksum(_INTERMEDIATE_BUFFER* pPacket);
    static void RecalculateTCPChecksum(_INTERMEDIATE_BUFFER* pPacket);
    static void RecalculateUDPChecksum(_INTERMEDIATE_BUFFER* pPacket);
};
