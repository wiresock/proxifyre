// packet_env.h: compiles netlib's real packet-rewriting headers on a non-Windows host for the
// portable packet tests (see winshim.h).
#pragma once

#include "winshim.h"
#include "../../../../external/ndisapi/include/Common.h"
// iphlp.h declares tcp_seq as u_long, which is 32-bit on Windows but 64-bit on LP64 hosts (and
// the host C library already declares its own u_long). Give iphlp.h a private u_long with the
// Windows (LLP64) width so tcphdr has its on-wire size.
#define u_long winshim_u_long
#define long int
#include "../../../src/iphlp.h"
#undef long
#include "../../../../external/ndisapi/ndisapi/inet_checksum.h"
#include "../../../src/tools/generic.h"
#include "../../../src/log/log.h"
#include "../../../src/net/ip_address.h"
#include "../../../src/net/ip_endpoint.h"
#include "../../../src/net/ipv6_helper.h"
#include "../../../src/proxy/proxy_common.h"
#include "../../../src/proxy/socks5_common.h"
#include "../../../src/ndisapi/tcp_local_redirect.h"
#include "../../../src/ndisapi/socks5_udp_local_redirect.h"
#include "../../../src/proxy/dns_routing_policy.h"
#include "../../../src/proxy/dns_udp_multiplexer.h"
