// pch.h: precompiled header for the native netlib test executable.
//
// Includes only the Windows, standard library, and netlib headers required by the code
// under test. It intentionally does not include the socksify (C++/CLI) PCH, the packet
// filter driver API, or any tunnel/WireGuard component.

#ifndef PCH_H
#define PCH_H

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <in6addr.h>
#include <ws2ipdef.h>
#include <IPHlpApi.h>
#include <Mstcpip.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <syncstream>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include <gsl/gsl>

#include <gtest/gtest.h>

#include "../netlib/src/tools/generic.h"
#include "../netlib/src/tools/strings.h"
#include "../netlib/src/log/log.h"
#include "../netlib/src/net/ip_address.h"
#include "../netlib/src/net/ip_endpoint.h"
#include "../netlib/src/iphelper/process_lookup.h"

#endif // PCH_H
