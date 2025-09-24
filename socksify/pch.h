// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// --- ADDED: Make Winsock available everywhere, and before any windows.h users
#define NOMINMAX 1
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <in6addr.h>
#include <ws2ipdef.h>
#pragma comment(lib, "Ws2_32.lib")
// --- END ADDED

#include <msclr/marshal.h>
#include <msclr/marshal_cppstd.h>
#include <msclr/lock.h>

#include <string>
#include <memory>
#include <variant>
#include <optional>
#include <fstream>

#include "mixed_types.h"

#endif //PCH_H
