#pragma once

// Keep Windows headers lean
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// Winsock must come before Windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

// STL common headers you likely use across the project
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>

// Link with Ws2_32 on native side (safe even with /clr)
#pragma comment(lib, "Ws2_32.lib")
