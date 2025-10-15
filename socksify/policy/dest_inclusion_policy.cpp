#include "pch.h"  // must be first for /Yu "pch.h"

// Pull in Winsock (needed for InetPtonA/ntohl). We *only* include these here
// so we don't perturb your original headers anywhere else.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#include "policy/dest_inclusion_policy.h"

#include <cwctype>     // towlower
#include <algorithm>
#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>
#include <cstring>     // memcpy
#include <cstdlib>     // atoi

namespace {
    struct CidrV4 {
        uint32_t network; // host order
        uint32_t mask;    // host order
    };

    // lower-case exe name ("chrome.exe")
    std::wstring to_lower(const std::wstring& s) {
        std::wstring r(s);
        std::transform(r.begin(), r.end(), r.begin(), [](wchar_t c){
            return static_cast<wchar_t>(::towlower(static_cast<wint_t>(c)));
        });
        return r;
    }

    // keep only the file name (no path)
    std::wstring basename_exe(const std::wstring& full) {
        size_t p = full.find_last_of(L"\\/"); 
        if (p == std::wstring::npos) return to_lower(full);
        return to_lower(full.substr(p + 1));
    }

    bool parse_cidr_v4(const char* cidr, CidrV4& out) {
        if (!cidr || !*cidr) return false;

        const char* slash = std::strchr(cidr, '/');
        if (!slash) return false;

        char ipbuf[64] = {0};
        size_t iplen = static_cast<size_t>(slash - cidr);
        if (iplen >= sizeof ipbuf) return false;
        std::memcpy(ipbuf, cidr, iplen);
        ipbuf[iplen] = '\0';

        int prefix = std::atoi(slash + 1);
        if (prefix < 0 || prefix > 32) return false;

        IN_ADDR ia{};
        if (InetPtonA(AF_INET, ipbuf, &ia) != 1) return false;

        uint32_t net_be = ia.S_un.S_addr;     // network order
        uint32_t net    = ntohl(net_be);      // host order

        uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
        out.network = net & mask;
        out.mask    = mask;
        return true;
    }

    bool ipv4_from_sockaddr(const sockaddr* sa, int salen, uint32_t& ip_out_host) {
        if (!sa || salen < static_cast<int>(sizeof(sockaddr_in))) return false;
        if (sa->sa_family != AF_INET) return false;
        auto sin = reinterpret_cast<const sockaddr_in*>(sa);
        ip_out_host = ntohl(sin->sin_addr.S_un.S_addr);
        return true;
    }

    struct PolicyStore {
        std::mutex m;
        std::unordered_map<std::wstring, std::vector<CidrV4>> by_proc; // key: "chrome.exe"
        std::vector<CidrV4> globals;

        bool add_proc(const std::wstring& exe, const char* cidr) {
            CidrV4 c{};
            if (!parse_cidr_v4(cidr, c)) return false;
            std::lock_guard<std::mutex> g(m);
            by_proc[exe].push_back(c);
            return true;
        }
        bool rem_proc(const std::wstring& exe, const char* cidr) {
            CidrV4 c{};
            if (!parse_cidr_v4(cidr, c)) return false;
            std::lock_guard<std::mutex> g(m);
            auto it = by_proc.find(exe);
            if (it == by_proc.end()) return false;
            auto& vec = it->second;
            vec.erase(std::remove_if(vec.begin(), vec.end(),
                        [&](const CidrV4& x){ return x.network==c.network && x.mask==c.mask; }),
                      vec.end());
            if (vec.empty()) by_proc.erase(it);
            return true;
        }
        bool add_global(const char* cidr) {
            CidrV4 c{};
            if (!parse_cidr_v4(cidr, c)) return false;
            std::lock_guard<std::mutex> g(m);
            globals.push_back(c);
            return true;
        }
        bool rem_global(const char* cidr) {
            CidrV4 c{};
            if (!parse_cidr_v4(cidr, c)) return false;
            std::lock_guard<std::mutex> g(m);
            auto& vec = globals;
            vec.erase(std::remove_if(vec.begin(), vec.end(),
                        [&](const CidrV4& x){ return x.network==c.network && x.mask==c.mask; }),
                      vec.end());
            return true;
        }

        static bool match_any(const std::vector<CidrV4>& list, uint32_t ip_host) {
            for (const auto& c : list) {
                if ((ip_host & c.mask) == c.network) return true;
            }
            return false;
        }

        // returns 1 = redirect, 0 = passthrough
        int should_redirect(const wchar_t* process_name_or_null,
                            const sockaddr* dst, int dstlen) {
            uint32_t ip_host{};
            // If we can't read IPv4 from sockaddr, keep current behavior: redirect.
            if (!ipv4_from_sockaddr(dst, dstlen, ip_host)) return 1;

            std::lock_guard<std::mutex> g(m);

            // Global rules first (you said you won't use them; this is harmless if empty)
            if (!globals.empty() && match_any(globals, ip_host)) return 1;

            // Per-process rules
            if (process_name_or_null && *process_name_or_null) {
                auto key = basename_exe(process_name_or_null);
                auto it = by_proc.find(key);
                if (it != by_proc.end()) {
                    // match => redirect, no match => passthrough
                    return match_any(it->second, ip_host) ? 1 : 0;
                }
            }

            // No specific rules found: keep existing behavior (redirect).
            return 1;
        }
    };

    PolicyStore& store() {
        static PolicyStore s;
        return s;
    }
} // namespace

// ---- C exports -------------------------------------------------------------

int DIP_CALL dip_add_process(const wchar_t* process_name, const char* cidr) {
    if (!process_name || !cidr) return 0;
    return store().add_proc(basename_exe(process_name), cidr) ? 1 : 0;
}

int DIP_CALL dip_remove_process(const wchar_t* process_name, const char* cidr) {
    if (!process_name || !cidr) return 0;
    return store().rem_proc(basename_exe(process_name), cidr) ? 1 : 0;
}

int DIP_CALL dip_add_global(const char* cidr) {
    if (!cidr) return 0;
    return store().add_global(cidr) ? 1 : 0;
}

int DIP_CALL dip_remove_global(const char* cidr) {
    if (!cidr) return 0;
    return store().rem_global(cidr) ? 1 : 0;
}

int DIP_CALL dip_should_redirect_for(const wchar_t* process_name_or_null,
                                     const sockaddr* dst, int dstlen) {
    return store().should_redirect(process_name_or_null, dst, dstlen);
}
