#pragma once

// Windows-light header for a tiny C API.
// NOTE: Do NOT include Windows headers here; the .cpp will pull in Winsock.

struct sockaddr;

#if defined(_WIN32)
  #define DIP_API extern "C" __declspec(dllexport)
  #define DIP_CALL __cdecl
#else
  #define DIP_API extern "C"
  #define DIP_CALL
#endif

// Returns 1 on success, 0 on failure.
DIP_API int DIP_CALL dip_add_process(const wchar_t* process_name, const char* cidr);
DIP_API int DIP_CALL dip_remove_process(const wchar_t* process_name, const char* cidr);

// Global API exists but you don't have to use it.
DIP_API int DIP_CALL dip_add_global(const char* cidr);
DIP_API int DIP_CALL dip_remove_global(const char* cidr);

// Decision hook (kept for completeness if you ever wire it in the router).
// Return 1 to redirect, 0 to passthrough.
DIP_API int DIP_CALL dip_should_redirect_for(const wchar_t* process_name_or_null,
                                             const sockaddr* dst, int dstlen);
