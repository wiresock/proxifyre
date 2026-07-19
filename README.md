# ProxiFyre: SOCKS5 Proxifier for Windows with UDP Support

**ProxiFyre** enables applications without native proxy support to transparently route both TCP and UDP traffic through a SOCKS5 proxy, enabling advanced use cases such as **QUIC over SOCKS**—a capability not supported by modern web browsers.

Built on top of the Windows Packet Filter `socksify` demo, ProxiFyre significantly extends its foundational functionality with production-ready enhancements. In addition to full UDP support, ProxiFyre allows users to manage **multiple SOCKS5 proxy instances** simultaneously.

Configuration is streamlined through a single `app-config.json` file, making setup intuitive and reproducible. For long-running or unattended use cases, ProxiFyre can also be configured to run as a **Windows Service**, ensuring continuous operation without manual intervention.

As of **v2.1.1**, ProxiFyre also supports **process exclusions**, allowing you to specify which applications should *bypass* the proxy while others remain proxied. Additionally, performance has been improved through intelligent caching of process matching.

As of **v2.2.0**, ProxiFyre supports **LAN bypass**, allowing local network traffic to pass through without being proxied.

As of **v2.3.0**, ProxiFyre also proxies **IPv6** destinations. Previously only IPv4 traffic from a matched application was routed through the proxy while its IPv6 TCP/UDP traffic leaked out directly; now both address families are redirected to the configured SOCKS5 proxy.

**Requirements and limitations:**

- **Your client host must already have working IPv6 connectivity.** ProxiFyre redirects the IPv6 packets your applications actually transmit — it does *not* create IPv6 reachability. On an **IPv4-only host**, your applications never emit global IPv6 traffic, so there is nothing to redirect and you will still see IPv4-only egress even for IPv6-capable destinations. (This is inherent to the packet-filter design: it intercepts transmitted packets, it does not originate connections on the application's behalf.)
- **The SOCKS5 server endpoint itself must be IPv4** — a literal IPv4 address, or a hostname that resolves to an **A** record. ProxiFyre connects to the proxy over IPv4 and reaches it via its IPv4-mapped IPv6 address on a dual-stack socket when relaying IPv6 destinations; an **IPv6-only proxy address** (an IPv6 literal, or an AAAA-only hostname) is **not** supported. Existing IPv4 endpoints (e.g., `127.0.0.1:1080`) continue to work unchanged.
- **The SOCKS5 server must accept IPv6 target addresses** (`ATYP=4`); servers that only support IPv4/domain targets will reject IPv6 destinations.
- **Fragmented IPv6 datagrams are not redirected.** To avoid corrupting a partially rewritten datagram, IPv6 packets that arrive fragmented are passed through unproxied — so an application that emits oversized IPv6 UDP datagrams (which the OS fragments at the source) can leak those datagrams outside the proxy. Most traffic is unaffected: TCP is never source-fragmented, and UDP that honors path-MTU discovery (e.g. QUIC/HTTP3) does not fragment. A one-time warning is logged when such a packet is first passed through.

---

## Configuration

The application uses a configuration file named `app-config.json`. This JSON file should contain configurations for different applications. Each configuration object should have the following properties:

- **appNames**: An array of strings representing the names of applications this configuration applies to.
- **socks5ProxyEndpoint**: A string that specifies the SOCKS5 proxy endpoint.
- **username**: A string that specifies the username for the proxy (optional).
- **password**: A string that specifies the password for the proxy (optional).
- **socks5Transport**: `"TCP"` for normal SOCKS5 (default) or `"TLS"` for SOCKS5-over-TLS.
- **tlsServerName**: SNI/certificate validation name for `"socks5Transport": "TLS"` (defaults to the endpoint host).
- **tlsPinnedSha256**: Optional SHA-256 certificate fingerprint pin for TLS upstreams.
- **tlsAllowInvalidCertificate**: Allows invalid TLS certificates (default: `false`). Prefer `tlsPinnedSha256` for self-signed test certificates.
- **supportedProtocols**: An array of strings specifying the supported protocols (e.g., `"TCP"`, `"UDP"`).
- **supportedAddressFamilies**: An array containing `"IPv4"`, `"IPv6"`, or both. If omitted, both are enabled. An explicit empty array or any other value is rejected as a configuration error.
- **excludes** *(new in v2.1.1)*: An array of application names or paths to exclude from proxy routing.
- **bypassLan** *(new in v2.2.0)*: A boolean to bypass proxy for local network traffic (default: `false`).

---

### LogLevel

LogLevel can have one of the following values which define the detail of the log:  
`Error`, `Warning`, `Info`, `Debug`, `All`

---

### appNames

- A **name** entry (one that contains neither `/` nor `\`) matches the executable's filename, **anchored** to the whole name.  
  - `firefox` or `firefox.exe` both match `firefox.exe`.  
  - It matches the exact name, or the name followed by an extension such as `.exe` — so `firefox` matches `firefox.exe` but **not** `NewFirefox.exe` (a short pattern won't match an unrelated executable).  
- If the pattern contains **slashes or backslashes**, it is treated as a **pathname** and matched as a substring of the process's full path.  
  - This allows targeting an entire folder (useful for UWP apps).  
  - Example: `C:\\Program Files\\WindowsApps\\ROBLOXCORPORATION.ROBLOX`  
- An **empty string** (`""`) is a **catch-all** that matches every process not already matched by a prior proxy and not listed in `excludes`. Use it for a default/fallback proxy — and place this proxy **last** in the `proxies` list, since proxies are matched in order and a catch-all shadows any proxy defined after it.

---

### supportedAddressFamilies

Use `supportedAddressFamilies` when a SOCKS5 proxy cannot relay every destination address family. For example, an IPv4-only proxy should be configured with:

```json
"supportedAddressFamilies": ["IPv4"]
```

For a matched application, unsupported destination families are blocked instead of being passed through directly or sent to a SOCKS path that cannot complete. This prevents IPv6 leaks and lets browsers fall back to IPv4 when the proxy only supports IPv4 destinations.

If the field is omitted, ProxiFyre assumes both IPv4 and IPv6 destinations are supported, preserving the previous behavior.

---

### Excludes (new in v2.1.1)

The `excludes` section lets you define processes that should **bypass the proxy**.  
This is useful when you want a global proxy setup but keep certain apps (like browsers, local dev tools, or games) unproxied.

When using a catch-all proxy entry (`"appNames": [""]`) together with another VPN, exclude the VPN's carrier process. Otherwise ProxiFyre can capture the VPN's outer tunnel packets, causing the proxy connection to recursively depend on itself and eventually time out.

Unlike `appNames`, exclusion entries match by **substring** (a name is matched against the process's filename, a path-form entry against the full path) — so `chrome` also excludes `chrome_proxy.exe`. Exclusion is deliberately permissive so an app you meant to keep direct is not accidentally proxied.

Example:

```json
{
  "logLevel": "Error",
  "proxies": [
    {
      "appNames": [""],
      "socks5ProxyEndpoint": "oracle.sshvpn.me:1080",
      "username": "username1",
      "password": "password1",
      "supportedProtocols": ["TCP", "UDP"],
      "supportedAddressFamilies": ["IPv4", "IPv6"]
    }
  ],
  "excludes": [
    "firefox",
    "C:\\Program Files\\LocalApp\\NotProxiedApp.exe"
  ]
}
```

---

### bypassLan (new in v2.2.0)

When set to `true`, traffic to/from local network ranges will pass through without being proxied. This is useful for accessing local network resources (printers, NAS, local servers) while proxying internet traffic.

**Bypassed ranges:**
- `10.0.0.0/8` – Private Class A
- `172.16.0.0/12` – Private Class B (172.16.x.x – 172.31.x.x)
- `192.168.0.0/16` – Private Class C
- `224.0.0.0/4` – Multicast (224.x.x.x – 239.x.x.x)
- `169.254.0.0/16` – Link-local (APIPA)

Example:

```json
{
  "logLevel": "Info",
  "bypassLan": true,
  "proxies": [
    {
      "appNames": ["chrome", "firefox"],
      "socks5ProxyEndpoint": "127.0.0.1:1080",
      "supportedProtocols": ["TCP", "UDP"],
      "supportedAddressFamilies": ["IPv4", "IPv6"]
    }
  ]
}
```

---

### SOCKS5 Proxy Authorization

If the SOCKS5 proxy does not support authorization, you can skip the `username` and `password` fields in the configuration.

---

### SOCKS5-over-TLS / Alighieri

ProxiFyre can initiate a TLS session to a SOCKS5 proxy that expects SOCKS5-over-TLS, such as Alighieri with `tls.certfile` / `tls.keyfile` enabled. TLS transport supports both TCP `CONNECT` and the UDP `ASSOCIATE` control channel.

```json
{
  "appNames": ["chrome"],
  "socks5ProxyEndpoint": "proxy.example.com:443",
  "socks5Transport": "TLS",
  "tlsServerName": "proxy.example.com",
  "tlsPinnedSha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "supportedProtocols": ["TCP", "UDP"],
  "supportedAddressFamilies": ["IPv4", "IPv6"]
}
```

For public certificates, omit `tlsPinnedSha256` and leave `tlsAllowInvalidCertificate` as `false`. Setting `tlsPinnedSha256` selects exact leaf-certificate pin validation instead of normal chain/hostname validation, which allows a self-signed certificate while still authenticating the configured certificate. Prefer that mode for self-signed lab certificates rather than disabling validation globally. The native transport currently negotiates TLS 1.2, which is supported by Alighieri's rustls listener.

---

## Example Configuration

```json
{
 "logLevel": "Error",
 "bypassLan": true,
 "proxies": [
   {
     "appNames": ["chrome", "C:\\Program Files\\WindowsApps\\ROBLOXCORPORATION.ROBLOX"],
     "socks5ProxyEndpoint": "158.101.205.51:1080",
     "username": "username1",
     "password": "password1",
     "supportedProtocols": ["TCP", "UDP"],
     "supportedAddressFamilies": ["IPv4", "IPv6"]
   },
   {
     "appNames": ["firefox", "firefox_dev"],
     "socks5ProxyEndpoint": "127.0.0.1:8080",
     "supportedProtocols": ["TCP"],
     "supportedAddressFamilies": ["IPv4"]
   }
 ],
 "excludes": [
   "edge",
   "localservice.exe"
 ]
}
```

---

## Quick Start Guide

This guide provides step-by-step instructions on how to set up and run the ProxiFyre application.

### Pre-installation Steps

#### 1. Install Windows Packet Filter (WinpkFilter)

Windows Packet Filter is a critical dependency for our project.

* Visit the [Windows Packet Filter Github page](https://github.com/wiresock/ndisapi/releases) to download the latest version.
* Follow the instructions on the page to install it.

#### 2. Install Visual Studio Runtime Libraries

Visual Studio Runtime Libraries are required for running applications developed with Visual Studio.

* Go to [Visual Studio 2022 redistributable download page](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170)
* Identify your system architecture (x64, x86, or ARM64).
* Download the appropriate installer for your platform to ensure compatibility and optimal performance.

  * For x64 systems, download the x64 installer.
  * For x86 systems, download the x86 installer.
  * For ARM64 systems, download the ARM64 installer.
* Locate the downloaded installer and double-click on it to begin the installation.
* Follow the on-screen instructions to complete the installation

Please ensure you download the correct installer to avoid any installation issues.

---

### Installation Steps

1. **Download the Latest Release**: Visit our [GitHub Releases page](https://github.com/wiresock/proxifyre/releases) to download the latest release of the ProxiFyre software.

2. **Unzip the Software**: After downloading, extract the contents of the `.zip` file to your preferred location.

3. **Create `app-config.json` File**: Following the template provided in the Configuration section of this document, create an `app-config.json` file. This file is crucial for the software to function properly. Save this file in the main application folder.

---

### Running the Application

4. **Run the Application**: Navigate to the directory where you extracted the software. Start `ProxiFyre.exe` from an Administrator console. Administrative privileges are required for reliable process ownership, exclusions, and packet redirection; interactive startup exits with an error when it is not elevated.

⚠️ **Firewall Note**: If ProxiFyre does not appear to work, check Windows Firewall. ProxiFyre needs to accept and initiate network connections.

* Temporarily disable the firewall to confirm if it’s blocking ProxiFyre.
* If this resolves the issue, add an **inbound firewall rule** for `ProxiFyre.exe` instead of keeping the firewall disabled.

  * Open **Windows Defender Firewall with Advanced Security**.
  * Go to **Inbound Rules → New Rule... → Program**.
  * Select `ProxiFyre.exe` and allow the connection.
  * Apply to all profiles (Domain, Private, Public).

---

### Running as a Service

ProxiFyre can be installed and run as a Windows service. Follow these steps:

1. Open a command prompt as an administrator.
2. Navigate to the directory containing `ProxiFyre.exe`.
3. Use the following command to install the service:

   ```
   ProxiFyre.exe install
   ```
4. Start the service with:

   ```
   ProxiFyre.exe start
   ```
5. To stop the service, use:

   ```
   ProxiFyre.exe stop
   ```
6. If you wish to uninstall the service, use:

   ```
   ProxiFyre.exe uninstall
   ```

---

### Logging

Logs are saved in the application folder under the `/logs` directory. The details and verbosity of the logs depend on the configuration set in the `app-config.json` file.

---

## Build Prerequisites

Before starting the build process, ensure the following requirements are met:

1. **Install vcpkg:** You can download and install vcpkg from the official website [here](https://vcpkg.io/en/getting-started.html).

2. **Install Microsoft GSL library via vcpkg:** Once vcpkg is installed, use it to download and install the Microsoft GSL library. Run the following commands in your terminal:

   ```
   vcpkg install ms-gsl:x86-windows ms-gsl:x64-windows ms-gsl:arm64-windows
   ```

3. **Add online NuGet Package Source:** In some cases, you may need to add an online NuGet Package Source. To do this, navigate to `Visual Studio -> Tools -> Options -> NuGet Package Manager -> Package Sources` and add `https://nuget.org/api/v2`.

---

## Projects

This repository consists of three main projects:

### 1. ndisapi.lib

This is an adopted Windows Packet Filter [NDISAPI](https://github.com/wiresock/ndisapi) static library project.

### 2. socksify

This project is a .Net C++/CLI class library that implements the local SOCKS5 router functionality.

### 3. ProxiFyre

This is a .Net-based Windows console application that employs the functionality provided by the socksify .Net C++/CLI class library.
