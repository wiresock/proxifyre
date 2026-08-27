# ProxiFyre: SOCKS5 Proxifier for Windows with UDP Support

**ProxiFyre** enables applications without native proxy support to transparently route both TCP and UDP traffic through a SOCKS5 proxy, enabling advanced use cases such as **QUIC over SOCKS**—a capability not supported by modern web browsers.

Built on top of the Windows Packet Filter `socksify` demo, ProxiFyre significantly extends its foundational functionality with production-ready enhancements. In addition to full UDP support, ProxiFyre allows users to manage **multiple SOCKS5 proxy instances** simultaneously.

Configuration is streamlined through a single `app-config.json` file, making setup intuitive and reproducible. For long-running or unattended use cases, ProxiFyre can also be configured to run as a **Windows Service**, ensuring continuous operation without manual intervention.

As of **v2.1.1**, ProxiFyre also supports **process exclusions**, allowing you to specify which applications should *bypass* the proxy while others remain proxied. Additionally, performance has been improved through intelligent caching of process matching.

As of **v2.2.0**, ProxiFyre supports **LAN bypass**, allowing local network traffic to pass through without being proxied.

As of **v2.3.0**, ProxiFyre also proxies **IPv6** destinations. Previously only IPv4 traffic from a matched application was routed through the proxy while its IPv6 TCP/UDP traffic leaked out directly; now both address families are redirected to the configured SOCKS5 proxy.

As of **v2.4.0**, ProxiFyre supports native **SOCKS5-over-TLS** upstreams through Windows SChannel, including encrypted TCP `CONNECT` relays and TLS-protected UDP `ASSOCIATE` control channels. This transport is compatible with [Alighieri](https://github.com/wiresock/alighieri) TLS listeners; normal unencrypted SOCKS5 remains the default.

As of **v2.5.0**, ProxiFyre includes an elevated Windows Forms management application for editing and validating routing rules, managing `ProxiFyreService`, following logs, and using notification-area controls. The release also adds architecture-specific WiX MSI packages and a recommended online setup executable that installs ProxiFyre after acquiring verified Visual C++ and Windows Packet Filter prerequisites when needed.

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
- **socks5Transport** *(new in v2.4.0)*: `"TCP"` for normal SOCKS5 (default) or `"TLS"` for SOCKS5-over-TLS.
- **tlsServerName** *(new in v2.4.0)*: SNI/certificate validation name for `"socks5Transport": "TLS"` (defaults to the endpoint host).
- **tlsPinnedSha256** *(new in v2.4.0)*: Optional SHA-256 certificate fingerprint pin for TLS upstreams.
- **tlsAllowInvalidCertificate** *(new in v2.4.0)*: Allows invalid TLS certificates (default: `false`). Prefer `tlsPinnedSha256` for self-signed test certificates.
- **supportedProtocols**: An array of strings specifying the supported protocols (e.g., `"TCP"`, `"UDP"`).
- **supportedAddressFamilies**: An array containing `"IPv4"`, `"IPv6"`, or both. If omitted, both are enabled. An explicit empty array or any other value is rejected as a configuration error.
- **excludes** *(new in v2.1.1)*: An array of application names or paths to exclude from proxy routing.
- **bypassLan** *(new in v2.2.0)*: A boolean to bypass proxy for local network traffic (default: `false`).

---

### LogLevel

LogLevel can have one of the following values which define the detail of the log:  
`Error`, `Warning`, `Info`, `Debug`, `All`

`Info` records service lifecycle and configuration summaries. Use `Debug` when per-connection routing, proxy negotiation, and relay details are needed for troubleshooting.

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

ProxiFyre can initiate a TLS session to a SOCKS5 proxy that expects SOCKS5-over-TLS, such as [Alighieri](https://github.com/wiresock/alighieri) with `tls.certfile` / `tls.keyfile` enabled. TLS transport supports both TCP `CONNECT` and the UDP `ASSOCIATE` control channel.

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

### Choose a release asset

For a `v2.5.0` release, CI publishes only after the x86, x64, and ARM64 build/package jobs all succeed. Pull-request and manual runs retain CI artifacts without creating a GitHub release; a release tag must exactly match the repository version (`v2.5.0`), after which the tag job gathers all 18 files, uploads them to a draft, and publishes the release only after every upload succeeds. Each architecture has three first-party artifacts and a `.sha256` sidecar for each one:

- **Recommended online setup:** `ProxiFyre-2.5.0-win-<x86|x64|arm64>-setup.exe` installs prerequisites when needed and then installs ProxiFyre.
- **Standalone MSI:** `ProxiFyre-2.5.0-win-<x86|x64|arm64>.msi` is for administrator-managed deployment, including offline deployment after all prerequisites have already been provisioned. The MSI does not download them.
- **Release ZIP payload:** `ProxiFyre-v2.5.0-<x86|x64|ARM64>.zip` contains the application files only. It is not an offline installer: it does not provision prerequisites, register the service, create firewall rules or shortcuts, or establish the protected installation directory required by the Release GUI. Prefer setup; advanced ZIP deployment must stage the complete payload in an administrator-protected directory on a fixed local volume as described in [docs/gui.md](docs/gui.md).

ProxiFyre's first-party binaries and packages are deliberately unsigned, so Windows can display **Unknown publisher**. Verify the selected artifact against its `.sha256` sidecar before elevation. A checksum establishes publisher provenance only when the expected value comes from a trusted release record or an independent channel.

### Install with setup

1. Install the required .NET Framework first: **4.7.2 or later on x86/x64**, or **4.8.1 or later on ARM64**. ProxiFyre Setup checks this requirement but does not download or install .NET Framework.
2. From the [GitHub Releases page](https://github.com/wiresock/proxifyre/releases), download the setup executable matching the machine's native Windows architecture and its `.sha256` sidecar. Setup rejects a mismatched architecture before acquiring the kernel driver.
3. Verify the checksum, run setup as an administrator, and accept the **Unknown publisher** prompt only after that verification. WiX Burn detects and, when needed, downloads the pinned architecture-matched [Microsoft Visual C++ 2015-2022 Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170) and official Windows Packet Filter 3.6.2.1 MSI from the upstream [`v3.6.2` release](https://github.com/wiresock/ndisapi/releases/tag/v3.6.2). Burn verifies the acquired bytes against the digests embedded in setup before executing either prerequisite.
4. Open **ProxiFyre** from the Start Menu, create or review `app-config.json`, and start the service from the GUI. The service is installed with demand/manual start and is intentionally left stopped until a valid configuration exists.

Windows 7 is supported only with Service Pack 1; install current servicing-stack and SHA-2 support updates and reboot first. Setup temporarily enables the current user's TLS 1.2 WinINet protocol bit during acquisition and restores the previous value afterward. If, on Windows 7 only, the pinned Visual C++ payload exhausts its normal HTTPS retries with WinINet error `12029`, setup makes one final request by changing only that exact Microsoft content-addressed URL's scheme to HTTP. Windows Packet Filter remains HTTPS, and Burn still requires the exact embedded SHA-512 before it will execute the Visual C++ package. This narrow fallback does not apply to another payload, host, path, error, or Windows version.

For an offline or centrally managed installation, provision the architecture-matched .NET Framework, Visual C++ runtime, and Windows Packet Filter first, then deploy the standalone MSI. It fails with an actionable prerequisite message instead of downloading another package.

The MSI creates two declarative inbound program rules for installed `ProxiFyre.exe`: `ProxiFyre (TCP-In)` and `ProxiFyre (UDP-In)`. Both apply to Domain, Private, and Public profiles, use dynamic/any ports because the redirect listeners are allocated at runtime, and deny edge traversal. No rule is created for the GUI and no arbitrary global port is opened. Repair and upgrade reconcile the same rules; uninstall removes only those two ProxiFyre-owned rules.

The MSI installs `ProxiFyreService` as LocalSystem with a dependency on `NDISRD`, creates a Start Menu shortcut to `ProxiFyreUI.exe`, and offers a shared-desktop shortcut. Uninstall through Windows Apps/Installed apps stops and removes the service, product files, shortcuts, and firewall rules while preserving `app-config.json`, its backup, logs, GUI preferences, the Visual C++ runtime, and Windows Packet Filter. Both prerequisites are shared system dependencies and are never removed by ProxiFyre setup.

For standalone-MSI deployment, exact payload details, prerequisite detection, hashes, upgrade behavior, build commands, limitations, licensing considerations, and the full lifecycle validation matrix, see [docs/installer.md](docs/installer.md).

---

### Logging

Logs are saved beside `ProxiFyre.exe` in the `.\logs` directory. The details and verbosity of the logs depend on the configuration set in `app-config.json`.

---

## ProxiFyre GUI

`ProxiFyreUI.exe` is the small native integrity host for the Windows Forms management application included with each architecture-specific release. Before starting .NET Framework it sanitizes CLR-control environment variables, rejects unexpected app-local executable modules, validates the fixed CLR configuration hash, and locks `ProxiFyreUI.Managed.dll` plus its managed dependencies against replacement. ProxiFyre's first-party modules are unsigned; the MSI-protected installation directory and published artifact SHA-256 are therefore important parts of the release boundary. The application requires administrator approval and .NET Framework 4.7.2 on x86/x64 or 4.8.1 on ARM64. The GUI edits configuration, controls `ProxiFyreService`, follows logs, opens the active log file, and provides notification-area controls; `ProxiFyre.exe` remains the console/service networking engine. The GUI does not load or call `socksify.dll`. For each Windows identity and terminal session, only one GUI instance runs; launching it again restores the existing window from the notification area.

The GUI locates the engine from the installed service registration first, then beside the GUI, then from the last explicitly selected path. Use **Browse for ProxiFyre.exe** when the engine is installed elsewhere. The Diagnostics tab shows the resolved engine, `app-config.json`, and `logs` paths. GUI preferences are stored separately under `%LocalAppData%\ProxiFyreUI`.

The MSI normally creates `ProxiFyreService`; if its registration is later removed, **Install Service** can restore it from the protected installed payload, while an MSI repair remains the preferred way to reconcile all product components. Release service operations require the engine payload to remain beneath a protected per-machine directory whose owner and ACL chain prevent replacement by standard users. **Uninstall service…** in the GUI stops and removes only the service registration and preserves configuration, backup, and logs; uninstall the product through Windows Apps/Installed apps to remove product files, shortcuts, and the two MSI-owned firewall rules. Before install/start/restart, the GUI distinguishes a missing or incompatible Windows Packet Filter dependency from an installed-but-stopped `NDISRD` service. An active device is queried for API major `3` and API minor `0x0601` or newer; SCM may start a compatible registered dependency. Start, stop, and restart remain asynchronous, and a successful save is never reported as active proxying.

Use the Routing tab to add or edit rules and move them into evaluation order. The first matching rule wins. **All unmatched applications** writes an explicit empty string (`"appNames": [""]`) and should be the last rule, because it shadows later rules. Exclusions are edited separately, take priority over the catch-all, and use permissive process-name/path substring matching; a VPN carrier process may need exclusion to avoid recursive routing.

Rules can use normal SOCKS5 over TCP or SOCKS5-over-TLS. A TLS certificate pin is the normalized 64-hex-character SHA-256 fingerprint of the expected leaf certificate. Prefer a pin for a self-signed test endpoint. Allowing an invalid certificate disables normal certificate validation and is prominently warned, especially when no pin is present.

**Save** validates and atomically updates the configuration while preserving `app-config.json.bak`; it does not restart a running service. **Apply & Restart** saves, restarts, waits for the actual SCM result, and offers a one-time rollback to the backup when startup fails. The **Engine log level** is a configuration setting and needs that restart to take effect. External file changes are detected before either action. Logs are read from the engine's `logs` directory and can be followed without locking the service's file; the Logs-tab **View filter** only changes displayed lines and never changes engine verbosity.

Release output is written to `bin\exe\<x86|x64|ARM64>\<Debug|Release>\`. Restore, build, and test from a Visual Studio developer shell with:

```powershell
nuget restore ProxiFyre.Configuration\packages.config -PackagesDirectory packages -NonInteractive
nuget restore ProxiFyre\packages.config -PackagesDirectory packages -NonInteractive
nuget restore ProxiFyre.Tests\packages.config -PackagesDirectory packages -NonInteractive
msbuild ProxiFyreSetupBootstrapper\ProxiFyreSetupBootstrapper.vcxproj -t:Restore -v:minimal -p:RestoreLockedMode=true -p:RestoreConfigFile="$PWD\NuGet.Installer.Config"
msbuild ProxiFyreSetupEngineExtension\ProxiFyreSetupEngineExtension.vcxproj -t:Restore -v:minimal -p:RestoreLockedMode=true -p:RestoreConfigFile="$PWD\NuGet.Installer.Config"
dotnet restore ProxiFyre.Installer\ProxiFyre.Installer.wixproj --configfile NuGet.Installer.Config --locked-mode
dotnet restore ProxiFyre.Bundle\ProxiFyre.Bundle.wixproj --configfile NuGet.Installer.Config --locked-mode
msbuild socksify.sln -t:Rebuild -v:minimal -p:Configuration=Release -p:Platform=x64 -p:Version=2.5.0 -p:Repository=wiresock/proxifyre
vstest.console.exe bin\tests\x64\Release\ProxiFyre.Tests.dll /TestAdapterPath:packages\NUnit3TestAdapter.4.6.0\build\net462 /Platform:x64
pwsh -File scripts\Build-Installer.ps1 -Platform x64 -Version 2.5.0 -NoRestore
```

Use `x86` in place of `x64` when running on a matching host. Build the ARM64 payload on x64 if the toolchain is installed, but run ARM64 tests only on Windows ARM64. See [docs/gui.md](docs/gui.md) for GUI architecture and behavior, and [docs/installer.md](docs/installer.md) for packaging, deployment, verification, and lifecycle testing.

---

## Build Prerequisites

Before starting the build process, install:

1. **Visual Studio 2022** with the **Desktop development with C++** and **.NET desktop development** workloads, the v143 toolset, an appropriate Windows SDK, and the .NET Framework 4.7.2 targeting pack.
2. **NuGet CLI**, available through `choco install nuget.commandline` or from [nuget.org](https://www.nuget.org/downloads).
3. **vcpkg** and the required Microsoft GSL and Boost.Pool triplets:

   ```powershell
   vcpkg integrate install
   vcpkg install ms-gsl:x86-windows ms-gsl:x64-windows ms-gsl:arm64-windows
   vcpkg install boost-pool:x86-windows boost-pool:x64-windows boost-pool:arm64-windows
   ```

4. **PowerShell 7** and a **.NET SDK** capable of restoring the pinned WiX Toolset 6.0.2 SDK and extensions.

The legacy managed packages restore through NuGet CLI. Installer restore is restricted to `https://api.nuget.org/v3/index.json` by `NuGet.Installer.Config` and the committed package lock files.

---

## Projects

This repository consists of eleven production, UI, test, and packaging projects:

### 1. ndisapi.lib

This is an adopted Windows Packet Filter [NDISAPI](https://github.com/wiresock/ndisapi) static library project.

### 2. socksify

This project is a .Net C++/CLI class library that implements the local SOCKS5 router functionality.

### 3. ProxiFyre

This is a .Net-based Windows console application that employs the functionality provided by the socksify .Net C++/CLI class library.

### 4. ProxiFyre.Configuration

This .NET Framework 4.7.2 class library contains the shared configuration models, forward-compatible JSON serialization, normalization, structured validation, fingerprints, and atomic persistence used by both the engine and GUI. It has no dependency on `socksify`.

### 5. ProxiFyreUI

This .NET Framework 4.7.2 Windows Forms assembly edits configuration and manages the existing Windows service. It depends only on `ProxiFyre.Configuration` and Windows framework APIs; it is not an in-process proxy engine.

### 6. ProxiFyreUILauncher

This native architecture-specific host establishes the UI's DLL-loading, CLR-environment, module-allow-list, fixed-configuration-hash, and payload-lease boundary before starting `ProxiFyreUI.Managed.dll`.

### 7. ProxiFyre.Tests

This project contains automated configuration, persistence, path-handling, workspace-state, rollback, and diagnostics-redaction tests and does not require the native driver or a live service.

### 8. ProxiFyre.Installer

This WiX Toolset 6.0.2 project builds the architecture-specific MSI containing the engine, GUI, service definition, shortcuts, protected install-directory ACL, and declarative firewall rules.

### 9. ProxiFyre.Bundle

This WiX Toolset 6.0.2 Burn project builds the user-facing setup executable that conditionally acquires the pinned official Visual C++ runtime and Windows Packet Filter prerequisites before chaining the ProxiFyre MSI.

### 10. ProxiFyreSetupBootstrapper

This architecture-specific, static-runtime WixStdBA functions DLL manages the temporary Windows 7 TLS 1.2 setting and the narrowly scoped final Visual C++ acquisition fallback after exhausted WinINet `12029` retries.

### 11. ProxiFyreSetupEngineExtension

This architecture-specific, static-runtime Burn engine extension conservatively repairs only the malformed all-zero WinINet LAN-route state inside the setup process, without rewriting the user's Internet Options.
