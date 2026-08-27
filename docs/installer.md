# ProxiFyre installer and deployment

ProxiFyre ships separate x86, x64, and ARM64 Windows Installer packages. For normal interactive installation, use the architecture-matched `*-setup.exe` bootstrapper. It uses WiX Burn to install the Microsoft Visual C++ runtime and Windows Packet Filter when necessary, then installs the ProxiFyre MSI. The standalone MSI is intended for managed deployment or offline environments where both prerequisites are already present.

ProxiFyre's first-party binaries, MSI, and bootstrapper are deliberately unsigned. Windows can therefore display **Unknown publisher** in SmartScreen or the elevation prompt. Verify the published SHA-256 checksum before elevation. Third-party prerequisite packages retain their upstream signatures; packaging validates those signatures together with pinned hashes without treating them as a first-party publisher identity.

Release builds produce their final artifacts directly. They do not require a code-signing certificate, certificate-store setup, signing secrets, timestamp services, or a post-build archive-replacement pass.

## Toolset and project layout

The packaging uses WiX Toolset **6.0.2** through pinned SDK-style projects:

- `ProxiFyre.Installer/ProxiFyre.Installer.wixproj` builds the per-architecture MSI.
- `ProxiFyre.Bundle/ProxiFyre.Bundle.wixproj` builds the per-architecture Burn bootstrapper.
- `ProxiFyreSetupBootstrapper/ProxiFyreSetupBootstrapper.vcxproj` builds the architecture-matched, static-runtime WixStdBA functions DLL used for Windows 7 HTTPS acquisition.
- `ProxiFyreSetupEngineExtension/ProxiFyreSetupEngineExtension.vcxproj` builds the architecture-matched, static-runtime extension that runs inside Burn's engine process and repairs one malformed WinINet configuration without changing Internet Options.
- `scripts/Build-Installer.ps1` validates and stages a closed runtime payload, validates both prerequisite sources, builds both packages, and writes SHA-256 sidecars.
- `scripts/Test-InstallerPackage.ps1` statically inspects the MSI database.
- `scripts/Test-BundlePackage.ps1` extracts and verifies the Burn manifest, prerequisite metadata, chain order, custom window icon, native bootstrapper-functions payload, and exact engine-extension payload, exports, architecture, and static-runtime dependency set.
- `scripts/Test-SetupEngineExtensionSource.ps1` guards the extension's process-scoped non-NULL WinINet call and rejects global WinINet refreshes or registry writes.
- `scripts/Test-UnsignedArtifacts.ps1` rejects Authenticode signatures on ProxiFyre's first-party release modules and packages.

WiX 6 was selected because its SDK-style projects build cleanly from the Visual Studio 2022/.NET SDK environment, and its maintained Burn, Firewall, UI, and Util extensions cover the required bootstrapper, declarative firewall, feature-selection, and prerequisite searches. Package lock files and `NuGet.Installer.Config` pin restoration to the reviewed WiX 6.0.2 inputs.

The MSI/bootstrapper model keeps Windows Installer deterministic: the MSI never downloads or launches another installer through a custom action. Burn owns acquisition and chaining, while the MSI remains independently deployable when administrators have already provisioned both prerequisites.

WiX 6 runs WixStdBA in a separate process, whose window does not inherit `Bundle/@IconSourceFile`. ProxiFyre therefore supplies a custom copy of the WiX hyperlink-license theme whose `Window/@IconFile` references the canonical multi-size `ProxiFyre.ico` payload. Package inspection checks both the theme reference and the extracted icon bytes so the setup title bar and taskbar retain the application branding, including on Windows 7.

## Architecture-specific artifacts

For version `2.4.0`, the packaging script produces these files beneath `bin\installer\<x86|x64|ARM64>\Release\`:

```text
ProxiFyre-2.4.0-win-x86.msi
ProxiFyre-2.4.0-win-x86.msi.sha256
ProxiFyre-2.4.0-win-x86-setup.exe
ProxiFyre-2.4.0-win-x86-setup.exe.sha256
```

The x64 and ARM64 directories use `x64` and `arm64` in the corresponding filenames. Use the package matching the machine's native Windows architecture. The bootstrapper checks that architecture before acquisition because Windows Packet Filter is a kernel driver; for example, the x86 setup deliberately does not use Windows' x86 emulation on an x64 machine. All five first-party architecture-bound PE files (`ProxiFyre.exe`, the native UI host, both managed assemblies, and `socksify.dll`) are checked against the requested architecture before packaging.

WiX materializes the verified, uncompressed Visual C++ and Windows Packet Filter source payloads while linking the bundle. The packaging script confines those layout byproducts to its guarded temporary staging directory and deletes them after validation. The output directory therefore contains only the four `ProxiFyre-*` files above, and setup must acquire missing prerequisites from their pinned official URLs.

## Windows 7 baseline

Windows 7 is supported only with Service Pack 1. Both setup and the standalone MSI reject Windows 7 RTM before acquiring or installing prerequisites. Before testing on Windows 7 SP1, install the current servicing-stack and SHA-2 support updates available for that image and reboot. In particular, [Microsoft's SHA-2 guidance](https://support.microsoft.com/en-us/topic/2019-sha-2-code-signing-support-requirement-for-windows-and-wsus-64d1c82d-31ee-c273-3930-69a4cde8e64f) documents KB4490628 and KB4474419 (or superseding updates) as the servicing baseline for post-2019 SHA-2 updates; this is a recommended fully patched baseline, not the cause of the Visual C++ detection failure fixed here.

The pinned Visual C++ redistributable carries [the Universal CRT update](https://support.microsoft.com/en-us/servicing/os/windows/2020/04/update-for-universal-c-runtime-in-windows) needed by its runtime on Windows 7. If that prerequisite reports that a reboot is required, Burn schedules the reboot and the installation must be retried or completed after Windows restarts. VM validation must therefore include a clean Windows 7 SP1 x64 image, prerequisite installation, any requested reboot, and a second setup run.

Burn uses the current user's WinINet protocol settings for remote payloads. On Windows 7 only, immediately before an HTTPS prerequisite acquisition, ProxiFyre's native setup-functions DLL temporarily adds the TLS 1.2 bit to `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\SecureProtocols`. It records whether the value originally existed and its exact contents, restores that state when caching completes or setup exits, and avoids overwriting a concurrent Internet Options change. The helper uses the static C++ runtime so it can run before the Visual C++ prerequisite is present. Later Windows versions and cache-only/local installation paths are unchanged.

Some fully patched Windows 7 systems still cannot negotiate with Microsoft's current Visual C++ CDN over HTTPS: WinINet reaches the host but returns error `12029`, while the same machine can complete other HTTPS acquisitions. A missing `VisualCppRuntime` download always gets WixStdBA's normal HTTPS attempts first. On Windows 7 only, after those retries are exhausted with `12029` for that exact package and payload, the setup-functions DLL asks Burn for one final acquisition attempt after replacing only the `https` scheme with `http` on the same `download.visualstudio.microsoft.com/download/pr/` content-addressed URL. It does not use HTTP for another error, a cached/local payload, another package or payload, an unexpected host/path, or Windows 8 and later. If the final HTTP acquisition or its digest verification fails, the helper suppresses another acquisition attempt. The URL embedded in the bundle remains Microsoft's HTTPS URL.

This legacy transport is intentionally narrow and does not make the payload trust depend on HTTP. The bundle binds the exact byte length and SHA-512 of the Microsoft-signed file, and the build separately verifies its SHA-256, SHA-512, version, and Microsoft Authenticode signature. Burn verifies the embedded SHA-512 before executing the downloaded file, so modified or substituted bytes fail closed. An unencrypted intermediary can still observe or block the Windows 7 download, but cannot supply a different executable that Burn will accept.

WiX 6 hosts WixStdBA and its functions DLL outside the Burn engine process, so proxy information set there cannot affect Burn's downloader. ProxiFyre therefore embeds a second, minimal BootstrapperExtension that WiX loads directly into the engine process. It handles only the invalid configuration where both `INTERNET_PER_CONN_FLAGS_UI` and `INTERNET_PER_CONN_FLAGS` are zero even though the machine is on an online LAN. Before applying anything, it also requires `ProxyEnable` to be an explicit zero DWORD; raw `ProxyServer` and `AutoConfigURL` values to be missing or exactly one-NUL `REG_SZ` values; `ProxySettingsPerUser` policy to be missing or exactly DWORD `1`; and no proxy, PAC, or automatic-discovery intent from either the WinINet API or `AutoDetect`. Both `DefaultConnectionSettings` and `SavedLegacySettings` must exist in one of the two recognized IE connection-blob formats (`0x3C` or `0x46` marker), contain only zero or DIRECT route flags, and have bounded empty embedded proxy and automatic-configuration strings. Unknown markers or flag bits, truncated length-prefixed strings, or any missing, malformed, policy-controlled, proxy, PAC, WPAD, modem, offline, or ambiguous state leaves normal Burn behavior untouched.

When every guard passes, the extension opens a non-NULL WinINet root handle, repeats the complete read-only guard to catch a route or policy change, and only then sets `INTERNET_PER_CONN_FLAGS=PROXY_TYPE_DIRECT` on that handle. [Microsoft documents that form](https://learn.microsoft.com/en-us/windows/win32/wininet/option-flags#internet_option_per_connection_option) as changing proxy information for the current process and retaining it after that handle closes. Burn's subsequent `INTERNET_OPEN_TYPE_PRECONFIG` sessions therefore use DIRECT, while other processes and the user's registry-backed Internet Options remain unchanged. Query or update failures are logged and fail open; the setup continues with Burn's normal acquisition behavior.

The Windows 7 TLS hook addresses only the legacy protocol default, while the engine hook addresses only the exact all-zero connection-flags state. Neither can repair a missing route, blocked firewall, unusable configured proxy, certificate-trust failure, or unreachable upstream server. A download log with HTTP status `0` and WinINet error `12029` should still be diagnosed as a connection-layer failure when neither narrow condition applies or the corresponding workaround does not resolve it.

## MSI contents and behavior

The MSI installs the following closed file set into the architecture-appropriate per-machine Program Files `ProxiFyre` directory:

```text
ProxiFyre.exe
ProxiFyre.exe.config
ProxiFyreUI.exe
ProxiFyreUI.exe.config
ProxiFyreUI.Managed.dll
ProxiFyre.Configuration.dll
socksify.dll
Newtonsoft.Json.dll
NLog.dll
Topshelf.dll
NLog.config
app-config.sample.json
```

The live `app-config.json`, `app-config.json.bak`, and `logs` directory are intentionally absent from the MSI File table. They are runtime/user data and remain in place across repair, major upgrade, and uninstall. `app-config.sample.json` and the executable configuration files are product files, so Windows Installer updates or removes those files normally. GUI preferences under `%LocalAppData%\ProxiFyreUI` are also outside the MSI.

The installer applies a protected application-directory ACL: `SYSTEM` and built-in Administrators receive full control, while standard users receive read and execute access. This supports the GUI and service payload-integrity checks without attempting to retrofit security onto a user-controlled extracted directory.

Add/Remove Programs identifies the product as **ProxiFyre**, manufacturer **NT KERNEL**, and includes project, support, update, and application-icon metadata. The required all-users Start Menu shortcut and the selectable shared-desktop shortcut both launch `ProxiFyreUI.exe`; the service executable is not presented as the normal user entry point.

### Service

The MSI declaratively installs:

- service name `ProxiFyreService`;
- display name `ProxiFyre Service`;
- executable `ProxiFyre.exe` from the installed directory;
- account `LocalSystem`;
- start type **demand/manual**;
- error control `normal`;
- service dependency `NDISRD`.

The installer deliberately does not start the service. A new installation has no live proxy configuration yet, so the user first opens ProxiFyreUI, creates or reviews `app-config.json`, and starts the service from the GUI. During uninstall Windows Installer stops the service, waits for it, and removes only the `ProxiFyreService` registration.

### Firewall rules

The engine creates dynamically allocated IPv4 and IPv6 TCP and UDP listeners bound to the unspecified local addresses. Windows Packet Filter redirects selected local flows into those listeners, so fixed port rules would be incomplete and opening arbitrary global ports would be broader than necessary. The WiX Firewall extension therefore owns exactly two inbound, program-scoped allow rules:

| Rule | Program | Direction | Protocol | Ports | Profiles | Remote scope | Edge traversal |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ProxiFyre (TCP-In)` | installed `ProxiFyre.exe` | Inbound | TCP | Any/dynamic | Domain, Private, Public | Any | Deny |
| `ProxiFyre (UDP-In)` | installed `ProxiFyre.exe` | Inbound | UDP | Any/dynamic | Domain, Private, Public | Any | Deny |

No rule targets `ProxiFyreUI.exe`, no outbound rule is added, and no standalone port is opened. These rules are components of the MSI: repair is idempotent, a major upgrade updates them with the engine component, and uninstall removes only these ProxiFyre-owned rules. The installer does not invoke `netsh`, PowerShell, or a firewall custom action.

## Microsoft Visual C++ runtime prerequisite

`socksify.dll` is a C++/CLI module built with the Visual Studio 2022 v143 toolset. Burn therefore chains the architecture-matched [Microsoft Visual C++ 2015-2022 Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170) before Windows Packet Filter and ProxiFyre. Version **14.44.35211.0** is pinned rather than following Microsoft's moving `aka.ms/vc14` links, so an already-published bootstrapper retains the exact payload identity and compatible operating-system floor it was tested against.

| Architecture | Official asset | Bytes | Pinned SHA-256 |
| --- | --- | ---: | --- |
| x86 | `VC_redist.x86.exe` | 13953392 | `0c09f2611660441084ce0df425c51c11e147e6447963c3690f97e0b25c55ed64` |
| x64 | `VC_redist.x64.exe` | 25635768 | `cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b` |
| ARM64 | `VC_redist.arm64.exe` | 11722336 | `5139e1440c3a20b92153a4db561c069a0175aaf76c276c3e5b6f56099edcf4b0` |

At build time the packaging script downloads the pinned asset over HTTPS from its content-addressed `download.visualstudio.microsoft.com` URL, or accepts it through `-VisualCppRedistributablePath`. It requires the exact length, SHA-256, SHA-512, file/product version, and a currently valid Microsoft Corporation Authenticode signature. It also requires the official URL path to contain that SHA-256 and filename. The third-party executable remains an external Burn payload; it is not committed to this repository or embedded in setup. At installation time, only the narrowly scoped Windows 7 compatibility path described above changes the transport scheme; newer Windows systems use the embedded HTTPS URL.

At installation time Burn reads Microsoft's `HKLM\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\<architecture>` values and checks native `ucrtbase.dll`, `msvcp140.dll`, `msvcp140_atomic_wait.dll`, `vcruntime140.dll`, and—on x64—`vcruntime140_1.dll` at the same floors used by the pinned VC redistributable. A complete compatible 14.44.35211-or-newer DLL set is skipped even if registration is absent. A missing or stale file forces the redistributable to run: current registration selects `/repair`, while missing or old registration selects `/install`. Burn verifies the SHA-512 bound into setup and runs the package quietly as a vital, permanent, shared machine prerequisite. A normal success continues the chain; a restart-required result stops before the ProxiFyre MSI so pending DLL replacements cannot trip its launch condition, and setup succeeds when rerun after Windows restarts. A conflicting newer package is not accepted as success when the required files remain incomplete. Any other result also stops the chain. ProxiFyre never uninstalls this shared runtime.

The standalone MSI cannot acquire the runtime. It performs declarative version searches for native `ucrtbase.dll` plus the architecture-specific VC DLLs in the Windows system directory and exits with an actionable message if the complete dependency is unavailable. x86 searches the native x86 `SystemFolder`; x64 and ARM64 search `System64Folder`, avoiding 32-bit filesystem redirection. Windows Installer compares file language when a file version exactly equals `Signature.MinVersion`, so the MSI encodes the language-independent VC minimum as the immediately preceding four-part value, `14.44.35210.65535`, and the UCRT minimum as `10.0.10239.65535`. The effective and user-facing requirements remain **14.44.35211.0** and **10.0.10240.0** respectively. This catches a missing or incomplete runtime even if stale registry detection exists.

When the ProxiFyre bundle chains the MSI, Burn sets `BURNMSIINSTALL=1` and the bundle adds `PROXIFYRE_SETUP_CHAIN=1`; the MSI requires both markers before skipping only this redundant Visual C++ launch condition. Burn has already checked the same native file set and version floors before planning the MSI. If the initial check is false, Burn trusts exit code 0 from the pinned, vital redistributable as successful completion; it does not rerun file searches between chained packages. Restart and failure results stop or suspend the chain before the MSI. A normal standalone deployment and an unrelated Burn wrapper do not receive both markers automatically, so the MSI's own AppSearch prerequisite gate remains active.

Both values are public MSI routing markers, not authentication or security attestation; an explicit `msiexec` command line or transform can supply them. That is acceptable here because the launch condition is an early dependency diagnostic, not an authorization boundary, and the native loader still enforces the runtime dependency when ProxiFyre executes.

Microsoft permits redistribution of listed runtime packages under the applicable [Visual Studio redistribution list](https://learn.microsoft.com/en-us/visualstudio/releases/2022/redistribution) and [license terms](https://visualstudio.microsoft.com/license-terms/). The release publisher must independently confirm that it is a licensed Visual Studio user and that its distribution complies with those terms; a public download URL alone is not a redistribution grant. The package is kept unmodified so Microsoft can service it independently.

## Windows Packet Filter prerequisite

ProxiFyre requires the `NDISRD` service and a compatible Windows Packet Filter 3.x driver. Compatibility is checked at two layers:

1. The installer performs declarative registry and driver-file version searches. It requires an `NDISRD` service registration together with an actual `ndisrd.sys` file version at least `3.6.1.0` and earlier than `4.0.0.0`; stale product/service registration alone is not accepted. As with the VC files, the MSI Signature row uses the language-independent predecessor encoding `3.6.0.65535`, while the effective compatibility floor remains `3.6.1.0`.
2. Before install/start/restart operations, ProxiFyreUI opens `\\.\NDISRD` without requesting read or write access and issues `IOCTL_NDISRD_GET_VERSION`. Runtime use requires API major `3` and API minor `0x0601` or newer. This active-device check catches custom or unexpectedly versioned drivers that satisfy the installer's file-version range but do not expose the API ProxiFyre uses.

An installed-but-stopped `NDISRD` service is valid. The MSI records it as a service dependency, allowing the Service Control Manager to start it when `ProxiFyreService` is started.

### Burn acquisition and verification

The bootstrapper is built against the official Windows Packet Filter **3.6.2.1** MSI assets published in the upstream [`v3.6.2` release](https://github.com/wiresock/ndisapi/releases/tag/v3.6.2):

| Architecture | Official asset | Bytes | Pinned SHA-256 |
| --- | --- | ---: | --- |
| x86 | `Windows.Packet.Filter.3.6.2.1.x86.msi` | 786432 | `ff882c295f9bb0c4465b179e912ad2d2c41eadc053142bd2f125f49a85ee4e1f` |
| x64 | `Windows.Packet.Filter.3.6.2.1.x64.msi` | 819200 | `9c388c0b7f189f7fa98720bae2caecf7d64f30910838b80b438ecf8956b8502c` |
| ARM64 | `Windows.Packet.Filter.3.6.2.1.ARM64.msi` | 745472 | `b13c6832c9e5c0c14948bbf5c17ccbe65dff55c0f6069df01494d97ebd1f3d69` |

The build performs the following flow:

1. Download the architecture-matched MSI from the versioned asset URL under `https://github.com/wiresock/ndisapi/releases/download/v3.6.2/`, or accept the same asset through `-WindowsPacketFilterMsiPath`.
2. Require the exact byte length and pinned SHA-256 shown above.
3. Require a valid upstream Authenticode signature on that third-party MSI.
4. Give the validated MSI to WiX at build time so Burn records its package identity and remote-payload metadata/digest.
5. Mark the prerequisite uncompressed and point it at the same official, versioned URL. The Windows Packet Filter binary is not committed to this repository or embedded in the ProxiFyre bootstrapper.

At installation time Burn checks the `NDISRD` registration and native `System32\drivers\ndisrd.sys` version. If the compatible range is already present, Burn skips the prerequisite. Otherwise it downloads the official architecture-matched MSI, verifies the acquired bytes against the payload metadata bound into the bootstrapper, installs it as a vital package, and continues to the ProxiFyre MSI. The ProxiFyre MSI repeats its declarative prerequisite condition, providing a second presence/version check before product installation proceeds.

If acquisition is impossible, the remote payload is modified, the upstream installer fails, or the user cancels it, the vital prerequisite stops the chain before ProxiFyre is installed. On an offline machine, manually install both missing architecture-matched prerequisites and rerun the bootstrapper, or deploy the standalone ProxiFyre MSI after confirming the compatible runtime and driver are present. Burn can also use prerequisite payloads already present in its package cache.

Windows Packet Filter is machine-wide and can be shared by other software. Its Burn package is permanent, so uninstalling ProxiFyre does **not** remove or downgrade Windows Packet Filter, even when the ProxiFyre bootstrapper originally acquired it.

Windows Packet Filter is a separate third-party product. Its licensing terms and the chosen acquisition/distribution process must be reviewed by anyone redistributing ProxiFyre. This repository's remote-download implementation does not assert or grant redistribution rights.

## Standalone MSI deployment

Use the MSI directly only when the architecture-matched Visual C++ runtime and Windows Packet Filter have already been provisioned:

```powershell
msiexec.exe /i .\ProxiFyre-2.4.0-win-x64.msi
```

On a clean machine without the compatible runtime files or registered driver/file version, the MSI exits with an actionable message directing the user to the setup executable and official prerequisite sources. It does not download prerequisites. x86 and x64 packages require .NET Framework 4.7.2 or later; the ARM64 package requires .NET Framework 4.8.1 or later.

Enterprise deployment can cache and validate the official Visual C++ and Windows Packet Filter packages separately, install them under local policy, and then deploy the ProxiFyre MSI. This is also the deterministic offline path.

## Upgrade, repair, and uninstall

The MSI uses a major-upgrade relationship and rejects downgrades. Release tags and MSI product versions are canonical `vMAJOR.MINOR.PATCH` values; prerelease tags are rejected because Windows Installer's three-part product version cannot preserve SemVer prerelease ordering safely. Use the same processor architecture for an in-place upgrade. A repair or upgrade reconciles the product files, service registration, shortcuts, application-directory ACL, and the two firewall rules without creating duplicate rules.

Because `app-config.json`, its backup, and logs are not Windows Installer components, they survive repair, upgrade, and uninstall. An uninstall removes product files, shortcuts, Add/Remove Programs registration, `ProxiFyreService`, and the two ProxiFyre firewall rules. It leaves the user configuration, backup, logs, GUI preferences, Visual C++ runtime, and Windows Packet Filter in place.

This is the first MSI-based deployment model. An older ZIP/manual installation has no Windows Installer product registration and cannot participate in an automatic major upgrade. Before the first MSI installation, stop and remove a manually registered `ProxiFyreService`, back up `app-config.json`, and remove or relocate the old extracted program files. After installing the matching MSI, restore or copy the configuration into the installed ProxiFyre directory through an elevated process or the GUI. Subsequent matching-architecture MSI releases can use the normal major-upgrade path.

## Building installers

Build prerequisites are Visual Studio 2022 with the C++ desktop and .NET Framework workloads, NuGet, vcpkg dependencies used by the solution, PowerShell 7, and a .NET SDK capable of restoring the pinned WiX packages. Internet access is needed for first-time NuGet restore and, unless validated local sources are supplied, both official prerequisite installers.

From a Visual Studio developer shell:

```powershell
nuget restore .\socksify.sln
msbuild .\ProxiFyreSetupBootstrapper\ProxiFyreSetupBootstrapper.vcxproj -t:Restore -v:minimal -p:RestoreLockedMode=true -p:RestoreConfigFile="$PWD\NuGet.Installer.Config"
msbuild .\ProxiFyreSetupEngineExtension\ProxiFyreSetupEngineExtension.vcxproj -t:Restore -v:minimal -p:RestoreLockedMode=true -p:RestoreConfigFile="$PWD\NuGet.Installer.Config"
msbuild .\socksify.sln -t:Rebuild -v:minimal -p:Configuration=Release -p:Platform=x64 -p:Version=2.4.0
vstest.console.exe .\bin\tests\x64\Release\ProxiFyre.Tests.dll /TestAdapterPath:.\packages\NUnit3TestAdapter.4.6.0\build\net462 /Platform:x64
pwsh -File .\scripts\Build-Installer.ps1 -Platform x64 -Version 2.4.0
```

Repeat with `x86` and `ARM64`. Run architecture-specific tests only on a matching Windows host; ARM64 payloads can be cross-built but ARM64 tests require Windows ARM64. To reuse previously downloaded official prerequisites during packaging:

```powershell
pwsh -File .\scripts\Build-Installer.ps1 `
  -Platform x64 `
  -Version 2.4.0 `
  -WindowsPacketFilterMsiPath C:\staging\Windows.Packet.Filter.3.6.2.1.x64.msi `
  -VisualCppRedistributablePath C:\staging\VC_redist.x64.exe
```

The script applies the same byte-length, SHA-256, SHA-512, version (where applicable), and upstream-signature checks to those local files. Use `-Force` only to replace the four exact outputs for the requested architecture and version.

### Verify an unsigned release artifact

Each MSI and setup executable has a `.sha256` sidecar:

```powershell
$artifact = '.\ProxiFyre-2.4.0-win-x64-setup.exe'
$expected = ((Get-Content "$artifact.sha256" -Raw) -split '\s+')[0].ToLowerInvariant()
$actual = (Get-FileHash $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -cne $expected) { throw "SHA-256 mismatch for $artifact" }
```

A checksum downloaded from the same location detects accidental corruption but is not equivalent to a publisher signature. For stronger provenance, obtain the expected digest through an independently trusted channel or verify it against a trusted release record before accepting the **Unknown publisher** elevation prompt.

## Installer lifecycle validation matrix

Coverage labels used below:

- **Automated/static**: repository tests or MSI-database/package inspection can verify the authoring without changing the test machine.
- **Manual**: execute on a disposable Windows VM with administrator access. Static inspection is not evidence that Windows completed an install, repair, upgrade, or removal.

| Scenario | Expected result | Coverage |
| --- | --- | --- |
| Setup on Windows 7 RTM | Setup exits immediately with an actionable Windows 7 SP1/update message and acquires nothing. | Manual on a disposable VM; the compiled WixStdBA condition is automated/static. |
| Clean online setup on fully updated Windows 7 SP1 with TLS 1.2 initially disabled in Internet Options | Setup enables TLS 1.2 and preserves the normal HTTPS retry budget. Only exhausted VC CDN `12029` retries get one final HTTP attempt of the same content-addressed Microsoft URL, followed by exact SHA-512 verification; WPF remains HTTPS, and setup restores `SecureProtocols` byte-for-byte (including absence) after caching or cancellation. | Manual on a disposable Windows 7 SP1 VM; source-override scoping, error/retry gate, embedded digest, CPU architecture, exports, and static-runtime dependencies of the helper are automated/static. |
| Online setup with WinINet LAN flags malformed as zero, no proxy/PAC/WPAD intent, and prerequisites missing | The engine extension applies DIRECT only inside the Burn process; both pinned payloads download through their platform-specific transports and verify, while a separate process and HKCU/HKLM Internet settings remain byte-for-byte unchanged. | Manual fault-injection VM test; extension embedding, exact validated DLL hash, CPU architecture, exports, system-only dependencies, and separate source safety guards are automated/static. |
| Setup with an explicit proxy, PAC URL, automatic discovery, machine-wide proxy policy, modem/offline route, or any nonzero WinINet connection flag | The engine extension logs a no-op and Burn preserves the configured route; it never forces DIRECT. | Manual matrix test; all conservative gate inputs and absence of registry/global WinINet writes are source-guarded automatically. |
| Setup window branding on Windows 7 | The setup title bar and taskbar use the canonical ProxiFyre icon rather than the generic WixStdBA host icon. | Manual on Windows 7; theme reference and extracted icon identity are automated/static. |
| Clean setup with both prerequisites already installed | Burn skips the Visual C++ and WPF packages; ProxiFyre MSI installs successfully. | Manual; prerequisite version/search authoring is automated/static. |
| ProxiFyre Setup chains the MSI after validating Visual C++ | Burn supplies `BURNMSIINSTALL=1` and the bundle supplies its prerequisite marker; the MSI does not repeat the inconsistent AppSearch launch gate, while all other launch conditions remain active. | Manual; Burn detection and the two-marker MSI bypass are automated/static. |
| Clean standalone MSI with both prerequisites installed | MSI accepts both prerequisites and installs without network acquisition. | Manual; launch-condition presence is automated/static. |
| Standalone MSI with the exact 14.44.35211.0 runtime | MSI finds the architecture-native DLLs and accepts the exact minimum despite their language metadata. | Real x86/x64 AppSearch is automated when an x64 build host has the pinned runtimes; manual on ARM64 and Windows 7. |
| Clean setup without Visual C++ runtime | Burn downloads and verifies 14.44.35211.0, installs it first, then continues through WPF to ProxiFyre. | Manual; URL, source size/hashes/version/signature, exit mapping, and chain order are automated/static at build time. |
| Compatible Visual C++ registration with a missing/stale required DLL | Burn does not trust registration alone; it runs the pinned redistributable in repair mode before continuing. | Manual fault-injection test; native file searches and conditional `/repair` selection are automated/static. |
| Visual C++ installation or repair requires a restart | Burn stops before WPF and the ProxiFyre MSI, reports that Windows must restart, and a setup rerun after restart detects the completed runtime and continues. | Manual in a disposable VM; the chain-stopping `3010` mapping is automated/static. |
| Missing Visual C++ runtime while offline and not cached | Burn reports acquisition failure and does not install ProxiFyre; user can manually install the pinned architecture-matched runtime and retry. | Manual in an isolated offline VM. |
| Visual C++ download is modified | Burn rejects the payload digest and stops before ProxiFyre installation. | Manual fault-injection test; build-time source validation is automated/static. |
| Visual C++ installation fails or is cancelled | The vital prerequisite aborts the chain; ProxiFyre is not installed. | Manual in a disposable VM. |
| Standalone MSI without compatible Visual C++ runtime | MSI exits with the actionable runtime message and makes no product installation. | Manual; file/version-search authoring is automated/static. |
| Clean setup without WPF | Burn downloads and verifies the official 3.6.2.1 package, installs it, and then installs ProxiFyre. | Manual; URL, source size/hash/signature, and chain authoring are automated/static at build time. |
| Missing WPF while offline and not cached | Burn reports acquisition failure and does not install the ProxiFyre MSI; user can manually install WPF and retry. | Manual in an isolated offline VM. |
| WPF download is modified | Burn rejects the payload digest and stops before ProxiFyre installation. | Manual fault-injection test; build-time source digest validation is automated/static. |
| WPF installation fails or is cancelled | The vital prerequisite aborts the chain; ProxiFyre is not installed. | Manual in a disposable VM. |
| Standalone MSI without compatible WPF | MSI exits with the actionable prerequisite message and makes no product installation. | Manual; launch-condition authoring is automated/static. |
| Setup architecture does not match native Windows | Setup exits with an actionable architecture message before acquiring WPF or changing the machine. | Manual on each mismatched host; the compiled WixStdBA condition is automated/static. |
| ProxiFyre service installation | `ProxiFyreService` exists as LocalSystem, demand-start, dependent on `NDISRD`, and remains stopped initially. | Service table is automated/static; actual SCM state is manual. |
| ProxiFyre service startup | After a valid configuration is saved, the GUI starts the service and SCM starts the `NDISRD` dependency as required. | Runtime probe/state logic has automated tests; actual driver/service startup is manual. |
| GUI startup | Start Menu and optional desktop shortcuts launch one elevated `ProxiFyreUI.exe` instance. | Shortcut targets are automated/static; elevation, CLR startup, icon, and single-instance behavior are manual. |
| Firewall rule creation | Exactly one TCP-In and one UDP-In program rule target installed `ProxiFyre.exe` with all profiles and no fixed port. | Firewall table/count/target are automated/static; Windows Firewall state is manual. |
| Repeated setup or MSI repair | Product repair succeeds and firewall-rule counts remain one TCP plus one UDP. | Declarative component ownership is static; repair/idempotence is manual. |
| Upgrade from an earlier matching-architecture MSI | New product files replace old files; service and firewall components reconcile; downgrade is refused. | Major-upgrade authoring is static; two-version upgrade is manual. |
| Transition from a ZIP/manual release | Existing manual service is removed first; configuration is backed up and restored after MSI install. No automatic migration is claimed. | Manual only. |
| Configuration preservation on repair/upgrade | `app-config.json`, `.bak`, logs, and GUI preferences remain byte-for-byte intact. | Their absence from the MSI File table is automated/static; content preservation is manual. |
| Product uninstall | Product files, shortcuts, Add/Remove Programs entry, service, and ProxiFyre firewall rules are removed. | Service/firewall removal authoring is automated/static; actual removal is manual. |
| Service removal | `ProxiFyreService` is stopped, Windows Installer waits for completion, and the service registration no longer exists. | ServiceControl stop/remove/wait authoring is automated/static; actual SCM removal is manual. |
| Firewall-rule removal | Both MSI-owned ProxiFyre rules are absent and unrelated firewall rules remain untouched. | Component ownership is automated/static; actual Windows Firewall state is manual. |
| Configuration preservation on uninstall | Live configuration, backup, logs, and GUI preferences remain. | File-table exclusion is automated/static; filesystem result is manual. |
| Shared prerequisites after uninstall | The Visual C++ runtime, `NDISRD`, and WPF package remain installed and usable by other products. | Both Burn packages' `Permanent=yes` metadata is static; actual retained dependencies are manual. |

For a manual VM pass, record installer logs and verify state with:

```powershell
Get-CimInstance Win32_Service -Filter "Name='ProxiFyreService'" |
  Select-Object Name, StartMode, State, StartName, PathName

$rules = Get-NetFirewallRule `
  -DisplayName 'ProxiFyre (TCP-In)', 'ProxiFyre (UDP-In)'
$rules | Select-Object DisplayName, Direction, Action, Profile, Enabled
$rules | Get-NetFirewallApplicationFilter | Select-Object Program
```

Before repair, upgrade, and uninstall, record SHA-256 hashes of `app-config.json` and `app-config.json.bak` and inventory the logs. After each operation, compare those values, count the two exact firewall display names, query `Get-Service NDISRD`, and inspect the architecture-matched Visual C++ runtime registry key to confirm both shared prerequisites remain.

## Current limitations

- ProxiFyre first-party artifacts have no Authenticode publisher identity and can trigger SmartScreen or **Unknown publisher** prompts.
- SHA-256 sidecars provide useful integrity checks but require a trusted source for the expected digest to provide publisher-level provenance.
- The bootstrapper requires network access when a compatible Visual C++ or Windows Packet Filter package is neither installed nor cached; the MSI itself never downloads prerequisites.
- Installer detection uses the registered service plus driver-file version; the exact active driver API is checked later by ProxiFyreUI before service lifecycle operations.
- The service is not automatically started because the user must first create or validate `app-config.json`.
- A pre-MSI ZIP/manual installation requires a manual migration; major upgrade applies to MSI-installed versions.
- Cross-architecture installation and in-place architecture switching are unsupported; uninstall the old architecture and install the setup matching native Windows.
- Windows 7 must be SP1 and should have the current servicing-stack and SHA-2 support updates installed. The setup compensates for a disabled TLS 1.2 WinINet default during acquisition, but Windows 7 is end-of-life, so this legacy path still needs an explicit disposable-VM pass for each release.
- Full install, repair, upgrade, firewall, driver, and uninstall behavior requires disposable-machine validation for every release and architecture.
- Windows Packet Filter licensing and distribution terms remain the distributor's responsibility; this project does not assert redistribution rights.
- Microsoft Visual C++ runtime redistribution is subject to the release publisher's applicable Visual Studio license; the project does not grant that right independently.
