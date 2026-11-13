# ProxiFyre GUI

`ProxiFyreUI.exe` is the native host for ProxiFyre's managed Windows Forms application. Together they edit the engine configuration, control `ProxiFyreService`, and follow the engine log files. The UI is deliberately not a packet-processing host: `ProxiFyre.exe` and the existing `socksify.dll` C++/CLI component remain the networking engine.

## Architecture and trust boundaries

The managed dependency graph is intentionally one-way:

```text
ProxiFyre.exe --------------> ProxiFyre.Configuration.dll
      |
      +---------------------> socksify.dll

ProxiFyreUI.exe (native integrity/CLR host)
      |
      +---------------------> ProxiFyreUI.Managed.dll
                                      |
                                      +--> ProxiFyre.Configuration.dll
                                      +--> Newtonsoft.Json.dll
```

`ProxiFyre.Configuration` contains the JSON models, forward-compatible serialization, normalization, structured validation, fingerprints, and atomic file operations. It has no native dependency. The native `ProxiFyreUI.exe` host validates and leases the complete unsigned managed UI chain and verifies its exact CLR-configuration hash before starting .NET Framework; this prevents a mutable CLR configuration from running code before the managed integrity check. `ProxiFyreUI.Managed.dll` never references or loads `socksify.dll`; it controls the installed service through the Windows Service Control Manager and invokes only the resolved `ProxiFyre.exe` with a fixed `install` or `uninstall` argument.

After payload validation and before constructing the first control, the managed UI verifies that .NET Framework WinForms can resolve its normal default font. If the legacy GDI+ generic-font path fails, it tries installed named Windows UI fonts and then asks GDI to realize the current Windows UI font as TrueType, selects it into a native device context, and creates the managed font directly from that context. This avoids GDI+'s unusable generic-family and `LOGFONT` reconstruction paths before controls such as `DataGridView` are created. Designer typography also uses guarded family construction: healthy systems retain Segoe UI/Consolas styling, while a damaged GDI+ family lookup falls back to the recovered process font.

The GUI requests administrator privileges at startup. This is required to manage a Windows service and to update a configuration beside an engine installed in a protected directory. ProxiFyre's first-party modules and installers are deliberately unsigned and can display **Unknown publisher**. Before loading the CLR, the statically linked native host removes CLR-control environment overrides and removes the working directory from native DLL lookup. On Windows 8 and newer it additionally restricts the default native DLL search path to the Windows system directory. Windows 7 deliberately retains the standard application/System32 order because that operating system's GDI+ font initialization is broken after `SetDefaultDllDirectories`; security-sensitive system modules are still loaded by absolute System32 path. The host also rejects unexpected app-local executable modules, verifies the exact CLR-configuration hash, and holds the required managed files plus every normal directory component open without write/delete sharing. In Release builds, the native host also requires its own file, every managed payload file, and the complete directory chain to be on a directly mounted fixed volume, owned by `SYSTEM`, `Administrators`, or `TrustedInstaller`, with ACLs that do not grant standard users mutation rights. An inheritable `CREATOR OWNER` entry on the payload directory, such as the one every new Program Files subdirectory inherits, is accepted: it only grants the owner of a newly created item rights that ownership already implies, and every payload file must still have a trusted owner. It is rejected when the directory also carries an inheritable `OWNER RIGHTS` entry, because that entry deliberately removes the implicit rights of new items' owners; an `OWNER RIGHTS` entry that applies only to the directory itself does not change this. Production service operations require the engine filename and version-resource identity, verify fixed engine/logging configuration hashes, and hold the complete app-local payload and path through process or SCM startup. Release service install, start, restart, and uninstall apply the same fixed-volume, owner, ACL, reparse-point, loader-redirection, and executable-module restrictions. The WiX MSI creates that protected per-machine directory; the GUI deliberately refuses to rewrite a user-controlled directory in place because an attacker could retain a pre-existing write or permission-control handle after the ACL change. Debug builds retain an explicit developer-directory policy. Third-party dependencies may retain signatures from their upstream publishers, but ProxiFyre does not require or replace them. SOCKS5 credentials remain in the existing plaintext JSON schema because the engine must be able to read them. The GUI masks passwords and omits them from logs, tooltips, and diagnostics.

The primary service controls include explicit install and uninstall actions. The MSI normally installs `ProxiFyreService` with demand/manual start; the GUI can restore a missing registration from the protected installed payload. **Uninstall service…** requires confirmation, stops a running service first, and removes only the Windows service registration; it does not uninstall the MSI, shortcuts, firewall rules, or Windows Packet Filter. `app-config.json`, its backup, and engine logs are preserved. If another service-management handle delays removal, the GUI reports the Windows deletion-pending state instead of treating the successful uninstall request as a failure. The same service-only action remains available under **Settings / Diagnostics**. Use Windows Apps/Installed apps for a complete product uninstall.

## Engine and configuration discovery

The GUI resolves the engine in this order:

1. The registered image path for `ProxiFyreService`, when installed.
2. `ProxiFyre.exe` beside `ProxiFyreUI.exe`.
3. The last explicitly selected engine saved in `%LocalAppData%\ProxiFyreUI\ui-settings.json`.
4. A file selected by the user.

Quoted service image paths and a fixed trailing service argument are parsed without executing the registered command line. Relative registrations and unquoted executable paths containing whitespace are rejected because the GUI and Windows service manager could resolve them to different executables. A selected file must be named `ProxiFyre.exe`. The engine, configuration, and log paths are displayed on the Diagnostics tab.

The live configuration is always `app-config.json` beside the resolved engine. GUI-only preferences are never written into that file. If the live file is missing, the GUI can initialize it from `app-config.sample.json` beside the engine or GUI; otherwise it starts with a blank model that must gain a valid proxy rule before the service can start.

## Editing rules

Routing rules are evaluated from top to bottom, and the first match wins. Use **Move Up** and **Move Down** to change the serialized order. The dedicated catch-all option is shown as **All unmatched applications** and is serialized as one explicit empty string in `appNames`. Put it last: an earlier catch-all shadows every later rule, and the validator reports that condition immediately.

Application entries without a slash match an executable name. Entries containing a slash or backslash match against the full path. Exclusions are separate from routing entries, take priority over catch-all routing, and deliberately use permissive process-name or path-substring matching. Exclude the carrier process of another VPN or tunnel when necessary to avoid recursive routing.

Each newly edited rule requires:

- a hostname or IPv4 upstream plus a port from 1 through 65535;
- both or neither of username and password;
- at least one of TCP or UDP;
- at least one of IPv4 or IPv6;
- a canonical transport of plain TCP or TLS.

The current engine reaches its upstream SOCKS5 server over IPv4, so an IPv6-literal upstream is rejected. Destination traffic may still use IPv4, IPv6, or both.

SOCKS5-over-TLS protects the TCP control connection (including the UDP `ASSOCIATE` negotiation); it does not mean the SOCKS5 UDP relay payload is wrapped in that TLS stream. `tlsServerName` defaults to the endpoint host. Certificate fingerprints are normalized by removing whitespace, colons, and hyphens and must contain exactly 64 hexadecimal characters. A pinned leaf certificate can authenticate a self-signed lab endpoint. **Allow invalid certificate** disables normal certificate validation, requires an explicit confirmation, and is particularly dangerous without a pin.

### DNS routing

The **DNS routing** group on the **Settings / Diagnostics** tab edits the global `dns` section described in the [configuration reference](configuration.md#dns-routing). **DNS mode** selects `Direct` (default) or `Proxy`. In `Direct` mode the **DNS proxy** and **Server override** fields are disabled but keep their values, so switching modes does not lose them. **DNS proxy** lists the routing rules by position, endpoint, and applications; selecting one stores that rule's stable `id` in `dns.proxyId`, assigning an id such as `proxy-1` to the rule if it has none, its id is invalid, or another rule uses the same id. Switching the mode to `Proxy` does the same for the rule already shown. When several rules share the referenced id, the selector shows the first, which is the rule validation and the service use. Ids that DNS does not use and that are invalid or repeated are reported as warnings and removed on the next save. The reference therefore survives **Move Up**/**Move Down**, editing, saving, and reloading. **Duplicate** clears the id on the copy. If the referenced rule is removed, the selector shows the missing id and validation fails until another rule is chosen; the GUI never substitutes a different proxy. Validation also requires the selected rule to support both TCP and UDP and checks that the server override is an IP literal whose address family the rule accepts. Like other engine settings, DNS changes take effect after **Apply & Restart**.

## Save, apply, conflicts, and recovery

**Save** validates the complete model and refuses to write when errors exist. It writes a temporary file in the configuration directory, flushes it, preserves the prior live file as `app-config.json.bak`, and replaces the live file atomically. If the service is running, the UI reports that a restart is still required.

**Apply & Restart** performs the same validated atomic save, then stops and starts the installed service while waiting for the actual SCM states. It reports success only when the SCM reports `Running`. The **Engine log level** setting is part of `app-config.json`, so changing the service's logging verbosity requires **Apply & Restart** (or a later manual service restart). Before changing service state, the GUI opens `\\.\NDISRD` with no requested read/write access and queries `IOCTL_NDISRD_GET_VERSION`. It accepts API major `3` with API minor `0x0601` or newer; an installed-but-stopped service can be started by SCM through the declared dependency. If Windows Packet Filter is missing or an active driver is incompatible, the saved configuration remains pending and the GUI reports the dependency immediately without stopping the service or offering a configuration rollback. Other startup failures may still offer to restore the backup and perform at most one controlled restart using the restored configuration.

The workspace fingerprints the file when it is loaded. If another process changes it before a save, the GUI offers to reload, explicitly overwrite, or cancel. It never silently overwrites an externally modified configuration.

## Logs and notification area

Engine logs are stored in the `logs` directory beside `ProxiFyre.exe`. The active file is `logfile.txt`. At 50 MiB (52,428,800 bytes), NLog rotates it into `logs/archive`, keeping three archives named `logfile_0.txt` (newest) through `logfile_2.txt` (oldest). The active file plus archives normally occupy up to approximately 200 MiB; the size threshold is not a strict disk quota, and an unusually large individual log event can exceed it. `Info` records service lifecycle and configuration summaries; `Debug` additionally records per-connection routing, proxy negotiation, and relay details.

Older releases wrote `logfile_yyyy-MM-dd.txt` files. Those files are preserved during upgrades and are outside the new retention policy. After stopping the engine, move any historical logs you want to keep out of the `logs` directory and delete the remaining old dated files if you need to reclaim their space. Restart the engine afterward. The application does not automatically delete those historical diagnostics.

The Logs tab reads a bounded tail with read/write/delete sharing, follows appended content incrementally, and recovers when rotation replaces the active file, or after creation, truncation, or temporary locks. Rotation resets the displayed view to the new active file. Lines not yet read when the old file is archived are not replayed; inspect the retained archives when you need that history. Archives in the subdirectory are not selected as the active log. **Open log file** launches the file currently being followed, or the newest top-level `.log`/`.txt` file when following is paused. The Logs-tab **View filter** changes only which already-written lines the GUI displays; it does not change the engine's logging verbosity or configuration and does not require a restart. Follow/pause, text filtering, copy, reload, clear-view, and open-folder actions affect only the viewer; clearing the view does not delete log files.

The Release GUI verifies the shipped `NLog.config` bytes against a fixed integrity hash. Do not edit that file to adjust retention; a modified file fails engine validation. Change logging verbosity with **Engine log level** and **Apply & Restart**. Retention controls are not exposed in the GUI.

Closing the window hides it in the notification area. The tray menu reflects the real service state and provides open, start, stop, restart, logs, and exit actions. Within each Windows identity and terminal session, ProxiFyre permits one GUI instance; launching it again restores and activates the existing window, including a tray-hidden window. Exiting the GUI does not stop the engine service. Unsaved edits are checked before reload, engine changes, or application exit.

## Build and test

Prerequisites are Visual Studio 2022 with the .NET Framework and C++ desktop workloads, NuGet, vcpkg, the repository's `ms-gsl` and `boost-pool` triplets, PowerShell 7, and a .NET SDK for the pinned WiX Toolset 6.0.2 packages.

From a Visual Studio developer shell:

```powershell
git submodule update --init   # external/ndisapi (Windows Packet Filter API)
nuget restore ProxiFyre.Configuration\packages.config -PackagesDirectory packages -NonInteractive
nuget restore ProxiFyre\packages.config -PackagesDirectory packages -NonInteractive
nuget restore ProxiFyre.Tests\packages.config -PackagesDirectory packages -NonInteractive

msbuild ProxiFyreSetupBootstrapper\ProxiFyreSetupBootstrapper.vcxproj -t:Restore -v:minimal -p:RestoreLockedMode=true -p:RestoreConfigFile="$PWD\NuGet.Installer.Config"
msbuild ProxiFyreSetupEngineExtension\ProxiFyreSetupEngineExtension.vcxproj -t:Restore -v:minimal -p:RestoreLockedMode=true -p:RestoreConfigFile="$PWD\NuGet.Installer.Config"
dotnet restore ProxiFyre.Installer\ProxiFyre.Installer.wixproj --configfile NuGet.Installer.Config --locked-mode
dotnet restore ProxiFyre.Bundle\ProxiFyre.Bundle.wixproj --configfile NuGet.Installer.Config --locked-mode

msbuild socksify.sln -t:Rebuild -v:minimal -p:Configuration=Release -p:Platform=x64 -p:Version=2.6.4
vstest.console.exe bin\tests\x64\Release\ProxiFyre.Tests.dll /TestAdapterPath:packages\NUnit3TestAdapter.4.6.0\build\net462 /Platform:x64
pwsh -File scripts\Build-Installer.ps1 -Platform x64 -Version 2.6.4 -NoRestore
```

The legacy `packages.config` projects, the two native setup helpers, and the two WiX projects are restored separately so their package-management models and locked installer dependency graph do not interfere with one another. `Directory.Build.props` is the repository version source; the explicit `2.6.4` arguments above make release validation unambiguous and must match it. Replace `x64` with `x86` for tests on a matching host. The ARM64 payload can be cross-built when the Visual Studio toolchain is installed, but its tests must run on Windows ARM64 rather than an x64 CI host. Architecture-specific runtime files, including `ProxiFyre.exe`, the native `ProxiFyreUI.exe` host, `ProxiFyreUI.Managed.dll`, `socksify.dll`, `ProxiFyre.Configuration.dll`, managed dependencies, and the sample configuration, are placed in:

```text
bin\exe\<architecture>\Release\
```

That Release directory feeds installer construction and release-ZIP creation; it is not a developer launch directory. The ZIP contains the application payload only. It is not an offline installer and does not install or detect the Visual C++ runtime, Windows Packet Filter, service registration, shortcuts, or firewall rules. Normal distribution uses the architecture-matched online `*-setup.exe`, which downloads and verifies missing prerequisites before installing the embedded MSI.

Because the first-party payload is unsigned, the elevated Release GUI refuses to load managed code from a user-writable extraction such as Downloads, `%TEMP%`, or the repository build tree. Follow the [protected ZIP staging procedure](zip-staging.md) for exact ownership and ACL requirements and a copyable Windows PowerShell script. Create and protect a fresh destination before extracting into it; do not extract into a user-writable directory and tighten its ACL afterward, because existing mutation handles cannot be revoked. Use a Debug build for normal developer-tree testing.

Tests write to `bin\tests\<architecture>\<configuration>\` and do not require the packet-filter driver, an installed service, administrator access, or a live SOCKS5 endpoint.

The installer build writes the unsigned standalone MSI, unsigned online Burn setup executable, and SHA-256 sidecars to `bin\installer\<architecture>\Release\`. CI separately packages `bin\exe\<architecture>\Release\` as the application ZIP and publishes all three artifact types with checksums. Use setup for normal installation, the MSI for managed or offline deployment only when its prerequisites are already present, and the ZIP only for protected manual staging or payload inspection. See [installer.md](installer.md) for the exact payload, pinned official Visual C++ and Windows Packet Filter acquisition flows, standalone-MSI requirements, firewall rules, upgrade/uninstall semantics, build options, and lifecycle validation matrix.

## Troubleshooting

- **Service not installed:** for an MSI installation, run product repair to reconcile the service and all other components. The GUI's **Install Service** action can restore only the service registration from the resolved protected engine payload.
- **Access denied:** restart the GUI and approve the administrator prompt. Check directory ACLs if the engine is installed outside the normal application directory.
- **ZIP rejected for owner SID:** an individual administrator account is not the built-in Administrators group. `icacls /reset` does not change ownership. Follow the [ZIP staging procedure](zip-staging.md); it sets ownership on the directory and extracted files without weakening launcher checks.
- **UI payload or path rejected:** when an ACL check causes the rejection, review the launcher's **Verification details** for the exact rejected path, trustee SID, ACE mask, prohibited rights, and whether the ACE was inherited. A DACL entry the launcher cannot evaluate, reported as an unsupported, malformed, or unreadable ACE, is rejected by design because it could still grant access; remove it or recreate the directory with the official setup. A standard user having generic all/write, delete/delete-child, or permission/owner-control access to any installation-path ancestor, including `Program Files`, allows path substitution before elevation and must not be bypassed. Have the system administrator restore that Windows directory from the correct operating-system or organizational ACL baseline; do not recursively reset or copy permissions across `Program Files`.
- **Service location is not protected:** the engine and GUI name the rejected path, the trustee, and whether the offending entry is inherited or applies only to new items. An entry the service policy cannot evaluate, such as an audit, alarm, compound, or mandatory-label entry in the DACL, is rejected by design for the same reason; remove it or recreate the directory with the official setup. If a pre-MSI service is installed outside a protected parent, stop and remove its registration, back up `app-config.json`, and exit the GUI. Install the matching architecture through the ProxiFyre WiX setup so Windows Installer creates the protected Program Files directory, then restore the configuration through an elevated process or the GUI. The installed registration takes precedence over Browse, so merely browsing to a new copy does not migrate an existing service.
- **Unknown publisher:** this is expected for ProxiFyre's deliberately unsigned first-party installer and binaries. Verify the release SHA-256 through a trusted source before elevation. Do not confuse a checksum obtained from the same untrusted download with publisher authentication.
- **Windows 7 UI startup failure:** use the current setup build and verify Windows 7 SP1 has current servicing-stack, SHA-2, and .NET Framework 4.7.2 updates. Builds must not call `SetDefaultDllDirectories` before WinForms starts on Windows 7 because an operating-system GDI+ bug then prevents even installed fonts from being constructed. The native host uses the compatible DLL-search policy described above and the managed UI retains its named/GDI font recovery for independently damaged font installations.
- **Configuration invalid:** open the validation details. The GUI will not save or start a new invalid rule set.
- **Saved, restart required:** choose **Apply & Restart** or restart the service after completing related edits.
- **Windows Packet Filter unavailable or incompatible:** rerun the architecture-matched setup while online so Burn can acquire the pinned official 3.6.2.1 package, or install the matching package manually from the [official releases](https://github.com/wiresock/ndisapi/releases) and retry. Restart Windows if requested. The GUI checks the active `NDISRD` API before install/start/restart and does not treat a driver failure as a configuration failure.
- **Firewall rules missing or duplicated:** repair the MSI and verify the exact `ProxiFyre (TCP-In)` and `ProxiFyre (UDP-In)` program rules. Do not disable Windows Firewall or add global port rules.
- **Engine startup failed:** the service may have rejected configuration or encountered another native initialization error. A service that returns to `Stopped` during startup is reported immediately; review recent lines on the Logs tab.
- **No log file yet:** start the service or use **Reload** after the engine creates its `logs` directory. The follower continues checking for creation and rotation; **Open log file** becomes useful as soon as a `.log` or `.txt` file exists.
- **External change detected:** reload to accept the on-disk file, overwrite only if the other edit is known to be obsolete, or cancel and compare both versions first.
- **Recursive timeouts with another VPN:** add the other VPN's carrier/tunnel process to Exclusions.

## GUI manual release validation

This checklist covers the GUI. The [installer lifecycle matrix](installer.md#installer-lifecycle-validation-matrix) separately covers clean prerequisite acquisition, offline/failure paths, MSI repair, firewall idempotence, upgrade, configuration preservation, and uninstall.

On a Windows test machine with the appropriate driver and administrator access:

1. Build and test Release x64, then build x86 and ARM64 when the toolchain is installed.
2. Install the Release payload with setup, or stage the complete Release ZIP in the protected
   fixed-volume location described above. Launch `ProxiFyreUI.exe`, resolve a separately located
   protected engine, and load the sample configuration.
3. Add, edit, duplicate, delete, and reorder rules. Confirm a catch-all saves as `"appNames": [""]`.
4. Confirm TLS fields and deliberately added unknown JSON fields survive load/save.
5. Modify the live JSON externally and verify that save presents conflict choices.
6. Verify service-not-installed state, then install/start/stop/restart the service where safe.
7. Confirm invalid configuration blocks apply and an engine startup failure is never displayed as Running.
8. Follow logs through service restart, append, truncation, and size-based rotation, then open the active file from the Logs toolbar. Confirm that rotation resets the view to the new active file and that archived history remains accessible in the archive directory. Confirm that changing the Logs-tab **View filter** only changes displayed lines, while changing **Engine log level** takes effect after a service restart.
9. Copy diagnostics and verify that no password or full credential-bearing configuration appears.
10. Hide the GUI to the notification area, launch `ProxiFyreUI.exe` again, and confirm the existing window is restored without creating a second tray icon.
11. Exit the GUI and confirm the service continues running.
12. On Windows 7 SP1 x64, launch the installed UI and confirm the main window is constructed without a managed startup failure before repeating the basic service-state checks.

### DNS routing manual validation

The routing policy and the packet rewriting are covered by automated tests (`netlib-tests` and `netlib/test/portable/run-portable-tests.sh`); the end-to-end path through the driver and a live SOCKS5 server needs a Windows test machine. Capture with Wireshark on the physical adapter and use `Resolve-DnsName -Server <server> -DnsOnly` (UDP) and `Resolve-DnsName -TcpOnly` (TCP), running `ipconfig /flushdns` before each step:

1. With no `dns` section (or `Direct`), confirm UDP and TCP queries to the system resolver and to `8.8.8.8` leave the adapter directly for IPv4 and IPv6, including with a catch-all rule.
2. Configure two proxies with ids and select the second in `Proxy` mode. Confirm no port-53 packets leave the adapter, that the second SOCKS5 server receives `UDP ASSOCIATE`/`CONNECT` requests, and that name resolution works from a browser (Dnscache) and from `nslookup <name> 8.8.8.8` (own resolver). Browse for a few minutes and confirm the SOCKS5 server sees one control connection and one `UDP ASSOCIATE` per address family for UDP DNS, not one per query.
3. Enable `bypassLan` with a router resolver (`192.168.x.1`): without an override the SOCKS5 server is asked for the router address; with `serverOverride: "1.1.1.1"` it is asked for `1.1.1.1` and `Resolve-DnsName` still reports answers from the router address.
4. Reorder the rules, Apply & Restart, and confirm DNS still uses the selected proxy.
5. Stop the SOCKS5 server (or block it with a firewall rule) and confirm queries fail and no port-53 packet leaves the adapter; the engine log has one "could not open a SOCKS5 UDP association" warning per address family in use, and attempts back off to about one every 30 seconds (plus the 5-second connect timeout when the server is black-holed). Start the SOCKS5 server again and confirm lookups recover within about 35 seconds. Restart the SOCKS5 server while ProxiFyre runs and confirm the association is reopened ("closing the SOCKS5 UDP association" and "opened" at `Info`) and lookups recover. Configure Windows with a second DNS server the SOCKS5 server cannot reach (for example a LAN address, without `serverOverride`), browse for two minutes, and confirm the log has no "queries stopped being answered" line. Stop the service while the SOCKS5 server is unreachable (black-holed, not refusing) and confirm it stops within a few seconds. Finally, with `serverOverride` removed and Windows using only a resolver the SOCKS5 server cannot reach (a LAN address), confirm one "no answer came back through the SOCKS5 UDP association" warning per address family in use within about a minute, not repeated; then set `serverOverride` and confirm lookups work. Then configure an IPv4-only DNS proxy rule and confirm IPv6 queries are dropped with one DNS routing warning for that cause and a throttled drop count.
6. Configure an IPv4 override with an IPv6 resolver and confirm IPv6 queries are dropped while IPv4 queries succeed.
7. **Upgrade.** With a configuration from an earlier release (no `dns` section, a catch-all rule), confirm that `Resolve-DnsName -TcpOnly` now leaves the adapter directly, that UDP DNS still does, and that the rule's other traffic is still proxied.
8. **Restart.** With `Proxy` mode and `bypassLan`, use **Apply & Restart** (or stop and start the service) and repeat step 3: DNS to the router resolver must still be proxied.
9. **DNS proxy unavailable at start.** Give the DNS proxy rule an endpoint that cannot be created (for example a host name that does not resolve) and start the service. Confirm the service starts, the log states that all DNS is blocked until the service is restarted, and no port-53 packet leaves the adapter.
10. **TCP close.** Run `Resolve-DnsName -TcpOnly` several times in `Proxy` mode. Confirm each lookup completes, that no FIN, ACK, or RST of those connections reaches the real DNS server, and that the log has no "dropped … DNS packet(s)" lines.
11. **Aborted connection.** Start a large download in a proxied application and cancel it. Confirm no segment from the local listener's port leaves the adapter and that the log has no "could not be translated back" warning.
12. **Large answer.** In `Proxy` mode request a UDP answer larger than about 1,200 bytes, over IPv4 and over IPv6, from a DNS server that sends UDP answers of that size (most public resolvers truncate them instead). Use a tool that sets the EDNS buffer size, such as BIND's `dig +dnssec +bufsize=4096 DNSKEY <zone> @<server>`, which is not part of Windows. Confirm the answer arrives truncated (the `tc` flag) and unfragmented, that `dig` then retries over TCP through the proxy and succeeds, and that no listener-reply warning is logged.
13. **Relay source and shared IDs.** If the SOCKS5 server reports an address other than the queried DNS server as the source of UDP replies (for example its own IPv4 address), confirm lookups succeed without and with `serverOverride`, to an IPv4 resolver and to an IPv6 resolver. Run many lookups in parallel (for example `1..200 | ForEach-Object -Parallel { Resolve-DnsName "host$_.example.com" -DnsOnly -ErrorAction SilentlyContinue }` in PowerShell 7) and confirm each one gets its own answer.
14. **SOCKS5 server used as a resolver.** Send a lookup to the SOCKS5 server's own IP address (`Resolve-DnsName example.com -Server <socks-ip> -DnsOnly`). Confirm the query goes through the proxy, not directly. If the server listens on TCP port 53 or returns a UDP relay on port 53, also confirm ProxiFyre still reaches it and the one-time `Info` line about the relay appears.
15. **Limited mode.** Repeat step 2 in the optional unelevated console mode.
16. **GUI.** On the **Settings / Diagnostics** tab at 100% and 150% scaling, confirm the DNS routing group and the Uninstall button are reachable (scrolling is expected). Confirm Alt+M, Alt+P, and Alt+S focus the mode, proxy, and override fields; that the DNS proxy selection survives **Move Up**/**Move Down** and a reload; that **Duplicate** does not copy the id; and that removing the selected rule shows the missing id and fails validation.
