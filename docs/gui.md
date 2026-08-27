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

After payload validation and before constructing the first control, the managed UI verifies that .NET Framework WinForms can resolve its normal default font. If the legacy GDI+ generic-font path fails, it recovers with an installed named Windows UI font before controls such as `DataGridView` can query the unusable fallback. Healthy systems retain the framework-selected default.

The GUI requests administrator privileges at startup. This is required to manage a Windows service and to update a configuration beside an engine installed in a protected directory. ProxiFyre's first-party modules and installers are deliberately unsigned and can display **Unknown publisher**. Before loading the CLR, the statically linked native host removes CLR-control environment overrides, restricts native DLL loading to the Windows system directory, rejects unexpected app-local executable modules, verifies the exact CLR-configuration hash, and holds the required managed files plus every normal directory component open without write/delete sharing. In Release builds, the native host also requires its own file, every managed payload file, and the complete directory chain to be on a directly mounted fixed volume, owned by `SYSTEM`, `Administrators`, or `TrustedInstaller`, with ACLs that do not grant standard users mutation rights. Production service operations require the engine filename and version-resource identity, verify fixed engine/logging configuration hashes, and hold the complete app-local payload and path through process or SCM startup. Release service install, start, restart, and uninstall apply the same fixed-volume, owner, ACL, reparse-point, loader-redirection, and executable-module restrictions. The WiX MSI creates that protected per-machine directory; the GUI deliberately refuses to rewrite a user-controlled directory in place because an attacker could retain a pre-existing write or permission-control handle after the ACL change. Debug builds retain an explicit developer-directory policy. Third-party dependencies may retain signatures from their upstream publishers, but ProxiFyre does not require or replace them. SOCKS5 credentials remain in the existing plaintext JSON schema because the engine must be able to read them. The GUI masks passwords and omits them from logs, tooltips, and diagnostics.

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

## Save, apply, conflicts, and recovery

**Save** validates the complete model and refuses to write when errors exist. It writes a temporary file in the configuration directory, flushes it, preserves the prior live file as `app-config.json.bak`, and replaces the live file atomically. If the service is running, the UI reports that a restart is still required.

**Apply & Restart** performs the same validated atomic save, then stops and starts the installed service while waiting for the actual SCM states. It reports success only when the SCM reports `Running`. The **Engine log level** setting is part of `app-config.json`, so changing the service's logging verbosity requires **Apply & Restart** (or a later manual service restart). Before changing service state, the GUI opens `\\.\NDISRD` with no requested read/write access and queries `IOCTL_NDISRD_GET_VERSION`. It accepts API major `3` with API minor `0x0601` or newer; an installed-but-stopped service can be started by SCM through the declared dependency. If Windows Packet Filter is missing or an active driver is incompatible, the saved configuration remains pending and the GUI reports the dependency immediately without stopping the service or offering a configuration rollback. Other startup failures may still offer to restore the backup and perform at most one controlled restart using the restored configuration.

The workspace fingerprints the file when it is loaded. If another process changes it before a save, the GUI offers to reload, explicitly overwrite, or cancel. It never silently overwrites an externally modified configuration.

## Logs and notification area

Engine logs are stored in the `logs` directory beside `ProxiFyre.exe`. `Info` records service lifecycle and configuration summaries; `Debug` additionally records per-connection routing, proxy negotiation, and relay details. The Logs tab reads a bounded tail with read/write sharing, follows appended content incrementally, switches to a newer daily file after rotation, and recovers from creation, truncation, or temporary locks. **Open log file** launches the file currently being followed, or the newest `.log`/`.txt` file when following is paused. The Logs-tab **View filter** changes only which already-written lines the GUI displays; it does not change the engine's logging verbosity or configuration and does not require a restart. Follow/pause, text filtering, copy, reload, clear-view, and open-folder actions affect only the viewer; clearing the view does not delete log files.

Closing the window hides it in the notification area. The tray menu reflects the real service state and provides open, start, stop, restart, logs, and exit actions. Within each Windows identity and terminal session, ProxiFyre permits one GUI instance per application major/minor version; launching the same version again restores and activates the existing window, including a tray-hidden window. Exiting the GUI does not stop the engine service. Unsaved edits are checked before reload, engine changes, or application exit.

## Build and test

Prerequisites are Visual Studio 2022 with the .NET Framework and C++ desktop workloads, NuGet, vcpkg, the repository's `ms-gsl` and `boost-pool` triplets, PowerShell 7, and a .NET SDK for the pinned WiX Toolset 6.0.2 packages.

From a Visual Studio developer shell:

```powershell
nuget restore ProxiFyre.Configuration\packages.config -PackagesDirectory packages -NonInteractive
nuget restore ProxiFyre\packages.config -PackagesDirectory packages -NonInteractive
nuget restore ProxiFyre.Tests\packages.config -PackagesDirectory packages -NonInteractive
msbuild socksify.sln -t:Rebuild -v:minimal -p:Configuration=Release -p:Platform=x64 -p:Version=2.4.0
vstest.console.exe bin\tests\x64\Release\ProxiFyre.Tests.dll /TestAdapterPath:packages\NUnit3TestAdapter.4.6.0\build\net462 /Platform:x64
pwsh -File scripts\Build-Installer.ps1 -Platform x64 -Version 2.4.0
```

Replace `x64` with `x86` for tests on a matching host. The ARM64 payload can be cross-built when the Visual Studio toolchain is installed, but its tests must run on Windows ARM64 rather than an x64 CI host. Architecture-specific runtime files, including `ProxiFyre.exe`, the native `ProxiFyreUI.exe` host, `ProxiFyreUI.Managed.dll`, `socksify.dll`, `ProxiFyre.Configuration.dll`, managed dependencies, and the sample configuration, are placed in:

```text
bin\exe\<architecture>\Release\
```

That Release directory is packaging output, not a developer launch directory. Because the
first-party payload is unsigned, the elevated Release GUI refuses to load managed code from a
user-writable extraction such as Downloads, `%TEMP%`, or the repository build tree. Use the setup
package (recommended). For a Release ZIP test, an administrator must stage the complete archive
on a fixed local volume in a protected per-machine directory: every directory component and
payload file must be owned by `SYSTEM`, `Administrators`, or `TrustedInstaller`, and their ACLs
must not let standard users replace files or change permissions. Create and protect a fresh
destination before extracting into it; do not extract into a user-writable directory and tighten
its ACL afterward, because existing mutation handles cannot be revoked. Use a Debug build for
normal developer-tree testing.

Tests write to `bin\tests\<architecture>\<configuration>\` and do not require the packet-filter driver, an installed service, administrator access, or a live SOCKS5 endpoint.

The installer build writes the unsigned MSI, unsigned Burn setup executable, and SHA-256 sidecars to `bin\installer\<architecture>\Release\`. See [installer.md](installer.md) for the exact payload, pinned official Visual C++ and Windows Packet Filter acquisition flows, standalone-MSI requirements, firewall rules, upgrade/uninstall semantics, build options, and lifecycle validation matrix.

## Troubleshooting

- **Service not installed:** for an MSI installation, run product repair to reconcile the service and all other components. The GUI's **Install Service** action can restore only the service registration from the resolved protected engine payload.
- **Access denied:** restart the GUI and approve the administrator prompt. Check directory ACLs if the engine is installed outside the normal application directory.
- **Service location is not protected:** if a pre-MSI service is installed outside a protected parent, stop and remove its registration, back up `app-config.json`, and exit the GUI. Install the matching architecture through the ProxiFyre WiX setup so Windows Installer creates the protected Program Files directory, then restore the configuration through an elevated process or the GUI. The installed registration takes precedence over Browse, so merely browsing to a new copy does not migrate an existing service.
- **Unknown publisher:** this is expected for ProxiFyre's deliberately unsigned first-party installer and binaries. Verify the release SHA-256 through a trusted source before elevation. Do not confuse a checksum obtained from the same untrusted download with publisher authentication.
- **Windows 7 UI startup failure:** use the current setup build and verify Windows 7 SP1 has current servicing-stack, SHA-2, .NET Framework 4.7.2, and font updates. The UI avoids the legacy GDI+ generic-font startup path, but a broadly damaged system font installation can still require Windows repair.
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
8. Follow logs through service restart, append, truncation, and daily rotation, then open the active file from the Logs toolbar. Confirm that changing the Logs-tab **View filter** only changes displayed lines, while changing **Engine log level** takes effect after a service restart.
9. Copy diagnostics and verify that no password or full credential-bearing configuration appears.
10. Hide the GUI to the notification area, launch `ProxiFyreUI.exe` again, and confirm the existing window is restored without creating a second tray icon.
11. Exit the GUI and confirm the service continues running.
12. On Windows 7 SP1 x64, launch the installed UI and confirm the main window is constructed without a managed startup failure before repeating the basic service-state checks.
