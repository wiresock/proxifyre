# ProxiFyre GUI

`ProxiFyreUI.exe` is the native Windows Forms management application for ProxiFyre. It edits the engine configuration, controls `ProxiFyreService`, and follows the engine log files. It is deliberately not a packet-processing host: `ProxiFyre.exe` and the existing `socksify.dll` C++/CLI component remain the networking engine.

## Architecture and trust boundaries

The managed dependency graph is intentionally one-way:

```text
ProxiFyre.exe --------------> ProxiFyre.Configuration.dll
      |
      +---------------------> socksify.dll

ProxiFyreUI.exe ------------> ProxiFyre.Configuration.dll
```

`ProxiFyre.Configuration` contains the JSON models, forward-compatible serialization, normalization, structured validation, fingerprints, and atomic file operations. It has no native dependency. `ProxiFyreUI` never references or loads `socksify.dll`; it controls the installed service through the Windows Service Control Manager and invokes only the resolved `ProxiFyre.exe` with a fixed `install` or `uninstall` argument.

The GUI requests administrator privileges at startup. This is required to manage a Windows service and to update a configuration beside an engine installed in a protected directory. SOCKS5 credentials remain in the existing plaintext JSON schema because the engine must be able to read them. The GUI masks passwords and omits them from logs, tooltips, and diagnostics.

The primary service controls include explicit install and uninstall actions. Uninstall requires confirmation and removes only the Windows service registration; `app-config.json`, its backup, and engine logs are preserved. The same uninstall action remains available under **Settings / Diagnostics**.

## Engine and configuration discovery

The GUI resolves the engine in this order:

1. The registered image path for `ProxiFyreService`, when installed.
2. `ProxiFyre.exe` beside `ProxiFyreUI.exe`.
3. The last explicitly selected engine saved in `%LocalAppData%\ProxiFyreUI\ui-settings.json`.
4. A file selected by the user.

Quoted service image paths and a fixed trailing service argument are parsed without executing the registered command line. A selected file must be named `ProxiFyre.exe`. The engine, configuration, and log paths are displayed on the Diagnostics tab.

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

**Apply & Restart** performs the same validated atomic save, then stops and starts the installed service while waiting for the actual SCM states. It reports success only when the SCM reports `Running`. The **Engine log level** setting is part of `app-config.json`, so changing the service's logging verbosity requires **Apply & Restart** (or a later manual service restart). Before changing service state, the GUI opens `\\.\NDISRD` with the same non-invasive capability probe used by the native engine. If Windows Packet Filter is unavailable, the saved configuration remains pending and the GUI reports the dependency immediately without stopping the service or offering a configuration rollback. Other startup failures may still offer to restore the backup and perform at most one controlled restart using the restored configuration.

The workspace fingerprints the file when it is loaded. If another process changes it before a save, the GUI offers to reload, explicitly overwrite, or cancel. It never silently overwrites an externally modified configuration.

## Logs and notification area

Engine logs are stored in the `logs` directory beside `ProxiFyre.exe`. The Logs tab reads a bounded tail with read/write sharing, follows appended content incrementally, switches to a newer daily file after rotation, and recovers from creation, truncation, or temporary locks. **Open log file** launches the file currently being followed, or the newest `.log`/`.txt` file when following is paused. The Logs-tab **View filter** changes only which already-written lines the GUI displays; it does not change the engine's logging verbosity or configuration and does not require a restart. Follow/pause, text filtering, copy, reload, clear-view, and open-folder actions affect only the viewer; clearing the view does not delete log files.

Closing the window hides it in the notification area. The tray menu reflects the real service state and provides open, start, stop, restart, logs, and exit actions. Within each Windows identity and terminal session, ProxiFyre permits one GUI instance per application major/minor version; launching the same version again restores and activates the existing window, including a tray-hidden window. Exiting the GUI does not stop the engine service. Unsaved edits are checked before reload, engine changes, or application exit.

## Build and test

Prerequisites are Visual Studio 2022 with the .NET Framework 4.7.2 and C++ desktop workloads, NuGet, vcpkg, and the repository's `ms-gsl` and `boost-pool` triplets.

From a Visual Studio developer shell:

```powershell
nuget restore socksify.sln
msbuild socksify.sln -t:Rebuild -v:minimal -p:Configuration=Release -p:Platform=x64 -p:Version=2.4.0
vstest.console.exe bin\tests\x64\Release\ProxiFyre.Tests.dll /TestAdapterPath:packages\NUnit3TestAdapter.4.6.0\build\net462 /Platform:x64
```

Replace `x64` with `x86` for tests on a matching host. The ARM64 payload can be cross-built when the Visual Studio toolchain is installed, but its tests must run on Windows ARM64 rather than an x64 CI host. Architecture-specific release files, including `ProxiFyre.exe`, `ProxiFyreUI.exe`, `socksify.dll`, `ProxiFyre.Configuration.dll`, managed dependencies, and the sample configuration, are placed in:

```text
bin\exe\<architecture>\Release\
```

Tests write to `bin\tests\<architecture>\<configuration>\` and do not require the packet-filter driver, an installed service, administrator access, or a live SOCKS5 endpoint.

## Troubleshooting

- **Service not installed:** verify the resolved engine path, then select **Install Service**. Installation uses that exact executable and refreshes SCM state afterward.
- **Access denied:** restart the GUI and approve the administrator prompt. Check directory ACLs if the engine is installed outside the normal application directory.
- **Configuration invalid:** open the validation details. The GUI will not save or start a new invalid rule set.
- **Saved, restart required:** choose **Apply & Restart** or restart the service after completing related edits.
- **Windows Packet Filter unavailable:** install WinpkFilter from `https://github.com/wiresock/ndisapi/releases`, restart Windows if requested, and retry. The GUI checks the `NDISRD` device before install/start/restart and does not treat a missing driver as a configuration failure.
- **Engine startup failed:** the service may have rejected configuration or encountered another native initialization error. A service that returns to `Stopped` during startup is reported immediately; review recent lines on the Logs tab.
- **No log file yet:** start the service or use **Reload** after the engine creates its `logs` directory. The follower continues checking for creation and rotation; **Open log file** becomes useful as soon as a `.log` or `.txt` file exists.
- **External change detected:** reload to accept the on-disk file, overwrite only if the other edit is known to be obsolete, or cancel and compare both versions first.
- **Recursive timeouts with another VPN:** add the other VPN's carrier/tunnel process to Exclusions.

## Manual release validation

On a Windows test machine with the appropriate driver and administrator access:

1. Build and test Release x64, then build x86 and ARM64 when the toolchain is installed.
2. Launch `ProxiFyreUI.exe`, resolve a separately located engine, and load the sample configuration.
3. Add, edit, duplicate, delete, and reorder rules. Confirm a catch-all saves as `"appNames": [""]`.
4. Confirm TLS fields and deliberately added unknown JSON fields survive load/save.
5. Modify the live JSON externally and verify that save presents conflict choices.
6. Verify service-not-installed state, then install/start/stop/restart the service where safe.
7. Confirm invalid configuration blocks apply and an engine startup failure is never displayed as Running.
8. Follow logs through service restart, append, truncation, and daily rotation, then open the active file from the Logs toolbar. Confirm that changing the Logs-tab **View filter** only changes displayed lines, while changing **Engine log level** takes effect after a service restart.
9. Copy diagnostics and verify that no password or full credential-bearing configuration appears.
10. Hide the GUI to the notification area, launch `ProxiFyreUI.exe` again, and confirm the existing window is restored without creating a second tray icon.
11. Exit the GUI and confirm the service continues running.
