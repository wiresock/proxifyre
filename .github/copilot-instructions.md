# ProxiFyre: SOCKS5 Proxifier for Windows

ProxiFyre is a Windows-specific SOCKS5 proxifier application that builds upon the Windows Packet Filter's socksify demo. The solution has 11 build projects: the packet-filter library, C++/CLI bridge, service engine, shared configuration library, managed UI, native UI launcher, managed tests, MSI, Burn bundle, and two native setup helpers. ProxiFyre.Tests covers managed logic without requiring the driver or a live service.

**ALWAYS reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.**

## Working Effectively

### CRITICAL: Platform Requirements
- **This application ONLY builds and runs on Windows**. Do not attempt to build on Linux/macOS.
- Build requires Windows, Visual Studio 2022 with the MSBuild/C++ and .NET desktop workloads, the v143 toolset, a Windows SDK, the .NET Framework 4.7.2 targeting pack, NuGet CLI, vcpkg, PowerShell 7, and a .NET SDK that can restore WiX 6.0.2.
- If you are in a Linux environment: **Document that builds cannot be completed** and focus on repository navigation and structure analysis only.

### Build Prerequisites (Windows Only)

1. **Visual Studio 2022** with the workloads, toolset, SDK, and targeting pack listed above.
2. **vcpkg Package Manager**:
   ```cmd
   git clone https://github.com/Microsoft/vcpkg.git
   cd vcpkg
   .\bootstrap-vcpkg.bat
   .\vcpkg integrate install
   ```

3. **Install Required vcpkg Packages**:
   ```cmd
   .\vcpkg install ms-gsl:x86-windows ms-gsl:x64-windows ms-gsl:arm64-windows
   .\vcpkg install boost-pool:x86-windows boost-pool:x64-windows boost-pool:arm64-windows
   ```
   - **NEVER CANCEL**: Package installation takes 10-15 minutes. Set timeout to 30+ minutes.

4. **NuGet CLI**:
   - Install via: `choco install nuget.commandline` or download from nuget.org
5. **PowerShell 7 and a .NET SDK** capable of restoring the pinned WiX Toolset 6.0.2 SDK and extensions.

Windows Packet Filter and the architecture-matched Visual C++ runtime are target runtime/manual integration-test prerequisites, not source-build prerequisites. `Build-Installer.ps1` downloads their official packages or accepts validated local copies as installer binding inputs; they do not need to be installed merely to compile or run the managed tests.

### Building the Application (Windows Only)

**CRITICAL BUILD TIMING**: All build commands require extended timeouts. **NEVER CANCEL** builds in progress.

1. **Restore packages in isolated groups** from PowerShell. Do not replace this sequence with a solution-wide NuGet restore: the legacy `packages.config` projects, native setup helpers, and SDK-style WiX projects use different restore models, while installer restores must honor their lock files and `NuGet.Installer.Config`.
   ```powershell
   nuget restore ProxiFyre.Configuration\packages.config -PackagesDirectory packages -NonInteractive
   nuget restore ProxiFyre\packages.config -PackagesDirectory packages -NonInteractive
   nuget restore ProxiFyre.Tests\packages.config -PackagesDirectory packages -NonInteractive

   msbuild ProxiFyreSetupBootstrapper\ProxiFyreSetupBootstrapper.vcxproj -target:Restore -verbosity:minimal -property:RestoreLockedMode=true -property:RestoreConfigFile="$PWD\NuGet.Installer.Config"
   msbuild ProxiFyreSetupEngineExtension\ProxiFyreSetupEngineExtension.vcxproj -target:Restore -verbosity:minimal -property:RestoreLockedMode=true -property:RestoreConfigFile="$PWD\NuGet.Installer.Config"
   dotnet restore ProxiFyre.Installer\ProxiFyre.Installer.wixproj --configfile NuGet.Installer.Config --locked-mode
   dotnet restore ProxiFyre.Bundle\ProxiFyre.Bundle.wixproj --configfile NuGet.Installer.Config --locked-mode
   ```
   - Takes: 2-5 minutes. Set timeout to 10+ minutes.

2. **Build the solution**. `Directory.Build.props` is the single repository release-version source and currently declares `2.5.0`; normal local builds inherit it. An explicit version is appropriate for release verification and controlled tests, but it must match the repository value for a release:
   ```cmd
   msbuild socksify.sln -t:rebuild -verbosity:minimal -property:Configuration=Release -property:Platform=x64 -property:Version=2.5.0
   ```
   - **NEVER CANCEL**: Build takes 5-8 minutes on average. Set timeout to 15+ minutes.
   - For other platforms, replace `x64` with `x86` or `ARM64`
   - Debug builds: Replace `Release` with `Debug`

3. **Run managed tests** after the solution build:
   ```cmd
   vstest.console.exe bin\tests\x64\Release\ProxiFyre.Tests.dll /TestAdapterPath:packages\NUnit3TestAdapter.4.6.0\build\net462 /Platform:x64
   ```
   Use a test assembly matching the host architecture; an x64 runner must not attempt to execute the ARM64 test assembly. The tests must remain independent of `socksify.dll`, the packet-filter driver, SCM mutations, and a live SOCKS5 endpoint.

4. **Build and validate the MSI and online setup** after the isolated restores and solution build:
   ```powershell
   pwsh -File scripts\Build-Installer.ps1 -Platform x64 -Version 2.5.0 -NoRestore
   ```
   The release tag must be exactly `v2.5.0` when `Directory.Build.props` declares `2.5.0`.

## Running the Application (Windows Only)

### Prerequisites for Running
- Windows Packet Filter must be installed and running
- Windows Firewall may block ProxiFyre - add inbound rule for `ProxiFyre.exe` if needed
- Requires administrative privileges

### Running as Console Application
1. Create `app-config.json` in the same directory as `ProxiFyre.exe`
2. Run: `ProxiFyre.exe`
3. **MANUAL VALIDATION**: Always test functionality by:
   - Creating a valid `app-config.json` with test SOCKS5 proxy settings
   - Running the application and monitoring logs in the `.\logs` directory beside `ProxiFyre.exe`
   - Verifying network traffic is routed through proxy using network monitoring tools

### Running as Windows Service
```cmd
# Install service (run as Administrator)
ProxiFyre.exe install

# Start service
ProxiFyre.exe start

# Stop service  
ProxiFyre.exe stop

# Uninstall service
ProxiFyre.exe uninstall
```

## Configuration

### Example app-config.json
Create this file in the same directory as `ProxiFyre.exe`:

```json
{
  "logLevel": "Error",
  "proxies": [
    {
      "appNames": ["chrome", "firefox"],
      "socks5ProxyEndpoint": "127.0.0.1:1080",
      "username": "testuser",
      "password": "testpass",
      "supportedProtocols": ["TCP", "UDP"]
    }
  ],
  "excludes": [
    "notepad",
    "explorer"
  ]
}
```

### Key Configuration Properties
- **logLevel**: `Error`, `Warning`, `Info`, `Debug`, `All`
- **appNames**: Process names use the engine's anchored name matching; path-form entries use permissive path substring matching
- **socks5ProxyEndpoint**: SOCKS5 server address and port
- **username/password**: Optional SOCKS5 authentication
- **supportedProtocols**: Array containing `TCP` and/or `UDP`
- **excludes**: Applications to bypass proxy routing

## Validation

### Build Validation (Windows Only)
- **NEVER CANCEL**: Wait for all builds to complete (5-15 minutes typical)
- Check build output in `bin\exe\{Platform}\{Configuration}\` directory
- Verify `ProxiFyre.exe` exists and required DLLs are present

### Runtime Validation (Windows Only)
- Always test with a working SOCKS5 proxy server
- Monitor application logs in the `.\logs` directory beside `ProxiFyre.exe`
- Test both TCP and UDP traffic routing if configured
- Verify excluded applications bypass the proxy
- Use network monitoring tools to confirm proxy routing

### Validation Not Possible on Linux/macOS
- Cannot build or run the application
- Cannot test SOCKS5 proxy functionality
- Cannot validate Windows service installation
- Focus on code analysis and documentation updates only

## Repository Structure

### Key Projects
1. **ndisapi.lib** (`./ndisapi.lib/`):
   - Windows Packet Filter static library
   - C++ project with Windows-specific networking APIs
   - File: `ndisapilib.vcxproj`

2. **socksify** (`./socksify/`):
   - .NET C++/CLI class library
   - Implements SOCKS5 router functionality
   - Key files: `Socksifier.h`, `Socksifier.cpp`, `socksify_unmanaged.cpp`
   - File: `socksify.vcxproj`

3. **ProxiFyre** (`./ProxiFyre/`):
   - C# console application (.NET Framework 4.7.2)
   - Main entry point and service management
   - Key files: `Program.cs`, `ProxiFyre.csproj`
   - Dependencies: ProxiFyre.Configuration, NLog, Topshelf, and socksify; JSON is consumed transitively through the shared configuration library

4. **ProxiFyre.Configuration** (`./ProxiFyre.Configuration/`):
   - Shared .NET Framework 4.7.2 configuration models and services
   - Owns JSON compatibility, normalization, validation, fingerprints, and atomic file persistence
   - Depends on Newtonsoft.Json only; it must never reference `socksify`

5. **ProxiFyreUI** (`./ProxiFyreUI/`):
   - Managed Windows Forms management application targeting .NET Framework 4.7.2
   - Edits `app-config.json`, controls `ProxiFyreService`, tails logs, and provides a tray icon
   - Depends on ProxiFyre.Configuration; it must never reference or load `socksify.dll`
   - The service/console executable remains the only networking engine

6. **ProxiFyreUILauncher** (`./ProxiFyreUILauncher/`):
   - Statically linked native integrity host that starts `ProxiFyreUI.Managed.dll`
   - Enforces the app-local module allowlist, fixed CLR configuration, secure DLL search, and payload leases without Authenticode

7. **ProxiFyre.Tests** (`./ProxiFyre.Tests/`):
   - NUnit tests for shared configuration and non-UI application services
   - Output: `bin\tests\{Platform}\{Configuration}\`

8. **ProxiFyre.Installer** (`./ProxiFyre.Installer/`):
   - Pinned WiX 6.0.2 per-machine MSI for x86, x64, and ARM64
   - Owns the protected runtime files, service registration, shortcuts, and exact program-scoped firewall rules

9. **ProxiFyre.Bundle** (`./ProxiFyre.Bundle/`):
   - Pinned WiX 6.0.2 Burn setup that embeds the ProxiFyre MSI
   - Detects compatible Visual C++ and Windows Packet Filter prerequisites and otherwise acquires the verified official architecture-specific packages

10. **ProxiFyreSetupBootstrapper** (`./ProxiFyreSetupBootstrapper/`):
    - Statically linked native WixStdBA functions DLL embedded in setup
    - Temporarily enables the Windows 7 WinINet TLS 1.2 bit and, only after the normal HTTPS retries end in error 12029 for the exact pinned Visual C++ payload, permits one digest-verified attempt at the same Microsoft content-addressed URL over HTTP

11. **ProxiFyreSetupEngineExtension** (`./ProxiFyreSetupEngineExtension/`):
    - Statically linked native Burn engine extension embedded in setup
    - Applies a process-scoped DIRECT WinINet route only for the narrowly validated all-zero connection-flags state, without changing registry-backed Internet Options

### Important Files
- `socksify.sln`: Main Visual Studio solution file
- `Directory.Build.props`: Canonical repository release version and default repository metadata
- `README.md`: User documentation and setup instructions
- `docs/installer.md`: Installer architecture, build, prerequisite, lifecycle, and validation documentation
- `scripts/Build-Installer.ps1`: Supported MSI/setup build and validation entry point
- `.github/workflows/main.yml`: CI/CD build pipeline

### Include Directories
- `./include/`: Common headers (`Common.h`, `ndisapi.h`)
- `./ndisapi/`: NDIS API implementation
- `./netlib/`: Network utility C++ classes

## Common Tasks

### Repository Navigation
```bash
# Root directory listing
ls -la
# Output includes the engine, managed UI, native launcher, tests, MSI, bundle, both setup helpers, socksify, ndisapi.lib, include, netlib, scripts, docs, README.md, and socksify.sln

# Key configuration files
find . -name "*.json" -o -name "*.config" -o -name "packages.config"
# Output includes the managed project App.config/packages.config files and ProxiFyre/NLog.config

# Project structure
find . -name "*.csproj" -o -name "*.vcxproj" -o -name "*.wixproj" -o -name "*.sln"
# Output additionally includes the managed UI/tests, native launcher, WiX MSI/Burn projects, and both native setup helpers
```

### Source Code Analysis
```bash
# Find C# files
find . -name "*.cs"
# Output includes the service, shared configuration, GUI forms/services, and managed test sources

# Find C++ files  
find . -name "*.cpp" -o -name "*.h"
# Output: socksify/ and ndisapi/ directories contain C++ implementation
```

## Limitations

### Cannot Do on Linux/macOS
- Build the application (requires Windows-specific MSBuild and Visual Studio C++ tools)
- Run or test the application (Windows-only dependencies)
- Install or test Windows Packet Filter
- Validate SOCKS5 proxy functionality
- Test Windows Service installation

### What You CAN Do on Non-Windows
- Navigate and analyze repository structure
- Read and modify source code
- Update documentation
- Analyze dependencies and configuration files
- Review GitHub workflows and CI/CD processes
- Make code changes for review (cannot test them)

## CI/CD Information

### GitHub Workflow Timing
- **Build Process**: ~5-8 minutes per platform (x86, x64, ARM64)
- **vcpkg Dependencies**: ~10-15 minutes for installation
- **Total Pipeline**: ~20-25 minutes for complete build across all platforms
- **Artifacts**: Creates an unsigned architecture-specific application ZIP, standalone MSI, online prerequisite setup bundle, and SHA-256 files. The ZIP is not an offline installer. Setup downloads and verifies the pinned Visual C++ and Windows Packet Filter packages when compatible prerequisites are missing; the standalone MSI and manually staged ZIP require prerequisites to be present. Releases do not require certificates, signing secrets, or a post-build signing pass.

### Build Matrix
- Platforms: x86, x64, ARM64
- Configuration: Release only for CI builds
- Runtime output: `bin\exe\{Platform}\Release\` contains `ProxiFyre.exe`, `ProxiFyreUI.exe`, `socksify.dll`, `ProxiFyre.Configuration.dll`, and their managed dependencies
- Test output: `bin\tests\{Platform}\Release\ProxiFyre.Tests.dll`
- Installer output: `bin\installer\{Platform}\Release\` contains the standalone MSI, online setup bundle, and checksum files
