# ProxiFyre: SOCKS5 Proxifier for Windows

ProxiFyre is a Windows-specific SOCKS5 proxifier application that builds upon the Windows Packet Filter's socksify demo. It consists of three main projects: ndisapi.lib (Windows Packet Filter static library), socksify (.NET C++/CLI class library), and ProxiFyre (C# console application).

**ALWAYS reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.**

## Working Effectively

### CRITICAL: Platform Requirements
- **This application ONLY builds and runs on Windows**. Do not attempt to build on Linux/macOS.
- Build requires: Windows, Visual Studio 2017+, MSBuild, vcpkg, Windows Packet Filter (WinpkFilter)
- If you are in a Linux environment: **Document that builds cannot be completed** and focus on repository navigation and structure analysis only.

### Prerequisites Installation (Windows Only)
Install these dependencies in the following exact order:

1. **Windows Packet Filter (WinpkFilter)**:
   - Download from: `https://github.com/wiresock/ndisapi/releases`
   - Follow installation instructions from the release page
   - Required for ndisapi.lib functionality

2. **Visual Studio 2022 Runtime Libraries**:
   - Download from: `https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170`
   - Install appropriate architecture version (x64, x86, or ARM64)

3. **vcpkg Package Manager**:
   ```cmd
   git clone https://github.com/Microsoft/vcpkg.git
   cd vcpkg
   .\bootstrap-vcpkg.bat
   .\vcpkg integrate install
   ```

4. **Install Required vcpkg Packages**:
   ```cmd
   .\vcpkg install ms-gsl:x86-windows ms-gsl:x64-windows ms-gsl:arm64-windows
   .\vcpkg install boost-pool:x86-windows boost-pool:x64-windows boost-pool:arm64-windows
   ```
   - **NEVER CANCEL**: Package installation takes 10-15 minutes. Set timeout to 30+ minutes.

5. **NuGet CLI**:
   - Install via: `choco install nuget.commandline` or download from nuget.org

### Building the Application (Windows Only)

**CRITICAL BUILD TIMING**: All build commands require extended timeouts. **NEVER CANCEL** builds in progress.

1. **Restore NuGet Packages**:
   ```cmd
   nuget restore socksify.sln
   ```
   - Takes: 2-5 minutes. Set timeout to 10+ minutes.

2. **Build the Solution**:
   ```cmd
   msbuild socksify.sln -t:rebuild -verbosity:minimal -property:Configuration=Release -property:Platform=x64
   ```
   - **NEVER CANCEL**: Build takes 5-8 minutes on average. Set timeout to 15+ minutes.
   - For other platforms, replace `x64` with `x86` or `ARM64`
   - Debug builds: Replace `Release` with `Debug`

3. **Alternative Build Command**:
   ```cmd
   msbuild socksify.sln -t:rebuild -verbosity:minimal -property:Configuration=Release -property:Platform=x64 -property:Version=2.1.1
   ```

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
   - Running the application and monitoring logs in `/logs` directory
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
- **appNames**: Application names or paths to proxy (partial matching supported)
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
- Monitor application logs in `/logs` directory
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
   - Dependencies: Newtonsoft.Json, NLog, Topshelf

### Important Files
- `socksify.sln`: Main Visual Studio solution file
- `README.md`: User documentation and setup instructions
- `.github/workflows/main.yml`: CI/CD build pipeline
- `sign/sign-update-release.ps1`: Code signing script for releases

### Include Directories
- `./include/`: Common headers (`Common.h`, `ndisapi.h`)
- `./ndisapi/`: NDIS API implementation
- `./netlib/`: Network utility C++ classes

## Common Tasks

### Repository Navigation
```bash
# Root directory listing
ls -la
# Output: ProxiFyre/, socksify/, ndisapi.lib/, include/, netlib/, sign/, README.md, socksify.sln

# Key configuration files
find . -name "*.json" -o -name "*.config" -o -name "packages.config"
# Output: ./ProxiFyre/App.config, ./ProxiFyre/NLog.config, ./ProxiFyre/packages.config

# Project structure
find . -name "*.csproj" -o -name "*.vcxproj" -o -name "*.sln"
# Output: ./ProxiFyre/ProxiFyre.csproj, ./socksify/socksify.vcxproj, ./ndisapi.lib/ndisapilib.vcxproj, ./socksify.sln
```

### Source Code Analysis
```bash
# Find C# files
find . -name "*.cs"
# Output: ./ProxiFyre/Program.cs, ./ProxiFyre/Properties/AssemblyInfo.cs

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
- **Artifacts**: Creates signed ZIP files for each platform

### Build Matrix
- Platforms: x86, x64, ARM64
- Configuration: Release only for CI builds
- Output: `bin\exe\{Platform}\Release\ProxiFyre.exe`