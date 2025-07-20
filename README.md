# ProxiFyre: SOCKS5 Proxifier for Windows

ProxiFyre elevates the foundational capabilities of the Windows Packet Filter's [socksify](https://github.com/wiresock/ndisapi/tree/master/examples/cpp/socksify) demo, introducing robust enhancements. Not only does it seamlessly integrate support for UDP, but it also empowers users with the flexibility of managing multiple proxy instances. Streamlining its configuration process, ProxiFyre now dynamically sources its settings from an app-config.json file, ensuring a more intuitive and user-friendly experience. Furthermore, with its adaptability in mind, ProxiFyre can be effortlessly configured to run as a Windows Service, providing continuous operation without the need for manual intervention.

## Configuration

The application uses a configuration file named app-config.json. This JSON file should contain configurations for different applications. Each configuration object should have the following properties:

- **appNames**: An array of strings representing the names of applications this configuration applies to.
- **socks5ProxyEndpoint**: A string that specifies the SOCKS5 proxy endpoint.
- **username**: A string that specifies the username for the proxy.
- **password**: A string that specifies the password for the proxy.
- **supportedProtocols**: An array of strings specifying the supported protocols (e.g., "TCP", "UDP").

### LogLevel

LogLevel can have one of the following values which define the detail of the log: `None`, `Info`, `Deb`, `All`

### appNames

On the application name, it can be a partial name or full name of the executable, e.g. `firefox` or `firefox.exe` both will work for the firefox browser, but also any application whose name includes `firefox` or `firefox.exe`, e.g. `NewFirefox.exe`. If the pattern specified in the appName contains slashes or backslashes then it is treated as a pathname and instead of matching the executable name, the full pathname is matched against the pattern. It allows specifying an entire folder using a full or partial path which can be convenient for UWP applications, e.g. `C:\\Program Files\\WindowsApps\\ROBLOXCORPORATION.ROBLOX` for ROBLOX.

### SOCKS5 Proxy Authorization

If the SOCKS5 proxy does not support authorization, you can skip the username and password in the configuration.

Here is an example configuration:

```json
{
 "logLevel": "Error",
 "proxies": [
         {
         "appNames": ["chrome", "C:\\Program Files\\WindowsApps\\ROBLOXCORPORATION.ROBLOX"],
         "socks5ProxyEndpoint": "158.101.205.51:1080",
         "username": "username1",
         "password": "password1",
         "supportedProtocols": ["TCP", "UDP"]
         },
         {
         "appNames": ["firefox", "firefox_dev"],
         "socks5ProxyEndpoint": "127.0.0.1:8080",
         "supportedProtocols": ["TCP"]
         }
     ]
}
```

## Quick Start Guide

This guide provides step-by-step instructions on how to set up and run the ProxiFyre application. 

### Pre-installation Steps

#### 1. Install Windows Packet Filter (WinpkFilter)

Windows Packet Filter is a critical dependency for our project. 

- Visit the [Windows Packet Filter Github page](https://github.com/wiresock/ndisapi/releases) to download the latest version.
- Follow the instructions on the page to install it.

#### 2. Install Visual Studio Runtime Libraries

Visual Studio Runtime Libraries are required for running applications developed with Visual Studio.

- Go to [Visual Studio 2022 redistributable download page](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170)
- Identify your system architecture (x64, x86, or ARM64).
- Download the appropriate installer for your platform to ensure compatibility and optimal performance.
  - For x64 systems, download the x64 installer.
  - For x86 systems, download the x86 installer.
  - For ARM64 systems, download the ARM64 installer.
- Locate the downloaded installer and double-click on it to begin the installation.
- Follow the on-screen instructions to complete the installation

Please ensure you download the correct installer to avoid any installation issues.

### Installation Steps

2. **Download the Latest Release**: Visit our [GitHub page](https://github.com/wiresock/socksify/releases) to download the latest release of the ProxiFyre software.

3. **Unzip the Software**: After downloading, extract the contents of the .zip file to your preferred location.

4. **Create `app-config.json` File**: Following the template provided in the Configuration section of this document, create an `app-config.json` file. This file is crucial for the software to function properly. Save this file in the main application folder.

### Running the Application

5. **Run the Application**: Navigate to the directory where you extracted the software. Find the main application executable (`.exe` file) and run it. It's recommended to run the application as an administrator to ensure all functionalities work as expected.

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

### Logging

Logs are saved in the application folder under the `/logs` directory. The details and verbosity of the logs depend on the configuration set in the `app-config.json` file.

## Build Prerequisites 

Before starting the build process, ensure the following requirements are met:

1. **Install vcpkg:** You can download and install vcpkg from the official website [here](https://vcpkg.io/en/getting-started.html).

2. **Install Microsoft GSL library via vcpkg:** Once vcpkg is installed, use it to download and install the Microsoft GSL library. Run the following commands in your terminal:

    ```
   vcpkg install ms-gsl:x86-windows ms-gsl:x64-windows ms-gsl:arm64-windows
    ```

3. **Add online NuGet Package Source:** In some cases, you may need to add an online NuGet Package Source. To do this, navigate to `Visual Studio->Tools->Options->NuGet Package Manager->Package Sources` and add `https://nuget.org/api/v2`.

## Projects

This repository consists of three main projects:

### 1. ndisapi.lib

This is an adopted Windows Packet Filter [NDISAPI](https://github.com/wiresock/ndisapi) static library project.

### 2. socksify

This project is a .Net C++/CLI class library that implements the local SOCKS5 router functionality.

### 3. ProxiFyre

This is a .Net-based Windows console application that employs the functionality provided by the socksify .Net C++/CLI class library.



