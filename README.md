# ProxiFyre: SOCKS5 Proxifier for Windows

ProxiFyre elevates the foundational capabilities of the Windows Packet Filter's [socksify](https://github.com/wiresock/ndisapi/tree/master/examples/cpp/socksify) demo, introducing robust enhancements. Not only does it seamlessly integrate support for UDP, but it also empowers users with the flexibility of managing multiple proxy instances. Streamlining its configuration process, ProxiFyre dynamically sources its settings from an `app-config.json` file, ensuring a more intuitive and user-friendly experience. Furthermore, with adaptability in mind, ProxiFyre can be effortlessly configured to run as a Windows Service, providing continuous operation without the need for manual intervention.

As of **v2.1.1**, ProxiFyre also supports **process exclusions**, allowing you to specify which applications should *bypass* the proxy while others remain proxied. Additionally, performance has been improved through intelligent caching of process matching.

---

## Configuration

The application uses a configuration file named `app-config.json`. This JSON file should contain configurations for different applications. Each configuration object should have the following properties:

- **appNames**: An array of strings representing the names of applications this configuration applies to.
- **socks5ProxyEndpoint**: A string that specifies the SOCKS5 proxy endpoint.
- **username**: A string that specifies the username for the proxy (optional).
- **password**: A string that specifies the password for the proxy (optional).
- **supportedProtocols**: An array of strings specifying the supported protocols (e.g., `"TCP"`, `"UDP"`).
- **excludes** *(new in v2.1.1)*: An array of application names or paths to exclude from proxy routing.

---

### LogLevel

LogLevel can have one of the following values which define the detail of the log:  
`Error`, `Warning`, `Info`, `Debug`, `All`

---

### IPv6 Blocking *(new in v2.2.0)*

- **blockIPv6** *(optional)*: A boolean value that enables IPv6 traffic blocking for proxied applications.
  - When set to `true`, all IPv6 traffic from applications listed in `appNames` will be dropped, preventing IPv6 IP leaks.
  - When set to `false` or omitted, IPv6 traffic passes through normally (default behavior).
  - This feature is particularly useful for preventing IP leaks in applications like Discord that may use IPv6 for voice channels while IPv4 traffic goes through the proxy.

Example:
```json
{
  "logLevel": "Info",
  "blockIPv6": true,
  "proxies": [...],
  "excludes": [...]
}
```

---

### appNames

- The application name can be a **partial** or **full name** of the executable.  
  - Example: `firefox` or `firefox.exe` will both match the Firefox browser.  
  - Any application containing that substring will also match, e.g., `NewFirefox.exe`.  
- If the pattern contains **slashes or backslashes**, it is treated as a **pathname**.  
  - This allows targeting an entire folder (useful for UWP apps).  
  - Example: `C:\\Program Files\\WindowsApps\\ROBLOXCORPORATION.ROBLOX`

---

### Excludes (new in v2.1.1)

The `excludes` section lets you define processes that should **bypass the proxy**.  
This is useful when you want a global proxy setup but keep certain apps (like browsers, local dev tools, or games) unproxied.

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
      "supportedProtocols": ["TCP", "UDP"]
    }
  ],
  "excludes": [
    "firefox",
    "C:\\Program Files\\LocalApp\\NotProxiedApp.exe"
  ]
}
````

---

### SOCKS5 Proxy Authorization

If the SOCKS5 proxy does not support authorization, you can skip the `username` and `password` fields in the configuration.

---

## Example Configuration

```json
{
 "logLevel": "Error",
 "blockIPv6": true,
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

4. **Run the Application**: Navigate to the directory where you extracted the software. Find the main application executable (`ProxiFyre.exe`) and run it. It's recommended to run the application as an administrator to ensure all functionalities work as expected.

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
