# ProxiFyre: SOCKS5 Proxifier for Windows

This project is an advanced version of the Windows Packet Filter [socksify](https://github.com/wiresock/ndisapi/tree/master/examples/cpp/socksify) demo. It enhances the base version with added support for UDP and multiple proxy instances. Additionally, it now reads its configuration from an `app-config.json` file.

## Configuration

The application now uses a configuration file named `app-config.json`. This JSON file should contain an array of configurations for different applications. Each configuration object should have the following properties:

- `appNames`: An array of strings representing the names of applications this configuration applies to.
- `socks5ProxyEndpoint`: A string that specifies the SOCKS5 proxy endpoint.
- `username`: A string that specifies the username for the proxy.
- `password`: A string that specifies the password for the proxy.

Here is an example configuration:

```json
[
    {
        "appNames": ["chrome", "chrome_canary"],
        "socks5ProxyEndpoint": "158.101.205.51:1080",
        "username": "username1",
        "password": "password1"
    },
    {
        "appNames": ["firefox", "firefox_dev"],
        "socks5ProxyEndpoint": "159.101.205.52:1080",
        "username": "username2",
        "password": "password2"
    }
]
```

## Quick Start Guide

This guide provides step-by-step instructions on how to set up and run the Local SOCKS5 Proxy Router application. 

### Pre-installation Steps

1. **Download and Install Windows Packet Filter (WinpkFilter)**: This is a critical dependency for our project. Please visit the [Windows Packet Filter Github page](https://github.com/wiresock/ndisapi/releases) to download and install the latest version.

### Installation Steps

2. **Download the Latest Release**: Visit our [GitHub page](https://github.com/wiresock/socksify/releases) to download the latest release of the Local SOCKS5 Proxy Router software.

3. **Unzip the Software**: After downloading, extract the contents of the .zip file to your preferred location.

4. **Create `app-config.json` File**: Following the template provided in the Configuration section of this document, create an `app-config.json` file. This file is crucial for the software to function properly. Save this file in the main application folder.

### Running the Application

5. **Run the Application**: Navigate to the directory where you extracted the software. Find the main application executable (`.exe` file) and run it. It's recommended to run the application as an administrator to ensure all functionalities work as expected.

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



