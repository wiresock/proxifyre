# Local SOCKS5 Proxy Router

This project is an advanced version of the Windows Packet Filter [socksify](https://github.com/wiresock/ndisapi/tree/master/examples/cpp/socksify) demo. It enhances the base version with added support for UDP and multiple proxy instances.

## Build Prerequisites 

Before starting the build process, ensure the following requirements are met:

1. **Install vcpkg:** You can download and install vcpkg from the official website [here](https://vcpkg.io/en/getting-started.html).

2. **Install Microsoft GSL library via vcpkg:** Once vcpkg is installed, use it to download and install the Microsoft GSL library. Run the following commands in your terminal:

    ```
   vcpkg install ms-gsl:x86-windows ms-gsl:x64-windows ms-gsl:arm64-windows ms-gsl:x86-windows-static ms-gsl:x64-windows-static ms-gsl:arm64-windows-static
    ```

3. **Add online NuGet Package Source:** In some cases, you may need to add an online NuGet Package Source. To do this, navigate to `Visual Studio->Tools->Options->NuGet Package Manager->Package Sources` and add `https://nuget.org/api/v2`.

## Projects

This repository consists of three main projects:

### 1. ndisapi.lib

This is an adopted Windows Packet Filter [NDISAPI](https://github.com/wiresock/ndisapi) static library project.

### 2. socksify

This project is a .Net C++/CLI class library that implements the local SOCKS5 router functionality.

### 3. dotNetSocksProxy

This is a .Net Windows console application designed for testing the socksify .Net C++/CLI class library.



