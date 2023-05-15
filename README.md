# Local SOCKS5 proxy router

An advanced version of socksify sample (https://github.com/wiresock/ndisapi/tree/master/examples/cpp/socksify).
Adds UDP and multiply proxy instances support.

## Build prerequisites 

* Install vcpkg https://vcpkg.io/en/getting-started.html  
* Use vcpkg to Install Microsoft GSL library  
    vcpkg install ms-gls  
    vcpkg install ms-gls:x64-windows  
* You may need to add online NuGet Package Source  
    Visual Studio->Tools->Options->NuGet Package Manager->Package Sources [Add nuget.org/https://nuget.org/api/v2]

## Projects

### ndisapi.lib

Adopted Windows Packet Filter NDISAPI static library project

### socksify

.Net C++/CLI class library implementing local SOCKS5 router functionality

### dotNetSocksProxy

.Net Windows console application for the testing socksify .Net C++/CLI class library


