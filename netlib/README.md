# netlib

Utility C++ classes used for the network development.

## Native tests

`netlib-tests` (`netlib-tests/netlib-tests.vcxproj`) is a native x64 GoogleTest executable for
netlib code. It is test-only: no product project references it, it is not part of the release
payload, and it has only x64 configurations (the solution's x86 and ARM64 configurations do not
build it). Test sources live under `netlib/test/`.

Prerequisites: Visual Studio 2022 (v143 toolset) and `ms-gsl:x64-windows` from vcpkg with
`vcpkg integrate install`, as for the product build.

From a VS 2022 developer PowerShell at the repository root (the same commands run in
`.github/workflows/native-tests.yml`):

```powershell
msbuild netlib-tests\netlib-tests.vcxproj -t:Restore -p:RestorePackagesConfig=true "-p:SolutionDir=$PWD\" -p:Platform=x64
msbuild socksify.sln -t:netlib-tests -m -p:Configuration=Debug -p:Platform=x64
.\bin\tests\x64\Debug\netlib-tests.exe
```

`nuget restore socksify.sln` also restores the GoogleTest package when the NuGet CLI is
available. Use `Release` in place of `Debug` for the optimized build.

Exit codes: `0` success; `1` assertion failure; `4` no test matched the filter; `5` one or more
cases could not be exercised on this host. Such cases print `[ UNSUPPORTED ]` with the reason and
are not counted as verified; pass `--netlib_allow_unsupported` to accept them explicitly (CI does
so and reports each one as a warning).

The ownership tests use real loopback sockets and, for some cases, a helper child process started
from the same executable. They do not open the packet-filter driver or change routing.
