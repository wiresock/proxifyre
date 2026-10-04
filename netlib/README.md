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

The run ends with `netlib-tests summary: N run: V verified, U unsupported, F failed.`

Exit codes: `0` success; `1` at least one failed test; `4` no test matched the filter; `5` one or
more cases could not be exercised on this host and nothing failed. Unsupported cases print
`[ UNSUPPORTED ]` with the reason, are recorded as an `unsupported` property in the XML output,
and are not counted as verified; pass `--netlib_allow_unsupported` to accept them explicitly (CI
does so and reports each one as a warning). UNSUPPORTED is used only for documented conditions:
successful OS table captures showing a dual-stack path cannot be isolated, or a recognized socket
limitation (`environment_limitation` in `netlib-tests/test_support.h`). Helper-process failures
and OS table query failures are always test failures, with or without the flag.

The ownership tests use real loopback sockets and, for some cases, a helper child process started
from the same executable. Helpers run in a kill-on-close job object that they join during
`CreateProcessW` itself (`PROC_THREAD_ATTRIBUTE_JOB_LIST`), so a test process that dies at any
point after creating a helper, even before resuming it, takes the helper down with it. Helpers
inherit only their own pipe handles and must report readiness within 10 seconds. The tests do not
open the packet-filter driver or change routing.

Running the tests requires Windows 10 / Windows Server 2016 or newer (for the job-list process
attribute; on an older host the helper launch fails before any process is created). This is a
requirement of the test host only and does not change the supported platforms of the product.

`DISABLED_NetlibFailureProbe.*` tests inject faults into the real case bodies; they are run only
as subprocesses by `ProcessLookupFailureProbeTest` and `ProcessLookupProbeExitTest`, which check
their exit codes, output, and XML. `DISABLED_HelperLifecycleProbe.HoldAtCreationBoundary` runs
only as the parent subprocess of `HelperLifecycleTest`, which terminates it at the
process-creation boundary and verifies that the still-suspended helper exits.
