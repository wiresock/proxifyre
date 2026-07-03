#include "pch.h"

using namespace System;
using namespace System::Reflection;
using namespace System::Runtime::CompilerServices;
using namespace System::Runtime::InteropServices;
using namespace System::Security::Permissions;

[assembly:AssemblyTitleAttribute(L"socksify")];
[assembly:AssemblyDescriptionAttribute(L"")];
[assembly:AssemblyConfigurationAttribute(L"")];
[assembly:AssemblyCompanyAttribute(L"")];
[assembly:AssemblyProductAttribute(L"socksify")];
[assembly:AssemblyCopyrightAttribute(L"Copyright NT KERNEL(c) 2022-2025")];
[assembly:AssemblyTrademarkAttribute(L"")];
[assembly:AssemblyCultureAttribute(L"")];

// Keep the major.minor in sync with the release tag. (The build-revision wildcard auto-fills
// the last two fields.) A prior release left this at 2.0.* while ProxiFyre.exe advanced, so the
// shipped socksify.dll reported a stale version; bumped for the 2.3.x line.
[assembly:AssemblyVersionAttribute("2.3.*")];

[assembly:ComVisible(false)];
