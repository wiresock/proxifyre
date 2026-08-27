#include "pch.h"

using namespace System;
using namespace System::Reflection;
using namespace System::Runtime::CompilerServices;
using namespace System::Runtime::InteropServices;
using namespace System::Security::Permissions;

#define PROXIFYRE_STRINGIFY_IMPL(value) #value
#define PROXIFYRE_STRINGIFY(value) PROXIFYRE_STRINGIFY_IMPL(value)

[assembly:AssemblyTitleAttribute(L"socksify")];
[assembly:AssemblyDescriptionAttribute(L"")];
[assembly:AssemblyConfigurationAttribute(L"")];
[assembly:AssemblyCompanyAttribute(L"")];
[assembly:AssemblyProductAttribute(L"ProxiFyre")];
[assembly:AssemblyCopyrightAttribute(L"Copyright NT KERNEL(c) 2022-2026")];
[assembly:AssemblyTrademarkAttribute(L"")];
[assembly:AssemblyCultureAttribute(L"")];

// The project supplies this value from the repository release version so the C++/CLI bridge
// reports the same assembly, file, and product version as the engine and management UI.
[assembly:AssemblyVersionAttribute(PROXIFYRE_STRINGIFY(PROXIFYRE_VERSION))];
[assembly:AssemblyFileVersionAttribute(PROXIFYRE_STRINGIFY(PROXIFYRE_VERSION))];
[assembly:AssemblyInformationalVersionAttribute(PROXIFYRE_STRINGIFY(PROXIFYRE_VERSION))];

[assembly:ComVisible(false)];
