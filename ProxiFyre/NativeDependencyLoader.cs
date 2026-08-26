using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ProxiFyre
{
    /// <summary>
    /// Establishes the process-wide native DLL search policy before the mixed-mode proxy engine
    /// can be loaded, then pins its direct Visual C++ runtime dependencies from System32.
    /// </summary>
    internal static class NativeDependencyLoader
    {
        private const uint LoadWithAlteredSearchPath = 0x00000008;
        private const uint LoadLibrarySearchSystem32 = 0x00000800;

        private static readonly string[] RequiredRuntimeLibraries =
        {
            "MSVCP140.dll",
            "MSVCP140_ATOMIC_WAIT.dll",
            "VCRUNTIME140.dll",
#if PROXIFYRE_REQUIRES_VCRUNTIME140_1
            // The current x64 socksify.dll imports the split exception-handling runtime.
            // x86 and ARM64 do not, and the x86 redistributable normally does not install it.
            "VCRUNTIME140_1.dll"
#endif
        };

        private static readonly object Sync = new object();
        private static IntPtr[] _preloadedModules;

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void Initialize()
        {
            lock (Sync)
            {
                if (_preloadedModules != null)
                    return;

                ConstrainDefaultSearchPathWhenSupported();
                _preloadedModules = PreloadRequiredRuntimeLibraries();
            }
        }

        private static void ConstrainDefaultSearchPathWhenSupported()
        {
            var kernel32 = GetModuleHandle("kernel32.dll");
            if (kernel32 == IntPtr.Zero)
                throw CreateWin32Exception("The Windows loader module could not be resolved.");

            // SetDefaultDllDirectories was introduced in Windows 8 and made available on
            // Windows 7 by KB2533623. Resolve it dynamically so an unpatched Windows 7 host can
            // use the explicit SystemDirectory preload fallback instead of failing type load.
            var entryPoint = GetProcAddress(kernel32, "SetDefaultDllDirectories");
            if (entryPoint == IntPtr.Zero)
                return;

            var setDefaultDllDirectories = (SetDefaultDllDirectoriesDelegate)
                Marshal.GetDelegateForFunctionPointer(entryPoint,
                    typeof(SetDefaultDllDirectoriesDelegate));
            if (!setDefaultDllDirectories(LoadLibrarySearchSystem32))
            {
                throw CreateWin32Exception(
                    "Windows rejected the System32-only native DLL search policy.");
            }
        }

        private static IntPtr[] PreloadRequiredRuntimeLibraries()
        {
            var systemDirectory = Environment.SystemDirectory;
            if (string.IsNullOrWhiteSpace(systemDirectory) || !Path.IsPathRooted(systemDirectory))
                throw new InvalidOperationException("The architecture-specific Windows SystemDirectory is unavailable.");

            var loadedModules = new List<IntPtr>(RequiredRuntimeLibraries.Length);
            try
            {
                foreach (var libraryName in RequiredRuntimeLibraries)
                {
                    var libraryPath = Path.Combine(systemDirectory, libraryName);
                    var module = LoadLibraryEx(libraryPath, IntPtr.Zero, LoadWithAlteredSearchPath);
                    if (module == IntPtr.Zero)
                    {
                        throw CreateWin32Exception(
                            "Required Visual C++ runtime library '" + libraryName +
                            "' could not be loaded from the Windows SystemDirectory.");
                    }

                    loadedModules.Add(module);
                }

                // Deliberately retain these loader references for process lifetime. Socksifier's
                // imports will bind to the trusted SystemDirectory modules already in memory.
                return loadedModules.ToArray();
            }
            catch
            {
                for (var index = loadedModules.Count - 1; index >= 0; index--)
                    FreeLibrary(loadedModules[index]);
                throw;
            }
        }

        private static Win32Exception CreateWin32Exception(string message)
        {
            var error = Marshal.GetLastWin32Error();
            return new Win32Exception(error, message + " " + new Win32Exception(error).Message);
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private delegate bool SetDefaultDllDirectoriesDelegate(uint directoryFlags);

        [DllImport("kernel32.dll", EntryPoint = "GetModuleHandleW", CharSet = CharSet.Unicode,
            ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("kernel32.dll", EntryPoint = "GetProcAddress", CharSet = CharSet.Ansi,
            ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string procedureName);

        [DllImport("kernel32.dll", EntryPoint = "LoadLibraryExW", CharSet = CharSet.Unicode,
            ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr LoadLibraryEx(string fileName, IntPtr file, uint flags);

        [DllImport("kernel32.dll", EntryPoint = "FreeLibrary", ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr module);
    }
}
