using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProxiFyreUI.Infrastructure
{
    /// <summary>
    /// Holds every validated app-local code/configuration file open without write/delete sharing
    /// so it cannot be replaced between validation and process/type loading.
    /// </summary>
    internal sealed class LifecycleExecutableLease : IDisposable
    {
        private const uint GenericRead = 0x80000000;
        private const uint FileReadAttributes = 0x00000080;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint OpenExisting = 3;
        private const uint FileAttributeDirectory = 0x00000010;
        private const uint FileAttributeReparsePoint = 0x00000400;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileFlagSequentialScan = 0x08000000;
        private const uint DriveFixed = 3;
        private const int ErrorMoreData = 234;

        private readonly List<FileStream> _streams;
        private readonly List<SafeFileHandle> _directoryHandles;

        private LifecycleExecutableLease(List<FileStream> streams,
            List<SafeFileHandle> directoryHandles)
        {
            _streams = streams;
            _directoryHandles = directoryHandles;
        }

        public static LifecycleExecutableLease Acquire(string path,
            Func<string, bool> validator)
        {
            return Acquire(new[] { path }, validator);
        }

        public static LifecycleExecutableLease Acquire(IEnumerable<string> paths,
            Func<string, bool> validator)
        {
            if (paths == null)
                throw new ArgumentNullException(nameof(paths));
            if (validator == null)
                throw new ArgumentNullException(nameof(validator));

            var verifiedPaths = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var path in paths)
            {
                if (string.IsNullOrWhiteSpace(path))
                    throw new FileNotFoundException("A required payload path is missing.");
                var fullPath = Path.GetFullPath(path);
                if (seen.Add(fullPath))
                    verifiedPaths.Add(fullPath);
            }

            if (verifiedPaths.Count == 0)
                throw new FileNotFoundException("No required payload files were supplied.");

            var streams = new List<FileStream>();
            var directoryHandles = new List<SafeFileHandle>();
            try
            {
                var leasedDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var path in verifiedPaths)
                    LeaseDirectoryChain(Path.GetDirectoryName(path), leasedDirectories,
                        directoryHandles);

                foreach (var path in verifiedPaths)
                    streams.Add(OpenRegularFile(path));
                foreach (var path in verifiedPaths)
                {
                    if (!validator(path))
                    {
                        throw new FileNotFoundException(
                            "A required payload file changed or does not have the expected integrity.",
                            path);
                    }
                }

                return new LifecycleExecutableLease(streams, directoryHandles);
            }
            catch
            {
                for (var index = streams.Count - 1; index >= 0; index--)
                    streams[index].Dispose();
                for (var index = directoryHandles.Count - 1; index >= 0; index--)
                    directoryHandles[index].Dispose();
                throw;
            }
        }

        private static void LeaseDirectoryChain(string directory,
            ISet<string> leasedDirectories, ICollection<SafeFileHandle> handles)
        {
            if (string.IsNullOrWhiteSpace(directory))
                throw new IOException("A required payload directory is unavailable.");

            var fullDirectory = Path.GetFullPath(directory);
            var root = Path.GetPathRoot(fullDirectory);
            if (string.IsNullOrWhiteSpace(root) || root.Length != 3 || root[1] != ':' ||
                GetDriveType(root) != DriveFixed)
                throw new IOException("A required payload directory is not on a fixed local volume.");

            var volumeName = new StringBuilder(64);
            if (!GetVolumeNameForVolumeMountPoint(root, volumeName, volumeName.Capacity) ||
                !IsRegisteredVolumeRoot(root, volumeName.ToString()))
                throw new IOException("A required payload volume cannot be pinned safely.");
            if (fullDirectory.Length > root.Length)
            {
                fullDirectory = fullDirectory.TrimEnd(Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar);
            }

            var current = root;
            var relative = fullDirectory.Substring(root.Length);
            foreach (var component in relative.Split(new[]
                     {
                         Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar
                     }, StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, component);
                if (!leasedDirectories.Add(current))
                    continue;

                var handle = CreateFile(current, FileReadAttributes,
                    FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting,
                    FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
                if (handle.IsInvalid)
                {
                    var error = Marshal.GetLastWin32Error();
                    handle.Dispose();
                    throw new Win32Exception(error,
                        "A required payload directory could not be locked: '" + current + "'.");
                }

                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    var error = Marshal.GetLastWin32Error();
                    handle.Dispose();
                    throw new Win32Exception(error,
                        "A required payload directory could not be inspected: '" + current + "'.");
                }
                if ((information.FileAttributes & FileAttributeDirectory) == 0 ||
                    (information.FileAttributes & FileAttributeReparsePoint) != 0)
                {
                    handle.Dispose();
                    throw new IOException(
                        "A required payload directory is not a normal directory: '" + current + "'.");
                }

                handles.Add(handle);
            }
        }

        private static bool IsRegisteredVolumeRoot(string root, string volumeName)
        {
            var volumePaths = new char[256];
            while (true)
            {
                uint requiredLength;
                if (GetVolumePathNamesForVolumeName(volumeName, volumePaths,
                        (uint)volumePaths.Length, out requiredLength))
                    break;

                if (Marshal.GetLastWin32Error() != ErrorMoreData ||
                    requiredLength <= volumePaths.Length || requiredLength > int.MaxValue)
                    return false;
                volumePaths = new char[(int)requiredLength];
            }

            var offset = 0;
            while (offset < volumePaths.Length && volumePaths[offset] != '\0')
            {
                var end = offset;
                while (end < volumePaths.Length && volumePaths[end] != '\0')
                    end++;
                if (end == volumePaths.Length)
                    return false;

                var registeredPath = new string(volumePaths, offset, end - offset);
                if (string.Equals(NormalizeVolumeRoot(registeredPath), NormalizeVolumeRoot(root),
                        StringComparison.OrdinalIgnoreCase))
                    return true;
                offset = end + 1;
            }

            return false;
        }

        private static string NormalizeVolumeRoot(string root)
        {
            return root.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar)
                       .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        }

        private static FileStream OpenRegularFile(string path)
        {
            // Open the directory entry itself first. Following a symlink here would lease its
            // old target while a later path-based Process/CLR operation could follow a
            // replacement link to different bytes.
            var handle = CreateFile(path, GenericRead, FileShareRead, IntPtr.Zero, OpenExisting,
                FileFlagOpenReparsePoint | FileFlagSequentialScan, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error,
                    "A required payload file could not be locked: '" + path + "'.");
            }

            try
            {
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information))
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "A required payload file could not be inspected: '" + path + "'.");
                if ((information.FileAttributes &
                     (FileAttributeDirectory | FileAttributeReparsePoint)) != 0)
                    throw new IOException("A required payload file is not a normal file: '" + path + "'.");

                return new FileStream(handle, FileAccess.Read);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            for (var index = _streams.Count - 1; index >= 0; index--)
                _streams[index].Dispose();
            for (var index = _directoryHandles.Count - 1; index >= 0; index--)
                _directoryHandles[index].Dispose();
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileTime
        {
            public uint LowDateTime;
            public uint HighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public FileTime CreationTime;
            public FileTime LastAccessTime;
            public FileTime LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
            ExactSpelling = true, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string fileName, uint desiredAccess,
            uint shareMode, IntPtr securityAttributes, uint creationDisposition,
            uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle file,
            out ByHandleFileInformation information);

        [DllImport("kernel32.dll", EntryPoint = "GetDriveTypeW", CharSet = CharSet.Unicode,
            ExactSpelling = true)]
        private static extern uint GetDriveType(string rootPathName);

        [DllImport("kernel32.dll", EntryPoint = "GetVolumeNameForVolumeMountPointW",
            CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumeNameForVolumeMountPoint(string volumeMountPoint,
            StringBuilder volumeName, int bufferLength);

        [DllImport("kernel32.dll", EntryPoint = "GetVolumePathNamesForVolumeNameW",
            CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumePathNamesForVolumeName(string volumeName,
            [Out] char[] volumePathNames, uint bufferLength, out uint returnLength);
    }

    internal static class PayloadHashValidator
    {
        public static bool HasExpectedSha256(string path, string expectedHash)
        {
            if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(expectedHash))
                return false;
            try
            {
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                           FileShare.Read))
                using (var sha256 = SHA256.Create())
                {
                    var actual = BitConverter.ToString(sha256.ComputeHash(stream))
                        .Replace("-", string.Empty);
                    return string.Equals(actual, expectedHash,
                        StringComparison.OrdinalIgnoreCase);
                }
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException ||
                                       ex is ArgumentException || ex is CryptographicException)
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Release builds validate and lease the UI's complete app-local managed dependency chain
    /// before any form type is created. The distribution is deliberately unsigned, so release
    /// integrity relies on the installed directory's access controls, the native host's module
    /// allow-list, fixed configuration hashes, and no-write/no-delete payload leases.
    /// </summary>
    internal static class UiStartupPayload
    {
        internal const string UiConfigurationSha256 =
            "104FEA6F8C0821CD27E28F0C0CC5F37B7F822168316AA1AE0FDEABBC1E81BF5D";

        public static IDisposable Acquire(string userInterfacePath)
        {
#if DEBUG
            // Debug output remains replaceable so an ordinary local rebuild can run in place.
            return null;
#else
            if (string.IsNullOrWhiteSpace(userInterfacePath))
                throw new FileNotFoundException("The ProxiFyre UI executable path is unavailable.");
            var fullUiPath = Path.GetFullPath(userInterfacePath);
            var directory = Path.GetDirectoryName(fullUiPath);
            if (string.IsNullOrWhiteSpace(directory))
                throw new FileNotFoundException("The ProxiFyre UI directory is unavailable.");

            return LifecycleExecutableLease.Acquire(
                GetStartupPayloadPaths(fullUiPath), IsTrustedUiPayloadFile);
#endif
        }

        internal static string[] GetStartupPayloadPaths(string userInterfacePath)
        {
            var fullUiPath = Path.GetFullPath(userInterfacePath);
            var directory = Path.GetDirectoryName(fullUiPath);
            if (string.IsNullOrWhiteSpace(directory))
                throw new ArgumentException("The UI executable must have a directory.",
                    nameof(userInterfacePath));

            return new[]
            {
                fullUiPath,
                Path.Combine(directory, "ProxiFyre.Configuration.dll"),
                Path.Combine(directory, "Newtonsoft.Json.dll"),
                Path.Combine(directory, "ProxiFyreUI.exe.config")
            };
        }

        internal static bool IsTrustedUiPayloadFile(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return false;
            var fileName = Path.GetFileName(path);
            if (string.Equals(fileName, "ProxiFyreUI.Managed.dll", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fileName, "ProxiFyre.Configuration.dll",
                    StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fileName, "Newtonsoft.Json.dll",
                    StringComparison.OrdinalIgnoreCase))
                return true;
            if (string.Equals(fileName, "ProxiFyreUI.exe.config",
                    StringComparison.OrdinalIgnoreCase))
                return PayloadHashValidator.HasExpectedSha256(path, UiConfigurationSha256);
            return false;
        }
    }
}
