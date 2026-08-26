using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

#if PROXIFYRE_ENGINE
namespace ProxiFyre
#else
namespace ProxiFyre.Configuration
#endif
{
    /// <summary>
    /// Verifies that an engine selected for LocalSystem service execution cannot be replaced by
    /// a standard user while the service is stopped. This is deliberately stricter than merely
    /// checking whether the current elevated process can write the directory.
    /// </summary>
#if PROXIFYRE_ENGINE
    internal static class EngineServiceInstallLocationPolicy
#else
    public static class ServiceInstallLocationPolicy
#endif
    {
        private const string EngineExecutableName = "ProxiFyre.exe";
        private const string ConfigurationFileName = "app-config.json";
        private const string SampleConfigurationFileName = "app-config.sample.json";
        private const int GenericAll = 0x10000000;
        private const int GenericWrite = 0x40000000;
        private const string TrustedInstallerSid =
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        private const uint DriveFixed = 3;
        private const int ErrorMoreData = 234;

        private static readonly HashSet<string> AllowedPortableExecutables =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "ProxiFyre.exe",
                "ProxiFyreUI.exe",
                "ProxiFyreUI.Managed.dll",
                "ProxiFyre.Configuration.dll",
                "socksify.dll",
                "Newtonsoft.Json.dll",
                "NLog.dll",
                "Topshelf.dll"
            };

        private const FileSystemRights PayloadDangerousRights =
            FileSystemRights.Write |
            FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership;

        private const FileSystemRights AncestorDangerousRights =
            FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership;

        public static bool IsProtected(string engineExecutablePath, out string failureReason)
        {
            failureReason = null;
            string fullEnginePath;
            string engineDirectory;
            try
            {
                fullEnginePath = Path.GetFullPath(engineExecutablePath ?? string.Empty);
                engineDirectory = Path.GetDirectoryName(fullEnginePath);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException ||
                                       ex is PathTooLongException)
            {
                failureReason = "The service executable path is invalid.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(engineDirectory) ||
                !string.Equals(Path.GetFileName(fullEnginePath), EngineExecutableName,
                    StringComparison.OrdinalIgnoreCase) ||
                !File.Exists(fullEnginePath))
            {
                failureReason = "The service executable path is missing or invalid.";
                return false;
            }

            try
            {
                var volumeRoot = Path.GetPathRoot(fullEnginePath);
                if (!IsDirectFixedVolumeRoot(volumeRoot))
                {
                    failureReason =
                        "The LocalSystem service payload must be stored on a fixed local volume.";
                    return false;
                }

                if (HasLoaderRedirection(engineDirectory))
                {
                    failureReason =
                        "The engine directory contains an external manifest or DLL-redirection marker.";
                    return false;
                }

                string unexpectedModule;
                if (TryFindUnexpectedPortableExecutable(engineDirectory, out unexpectedModule))
                {
                    failureReason = "The engine directory contains unexpected executable module '" +
                                    unexpectedModule + "'.";
                    return false;
                }

                if (!HasProtectedDirectoryChain(engineDirectory, out failureReason))
                    return false;

                foreach (var filePath in Directory.EnumerateFiles(engineDirectory,
                             "*", SearchOption.TopDirectoryOnly).Where(IsSecuritySensitiveFile))
                {
                    if (IsReparsePoint(filePath))
                    {
                        failureReason = "A service payload file is a reparse point: '" +
                                        Path.GetFileName(filePath) + "'.";
                        return false;
                    }

                    if (!HasProtectedSecurity(new FileInfo(filePath), PayloadDangerousRights,
                            false, out failureReason))
                        return false;
                }

                return true;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException ||
                                       ex is ArgumentException ||
                                       ex is System.Security.SecurityException)
            {
                failureReason = "Windows could not verify the service directory permissions: " +
                                ex.Message;
                return false;
            }
        }

        internal static bool IsAllowedPortableExecutable(string fileName)
        {
            return !string.IsNullOrWhiteSpace(fileName) &&
                   AllowedPortableExecutables.Contains(fileName);
        }

        internal static bool HasProtectedDirectoryChain(string directory,
            out string failureReason)
        {
            return HasProtectedDirectoryChain(directory, true, out failureReason);
        }

        internal static bool HasProtectedDirectoryChain(string directory,
            bool isPayloadDirectory, out string failureReason)
        {
            var currentDirectory = new DirectoryInfo(Path.GetFullPath(directory));
            while (currentDirectory != null)
            {
                if (IsReparsePoint(currentDirectory.FullName))
                {
                    failureReason = "The service directory chain contains a reparse point: '" +
                                    currentDirectory.FullName + "'.";
                    return false;
                }

                var dangerousRights = isPayloadDirectory
                    ? PayloadDangerousRights
                    : AncestorDangerousRights;
                if (!HasProtectedSecurity(currentDirectory, dangerousRights,
                        isPayloadDirectory, out failureReason))
                    return false;

                currentDirectory = currentDirectory.Parent;
                isPayloadDirectory = false;
            }

            failureReason = null;
            return true;
        }

        internal static bool IsTrustedOwner(SecurityIdentifier identity)
        {
            return identity != null &&
                   (identity.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
                    identity.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
                    string.Equals(identity.Value, TrustedInstallerSid,
                        StringComparison.OrdinalIgnoreCase));
        }

        internal static bool GrantsDangerousAccess(FileSystemAccessRule rule,
            FileSystemRights dangerousRights, bool includeInheritedChildRights)
        {
            if (rule == null || rule.AccessControlType != AccessControlType.Allow)
                return false;

            var identity = rule.IdentityReference as SecurityIdentifier;
            if (IsTrustedRuleIdentity(identity))
                return false;
            if (!includeInheritedChildRights &&
                (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0)
                return false;

            var rawRights = unchecked((int)rule.FileSystemRights);
            return (rawRights & GenericAll) != 0 ||
                   (rawRights & GenericWrite) != 0 ||
                   (rule.FileSystemRights & dangerousRights) != 0;
        }

        private static bool HasProtectedSecurity(FileSystemInfo fileSystemInfo,
            FileSystemRights dangerousRights, bool includeInheritedChildRights,
            out string failureReason)
        {
            FileSystemSecurity security;
            var directoryInfo = fileSystemInfo as DirectoryInfo;
            if (directoryInfo != null)
                security = directoryInfo.GetAccessControl(AccessControlSections.Access |
                                                          AccessControlSections.Owner);
            else
                security = ((FileInfo)fileSystemInfo).GetAccessControl(
                    AccessControlSections.Access | AccessControlSections.Owner);

            var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
            if (!IsTrustedOwner(owner))
            {
                failureReason = "'" + fileSystemInfo.FullName +
                                "' is owned by an identity that can modify its permissions without administrator approval.";
                return false;
            }

            foreach (FileSystemAccessRule rule in rules)
            {
                if (GrantsDangerousAccess(rule, dangerousRights,
                        includeInheritedChildRights))
                {
                    failureReason = "'" + fileSystemInfo.FullName +
                                    "' grants write, delete, or permission-control access to '" +
                                    rule.IdentityReference.Value + "'.";
                    return false;
                }
            }

            failureReason = null;
            return true;
        }

        private static bool IsTrustedRuleIdentity(SecurityIdentifier identity)
        {
            return IsTrustedOwner(identity);
        }

        private static bool HasLoaderRedirection(string directory)
        {
            return File.Exists(Path.Combine(directory, "ProxiFyre.exe.local")) ||
                   Directory.Exists(Path.Combine(directory, "ProxiFyre.exe.local")) ||
                   File.Exists(Path.Combine(directory, "ProxiFyre.exe.manifest"));
        }

        private static bool TryFindUnexpectedPortableExecutable(string directory,
            out string unexpectedFileName)
        {
            foreach (var filePath in Directory.EnumerateFiles(directory, "*",
                         SearchOption.TopDirectoryOnly))
            {
                var extension = Path.GetExtension(filePath);
                if (!string.Equals(extension, ".exe", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(extension, ".dll", StringComparison.OrdinalIgnoreCase))
                    continue;

                var fileName = Path.GetFileName(filePath);
                if (!IsAllowedPortableExecutable(fileName))
                {
                    unexpectedFileName = fileName;
                    return true;
                }
            }

            unexpectedFileName = null;
            return false;
        }

        private static bool IsSecuritySensitiveFile(string path)
        {
            var extension = Path.GetExtension(path);
            if (string.Equals(extension, ".exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(extension, ".dll", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(extension, ".config", StringComparison.OrdinalIgnoreCase))
                return true;

            var name = Path.GetFileName(path);
            return string.Equals(name, ConfigurationFileName,
                       StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, SampleConfigurationFileName,
                       StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsReparsePoint(string path)
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }

        private static bool IsDirectFixedVolumeRoot(string root)
        {
            if (string.IsNullOrWhiteSpace(root) || root.Length != 3 || root[1] != ':' ||
                root[2] != Path.DirectorySeparatorChar || GetDriveType(root) != DriveFixed)
                return false;

            // GetDriveType reports mutable DOS-device aliases as fixed drives. Require both the
            // volume GUID and a mount-manager-registered root; LocalSystem may not see per-logon
            // aliases, and their targets can otherwise be rebound after validation.
            var volumeName = new StringBuilder(64);
            return GetVolumeNameForVolumeMountPoint(root, volumeName, volumeName.Capacity) &&
                   IsRegisteredVolumeRoot(root, volumeName.ToString());
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
}
