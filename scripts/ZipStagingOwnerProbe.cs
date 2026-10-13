// Test-only helper: attempt real mutations with the creating user's admin group
// disabled and privileges removed. No payload assemblies are loaded here.
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

public static class ZipStagingOwnerProbe
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CreateRestrictedToken(IntPtr token, uint flags,
        uint disableCount, SidAndAttributes[] disable, uint deleteCount, IntPtr delete,
        uint restrictCount, IntPtr restrict, out SafeAccessTokenHandle restricted);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attributes,
        int impersonationLevel, int tokenType, out SafeAccessTokenHandle duplicate);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(SafeAccessTokenHandle token,
        int informationClass, ref IntPtr information, int length);

    private static void CreateUserOwnedObjects(WindowsIdentity identity, string directory, string file)
    {
        var userBytes = new byte[identity.User.BinaryLength];
        identity.User.GetBinaryForm(userBytes, 0);
        var ownerSid = Marshal.AllocHGlobal(userBytes.Length);
        try
        {
            Marshal.Copy(userBytes, 0, ownerSid, userBytes.Length);
            SafeAccessTokenHandle creator;
            // Duplicate/impersonate/query/adjust-default, SecurityImpersonation,
            // TokenImpersonation. Change only the duplicate's default owner.
            if (!DuplicateTokenEx(identity.Token, 0x8e, IntPtr.Zero, 2, 2, out creator))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            using (creator)
            {
                if (!SetTokenInformation(creator, 4 /* TokenOwner */, ref ownerSid, IntPtr.Size))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                using (WindowsIdentity.Impersonate(creator.DangerousGetHandle()))
                {
                    // Default creation attributes are essential: supplying an
                    // owner-only descriptor to CreateDirectory disables inheritance.
                    Directory.CreateDirectory(directory);
                    File.WriteAllBytes(file, new byte[] { 42 });
                }
            }
        }
        finally { Marshal.FreeHGlobal(ownerSid); }
    }

    public static void AssertProtected(string parent)
    {
        using (var identity = WindowsIdentity.GetCurrent())
        {
            var user = identity.User;
            var directory = Path.Combine(parent, "owner-probe-" + Guid.NewGuid().ToString("N"));
            var file = Path.Combine(directory, "inert.txt");
            try
            {
                CreateUserOwnedObjects(identity, directory, file);
                if (!File.GetAccessControl(file).GetOwner(typeof(SecurityIdentifier)).Equals(user) ||
                    !Directory.GetAccessControl(directory).GetOwner(typeof(SecurityIdentifier)).Equals(user))
                    throw new InvalidOperationException("Owner probe did not create user-owned objects.");

                var admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                var bytes = new byte[admin.BinaryLength];
                admin.GetBinaryForm(bytes, 0);
                var sid = Marshal.AllocHGlobal(bytes.Length);
                try
                {
                    Marshal.Copy(bytes, 0, sid, bytes.Length);
                    SafeAccessTokenHandle restricted;
                    // DISABLE_MAX_PRIVILEGE plus Administrators as deny-only.
                    if (!CreateRestrictedToken(identity.Token, 1, 1,
                        new[] { new SidAndAttributes { Sid = sid } }, 0, IntPtr.Zero,
                        0, IntPtr.Zero, out restricted))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    using (restricted)
                    using (WindowsIdentity.Impersonate(restricted.DangerousGetHandle()))
                    {
                        using (var reduced = WindowsIdentity.GetCurrent())
                        {
                            if (!reduced.User.Equals(user) || new WindowsPrincipal(reduced)
                                .IsInRole(WindowsBuiltInRole.Administrator))
                                throw new InvalidOperationException("Owner probe must retain the user SID without admin access.");
                        }
                        if (File.ReadAllBytes(file)[0] != 42)
                            throw new InvalidOperationException("Owner probe must retain read access.");
                        Denied("file DACL", delegate {
                            var acl = File.GetAccessControl(file);
                            acl.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.Write, AccessControlType.Allow));
                            File.SetAccessControl(file, acl);
                        });
                        Denied("directory DACL", delegate {
                            var acl = Directory.GetAccessControl(directory);
                            acl.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.Write, AccessControlType.Allow));
                            Directory.SetAccessControl(directory, acl);
                        });
                        Denied("file contents", delegate { File.WriteAllText(file, "changed"); });
                        Denied("child creation", delegate { File.WriteAllText(Path.Combine(directory, "injected.txt"), "changed"); });
                    }
                }
                finally { Marshal.FreeHGlobal(sid); }
            }
            finally
            {
                // Only the unique child just created by this helper is removed.
                if (!String.Equals(Path.GetDirectoryName(Path.GetFullPath(directory)),
                        Path.GetFullPath(parent).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase) ||
                    (Directory.Exists(directory) && (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0))
                    throw new InvalidOperationException("Unexpected owner-probe cleanup path.");
                if (Directory.Exists(directory))
                    Directory.Delete(directory, true);
            }
        }
    }

    private static void Denied(string operation, Action action)
    {
        try { action(); }
        catch (UnauthorizedAccessException) { return; }
        throw new InvalidOperationException("Unprivileged owner could mutate " + operation + ".");
    }
}
