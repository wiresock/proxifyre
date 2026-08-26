using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ProxiFyreUI.Infrastructure
{
    public sealed class WindowsPacketFilterStatus
    {
        public const string DevicePath = @"\\.\NDISRD";
        public const string DownloadUrl = "https://github.com/wiresock/ndisapi/releases";

        private WindowsPacketFilterStatus(bool isAvailable, int? nativeErrorCode, string details)
        {
            IsAvailable = isAvailable;
            NativeErrorCode = nativeErrorCode;
            Details = details;
        }

        public bool IsAvailable { get; }
        public int? NativeErrorCode { get; }
        public string Details { get; }

        public string StartupMessage => IsAvailable
            ? null
            : "Windows Packet Filter (WinpkFilter) is not available. ProxiFyre requires the NDISRD driver. " +
              "Install it from " + DownloadUrl +
              ", restart Windows if requested, and try again.";

        public static WindowsPacketFilterStatus Available()
        {
            return new WindowsPacketFilterStatus(true, null, null);
        }

        public static WindowsPacketFilterStatus Unavailable(int? nativeErrorCode, string details)
        {
            return new WindowsPacketFilterStatus(false, nativeErrorCode, details);
        }
    }

    public interface IWindowsPacketFilterProbe
    {
        WindowsPacketFilterStatus GetStatus();
    }

    /// <summary>
    /// Performs the same capability check as the native NDISAPI constructor without loading
    /// socksify.dll into the GUI process. Opening the device with no requested access is
    /// non-invasive and works while another client is using the driver.
    /// </summary>
    public sealed class WindowsPacketFilterProbe : IWindowsPacketFilterProbe
    {
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint OpenExisting = 3;
        private const uint FileFlagOverlapped = 0x40000000;

        public WindowsPacketFilterStatus GetStatus()
        {
            try
            {
                using (var handle = CreateFile(WindowsPacketFilterStatus.DevicePath, 0,
                           FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting,
                           FileFlagOverlapped, IntPtr.Zero))
                {
                    if (!handle.IsInvalid)
                        return WindowsPacketFilterStatus.Available();

                    var error = Marshal.GetLastWin32Error();
                    return WindowsPacketFilterStatus.Unavailable(error,
                        "The NDISRD device could not be opened (Win32 error " + error + ": " +
                        new Win32Exception(error).Message + ").");
                }
            }
            catch (Exception ex) when (ex is DllNotFoundException || ex is EntryPointNotFoundException ||
                                       ex is TypeInitializationException)
            {
                return WindowsPacketFilterStatus.Unavailable(null,
                    "The NDISRD availability check failed: " + ex.Message);
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string fileName, uint desiredAccess,
            uint shareMode, IntPtr securityAttributes, uint creationDisposition,
            uint flagsAndAttributes, IntPtr templateFile);
    }
}
