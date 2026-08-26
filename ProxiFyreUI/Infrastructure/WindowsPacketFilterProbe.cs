using Microsoft.Win32.SafeHandles;
using ProxiFyre.Configuration;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.ServiceProcess;

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

    internal enum WindowsPacketFilterServiceState
    {
        Missing,
        Stopped,
        StartPending,
        OtherInstalled,
        Unknown
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

        private readonly Func<WindowsPacketFilterStatus> _deviceProbe;
        private readonly Func<WindowsPacketFilterServiceState> _serviceStateProbe;

        public WindowsPacketFilterProbe()
            : this(ProbeDevice, ProbeServiceState)
        {
        }

        internal WindowsPacketFilterProbe(Func<WindowsPacketFilterStatus> deviceProbe,
            Func<WindowsPacketFilterServiceState> serviceStateProbe)
        {
            _deviceProbe = deviceProbe ?? throw new ArgumentNullException(nameof(deviceProbe));
            _serviceStateProbe = serviceStateProbe ??
                                 throw new ArgumentNullException(nameof(serviceStateProbe));
        }

        public WindowsPacketFilterStatus GetStatus()
        {
            var serviceState = _serviceStateProbe();
            var deviceStatus = _deviceProbe();

            // The SCM dependency must exist even when its device remains loaded temporarily
            // after service registration is removed.
            if (serviceState == WindowsPacketFilterServiceState.Missing)
            {
                var details = "The NDISRD driver service is not installed.";
                if (!string.IsNullOrWhiteSpace(deviceStatus.Details))
                    details += " " + deviceStatus.Details;
                return WindowsPacketFilterStatus.Unavailable(deviceStatus.NativeErrorCode,
                    details);
            }

            if (deviceStatus.IsAvailable)
                return deviceStatus;

            // A stopped (or already starting) NDISRD service is a valid SCM dependency state.
            // Let ServiceController.Start ask SCM to start/wait for it instead of rejecting the
            // ProxiFyre operation merely because the device is not open yet. If registration
            // could not be queried, SCM remains the authoritative source of the eventual error.
            if (serviceState == WindowsPacketFilterServiceState.Stopped ||
                serviceState == WindowsPacketFilterServiceState.StartPending ||
                serviceState == WindowsPacketFilterServiceState.Unknown)
                return WindowsPacketFilterStatus.Available();

            return deviceStatus;
        }

        private static WindowsPacketFilterStatus ProbeDevice()
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

        private static WindowsPacketFilterServiceState ProbeServiceState()
        {
            try
            {
                using (var controller = new ServiceController(
                           ProxiFyrePaths.WindowsPacketFilterServiceName))
                {
                    var status = controller.Status;
                    if (status == ServiceControllerStatus.Stopped)
                        return WindowsPacketFilterServiceState.Stopped;
                    if (status == ServiceControllerStatus.StartPending)
                        return WindowsPacketFilterServiceState.StartPending;
                    return WindowsPacketFilterServiceState.OtherInstalled;
                }
            }
            catch (Exception ex) when (HasNativeError(ex, 1060))
            {
                return WindowsPacketFilterServiceState.Missing;
            }
            catch (Exception ex) when (ex is InvalidOperationException ||
                                       ex is Win32Exception ||
                                       ex is UnauthorizedAccessException ||
                                       ex is System.Security.SecurityException)
            {
                return WindowsPacketFilterServiceState.Unknown;
            }
        }

        private static bool HasNativeError(Exception exception, int errorCode)
        {
            for (var current = exception; current != null; current = current.InnerException)
            {
                var native = current as Win32Exception;
                if (native != null && native.NativeErrorCode == errorCode)
                    return true;
            }

            return false;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string fileName, uint desiredAccess,
            uint shareMode, IntPtr securityAttributes, uint creationDisposition,
            uint flagsAndAttributes, IntPtr templateFile);
    }
}
