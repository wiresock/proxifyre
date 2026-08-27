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

        private WindowsPacketFilterStatus(bool isAvailable, int? nativeErrorCode, string details,
            bool deviceOpened)
        {
            IsAvailable = isAvailable;
            NativeErrorCode = nativeErrorCode;
            Details = details;
            DeviceOpened = deviceOpened;
        }

        public bool IsAvailable { get; }
        public int? NativeErrorCode { get; }
        public string Details { get; }
        internal bool DeviceOpened { get; }

        public string StartupMessage => IsAvailable
            ? null
            : "Windows Packet Filter (WinpkFilter) is unavailable or incompatible. " +
              "ProxiFyre requires a compatible NDISRD driver. Install or update it from " + DownloadUrl +
              ", restart Windows if requested, and try again.";

        public static WindowsPacketFilterStatus Available()
        {
            return new WindowsPacketFilterStatus(true, null, null, false);
        }

        public static WindowsPacketFilterStatus Unavailable(int? nativeErrorCode, string details)
        {
            return new WindowsPacketFilterStatus(false, nativeErrorCode, details, false);
        }

        internal static WindowsPacketFilterStatus ActiveDeviceUnavailable(int? nativeErrorCode,
            string details)
        {
            return new WindowsPacketFilterStatus(false, nativeErrorCode, details, true);
        }

        internal static WindowsPacketFilterStatus CompatibleDevice()
        {
            return new WindowsPacketFilterStatus(true, null, null, true);
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
    /// Probes the active NDISRD device and verifies its API version without loading socksify.dll
    /// into the GUI process. Opening the device with no requested access is non-invasive and works
    /// while another client is using the driver.
    /// </summary>
    public sealed class WindowsPacketFilterProbe : IWindowsPacketFilterProbe
    {
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint OpenExisting = 3;
        private const uint FileDeviceNdisrd = 0x00008300;
        private const uint NdisrdIoctlIndex = 0x830;
        private const uint MethodBuffered = 0;
        private const uint FileAnyAccess = 0;
        internal const uint IoctlNdisrdGetVersion =
            (FileDeviceNdisrd << 16) | (FileAnyAccess << 14) |
            (NdisrdIoctlIndex << 2) | MethodBuffered;
        internal const uint MinimumCompatibleApiVersion = 0x06013000;
        internal const ushort RequiredApiMajor = 0x0003;
        internal const ushort MinimumApiMinor = 0x0601;

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

            // A stopped (or already starting) NDISRD service is a valid SCM dependency state when
            // its device is not open yet. Let ServiceController.Start ask SCM to start/wait for it.
            // Once the device opens, however, a failed or incompatible version response is an
            // active-driver failure and must not be hidden by a stale SCM state.
            if (!deviceStatus.DeviceOpened &&
                (serviceState == WindowsPacketFilterServiceState.Stopped ||
                 serviceState == WindowsPacketFilterServiceState.StartPending ||
                 serviceState == WindowsPacketFilterServiceState.Unknown))
                return WindowsPacketFilterStatus.Available();

            return deviceStatus;
        }

        private static WindowsPacketFilterStatus ProbeDevice()
        {
            try
            {
                using (var handle = CreateFile(WindowsPacketFilterStatus.DevicePath, 0,
                           FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting,
                           0, IntPtr.Zero))
                {
                    if (handle.IsInvalid)
                    {
                        var error = Marshal.GetLastWin32Error();
                        return WindowsPacketFilterStatus.Unavailable(error,
                            "The NDISRD device could not be opened (Win32 error " + error + ": " +
                            new Win32Exception(error).Message + ").");
                    }

                    var inputVersion = uint.MaxValue;
                    uint driverVersion;
                    uint bytesReturned;
                    if (!DeviceIoControl(handle, IoctlNdisrdGetVersion, ref inputVersion,
                            sizeof(uint), out driverVersion, sizeof(uint), out bytesReturned,
                            IntPtr.Zero))
                    {
                        var error = Marshal.GetLastWin32Error();
                        return WindowsPacketFilterStatus.ActiveDeviceUnavailable(error,
                            "The active NDISRD device opened, but IOCTL_NDISRD_GET_VERSION failed " +
                            "(Win32 error " + error + ": " + new Win32Exception(error).Message +
                            ").");
                    }

                    if (bytesReturned != sizeof(uint))
                    {
                        return WindowsPacketFilterStatus.ActiveDeviceUnavailable(null,
                            "The active NDISRD device returned an invalid version response (" +
                            bytesReturned + " bytes; expected " + sizeof(uint) + ").");
                    }

                    return EvaluateDriverVersion(driverVersion);
                }
            }
            catch (Exception ex) when (ex is DllNotFoundException || ex is EntryPointNotFoundException ||
                                       ex is TypeInitializationException)
            {
                return WindowsPacketFilterStatus.Unavailable(null,
                    "The NDISRD availability check failed: " + ex.Message);
            }
        }

        internal static WindowsPacketFilterStatus EvaluateDriverVersion(uint driverVersion)
        {
            var apiMajor = GetApiMajor(driverVersion);
            var apiMinor = GetApiMinor(driverVersion);
            if (apiMajor == RequiredApiMajor && apiMinor >= MinimumApiMinor)
                return WindowsPacketFilterStatus.CompatibleDevice();

            var reported = FormatApiVersion(driverVersion, apiMajor, apiMinor);
            if (apiMajor != RequiredApiMajor)
            {
                return WindowsPacketFilterStatus.ActiveDeviceUnavailable(null,
                    "The active NDISRD device reports an incompatible " + reported + ". " +
                    "ProxiFyre supports API major " + RequiredApiMajor +
                    " only; install a compatible WinpkFilter release (minimum API encoding " +
                    FormatApiEncoding(MinimumCompatibleApiVersion) + ").");
            }

            return WindowsPacketFilterStatus.ActiveDeviceUnavailable(null,
                "The active NDISRD device reports " + reported + ". ProxiFyre requires API minor " +
                FormatApiMinor(MinimumApiMinor) + " or later with API major " +
                RequiredApiMajor + " (minimum API encoding " +
                FormatApiEncoding(MinimumCompatibleApiVersion) + ").");
        }

        private static ushort GetApiMajor(uint driverVersion)
        {
            return (ushort)((driverVersion >> 12) & 0x000f);
        }

        private static ushort GetApiMinor(uint driverVersion)
        {
            return (ushort)(driverVersion >> 16);
        }

        private static string FormatApiVersion(uint driverVersion, ushort apiMajor,
            ushort apiMinor)
        {
            return "API encoding " + FormatApiEncoding(driverVersion) + " (API major " +
                   apiMajor + ", API minor " + FormatApiMinor(apiMinor) + ")";
        }

        private static string FormatApiEncoding(uint driverVersion)
        {
            return "0x" + driverVersion.ToString("X8");
        }

        private static string FormatApiMinor(ushort apiMinor)
        {
            return "0x" + apiMinor.ToString("X4");
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

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(SafeFileHandle deviceHandle,
            uint ioControlCode, ref uint inputBuffer, uint inputBufferSize,
            out uint outputBuffer, uint outputBufferSize, out uint bytesReturned,
            IntPtr overlapped);
    }
}
