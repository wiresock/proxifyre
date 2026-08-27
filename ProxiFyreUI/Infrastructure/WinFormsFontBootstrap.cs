using System;
using System.ComponentModel;
using System.Drawing;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace ProxiFyreUI.Infrastructure
{
    /// <summary>
    /// Initializes the .NET Framework WinForms default font before the first control is created.
    /// Some legacy Windows installations cannot resolve GDI+'s generic sans-serif fallback;
    /// controls such as DataGridView query that fallback from their base constructor, before an
    /// explicitly assigned form font can be inherited.
    /// </summary>
    internal static class WinFormsFontBootstrap
    {
        private const uint GetIconTitleLogFont = 0x001F;
        private const byte TrueTypeOnlyOutputPrecision = 7;
        private const int LogFontFaceSize = 32;
        private static readonly IntPtr InvalidGdiObject = new IntPtr(-1);
        private static readonly object SyncRoot = new object();
        private static readonly string[] PreferredFontFamilies =
        {
            "Segoe UI",
            "Tahoma",
            "Microsoft Sans Serif"
        };

        // The font is intentionally process-lived. WinForms stores the same instance as its
        // process default and may use its native handle for the lifetime of the application.
        private static Font processDefaultFont;

        internal static void EnsureDefaultFont()
        {
            EnsureDefaultFont(() => Control.DefaultFont);
        }

        internal static void EnsureDefaultFont(Func<Font> defaultFontProvider)
        {
            EnsureDefaultFont(defaultFontProvider, family =>
                CreateNamedFont(family, 9.0F, FontStyle.Regular));
        }

        internal static Font CreateUiFont(
            string familyName,
            float sizeInPoints,
            FontStyle style = FontStyle.Regular)
        {
            try
            {
                return CreateNamedFont(familyName, sizeInPoints, style);
            }
            catch (ArgumentException)
            {
                return processDefaultFont ?? Control.DefaultFont;
            }
            catch (ExternalException)
            {
                return processDefaultFont ?? Control.DefaultFont;
            }
        }

        internal static void EnsureDefaultFont(
            Func<Font> defaultFontProvider,
            Func<string, Font> namedFontProvider)
        {
            EnsureDefaultFont(defaultFontProvider, namedFontProvider, Font.FromHdc);
        }

        internal static void EnsureDefaultFont(
            Func<Font> defaultFontProvider,
            Func<string, Font> namedFontProvider,
            Func<IntPtr, Font> selectedDeviceContextFontProvider)
        {
            if (defaultFontProvider == null)
                throw new ArgumentNullException(nameof(defaultFontProvider));
            if (namedFontProvider == null)
                throw new ArgumentNullException(nameof(namedFontProvider));
            if (selectedDeviceContextFontProvider == null)
                throw new ArgumentNullException(nameof(selectedDeviceContextFontProvider));

            try
            {
                if (defaultFontProvider() != null)
                    return;
            }
            catch (ArgumentException)
            {
                // The legacy GDI+ generic-family path can fail before Control.defaultFont is set.
            }
            catch (ExternalException)
            {
                // Recover only from the documented GDI+ font-resolution failure family.
            }

            SeedDefaultFont(namedFontProvider, selectedDeviceContextFontProvider);
        }

        private static void SeedDefaultFont(
            Func<string, Font> namedFontProvider,
            Func<IntPtr, Font> selectedDeviceContextFontProvider)
        {
            var defaultFontField = typeof(Control).GetField("defaultFont",
                BindingFlags.NonPublic | BindingFlags.Static);
            var defaultFontHandleField = typeof(Control).GetField("defaultFontHandleWrapper",
                BindingFlags.NonPublic | BindingFlags.Static);
            if (defaultFontField == null || defaultFontField.FieldType != typeof(Font) ||
                defaultFontField.IsInitOnly || defaultFontHandleField == null)
            {
                throw new InvalidOperationException(
                    "The .NET Framework WinForms default-font state is unavailable.");
            }

            lock (SyncRoot)
            {
                if (defaultFontField.GetValue(null) != null)
                    return;
                if (defaultFontHandleField.GetValue(null) != null)
                {
                    throw new InvalidOperationException(
                        "The WinForms default-font handle was initialized before recovery.");
                }

                var font = CreateDefaultFont(
                    namedFontProvider, selectedDeviceContextFontProvider);
                try
                {
                    defaultFontField.SetValue(null, font);
                    processDefaultFont = font;
                }
                catch
                {
                    font.Dispose();
                    throw;
                }
            }
        }

        private static Font CreateDefaultFont(
            Func<string, Font> namedFontProvider,
            Func<IntPtr, Font> selectedDeviceContextFontProvider)
        {
            Exception lastFailure = null;
            foreach (var family in PreferredFontFamilies)
            {
                try
                {
                    return namedFontProvider(family);
                }
                catch (ArgumentException exception)
                {
                    lastFailure = exception;
                }
                catch (ExternalException exception)
                {
                    lastFailure = exception;
                }
            }

            try
            {
                return CreateSystemTrueTypeFont(selectedDeviceContextFontProvider);
            }
            catch (ArgumentException exception)
            {
                lastFailure = exception;
            }
            catch (ExternalException exception)
            {
                lastFailure = exception;
            }

            throw new InvalidOperationException(
                "No installed Windows UI font could be initialized.", lastFailure);
        }

        private static Font CreateNamedFont(
            string familyName,
            float sizeInPoints,
            FontStyle style)
        {
            // Font(string, ...) asks GDI+ for GenericSansSerif when lookup fails. Constructing
            // the family explicitly makes an unavailable face fail directly, so callers can
            // fall back without touching the broken generic-family path.
            using (var family = new FontFamily(familyName))
            {
                return new Font(family, sizeInPoints, style, GraphicsUnit.Point);
            }
        }

        private static Font CreateSystemTrueTypeFont(
            Func<IntPtr, Font> selectedDeviceContextFontProvider)
        {
            var logicalFont = new LogFont();
            var logicalFontSize = Marshal.SizeOf(typeof(LogFont));
            if (!SystemParametersInfo(
                GetIconTitleLogFont, (uint)logicalFontSize, ref logicalFont, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "Windows did not provide its current UI font settings.");
            }

            // Font.FromHdc accepts only TrueType fonts. Preserve the system-selected face and
            // metrics, but require GDI's font mapper to substitute another TrueType face if
            // that particular legacy font is raster-only.
            logicalFont.OutputPrecision = TrueTypeOnlyOutputPrecision;
            var nativeFont = CreateFontIndirect(ref logicalFont);
            if (nativeFont == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "Windows could not realize a TrueType UI font.");
            }

            var deviceContext = IntPtr.Zero;
            var previousObject = IntPtr.Zero;
            try
            {
                deviceContext = CreateCompatibleDC(IntPtr.Zero);
                if (deviceContext == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "Windows could not create a font device context.");
                }

                previousObject = SelectObject(deviceContext, nativeFont);
                if (previousObject == IntPtr.Zero || previousObject == InvalidGdiObject)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "Windows could not select the recovered UI font.");
                }

                // Unlike Font.FromHfont, this calls GdipCreateFontFromDC directly and avoids
                // the failing GDI+ FontFamily/LOGFONT reconstruction paths.
                return selectedDeviceContextFontProvider(deviceContext);
            }
            finally
            {
                if (deviceContext != IntPtr.Zero)
                {
                    if (previousObject != IntPtr.Zero && previousObject != InvalidGdiObject)
                        SelectObject(deviceContext, previousObject);
                    DeleteDC(deviceContext);
                }

                DeleteObject(nativeFont);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct LogFont
        {
            internal int Height;
            internal int Width;
            internal int Escapement;
            internal int Orientation;
            internal int Weight;
            internal byte Italic;
            internal byte Underline;
            internal byte StrikeOut;
            internal byte CharacterSet;
            internal byte OutputPrecision;
            internal byte ClipPrecision;
            internal byte Quality;
            internal byte PitchAndFamily;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = LogFontFaceSize)]
            internal string FaceName;
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SystemParametersInfo(
            uint action,
            uint parameter,
            ref LogFont value,
            uint updateFlags);

        [DllImport("gdi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFontIndirect(ref LogFont logicalFont);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern IntPtr CreateCompatibleDC(IntPtr deviceContext);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern IntPtr SelectObject(IntPtr deviceContext, IntPtr gdiObject);

        [DllImport("gdi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteObject(IntPtr gdiObject);

        [DllImport("gdi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteDC(IntPtr deviceContext);
    }
}
