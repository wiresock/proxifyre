using System;
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
        private const int DefaultGuiFontStockObject = 17;
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
            if (defaultFontProvider == null)
                throw new ArgumentNullException(nameof(defaultFontProvider));
            if (namedFontProvider == null)
                throw new ArgumentNullException(nameof(namedFontProvider));

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

            SeedDefaultFont(namedFontProvider);
        }

        private static void SeedDefaultFont(Func<string, Font> namedFontProvider)
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

                var font = CreateDefaultFont(namedFontProvider);
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

        private static Font CreateDefaultFont(Func<string, Font> namedFontProvider)
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
                // SystemFonts.DefaultFont converts this stock font through another
                // FontFamily-dependent Point-unit constructor. That conversion can fail on
                // the affected Windows 7 image even when the raw Win32 font is usable.
                // Preserve the raw World-unit font as a last-resort process default.
                var handle = GetStockObject(DefaultGuiFontStockObject);
                if (handle == IntPtr.Zero)
                    throw new ExternalException("Windows did not provide a default GUI font.");
                return Font.FromHfont(handle);
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

        [DllImport("gdi32.dll")]
        private static extern IntPtr GetStockObject(int objectIndex);
    }
}
