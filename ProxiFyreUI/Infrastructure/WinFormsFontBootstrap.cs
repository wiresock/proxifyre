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
            if (defaultFontProvider == null)
                throw new ArgumentNullException(nameof(defaultFontProvider));

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

            SeedNamedDefaultFont();
        }

        private static void SeedNamedDefaultFont()
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

                var font = CreateDefaultFont();
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

        private static Font CreateDefaultFont()
        {
            Exception lastFailure = null;
            foreach (var family in PreferredFontFamilies)
            {
                try
                {
                    return new Font(family, 9.0F, FontStyle.Regular, GraphicsUnit.Point);
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

            throw new InvalidOperationException(
                "No installed Windows UI font could be initialized.", lastFailure);
        }
    }
}
