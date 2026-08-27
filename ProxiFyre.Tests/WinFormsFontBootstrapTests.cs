using NUnit.Framework;
using ProxiFyreUI.Infrastructure;
using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class WinFormsFontBootstrapTests
    {
        [Test]
        [Apartment(ApartmentState.STA)]
        [NonParallelizable]
        public void RecoversWithWin32GuiFontWhenNamedGdiPlusFamiliesFail()
        {
            var applicationBase = Path.GetDirectoryName(
                typeof(WinFormsFontBootstrapTests).Assembly.Location);
            var setup = new AppDomainSetup
            {
                ApplicationBase = applicationBase,
                ShadowCopyFiles = "false"
            };
            var domain = AppDomain.CreateDomain(
                "ProxiFyre.WinFormsFontBootstrap." + Guid.NewGuid().ToString("N"), null, setup);

            try
            {
                var probe = (WinFormsFontBootstrapProbe)domain.CreateInstanceFromAndUnwrap(
                    typeof(WinFormsFontBootstrapProbe).Assembly.Location,
                    typeof(WinFormsFontBootstrapProbe).FullName);

                Assert.That(probe.Exercise(), Is.True);
            }
            finally
            {
                AppDomain.Unload(domain);
            }
        }
    }

    public sealed class WinFormsFontBootstrapProbe : MarshalByRefObject
    {
        public bool Exercise()
        {
            var defaultFontField = typeof(Control).GetField("defaultFont",
                BindingFlags.NonPublic | BindingFlags.Static);
            var defaultFontHandleField = typeof(Control).GetField("defaultFontHandleWrapper",
                BindingFlags.NonPublic | BindingFlags.Static);
            if (defaultFontField == null || defaultFontHandleField == null ||
                defaultFontField.GetValue(null) != null ||
                defaultFontHandleField.GetValue(null) != null)
                return false;

            var namedFontAttempts = 0;
            WinFormsFontBootstrap.EnsureDefaultFont(
                () => throw new ArgumentException("Simulated default-font failure."),
                family =>
                {
                    namedFontAttempts++;
                    throw new ArgumentException(
                        "Simulated named GDI+ font failure for " + family + ".");
                });

            var seededFont = defaultFontField.GetValue(null) as Font;
            if (seededFont == null || seededFont.SizeInPoints <= 0.0F ||
                namedFontAttempts != 3)
                return false;

            var decorativeFallback = WinFormsFontBootstrap.CreateUiFont(
                "__ProxiFyre Missing UI Font__", 16.0F, FontStyle.Bold);
            if (!ReferenceEquals(decorativeFallback, seededFont))
                return false;

            using (var form = new Form())
            using (var grid = new DataGridView())
            using (var textBox = new TextBox())
            {
                form.Controls.Add(grid);
                form.Controls.Add(textBox);
                var formHandle = form.Handle;
                var gridHandle = grid.Handle;
                var textBoxHandle = textBox.Handle;
                return formHandle != IntPtr.Zero && gridHandle != IntPtr.Zero &&
                    textBoxHandle != IntPtr.Zero &&
                    ReferenceEquals(grid.Font, seededFont) &&
                    !string.IsNullOrWhiteSpace(seededFont.Name) &&
                    defaultFontHandleField.GetValue(null) != null;
            }
        }

        public override object InitializeLifetimeService()
        {
            return null;
        }
    }
}
