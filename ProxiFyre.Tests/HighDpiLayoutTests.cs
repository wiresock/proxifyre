using NUnit.Framework;
using ProxiFyreUI.Forms;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

namespace ProxiFyre.Tests
{
    [TestFixture]
    [Apartment(ApartmentState.STA)]
    public sealed class HighDpiLayoutTests
    {
        [Test]
        public void MainWindowHeaderAndActionsRemainUsableAtTwoHundredPercent()
        {
            var form = new MainForm();
            var scaledFonts = new Font[0];
            try
            {
                scaledFonts = ScaleToTwoHundredPercent(form);

                var title = FindControl<Label>(form, "titleLabel");
                var serviceLabel = FindControl<Label>(form, "serviceStateLabel");
                var serviceValue = FindControl<Label>(form, "serviceStateValueLabel");
                var configurationLabel = FindControl<Label>(form, "configurationStateLabel");
                var configurationValue = FindControl<Label>(form,
                    "configurationStateValueLabel");
                var changesLabel = FindControl<Label>(form, "changesStateLabel");
                var changesValue = FindControl<Label>(form, "changesStateValueLabel");
                var headerButtons = new[]
                {
                    FindControl<Button>(form, "startServiceButton"),
                    FindControl<Button>(form, "stopServiceButton"),
                    FindControl<Button>(form, "restartServiceButton"),
                    FindControl<Button>(form, "installServiceButton"),
                    FindControl<Button>(form, "headerUninstallServiceButton")
                };

                Assert.Multiple(() =>
                {
                    Assert.That(title.Right, Is.LessThan(serviceLabel.Left));
                    Assert.That(serviceLabel.Right, Is.LessThanOrEqualTo(serviceValue.Left));
                    Assert.That(serviceValue.Right, Is.LessThan(configurationLabel.Left));
                    Assert.That(configurationLabel.Right,
                        Is.LessThanOrEqualTo(configurationValue.Left));
                    Assert.That(configurationValue.Right, Is.LessThan(changesLabel.Left));
                    Assert.That(changesLabel.Right, Is.LessThanOrEqualTo(changesValue.Left));
                    Assert.That(new[]
                    {
                        title.Bottom, serviceLabel.Bottom, serviceValue.Bottom,
                        configurationLabel.Bottom, configurationValue.Bottom,
                        changesLabel.Bottom, changesValue.Bottom
                    }.Max(), Is.LessThan(headerButtons.Min(button => button.Top)));
                });

                AssertControlsAreContained(headerButtons.Cast<Control>());
                AssertControlsAreContained(new Control[]
                {
                    FindControl<Button>(form, "reloadButton"),
                    FindControl<Button>(form, "validateButton"),
                    FindControl<Button>(form, "saveButton"),
                    FindControl<Button>(form, "applyRestartButton")
                });

                var grid = FindControl<DataGridView>(form, "routingGrid");
                Assert.That(grid.ColumnHeadersHeightSizeMode,
                    Is.EqualTo(DataGridViewColumnHeadersHeightSizeMode.AutoSize));
            }
            finally
            {
                form.Dispose();
                DisposeFonts(scaledFonts);
            }
        }

        [Test]
        public void DialogActionsRemainInsideTheirWindowsAtTwoHundredPercent()
        {
            var forms = new Form[]
            {
                new InputDialog("Test", "Value:"),
                new ProcessPickerForm(),
                new ProxyRuleEditorForm(null, 0, 1)
            };
            foreach (var form in forms)
            {
                var scaledFonts = new Font[0];
                try
                {
                    scaledFonts = ScaleToTwoHundredPercent(form);
                    AssertControlsAreContained(form.Controls.Cast<Control>().Where(control =>
                        control is Button));
                }
                finally
                {
                    form.Dispose();
                    DisposeFonts(scaledFonts);
                }
            }
        }

        private static Font[] ScaleToTwoHundredPercent(Form form)
        {
            Assert.That(form.AutoScaleMode, Is.EqualTo(AutoScaleMode.Dpi));
            var originalClientSize = form.ClientSize;
            var originalFontHeight = form.Font.Height;
            var fontSnapshots = GetControlTree(form)
                .Select(control => new KeyValuePair<Control, Font>(control, control.Font))
                .ToArray();

            // CI normally runs at 96 DPI. At 192 DPI, point fonts retain their point size but
            // occupy roughly twice as many device pixels, so double both geometry and the
            // 96-DPI font metrics to exercise clipping without changing the runner display.
            form.Scale(new SizeF(2F, 2F));
            var scaledFonts = new List<Font>(fontSnapshots.Length);
            foreach (var snapshot in fontSnapshots.Reverse())
            {
                var originalFont = snapshot.Value;
                var scaledFont = new Font(originalFont.FontFamily,
                    originalFont.SizeInPoints * 2F, originalFont.Style, GraphicsUnit.Point,
                    originalFont.GdiCharSet, originalFont.GdiVerticalFont);
                snapshot.Key.Font = scaledFont;
                scaledFonts.Add(scaledFont);
            }
            form.PerformLayout();

            Assert.Multiple(() =>
            {
                Assert.That(form.ClientSize.Width,
                    Is.GreaterThanOrEqualTo(originalClientSize.Width * 2 - 2));
                Assert.That(form.ClientSize.Height,
                    Is.GreaterThanOrEqualTo(originalClientSize.Height * 2 - 2));
                Assert.That(form.Font.Height,
                    Is.GreaterThanOrEqualTo(originalFontHeight * 2 - 1));
            });
            return scaledFonts.ToArray();
        }

        private static IEnumerable<Control> GetControlTree(Control root)
        {
            yield return root;
            foreach (Control child in root.Controls)
            {
                foreach (var descendant in GetControlTree(child))
                    yield return descendant;
            }
        }

        private static void DisposeFonts(IEnumerable<Font> fonts)
        {
            foreach (var font in fonts)
                font.Dispose();
        }

        private static T FindControl<T>(Control root, string name) where T : Control
        {
            var field = root.GetType().GetField(name,
                BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.That(field, Is.Not.Null, "Expected a field named '{0}'.", name);
            var control = field.GetValue(root) as T;
            Assert.That(control, Is.Not.Null, "Expected '{0}' to be a {1}.", name,
                typeof(T).Name);
            return control;
        }

        private static void AssertControlsAreContained(System.Collections.Generic.IEnumerable<Control> controls)
        {
            foreach (var control in controls)
            {
                Assert.That(control.Parent, Is.Not.Null);
                Assert.That(control.Parent.ClientRectangle.Contains(control.Bounds), Is.True,
                    "Control '{0}' is clipped by '{1}' at 200% scaling.",
                    control.Name, control.Parent.Name);
            }
        }
    }
}
