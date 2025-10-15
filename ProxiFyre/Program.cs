using System;
using System.IO;
using System.Windows.Forms;

namespace ProxiFyre
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            System.Windows.Forms.Application.EnableVisualStyles();
            System.Windows.Forms.Application.SetCompatibleTextRenderingDefault(false);

            var service = new ProxiFyreService();
            var form = new MainForm(service);

            var originalOut = Console.Out;
            var originalErr = Console.Error;
            var uiWriter = new TextBoxTextWriter(form.AppendLogSafe);

            Console.SetOut(new MultiTextWriter(originalOut, uiWriter));
            Console.SetError(new MultiTextWriter(originalErr, uiWriter));

            System.Windows.Forms.Application.Run(form);

            try { service.Stop(); } catch { }
            try { Console.SetOut(originalOut); } catch { }
            try { Console.SetError(originalErr); } catch { }
        }
    }
}
