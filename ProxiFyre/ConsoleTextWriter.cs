using System;
using System.IO;
using System.Text;

namespace ProxiFyre
{
    public class TextBoxTextWriter : TextWriter
    {
        readonly Action<string> _sink;
        public TextBoxTextWriter(Action<string> sink) { _sink = sink; }
        public override Encoding Encoding => Encoding.UTF8;

        public override void Write(char value) => _sink(value.ToString());
        public override void Write(char[] buffer, int index, int count) => _sink(new string(buffer, index, count));
        public override void Write(string value) => _sink(value ?? string.Empty);

        public override void WriteLine() => _sink(Environment.NewLine);
        public override void WriteLine(string value) => _sink((value ?? string.Empty) + Environment.NewLine);
        public override void WriteLine(char value) => _sink(value + Environment.NewLine);
        public override void WriteLine(char[] buffer, int index, int count) => _sink(new string(buffer, index, count) + Environment.NewLine);
    }

    public class MultiTextWriter : TextWriter
    {
        readonly TextWriter _a;
        readonly TextWriter _b;

        public MultiTextWriter(TextWriter a, TextWriter b) { _a = a; _b = b; }
        public override Encoding Encoding => _a?.Encoding ?? _b?.Encoding ?? Encoding.UTF8;

        public override void Write(char value)
        {
            try { _a?.Write(value); } catch { }
            try { _b?.Write(value); } catch { }
        }

        public override void Write(char[] buffer, int index, int count)
        {
            try { _a?.Write(buffer, index, count); } catch { }
            try { _b?.Write(buffer, index, count); } catch { }
        }

        public override void Write(string value)
        {
            try { _a?.Write(value); } catch { }
            try { _b?.Write(value); } catch { }
        }

        public override void WriteLine()
        {
            try { _a?.WriteLine(); } catch { }
            try { _b?.WriteLine(); } catch { }
        }

        public override void WriteLine(string value)
        {
            try { _a?.WriteLine(value); } catch { }
            try { _b?.WriteLine(value); } catch { }
        }

        public override void WriteLine(char value)
        {
            try { _a?.WriteLine(value); } catch { }
            try { _b?.WriteLine(value); } catch { }
        }

        public override void WriteLine(char[] buffer, int index, int count)
        {
            try { _a?.WriteLine(buffer, index, count); } catch { }
            try { _b?.WriteLine(buffer, index, count); } catch { }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                try { _a?.Flush(); } catch { }
                try { _b?.Flush(); } catch { }
            }
            base.Dispose(disposing);
        }
    }
}
