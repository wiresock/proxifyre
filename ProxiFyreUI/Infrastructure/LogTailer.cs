using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace ProxiFyreUI.Infrastructure
{
    public sealed class LogLinesEventArgs : EventArgs
    {
        public LogLinesEventArgs(IReadOnlyList<string> lines, string filePath, bool reset)
        {
            Lines = lines;
            FilePath = filePath;
            Reset = reset;
        }

        public IReadOnlyList<string> Lines { get; }
        public string FilePath { get; }
        public bool Reset { get; }
    }

    public interface ILogTailer : IDisposable
    {
        event EventHandler<LogLinesEventArgs> LinesRead;
        event EventHandler<string> StatusChanged;
        string CurrentFilePath { get; }
        bool IsRunning { get; }
        void Start(string directoryPath);
        void Stop();
        void Reload();
    }

    public sealed class LogTailer : ILogTailer
    {
        private const int MaximumInitialBytes = 1024 * 1024;
        private const int MaximumPendingCharacters = 64 * 1024;
        private const string TruncatedLineSuffix = " … [line truncated by ProxiFyreUI]";
        private const int MaximumBytesPerPoll = 256 * 1024;
        private readonly object _sync = new object();
        private Timer _timer;
        private string _directoryPath;
        private string _currentFilePath;
        private long _position;
        private string _pendingText = string.Empty;
        private Decoder _decoder;
        private int _polling;
        private int _generation;
        private bool _forceReload;
        private bool _disposed;

        public event EventHandler<LogLinesEventArgs> LinesRead;
        public event EventHandler<string> StatusChanged;

        public string CurrentFilePath
        {
            get { lock (_sync) return _currentFilePath; }
        }

        public bool IsRunning { get { lock (_sync) return _timer != null; } }

        public void Start(string directoryPath)
        {
            ThrowIfDisposed();
            lock (_sync)
            {
                _generation++;
                _directoryPath = directoryPath;
                ResetFileState();
                _forceReload = true;
                _timer?.Dispose();
                _timer = new Timer(Poll, _generation, TimeSpan.Zero, TimeSpan.FromMilliseconds(750));
            }
        }

        public void Stop()
        {
            lock (_sync)
            {
                _generation++;
                _timer?.Dispose();
                _timer = null;
                ResetFileState();
            }
        }

        public void Reload()
        {
            ThrowIfDisposed();
            int generation;
            lock (_sync)
            {
                _forceReload = true;
                _position = 0;
                _pendingText = string.Empty;
                _decoder = null;
                generation = _generation;
            }
            Poll(generation);
        }

        private void Poll(object state)
        {
            if (Interlocked.Exchange(ref _polling, 1) != 0)
                return;

            try
            {
                string directory;
                bool forceReload;
                var callbackGeneration = state is int ? (int)state : -1;
                lock (_sync)
                {
                    if (_timer == null || callbackGeneration != _generation)
                        return;
                    directory = _directoryPath;
                    forceReload = _forceReload;
                    _forceReload = false;
                }

                if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
                {
                    RaiseStatus("Waiting for the log directory to be created…", callbackGeneration);
                    return;
                }

                var latest = FindLatestLogFile(directory);
                if (latest == null)
                {
                    RaiseStatus("Waiting for a ProxiFyre log file…", callbackGeneration);
                    return;
                }

                string previous;
                lock (_sync) previous = _currentFilePath;
                var changedFile = !string.Equals(previous, latest, StringComparison.OrdinalIgnoreCase);
                ReadAvailable(latest, changedFile || forceReload, callbackGeneration);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException ||
                                       ex is DirectoryNotFoundException)
            {
                RaiseStatus("Log file is temporarily unavailable: " + ex.Message,
                    state is int ? (int)state : -1);
            }
            finally
            {
                Interlocked.Exchange(ref _polling, 0);
            }
        }

        private void ReadAvailable(string filePath, bool reset, int generation)
        {
            var lines = new List<string>();
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan))
            {
                lock (_sync)
                {
                    if (reset || stream.Length < _position)
                    {
                        reset = true;
                        _currentFilePath = filePath;
                        _pendingText = string.Empty;
                        _decoder = new UTF8Encoding(false, false).GetDecoder();
                        _position = Math.Max(0, stream.Length - MaximumInitialBytes);
                        if (_position > 0)
                            _position = MoveAfterNextNewline(stream, _position);
                    }

                    if (_decoder == null)
                        _decoder = new UTF8Encoding(false, false).GetDecoder();

                    stream.Position = _position;
                    var buffer = new byte[8192];
                    var processedBytes = 0;
                    int read;
                    while (processedBytes < MaximumBytesPerPoll &&
                           (read = stream.Read(buffer, 0,
                               Math.Min(buffer.Length, MaximumBytesPerPoll - processedBytes))) > 0)
                    {
                        var characters = new char[new UTF8Encoding(false, false).GetMaxCharCount(read)];
                        int bytesUsed;
                        int charactersUsed;
                        bool completed;
                        _decoder.Convert(buffer, 0, read, characters, 0, characters.Length, false,
                            out bytesUsed, out charactersUsed, out completed);
                        AppendText(new string(characters, 0, charactersUsed), lines);
                        processedBytes += bytesUsed;
                    }
                    _position = stream.Position;
                }
            }

            if (reset && lines.Count > ApplicationConstants.InitialLogLines)
                lines = lines.Skip(lines.Count - ApplicationConstants.InitialLogLines).ToList();

            if (!IsGenerationActive(generation))
                return;
            if (reset || lines.Count > 0)
                LinesRead?.Invoke(this, new LogLinesEventArgs(lines, filePath, reset));
            RaiseStatus("Following " + Path.GetFileName(filePath), generation);
        }

        private void AppendText(string text, List<string> lines)
        {
            var combined = _pendingText + text;
            var start = 0;
            for (var index = 0; index < combined.Length; index++)
            {
                if (combined[index] != '\n')
                    continue;

                var length = index - start;
                if (length > 0 && combined[index - 1] == '\r')
                    length--;
                lines.Add(combined.Substring(start, length));
                start = index + 1;
            }

            var pending = start < combined.Length ? combined.Substring(start) : string.Empty;
            if (pending.Length > MaximumPendingCharacters)
            {
                lines.Add(pending.Substring(0, MaximumPendingCharacters) + TruncatedLineSuffix);
                _pendingText = string.Empty;
            }
            else
            {
                _pendingText = pending;
            }
        }

        private static long MoveAfterNextNewline(FileStream stream, long position)
        {
            stream.Position = position;
            int value;
            while ((value = stream.ReadByte()) >= 0)
            {
                if (value == '\n')
                    return stream.Position;
            }
            return stream.Position;
        }

        private static string FindLatestLogFile(string directoryPath)
        {
            return Directory.EnumerateFiles(directoryPath, "*", SearchOption.TopDirectoryOnly)
                .Where(path => path.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
                               path.EndsWith(".log", StringComparison.OrdinalIgnoreCase))
                .Select(path => new FileInfo(path))
                .OrderByDescending(info => info.LastWriteTimeUtc)
                .ThenByDescending(info => info.Name, StringComparer.OrdinalIgnoreCase)
                .Select(info => info.FullName)
                .FirstOrDefault();
        }

        private void RaiseStatus(string status, int generation)
        {
            if (IsGenerationActive(generation))
                StatusChanged?.Invoke(this, status);
        }

        private bool IsGenerationActive(int generation)
        {
            lock (_sync)
                return !_disposed && _timer != null && generation == _generation;
        }

        private void ResetFileState()
        {
            _currentFilePath = null;
            _position = 0;
            _pendingText = string.Empty;
            _decoder = null;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(LogTailer));
        }

        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            Stop();
        }
    }
}
