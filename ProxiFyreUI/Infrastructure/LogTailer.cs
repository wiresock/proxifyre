using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace ProxiFyreUI.Infrastructure
{
    public static class LogFileLocator
    {
        public static string FindLatest(string directoryPath)
        {
            if (string.IsNullOrWhiteSpace(directoryPath) || !Directory.Exists(directoryPath))
                return null;

            return Directory.EnumerateFiles(directoryPath, "*", SearchOption.TopDirectoryOnly)
                .Where(path => path.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
                               path.EndsWith(".log", StringComparison.OrdinalIgnoreCase))
                .Select(path => new FileInfo(path))
                .OrderByDescending(info => info.LastWriteTimeUtc)
                .ThenByDescending(info => info.Name, StringComparer.OrdinalIgnoreCase)
                .Select(info => info.FullName)
                .FirstOrDefault();
        }
    }

    public sealed class LogLinesEventArgs : EventArgs
    {
        public LogLinesEventArgs(IReadOnlyList<string> lines, string filePath,
            string sourceDirectoryPath, int generation, bool reset)
        {
            Lines = lines;
            FilePath = filePath;
            SourceDirectoryPath = sourceDirectoryPath;
            Generation = generation;
            Reset = reset;
        }

        public IReadOnlyList<string> Lines { get; }
        public string FilePath { get; }
        public string SourceDirectoryPath { get; }
        public int Generation { get; }
        public bool Reset { get; }
    }

    public sealed class LogStatusEventArgs : EventArgs
    {
        public LogStatusEventArgs(string status, string sourceDirectoryPath, int generation)
        {
            Status = status;
            SourceDirectoryPath = sourceDirectoryPath;
            Generation = generation;
        }

        public string Status { get; }
        public string SourceDirectoryPath { get; }
        public int Generation { get; }
    }

    public interface ILogTailer : IDisposable
    {
        event EventHandler<LogLinesEventArgs> LinesRead;
        event EventHandler<LogStatusEventArgs> StatusChanged;
        string CurrentFilePath { get; }
        int Generation { get; }
        bool IsRunning { get; }
        void Start(string directoryPath);
        void Stop();
        void Reload(string directoryPath);
    }

    public sealed class LogTailer : ILogTailer
    {
        private const int MaximumInitialBytes = 1024 * 1024;
        private const int MaximumPendingCharacters = 64 * 1024;
        private const string TruncatedLineSuffix = " … [line truncated by ProxiFyreUI]";
        private const int MaximumBytesPerPoll = 256 * 1024;
        private const int PositionSentinelBytes = 64;
        private readonly object _sync = new object();
        private readonly SemaphoreSlim _pollGate = new SemaphoreSlim(1, 1);
        private Timer _timer;
        private string _directoryPath;
        private string _currentFilePath;
        private long _position;
        private byte[] _positionSentinel = new byte[0];
        private string _pendingText = string.Empty;
        private Decoder _decoder;
        private int _generation;
        private bool _forceReload;
        private bool _disposed;

        public event EventHandler<LogLinesEventArgs> LinesRead;
        public event EventHandler<LogStatusEventArgs> StatusChanged;

        public string CurrentFilePath
        {
            get { lock (_sync) return _currentFilePath; }
        }

        public int Generation { get { lock (_sync) return _generation; } }

        public bool IsRunning { get { lock (_sync) return _timer != null; } }

        public void Start(string directoryPath)
        {
            lock (_sync)
            {
                ThrowIfDisposed();
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

        public void Reload(string directoryPath)
        {
            int generation;
            lock (_sync)
            {
                ThrowIfDisposed();
                _directoryPath = directoryPath;
                _forceReload = true;
                _position = 0;
                _pendingText = string.Empty;
                _decoder = null;
                generation = _generation;
            }
            ThreadPool.QueueUserWorkItem(Poll, new PollRequest(generation, true));
        }

        private void Poll(object state)
        {
            var request = state as PollRequest;
            var callbackGeneration = request?.Generation ?? (state is int ? (int)state : -1);
            var allowWithoutTimer = request?.AllowWithoutTimer == true;
            string directory = null;
            if (allowWithoutTimer)
                _pollGate.Wait();
            else if (!_pollGate.Wait(0))
                return;

            try
            {
                bool forceReload;
                lock (_sync)
                {
                    if ((!allowWithoutTimer && _timer == null) || callbackGeneration != _generation || _disposed)
                        return;
                    directory = _directoryPath;
                    forceReload = _forceReload;
                    _forceReload = false;
                }

                if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
                {
                    RaiseStatus("Waiting for the log directory to be created…", callbackGeneration,
                        directory, allowWithoutTimer);
                    return;
                }

                var latest = LogFileLocator.FindLatest(directory);
                if (latest == null)
                {
                    RaiseStatus("Waiting for a ProxiFyre log file…", callbackGeneration,
                        directory, allowWithoutTimer);
                    return;
                }

                string previous;
                lock (_sync) previous = _currentFilePath;
                var changedFile = !string.Equals(previous, latest, StringComparison.OrdinalIgnoreCase);
                ReadAvailable(latest, directory, changedFile || forceReload, callbackGeneration,
                    allowWithoutTimer);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException ||
                                       ex is DirectoryNotFoundException)
            {
                RaiseStatus("Log file is temporarily unavailable: " + ex.Message,
                    callbackGeneration, directory, allowWithoutTimer);
            }
            finally
            {
                _pollGate.Release();
            }
        }

        private void ReadAvailable(string filePath, string sourceDirectoryPath, bool reset,
            int generation, bool allowWithoutTimer)
        {
            var lines = new List<string>();
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan))
            {
                lock (_sync)
                {
                    if (_disposed || generation != _generation ||
                        (!allowWithoutTimer && _timer == null))
                        return;

                    if (reset || stream.Length < _position ||
                        !PositionSentinelMatches(stream))
                    {
                        reset = true;
                        _currentFilePath = filePath;
                        _pendingText = string.Empty;
                        _decoder = new UTF8Encoding(false, false).GetDecoder();
                        _position = Math.Max(0, stream.Length - MaximumInitialBytes);
                        if (_position > 0)
                            _position = MoveAfterNextNewline(stream, _position);
                        _positionSentinel = ReadPositionSentinel(stream, _position);
                    }

                    if (_decoder == null)
                        _decoder = new UTF8Encoding(false, false).GetDecoder();

                    stream.Position = _position;
                    var buffer = new byte[8192];
                    var availableBytes = Math.Max(0L, stream.Length - stream.Position);
                    var remainingBytes = allowWithoutTimer
                        ? availableBytes
                        : Math.Min((long)MaximumBytesPerPoll, availableBytes);
                    int read;
                    while (remainingBytes > 0 &&
                           (read = stream.Read(buffer, 0,
                               (int)Math.Min(buffer.Length, remainingBytes))) > 0)
                    {
                        var characters = new char[new UTF8Encoding(false, false).GetMaxCharCount(read)];
                        int bytesUsed;
                        int charactersUsed;
                        bool completed;
                        _decoder.Convert(buffer, 0, read, characters, 0, characters.Length, false,
                            out bytesUsed, out charactersUsed, out completed);
                        AppendText(new string(characters, 0, charactersUsed), lines);
                        AppendPositionSentinel(buffer, read);
                        remainingBytes -= read;
                    }
                    _position = stream.Position;
                }
            }

            if (reset && lines.Count > ApplicationConstants.InitialLogLines)
                lines = lines.Skip(lines.Count - ApplicationConstants.InitialLogLines).ToList();

            if (!IsGenerationActive(generation, allowWithoutTimer))
                return;
            if (reset || lines.Count > 0)
                LinesRead?.Invoke(this, new LogLinesEventArgs(lines, filePath,
                    sourceDirectoryPath, generation, reset));
            RaiseStatus((allowWithoutTimer ? "Loaded " : "Following ") + Path.GetFileName(filePath),
                generation, sourceDirectoryPath, allowWithoutTimer);
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

        private bool PositionSentinelMatches(FileStream stream)
        {
            if (_positionSentinel.Length == 0)
                return true;
            if (_position < _positionSentinel.Length || stream.Length < _position)
                return false;

            var originalPosition = stream.Position;
            try
            {
                stream.Position = _position - _positionSentinel.Length;
                var observed = new byte[_positionSentinel.Length];
                var totalRead = 0;
                while (totalRead < observed.Length)
                {
                    var read = stream.Read(observed, totalRead, observed.Length - totalRead);
                    if (read == 0)
                        return false;
                    totalRead += read;
                }

                for (var index = 0; index < observed.Length; index++)
                {
                    if (observed[index] != _positionSentinel[index])
                        return false;
                }
                return true;
            }
            finally
            {
                stream.Position = originalPosition;
            }
        }

        private static byte[] ReadPositionSentinel(FileStream stream, long position)
        {
            var length = (int)Math.Min(position, PositionSentinelBytes);
            if (length <= 0)
                return new byte[0];

            var originalPosition = stream.Position;
            try
            {
                stream.Position = position - length;
                var sentinel = new byte[length];
                var totalRead = 0;
                while (totalRead < length)
                {
                    var read = stream.Read(sentinel, totalRead, length - totalRead);
                    if (read == 0)
                        break;
                    totalRead += read;
                }
                if (totalRead == length)
                    return sentinel;

                var partial = new byte[totalRead];
                Buffer.BlockCopy(sentinel, 0, partial, 0, totalRead);
                return partial;
            }
            finally
            {
                stream.Position = originalPosition;
            }
        }

        private void AppendPositionSentinel(byte[] buffer, int count)
        {
            if (count <= 0)
                return;
            if (count >= PositionSentinelBytes)
            {
                _positionSentinel = new byte[PositionSentinelBytes];
                Buffer.BlockCopy(buffer, count - PositionSentinelBytes,
                    _positionSentinel, 0, PositionSentinelBytes);
                return;
            }

            var retained = Math.Min(_positionSentinel.Length, PositionSentinelBytes - count);
            var updated = new byte[retained + count];
            if (retained > 0)
            {
                Buffer.BlockCopy(_positionSentinel, _positionSentinel.Length - retained,
                    updated, 0, retained);
            }
            Buffer.BlockCopy(buffer, 0, updated, retained, count);
            _positionSentinel = updated;
        }

        private void RaiseStatus(string status, int generation, string sourceDirectoryPath,
            bool allowWithoutTimer)
        {
            if (IsGenerationActive(generation, allowWithoutTimer))
                StatusChanged?.Invoke(this,
                    new LogStatusEventArgs(status, sourceDirectoryPath, generation));
        }

        private bool IsGenerationActive(int generation, bool allowWithoutTimer)
        {
            lock (_sync)
                return !_disposed && generation == _generation && (allowWithoutTimer || _timer != null);
        }

        private sealed class PollRequest
        {
            public PollRequest(int generation, bool allowWithoutTimer)
            {
                Generation = generation;
                AllowWithoutTimer = allowWithoutTimer;
            }

            public int Generation { get; }
            public bool AllowWithoutTimer { get; }
        }

        private void ResetFileState()
        {
            _currentFilePath = null;
            _position = 0;
            _positionSentinel = new byte[0];
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
            lock (_sync)
            {
                if (_disposed)
                    return;
                _disposed = true;
                _generation++;
                _timer?.Dispose();
                _timer = null;
                ResetFileState();
            }
        }
    }
}
