using System;

namespace ProxiFyreUI.Infrastructure
{
    internal static class ApplicationConstants
    {
        public const int MaximumLogLines = 5000;
        public const int InitialLogLines = 1000;
        public static readonly TimeSpan ServiceOperationTimeout = TimeSpan.FromSeconds(30);
    }
}
