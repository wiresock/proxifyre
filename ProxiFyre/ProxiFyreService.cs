using Newtonsoft.Json;
using NLog;
using NLog.Config;
using NLog.Targets;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

// Aliases to avoid LogLevel ambiguity
using SLogLevel = Socksifier.LogLevel;
using ProtoEnum = Socksifier.SupportedProtocolsEnum;

namespace ProxiFyre
{
    public class ProxiFyreService
    {
        private static readonly Logger FileLog = LogManager.GetCurrentClassLogger();

        private Socksifier.Socksifier _socksify;
        private SLogLevel _logLevel = SLogLevel.Info;

        public void Start()
        {
            var exePath = Assembly.GetExecutingAssembly().Location;
            var baseDir = Path.GetDirectoryName(exePath) ?? AppDomain.CurrentDomain.BaseDirectory;
            var configPath = Path.Combine(baseDir, "app-config.json");
            var nlogPath = Path.Combine(baseDir, "NLog.config");

            Console.WriteLine($"Loaded config: {configPath}");

            var json = File.ReadAllText(configPath);
            var cfg = JsonConvert.DeserializeObject<AppConfig>(json) ?? new AppConfig();

            if (File.Exists(nlogPath))
                LogManager.Configuration = new XmlLoggingConfiguration(nlogPath, true);

            EnsureNLogConsoleMirroring();

            _logLevel = ParseSocksifierLogLevel(cfg.logLevel);

            _socksify = Socksifier.Socksifier.GetInstance(_logLevel);
            _socksify.LogEventInterval = 1000;

            _socksify.LogEvent += NativeLogToNLog;

            var anyAssociation = false;

            foreach (var rule in (cfg.proxies ?? new List<ProxyRule>()))
            {
                var endpoint = rule.socks5ProxyEndpoint ?? "";
                var proto = ParseProtocols(rule.supportedProtocols);

                var handle = _socksify.AddSocks5Proxy(endpoint, rule.username, rule.password, proto, false);

                if (handle == IntPtr.Zero || handle.ToInt64() == -1)
                    Console.WriteLine($"WARN: AddSocks5Proxy({endpoint}) returned 0 handle during bootstrap.");

                foreach (var name in (rule.appNames ?? new List<string>()))
                {
                    var ok = _socksify.AssociateProcessNameToProxy(name, handle);
                    if (ok)
                    {
                        anyAssociation = true;
                        Console.WriteLine($"INFO: Associated {name} -> {endpoint} (protocols {ProtoPrint(proto)}).");
                    }
                    else
                    {
                        Console.WriteLine($"WARN: Failed to associate {name} -> {endpoint}.");
                    }
                }

                if (rule.ipRanges != null && rule.appNames != null)
                {
                    foreach (var name in rule.appNames)
                    foreach (var cidr in rule.ipRanges)
                    {
                        var added = _socksify.IncludeProcessDestinationCidr(name, cidr);
                        if (added)
                            Console.WriteLine($"INFO: Added CIDR {cidr} for process {name}.");
                        else
                            Console.WriteLine($"WARN: Failed to add CIDR {cidr} for process {name}.");
                    }
                }
            }

            if (cfg.excludes != null)
            {
                foreach (var ex in cfg.excludes)
                {
                    var ok = _socksify.ExcludeProcessName(ex);
                    if (ok) Console.WriteLine($"INFO: Excluded {ex}.");
                    else Console.WriteLine($"WARN: Failed to exclude {ex}.");
                }
            }

            if (!anyAssociation)
                Console.WriteLine("WARN: No process-to-proxy associations were registered. Nothing to do.");

            var started = _socksify.Start();
            if (!started)
                Console.Error.WriteLine("ERROR: Failed to start native router.");

            FileLog.Info("ProxiFyre Service is running...");
        }

        public void Stop()
        {
            try
            {
                if (_socksify != null)
                    _socksify.Stop();
            }
            finally
            {
                FileLog.Info("ProxiFyre Service has stopped.");
                LogManager.Shutdown();
            }
        }

        private void NativeLogToNLog(object sender, Socksifier.LogEventArgs e)
        {
            if (e?.Log == null) return;

            foreach (var entry in e.Log)
            {
                var msg = (entry?.Description ?? string.Empty).Trim();
                if (msg.Length == 0) continue;

                FileLog.Info(msg);      // keep file logging
                Console.WriteLine(msg); // mirror to UI (stdout → textbox)
            }
        }

        private static void EnsureNLogConsoleMirroring()
        {
            var cfg = LogManager.Configuration ?? new LoggingConfiguration();

            var consoleOut = cfg.FindTargetByName<ConsoleTarget>("uiConsoleOut");
            if (consoleOut == null)
            {
                consoleOut = new ConsoleTarget("uiConsoleOut") { Error = false };
                cfg.AddTarget(consoleOut);
                cfg.AddRule(NLog.LogLevel.Trace, NLog.LogLevel.Info, consoleOut);
            }

            var consoleErr = cfg.FindTargetByName<ConsoleTarget>("uiConsoleErr");
            if (consoleErr == null)
            {
                consoleErr = new ConsoleTarget("uiConsoleErr") { Error = true };
                cfg.AddTarget(consoleErr);
                cfg.AddRule(NLog.LogLevel.Warn, NLog.LogLevel.Fatal, consoleErr);
            }

            LogManager.Configuration = cfg;
            LogManager.ReconfigExistingLoggers();
        }

        private static SLogLevel ParseSocksifierLogLevel(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return SLogLevel.Info;
            try { return (SLogLevel)Enum.Parse(typeof(SLogLevel), s, true); }
            catch { return SLogLevel.Info; }
        }

        private static ProtoEnum ParseProtocols(List<string> list)
        {
            if (list == null || list.Count == 0) return ProtoEnum.BOTH;

            var hasTcp = false;
            var hasUdp = false;

            foreach (var s in list)
            {
                if (s == null) continue;
                var u = s.Trim().ToUpperInvariant();
                if (u == "TCP") hasTcp = true;
                else if (u == "UDP") hasUdp = true;
                else if (u == "BOTH") { hasTcp = true; hasUdp = true; }
            }

            if (hasTcp && hasUdp) return ProtoEnum.BOTH;
            if (hasTcp) return ProtoEnum.TCP;
            if (hasUdp) return ProtoEnum.UDP;
            return ProtoEnum.BOTH;
        }

        private static string ProtoPrint(ProtoEnum p)
        {
            switch (p)
            {
                case ProtoEnum.TCP: return "TCP";
                case ProtoEnum.UDP: return "UDP";
                case ProtoEnum.BOTH: return "TCP"; // keep original behavior
                default: return "TCP";
            }
        }

        private class AppConfig
        {
            public string logLevel { get; set; } = "Info";
            public List<ProxyRule> proxies { get; set; } = new List<ProxyRule>();
            public List<string> excludes { get; set; } = new List<string>();
        }

        private class ProxyRule
        {
            public List<string> appNames { get; set; } = new List<string>();
            public string socks5ProxyEndpoint { get; set; }
            public string username { get; set; }
            public string password { get; set; }
            public List<string> supportedProtocols { get; set; } = new List<string>();
            public List<string> ipRanges { get; set; }
        }
    }
}
