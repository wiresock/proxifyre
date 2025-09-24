using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using Newtonsoft.Json;
using NLog;
using NLog.Config;
using NLog.Targets;

// Managed C++/CLI wrapper
using ManagedSocksifier = Socksifier.Socksifier;
using ManagedLogLevel = Socksifier.LogLevel;
using ManagedProtocols = Socksifier.SupportedProtocolsEnum;

namespace ProxiFyre
{
    // ----------------- Config DTOs (schema unchanged) -----------------
    public sealed class AppConfig
    {
        public string logLevel;
        public List<ProxyRule> proxies;
    }

    public sealed class ProxyRule
    {
        public List<string> appNames;
        public string socks5ProxyEndpoint;      // "host:port"
        public List<string> supportedProtocols; // ["TCP"], ["UDP"], ["TCP","UDP"]
        public List<string> ipRanges;           // optional, per-process CIDR includes
    }

    internal static class Program
    {
        private static readonly Logger Log = LogManager.GetCurrentClassLogger();

        private static int Main(string[] args)
        {
            try
            {
                var baseDir = AppContext.BaseDirectory;
                var configPath = Path.Combine(baseDir, "app-config.json");
                if (!File.Exists(configPath))
                {
                    Console.Error.WriteLine("Config file not found: " + configPath);
                    return 2;
                }

                // Load config
                var json = File.ReadAllText(configPath);
                var cfg = JsonConvert.DeserializeObject<AppConfig>(json);
                if (cfg == null || cfg.proxies == null || cfg.proxies.Count == 0)
                {
                    Console.Error.WriteLine("Invalid or empty app-config.json");
                    return 3;
                }

                // NLog to file + console
                ConfigureNLog(cfg.logLevel, baseDir);

                Log.Info("ProxiFyre starting…");
                Log.Info("Loaded config: {0}", configPath);

                // Create socksifier instance (do NOT assume started)
                var s = ManagedSocksifier.GetInstance(ToManagedLogLevel(cfg.logLevel));

                // We will attempt: (A) add all proxies BEFORE Start(); if any Add fails,
                // we will fall back to (B) Start() early and Add with start=true.
                bool started = false;
                int associations = 0;

                foreach (var rule in cfg.proxies)
                {
                    if (rule == null) continue;

                    string endpoint = (rule.socks5ProxyEndpoint ?? string.Empty).Trim();
                    string host;
                    int port;
                    string parseErr;
                    if (!TryParseEndpoint(endpoint, out host, out port, out parseErr))
                    {
                        Log.Error("Invalid socks5ProxyEndpoint '{0}': {1}", rule.socks5ProxyEndpoint, parseErr);
                        continue;
                    }

                    // Optional preflight reachability for clear errors
                    string reachErr;
                    if (!TestTcpReachability(host, port, 1000, out reachErr))
                    {
                        Log.Error("Cannot connect to SOCKS5 {0}:{1} - {2}", host, port, reachErr);
                        Log.Error("Skipping AddSocks5Proxy for endpoint {0}", endpoint);
                        continue;
                    }

                    // Map config -> managed enum with native-compatible numeric values (TCP=1, UDP=2, BOTH=3)
                    var prot = ToManagedProtocolsNativeCompatible(rule.supportedProtocols);

                    // ---------- Plan A: Add before Start ----------
                    IntPtr handle = s.AddSocks5Proxy(
                        endpoint,
                        string.Empty,
                        string.Empty,
                        prot,
                        false // don't start yet; prefer single Start after all adds
                    );

                    // ---------- Plan B (fallback): Start early + Add with start=true ----------
                    if (handle == IntPtr.Zero)
                    {
                        Log.Warn("AddSocks5Proxy({0}) returned null handle before Start(); trying fallback (Start-early + start=true).", endpoint);

                        if (!started)
                        {
                            if (!s.Start())
                            {
                                Log.Error("Socksifier.Start() failed during fallback. Cannot add {0}.", endpoint);
                                // give up on this rule
                                continue;
                            }
                            started = true;
                        }

                        handle = s.AddSocks5Proxy(
                            endpoint,
                            string.Empty,
                            string.Empty,
                            prot,
                            true // start immediately when already started
                        );

                        if (handle == IntPtr.Zero)
                        {
                            Log.Error("AddSocks5Proxy failed for endpoint {0}.", endpoint);
                            Log.Error("If reachability is OK, verify matching x64 builds and try running as Administrator.");
                            continue;
                        }
                    }

                    // Associate processes → proxy handle
                    if (rule.appNames != null)
                    {
                        foreach (var rawName in rule.appNames)
                        {
                            if (string.IsNullOrWhiteSpace(rawName)) continue;
                            var proc = rawName.Trim();

                            bool ok = s.AssociateProcessNameToProxy(proc, handle);
                            if (ok)
                            {
                                Log.Info("Successfully associated {0} to {1} SOCKS5 proxy with protocols {2}!",
                                         proc, endpoint, DescribeProtocols(rule.supportedProtocols));
                                associations++;
                            }
                            else
                            {
                                Log.Warn("AssociateProcessNameToProxy failed for '{0}' -> {1}", proc, endpoint);
                            }

                            // Optional per-process CIDR includes
                            if (rule.ipRanges != null && rule.ipRanges.Count > 0)
                            {
                                foreach (var rawCidr in rule.ipRanges)
                                {
                                    if (string.IsNullOrWhiteSpace(rawCidr)) continue;
                                    var cidr = rawCidr.Trim();
                                    bool added = s.IncludeProcessDestinationCidr(proc, cidr);
                                    if (!added)
                                        Log.Warn("IncludeProcessDestinationCidr failed for '{0}' with '{1}'", proc, cidr);
                                }
                            }
                        }
                    }
                }

                // If we haven’t started yet (Plan A succeeded everywhere), start once now.
                if (!started)
                {
                    if (!s.Start())
                    {
                        Log.Error("Socksifier.Start() returned false.");
                        return 5;
                    }
                    started = true;
                }

                if (associations == 0)
                {
                    Log.Warn("No process-to-proxy associations were registered. Nothing to do.");
                }

                Log.Info("ProxiFyre Service is running... (Press Ctrl+C to exit)");

                using (var quit = new ManualResetEvent(false))
                {
                    Console.CancelKeyPress += (sender, e) =>
                    {
                        e.Cancel = true;
                        quit.Set();
                    };
                    quit.WaitOne();
                }

                if (started)
                {
                    s.Stop();
                }

                Log.Info("ProxiFyre stopped.");
                LogManager.Shutdown();
                return 0;
            }
            catch (Exception ex)
            {
                try
                {
                    Log.Fatal(ex, "Fatal error during startup.");
                    LogManager.Shutdown();
                }
                catch
                {
                    Console.Error.WriteLine(ex.ToString());
                }
                return 1;
            }
        }

        // ----------------- Helpers -----------------

        private static bool TryParseEndpoint(string endpoint, out string host, out int port, out string error)
        {
            host = string.Empty;
            port = 0;
            error = null;

            if (string.IsNullOrWhiteSpace(endpoint))
            {
                error = "Empty endpoint";
                return false;
            }

            int idx = endpoint.LastIndexOf(':');
            if (idx <= 0 || idx == endpoint.Length - 1)
            {
                error = "Expected format 'host:port'";
                return false;
            }

            host = endpoint.Substring(0, idx).Trim();
            var portStr = endpoint.Substring(idx + 1).Trim();

            int p;
            if (!int.TryParse(portStr, out p) || p < 1 || p > 65535)
            {
                error = "Port must be an integer 1..65535";
                return false;
            }

            if (host.Length == 0)
            {
                error = "Host cannot be empty";
                return false;
            }

            port = p;
            return true;
        }

        private static bool TestTcpReachability(string host, int port, int timeoutMs, out string error)
        {
            error = null;
            try
            {
                using (var client = new TcpClient())
                {
                    var ar = client.BeginConnect(host, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(timeoutMs))
                    {
                        error = "Connect timeout";
                        return false;
                    }
                    client.EndConnect(ar);
                    return true;
                }
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static string DescribeProtocols(List<string> list)
        {
            if (list == null || list.Count == 0) return "TCP";
            return string.Join(",", list);
        }

        private static ManagedLogLevel ToManagedLogLevel(string level)
        {
            if (string.IsNullOrWhiteSpace(level)) return ManagedLogLevel.Info;
            switch (level.Trim().ToLowerInvariant())
            {
                case "all":     return ManagedLogLevel.All;
                case "debug":   return ManagedLogLevel.Debug;
                case "info":    return ManagedLogLevel.Info;
                case "warning":
                case "warn":    return ManagedLogLevel.Warning;
                case "error":   return ManagedLogLevel.Error;
                default:        return ManagedLogLevel.Info;
            }
        }

        // IMPORTANT: Many native builds expect TCP=1, UDP=2, BOTH=3.
        // We return the managed enum *with those numeric values* using an explicit cast.
        private static ManagedProtocols ToManagedProtocolsNativeCompatible(List<string> list)
        {
            bool hasTcp = false, hasUdp = false;

            if (list != null)
            {
                foreach (var s in list)
                {
                    if (string.IsNullOrWhiteSpace(s)) continue;
                    var t = s.Trim().ToUpperInvariant();
                    if (t == "TCP") hasTcp = true;
                    else if (t == "UDP") hasUdp = true;
                }
            }

            if (hasTcp && hasUdp) return (ManagedProtocols)3; // BOTH
            if (hasUdp && !hasTcp) return (ManagedProtocols)2; // UDP
            return (ManagedProtocols)1;                         // TCP (default)
        }

        private static void ConfigureNLog(string level, string baseDir)
        {
            var cfg = new LoggingConfiguration();

            var file = new FileTarget("file")
            {
                FileName = Path.Combine(baseDir, "ProxiFyre.log"),
                ArchiveFileName = Path.Combine(baseDir, "ProxiFyre_${shortdate}.log"),
                ArchiveEvery = FileArchivePeriod.Day,
                ArchiveNumbering = ArchiveNumberingMode.Date,
                MaxArchiveFiles = 30,
                ConcurrentWrites = true,
                KeepFileOpen = false,
                Layout = "${longdate}|${level:uppercase=true}|${logger}|${message}${onexception:inner=${newline}${exception:format=tostring}}"
            };

            var console = new ColoredConsoleTarget("console")
            {
                Layout = "${longdate}|${level:uppercase=true}|${logger}|${message}"
            };

            cfg.AddTarget(file);
            cfg.AddTarget(console);

            var min = ToNLogLevel(level);
            cfg.AddRule(min, LogLevel.Fatal, console);
            cfg.AddRule(min, LogLevel.Fatal, file);

            LogManager.Configuration = cfg;
        }

        private static LogLevel ToNLogLevel(string level)
        {
            if (string.IsNullOrWhiteSpace(level)) return LogLevel.Info;
            switch (level.Trim().ToLowerInvariant())
            {
                case "all":     return LogLevel.Trace;
                case "debug":   return LogLevel.Debug;
                case "info":    return LogLevel.Info;
                case "warning":
                case "warn":    return LogLevel.Warn;
                case "error":   return LogLevel.Error;
                default:        return LogLevel.Info;
            }
        }
    }
}
