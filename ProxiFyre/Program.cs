using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using NLog;
using NLog.Config;
using NLog.Targets;
using Newtonsoft.Json;

namespace ProxiFyre
{
    internal static class Program
    {
        // ===== Native policy (DIP) interop: per-process rule only =============
        // Exported from socksify.dll (C/C++): int dip_add_process(const wchar_t*, const char*);
        [DllImport("socksify.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        private static extern int dip_add_process(string process_name, [MarshalAs(UnmanagedType.LPStr)] string cidr);

        private static Logger Log;

        private static int Main(string[] args)
        {
            ConfigureLogging();
            Log = LogManager.GetCurrentClassLogger();

            try
            {
                AppConfig cfg = LoadConfig();

                object socksifier = StartSocksifierViaReflection(cfg.ProxyHost, cfg.ProxyPort);

                // Add processes to the managed socksifier if such method exists
                if (cfg.Processes != null)
                {
                    foreach (ProcRule p in cfg.Processes)
                    {
                        if (p == null) continue;
                        if (!p.Enabled) continue;
                        if (string.IsNullOrWhiteSpace(p.Name)) continue;

                        // Tell managed layer (best-effort)
                        TryCallOneStringParam(socksifier, new[] { "Add", "Include", "AddProcess", "IncludeProcess", "Whitelist" }, p.Name.Trim());

                        // Add DIP rules for each CIDR (optional)
                        if (p.IpRanges != null)
                        {
                            foreach (string cidr in p.IpRanges)
                            {
                                if (string.IsNullOrWhiteSpace(cidr)) continue;
                                int ok = dip_add_process(p.Name.Trim(), cidr.Trim());
                                if (ok != 1)
                                    Log.Warn("dip_add_process failed: {0} / {1}", p.Name, cidr);
                            }
                        }
                    }
                }

                Log.Info("ProxiFyre running. Press Ctrl+C to exit.");
                ManualResetEvent quit = new ManualResetEvent(false);
                Console.CancelKeyPress += (s, e) => { e.Cancel = true; quit.Set(); };
                quit.WaitOne();

                TryCallNoParam(socksifier, new[] { "Stop", "Shutdown" });
                Log.Info("ProxiFyre stopped.");
                return 0;
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Fatal error in ProxiFyre.");
                return 1;
            }
            finally
            {
                LogManager.Shutdown();
            }
        }

        // ===== Logging: always ProxiFyre.log, roll daily to ProxiFyre_yyyyMMdd.txt
        private static void ConfigureLogging()
        {
            LoggingConfiguration config = new LoggingConfiguration();

            string logDir = AppDomain.CurrentDomain.BaseDirectory;
            FileTarget fileTarget = new FileTarget("file");
            fileTarget.FileName = Path.Combine(logDir, "ProxiFyre.log");
            fileTarget.Layout = "${longdate}|${level:uppercase=true}|${message}${onexception:inner=${newline}${exception:format=tostring}}";
            fileTarget.ConcurrentWrites = true;
            fileTarget.KeepFileOpen = false;

            // Daily rolling
            fileTarget.ArchiveEvery = FileArchivePeriod.Day;
            fileTarget.ArchiveNumbering = ArchiveNumberingMode.Date;
            fileTarget.ArchiveDateFormat = "yyyyMMdd";
            // Rolled files: ProxiFyre_yyyyMMdd.txt
            fileTarget.ArchiveFileName = Path.Combine(logDir, "ProxiFyre_{#}.txt");
            fileTarget.Encoding = Encoding.UTF8;
            fileTarget.MaxArchiveFiles = 30; // keep last 30 days

            config.AddRule(LogLevel.Info, LogLevel.Fatal, fileTarget);

            LogManager.Configuration = config;
        }

        // ===== JSON config loader (file next to the exe)
        private static AppConfig LoadConfig()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string[] candidates = new string[]
            {
                Path.Combine(baseDir, "ProxiFyre.json"),
                Path.Combine(baseDir, "config.json")
            };

            string path = null;
            foreach (string c in candidates)
            {
                if (File.Exists(c)) { path = c; break; }
            }

            if (path == null)
                throw new FileNotFoundException("No config JSON found (ProxiFyre.json or config.json) next to the exe.");

            string json = File.ReadAllText(path);
            AppConfig cfg = JsonConvert.DeserializeObject<AppConfig>(json);
            if (cfg == null) cfg = new AppConfig();

            if (cfg.ProxyPort <= 0) cfg.ProxyPort = 1080;
            if (string.IsNullOrWhiteSpace(cfg.ProxyHost)) cfg.ProxyHost = "127.0.0.1";

            return cfg;
        }

        // ===== Managed Socksifier boot via reflection (no compile-time tie)
        private static object StartSocksifierViaReflection(string host, int port)
        {
            try
            {
                Type type = null;

                // Look in already loaded assemblies
                foreach (Assembly a in AppDomain.CurrentDomain.GetAssemblies())
                {
                    Type found;
                    try { found = a.GetTypes().FirstOrDefault(t => t != null && t.Name == "Socksifier"); }
                    catch { found = null; }
                    if (found != null) { type = found; break; }
                }

                // Try load socksify.dll as managed assembly (if not found)
                if (type == null)
                {
                    string candidate = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "socksify.dll");
                    if (File.Exists(candidate))
                    {
                        try
                        {
                            Assembly asm = Assembly.LoadFrom(candidate);
                            type = asm.GetTypes().FirstOrDefault(t => t != null && t.Name == "Socksifier");
                        }
                        catch { /* ignore */ }
                    }
                }

                if (type == null)
                {
                    Log.Warn("Managed type 'Socksifier' not found; continuing with DIP policy only.");
                    return null;
                }

                // Get instance (static Instance or default ctor)
                object instance = null;
                PropertyInfo instanceProp = type.GetProperty("Instance", BindingFlags.Public | BindingFlags.Static);
                if (instanceProp != null)
                {
                    try { instance = instanceProp.GetValue(null, null); } catch { instance = null; }
                }
                if (instance == null)
                {
                    try { instance = Activator.CreateInstance(type); } catch { instance = null; }
                }

                if (instance == null)
                {
                    Log.Warn("Could not create 'Socksifier' instance; continuing with DIP policy only.");
                    return null;
                }

                // Start(host, port) or Start()
                MethodInfo start = type.GetMethod("Start", new[] { typeof(string), typeof(int) });
                if (start != null)
                {
                    try { start.Invoke(instance, new object[] { host, port }); }
                    catch (Exception ex) { Log.Warn(ex, "Socksifier.Start(host,port) failed; attempting Start()."); start = null; }
                }
                if (start == null)
                {
                    MethodInfo startNoArgs = type.GetMethod("Start", Type.EmptyTypes);
                    if (startNoArgs != null)
                    {
                        try { startNoArgs.Invoke(instance, new object[0]); }
                        catch (Exception ex) { Log.Warn(ex, "Socksifier.Start() failed; proceeding without managed start."); }
                    }
                    else
                    {
                        Log.Warn("'Socksifier.Start' not found; proceeding without managed start.");
                    }
                }

                Log.Info("Socksifier started on {0}:{1}", host, port);
                return instance;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to start Socksifier via reflection.");
                return null;
            }
        }

        private static void TryCallNoParam(object instance, string[] methodNames)
        {
            if (instance == null) return;
            Type t = instance.GetType();
            foreach (string name in methodNames)
            {
                MethodInfo m = t.GetMethod(name, BindingFlags.Public | BindingFlags.Instance, null, Type.EmptyTypes, null);
                if (m != null)
                {
                    try { m.Invoke(instance, new object[0]); return; }
                    catch (Exception ex) { Log.Debug(ex, "Call {0}() failed (ignored).", name); }
                }
            }
        }

        private static void TryCallOneStringParam(object instance, string[] methodNames, string arg)
        {
            if (instance == null) return;
            Type t = instance.GetType();
            foreach (string name in methodNames)
            {
                MethodInfo m = t.GetMethod(name, BindingFlags.Public | BindingFlags.Instance, null, new[] { typeof(string) }, null);
                if (m != null)
                {
                    try { m.Invoke(instance, new object[] { arg }); return; }
                    catch (Exception ex) { Log.Debug(ex, "Call {0}(string) failed (ignored).", name); }
                }
            }
        }
    }

    // ===== Config DTOs (C# 7.3 friendly, no nullable-ref syntax) ==============
    internal class AppConfig
    {
        public string ProxyHost { get; set; }
        public int ProxyPort { get; set; }
        public List<ProcRule> Processes { get; set; }

        public AppConfig()
        {
            ProxyHost = "127.0.0.1";
            ProxyPort = 1080;
            Processes = new List<ProcRule>();
        }
    }

    internal class ProcRule
    {
        // e.g. "chrome.exe"
        public string Name { get; set; }
        public bool Enabled { get; set; }

        // Optional. When present, only matching destinations are redirected for this process.
        public List<string> IpRanges { get; set; }

        public ProcRule()
        {
            Name = "";
            Enabled = true;
            IpRanges = new List<string>();
        }
    }
}
