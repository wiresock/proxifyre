using Newtonsoft.Json;
using NLog;
using NLog.Config;
using Socksifier;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using Topshelf;
using LogLevel = Socksifier.LogLevel;

namespace ProxiFyre
{
    /// <summary>
    /// Main class for the SOCKS proxy application.
    /// Handles service lifecycle, configuration loading, and proxy association.
    /// </summary>
    public class ProxiFyreService
    {
        /// <summary>
        /// NLog logger instance for logging service events.
        /// </summary>
        private static readonly Logger LoggerInstance = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// The current log level for the service.
        /// </summary>
        private static LogLevel _logLevel;

        /// <summary>
        /// The Socksifier instance used to manage SOCKS5 proxies.
        /// </summary>
        private Socksifier.Socksifier _socksify;

        /// <summary>
        /// Starts the ProxiFyre service, loads configuration, and initializes proxies.
        /// </summary>
        public void Start()
        {
            // Get the current executable path
            var executablePath = Assembly.GetExecutingAssembly().Location;
            var directoryPath = Path.GetDirectoryName(executablePath);

            // Form the path to app-config.json
            var configFilePath = Path.Combine(directoryPath ?? string.Empty, "app-config.json");

            // Form the path to NLog.config
            var logConfigFilePath = Path.Combine(directoryPath ?? string.Empty, "NLog.config");

            // Configure logging first so that any configuration problems below are recorded.
            if (File.Exists(logConfigFilePath))
                LogManager.Configuration = new XmlLoggingConfiguration(logConfigFilePath);

            // Load and validate the configuration from JSON
            var serviceSettings = LoadConfiguration(configFilePath);

            // Handle the global log level from the configuration
            _logLevel = Enum.TryParse<LogLevel>(serviceSettings.LogLevel, true, out var globalLogLevel)
                ? globalLogLevel
                : LogLevel.Info;

            // Get an instance of the Socksifier
            _socksify = Socksifier.Socksifier.GetInstance(_logLevel);

            // Attach the LogPrinter method to the LogEvent event
            _socksify.LogEvent += LogPrinter;

            // Set the limit for logging and the interval between logs
            _socksify.LogLimit = 100;
            _socksify.LogEventInterval = 1000;

            // Configure LAN bypass if enabled
            if (serviceSettings.BypassLan)
            {
                _socksify.SetBypassLan();
                if (_logLevel >= LogLevel.Info)
                    LoggerInstance.Info("LAN bypass enabled - local network traffic will not be proxied.");
            }

            foreach (var appSettings in serviceSettings.Proxies)
            {
                // Add the defined SOCKS5 proxies
                var proxy = _socksify.AddSocks5Proxy(appSettings.Socks5ProxyEndpoint, appSettings.Username,
                    appSettings.Password, appSettings.SupportedProtocolsParse,
                    appSettings.SupportedAddressFamiliesParse,
                    appSettings.Socks5TransportParse,
                    appSettings.EffectiveTlsServerName,
                    NormalizeFingerprint(appSettings.TlsPinnedSha256),
                    appSettings.TlsAllowInvalidCertificate,
                    true);

                if (proxy.ToInt64() == -1)
                {
                    LoggerInstance.Warn(
                        $"Failed to create SOCKS5 proxy for endpoint {appSettings.Socks5ProxyEndpoint}; skipping its application associations.");
                    continue;
                }

                var protocols = appSettings.SupportedProtocols != null && appSettings.SupportedProtocols.Count > 0
                    ? string.Join(", ", appSettings.SupportedProtocols)
                    : "TCP, UDP";
                var addressFamilies = appSettings.SupportedAddressFamilies != null && appSettings.SupportedAddressFamilies.Count > 0
                    ? string.Join(", ", appSettings.SupportedAddressFamilies)
                    : "IPv4, IPv6";
                var transport = appSettings.Socks5TransportParse == Socks5TransportEnum.TLS
                    ? "SOCKS5Tls"
                    : "SOCKS5";
                foreach (var appName in appSettings.AppNames)
                    // Associate the defined application names to the proxies
                    if (_socksify.AssociateProcessNameToProxy(appName, proxy) && _logLevel >= LogLevel.Info)
                        LoggerInstance.Info(
                            $"Successfully associated {appName} to {appSettings.Socks5ProxyEndpoint} {transport} proxy with protocols {protocols} and address families {addressFamilies}!");
            }

            foreach (var excludedEntry in serviceSettings.ExcludedList)
            {
                // Add the relevant entries dynamically to the excluded list
                if (_socksify.ExcludeProcessName(excludedEntry)) {
                    LoggerInstance.Info($"Successfully excluded {excludedEntry} from being proxied.");
                } else {
                    LoggerInstance.Warn($"Failed to exclude {excludedEntry} from being proxied.");
                }
            }

            // Start() propagates failure from the whole native chain (e.g. the Windows Packet
            // Filter driver is not installed or failed to load). Do NOT ignore it: swallowing
            // the failure leaves the Windows service in the RUNNING state while proxying nothing,
            // silently sending configured applications' traffic direct/un-proxied. Throw so
            // Topshelf fails the start and the SCM reports the failure.
            if (!_socksify.Start())
            {
                const string message =
                    "Failed to start the ProxiFyre proxy engine. Ensure the Windows Packet Filter " +
                    "(NDIS lightweight filter) driver is installed and running, then restart the service.";
                LoggerInstance.Error(message);
                throw new InvalidOperationException(message);
            }

            // Inform user that the application is running
            if (_logLevel >= LogLevel.Info)
                LoggerInstance.Info("ProxiFyre Service is running...");
        }

        /// <summary>
        /// Loads, parses and validates the ProxiFyre configuration file.
        /// </summary>
        /// <param name="configFilePath">Full path to app-config.json.</param>
        /// <returns>The validated <see cref="ProxiFyreSettings"/>.</returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the file is missing, cannot be parsed, or fails validation.
        /// </exception>
        private static ProxiFyreSettings LoadConfiguration(string configFilePath)
        {
            if (!File.Exists(configFilePath))
            {
                var message = $"Configuration file not found: '{configFilePath}'. " +
                              "Create an app-config.json next to ProxiFyre.exe before starting the service.";
                LoggerInstance.Error(message);
                throw new InvalidOperationException(message);
            }

            ProxiFyreSettings settings;
            try
            {
                settings = JsonConvert.DeserializeObject<ProxiFyreSettings>(File.ReadAllText(configFilePath));
            }
            catch (Exception ex)
            {
                var message = $"Failed to read or parse configuration file '{configFilePath}': {ex.Message}";
                LoggerInstance.Error(ex, message);
                throw new InvalidOperationException(message, ex);
            }

            if (settings == null)
            {
                var message = $"Configuration file '{configFilePath}' is empty or contains no settings.";
                LoggerInstance.Error(message);
                throw new InvalidOperationException(message);
            }

            if (settings.Proxies == null || settings.Proxies.Count == 0)
            {
                var message = $"Configuration file '{configFilePath}' does not define any proxies. " +
                              "Add at least one entry under \"proxies\".";
                LoggerInstance.Error(message);
                throw new InvalidOperationException(message);
            }

            foreach (var proxy in settings.Proxies)
            {
                if (proxy == null)
                {
                    var message = $"Configuration file '{configFilePath}' contains a null entry under \"proxies\". " +
                                  "Remove the empty entry or replace it with a valid proxy definition.";
                    LoggerInstance.Error(message);
                    throw new InvalidOperationException(message);
                }

                if (string.IsNullOrWhiteSpace(proxy.Socks5ProxyEndpoint))
                {
                    var message = "Each proxy entry must specify a non-empty \"socks5ProxyEndpoint\".";
                    LoggerInstance.Error(message);
                    throw new InvalidOperationException(message);
                }

                var hasUsername = !string.IsNullOrEmpty(proxy.Username);
                var hasPassword = !string.IsNullOrEmpty(proxy.Password);
                if (hasUsername != hasPassword)
                {
                    var message = $"Proxy '{proxy.Socks5ProxyEndpoint}' must specify both \"username\" and " +
                                  "\"password\", or leave both empty.";
                    LoggerInstance.Error(message);
                    throw new InvalidOperationException(message);
                }

                // Drop null and whitespace-only application names (a null String^ throws in
                // marshal_as<std::wstring>, and "   " is a typo that matches nothing), but PRESERVE
                // an explicit empty string "": it is the catch-all that matches EVERY process (see
                // match_app_name in the native router), so it must reach the unmanaged layer. A
                // plain IsNullOrWhiteSpace would strip "" too and silently disable that catch-all.
                if (proxy.AppNames == null)
                    proxy.AppNames = new List<string>();
                else
                    // Remove null and whitespace-only entries but keep "": IsNullOrWhiteSpace is
                    // already true for null/""/whitespace, so `s != string.Empty && IsNullOrWhiteSpace(s)`
                    // drops null and "   " while preserving the "" catch-all.
                    proxy.AppNames.RemoveAll(s => s != string.Empty && string.IsNullOrWhiteSpace(s));

                if (proxy.AppNames.Count == 0)
                    LoggerInstance.Warn(
                        $"Proxy '{proxy.Socks5ProxyEndpoint}' has no application names; it will not match any process.");
                else if (proxy.AppNames.Contains(string.Empty))
                {
                    LoggerInstance.Info(
                        $"Proxy '{proxy.Socks5ProxyEndpoint}' has an empty application name; it will match ALL processes (catch-all) except excluded ones.");

                    // Proxies are matched in configuration order and the first match wins, so a
                    // catch-all shadows every proxy listed after it. Warn if it is not last.
                    if (!ReferenceEquals(proxy, settings.Proxies[settings.Proxies.Count - 1]))
                        LoggerInstance.Warn(
                            $"Proxy '{proxy.Socks5ProxyEndpoint}' is a catch-all but is not the last configured proxy; " +
                            "proxies listed after it will be shadowed and never matched. Move it to the end of \"proxies\".");
                }

                // Warn on unrecognized protocol tokens: SupportedProtocolsParse only counts
                // "TCP"/"UDP" (case-insensitively) and ignores anything else, defaulting to
                // BOTH only when neither is present -- so a typo alongside a valid token is
                // silently dropped, and a typo on its own silently proxies both protocols.
                if (proxy.SupportedProtocols != null)
                {
                    var unknownProtocols = proxy.SupportedProtocols
                        .Where(p => !string.Equals(p, "TCP", StringComparison.OrdinalIgnoreCase) &&
                                    !string.Equals(p, "UDP", StringComparison.OrdinalIgnoreCase))
                        .ToList();
                    if (unknownProtocols.Count > 0)
                    {
                        var values = string.Join(", ", unknownProtocols.Select(p => p ?? "<null>"));
                        LoggerInstance.Warn(
                            $"Proxy '{proxy.Socks5ProxyEndpoint}' lists unrecognized protocol(s): " +
                            $"{values}. Only \"TCP\" and \"UDP\" are recognized; " +
                            "unrecognized tokens are ignored (a proxy with no recognized protocol defaults to both).");
                    }
                }

                if (proxy.SupportedAddressFamilies != null)
                {
                    if (proxy.SupportedAddressFamilies.Count == 0)
                    {
                        var message = $"Proxy '{proxy.Socks5ProxyEndpoint}' has an empty " +
                                      "\"supportedAddressFamilies\" array. Omit the setting to enable both " +
                                      "families, or specify \"IPv4\", \"IPv6\", or both.";
                        LoggerInstance.Error(message);
                        throw new InvalidOperationException(message);
                    }

                    var unknownAddressFamilies = proxy.SupportedAddressFamilies
                        .Where(f => !string.Equals(f, "IPv4", StringComparison.OrdinalIgnoreCase) &&
                                    !string.Equals(f, "IPv6", StringComparison.OrdinalIgnoreCase))
                        .ToList();
                    if (unknownAddressFamilies.Count > 0)
                    {
                        var values = string.Join(", ", unknownAddressFamilies.Select(f => f ?? "<null>"));
                        var message = $"Proxy '{proxy.Socks5ProxyEndpoint}' lists unrecognized address " +
                                      $"family/families: {values}. Only \"IPv4\" and \"IPv6\" are valid.";
                        LoggerInstance.Error(message);
                        throw new InvalidOperationException(message);
                    }
                }

                var transport = proxy.Socks5TransportParse;
                if (transport == Socks5TransportEnum.TLS)
                {
                    if (!string.IsNullOrWhiteSpace(proxy.TlsPinnedSha256) && !IsSha256Fingerprint(proxy.TlsPinnedSha256))
                    {
                        var message = $"Proxy '{proxy.Socks5ProxyEndpoint}' has an invalid " +
                                      "\"tlsPinnedSha256\" value. Use a 64-character hex SHA-256 certificate fingerprint.";
                        LoggerInstance.Error(message);
                        throw new InvalidOperationException(message);
                    }

                    if (proxy.TlsAllowInvalidCertificate && string.IsNullOrWhiteSpace(proxy.TlsPinnedSha256))
                    {
                        LoggerInstance.Warn(
                            $"Proxy '{proxy.Socks5ProxyEndpoint}' allows invalid TLS certificates without a certificate pin. " +
                            "This disables upstream identity verification.");
                    }
                }
            }

            // Drop null/blank excluded entries for the same reason.
            settings.ExcludedList.RemoveAll(string.IsNullOrWhiteSpace);

            return settings;
        }

        private static bool IsSha256Fingerprint(string value)
        {
            var normalized = NormalizeFingerprint(value);
            return normalized.Length == 64 && normalized.All(Uri.IsHexDigit);
        }

        private static string NormalizeFingerprint(string value)
        {
            return new string((value ?? string.Empty)
                .Where(c => c != ':' && c != '-' && !char.IsWhiteSpace(c))
                .Select(char.ToLowerInvariant)
                .ToArray());
        }

        /// <summary>
        /// Stops the ProxiFyre service and disposes of resources.
        /// </summary>
        public void Stop()
        {
            // Dispose of the Socksifier before exiting
            _socksify?.Dispose();
            if (_logLevel >= LogLevel.Info)
                LoggerInstance.Info("ProxiFyre Service has stopped.");
            LogManager.Shutdown();
        }

        /// <summary>
        /// Handles logging events from the Socksifier and logs them using NLog.
        /// </summary>
        /// <param name="sender">The event sender.</param>
        /// <param name="e">The log event arguments.</param>
        private static void LogPrinter(object sender, LogEventArgs e)
        {
            // Loop through each log entry and log it using NLog
            foreach (var entry in e.Log.Where(entry => entry != null))
            {
                // Format log entry with ISO 8601 timestamp, event, description, and data.
                //var logMessage =
                //    $"{DateTimeOffset.FromUnixTimeMilliseconds(entry.TimeStamp):u} | Event: {entry.Event} | Description: {entry.Description ?? string.Empty} | Data: {entry.Data}";
                LoggerInstance.Info((entry.Description ?? string.Empty).Replace("\n", "").Replace("\r", ""));
            }
        }

        //{
        //    "logLevel": "Warning",
        //    "proxies": [
        //        {
        //            "appNames": ["chrome", "chrome_canary"],
        //            "socks5ProxyEndpoint": "158.101.205.51:1080",
        //            "username": "username1",
        //            "password": "password1",
        //            "supportedProtocols": ["TCP", "UDP"],
        //            "supportedAddressFamilies": ["IPv4", "IPv6"]
        //        },
        //        {
        //            "appNames": ["firefox", "firefox_dev"],
        //            "socks5ProxyEndpoint": "159.101.205.52:1080",
        //            "username": "username2",
        //            "password": "password2",
        //            "supportedProtocols": ["TCP"],
        //            "supportedAddressFamilies": ["IPv4"]
        //        }
        //    ],
        //    "excludes": [
        //        "notepad.exe",
        //        "calc.exe",
        //        "C:\\Windows\\System32\\svchost.exe",
        //        "Windows\\System32\\",
        //        "antivirus"
        //    ]
        //}

        /// <summary>
        /// Represents the root configuration settings for ProxiFyre.
        /// </summary>
        private class ProxiFyreSettings
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="ProxiFyreSettings"/> class.
            /// </summary>
            /// <param name="logLevel">The log level as a string.</param>
            /// <param name="proxies">The list of proxy application settings.</param>
            /// <param name="excludedList">The list of process names or paths to exclude from proxying.</param>
            /// <param name="bypassLan">Whether to bypass LAN traffic.</param>
            public ProxiFyreSettings(string logLevel, List<AppSettings> proxies, List<string> excludedList = null, bool bypassLan = false)
            {
                LogLevel = logLevel;
                Proxies = proxies;
                ExcludedList = excludedList ?? new List<string>();
                BypassLan = bypassLan;
            }

            /// <summary>
            /// Gets the log level for the service.
            /// </summary>
            public string LogLevel { get; }

            /// <summary>
            /// Gets the list of proxy application settings.
            /// </summary>
            public List<AppSettings> Proxies { get; }

            /// <summary>
            /// Gets the list of app names to exclude.
            /// </summary>
            [JsonProperty("excludes", NullValueHandling = NullValueHandling.Ignore)]
            public List<string> ExcludedList { get; }

            /// <summary>
            /// Gets a value indicating whether LAN traffic should bypass the proxy.
            /// </summary>
            [JsonProperty("bypassLan", NullValueHandling = NullValueHandling.Ignore)]
            public bool BypassLan { get; }
        }

        /// <summary>
        /// Represents the settings for a single proxy and its associated applications.
        /// </summary>
        internal class AppSettings
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="AppSettings"/> class.
            /// </summary>
            /// <param name="appNames">List of application names to associate with the proxy.</param>
            /// <param name="socks5ProxyEndpoint">SOCKS5 proxy endpoint address.</param>
            /// <param name="username">Username for proxy authentication.</param>
            /// <param name="password">Password for proxy authentication.</param>
            /// <param name="supportedProtocols">List of supported protocols (e.g., TCP, UDP).</param>
            /// <param name="supportedAddressFamilies">List of supported destination address families (e.g., IPv4, IPv6).</param>
            public AppSettings(List<string> appNames, string socks5ProxyEndpoint, string username, string password,
                List<string> supportedProtocols, List<string> supportedAddressFamilies = null,
                string socks5Transport = null, string tlsServerName = null, string tlsPinnedSha256 = null,
                bool tlsAllowInvalidCertificate = false)
            {
                AppNames = appNames;
                Socks5ProxyEndpoint = socks5ProxyEndpoint;
                Username = username;
                Password = password;
                SupportedProtocols = supportedProtocols;
                SupportedAddressFamilies = supportedAddressFamilies;
                Socks5Transport = socks5Transport;
                TlsServerName = tlsServerName;
                TlsPinnedSha256 = tlsPinnedSha256;
                TlsAllowInvalidCertificate = tlsAllowInvalidCertificate;
            }

            /// <summary>
            /// Gets or sets the list of application names to associate with the proxy.
            /// </summary>
            public List<string> AppNames { get; set; }

            /// <summary>
            /// Gets the SOCKS5 proxy endpoint address.
            /// </summary>
            public string Socks5ProxyEndpoint { get; }

            /// <summary>
            /// Gets the username for proxy authentication.
            /// </summary>
            public string Username { get; }

            /// <summary>
            /// Gets the password for proxy authentication.
            /// </summary>
            public string Password { get; }

            /// <summary>
            /// Gets the list of supported protocols (e.g., TCP, UDP).
            /// </summary>
            public List<string> SupportedProtocols { get; }

            /// <summary>
            /// Gets the list of supported destination address families (e.g., IPv4, IPv6).
            /// </summary>
            public List<string> SupportedAddressFamilies { get; }

            /// <summary>
            /// Gets the upstream transport used to reach the SOCKS5 proxy.
            /// </summary>
            public string Socks5Transport { get; }

            /// <summary>
            /// Gets the TLS SNI and certificate validation server name.
            /// </summary>
            public string TlsServerName { get; }

            /// <summary>
            /// Gets the optional SHA-256 certificate fingerprint pin.
            /// </summary>
            public string TlsPinnedSha256 { get; }

            /// <summary>
            /// Gets a value indicating whether invalid TLS certificates are allowed.
            /// </summary>
            public bool TlsAllowInvalidCertificate { get; }

            /// <summary>
            /// Gets the effective TLS server name, defaulting to the endpoint host.
            /// </summary>
            public string EffectiveTlsServerName
            {
                get
                {
                    return string.IsNullOrWhiteSpace(TlsServerName)
                        ? ExtractEndpointHost(Socks5ProxyEndpoint)
                        : TlsServerName.Trim();
                }
            }

            /// <summary>
            /// Gets the supported protocols as an enum value.
            /// </summary>
            public SupportedProtocolsEnum SupportedProtocolsParse
            {
                get
                {
                    var supportsTcp = ContainsProtocol("TCP");
                    var supportsUdp = ContainsProtocol("UDP");
                    if (SupportedProtocols == null || SupportedProtocols.Count == 0 ||
                        (supportsTcp && supportsUdp))
                        return SupportedProtocolsEnum.BOTH;
                    if (supportsTcp)
                        return SupportedProtocolsEnum.TCP;
                    return supportsUdp
                        ? SupportedProtocolsEnum.UDP
                        : SupportedProtocolsEnum.BOTH;
                }
            }

            /// <summary>
            /// Gets the upstream SOCKS5 transport as an enum value.
            /// </summary>
            public Socks5TransportEnum Socks5TransportParse
            {
                get
                {
                    var transport = Socks5Transport?.Trim();
                    if (string.IsNullOrEmpty(transport) ||
                        string.Equals(transport, "TCP", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(transport, "Plain", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(transport, "SOCKS5", StringComparison.OrdinalIgnoreCase))
                        return Socks5TransportEnum.TCP;

                    if (string.Equals(transport, "TLS", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(transport, "SOCKS5TLS", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(transport, "SOCKS5_TLS", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(transport, "SOCKS5-TLS", StringComparison.OrdinalIgnoreCase))
                        return Socks5TransportEnum.TLS;

                    throw new InvalidOperationException(
                        "socks5Transport must be TCP or TLS.");
                }
            }

            /// <summary>
            /// Gets the supported destination address families as an enum value.
            /// </summary>
            public SupportedAddressFamiliesEnum SupportedAddressFamiliesParse
            {
                get
                {
                    if (SupportedAddressFamilies == null)
                        return SupportedAddressFamiliesEnum.BOTH;

                    var supportsIPv4 = ContainsAddressFamily("IPv4");
                    var supportsIPv6 = ContainsAddressFamily("IPv6");
                    if (supportsIPv4 && supportsIPv6)
                        return SupportedAddressFamiliesEnum.BOTH;
                    if (supportsIPv4)
                        return SupportedAddressFamiliesEnum.IPv4;
                    if (supportsIPv6)
                        return SupportedAddressFamiliesEnum.IPv6;

                    throw new InvalidOperationException(
                        "supportedAddressFamilies must contain IPv4, IPv6, or both.");
                }
            }

            private bool ContainsAddressFamily(string value)
            {
                return SupportedAddressFamilies != null &&
                    SupportedAddressFamilies.Any(f => string.Equals(f, value, StringComparison.OrdinalIgnoreCase));
            }

            private bool ContainsProtocol(string value)
            {
                return SupportedProtocols != null &&
                    SupportedProtocols.Any(p => string.Equals(p, value, StringComparison.OrdinalIgnoreCase));
            }

            private static string ExtractEndpointHost(string endpoint)
            {
                var value = (endpoint ?? string.Empty).Trim();
                if (value.StartsWith("[", StringComparison.Ordinal))
                {
                    var end = value.IndexOf(']');
                    return end > 1 ? value.Substring(1, end - 1) : value;
                }

                var colon = value.LastIndexOf(':');
                return colon > 0 ? value.Substring(0, colon) : value;
            }
        }
    }

    /// <summary>
    /// Entry point for the ProxiFyre service application.
    /// </summary>
    internal class Program
    {
        private static bool IsElevated()
        {
            try
            {
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Main method. Configures and runs the ProxiFyre service using Topshelf.
        /// </summary>
        /// <param name="args">Command-line arguments (e.g., install, uninstall, start, stop).</param>
        /// <returns>The Topshelf exit code as an integer.</returns>
        private static int Main(string[] args)
        {
            // Detect Topshelf lifecycle commands. For these commands the underlying
            // .NET installer (System.Configuration.Install.InstallContext, invoked via
            // ManagedInstallerClass.InstallHelper) writes multiple localized status
            // lines to Console.Out with noticeable delays between them, which can lead
            // users to close the console before the operation has actually completed.
            // We capture that output and replace it with a single, unambiguous message.
            var command = args.Length > 0 && !string.IsNullOrEmpty(args[0])
                ? args[0].ToLowerInvariant()
                : null;

            var isLifecycleCommand = command == "install"
                                     || command == "uninstall"
                                     || command == "start"
                                     || command == "stop";

            var isHelpCommand = command == "help"
                                || command == "--help"
                                || command == "-h"
                                || command == "/?";

            if (!isLifecycleCommand && !isHelpCommand && !IsElevated())
            {
                Console.Error.WriteLine(
                    "ProxiFyre must run with administrator privileges so process ownership, " +
                    "application exclusions, and packet redirection remain reliable. Start it from " +
                    "an Administrator console or install and start the Windows service.");
                return 5; // ERROR_ACCESS_DENIED
            }

            var originalOut = Console.Out;
            var originalError = Console.Error;

            using (var capturedOutput = isLifecycleCommand ? new StringWriter() : null)
            {
                if (isLifecycleCommand)
                {
                    Console.SetOut(capturedOutput);
                    Console.SetError(capturedOutput);
                }

                TopshelfExitCode exitCode;
                try
                {
                    exitCode = HostFactory.Run(x =>
                    {
                        x.Service<ProxiFyreService>(s =>
                        {
                            s.ConstructUsing(name => new ProxiFyreService());
                            s.WhenStarted(tc => tc.Start());
                            s.WhenStopped(tc => tc.Stop());
                        });

                        x.RunAsLocalSystem();

                        x.SetDescription("ProxiFyre - SOCKS5 ProxiFyre Service");
                        x.SetDisplayName("ProxiFyre Service");
                        x.SetServiceName("ProxiFyreService");
                    });
                }
                finally
                {
                    if (isLifecycleCommand)
                    {
                        Console.SetOut(originalOut);
                        Console.SetError(originalError);
                    }
                }

                if (isLifecycleCommand)
                {
                    if (exitCode == TopshelfExitCode.Ok)
                    {
                        string message;
                        switch (command)
                        {
                            case "install":
                                message = "ProxiFyre service installed successfully.";
                                break;
                            case "uninstall":
                                message = "ProxiFyre service uninstalled successfully.";
                                break;
                            case "start":
                                message = "ProxiFyre service started successfully.";
                                break;
                            case "stop":
                                message = "ProxiFyre service stopped successfully.";
                                break;
                            default:
                                message = "ProxiFyre command completed successfully.";
                                break;
                        }

                        originalOut.WriteLine(message);
                    }
                    else
                    {
                        // Surface the captured installer output so failures remain diagnosable.
                        var captured = capturedOutput.ToString();
                        if (!string.IsNullOrEmpty(captured))
                            originalError.Write(captured);
                        originalError.WriteLine($"ProxiFyre {command} command failed (exit code: {exitCode}).");
                    }
                }

                return (int)exitCode;
            }
        }
    }
}
