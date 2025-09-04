using Newtonsoft.Json;
using NLog;
using NLog.Config;
using Socksifier;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
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

            // Load the configuration from JSON
            var serviceSettings = JsonConvert.DeserializeObject<ProxiFyreSettings>(File.ReadAllText(configFilePath));

            LogManager.Configuration = new XmlLoggingConfiguration(logConfigFilePath);

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

            foreach (var appSettings in serviceSettings.Proxies)
            {
                // Add the defined SOCKS5 proxies
                var proxy = _socksify.AddSocks5Proxy(appSettings.Socks5ProxyEndpoint, appSettings.Username,
                    appSettings.Password, appSettings.SupportedProtocolsParse,
                    true); // Assuming the AddSocks5Proxy method supports a list of protocols

                foreach (var appName in appSettings.AppNames)
                    // Associate the defined application names to the proxies
                    if (proxy.ToInt64() != -1 && _socksify.AssociateProcessNameToProxy(appName, proxy) && _logLevel >= LogLevel.Info)
                        LoggerInstance.Info(
                            $"Successfully associated {appName} to {appSettings.Socks5ProxyEndpoint} SOCKS5 proxy with protocols {string.Join(", ", appSettings.SupportedProtocols)}!");
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

            // Configure IPv6 blocking if enabled
            if (serviceSettings.BlockIPv6)
            {
                if (_socksify.SetIPv6Blocking(true))
                {
                    if (_logLevel >= LogLevel.Info)
                        LoggerInstance.Info("IPv6 blocking enabled to prevent IP leaks from proxied applications.");
                }
                else
                {
                    LoggerInstance.Warn("Failed to enable IPv6 blocking.");
                }
            }

            _socksify.Start();

            // Inform user that the application is running
            if (_logLevel >= LogLevel.Info)
                LoggerInstance.Info("ProxiFyre Service is running...");
        }

        /// <summary>
        /// Stops the ProxiFyre service and disposes of resources.
        /// </summary>
        public void Stop()
        {
            // Dispose of the Socksifier before exiting
            _socksify.Dispose();
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
                LoggerInstance.Info(entry.Description?.Replace("\n", "").Replace("\r", ""));
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
        //            "supportedProtocols": ["TCP", "UDP"]
        //        },
        //        {
        //            "appNames": ["firefox", "firefox_dev"],
        //            "socks5ProxyEndpoint": "159.101.205.52:1080",
        //            "username": "username2",
        //            "password": "password2",
        //            "supportedProtocols": ["TCP"]
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
            /// Gets or sets the log level for the service.
            /// </summary>
            public string LogLevel { get; set; } = "Error";

            /// <summary>
            /// Gets or sets the list of proxy application settings.
            /// </summary>
            public List<AppSettings> Proxies { get; set; } = new List<AppSettings>();

            /// <summary>
            /// Gets or sets the list of app names to exclude.
            /// </summary>
            [JsonProperty("excludes", NullValueHandling = NullValueHandling.Ignore)]
            public List<string> ExcludedList { get; set; } = new List<string>();

            /// <summary>
            /// Gets or sets whether to block IPv6 traffic for proxied applications to prevent IP leaks.
            /// </summary>
            [JsonProperty("blockIPv6", NullValueHandling = NullValueHandling.Ignore)]
            public bool BlockIPv6 { get; set; } = false;
        }

        /// <summary>
        /// Represents the settings for a single proxy and its associated applications.
        /// </summary>
        internal class AppSettings
        {
            /// <summary>
            /// Gets or sets the list of application names to associate with the proxy.
            /// </summary>
            public List<string> AppNames { get; set; } = new List<string>();

            /// <summary>
            /// Gets or sets the SOCKS5 proxy endpoint address.
            /// </summary>
            public string Socks5ProxyEndpoint { get; set; } = "";

            /// <summary>
            /// Gets or sets the username for proxy authentication.
            /// </summary>
            public string Username { get; set; } = "";

            /// <summary>
            /// Gets or sets the password for proxy authentication.
            /// </summary>
            public string Password { get; set; } = "";

            /// <summary>
            /// Gets or sets the list of supported protocols (e.g., TCP, UDP).
            /// </summary>
            public List<string> SupportedProtocols { get; set; } = new List<string>();

            /// <summary>
            /// Gets the supported protocols as an enum value.
            /// </summary>
            public SupportedProtocolsEnum SupportedProtocolsParse
            {
                get
                {
                    if (SupportedProtocols.Count == 0 ||
                        (SupportedProtocols.Contains("TCP") && SupportedProtocols.Contains("UDP")))
                        return SupportedProtocolsEnum.BOTH;
                    if (SupportedProtocols.Contains("TCP"))
                        return SupportedProtocolsEnum.TCP;
                    return SupportedProtocols.Contains("UDP")
                        ? SupportedProtocolsEnum.UDP
                        : SupportedProtocolsEnum.BOTH;
                }
            }
        }
    }

    /// <summary>
    /// Entry point for the ProxiFyre service application.
    /// </summary>
    internal class Program
    {
        /// <summary>
        /// Main method. Configures and runs the ProxiFyre service using Topshelf.
        /// </summary>
        private static void Main()
        {
            HostFactory.Run(x =>
            {
                x.Service<ProxiFyreService>(s =>
                {
                    s.ConstructUsing(name => new ProxiFyreService());
                    s.WhenStarted(tc => tc.Start());
                    s.WhenStopped(tc => tc.Stop());
                });

                x.RunAsLocalSystem();

                x.SetDescription("ProxiFyre - SOCKS5 Proxifyre Service");
                x.SetDisplayName("ProxiFyre Service");
                x.SetServiceName("ProxiFyreService");
            });
        }
    }
}
