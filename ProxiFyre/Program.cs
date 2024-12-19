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
    // Main class for the SOCKS proxy application
    public class ProxiFyreService
    {
        private static readonly Logger _logger = LogManager.GetCurrentClassLogger();
        private static LogLevel _logLevel;
        private Socksifier.Socksifier _socksify;

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
                    if (proxy.ToInt64() != -1 && _socksify.AssociateProcessNameToProxy(appName, proxy) && _logLevel != LogLevel.None)
                        _logger.Info(
                            $"Successfully associated {appName} to {appSettings.Socks5ProxyEndpoint} SOCKS5 proxy with protocols {string.Join(", ", appSettings.SupportedProtocols)}!");
            }

            _socksify.Start();

            // Inform user that the application is running
            if (_logLevel != LogLevel.None)
                _logger.Info("ProxiFyre Service is running...");
        }

        public void Stop()
        {
            // Dispose of the Socksifier before exiting
            _socksify.Dispose();
            if (_logLevel != LogLevel.None)
                _logger.Info("ProxiFyre Service has stopped.");
            LogManager.Shutdown();
        }

        // Method to handle logging events
        private static void LogPrinter(object sender, LogEventArgs e)
        {
            if (_logLevel == LogLevel.None)
                return;

            // Loop through each log entry and log it using NLog
            foreach (var entry in e.Log.Where(entry => entry != null))
            {
                var logMessage =
                    $"{new DateTime(1970, 1, 1).AddSeconds(entry.TimeStamp / 1000)}::{entry.Event}::{entry.Description}::{entry.Data}";
                _logger.Info(logMessage);
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
        //    ]
        //}

        private class ProxiFyreSettings
        {
            public string LogLevel { get; set; }
            public List<AppSettings> Proxies { get; set; }
        }

        private class AppSettings
        {
            public List<string> AppNames { get; set; }
            public string Socks5ProxyEndpoint { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }
            public List<string> SupportedProtocols { get; set; } // Keep the original list for parsing

            public SupportedProtocolsEnum SupportedProtocolsParse // New property for the enum
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

    internal class Program
    {
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

                x.SetDescription("ProxiFyre - SOCKS5 Proxifier Service");
                x.SetDisplayName("ProxiFyre Service");
                x.SetServiceName("ProxiFyreService");
            });
        }
    }
}