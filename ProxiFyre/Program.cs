using NLog;
using NLog.Config;
using ProxiFyre.Configuration;
using Socksifier;
using System;
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
            var configFilePath = ProxiFyrePaths.GetConfigurationPath(executablePath);

            // Form the path to NLog.config
            var logConfigFilePath = Path.Combine(directoryPath ?? string.Empty, "NLog.config");

            // Configure logging first so that any configuration problems below are recorded.
            if (File.Exists(logConfigFilePath))
                LogManager.Configuration = new XmlLoggingConfiguration(logConfigFilePath);

            // Load and validate the configuration from JSON
            var serviceSettings = LoadConfiguration(configFilePath);

            // Handle the global log level from the configuration
            _logLevel = MapLogLevel(ConfigurationValueParser.GetLogLevel(serviceSettings.LogLevel));

            // Native construction opens the NDISRD device before Start() is called. Translate
            // initialization failures here so direct console/service starts always leave an
            // actionable engine log instead of only an SCM startup failure.
            try
            {
                _socksify = Socksifier.Socksifier.GetInstance(_logLevel);
            }
            catch (Exception ex)
            {
                const string message =
                    "Failed to initialize the ProxiFyre proxy engine. Ensure the Windows Packet Filter " +
                    "(NDISRD) driver is installed and available, then restart the service.";
                LoggerInstance.Error(ex, message);
                throw new InvalidOperationException(message, ex);
            }

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
                var protocolSelection = ConfigurationValueParser.GetProtocols(appSettings.SupportedProtocols);
                var addressFamilySelection =
                    ConfigurationValueParser.GetAddressFamilies(appSettings.SupportedAddressFamilies);
                var transportSelection = ConfigurationValueParser.GetTransport(appSettings.Socks5Transport);

                // Add the defined SOCKS5 proxies
                var proxy = _socksify.AddSocks5Proxy(appSettings.Socks5ProxyEndpoint, appSettings.Username,
                    appSettings.Password, MapProtocols(protocolSelection),
                    MapAddressFamilies(addressFamilySelection),
                    MapTransport(transportSelection),
                    appSettings.EffectiveTlsServerName,
                    ConfigurationNormalizer.NormalizeFingerprint(appSettings.TlsPinnedSha256),
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
                var transport = transportSelection == Socks5TransportKind.Tls
                    ? "SOCKS5Tls"
                    : "SOCKS5";
                foreach (var appName in appSettings.AppNames)
                    // Associate the defined application names to the proxies
                    if (_socksify.AssociateProcessNameToProxy(appName, proxy) && _logLevel >= LogLevel.Info)
                        LoggerInstance.Info(
                            $"Successfully associated {appName} to {appSettings.Socks5ProxyEndpoint} {transport} proxy with protocols {protocols} and address families {addressFamilies}!");
            }

            foreach (var excludedEntry in serviceSettings.Excludes)
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
        /// Loads, validates, and normalizes app-config.json through the shared managed layer.
        /// Validation is dependency-free: this service owns logging and native enum mapping.
        /// </summary>
        private static ProxiFyreConfiguration LoadConfiguration(string configFilePath)
        {
            if (!File.Exists(configFilePath))
            {
                var message = $"Configuration file not found: '{configFilePath}'. " +
                              "Create an app-config.json next to ProxiFyre.exe before starting the service.";
                LoggerInstance.Error(message);
                throw new InvalidOperationException(message);
            }

            ProxiFyreConfiguration configuration;
            try
            {
                configuration = new ConfigurationSerializer().Load(configFilePath);
            }
            catch (Exception ex)
            {
                var message = $"Failed to read or parse configuration file '{configFilePath}': {ex.Message}";
                LoggerInstance.Error(ex, message);
                throw new InvalidOperationException(message, ex);
            }

            var validation = new ConfigurationValidator().Validate(configuration);
            foreach (var warning in validation.Warnings)
                LoggerInstance.Warn(FormatValidationIssue(warning));

            if (validation.HasErrors)
            {
                foreach (var error in validation.Errors)
                    LoggerInstance.Error(FormatValidationIssue(error));

                throw new InvalidOperationException(
                    "ProxiFyre configuration validation failed. Review the preceding configuration errors.");
            }

            return new ConfigurationNormalizer().Normalize(configuration);
        }

        private static string FormatValidationIssue(ValidationIssue issue)
        {
            var location = string.IsNullOrWhiteSpace(issue.Path) ? string.Empty : $" at {issue.Path}";
            return $"Configuration {issue.Severity.ToString().ToLowerInvariant()} {issue.Code}{location}: {issue.Message}";
        }

        private static SupportedProtocolsEnum MapProtocols(ProxyProtocolSelection selection)
        {
            if (selection == ProxyProtocolSelection.Tcp)
                return SupportedProtocolsEnum.TCP;
            if (selection == ProxyProtocolSelection.Udp)
                return SupportedProtocolsEnum.UDP;
            return SupportedProtocolsEnum.BOTH;
        }

        private static LogLevel MapLogLevel(ConfigurationLogLevel logLevel)
        {
            switch (logLevel)
            {
                case ConfigurationLogLevel.Error:
                    return LogLevel.Error;
                case ConfigurationLogLevel.Warning:
                    return LogLevel.Warning;
                case ConfigurationLogLevel.Debug:
                    return LogLevel.Debug;
                case ConfigurationLogLevel.All:
                    return LogLevel.All;
                default:
                    return LogLevel.Info;
            }
        }

        private static SupportedAddressFamiliesEnum MapAddressFamilies(ProxyAddressFamilySelection selection)
        {
            if (selection == ProxyAddressFamilySelection.Ipv4)
                return SupportedAddressFamiliesEnum.IPv4;
            if (selection == ProxyAddressFamilySelection.Ipv6)
                return SupportedAddressFamiliesEnum.IPv6;
            return SupportedAddressFamiliesEnum.BOTH;
        }

        private static Socks5TransportEnum MapTransport(Socks5TransportKind transport)
        {
            return transport == Socks5TransportKind.Tls
                ? Socks5TransportEnum.TLS
                : Socks5TransportEnum.TCP;
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
                        x.SetServiceName(ProxiFyrePaths.ServiceName);
                        x.DependsOn(ProxiFyrePaths.WindowsPacketFilterServiceName);
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
