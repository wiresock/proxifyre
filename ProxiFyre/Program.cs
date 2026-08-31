using NLog;
using NLog.Config;
using ProxiFyre.Configuration;
using Socksifier;
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Text;
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
        /// When true, traffic whose owning process cannot be resolved is deliberately
        /// kept direct instead of being eligible for a catch-all proxy rule.
        /// </summary>
        private readonly bool _useLimitedMode;

        public ProxiFyreService() : this(false)
        {
        }

        internal ProxiFyreService(bool useLimitedMode)
        {
            _useLimitedMode = useLimitedMode;
        }

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

            // Emit this before applying the configured minimum level so the safety warning is
            // retained even when app-config.json selects Error logging. The command-line path
            // also writes it to stderr for launchers that capture console output.
            if (_useLimitedMode)
                LoggerInstance.Warn(Program.LimitedModeWarning);

            // Load and validate the configuration from JSON
            var serviceSettings = LoadConfiguration(configFilePath);

            // Handle the global log level from the configuration
            _logLevel = MapLogLevel(ConfigurationValueParser.GetLogLevel(serviceSettings.LogLevel));
            ConfigureManagedLogLevel(_logLevel);

            // Native construction opens the NDISRD device before Start() is called. Translate
            // initialization failures here so direct console/service starts always leave an
            // actionable engine log instead of only an SCM startup failure.
            try
            {
                _socksify = Socksifier.Socksifier.GetInstance(_logLevel, _useLimitedMode);
            }
            catch (Exception ex)
            {
                var message = _useLimitedMode
                    ? "Failed to initialize the ProxiFyre proxy engine in non-administrator mode. " +
                      "Ensure the Windows Packet Filter (NDISRD) driver is installed and that this " +
                      "Windows account is permitted to open the driver, then retry."
                    : "Failed to initialize the ProxiFyre proxy engine. Ensure the Windows Packet Filter " +
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
                var message = _useLimitedMode
                    ? "Failed to start the ProxiFyre proxy engine in non-administrator mode. " +
                      "Ensure the Windows Packet Filter (NDISRD) driver is installed and running and " +
                      "that this Windows account is permitted to activate it, or retry from an " +
                      "Administrator console."
                    : "Failed to start the ProxiFyre proxy engine. Ensure the Windows Packet Filter " +
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

        private static void ConfigureManagedLogLevel(LogLevel logLevel)
        {
            var configuration = LogManager.Configuration;
            if (configuration == null)
                return;

            var minimumLevel = MapManagedLogLevel(logLevel);
            foreach (var rule in configuration.LoggingRules)
                rule.SetLoggingLevels(minimumLevel, NLog.LogLevel.Fatal);
            LogManager.ReconfigExistingLoggers();
        }

        private static NLog.LogLevel MapManagedLogLevel(LogLevel logLevel)
        {
            switch (logLevel)
            {
                case LogLevel.Error:
                    return NLog.LogLevel.Error;
                case LogLevel.Warning:
                    return NLog.LogLevel.Warn;
                case LogLevel.Debug:
                case LogLevel.All:
                    return NLog.LogLevel.Debug;
                default:
                    return NLog.LogLevel.Info;
            }
        }

        private static NLog.LogLevel GetNativeLogLevel(string message)
        {
            LogMessageLevel nativeLevel;
            if (!LogMessageLevelParser.TryGetLeadingNativeLevel(message, out nativeLevel))
                return NLog.LogLevel.Info;

            switch (nativeLevel)
            {
                case LogMessageLevel.Error:
                    return NLog.LogLevel.Error;
                case LogMessageLevel.Warning:
                    return NLog.LogLevel.Warn;
                case LogMessageLevel.Debug:
                    return NLog.LogLevel.Debug;
                default:
                    return NLog.LogLevel.Info;
            }
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
            // Preserve the native severity in the structured NLog record. Keeping the native
            // token in the message also lets the GUI read logs created by older releases.
            foreach (var entry in e.Log.Where(entry => entry != null))
            {
                var message = (entry.Description ?? string.Empty).Replace("\n", "").Replace("\r", "");
                LoggerInstance.Log(GetNativeLogLevel(message), message);
            }
        }

    }

    /// <summary>
    /// Entry point for the ProxiFyre service application.
    /// </summary>
    internal class Program
    {
        internal const string LimitedModeWarning =
            "WARNING: ProxiFyre is running in explicitly enabled non-administrator mode. " +
            "Driver access and process attribution are best effort. Traffic whose owner cannot be " +
            "resolved (which may include protected, elevated, system, or other-user traffic) remains direct. " +
            "This mode is not a strict current-user security boundary and must not be used for complete " +
            "machine-wide enforcement.";

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
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int Main(string[] args)
        {
            args = args ?? Array.Empty<string>();

            try
            {
                NativeDependencyLoader.Initialize();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(
                    "ProxiFyre could not establish its secure native dependency loading policy. " +
                    ex.Message);
                return 126; // ERROR_MOD_NOT_FOUND
            }

            var commandLine = EngineCommandLinePolicy.Evaluate(
                args, Environment.UserInteractive, IsElevated());

            if (!commandLine.CanRun)
            {
                Console.Error.WriteLine(GetCommandLineDenialMessage(commandLine.Denial));
                return commandLine.Denial == EngineCommandLineDenial.AdministratorPrivilegesRequired
                    ? 5 // ERROR_ACCESS_DENIED
                    : 87; // ERROR_INVALID_PARAMETER
            }

#if !DEBUG
            if (commandLine.RequiresProtectedServiceLocation)
            {
                string locationFailure;
                if (!EngineServiceInstallLocationPolicy.IsProtected(
                        Assembly.GetExecutingAssembly().Location, out locationFailure))
                {
                    Console.Error.WriteLine(
                        "ProxiFyre cannot install or run its LocalSystem service from a location " +
                        "writable by standard users. Copy or extract the complete release into " +
                        "a protected per-machine directory (normally under Program Files), " +
                        "preserve inherited permissions, and retry. " + locationFailure);
                    return 5; // ERROR_ACCESS_DENIED
                }
            }
#endif

            // Keep all references that can cause the mixed-mode Socksifier assembly to load
            // behind a non-inlined boundary. The CLR must execute the loader policy above before
            // it can JIT this method or resolve ProxiFyreService.
            return RunAfterNativeDependencyPolicy(args, commandLine);
        }

        private static string GetCommandLineDenialMessage(EngineCommandLineDenial denial)
        {
            switch (denial)
            {
                case EngineCommandLineDenial.AllowNotAdministratorWithLifecycleCommand:
                    return "--allow-not-admin is available only for an interactive console run; " +
                           "it cannot be combined with install, uninstall, start, or stop.";
                case EngineCommandLineDenial.AllowNotAdministratorRequiresInteractiveSession:
                    return "--allow-not-admin cannot be used by the Windows service or another " +
                           "non-interactive session. Run ProxiFyre interactively instead.";
                default:
                    return "ProxiFyre must run with administrator privileges so process ownership, " +
                           "application exclusions, and packet redirection remain reliable. Start it from " +
                           "an Administrator console, install and start the Windows service, or explicitly " +
                           "opt into the limited interactive mode with --allow-not-admin.";
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int RunAfterNativeDependencyPolicy(string[] arguments,
            EngineCommandLineDecision commandLine)
        {
            // Detect Topshelf lifecycle commands. For these commands the underlying
            // .NET installer (System.Configuration.Install.InstallContext, invoked via
            // ManagedInstallerClass.InstallHelper) writes multiple localized status
            // lines to Console.Out with noticeable delays between them, which can lead
            // users to close the console before the operation has actually completed.
            // We capture that output and replace it with a single, unambiguous message.
            var command = commandLine.LifecycleCommand;
            var isLifecycleCommand = commandLine.IsLifecycleCommand;

            if (commandLine.UseLimitedMode)
                Console.Error.WriteLine(LimitedModeWarning);

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
                            s.ConstructUsing(name => new ProxiFyreService(commandLine.UseLimitedMode));
                            s.WhenStarted(tc => tc.Start());
                            s.WhenStopped(tc => tc.Stop());
                        });

                        x.RunAsLocalSystem();

                        x.SetDescription("ProxiFyre - SOCKS5 ProxiFyre Service");
                        x.SetDisplayName("ProxiFyre Service");
                        x.SetServiceName(ProxiFyrePaths.ServiceName);
                        x.DependsOn(ProxiFyrePaths.WindowsPacketFilterServiceName);

                        if (commandLine.AllowNotAdministratorRequested)
                        {
                            // Topshelf 4.3 splits hyphenated switch names into separate tokens.
                            // ProxiFyre owns this exact opt-in, so remove only that token and ask
                            // Topshelf to parse every remaining argument explicitly. Calling this
                            // overload also prevents HostFactory from reparsing Environment.CommandLine.
                            x.ApplyCommandLine(BuildTopshelfCommandLine(arguments));
                        }
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

        private static string BuildTopshelfCommandLine(string[] arguments)
        {
            return string.Join(" ", arguments
                .Where(argument => !string.Equals(argument,
                    EngineCommandLinePolicy.AllowNotAdministratorSwitch,
                    StringComparison.Ordinal))
                .Select(QuoteCommandLineArgument));
        }

        private static string QuoteCommandLineArgument(string argument)
        {
            argument = argument ?? string.Empty;
            if (argument.Length > 0 && argument.IndexOf('"') < 0 && !argument.Any(char.IsWhiteSpace))
                return argument;

            // Preserve the standard Windows command-line quoting rules so Topshelf receives the
            // same argument values that Main did, including embedded quotes and trailing slashes.
            var result = new StringBuilder(argument.Length + 2);
            result.Append('"');
            var backslashes = 0;
            foreach (var character in argument)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }

                if (character == '"')
                {
                    result.Append('\\', backslashes * 2 + 1);
                    result.Append('"');
                    backslashes = 0;
                    continue;
                }

                result.Append('\\', backslashes);
                backslashes = 0;
                result.Append(character);
            }

            result.Append('\\', backslashes * 2);
            result.Append('"');
            return result.ToString();
        }
    }
}
