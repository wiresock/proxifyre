using System;

namespace ProxiFyre.Configuration
{
    /// <summary>
    /// Classifies an engine invocation before Topshelf loads the service implementation.
    /// Keeping this policy independent of the mixed-mode engine makes privilege-boundary
    /// decisions deterministic and directly testable.
    /// </summary>
    public static class EngineCommandLinePolicy
    {
        public const string AllowNotAdministratorSwitch = "--allow-not-admin";

        private static readonly string[] LifecycleCommands =
        {
            "install",
            "uninstall",
            "start",
            "stop"
        };

        private static readonly string[] ServiceControlCommands =
        {
            "install",
            "uninstall",
            "start",
            "stop",
            "command"
        };

        private static readonly string[] OperationalCommands =
        {
            "run",
            "install",
            "uninstall",
            "start",
            "stop",
            "command"
        };

        private static readonly string[] HelpCommands =
        {
            "help",
            "--help",
            "-h",
            "/?"
        };

        public static EngineCommandLineDecision Evaluate(string[] arguments,
            bool isUserInteractive, bool isElevated)
        {
            arguments = arguments ?? Array.Empty<string>();

            var lifecycleCommand = FindKnownArgument(arguments, LifecycleCommands);
            var serviceControlCommand = FindKnownArgument(arguments, ServiceControlCommands);
            var operationalCommandCount = CountDistinctKnownArguments(
                arguments, OperationalCommands);
            var isHelpCommand = IsHelpOnlyInvocation(arguments);
            var allowNotAdministratorRequested = ContainsExactArgument(arguments,
                AllowNotAdministratorSwitch);
            var requiresProtectedServiceLocation =
                !isHelpCommand &&
                (string.Equals(lifecycleCommand, "install", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(lifecycleCommand, "start", StringComparison.OrdinalIgnoreCase) ||
                 !isUserInteractive);

            // Topshelf applies recognized verbs in argument order, so the final verb can replace
            // an earlier lifecycle command. Reject ambiguous command lines before the lifecycle
            // privilege exemption can be used to reach a later interactive `run` verb.
            if (operationalCommandCount > 1)
            {
                return new EngineCommandLineDecision(lifecycleCommand, false,
                    isHelpCommand, allowNotAdministratorRequested, false,
                    requiresProtectedServiceLocation,
                    EngineCommandLineDenial.ConflictingOperationalCommands);
            }

            if (allowNotAdministratorRequested && serviceControlCommand != null)
            {
                return new EngineCommandLineDecision(lifecycleCommand, false,
                    isHelpCommand, true, false, requiresProtectedServiceLocation,
                    EngineCommandLineDenial.AllowNotAdministratorWithServiceControlCommand);
            }

            // Help must remain available to a standard user. The opt-in switch has no runtime
            // effect when help is requested.
            if (isHelpCommand)
            {
                return new EngineCommandLineDecision(lifecycleCommand, false, true,
                    allowNotAdministratorRequested, false, requiresProtectedServiceLocation,
                    EngineCommandLineDenial.None);
            }

            // Topshelf owns privilege handling for service lifecycle commands. The limited
            // interactive mode never changes their behavior.
            if (lifecycleCommand != null)
            {
                return new EngineCommandLineDecision(lifecycleCommand, true, false, false,
                    false, requiresProtectedServiceLocation, EngineCommandLineDenial.None);
            }

            if (allowNotAdministratorRequested && !isUserInteractive)
            {
                return new EngineCommandLineDecision(null, false, false, true, false,
                    true, EngineCommandLineDenial.AllowNotAdministratorRequiresInteractiveSession);
            }

            if (!isElevated && !allowNotAdministratorRequested)
            {
                return new EngineCommandLineDecision(null, false, false, false, false,
                    requiresProtectedServiceLocation,
                    EngineCommandLineDenial.AdministratorPrivilegesRequired);
            }

            return new EngineCommandLineDecision(null, false, false,
                allowNotAdministratorRequested,
                allowNotAdministratorRequested && isUserInteractive && !isElevated,
                requiresProtectedServiceLocation, EngineCommandLineDenial.None);
        }

        private static bool ContainsExactArgument(string[] arguments, string expected)
        {
            foreach (var argument in arguments)
            {
                if (string.Equals(argument, expected, StringComparison.Ordinal))
                    return true;
            }

            return false;
        }

        private static string FindKnownArgument(string[] arguments, string[] expectedArguments)
        {
            foreach (var argument in arguments)
            {
                foreach (var expected in expectedArguments)
                {
                    if (string.Equals(argument, expected, StringComparison.OrdinalIgnoreCase))
                        return expected;
                }
            }

            return null;
        }

        private static int CountDistinctKnownArguments(
            string[] arguments, string[] expectedArguments)
        {
            var count = 0;
            var foundArguments = new bool[expectedArguments.Length];
            foreach (var argument in arguments)
            {
                for (var index = 0; index < expectedArguments.Length; index++)
                {
                    if (!string.Equals(argument, expectedArguments[index],
                            StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (!foundArguments[index])
                    {
                        foundArguments[index] = true;
                        count++;
                    }

                    break;
                }
            }

            return count;
        }

        private static bool IsHelpOnlyInvocation(string[] arguments)
        {
            var foundHelp = false;
            foreach (var argument in arguments)
            {
                if (string.Equals(argument, AllowNotAdministratorSwitch,
                        StringComparison.Ordinal))
                    continue;

                if (FindKnownArgument(new[] { argument }, HelpCommands) != null)
                {
                    foundHelp = true;
                    continue;
                }

                // Do not let a help token bypass the elevation policy for an invocation
                // that Topshelf could interpret as a run or another command.
                return false;
            }

            return foundHelp;
        }
    }

    public enum EngineCommandLineDenial
    {
        None,
        AdministratorPrivilegesRequired,
        ConflictingOperationalCommands,
        AllowNotAdministratorWithServiceControlCommand,
        AllowNotAdministratorRequiresInteractiveSession
    }

    public sealed class EngineCommandLineDecision
    {
        internal EngineCommandLineDecision(string lifecycleCommand, bool isLifecycleCommand,
            bool isHelpCommand, bool allowNotAdministratorRequested, bool useLimitedMode,
            bool requiresProtectedServiceLocation, EngineCommandLineDenial denial)
        {
            LifecycleCommand = lifecycleCommand;
            IsLifecycleCommand = isLifecycleCommand;
            IsHelpCommand = isHelpCommand;
            AllowNotAdministratorRequested = allowNotAdministratorRequested;
            UseLimitedMode = useLimitedMode;
            RequiresProtectedServiceLocation = requiresProtectedServiceLocation;
            Denial = denial;
        }

        public string LifecycleCommand { get; }
        public bool IsLifecycleCommand { get; }
        public bool IsHelpCommand { get; }
        public bool AllowNotAdministratorRequested { get; }
        public bool UseLimitedMode { get; }
        public bool RequiresProtectedServiceLocation { get; }
        public EngineCommandLineDenial Denial { get; }
        public bool CanRun => Denial == EngineCommandLineDenial.None;
    }
}
