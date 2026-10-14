using ProxiFyre.Configuration;
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;
using Topshelf;

namespace ProxiFyre
{    /// <summary>
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
                    Console.Error.WriteLine(GetUnprotectedServiceLocationMessage(locationFailure));
                    return 5; // ERROR_ACCESS_DENIED
                }
            }
#endif

            // Keep all references that can cause the mixed-mode Socksifier assembly to load
            // behind a non-inlined boundary. The CLR must execute the loader policy above before
            // it can JIT this method or resolve ProxiFyreService.
            return RunAfterNativeDependencyPolicy(args, commandLine);
        }

        internal static string GetUnprotectedServiceLocationMessage(string locationFailure)
        {
            return "ProxiFyre cannot install or run its LocalSystem service from this location " +
                   "because its files might be replaceable without administrator approval." +
                   Environment.NewLine + "Reason: " + locationFailure + Environment.NewLine +
                   "To fix this, install ProxiFyre with the official setup or MSI package. It " +
                   "creates a protected directory under Program Files. To use the ZIP package " +
                   "instead, follow the protected staging procedure at " +
                   GetZipStagingDocumentationUrl();
        }

        // Links the staging procedure from this build's release tag so the steps match the
        // checks this binary enforces. A version that is not a plain major.minor.patch release
        // number, such as one passed with /p:Version for a test build, has no tag to link to.
        private static string GetZipStagingDocumentationUrl()
        {
            var version = typeof(Program).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            Version parsed;
            var isReleaseVersion = Version.TryParse(version, out parsed) && parsed.Build >= 0 &&
                                   parsed.Revision < 0 &&
                                   string.Equals(parsed.ToString(), version, StringComparison.Ordinal);
            var reference = isReleaseVersion ? "v" + version : "main";
            return "https://github.com/wiresock/proxifyre/blob/" + reference +
                   "/docs/zip-staging.md";
        }

        private static string GetCommandLineDenialMessage(EngineCommandLineDenial denial)
        {
            switch (denial)
            {
                case EngineCommandLineDenial.ConflictingOperationalCommands:
                    return "ProxiFyre received more than one operational command. Specify only one " +
                           "of run, install, uninstall, start, stop, or command.";
                case EngineCommandLineDenial.AllowNotAdministratorWithServiceControlCommand:
                    return "--allow-not-admin is available only for an interactive console run; " +
                           "it cannot be combined with service-control commands: install, " +
                           "uninstall, start, stop, or command.";
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
            if (ShouldLaunchEngineWinForms(arguments, commandLine))
                return RunEngineWinForms(commandLine);

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

        private static bool ShouldLaunchEngineWinForms(string[] arguments,
            EngineCommandLineDecision commandLine)
        {
            if (commandLine.IsLifecycleCommand || commandLine.IsHelpCommand)
                return false;
            if (!Environment.UserInteractive)
                return false;
            if (ContainsOperationalVerb(arguments, "run") ||
                ContainsOperationalVerb(arguments, "command"))
                return false;

            return true;
        }

        private static bool ContainsOperationalVerb(string[] arguments, string verb)
        {
            foreach (var argument in arguments ?? Array.Empty<string>())
            {
                if (string.Equals(argument, verb, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static int RunEngineWinForms(EngineCommandLineDecision commandLine)
        {
            if (commandLine.UseLimitedMode)
                Console.Error.WriteLine(LimitedModeWarning);

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            var service = new ProxiFyreService(commandLine.UseLimitedMode);
            using (var form = new MainForm(service))
            {
                var originalOut = Console.Out;
                var originalError = Console.Error;
                var uiWriter = new TextBoxTextWriter(form.AppendLogSafe);
                Console.SetOut(new MultiTextWriter(originalOut, uiWriter));
                Console.SetError(new MultiTextWriter(originalError, uiWriter));
                Application.Run(form);
                try { service.Stop(); } catch { }
                try { Console.SetOut(originalOut); } catch { }
                try { Console.SetError(originalError); } catch { }
            }

            return 0;
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
