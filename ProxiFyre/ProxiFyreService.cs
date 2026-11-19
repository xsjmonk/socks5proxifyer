using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using NLog;
using NLog.Config;
using ProxiFyre.Configuration;
using Socksifier;
using SocksifierLogLevel = Socksifier.LogLevel;

namespace ProxiFyre
{
    /// <summary>
    /// Owns the single configuration-driven runtime bootstrap used by both the
    /// WinForms UI and Topshelf service dispatch.
    /// </summary>
    public sealed class ProxiFyreService
    {
        private static readonly Logger LoggerInstance = LogManager.GetCurrentClassLogger();
        private readonly bool _useLimitedMode;
        private Socksifier.Socksifier _socksify;
        private SocksifierLogLevel _logLevel;

        public ProxiFyreService() : this(false)
        {
        }

        internal ProxiFyreService(bool useLimitedMode)
        {
            _useLimitedMode = useLimitedMode;
        }

        public void Start()
        {
            var executablePath = Assembly.GetExecutingAssembly().Location;
            var directoryPath = Path.GetDirectoryName(executablePath) ?? string.Empty;
            var configFilePath = ProxiFyrePaths.GetConfigurationPath(executablePath);
            var logConfigFilePath = Path.Combine(directoryPath, "NLog.config");

            if (File.Exists(logConfigFilePath))
                LogManager.Configuration = new XmlLoggingConfiguration(logConfigFilePath);

            if (_useLimitedMode)
                LoggerInstance.Warn(Program.LimitedModeWarning);

            ArtifactIdentity.Log(LoggerInstance, configFilePath);
            var settings = LoadConfiguration(configFilePath);
            _logLevel = MapLogLevel(ConfigurationValueParser.GetLogLevel(settings.LogLevel));
            ConfigureManagedLogLevel(_logLevel);

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

            _socksify.LogEvent += LogPrinter;
            _socksify.LogLimit = 100;
            _socksify.LogEventInterval = 1000;

            if (settings.BypassLan)
                _socksify.SetBypassLan();

            // The coordinator owns the invalid-handle guard: handle == IntPtr.Zero
            // or -1 is rejected before association and the rule uses continue;
            // semantics so later valid rules are still attempted.
            var coordinator = new ProxyRuleRegistrationCoordinator();
            var registration = coordinator.Register(
                settings.Proxies,
                new SocksifierProxyEngine(_socksify),
                (index, rule) => LoggerInstance.Info(
                    "Proxy rule {0}: endpoint={1}, credentials={2}/{3}, protocols={4}, addressFamilies={5}, transport={6}, tlsServerName={7}, fingerprint={8}, allowInvalidCertificate={9}, overload=full, start={10}.",
                    index + 1,
                    rule.Endpoint,
                    rule.UsernameLength == 0 ? "none" : "present",
                    rule.PasswordLength == 0 ? "none" : "present",
                    rule.Protocols,
                    rule.AddressFamilies,
                    rule.Transport,
                    rule.TlsServerName,
                    string.IsNullOrEmpty(rule.TlsPinnedSha256) ? "absent" : "present",
                    rule.TlsAllowInvalidCertificate,
                    rule.Start),
                (index, message) => LoggerInstance.Warn(
                    "Proxy rule {0} ({1}): {2}.",
                    index + 1,
                    settings.Proxies[index]?.Socks5ProxyEndpoint ?? string.Empty,
                    message),
                (index, message) => LoggerInstance.Info(
                    "Proxy rule {0}: {1}.", index + 1, message));

            if (!registration.AllRequiredRulesRegistered)
            {
                var failedRules = string.Join(
                    ", ",
                    registration.Failures.Select(f =>
                        (f.RuleIndex + 1) + ":" + f.Endpoint + ":" + f.Category));
                throw new InvalidOperationException(
                    "Required SOCKS5 proxy registration failed; the router was not started. " +
                    "Failed rules: " + failedRules);
            }

            foreach (var excludedEntry in settings.Excludes ?? Enumerable.Empty<string>())
                _socksify.ExcludeProcessName(excludedEntry);

            ConfigureDnsRouting(settings, registration.RuleHandles);

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

            if (_logLevel >= SocksifierLogLevel.Info)
                LoggerInstance.Info("ProxiFyre Service is running...");
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
                LogManager.Shutdown();
            }
        }

        /// <summary>
        /// Applies the global DNS policy before the router starts. Direct mode lets DNS bypass
        /// the proxies. Proxy mode routes DNS through the rule selected by dns.proxyId. Any
        /// failure stops the start instead of sending DNS directly or through another proxy.
        /// </summary>
        private void ConfigureDnsRouting(ProxiFyreConfiguration settings, IList<IntPtr> ruleHandles)
        {
            DnsRoutingMode mode;
            if (!DnsConfiguration.TryGetMode(settings.Dns == null ? null : settings.Dns.Mode, out mode))
            {
                var message = "DNS routing: the DNS mode '" + settings.Dns.Mode + "' is not recognized; use Direct or Proxy.";
                LoggerInstance.Error(message);
                throw new InvalidOperationException(message);
            }

            if (mode == DnsRoutingMode.Direct)
            {
                if (!_socksify.SetDnsRouting(DnsRoutingModeEnum.Direct, new IntPtr(-1), null))
                    LoggerInstance.Warn("Failed to apply Direct DNS routing.");
                else if (_logLevel >= SocksifierLogLevel.Info)
                    LoggerInstance.Info("DNS routing: Direct - DNS (UDP/TCP port 53) bypasses the SOCKS5 proxies.");
                return;
            }

            var dns = settings.Dns;
            var ruleIndex = DnsConfiguration.FindProxyRuleIndex(settings.Proxies, dns.ProxyId);
            var handle = ruleIndex >= 0 && ruleIndex < ruleHandles.Count ? ruleHandles[ruleIndex] : new IntPtr(-1);
            if (handle == IntPtr.Zero || handle.ToInt64() == -1)
            {
                var message = "DNS routing: the DNS proxy '" + dns.ProxyId + "' has no usable SOCKS5 proxy handle. " +
                              "The router was not started so that DNS is not sent directly or through another proxy.";
                LoggerInstance.Error(message);
                throw new InvalidOperationException(message);
            }

            if (!_socksify.SetDnsRouting(DnsRoutingModeEnum.Proxy, handle, dns.ServerOverride))
            {
                var message = "DNS routing: the engine rejected the Proxy mode configuration; the router was not started.";
                LoggerInstance.Error(message);
                throw new InvalidOperationException(message);
            }

            if (_logLevel >= SocksifierLogLevel.Info)
            {
                var serverOverride = string.IsNullOrWhiteSpace(dns.ServerOverride) ? "original destinations" : dns.ServerOverride;
                LoggerInstance.Info("DNS routing: Proxy via '" + dns.ProxyId + "' (" +
                                    settings.Proxies[ruleIndex].Socks5ProxyEndpoint + "), upstream DNS: " + serverOverride + ".");
            }
        }

        private static ProxiFyreConfiguration LoadConfiguration(string filePath)
        {
            if (!File.Exists(filePath))
                throw new InvalidOperationException(
                    "Configuration file not found: " + filePath);

            var configuration = new ConfigurationSerializer().Load(filePath);
            var validation = new ConfigurationValidator().Validate(configuration);
            if (validation.HasErrors)
                throw new InvalidOperationException(
                    "ProxiFyre configuration validation failed.");

            foreach (var warning in validation.Warnings)
                LoggerInstance.Warn(warning.Message);

            return new ConfigurationNormalizer().Normalize(configuration);
        }

        private static SocksifierLogLevel MapLogLevel(ConfigurationLogLevel logLevel)
        {
            switch (logLevel)
            {
                case ConfigurationLogLevel.Error: return SocksifierLogLevel.Error;
                case ConfigurationLogLevel.Warning: return SocksifierLogLevel.Warning;
                case ConfigurationLogLevel.Debug: return SocksifierLogLevel.Debug;
                case ConfigurationLogLevel.All: return SocksifierLogLevel.All;
                default: return SocksifierLogLevel.Info;
            }
        }

        private static void ConfigureManagedLogLevel(SocksifierLogLevel level)
        {
            var configuration = LogManager.Configuration;
            if (configuration == null)
                return;

            var minimum = level == SocksifierLogLevel.Error
                ? NLog.LogLevel.Error
                : level == SocksifierLogLevel.Warning
                    ? NLog.LogLevel.Warn
                    : level == SocksifierLogLevel.Debug || level == SocksifierLogLevel.All
                        ? NLog.LogLevel.Debug
                        : NLog.LogLevel.Info;

            foreach (var rule in configuration.LoggingRules)
                rule.SetLoggingLevels(minimum, NLog.LogLevel.Fatal);
            LogManager.ReconfigExistingLoggers();
        }

        private static void LogPrinter(object sender, LogEventArgs eventArgs)
        {
            foreach (var entry in eventArgs.Log.Where(entry => entry != null))
            {
                var message = (entry.Description ?? string.Empty)
                    .Replace("\r", string.Empty)
                    .Replace("\n", string.Empty);
                LoggerInstance.Log(GetNativeLogLevel(message), message);
            }
        }

        private static NLog.LogLevel GetNativeLogLevel(string message)
        {
            LogMessageLevel nativeLevel;
            if (!LogMessageLevelParser.TryGetLeadingNativeLevel(message, out nativeLevel))
                return NLog.LogLevel.Info;

            switch (nativeLevel)
            {
                case LogMessageLevel.Error: return NLog.LogLevel.Error;
                case LogMessageLevel.Warning: return NLog.LogLevel.Warn;
                case LogMessageLevel.Debug: return NLog.LogLevel.Debug;
                default: return NLog.LogLevel.Info;
            }
        }

        private sealed class SocksifierProxyEngine : IProxyEngineBoundary
        {
            private readonly Socksifier.Socksifier _engine;

            public SocksifierProxyEngine(Socksifier.Socksifier engine)
            {
                _engine = engine ?? throw new ArgumentNullException(nameof(engine));
            }

            public IntPtr AddSocks5Proxy(NativeProxyRuleSettings settings)
            {
                return _engine.AddSocks5Proxy(
                    settings.Endpoint,
                    settings.Username,
                    settings.Password,
                    MapProtocols(settings.Protocols),
                    MapAddressFamilies(settings.AddressFamilies),
                    MapTransport(settings.Transport),
                    settings.TlsServerName,
                    settings.TlsPinnedSha256,
                    settings.TlsAllowInvalidCertificate,
                    settings.Start);
            }

            public bool AssociateProcessNameToProxy(string processName, IntPtr handle)
            {
                return _engine.AssociateProcessNameToProxy(processName, handle);
            }

            public bool IncludeProcessDestinationCidr(string processName, string cidr)
            {
                return _engine.IncludeProcessDestinationCidr(processName, cidr);
            }

            public bool ExcludeProcessName(string processName)
            {
                return _engine.ExcludeProcessName(processName);
            }

            private static SupportedProtocolsEnum MapProtocols(ProxyProtocolSelection selection)
            {
                if (selection == ProxyProtocolSelection.Tcp)
                    return SupportedProtocolsEnum.TCP;
                if (selection == ProxyProtocolSelection.Udp)
                    return SupportedProtocolsEnum.UDP;
                return SupportedProtocolsEnum.BOTH;
            }

            private static SupportedAddressFamiliesEnum MapAddressFamilies(
                ProxyAddressFamilySelection selection)
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
        }
    }
}
