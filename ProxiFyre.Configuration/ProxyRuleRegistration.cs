using System;
using System.Collections.Generic;

namespace ProxiFyre.Configuration
{
    public enum NativeFailureCategory
    {
        InvalidCredentials,
        NativeProxyCreation
    }

    public sealed class ProxyRegistrationFailure
    {
        public int RuleIndex { get; set; }
        public string Endpoint { get; set; }
        public NativeFailureCategory Category { get; set; }
    }

    public sealed class ProxyRegistrationResult
    {
        public IList<ProxyRegistrationFailure> Failures { get; } =
            new List<ProxyRegistrationFailure>();

        public bool AllRequiredRulesRegistered
        {
            get { return Failures.Count == 0; }
        }
    }

    /// <summary>
    /// The normalized, secret-safe input passed from configuration to the
    /// managed/native proxy boundary.
    /// </summary>
    public sealed class NativeProxyRuleSettings
    {
        public string Endpoint { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public ProxyProtocolSelection Protocols { get; set; }
        public ProxyAddressFamilySelection AddressFamilies { get; set; }
        public Socks5TransportKind Transport { get; set; }
        public string TlsServerName { get; set; }
        public string TlsPinnedSha256 { get; set; }
        public bool TlsAllowInvalidCertificate { get; set; }
        public bool Start { get; set; }
        public int UsernameLength { get; set; }
        public int PasswordLength { get; set; }
    }

    public interface IProxyEngineBoundary
    {
        IntPtr AddSocks5Proxy(NativeProxyRuleSettings settings);
        bool AssociateProcessNameToProxy(string processName, IntPtr handle);
        bool IncludeProcessDestinationCidr(string processName, string cidr);
        bool ExcludeProcessName(string processName);
    }

    /// <summary>
    /// Maps ordered configuration rules and applies them through an injectable
    /// engine boundary. It deliberately does not own native loading or UI.
    /// </summary>
    public sealed class ProxyRuleRegistrationCoordinator
    {
        public ProxyRegistrationResult Register(
            IList<ProxyRule> rules,
            IProxyEngineBoundary engine,
            Action<int, NativeProxyRuleSettings> beforeAdd,
            Action<int, string> warning,
            Action<int, string> information)
        {
            if (engine == null)
                throw new ArgumentNullException(nameof(engine));

            var result = new ProxyRegistrationResult();
            if (rules == null)
                return result;

            for (var index = 0; index < rules.Count; index++)
            {
                var rule = rules[index] ?? new ProxyRule();
                var settings = CreateSettings(rule);
                beforeAdd?.Invoke(index, settings);

                if (settings.UsernameLength != settings.PasswordLength &&
                    (settings.UsernameLength != 0 || settings.PasswordLength != 0))
                {
                    result.Failures.Add(new ProxyRegistrationFailure
                    {
                        RuleIndex = index,
                        Endpoint = settings.Endpoint,
                        Category = NativeFailureCategory.InvalidCredentials
                    });
                    warning?.Invoke(index, "credentials are partial; native registration was skipped");
                    continue;
                }

                var handle = engine.AddSocks5Proxy(settings);
                if (handle == IntPtr.Zero || handle.ToInt64() == -1)
                {
                    result.Failures.Add(new ProxyRegistrationFailure
                    {
                        RuleIndex = index,
                        Endpoint = settings.Endpoint,
                        Category = NativeFailureCategory.NativeProxyCreation
                    });
                    warning?.Invoke(index, "native proxy creation failed; associations were skipped");
                    continue;
                }

                foreach (var appName in rule.AppNames ?? new List<string>())
                {
                    if (engine.AssociateProcessNameToProxy(appName, handle))
                        information?.Invoke(index, "associated " + appName);

                    foreach (var cidr in rule.IpRanges ?? new List<string>())
                    {
                        if (engine.IncludeProcessDestinationCidr(appName, cidr))
                            information?.Invoke(index, "added CIDR " + cidr + " for " + appName);
                        else
                            warning?.Invoke(
                                index,
                                "rule " + (index + 1) + " rejected CIDR " + cidr + " for process " + appName);
                    }
                }
            }

            return result;
        }

        private static NativeProxyRuleSettings CreateSettings(ProxyRule rule)
        {
            var username = rule.Username ?? string.Empty;
            var password = rule.Password ?? string.Empty;
            return new NativeProxyRuleSettings
            {
                Endpoint = (rule.Socks5ProxyEndpoint ?? string.Empty).Trim(),
                Username = username,
                Password = password,
                UsernameLength = username.Length,
                PasswordLength = password.Length,
                Protocols = ConfigurationValueParser.GetProtocols(rule.SupportedProtocols),
                AddressFamilies =
                    ConfigurationValueParser.GetAddressFamilies(rule.SupportedAddressFamilies),
                Transport = ConfigurationValueParser.GetTransport(rule.Socks5Transport),
                TlsServerName = rule.EffectiveTlsServerName,
                TlsPinnedSha256 = ConfigurationNormalizer.NormalizeFingerprint(rule.TlsPinnedSha256),
                TlsAllowInvalidCertificate = rule.TlsAllowInvalidCertificate,
                Start = true
            };
        }
    }
}
