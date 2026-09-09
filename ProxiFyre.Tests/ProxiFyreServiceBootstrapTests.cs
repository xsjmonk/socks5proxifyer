using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using NUnit.Framework;
using ProxiFyre.Configuration;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class ProxiFyreServiceBootstrapTests
    {
        private static string RepositoryRoot
        {
            get
            {
                var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
                while (directory != null &&
                       !File.Exists(Path.Combine(directory.FullName, "socksify.sln")))
                    directory = directory.Parent;
                return directory == null ? null : directory.FullName;
            }
        }

        [Test]
        public void ServiceImplementationIsCompiledExactlyOnce()
        {
            var root = RepositoryRoot;
            Assert.That(root, Is.Not.Null);

            var project = File.ReadAllText(Path.Combine(root, "ProxiFyre", "ProxiFyre.csproj"));
            Assert.That(project.Split(new[] { "Compile Include=\"ProxiFyreService.cs\"" },
                StringSplitOptions.None).Length - 1, Is.EqualTo(1));

            var definitions = Directory.GetFiles(Path.Combine(root, "ProxiFyre"), "*.cs")
                .Select(File.ReadAllText)
                .Sum(text => Regex.Matches(
                    text, @"\bclass\s+ProxiFyreService\b").Count);
            Assert.That(definitions, Is.EqualTo(1));
        }

        [Test]
        public void BootstrapUsesCanonicalConfigurationAndFullRegistrationContract()
        {
            var root = RepositoryRoot;
            var service = File.ReadAllText(
                Path.Combine(root, "ProxiFyre", "ProxiFyreService.cs"));

            StringAssert.Contains("ConfigurationSerializer", service);
            StringAssert.Contains("ConfigurationValidator", service);
            StringAssert.Contains("ConfigurationNormalizer", service);
            var coordinator = File.ReadAllText(Path.Combine(
                root, "ProxiFyre.Configuration", "ProxyRuleRegistration.cs"));
            StringAssert.Contains("rule.EffectiveTlsServerName", coordinator);
            StringAssert.Contains("rule.TlsPinnedSha256", coordinator);
            StringAssert.Contains("rule.TlsAllowInvalidCertificate", coordinator);
            StringAssert.Contains("Start = true", coordinator);
            StringAssert.Contains("handle == IntPtr.Zero", coordinator);
            StringAssert.Contains("handle.ToInt64() == -1", coordinator);
            StringAssert.Contains("!registration.AllRequiredRulesRegistered", service);
            StringAssert.Contains("router was not started", service);
        }

        [Test]
        public void UiAndTopshelfBothReferenceTheSameServiceType()
        {
            var root = RepositoryRoot;
            var program = File.ReadAllText(Path.Combine(root, "ProxiFyre", "Program.cs"));

            StringAssert.Contains("new ProxiFyreService()", program);
            StringAssert.Contains("Service<ProxiFyreService>", program);
            StringAssert.Contains("new MainForm(service)", program);
        }

        [Test]
        public void SharedModelRetainsConfiguredDestinationRanges()
        {
            var root = RepositoryRoot;
            var models = File.ReadAllText(Path.Combine(
                root, "ProxiFyre.Configuration", "Models.cs"));
            StringAssert.Contains("[JsonProperty(\"ipRanges\"", models);
            StringAssert.Contains("List<string> IpRanges", models);
        }

        [Test]
        public void RegistrationCoordinatorPreservesNormalizedRuleAndValidatesCredentials()
        {
            var rule = new ProxyRule
            {
                Socks5ProxyEndpoint = " 127.0.0.1:1080 ",
                SupportedProtocols = new List<string> { "TCP" },
                SupportedAddressFamilies = new List<string> { "IPv4" },
                AppNames = new List<string> { "rdcman" },
                IpRanges = new List<string> { "192.168.100.0/24" }
            };
            var fake = new FakeProxyEngine(new IntPtr(1));
            NativeProxyRuleSettings captured = null;

            new ProxyRuleRegistrationCoordinator().Register(
                new List<ProxyRule> { rule }, fake,
                (index, settings) => captured = settings, null, null);

            Assert.That(captured.Endpoint, Is.EqualTo("127.0.0.1:1080"));
            Assert.That(captured.Protocols, Is.EqualTo(ProxyProtocolSelection.Tcp));
            Assert.That(captured.AddressFamilies, Is.EqualTo(ProxyAddressFamilySelection.Ipv4));
            Assert.That(captured.Transport, Is.EqualTo(Socks5TransportKind.Tcp));
            Assert.That(captured.Start, Is.True);
            Assert.That(fake.AssociationCount, Is.EqualTo(1));
            Assert.That(fake.CidrCount, Is.EqualTo(1));
        }

        [Test]
        public void AppConfigDestinationRangesSurviveNormalizationAndRegisterPerApplication()
        {
            var json = "{\"proxies\":[" +
                "{\"appNames\":[\"idea64\",\"rider64\"],\"socks5ProxyEndpoint\":\"127.0.0.1:1080\",\"ipRanges\":[\"192.168.100.0/24\"]}," +
                "{\"appNames\":[\"rdcman\",\"mstsc\"],\"socks5ProxyEndpoint\":\"127.0.0.1:1081\",\"ipRanges\":[\"192.168.100.0/24\"]}]}";
            var configuration = new ConfigurationSerializer().Deserialize(json);
            Assert.That(new ConfigurationValidator().Validate(configuration).IsValid, Is.True);
            var normalized = new ConfigurationNormalizer().Normalize(configuration);
            var fake = new FakeProxyEngine(new IntPtr(1));

            new ProxyRuleRegistrationCoordinator().Register(
                normalized.Proxies, fake, null, null, null);

            Assert.That(fake.CidrCount, Is.EqualTo(4));
            CollectionAssert.AreEqual(
                new[] { "idea64", "rider64", "rdcman", "mstsc" },
                fake.CidrProcesses);
            CollectionAssert.AreEqual(
                new[] { "192.168.100.0/24", "192.168.100.0/24", "192.168.100.0/24", "192.168.100.0/24" },
                fake.CidrValues);
        }

        [Test]
        public void RuleWithoutDestinationRangesProducesNoCidrCalls()
        {
            var fake = new FakeProxyEngine(new IntPtr(1));
            new ProxyRuleRegistrationCoordinator().Register(
                new List<ProxyRule> {
                    new ProxyRule {
                        Socks5ProxyEndpoint = "127.0.0.1:1080",
                        AppNames = new List<string> { "mstsc" }
                    }
                }, fake, null, null, null);

            Assert.That(fake.CidrCount, Is.EqualTo(0));
        }

        [Test]
        public void RegistrationCoordinatorDoesNotUseInvalidHandlesOrPartialCredentials()
        {
            var partial = new ProxyRule
            {
                Socks5ProxyEndpoint = "127.0.0.1:1080",
                Username = "user",
                AppNames = new List<string> { "rdcman" }
            };
            var fake = new FakeProxyEngine(new IntPtr(1));
            var warnings = 0;

            new ProxyRuleRegistrationCoordinator().Register(
                new List<ProxyRule> { partial }, fake, null,
                (index, message) => warnings++, null);

            Assert.That(fake.AddCount, Is.EqualTo(0));
            Assert.That(fake.AssociationCount, Is.EqualTo(0));
            Assert.That(warnings, Is.EqualTo(1));

            var failed = new FakeProxyEngine(new IntPtr(-1));
            new ProxyRuleRegistrationCoordinator().Register(
                new List<ProxyRule> { new ProxyRule {
                    Socks5ProxyEndpoint = "127.0.0.1:1080",
                    AppNames = new List<string> { "rdcman" }
                } }, failed, null, null, null);
            Assert.That(failed.AssociationCount, Is.EqualTo(0));
        }

        [Test]
        public void RequiredFailureIsReportedAndLaterRulesDoNotMaskIt()
        {
            var rules = new List<ProxyRule>
            {
                new ProxyRule {
                    Socks5ProxyEndpoint = "127.0.0.1:1080",
                    AppNames = new List<string> { "rdcman" }
                },
                new ProxyRule {
                    Socks5ProxyEndpoint = "192.168.250.3:1080",
                    AppNames = new List<string> { "mstsc" }
                }
            };
            var fake = new SequenceProxyEngine(new[] { new IntPtr(-1), new IntPtr(1) });

            var result = new ProxyRuleRegistrationCoordinator().Register(
                rules, fake, null, null, null);

            Assert.That(result.AllRequiredRulesRegistered, Is.False);
            Assert.That(result.Failures.Count, Is.EqualTo(1));
            Assert.That(result.Failures[0].RuleIndex, Is.EqualTo(0));
            Assert.That(result.Failures[0].Endpoint, Is.EqualTo("127.0.0.1:1080"));
            Assert.That(result.Failures[0].Category,
                Is.EqualTo(NativeFailureCategory.NativeProxyCreation));
            Assert.That(fake.Endpoints, Is.EqualTo(new[] {
                "127.0.0.1:1080", "192.168.250.3:1080" }));
            Assert.That(fake.AssociationCount, Is.EqualTo(1));
        }

        [Test]
        public void NativeBoundaryEncodesZeroBasedIndexZeroAsNonzeroHandle()
        {
            var root = RepositoryRoot;
            var native = File.ReadAllText(Path.Combine(
                root, "socksify", "socksify_unmanaged.cpp"));
            StringAssert.Contains("result.value()) + 1", native);
            StringAssert.Contains("proxy_id - 1", native);
        }

        [Test]
        public void DiagnosticsContainIdentityButNeverCredentialValues()
        {
            var root = RepositoryRoot;
            var service = File.ReadAllText(Path.Combine(
                root, "ProxiFyre", "ProxiFyreService.cs"));
            var identity = File.ReadAllText(Path.Combine(
                root, "ProxiFyre", "ArtifactIdentity.cs"));
            var coordinator = File.ReadAllText(Path.Combine(
                root, "ProxiFyre.Configuration", "ProxyRuleRegistration.cs"));

            StringAssert.Contains("ArtifactIdentity.Log", service);
            StringAssert.Contains("configurationSha256", identity);
            StringAssert.Contains("UsernameLength", coordinator);
            StringAssert.Contains("PasswordLength", coordinator);

            var messages = new List<string>();
            new ProxyRuleRegistrationCoordinator().Register(
                new List<ProxyRule> { new ProxyRule {
                    Socks5ProxyEndpoint = "127.0.0.1:1080",
                    Username = "user-secret",
                    Password = "password-secret",
                    AppNames = new List<string> { "rdcman" }
                } },
                new FakeProxyEngine(new IntPtr(1)),
                null, (index, message) => messages.Add(message),
                (index, message) => messages.Add(message));
            Assert.That(messages.Any(message => message.Contains("secret")),
                Is.False);
        }

        [Test]
        public void LauncherRequiresExplicitDeploymentAndConfigurationPaths()
        {
            var root = RepositoryRoot;
            var launcher = File.ReadAllText(Path.Combine(
                root, "scripts", "Launch-ProxiFyreArtifact.ps1"));
            StringAssert.Contains("[Parameter(Mandatory = $true)]", launcher);
            StringAssert.Contains("[string]$DeploymentDirectory", launcher);
            StringAssert.Contains("[string]$ConfigurationPath", launcher);
            StringAssert.Contains("UiSelectedEnginePath", launcher);
            StringAssert.DoesNotContain("Build\\exe", launcher);
        }

        private sealed class FakeProxyEngine : IProxyEngineBoundary
        {
            private readonly IntPtr _result;
            public int AddCount { get; private set; }
            public int AssociationCount { get; private set; }
            public int CidrCount { get; private set; }
            public readonly List<string> CidrProcesses = new List<string>();
            public readonly List<string> CidrValues = new List<string>();

            public FakeProxyEngine(IntPtr result) { _result = result; }

            public IntPtr AddSocks5Proxy(NativeProxyRuleSettings settings)
            {
                AddCount++;
                return _result;
            }

            public bool AssociateProcessNameToProxy(string processName, IntPtr handle)
            {
                AssociationCount++;
                return true;
            }

            public bool IncludeProcessDestinationCidr(string processName, string cidr)
            {
                CidrCount++;
                CidrProcesses.Add(processName);
                CidrValues.Add(cidr);
                return true;
            }

            public bool ExcludeProcessName(string processName) { return true; }
        }

        private sealed class SequenceProxyEngine : IProxyEngineBoundary
        {
            private readonly IntPtr[] _results;
            private int _position;
            public readonly List<string> Endpoints = new List<string>();
            public int AssociationCount { get; private set; }

            public SequenceProxyEngine(IntPtr[] results) { _results = results; }

            public IntPtr AddSocks5Proxy(NativeProxyRuleSettings settings)
            {
                Endpoints.Add(settings.Endpoint);
                return _results[_position++];
            }

            public bool AssociateProcessNameToProxy(string processName, IntPtr handle)
            {
                AssociationCount++;
                return true;
            }

            public bool IncludeProcessDestinationCidr(string processName, string cidr)
            {
                return true;
            }

            public bool ExcludeProcessName(string processName) { return true; }
        }
    }
}
