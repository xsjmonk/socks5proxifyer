using System;
using System.Linq;
using NUnit.Framework;
using ProxiFyre.Configuration;

namespace ProxiFyre.Tests
{
    [TestFixture]
    public sealed class UiLogBufferTests
    {
        [Test]
        public void DefaultLimitRetainsRepresentativeStartup()
        {
            var buffer = new UiLogBuffer();
            var startup = string.Join(Environment.NewLine, new[]
            {
                "UI started. BaseDir = C:\\ProxiFyre",
                "Starting ProxiFyre service...",
                "Proxy rule 1: endpoint=127.0.0.1:1080",
                "Associated rdcman with 127.0.0.1:1080.",
                "Associated mstsc with 127.0.0.1:1080.",
                "Added CIDR 192.168.100.0/24 for process rdcman.",
                "Proxy rule 2: endpoint=192.168.250.3:1080",
                "Associated rdcman with 192.168.250.3:1080.",
                "Associated mstsc with 192.168.250.3:1080.",
                "Added CIDR 192.168.100.0/24 for process mstsc.",
                "SOCKS5 Local Router instance started successfully."
            });

            buffer.Append(startup);

            StringAssert.Contains("SOCKS5 Local Router instance started successfully.", buffer.Text);
            Assert.That(buffer.WasTrimmed, Is.False);
        }

        [Test]
        public void TrimmingPreservesLineBoundariesAndOrder()
        {
            var buffer = new UiLogBuffer(256);
            for (var index = 0; index < 80; index++)
                buffer.Append("line-" + index.ToString("D2"));

            Assert.That(buffer.WasTrimmed, Is.True);
            Assert.That(buffer.Text.Length, Is.LessThanOrEqualTo(256));
            Assert.That(buffer.Text.Split(new[] { Environment.NewLine },
                StringSplitOptions.RemoveEmptyEntries).All(line => line.StartsWith("line-")),
                Is.True);
            StringAssert.Contains("line-79", buffer.Text);
        }

        [Test]
        public void OversizedMessageKeepsNewestBoundedPortion()
        {
            var buffer = new UiLogBuffer(256);
            var message = new string('x', 1000);

            buffer.Append(message);

            Assert.That(buffer.WasTrimmed, Is.True);
            Assert.That(buffer.Text.Length, Is.EqualTo(256));
            StringAssert.EndsWith(new string('x', 256 - Environment.NewLine.Length) +
                Environment.NewLine, buffer.Text);
        }

        [Test]
        public void AppendsRemainOrderedAndSeparateFromFileRetention()
        {
            var buffer = new UiLogBuffer(512);
            var fullHistory = string.Empty;
            for (var index = 0; index < 40; index++)
            {
                var line = "ordered-" + index;
                fullHistory += line + Environment.NewLine;
                buffer.Append(line);
            }

            Assert.That(fullHistory, Does.Contain("ordered-0"));
            StringAssert.Contains("ordered-39", buffer.Text);
            Assert.That(buffer.Text.IndexOf("ordered-38", StringComparison.Ordinal),
                Is.LessThan(buffer.Text.IndexOf("ordered-39", StringComparison.Ordinal)));
        }
    }
}
