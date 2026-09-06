using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using NLog;

namespace ProxiFyre
{
    internal static class ArtifactIdentity
    {
        public static void Log(Logger logger, string configurationPath)
        {
            var executable = Assembly.GetExecutingAssembly();
            LogAssembly(logger, "ProxiFyre", executable);
            LogAssembly(logger, "ProxiFyre.Configuration", typeof(ProxiFyre.Configuration.ProxiFyreConfiguration).Assembly);
            LogAssembly(logger, "Socksifier", typeof(Socksifier.Socksifier).Assembly);

            logger.Info(
                "Artifact runtime: baseDirectory={0}, processArchitecture={1}, configurationPath={2}, configurationTimestampUtc={3}, configurationSha256={4}.",
                AppDomain.CurrentDomain.BaseDirectory,
                Environment.Is64BitProcess ? "x64" : "x86",
                configurationPath,
                File.Exists(configurationPath) ? File.GetLastWriteTimeUtc(configurationPath).ToString("O") : "missing",
                File.Exists(configurationPath) ? Sha256(configurationPath) : "missing");
        }

        private static void LogAssembly(Logger logger, string name, Assembly assembly)
        {
            var location = assembly.Location;
            var info = File.Exists(location) ? FileVersionInfo.GetVersionInfo(location) : null;
            var version = assembly.GetCustomAttributes(typeof(AssemblyInformationalVersionAttribute), false)
                .OfType<AssemblyInformationalVersionAttribute>()
                .Select(attribute => attribute.InformationalVersion)
                .FirstOrDefault() ?? assembly.GetName().Version?.ToString() ?? "unknown";

            logger.Info(
                "Artifact {0}: path={1}, informationalVersion={2}, fileVersion={3}, timestampUtc={4}, sha256={5}.",
                name,
                location,
                version,
                info?.FileVersion ?? "unknown",
                File.Exists(location) ? File.GetLastWriteTimeUtc(location).ToString("O") : "missing",
                File.Exists(location) ? Sha256(location) : "missing");
        }

        private static string Sha256(string path)
        {
            using (var stream = File.OpenRead(path))
            using (var sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(stream))
                    .Replace("-", string.Empty)
                    .ToLowerInvariant();
        }
    }
}
