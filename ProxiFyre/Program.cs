using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Windows.Forms;
using ProxiFyre.Configuration;
using Topshelf;

namespace ProxiFyre
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            var service = new ProxiFyreService();
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
        }
    }

    /// <summary>
    /// Keeps the installer/service command path available while sharing the
    /// exact same ProxiFyreService bootstrap as the UI.
    /// </summary>
    internal static class ServiceProgram
    {
        private static bool IsElevated()
        {
            try
            {
                using (var identity = WindowsIdentity.GetCurrent())
                    return new WindowsPrincipal(identity)
                        .IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static int Run(string[] args)
        {
            args = args ?? Array.Empty<string>();
            if (!IsElevated())
                return 5;

            try
            {
                NativeDependencyLoader.Initialize();
                return (int)HostFactory.Run(configuration =>
                {
                    configuration.Service<ProxiFyreService>(service =>
                    {
                        service.ConstructUsing(name => new ProxiFyreService());
                        service.WhenStarted(instance => instance.Start());
                        service.WhenStopped(instance => instance.Stop());
                    });
                    configuration.RunAsLocalSystem();
                    configuration.SetDescription("ProxiFyre - SOCKS5 ProxiFyre Service");
                    configuration.SetDisplayName("ProxiFyre Service");
                    configuration.SetServiceName(ProxiFyrePaths.ServiceName);
                    configuration.DependsOn(ProxiFyrePaths.WindowsPacketFilterServiceName);
                });
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine(exception.Message);
                return 1;
            }
        }
    }
}
