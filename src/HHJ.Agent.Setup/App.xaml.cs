using System.IO;
using System.Windows;
using HHJ.Agent.Setup.Engine.Engine;
using HHJ.Agent.Setup.ViewModels;
using HHJ.Agent.Setup.Windows;
using Microsoft.Extensions.Logging;

namespace HHJ.Agent.Setup;

public partial class App : Application
{
    private SetupLogSink? _logSink;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _logSink = new SetupLogSink(SetupOrchestrator.LogsDir);
        using var loggerFactory = LoggerFactory.Create(b => b.AddProvider(_logSink));

        var process = new WindowsProcessRunner();
        var fs = new PhysicalFileSystem();
        var reg = new WindowsRegistryReader();
        var svc = new WindowsServiceManager(process);
        var net = new WindowsNetworkProbe();
        var priv = new WindowsPrivilegeChecker();
        var dl = new HttpPackageDownloader();
        var verifier = new WinVerifyTrustAuthenticodeVerifier();
        var acls = new WindowsAclManager();

        var preCheck = new PreCheckEvaluator(priv, reg, fs, svc, net, process);
        var orchestrator = new SetupOrchestrator(process, fs, reg, svc, net, priv, dl, verifier, acls,
            loggerFactory.CreateLogger<SetupOrchestrator>());

        if (e.Args.Any(a => a.Equals("--disable", StringComparison.OrdinalIgnoreCase)))
        {
            await orchestrator.DisableRemoteAccessAsync(new DisableOptions(), CancellationToken.None);
            Shutdown(0);
            return;
        }

        if (e.Args.Any(a => a.Equals("--status", StringComparison.OrdinalIgnoreCase)))
        {
            var statusJson = await orchestrator.GetStatusJsonAsync(CancellationToken.None);
            var statusOut = Path.Combine(SetupOrchestrator.DataRoot, "status.json");
            Directory.CreateDirectory(SetupOrchestrator.DataRoot);
            await File.WriteAllTextAsync(statusOut, statusJson);
            Shutdown(0);
            return;
        }

        var vm = new SetupWizardViewModel(preCheck, orchestrator, priv, net, svc, _logSink);
        await vm.InitializeAsync();

        var window = new MainWindow(vm);
        MainWindow = window;
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _logSink?.Dispose();
        base.OnExit(e);
    }
}
