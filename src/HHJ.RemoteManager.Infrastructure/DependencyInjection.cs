using System.Runtime.Versioning;
using HHJ.RemoteManager.Core.Security;
using HHJ.RemoteManager.Core.Ssh;
using HHJ.RemoteManager.Infrastructure.Diagnostics;
using HHJ.RemoteManager.Infrastructure.Logging;
using HHJ.RemoteManager.Infrastructure.Persistence;
using HHJ.RemoteManager.Infrastructure.Security;
using HHJ.RemoteManager.Infrastructure.Ssh;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace HHJ.RemoteManager.Infrastructure;

public static class ServiceCollectionExtensions
{
    public static string GetDefaultDataDirectory() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HHJ", "RemoteManager");

    [SupportedOSPlatform("windows")]
    public static IServiceCollection AddRemoteManagerInfrastructure(this IServiceCollection services, string? dataDirectory = null)
    {
        var dir = dataDirectory ?? GetDefaultDataDirectory();
        var logSink = new AppLogSink(Path.Combine(dir, "logs"));

        services.AddSingleton(logSink);
        services.AddLogging(b =>
        {
            b.SetMinimumLevel(LogLevel.Information);
            b.AddProvider(logSink);
        });

        services.AddSingleton<ISecretProtector, DpapiSecretProtector>();
        services.AddSingleton<ICredentialStore, WindowsCredentialStore>();
        services.AddSingleton<IDeviceRepository>(_ => new JsonDeviceRepository(Path.Combine(dir, "devices.json")));
        services.AddSingleton<ISshKeyStore>(sp => new JsonSshKeyStore(
            dir,
            sp.GetRequiredService<ISecretProtector>(),
            sp.GetRequiredService<ICredentialStore>()));
        services.AddSingleton<ISshSessionFactory, SshNetSessionFactory>();
        services.AddSingleton<ConnectionDiagnosticsService>();

        return services;
    }
}
