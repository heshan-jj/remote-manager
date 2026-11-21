using System.Windows;
using HHJ.RemoteManager.Desktop.ViewModels;
using HHJ.RemoteManager.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace HHJ.RemoteManager.Desktop;

public partial class App : Application
{
    private ServiceProvider? _services;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var collection = new ServiceCollection();
        collection.AddRemoteManagerInfrastructure();
        collection.AddSingleton<MainViewModel>();
        collection.AddSingleton<MainWindow>();

        _services = collection.BuildServiceProvider();

        var vm = _services.GetRequiredService<MainViewModel>();
        await vm.InitializeAsync();

        var window = _services.GetRequiredService<MainWindow>();
        MainWindow = window;
        window.Show();
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        if (_services is not null)
        {
            await _services.DisposeAsync();
        }
        base.OnExit(e);
    }
}
