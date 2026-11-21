using System.IO;
using System.Text.Json;
using System.Windows;
using HHJ.RemoteManager.Core.Devices;
using HHJ.RemoteManager.Desktop.Dialogs;
using HHJ.RemoteManager.Desktop.ViewModels;
using Microsoft.Web.WebView2.Core;

namespace HHJ.RemoteManager.Desktop;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;
    private bool _webViewReady;

    public MainWindow(MainViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        DataContext = _vm;

        _vm.TerminalOutputReceived += OnTerminalOutputReceived;
        _vm.TerminalCleared += OnTerminalCleared;
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            await TerminalWebView.EnsureCoreWebView2Async();
            TerminalWebView.CoreWebView2.WebMessageReceived += OnWebMessageReceived;
            var htmlPath = Path.Combine(AppContext.BaseDirectory, "Assets", "terminal", "index.html");
            TerminalWebView.CoreWebView2.Navigate(new Uri(htmlPath).AbsoluteUri);
            _webViewReady = true;
        }
        catch
        {
            // WebView2 runtime may be absent in minimal environments; other tabs still work.
        }
    }

    private async void OnWebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        try
        {
            using var doc = JsonDocument.Parse(e.TryGetWebMessageAsString());
            var type = doc.RootElement.GetProperty("type").GetString();
            switch (type)
            {
                case "input":
                    var data = doc.RootElement.GetProperty("data").GetString();
                    if (!string.IsNullOrEmpty(data)) await _vm.SendTerminalInputAsync(data);
                    break;
                case "resize":
                case "ready":
                    var cols = doc.RootElement.GetProperty("cols").GetInt32();
                    var rows = doc.RootElement.GetProperty("rows").GetInt32();
                    _vm.ResizeTerminal(cols, rows);
                    break;
            }
        }
        catch { /* Ignore malformed message */ }
    }

    private void OnTerminalOutputReceived(byte[] bytes)
    {
        if (!_webViewReady) return;
        var b64 = Convert.ToBase64String(bytes);
        Dispatcher.BeginInvoke(async () =>
        {
            if (TerminalWebView.CoreWebView2 is not null)
                await TerminalWebView.CoreWebView2.ExecuteScriptAsync($"window.hhjTerminal.writeBase64('{b64}')");
        });
    }

    private void OnTerminalCleared()
    {
        if (!_webViewReady) return;
        Dispatcher.BeginInvoke(async () =>
        {
            if (TerminalWebView.CoreWebView2 is not null)
                await TerminalWebView.CoreWebView2.ExecuteScriptAsync("window.hhjTerminal.clear()");
        });
    }

    private async void OnAddDeviceClick(object sender, RoutedEventArgs e)
    {
        var dlg = new DeviceEditorDialog(new DeviceProfile(), _vm.SshKeys) { Owner = this };
        if (dlg.ShowDialog() == true)
        {
            _vm.Devices.Add(dlg.ResultProfile);
            _vm.SelectedDevice = dlg.ResultProfile;
            await _vm.SaveDevicesAsync();
        }
    }

    private async void OnEditDeviceClick(object sender, RoutedEventArgs e)
    {
        if (_vm.SelectedDevice is null) return;
        var idx = _vm.Devices.IndexOf(_vm.SelectedDevice);
        var dlg = new DeviceEditorDialog(_vm.SelectedDevice, _vm.SshKeys) { Owner = this };
        if (dlg.ShowDialog() == true && idx >= 0)
        {
            _vm.Devices[idx] = dlg.ResultProfile;
            _vm.SelectedDevice = dlg.ResultProfile;
            await _vm.SaveDevicesAsync();
        }
    }
}
