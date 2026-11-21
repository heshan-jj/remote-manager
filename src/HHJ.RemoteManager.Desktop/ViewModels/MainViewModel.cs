using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HHJ.RemoteManager.Core.Connections;
using HHJ.RemoteManager.Core.Devices;
using HHJ.RemoteManager.Core.Remote;
using HHJ.RemoteManager.Core.Security;
using HHJ.RemoteManager.Core.Ssh;
using HHJ.RemoteManager.Core.Telemetry;
using HHJ.RemoteManager.Infrastructure.Diagnostics;
using HHJ.RemoteManager.Infrastructure.Logging;
using HHJ.Shared.Contracts.Telemetry;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SkiaSharp;

namespace HHJ.RemoteManager.Desktop.ViewModels;

public sealed partial class MainViewModel : ObservableObject, IAsyncDisposable
{
    private const int HistoryCapacity = 60;

    private readonly IDeviceRepository _devicesRepo;
    private readonly ISshKeyStore _keyStore;
    private readonly ISshSessionFactory _sshFactory;
    private readonly ConnectionDiagnosticsService _diagnostics;
    private readonly AppLogSink _logSink;
    private readonly ILogger<MainViewModel> _logger;

    private readonly ConnectionStateMachine _stateMachine = new();
    private readonly ProcessCpuTracker _processTracker = new();
    private readonly MetricHistory _cpuHistory = new(HistoryCapacity);
    private readonly MetricHistory _ramHistory = new(HistoryCapacity);

    private readonly ObservableCollection<ObservableValue> _cpuPoints = [];
    private readonly ObservableCollection<ObservableValue> _ramPoints = [];
    private readonly ObservableCollection<ObservableValue> _netRxPoints = [];
    private readonly ObservableCollection<ObservableValue> _netTxPoints = [];

    private ISshSession? _session;
    private RemoteEndpointClient? _client;
    private TelemetryPoller? _poller;
    private IShellChannel? _shellChannel;
    private CancellationTokenSource? _connectCts;
    private List<ProcessInfo> _allProcesses = [];
    private List<ServiceDto> _allServices = [];

    public MainViewModel(
        IDeviceRepository devicesRepo,
        ISshKeyStore keyStore,
        ISshSessionFactory sshFactory,
        ConnectionDiagnosticsService diagnostics,
        AppLogSink logSink,
        ILogger<MainViewModel> logger)
    {
        _devicesRepo = devicesRepo;
        _keyStore = keyStore;
        _sshFactory = sshFactory;
        _diagnostics = diagnostics;
        _logSink = logSink;
        _logger = logger;

        _stateMachine.StateChanged += (_, e) =>
            RunOnUi(() =>
            {
                ConnectionState = e.To;
                ConnectionErrorMessage = e.Failure?.Message;
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(ConnectionStateDisplay));
            });

        CpuSeries =
        [
            new LineSeries<ObservableValue>
            {
                Values = _cpuPoints,
                Name = "CPU %",
                Stroke = new SolidColorPaint(SKColor.Parse("#3B82F6"), 2),
                Fill = new SolidColorPaint(SKColor.Parse("#223B82F6")),
                GeometrySize = 0,
            }
        ];

        RamSeries =
        [
            new LineSeries<ObservableValue>
            {
                Values = _ramPoints,
                Name = "RAM %",
                Stroke = new SolidColorPaint(SKColor.Parse("#10B981"), 2),
                Fill = new SolidColorPaint(SKColor.Parse("#2210B981")),
                GeometrySize = 0,
            }
        ];

        NetworkSeries =
        [
            new LineSeries<ObservableValue>
            {
                Values = _netRxPoints,
                Name = "RX KB/s",
                Stroke = new SolidColorPaint(SKColor.Parse("#8B5CF6"), 2),
                Fill = null,
                GeometrySize = 0,
            },
            new LineSeries<ObservableValue>
            {
                Values = _netTxPoints,
                Name = "TX KB/s",
                Stroke = new SolidColorPaint(SKColor.Parse("#F59E0B"), 2),
                Fill = null,
                GeometrySize = 0,
            }
        ];

        foreach (var entry in _logSink.GetRecent()) LogEntries.Add(FormatLogEntry(entry));
        _logSink.EntryAdded += (_, entry) => RunOnUi(() =>
        {
            LogEntries.Add(FormatLogEntry(entry));
            if (LogEntries.Count > 500) LogEntries.RemoveAt(0);
        });
    }

    public event Action<byte[]>? TerminalOutputReceived;
    public event Action? TerminalCleared;

    // Navigation: 0=Dashboard, 1=Devices, 2=Processes, 3=Services, 4=Terminal, 5=Actions, 6=Logs, 7=Settings
    [ObservableProperty] private int _selectedTabIndex;

    public ObservableCollection<DeviceProfile> Devices { get; } = [];
    public ObservableCollection<SshKeyInfo> SshKeys { get; } = [];
    public ObservableCollection<DiskUsage> Disks { get; } = [];
    public ObservableCollection<NetworkAdapterDto> Adapters { get; } = [];
    public ObservableCollection<ProcessInfo> FilteredProcesses { get; } = [];
    public ObservableCollection<ServiceDto> FilteredServices { get; } = [];
    public ObservableCollection<EventLogEntryDto> EventLogs { get; } = [];
    public ObservableCollection<InstalledSoftwareDto> InstalledSoftware { get; } = [];
    public ObservableCollection<DiagnosticStep> DiagnosticSteps { get; } = [];
    public ObservableCollection<string> LogEntries { get; } = [];

    public ISeries[] CpuSeries { get; }
    public ISeries[] RamSeries { get; }
    public ISeries[] NetworkSeries { get; }
    public Axis[] PercentYAxes { get; } = [new Axis { MinLimit = 0, MaxLimit = 100 }];
    public Axis[] HiddenXAxes { get; } = [new Axis { IsVisible = false }];

    [ObservableProperty] private DeviceProfile? _selectedDevice;
    [ObservableProperty] private ConnectionState _connectionState = ConnectionState.Disconnected;
    [ObservableProperty] private string? _connectionErrorMessage;
    [ObservableProperty] private string? _bannerNotice;

    public bool IsConnected => ConnectionState == ConnectionState.Connected;
    public string ConnectionStateDisplay => ConnectionState.ToString();

    // Live Telemetry
    [ObservableProperty] private string _cpuDisplay = "—";
    [ObservableProperty] private string _ramDisplay = "—";
    [ObservableProperty] private string _networkDisplay = "—";
    [ObservableProperty] private string _latencyDisplay = "—";
    [ObservableProperty] private string _uptimeDisplay = "—";
    [ObservableProperty] private string _lastUpdatedDisplay = "—";

    // System Info
    [ObservableProperty] private string _sysComputerName = "—";
    [ObservableProperty] private string _sysOs = "—";
    [ObservableProperty] private string _sysCpu = "—";
    [ObservableProperty] private string _sysRam = "—";
    [ObservableProperty] private string _sysSshd = "—";
    [ObservableProperty] private string _sysUser = "—";

    // Polling settings
    public int[] AvailableIntervals => TelemetryPoller.SupportedIntervalsSeconds;
    [ObservableProperty] private int _pollIntervalSeconds = 5;
    [ObservableProperty] private bool _isPollingPaused;

    partial void OnPollIntervalSecondsChanged(int value)
    {
        if (_poller is not null) _poller.IntervalSeconds = value;
    }

    partial void OnIsPollingPausedChanged(bool value)
    {
        if (_poller is not null) _poller.IsPaused = value;
    }

    // Processes & Services filtering
    [ObservableProperty] private string _processFilter = "";
    [ObservableProperty] private ProcessInfo? _selectedProcess;
    [ObservableProperty] private string _serviceFilter = "";
    [ObservableProperty] private ServiceDto? _selectedService;

    partial void OnProcessFilterChanged(string value) => ApplyProcessFilter();
    partial void OnServiceFilterChanged(string value) => ApplyServiceFilter();

    // Terminal state
    [ObservableProperty] private bool _isTerminalOpen;
    private int _termCols = 100;
    private int _termRows = 30;

    // Key generation UI
    [ObservableProperty] private string _newKeyName = "my-admin-key";
    [ObservableProperty] private string _logFilePath = "";

    public async Task InitializeAsync()
    {
        LogFilePath = _logSink.LogFilePath;
        var keys = await _keyStore.ListAsync();
        foreach (var k in keys) SshKeys.Add(k);

        var devs = await _devicesRepo.LoadAsync();
        foreach (var d in devs) Devices.Add(d);
        SelectedDevice = Devices.FirstOrDefault();
    }

    // --- Device & Key Management ---

    [RelayCommand]
    private async Task GenerateSshKeyAsync()
    {
        var name = string.IsNullOrWhiteSpace(NewKeyName) ? "hhj-admin-key" : NewKeyName.Trim();
        var key = await _keyStore.GenerateAsync(name);
        SshKeys.Add(key);
        BannerNotice = $"Generated key '{key.Name}' (SHA256:{key.FingerprintSha256}). Copy its public key to HHJ Agent Setup on your managed PC.";
    }

    [RelayCommand]
    private async Task ImportSshKeyAsync()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Select OpenSSH Private Key",
            Filter = "All Files (*.*)|*.*",
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            var key = await _keyStore.ImportAsync(Path.GetFileNameWithoutExtension(dlg.FileName), dlg.FileName, passphrase: null);
            SshKeys.Add(key);
            BannerNotice = $"Imported key '{key.Name}' (SHA256:{key.FingerprintSha256}).";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Could not import SSH key: {ex.Message}", "SSH Key Import", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private void CopyPublicKey(SshKeyInfo? key)
    {
        if (key is null) return;
        Clipboard.SetText(key.PublicKey);
        BannerNotice = $"Copied public key '{key.Name}' to clipboard.";
    }

    [RelayCommand]
    private async Task DeleteSshKeyAsync(SshKeyInfo? key)
    {
        if (key is null) return;
        var confirm = MessageBox.Show($"Remove SSH key '{key.Name}' from HHJ Remote Manager?", "Delete Key", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;
        await _keyStore.DeleteAsync(key.Id);
        SshKeys.Remove(key);
    }

    public async Task SaveDevicesAsync() => await _devicesRepo.SaveAsync(Devices);

    [RelayCommand]
    private async Task RemoveSelectedDeviceAsync()
    {
        if (SelectedDevice is null) return;
        var confirm = MessageBox.Show(
            $"Remove device profile '{SelectedDevice.DisplayName}'?\n\nThis only removes it from this control panel and does not uninstall software from the remote PC.",
            "Remove Device", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) return;

        await DisconnectAsync();
        Devices.Remove(SelectedDevice);
        SelectedDevice = Devices.FirstOrDefault();
        await SaveDevicesAsync();
    }

    // --- Connection Lifecycle ---

    [RelayCommand]
    private async Task ConnectSelectedAsync()
    {
        if (SelectedDevice is null) return;
        var device = SelectedDevice;

        var validation = DeviceProfileValidator.Validate(device);
        if (!validation.IsValid)
        {
            MessageBox.Show(string.Join("\n", validation.Errors), "Invalid Device Profile", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        await DisconnectAsync();
        _connectCts = new CancellationTokenSource();
        var ct = _connectCts.Token;

        _stateMachine.TryTransition(ConnectionState.Connecting);
        ClearLiveMetrics();

        try
        {
            // Explicit host-key trust on first connect (or mismatch)
            if (device.HostKey is null)
            {
                var probed = await _sshFactory.ProbeHostKeyAsync(device.Address, device.Port, TimeSpan.FromSeconds(10), ct);
                var trust = MessageBox.Show(
                    $"First connection to '{device.DisplayName}' ({device.Address}:{device.Port}).\n\n" +
                    $"Presented SSH Host Key:\n{probed.Display}\n\n" +
                    "Do you trust and pin this host key?",
                    "Verify SSH Host Key", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (trust != MessageBoxResult.Yes)
                {
                    _stateMachine.Fail(new ConnectionFailure(FailureKind.HostKeyUntrusted, "Host key was not trusted by the administrator."));
                    return;
                }
                device.HostKey = new PinnedHostKey(probed.Algorithm, probed.FingerprintSha256, DateTimeOffset.UtcNow);
                await SaveDevicesAsync();
            }

            var req = new SshConnectionRequest
            {
                Host = device.Address,
                Port = device.Port,
                Username = device.Username,
                PrivateKeyProvider = token => _keyStore.LoadPrivateKeyAsync(device.KeyId!, token),
                ExpectedHostKey = new HostKeyInfo(device.HostKey.Algorithm, device.HostKey.FingerprintSha256),
            };

            _session = await _sshFactory.ConnectAsync(req, ct);
            _session.Disconnected += (_, ex) => RunOnUi(async () =>
            {
                if (ConnectionState == ConnectionState.Connected)
                {
                    _stateMachine.Fail(new ConnectionFailure(FailureKind.VpnUnreachable, ex?.Message ?? "SSH connection lost."));
                    await CleanupSessionOnlyAsync();
                }
            });

            _client = new RemoteEndpointClient(_session);
            var probe = await _client.ProbeAsync(ct);
            device.ReportedComputerName = probe.ComputerName;
            device.LastConnectedUtc = DateTimeOffset.UtcNow;
            await SaveDevicesAsync();

            _stateMachine.TryTransition(ConnectionState.Connected);

            // Load expensive SystemInfo once, and start non-overlapping poller
            _ = LoadSystemInfoAsync(ct);
            _poller = new TelemetryPoller(_client, _logger)
            {
                IntervalSeconds = PollIntervalSeconds,
                IsPaused = IsPollingPaused,
            };
            _poller.SampleReceived += (_, snap) => RunOnUi(() => ApplyTelemetrySnapshot(snap, device));
            _poller.PollFailed += (_, ex) => RunOnUi(() => BannerNotice = $"Telemetry poll warning: {ex.Message}");
            _poller.Start();
        }
        catch (SshConnectException ex)
        {
            _stateMachine.Fail(ex.Failure);
        }
        catch (OperationCanceledException)
        {
            _stateMachine.TryTransition(ConnectionState.Disconnected);
        }
        catch (Exception ex)
        {
            _stateMachine.Fail(new ConnectionFailure(FailureKind.Unknown, ex.Message));
        }
    }

    [RelayCommand]
    private async Task DisconnectAsync()
    {
        if (_connectCts is not null)
        {
            await _connectCts.CancelAsync();
            _connectCts.Dispose();
            _connectCts = null;
        }
        await CleanupSessionOnlyAsync();
        _stateMachine.TryTransition(ConnectionState.Disconnected);
    }

    private async Task CleanupSessionOnlyAsync()
    {
        if (_poller is not null)
        {
            await _poller.DisposeAsync();
            _poller = null;
        }
        if (_shellChannel is not null)
        {
            await _shellChannel.DisposeAsync();
            _shellChannel = null;
            IsTerminalOpen = false;
        }
        if (_session is not null)
        {
            await _session.DisposeAsync();
            _session = null;
        }
        _client = null;
        _processTracker.Reset();
    }

    private async Task LoadSystemInfoAsync(CancellationToken ct)
    {
        if (_client is null) return;
        try
        {
            var info = await _client.GetSystemInfoAsync(ct);
            RunOnUi(() =>
            {
                SysComputerName = info.ComputerName ?? "—";
                SysOs = $"{info.OsCaption} {info.DisplayVersion} (Build {info.OsBuild}, {info.OsArchitecture})".Trim();
                SysCpu = $"{info.CpuName} ({info.CpuCores}C / {info.CpuLogicalProcessors}T)";
                SysRam = info.PhysicalMemoryBytes is { } b ? UnitFormatter.Bytes(b) : "—";
                SysSshd = $"{info.SshdStatus} ({info.SshdStartType})";
                SysUser = $"{info.UserName} (Admin: {info.IsAdministrator})";
                Adapters.Clear();
                foreach (var a in info.Adapters) Adapters.Add(a);
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load system info");
        }
    }

    private void ApplyTelemetrySnapshot(MetricsSnapshot snap, DeviceProfile device)
    {
        device.LastTelemetryUtc = snap.Timestamp;
        CpuDisplay = snap.CpuPercent is { } c
            ? UnitFormatter.Percent(c, 1) + (snap.CpuIsApproximate ? " (approx)" : "")
            : "Sampling…";
        RamDisplay = snap.MemoryTotalBytes is { } t && snap.MemoryUsedBytes is { } u
            ? $"{UnitFormatter.Bytes(u)} / {UnitFormatter.Bytes(t)} ({UnitFormatter.Percent(snap.MemoryPercent, 0)})"
            : "—";
        NetworkDisplay = $"↓ {UnitFormatter.BytesPerSecond(snap.TotalReceiveBytesPerSecond)}   ↑ {UnitFormatter.BytesPerSecond(snap.TotalSendBytesPerSecond)}";
        LatencyDisplay = UnitFormatter.Milliseconds(snap.CommandRoundTrip);
        UptimeDisplay = UnitFormatter.Duration(snap.Uptime);
        LastUpdatedDisplay = snap.Timestamp.ToLocalTime().ToString("T");

        if (snap.CpuPercent is { } cpuVal)
        {
            _cpuHistory.Add(snap.Timestamp, cpuVal);
            AppendChartPoint(_cpuPoints, cpuVal);
        }
        if (snap.MemoryPercent is { } ramVal)
        {
            _ramHistory.Add(snap.Timestamp, ramVal);
            AppendChartPoint(_ramPoints, ramVal);
        }
        if (snap.TotalReceiveBytesPerSecond is { } rx)
            AppendChartPoint(_netRxPoints, rx / 1024.0);
        if (snap.TotalSendBytesPerSecond is { } tx)
            AppendChartPoint(_netTxPoints, tx / 1024.0);

        Disks.Clear();
        foreach (var d in snap.Disks) Disks.Add(d);
    }

    private static void AppendChartPoint(ObservableCollection<ObservableValue> series, double val)
    {
        series.Add(new ObservableValue(Math.Round(val, 1)));
        if (series.Count > HistoryCapacity) series.RemoveAt(0);
    }

    private void ClearLiveMetrics()
    {
        CpuDisplay = RamDisplay = NetworkDisplay = LatencyDisplay = UptimeDisplay = LastUpdatedDisplay = "—";
        _cpuHistory.Clear();
        _ramHistory.Clear();
        _cpuPoints.Clear();
        _ramPoints.Clear();
        _netRxPoints.Clear();
        _netTxPoints.Clear();
        Disks.Clear();
        Adapters.Clear();
    }

    // --- Diagnostics ---

    [RelayCommand]
    private async Task RunDiagnosticsAsync()
    {
        if (SelectedDevice is null) return;
        DiagnosticSteps.Clear();
        var report = await _diagnostics.RunAsync(SelectedDevice, CancellationToken.None);
        foreach (var s in report.Steps) DiagnosticSteps.Add(s);
    }

    // --- Processes & Services ---

    [RelayCommand]
    private async Task RefreshProcessesAsync()
    {
        if (_client is null) return;
        try
        {
            var dto = await _client.GetProcessesAsync(CancellationToken.None);
            _allProcesses = _processTracker.Compute(dto).OrderByDescending(p => p.WorkingSetBytes).ToList();
            ApplyProcessFilter();
        }
        catch (Exception ex) { BannerNotice = $"Process refresh failed: {ex.Message}"; }
    }

    private void ApplyProcessFilter()
    {
        FilteredProcesses.Clear();
        var q = ProcessFilter.Trim();
        var items = string.IsNullOrEmpty(q)
            ? _allProcesses
            : _allProcesses.Where(p => p.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || p.Id.ToString().Contains(q, StringComparison.Ordinal));
        foreach (var p in items) FilteredProcesses.Add(p);
    }

    [RelayCommand]
    private async Task EndSelectedProcessAsync()
    {
        if (_client is null || SelectedProcess is null) return;
        var p = SelectedProcess;
        var confirm = MessageBox.Show($"End process '{p.Name}' (PID {p.Id})?", "Confirm End Process", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        try
        {
            var res = await _client.StopProcessAsync(p.Id, p.Name, CancellationToken.None);
            BannerNotice = res.Ok ? $"Ended process {p.Name} ({p.Id})." : $"Failed: {res.Error}";
            await RefreshProcessesAsync();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "End Process", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private async Task RefreshServicesAsync()
    {
        if (_client is null) return;
        try
        {
            var dto = await _client.GetServicesAsync(CancellationToken.None);
            _allServices = dto.Services.OrderBy(s => s.DisplayName ?? s.Name, StringComparer.OrdinalIgnoreCase).ToList();
            ApplyServiceFilter();
        }
        catch (Exception ex) { BannerNotice = $"Service refresh failed: {ex.Message}"; }
    }

    private void ApplyServiceFilter()
    {
        FilteredServices.Clear();
        var q = ServiceFilter.Trim();
        var items = string.IsNullOrEmpty(q)
            ? _allServices
            : _allServices.Where(s => s.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                                       (s.DisplayName?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false));
        foreach (var s in items) FilteredServices.Add(s);
    }

    [RelayCommand]
    private async Task StartSelectedServiceAsync() => await ControlSelectedServiceAsync(RemoteScripts.ServiceAction.Start);
    [RelayCommand]
    private async Task StopSelectedServiceAsync() => await ControlSelectedServiceAsync(RemoteScripts.ServiceAction.Stop);
    [RelayCommand]
    private async Task RestartSelectedServiceAsync() => await ControlSelectedServiceAsync(RemoteScripts.ServiceAction.Restart);

    private async Task ControlSelectedServiceAsync(RemoteScripts.ServiceAction action)
    {
        if (_client is null || SelectedService is null) return;
        var svc = SelectedService;
        var risk = CriticalServiceCatalog.Assess(svc.Name);

        if (action != RemoteScripts.ServiceAction.Start || risk.Level != CriticalServiceCatalog.RiskLevel.Normal)
        {
            var warning = risk.Reason is not null ? $"\n\nWARNING ({risk.Level}): {risk.Reason}" : "";
            var confirm = MessageBox.Show(
                $"{action} Windows service '{svc.DisplayName ?? svc.Name}' ({svc.Name})?{warning}",
                "Confirm Service Action",
                MessageBoxButton.YesNo,
                risk.Level == CriticalServiceCatalog.RiskLevel.Critical ? MessageBoxImage.Warning : MessageBoxImage.Question);
            if (confirm != MessageBoxResult.Yes) return;
        }

        try
        {
            var res = await _client.ControlServiceAsync(svc.Name, action, CancellationToken.None);
            BannerNotice = res.Ok ? $"Service '{svc.Name}' is now {res.State}." : $"Failed: {res.Error}";
            await RefreshServicesAsync();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Service Control", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // --- Embedded Terminal ---

    [RelayCommand]
    private async Task OpenTerminalAsync()
    {
        if (_session is null || !_session.IsConnected)
        {
            MessageBox.Show("Connect to a device first before opening an SSH terminal.", "Terminal", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        await CloseTerminalAsync();
        _shellChannel = await _session.OpenShellAsync(_termCols, _termRows, CancellationToken.None);
        _shellChannel.DataReceived += (_, data) => TerminalOutputReceived?.Invoke(data.ToArray());
        _shellChannel.Closed += (_, _) => RunOnUi(() => IsTerminalOpen = false);
        TerminalCleared?.Invoke();
        IsTerminalOpen = true;
    }

    [RelayCommand]
    private async Task CloseTerminalAsync()
    {
        if (_shellChannel is not null)
        {
            await _shellChannel.DisposeAsync();
            _shellChannel = null;
        }
        IsTerminalOpen = false;
    }

    public async Task SendTerminalInputAsync(string data)
    {
        if (_shellChannel is null || !_shellChannel.IsOpen) return;
        await _shellChannel.WriteAsync(Encoding.UTF8.GetBytes(data), CancellationToken.None);
    }

    public void ResizeTerminal(int cols, int rows)
    {
        _termCols = cols;
        _termRows = rows;
        _shellChannel?.Resize(cols, rows);
    }

    // --- Optional Remote Actions & Reports ---

    [RelayCommand]
    private async Task LoadEventLogsAsync()
    {
        if (_client is null) return;
        EventLogs.Clear();
        var summary = await _client.GetEventLogSummaryAsync(24, 100, CancellationToken.None);
        foreach (var e in summary.Entries) EventLogs.Add(e);
    }

    [RelayCommand]
    private async Task LoadInstalledSoftwareAsync()
    {
        if (_client is null) return;
        InstalledSoftware.Clear();
        var list = await _client.GetInstalledSoftwareAsync(CancellationToken.None);
        foreach (var item in list.Items) InstalledSoftware.Add(item);
    }

    [RelayCommand]
    private async Task FlushDnsAsync()
    {
        if (_client is null) return;
        try
        {
            var res = await _client.FlushDnsAsync(CancellationToken.None);
            BannerNotice = res.Ok ? "Remote DNS cache cleared." : $"DNS flush failed: {res.Error}";
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Flush DNS", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    [RelayCommand]
    private Task RestartRemoteComputerAsync() => ScheduleRemotePowerAsync(RemoteScripts.PowerAction.Restart);

    [RelayCommand]
    private Task ShutdownRemoteComputerAsync() => ScheduleRemotePowerAsync(RemoteScripts.PowerAction.Shutdown);

    private async Task ScheduleRemotePowerAsync(RemoteScripts.PowerAction action)
    {
        if (_client is null) return;
        var confirm = MessageBox.Show(
            $"Schedule a {action} on '{SelectedDevice?.DisplayName}' in 30 seconds?\n\nAny signed-in user will see a Windows shutdown notice.",
            $"Confirm Remote {action}", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        try
        {
            var res = await _client.SchedulePowerAsync(action, 30, CancellationToken.None);
            BannerNotice = res.Ok ? $"Scheduled remote {action} in 30s." : $"Failed: {res.Error}";
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Remote Power", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    [RelayCommand]
    private void ExportPerformanceReport()
    {
        var dlg = new SaveFileDialog
        {
            Title = "Export Performance Report",
            Filter = "JSON Report (*.json)|*.json",
            FileName = $"hhj-report-{SelectedDevice?.DisplayName ?? "device"}-{DateTime.Now:yyyyMMdd-HHmmss}.json",
        };
        if (dlg.ShowDialog() != true) return;

        var report = new
        {
            exportedUtc = DateTimeOffset.UtcNow,
            device = SelectedDevice?.DisplayName,
            address = SelectedDevice?.Address,
            system = new { SysComputerName, SysOs, SysCpu, SysRam, SysSshd },
            cpuHistory = _cpuHistory.Snapshot(),
            ramHistory = _ramHistory.Snapshot(),
            disks = Disks.ToArray(),
        };
        File.WriteAllText(dlg.FileName, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        BannerNotice = $"Exported performance report to {dlg.FileName}";
    }

    private static string FormatLogEntry(LogEntry e) =>
        $"{e.Timestamp:HH:mm:ss} [{e.Level}] {e.Category}: {e.Message}";

    private static void RunOnUi(Action action)
    {
        var disp = Application.Current?.Dispatcher;
        if (disp is null || disp.CheckAccess()) action();
        else disp.BeginInvoke(action);
    }

    public async ValueTask DisposeAsync() => await DisconnectAsync();
}
