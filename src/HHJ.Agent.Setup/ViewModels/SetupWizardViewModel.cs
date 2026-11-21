using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HHJ.Agent.Setup.Engine.Abstractions;
using HHJ.Agent.Setup.Engine.Engine;
using HHJ.Agent.Setup.Engine.Firewall;
using HHJ.Agent.Setup.Engine.State;
using HHJ.Agent.Setup.Engine.Tailscale;
using HHJ.Agent.Setup.Engine.Validation;
using HHJ.Agent.Setup.Windows;

namespace HHJ.Agent.Setup.ViewModels;

public sealed partial class BroadRuleItemViewModel : ObservableObject
{
    public BroadRuleItemViewModel(BroadRuleFinding finding)
    {
        Name = finding.Name;
        Reason = finding.Reason;
    }

    public string Name { get; }
    public string Reason { get; }

    [ObservableProperty]
    private bool _disableRule = true;
}

public sealed partial class SetupWizardViewModel : ObservableObject
{
    private readonly PreCheckEvaluator _preCheck;
    private readonly SetupOrchestrator _orchestrator;
    private readonly IPrivilegeChecker _privileges;
    private readonly INetworkProbe _network;
    private readonly IServiceManager _services;
    private readonly SetupLogSink _logSink;

    private AgentSetupState _state = new();
    private PreCheckReport? _lastPreCheck;
    private OpenSshStageResult? _openSshResult;
    private CancellationTokenSource? _tailscalePollCts;

    public SetupWizardViewModel(
        PreCheckEvaluator preCheck,
        SetupOrchestrator orchestrator,
        IPrivilegeChecker privileges,
        INetworkProbe network,
        IServiceManager services,
        SetupLogSink logSink)
    {
        _preCheck = preCheck;
        _orchestrator = orchestrator;
        _privileges = privileges;
        _network = network;
        _services = services;
        _logSink = logSink;

        LogPath = logSink.LogFilePath;
        ComputerName = privileges.GetComputerName();
        _logSink.LineLogged += line =>
        {
            Application.Current?.Dispatcher.BeginInvoke(() =>
            {
                LogLines.Add(line);
                if (LogLines.Count > 250) LogLines.RemoveAt(0);
            });
        };
    }

    public ObservableCollection<string> LogLines { get; } = [];
    public ObservableCollection<PreCheckItem> PreCheckItems { get; } = [];
    public ObservableCollection<LocalUserAccount> LocalUsers { get; } = [];
    public ObservableCollection<AuthorizedKeyEntry> ManagedKeys { get; } = [];
    public ObservableCollection<BroadRuleItemViewModel> BroadRules { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StageTitle))]
    [NotifyPropertyChangedFor(nameof(CanGoBack))]
    [NotifyPropertyChangedFor(nameof(IsStage0))]
    [NotifyPropertyChangedFor(nameof(IsStage1))]
    [NotifyPropertyChangedFor(nameof(IsStage2))]
    [NotifyPropertyChangedFor(nameof(IsStage3))]
    [NotifyPropertyChangedFor(nameof(IsStage4))]
    [NotifyPropertyChangedFor(nameof(IsStage5))]
    [NotifyPropertyChangedFor(nameof(IsStage6))]
    private int _currentStage;

    public bool IsStage0 => CurrentStage == 0;
    public bool IsStage1 => CurrentStage == 1;
    public bool IsStage2 => CurrentStage == 2;
    public bool IsStage3 => CurrentStage == 3;
    public bool IsStage4 => CurrentStage == 4;
    public bool IsStage5 => CurrentStage == 5;
    public bool IsStage6 => CurrentStage == 6;

    public string StageTitle => CurrentStage switch
    {
        0 => "1 / 7 — Welcome & Explicit Consent",
        1 => "2 / 7 — System Pre-Installation Checks",
        2 => "3 / 7 — Windows OpenSSH Server",
        3 => "4 / 7 — Tailscale Private Network",
        4 => "5 / 7 — SSH Public-Key Authentication",
        5 => "6 / 7 — Windows Defender Firewall",
        6 => "7 / 7 — Setup Complete",
        _ => "HHJ Agent Setup",
    };

    public bool CanGoBack => CurrentStage is > 0 and < 6 && !IsBusy;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanGoBack))]
    private bool _isBusy;

    [ObservableProperty] private string? _statusMessage;
    [ObservableProperty] private string? _errorMessage;

    // Stage 0
    [ObservableProperty] private bool _consentAccepted;
    [ObservableProperty] private bool _existingInstallDetected;

    // Stage 2
    [ObservableProperty] private bool _setPowerShellDefaultShell = true;
    [ObservableProperty] private string _openSshSummary = "Not configured yet.";

    // Stage 3
    [ObservableProperty] private bool _tailscaleUnattendedConsent = true;
    [ObservableProperty] private double _tailscaleDownloadProgress;
    [ObservableProperty] private string _tailscaleHostname = "";
    [ObservableProperty] private string _tailscaleAuthKey = "";
    [ObservableProperty] private string? _tailscaleLoginUrl;
    [ObservableProperty] private TailscaleStatusInfo? _tailscaleStatus;
    [ObservableProperty] private bool _tailnetConfirmed;
    [ObservableProperty] private string _tailscaleStateSummary = "Checking Tailscale...";

    // Stage 4
    [ObservableProperty] private LocalUserAccount? _selectedUser;
    [ObservableProperty] private string _publicKeyText = "";
    [ObservableProperty] private string _keyLabel = "admin";
    [ObservableProperty] private string? _keyValidationMessage;
    [ObservableProperty] private string? _keyFingerprintDisplay;
    [ObservableProperty] private bool _isPublicKeyValid;

    // Stage 5
    [ObservableProperty] private string _firewallPlanSummary = "Pending...";

    // Stage 6
    public string ComputerName { get; }
    public string LogPath { get; }
    [ObservableProperty] private string _finalOsSummary = "";
    [ObservableProperty] private string _finalSshdSummary = "";
    [ObservableProperty] private string _finalTailscaleSummary = "";
    [ObservableProperty] private string _finalVpnAddress = "";
    [ObservableProperty] private string _finalUsername = "";
    [ObservableProperty] private string _connectionTestResult = "Not tested yet.";

    partial void OnPublicKeyTextChanged(string value)
    {
        var parsed = PublicKeyParser.Parse(value);
        IsPublicKeyValid = parsed.IsValid;
        if (parsed.IsValid && parsed.Key is not null)
        {
            KeyFingerprintDisplay = $"SHA256:{parsed.Key.FingerprintSha256} ({parsed.Key.KeyType}{(parsed.Key.RsaKeyBits is { } b ? $", {b} bits" : "")})";
            KeyValidationMessage = "Valid SSH public key.";
        }
        else
        {
            KeyFingerprintDisplay = null;
            KeyValidationMessage = string.IsNullOrWhiteSpace(value) ? null : parsed.Error;
        }
    }

    public async Task InitializeAsync()
    {
        _state = await _orchestrator.LoadStateAsync(CancellationToken.None);
        ExistingInstallDetected = _state.FirstConfiguredUtc is not null;
        foreach (var u in _privileges.GetLocalUsers()) LocalUsers.Add(u);
        SelectedUser = LocalUsers.FirstOrDefault(u => u.Username.Equals(_privileges.GetCurrentUsername(), StringComparison.OrdinalIgnoreCase))
                       ?? LocalUsers.FirstOrDefault();
    }

    [RelayCommand]
    private void Back()
    {
        if (!CanGoBack) return;
        ErrorMessage = null;
        CurrentStage--;
    }

    [RelayCommand]
    private async Task RunPreChecksAsync()
    {
        if (!ConsentAccepted)
        {
            ErrorMessage = "You must confirm authorization and consent before proceeding.";
            return;
        }
        await ExecuteBusyAsync("Running system pre-installation checks...", async ct =>
        {
            CurrentStage = 1;
            PreCheckItems.Clear();
            _lastPreCheck = await _preCheck.EvaluateAsync(ct);
            foreach (var item in _lastPreCheck.Items) PreCheckItems.Add(item);
            if (_lastPreCheck.HasFailures)
                ErrorMessage = "Resolve the failed pre-checks above before continuing.";
        });
    }

    [RelayCommand]
    private async Task ConfigureOpenSshAsync()
    {
        if (_lastPreCheck?.HasFailures == true) return;
        await ExecuteBusyAsync("Configuring Windows OpenSSH Server...", async ct =>
        {
            CurrentStage = 2;
            var cap = _lastPreCheck?.OpenSshCapabilityName ?? "OpenSSH.Server~~~~0.0.1.0";
            _openSshResult = await _orchestrator.ConfigureOpenSshAsync(cap, SetPowerShellDefaultShell, _state, ct);
            OpenSshSummary = $"sshd Running on port {_openSshResult.Port} | Banner: {_openSshResult.SshBanner ?? "unavailable"} | Match Admin block: {_openSshResult.Config.HasMatchAdministratorsBlock}";
        });
    }

    [RelayCommand]
    private async Task EnterTailscaleStageAsync()
    {
        CurrentStage = 3;
        await RefreshTailscaleStatusAsync();
    }

    [RelayCommand]
    private async Task InstallOrEnrollTailscaleAsync()
    {
        await ExecuteBusyAsync("Installing / enrolling Tailscale...", async ct =>
        {
            var progress = new Progress<double>(p => TailscaleDownloadProgress = p);
            await _orchestrator.InstallTailscaleAsync(TailscaleUnattendedConsent, _state, progress, ct);
            var url = await _orchestrator.StartTailscaleUpAsync(
                TailscaleUnattendedConsent,
                string.IsNullOrWhiteSpace(TailscaleAuthKey) ? null : TailscaleAuthKey,
                string.IsNullOrWhiteSpace(TailscaleHostname) ? null : TailscaleHostname,
                forceReauth: false,
                ct);
            TailscaleAuthKey = ""; // Clear from memory/UI
            TailscaleLoginUrl = url;
            await StartPollingTailscaleAsync();
        });
    }

    [RelayCommand]
    private async Task ForceReauthTailscaleAsync()
    {
        await ExecuteBusyAsync("Starting Tailscale re-authentication...", async ct =>
        {
            TailnetConfirmed = false;
            var url = await _orchestrator.StartTailscaleUpAsync(
                TailscaleUnattendedConsent,
                string.IsNullOrWhiteSpace(TailscaleAuthKey) ? null : TailscaleAuthKey,
                string.IsNullOrWhiteSpace(TailscaleHostname) ? null : TailscaleHostname,
                forceReauth: true,
                ct);
            TailscaleAuthKey = "";
            TailscaleLoginUrl = url;
            await StartPollingTailscaleAsync();
        });
    }

    [RelayCommand]
    private async Task RejectTailnetAsync()
    {
        await ExecuteBusyAsync("Logging out of tailnet...", async ct =>
        {
            TailnetConfirmed = false;
            await _orchestrator.LogoutTailscaleAsync(ct);
            await RefreshTailscaleStatusAsync();
        });
    }

    [RelayCommand]
    private async Task RefreshTailscaleStatusAsync()
    {
        var st = await _orchestrator.GetTailscaleStatusAsync(CancellationToken.None);
        TailscaleStatus = st;
        if (st is null)
        {
            TailscaleStateSummary = "Tailscale is not installed yet.";
            return;
        }
        TailscaleLoginUrl ??= st.AuthUrl;
        TailscaleStateSummary = st.BackendState switch
        {
            "Running" => $"Connected to tailnet '{st.TailnetName ?? "unknown"}' as {st.LoggedInUser ?? "unknown"} ({st.SelfDnsName ?? string.Join(", ", st.SelfIps)})",
            "NeedsLogin" => "Waiting for Tailscale login. Open the login URL in a browser to enroll this computer.",
            "NeedsMachineAuth" => "Waiting for administrator approval in the Tailscale admin console.",
            _ => $"Tailscale state: {st.BackendState}",
        };
    }

    [RelayCommand]
    private void CopyLoginUrl()
    {
        if (!string.IsNullOrWhiteSpace(TailscaleLoginUrl))
            Clipboard.SetText(TailscaleLoginUrl);
    }

    [RelayCommand]
    private void OpenLoginUrl()
    {
        if (!string.IsNullOrWhiteSpace(TailscaleLoginUrl))
            Process.Start(new ProcessStartInfo(TailscaleLoginUrl) { UseShellExecute = true });
    }

    private async Task StartPollingTailscaleAsync()
    {
        _tailscalePollCts?.Cancel();
        _tailscalePollCts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        var ct = _tailscalePollCts.Token;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await RefreshTailscaleStatusAsync();
                if (TailscaleStatus?.BackendState.Equals("Running", StringComparison.OrdinalIgnoreCase) == true)
                    break;
                await Task.Delay(TimeSpan.FromSeconds(2), ct);
            }
        }
        catch (OperationCanceledException) { }
    }

    [RelayCommand]
    private async Task EnterAuthStageAsync()
    {
        if (TailscaleStatus?.BackendState.Equals("Running", StringComparison.OrdinalIgnoreCase) == true && !TailnetConfirmed)
        {
            ErrorMessage = "Please confirm that this computer is enrolled in your intended tailnet before continuing.";
            return;
        }
        ErrorMessage = null;
        CurrentStage = 4;
        await RefreshManagedKeysAsync();
    }

    [RelayCommand]
    private async Task RefreshManagedKeysAsync()
    {
        ManagedKeys.Clear();
        if (SelectedUser is null) return;
        var keys = await _orchestrator.ListHhjKeysAsync(SelectedUser, CancellationToken.None);
        foreach (var k in keys) ManagedKeys.Add(k);
    }

    [RelayCommand]
    private async Task RevokeKeyAsync(AuthorizedKeyEntry? entry)
    {
        if (entry is null || SelectedUser is null) return;
        await ExecuteBusyAsync("Revoking SSH key...", async ct =>
        {
            await _orchestrator.RevokeHhjKeyAsync(SelectedUser, entry.FingerprintSha256, _state, ct);
            await RefreshManagedKeysAsync();
        });
    }

    [RelayCommand]
    private async Task ApplyAuthAndPrepareFirewallAsync()
    {
        if (SelectedUser is null)
        {
            ErrorMessage = "Select a target Windows account.";
            return;
        }
        if (!IsPublicKeyValid)
        {
            ErrorMessage = KeyValidationMessage ?? "Enter a valid OpenSSH public key.";
            return;
        }

        await ExecuteBusyAsync("Authorizing SSH public key & inspecting firewall...", async ct =>
        {
            await _orchestrator.AuthorizePublicKeyAsync(PublicKeyText, SelectedUser, KeyLabel, _state, ct);
            await RefreshManagedKeysAsync();

            var refreshed = await _preCheck.EvaluateAsync(ct);
            _lastPreCheck = refreshed;
            var port = _openSshResult?.Port ?? refreshed.DetectedSshPort;
            var plan = FirewallReconciler.Reconcile(refreshed.ExistingFirewallRules, port, PreCheckEvaluator.SshdExePath, refreshed.TailscaleInterfaceAlias);

            BroadRules.Clear();
            foreach (var b in plan.BroadRules) BroadRules.Add(new BroadRuleItemViewModel(b));

            FirewallPlanSummary = $"Rule '{plan.Desired.Name}': {plan.Action} | Port {plan.Desired.LocalPort} | Remote: {string.Join(", ", plan.Desired.RemoteAddresses)} | Interface: {plan.Desired.InterfaceAlias ?? "Any (Tailscale adapter not found)"}";
            CurrentStage = 5;
        });
    }

    [RelayCommand]
    private async Task ApplyFirewallAndFinishAsync()
    {
        await ExecuteBusyAsync("Applying Windows Firewall configuration...", async ct =>
        {
            var port = _openSshResult?.Port ?? _lastPreCheck?.DetectedSshPort ?? 22;
            var plan = FirewallReconciler.Reconcile(
                _lastPreCheck?.ExistingFirewallRules ?? [],
                port,
                PreCheckEvaluator.SshdExePath,
                _lastPreCheck?.TailscaleInterfaceAlias);

            var toDisable = BroadRules.Where(r => r.DisableRule).Select(r => r.Name).ToList();
            await _orchestrator.ApplyFirewallPlanAsync(plan, toDisable, _state, ct);

            await PopulateCompletionSummaryAsync(ct);
            CurrentStage = 6;
        });
    }

    private async Task PopulateCompletionSummaryAsync(CancellationToken ct)
    {
        var sshd = _services.GetService("sshd");
        var ts = await _orchestrator.GetTailscaleStatusAsync(ct);
        FinalOsSummary = _lastPreCheck?.Items.FirstOrDefault(i => i.Name == "Windows Version")?.Summary ?? "Windows";
        FinalSshdSummary = $"{sshd.Status ?? "Unknown"} ({sshd.StartType ?? "Unknown"})";
        FinalTailscaleSummary = ts?.BackendState ?? "Not running";
        FinalVpnAddress = ts is not null
            ? $"{ts.SelfDnsName ?? "(no MagicDNS)"} | {string.Join(", ", ts.SelfIps)}"
            : "(unavailable)";
        FinalUsername = SelectedUser?.Username ?? _privileges.GetCurrentUsername();
        await TestConnectionAsync();
    }

    [RelayCommand]
    private async Task TestConnectionAsync()
    {
        var port = _openSshResult?.Port ?? _lastPreCheck?.DetectedSshPort ?? 22;
        var ts = await _orchestrator.GetTailscaleStatusAsync(CancellationToken.None);
        var target = ts?.SelfIps.FirstOrDefault() ?? "127.0.0.1";
        var banner = await _network.ProbeSshBannerAsync(target, port, TimeSpan.FromSeconds(5), CancellationToken.None);
        ConnectionTestResult = banner is not null
            ? $"PASS — {target}:{port} responded with '{banner}'"
            : $"FAIL — No SSH banner received on {target}:{port}";
    }

    [RelayCommand]
    private void ViewDetails()
    {
        if (System.IO.File.Exists(LogPath))
            Process.Start(new ProcessStartInfo(LogPath) { UseShellExecute = true });
    }

    [RelayCommand]
    private async Task DisableRemoteAccessAsync()
    {
        var confirm = MessageBox.Show(
            "Disable HHJ Remote Access on this computer?\n\nThis will stop sshd, remove the HHJ firewall rule, and revoke HHJ-added authorized SSH keys.",
            "Disable Remote Access",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        await ExecuteBusyAsync("Disabling remote access...", async ct =>
        {
            await _orchestrator.DisableRemoteAccessAsync(new DisableOptions(), ct);
            MessageBox.Show("Remote access has been disabled and HHJ changes were rolled back.", "HHJ Agent Setup", MessageBoxButton.OK, MessageBoxImage.Information);
            CurrentStage = 0;
        });
    }

    [RelayCommand]
    private void Finish() => Application.Current?.Shutdown(0);

    private async Task ExecuteBusyAsync(string status, Func<CancellationToken, Task> action)
    {
        if (IsBusy) return;
        IsBusy = true;
        ErrorMessage = null;
        StatusMessage = status;
        try
        {
            await action(CancellationToken.None);
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsBusy = false;
            StatusMessage = null;
        }
    }
}
