using System.Globalization;
using System.Text.Json;
using HHJ.Agent.Setup.Engine.Abstractions;
using HHJ.Agent.Setup.Engine.Firewall;
using HHJ.Agent.Setup.Engine.OpenSsh;
using HHJ.Agent.Setup.Engine.Tailscale;

namespace HHJ.Agent.Setup.Engine.Engine;

public enum CheckStatus { Pass, Warn, Fail }

public sealed record PreCheckItem(string Name, CheckStatus Status, string Summary, string? Detail = null);

public sealed record PreCheckReport(
    IReadOnlyList<PreCheckItem> Items,
    bool CanProceed,
    string? OpenSshCapabilityName,
    bool OpenSshInstalled,
    bool TailscaleInstalled,
    TailscaleStatusInfo? TailscaleStatus,
    int DetectedSshPort,
    IReadOnlyList<FirewallRuleSnapshot> ExistingFirewallRules,
    string? TailscaleInterfaceAlias)
{
    public bool HasFailures => Items.Any(i => i.Status == CheckStatus.Fail);
}

/// <summary>
/// Stage 1 pre-installation checks. Purely driven by injected abstractions so it can be unit-tested.
/// </summary>
public sealed class PreCheckEvaluator(
    IPrivilegeChecker privileges,
    IRegistryReader registry,
    IFileSystem fs,
    IServiceManager services,
    INetworkProbe network,
    IProcessRunner process)
{
    public const int MinimumWindowsBuild = 17763; // Windows 10 1809 / Server 2019 (OpenSSH capability)
    public const string TailscaleExePath = @"C:\Program Files\Tailscale\tailscale.exe";
    public const string SshdExePath = @"C:\Windows\System32\OpenSSH\sshd.exe";
    public const string SshdConfigPath = @"C:\ProgramData\ssh\sshd_config";

    public async Task<PreCheckReport> EvaluateAsync(CancellationToken ct)
    {
        var items = new List<PreCheckItem>();

        // 1. Administrator privileges
        var isAdmin = privileges.IsAdministrator();
        items.Add(isAdmin
            ? new("Administrator Privileges", CheckStatus.Pass, $"Running elevated as {privileges.GetCurrentUsername()}.")
            : new("Administrator Privileges", CheckStatus.Fail, "Administrator elevation is required to configure OpenSSH, Tailscale, and Windows Firewall."));

        // 2. CPU architecture
        var arch = privileges.GetOsArchitecture();
        items.Add(arch.Equals("X64", StringComparison.OrdinalIgnoreCase)
            ? new("CPU Architecture", CheckStatus.Pass, "Windows x64 detected.")
            : new("CPU Architecture", CheckStatus.Warn, $"Detected architecture '{arch}'. This installer targets Windows x64."));

        // 3. Windows version & build
        var prodName = registry.GetString(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName") ?? "Windows";
        var displayVer = registry.GetString(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion") ?? "";
        var buildStr = registry.GetString(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild") ?? "0";
        var ubr = registry.GetDword(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR");
        _ = int.TryParse(buildStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out var buildNum);
        var fullBuild = ubr is not null ? $"{buildNum}.{ubr}" : buildStr;

        items.Add(buildNum >= MinimumWindowsBuild
            ? new("Windows Version", CheckStatus.Pass, $"{prodName} {displayVer} (Build {fullBuild})".Trim())
            : new("Windows Version", CheckStatus.Fail, $"Windows build {fullBuild} is below {MinimumWindowsBuild} (Windows 10 1809). OpenSSH Server capability is not supported."));

        // 4. Pending reboot
        var rebootPending =
            registry.ValueExists(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending", "") ||
            registry.ValueExists(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired", "") ||
            registry.ValueExists(RegistryHiveKind.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations");
        items.Add(rebootPending
            ? new("Windows Reboot Status", CheckStatus.Warn, "A Windows restart is pending. Installing capabilities may require rebooting.")
            : new("Windows Reboot Status", CheckStatus.Pass, "No pending Windows reboot detected."));

        // 5. OpenSSH Server capability + sshd service
        var capName = "OpenSSH.Server~~~~0.0.1.0";
        var openSshInstalled = fs.FileExists(SshdExePath);
        if (isAdmin)
        {
            var capRes = await RunPowerShellJsonAsync(
                "Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1 Name,State | ConvertTo-Json -Compress",
                TimeSpan.FromSeconds(25), ct);
            if (capRes.ExitCode == 0 && !string.IsNullOrWhiteSpace(capRes.StdOut))
            {
                try
                {
                    using var doc = JsonDocument.Parse(capRes.StdOut.Trim());
                    if (doc.RootElement.TryGetProperty("Name", out var n) && !string.IsNullOrWhiteSpace(n.GetString()))
                        capName = n.GetString()!;
                    if (doc.RootElement.TryGetProperty("State", out var st))
                    {
                        var stateVal = st.ToString();
                        openSshInstalled = stateVal.Equals("Installed", StringComparison.OrdinalIgnoreCase) ||
                                           stateVal.Equals("4", StringComparison.OrdinalIgnoreCase) ||
                                           openSshInstalled;
                    }
                }
                catch { /* Fall back to file presence */ }
            }
        }

        var sshdSvc = services.GetService("sshd");
        items.Add(openSshInstalled && sshdSvc.Exists
            ? new("OpenSSH Server", CheckStatus.Pass, $"Installed (service sshd: {sshdSvc.Status}, StartType: {sshdSvc.StartType}).")
            : openSshInstalled
                ? new("OpenSSH Server", CheckStatus.Warn, "OpenSSH binary found, but sshd service is not registered yet.")
                : new("OpenSSH Server", CheckStatus.Warn, "Not installed yet — Stage 2 will install the Windows OpenSSH Server capability."));

        // Read sshd_config if present
        var detectedPort = 22;
        if (fs.FileExists(SshdConfigPath))
        {
            var cfgText = await fs.ReadAllTextAsync(SshdConfigPath, ct);
            detectedPort = SshdConfigParser.Parse(cfgText).Port;
        }

        // 6. Tailscale installation & status
        var tailscaleInstalled = fs.FileExists(TailscaleExePath);
        TailscaleStatusInfo? tsStatus = null;
        if (tailscaleInstalled)
        {
            var tsRes = await process.RunAsync(TailscaleExePath, ["status", "--json"], TimeSpan.FromSeconds(8), ct);
            if (!string.IsNullOrWhiteSpace(tsRes.StdOut))
            {
                try { tsStatus = TailscaleParser.ParseStatusJson(tsRes.StdOut); }
                catch { /* Ignore parse error */ }
            }
            items.Add(tsStatus?.BackendState.Equals("Running", StringComparison.OrdinalIgnoreCase) == true
                ? new("Tailscale", CheckStatus.Pass, $"Installed and connected ({tsStatus.SelfDnsName ?? string.Join(", ", tsStatus.SelfIps)}).")
                : new("Tailscale", CheckStatus.Warn, $"Installed (state: {tsStatus?.BackendState ?? "Unknown"}). Enrollment can be completed in Stage 3."));
        }
        else
        {
            items.Add(new("Tailscale", CheckStatus.Warn, "Not installed yet — Stage 3 can download and install the signed Tailscale MSI."));
        }

        // 7. Network & DNS connectivity
        var netUp = network.IsNetworkAvailable();
        var dnsOk = netUp && await network.CanResolveDnsAsync("pkgs.tailscale.com", ct);
        items.Add(netUp && dnsOk
            ? new("Network Connectivity", CheckStatus.Pass, "Network online and able to resolve pkgs.tailscale.com.")
            : netUp
                ? new("Network Connectivity", CheckStatus.Warn, "Network is up, but pkgs.tailscale.com could not be resolved (offline installation may be required).")
                : new("Network Connectivity", CheckStatus.Warn, "No active network interface detected."));

        // 8. Firewall rules & Tailscale interface
        var fwRules = new List<FirewallRuleSnapshot>();
        string? tsAlias = null;
        if (isAdmin)
        {
            var fwScript = """
                $ErrorActionPreference='SilentlyContinue'
                $rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow | Where-Object { $_.Enabled -eq 'True' -or $_.DisplayName -like 'HHJ Remote Manager*' -or $_.DisplayName -like '*OpenSSH*' } | ForEach-Object {
                  $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                  $af = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                  $ap = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
                  $if = $_ | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue
                  [ordered]@{
                    Name=$_.DisplayName; Group=$_.Group; Enabled=($_.Enabled -eq 'True');
                    Direction=[string]$_.Direction; Action=[string]$_.Action;
                    Protocol=[string]$pf.Protocol; LocalPort=[string]$pf.LocalPort;
                    RemoteAddress=(@($af.RemoteAddress) -join ',');
                    Program=[string]$ap.Program;
                    InterfaceAlias=(@($if.InterfaceAlias) -join ',')
                  }
                })
                $ts = (Get-NetAdapter | Where-Object { $_.InterfaceDescription -like 'Tailscale*' } | Select-Object -First 1).Name
                [ordered]@{ rules=$rules; tsAlias=$ts } | ConvertTo-Json -Depth 4 -Compress
                """;
            var fwRes = await RunPowerShellJsonAsync(fwScript, TimeSpan.FromSeconds(15), ct);
            if (fwRes.ExitCode == 0 && !string.IsNullOrWhiteSpace(fwRes.StdOut))
            {
                try
                {
                    using var doc = JsonDocument.Parse(fwRes.StdOut.Trim());
                    if (doc.RootElement.TryGetProperty("tsAlias", out var ta))
                        tsAlias = ta.GetString();
                    if (doc.RootElement.TryGetProperty("rules", out var arr) && arr.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var el in arr.EnumerateArray())
                        {
                            fwRules.Add(new FirewallRuleSnapshot(
                                el.TryGetProperty("Name", out var n) ? n.GetString() ?? "" : "",
                                el.TryGetProperty("Group", out var g) ? g.GetString() : null,
                                el.TryGetProperty("Enabled", out var en) && en.GetBoolean(),
                                el.TryGetProperty("Direction", out var d) ? d.GetString() ?? "Inbound" : "Inbound",
                                el.TryGetProperty("Action", out var a) ? a.GetString() ?? "Allow" : "Allow",
                                el.TryGetProperty("Protocol", out var pr) ? pr.GetString() : null,
                                el.TryGetProperty("LocalPort", out var lp) ? lp.GetString() : null,
                                el.TryGetProperty("RemoteAddress", out var ra) ? ra.GetString() : null,
                                el.TryGetProperty("Program", out var pg) ? pg.GetString() : null,
                                el.TryGetProperty("InterfaceAlias", out var ia) ? ia.GetString() : null));
                        }
                    }
                }
                catch { /* Ignore parse error */ }
            }
        }

        var plan = FirewallReconciler.Reconcile(fwRules, detectedPort, SshdExePath, tsAlias);
        items.Add(plan.BroadRules.Count > 0
            ? new("Firewall Exposure", CheckStatus.Warn,
                $"{plan.BroadRules.Count} broad OpenSSH rule(s) allow ANY remote IP. Stage 5 will offer to disable them.",
                string.Join("\n", plan.BroadRules.Select(b => b.Reason)))
            : new("Firewall Exposure", CheckStatus.Pass, "No broad OpenSSH firewall exposure detected."));

        var canProceed = !items.Any(i => i.Status == CheckStatus.Fail);
        return new PreCheckReport(items, canProceed, capName, openSshInstalled, tailscaleInstalled, tsStatus, detectedPort, fwRules, tsAlias);
    }

    private Task<ProcessRunResult> RunPowerShellJsonAsync(string script, TimeSpan timeout, CancellationToken ct)
    {
        var encoded = FirewallReconciler.ToEncodedCommand(script);
        return process.RunAsync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], timeout, ct);
    }
}
