using System.Text.Json;
using HHJ.Agent.Setup.Engine.Abstractions;
using HHJ.Agent.Setup.Engine.Firewall;
using HHJ.Agent.Setup.Engine.OpenSsh;
using HHJ.Agent.Setup.Engine.State;
using HHJ.Agent.Setup.Engine.Tailscale;
using HHJ.Agent.Setup.Engine.Validation;
using Microsoft.Extensions.Logging;

namespace HHJ.Agent.Setup.Engine.Engine;

public sealed record OpenSshStageResult(
    int Port,
    string? SshBanner,
    bool InstalledNow,
    bool DefaultShellSet,
    SshdConfigSummary Config);

public sealed record DisableOptions(
    bool StopAndRestoreSshd = true,
    bool DisableSshdEntirely = false,
    bool RemoveHhjFirewallRule = true,
    bool ReEnablePreviouslyDisabledRules = false,
    bool RemoveHhjAuthorizedKeys = true,
    bool RestoreDefaultShell = true,
    bool UninstallOpenSshIfInstalledByHhj = false,
    bool LogoutTailscale = false);

/// <summary>
/// Coordinates idempotent configuration and clean rollback across Stages 2-6 and CLI modes.
/// </summary>
public sealed class SetupOrchestrator(
    IProcessRunner process,
    IFileSystem fs,
    IRegistryReader registry,
    IServiceManager services,
    INetworkProbe network,
    IPrivilegeChecker privileges,
    IPackageDownloader downloader,
    IAuthenticodeVerifier verifier,
    IAclManager acls,
    ILogger<SetupOrchestrator> logger)
{
    public const string DataRoot = @"C:\ProgramData\HHJ\AgentSetup";
    public const string StateFilePath = @"C:\ProgramData\HHJ\AgentSetup\state.json";
    public const string DownloadsDir = @"C:\ProgramData\HHJ\AgentSetup\downloads";
    public const string LogsDir = @"C:\ProgramData\HHJ\AgentSetup\logs";
    public const string OpenSshRegKey = @"SOFTWARE\OpenSSH";
    public const string DefaultShellValueName = "DefaultShell";
    public const string PowerShellExePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    public const string AdminAuthorizedKeysPath = @"C:\ProgramData\ssh\administrators_authorized_keys";

    public async Task<AgentSetupState> LoadStateAsync(CancellationToken ct)
    {
        if (!fs.FileExists(StateFilePath)) return new AgentSetupState();
        try
        {
            var json = await fs.ReadAllTextAsync(StateFilePath, ct);
            return AgentSetupStateStore.Deserialize(json);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not parse existing state.json; starting fresh state record.");
            return new AgentSetupState();
        }
    }

    public async Task SaveStateAsync(AgentSetupState state, CancellationToken ct)
    {
        fs.CreateDirectory(DataRoot);
        acls.ApplyAdminOnlyDirectoryAcl(DataRoot);
        state.FirstConfiguredUtc ??= DateTimeOffset.UtcNow;
        state.LastUpdatedUtc = DateTimeOffset.UtcNow;
        await fs.WriteAllTextAsync(StateFilePath, AgentSetupStateStore.Serialize(state), ct);
    }

    // --- Stage 2: OpenSSH Server ---

    public async Task<OpenSshStageResult> ConfigureOpenSshAsync(
        string capabilityName,
        bool setPowerShellDefaultShell,
        AgentSetupState state,
        CancellationToken ct)
    {
        var svc = services.GetService("sshd");
        var installedNow = false;

        if (!svc.Exists || !fs.FileExists(PreCheckEvaluator.SshdExePath))
        {
            logger.LogInformation("Installing Windows capability {Capability}...", capabilityName);
            var script = $"$ErrorActionPreference='Stop'; Add-WindowsCapability -Online -Name {FirewallReconciler.PsLiteral(capabilityName)} | Out-Null";
            var res = await RunPowerShellAsync(script, TimeSpan.FromMinutes(10), ct);
            if (res.ExitCode != 0)
                throw new InvalidOperationException($"Failed to install OpenSSH Server capability: {res.StdErr}".Trim());

            state.OpenSshInstalledByHhj = true;
            installedNow = true;
            svc = services.GetService("sshd");
        }

        if (svc.Exists && state.SshdOriginalStartType is null)
        {
            state.SshdOriginalStartType = svc.StartType ?? "Manual";
        }

        if (!string.Equals(svc.StartType, "Automatic", StringComparison.OrdinalIgnoreCase))
        {
            logger.LogInformation("Setting sshd startup type to Automatic.");
            await services.SetStartTypeAsync("sshd", "Automatic", ct);
        }

        if (!string.Equals(svc.Status, "Running", StringComparison.OrdinalIgnoreCase))
        {
            logger.LogInformation("Starting sshd service...");
            await services.StartAsync("sshd", ct);
        }

        var cfgText = fs.FileExists(PreCheckEvaluator.SshdConfigPath)
            ? await fs.ReadAllTextAsync(PreCheckEvaluator.SshdConfigPath, ct)
            : "";
        var cfg = SshdConfigParser.Parse(cfgText);

        if (setPowerShellDefaultShell)
        {
            var prevExists = registry.ValueExists(RegistryHiveKind.LocalMachine, OpenSshRegKey, DefaultShellValueName);
            var prevVal = registry.GetString(RegistryHiveKind.LocalMachine, OpenSshRegKey, DefaultShellValueName);
            if (!state.DefaultShellChangedByHhj && !string.Equals(prevVal, PowerShellExePath, StringComparison.OrdinalIgnoreCase))
            {
                state.DefaultShellPreviouslyExisted = prevExists;
                state.DefaultShellPreviousValue = prevVal;
                state.DefaultShellChangedByHhj = true;
            }
            registry.SetString(RegistryHiveKind.LocalMachine, OpenSshRegKey, DefaultShellValueName, PowerShellExePath);
        }

        var ports = network.GetActiveTcpListenerPorts();
        if (!ports.Contains(cfg.Port))
        {
            // Give sshd a brief moment to bind after starting
            await Task.Delay(TimeSpan.FromSeconds(1), ct);
        }

        var banner = await network.ProbeSshBannerAsync("127.0.0.1", cfg.Port, TimeSpan.FromSeconds(5), ct);
        logger.LogInformation("OpenSSH verified on port {Port}. Banner: {Banner}", cfg.Port, banner ?? "(none)");

        await SaveStateAsync(state, ct);
        return new OpenSshStageResult(cfg.Port, banner, installedNow, setPowerShellDefaultShell, cfg);
    }

    // --- Stage 3: Tailscale ---

    public async Task InstallTailscaleAsync(
        bool unattendedModeConsent,
        AgentSetupState state,
        IProgress<double>? downloadProgress,
        CancellationToken ct)
    {
        if (fs.FileExists(PreCheckEvaluator.TailscaleExePath))
        {
            logger.LogInformation("Tailscale is already installed.");
            return;
        }

        fs.CreateDirectory(DownloadsDir);
        var msiPath = Path.Combine(DownloadsDir, "tailscale-setup-latest-amd64.msi");

        logger.LogInformation("Downloading official Tailscale MSI from {Url}", TailscaleParser.OfficialMsiUrl);
        await downloader.DownloadFileAsync(TailscaleParser.OfficialMsiUrl, msiPath, downloadProgress, ct);

        var sig = verifier.VerifySignedByPublisher(msiPath, TailscaleParser.ExpectedPublisherOrganization);
        if (!sig.IsValid)
        {
            try { fs.DeleteFile(msiPath); } catch { }
            throw new InvalidOperationException($"Tailscale MSI signature verification failed: {sig.Error ?? "Untrusted publisher"}");
        }
        logger.LogInformation("Verified Authenticode signature: {Publisher}", sig.Publisher);

        fs.CreateDirectory(LogsDir);
        var msiLog = Path.Combine(LogsDir, $"tailscale-msi-{DateTime.Now:yyyyMMdd-HHmmss}.log");
        var args = new List<string> { "/i", msiPath, "/qn", "/norestart", "/l*v", msiLog };
        if (unattendedModeConsent) args.Add("TS_UNATTENDEDMODE=always");

        var res = await process.RunAsync("msiexec.exe", args, TimeSpan.FromMinutes(5), ct);
        if (res.ExitCode is not (0 or 3010))
            throw new InvalidOperationException($"Tailscale MSI installation failed with exit code {res.ExitCode}. See {msiLog}.");

        state.TailscaleInstalledByHhj = true;
        await SaveStateAsync(state, ct);
        logger.LogInformation("Tailscale installed successfully (exit code {Code}).", res.ExitCode);
    }

    public async Task<string?> StartTailscaleUpAsync(
        bool unattendedMode,
        string? authKey,
        string? hostname,
        bool forceReauth,
        CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(hostname) && !TailscaleParser.IsValidTailscaleHostname(hostname))
            throw new ArgumentException("Hostname must be 1-63 lowercase letters, digits, or hyphens.");

        var args = new List<string> { "up", "--timeout=5s" };
        if (unattendedMode) args.Add("--unattended");
        if (forceReauth) args.Add("--force-reauth");
        if (!string.IsNullOrWhiteSpace(hostname))
        {
            args.Add("--hostname");
            args.Add(hostname.Trim());
        }
        if (!string.IsNullOrWhiteSpace(authKey))
        {
            args.Add("--auth-key=" + authKey.Trim());
        }

        var res = await process.RunAsync(PreCheckEvaluator.TailscaleExePath, args, TimeSpan.FromSeconds(15), ct);
        var combined = TailscaleParser.MaskSecret($"{res.StdOut}\n{res.StdErr}", authKey);
        logger.LogInformation("tailscale up exited with {Code}.", res.ExitCode);

        var url = TailscaleParser.ExtractAuthUrl(combined);
        if (url is not null) return url;

        var status = await GetTailscaleStatusAsync(ct);
        return status?.AuthUrl;
    }

    public async Task<TailscaleStatusInfo?> GetTailscaleStatusAsync(CancellationToken ct)
    {
        if (!fs.FileExists(PreCheckEvaluator.TailscaleExePath)) return null;
        var res = await process.RunAsync(PreCheckEvaluator.TailscaleExePath, ["status", "--json"], TimeSpan.FromSeconds(8), ct);
        if (string.IsNullOrWhiteSpace(res.StdOut)) return null;
        try { return TailscaleParser.ParseStatusJson(res.StdOut); }
        catch { return null; }
    }

    public Task LogoutTailscaleAsync(CancellationToken ct) =>
        process.RunAsync(PreCheckEvaluator.TailscaleExePath, ["logout"], TimeSpan.FromSeconds(15), ct);

    // --- Stage 4: SSH Public-Key Authentication ---

    public static string GetAuthorizedKeysPath(LocalUserAccount account) =>
        account.IsAdministrator
            ? AdminAuthorizedKeysPath
            : Path.Combine(@"C:\Users", account.Username, ".ssh", "authorized_keys");

    public async Task<ParsedPublicKey> AuthorizePublicKeyAsync(
        string publicKeyLine,
        LocalUserAccount targetAccount,
        string label,
        AgentSetupState state,
        CancellationToken ct)
    {
        var parsed = PublicKeyParser.Parse(publicKeyLine);
        if (!parsed.IsValid || parsed.Key is null)
            throw new ArgumentException(parsed.Error ?? "Invalid SSH public key.");

        var path = GetAuthorizedKeysPath(targetAccount);
        var dir = Path.GetDirectoryName(path)!;
        fs.CreateDirectory(dir);

        var existing = fs.FileExists(path) ? await fs.ReadAllTextAsync(path, ct) : "";
        var formatted = PublicKeyParser.FormatHhjLine(parsed.Key, DateOnly.FromDateTime(DateTime.UtcNow), label);
        var (updated, added) = PublicKeyParser.MergeAuthorizedKeys(existing, formatted, parsed.Key);

        if (added || !fs.FileExists(path))
        {
            await fs.WriteAllTextAsync(path, updated, ct);
        }

        if (targetAccount.IsAdministrator)
            acls.ApplyAdministratorsAuthorizedKeysAcl(path);
        else
            acls.ApplyUserAuthorizedKeysAcl(path, targetAccount.Username);

        if (!state.AddedAuthorizedKeys.Any(k =>
                string.Equals(k.FilePath, path, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(k.FingerprintSha256, parsed.Key.FingerprintSha256, StringComparison.Ordinal)))
        {
            state.AddedAuthorizedKeys.Add(new AddedAuthorizedKeyRecord
            {
                FilePath = path,
                FingerprintSha256 = parsed.Key.FingerprintSha256,
                Username = targetAccount.Username,
                AddedUtc = DateTimeOffset.UtcNow,
            });
            await SaveStateAsync(state, ct);
        }

        logger.LogInformation("Authorized SSH key SHA256:{Fingerprint} for {User} at {Path} (added={Added}).",
            parsed.Key.FingerprintSha256, targetAccount.Username, path, added);

        return parsed.Key;
    }

    public async Task<IReadOnlyList<AuthorizedKeyEntry>> ListHhjKeysAsync(LocalUserAccount targetAccount, CancellationToken ct)
    {
        var path = GetAuthorizedKeysPath(targetAccount);
        if (!fs.FileExists(path)) return [];
        var content = await fs.ReadAllTextAsync(path, ct);
        return PublicKeyParser.ListHhjKeys(content);
    }

    public async Task<int> RevokeHhjKeyAsync(LocalUserAccount targetAccount, string fingerprintSha256, AgentSetupState state, CancellationToken ct)
    {
        var path = GetAuthorizedKeysPath(targetAccount);
        if (!fs.FileExists(path)) return 0;

        var content = await fs.ReadAllTextAsync(path, ct);
        var (updated, removed) = PublicKeyParser.RevokeHhjKeys(content, fingerprintSha256);
        if (removed > 0)
        {
            await fs.WriteAllTextAsync(path, updated, ct);
            if (targetAccount.IsAdministrator) acls.ApplyAdministratorsAuthorizedKeysAcl(path);
            else acls.ApplyUserAuthorizedKeysAcl(path, targetAccount.Username);

            state.AddedAuthorizedKeys.RemoveAll(k =>
                string.Equals(k.FilePath, path, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(k.FingerprintSha256, fingerprintSha256, StringComparison.Ordinal));
            await SaveStateAsync(state, ct);
            logger.LogInformation("Revoked {Count} SSH key(s) with fingerprint SHA256:{Fingerprint}.", removed, fingerprintSha256);
        }
        return removed;
    }

    // --- Stage 5: Firewall ---

    public async Task ApplyFirewallPlanAsync(
        FirewallPlan plan,
        IReadOnlyList<string> broadRuleNamesToDisable,
        AgentSetupState state,
        CancellationToken ct)
    {
        if (plan.Action != HhjRuleAction.NoChange)
        {
            var script = FirewallReconciler.BuildApplyScript(plan.Desired);
            var res = await RunPowerShellAsync(script, TimeSpan.FromSeconds(20), ct);
            if (res.ExitCode != 0)
                throw new InvalidOperationException($"Failed to configure firewall rule: {res.StdErr}".Trim());
            state.FirewallRuleCreatedByHhj = true;
            logger.LogInformation("Applied firewall rule '{Rule}' ({Action}).", plan.Desired.Name, plan.Action);
        }

        foreach (var ruleName in broadRuleNamesToDisable)
        {
            var res = await RunPowerShellAsync(FirewallReconciler.BuildDisableRuleScript(ruleName), TimeSpan.FromSeconds(15), ct);
            if (res.ExitCode != 0)
            {
                logger.LogWarning("Could not disable broad firewall rule '{Rule}': {Err}", ruleName, res.StdErr);
                continue;
            }
            if (!state.DisabledFirewallRules.Any(r => string.Equals(r.Name, ruleName, StringComparison.OrdinalIgnoreCase)))
            {
                state.DisabledFirewallRules.Add(new DisabledFirewallRuleRecord { Name = ruleName, WasEnabled = true });
            }
            logger.LogInformation("Disabled broad firewall rule '{Rule}'.", ruleName);
        }

        await SaveStateAsync(state, ct);
    }

    // --- Stage 6 & CLI: Disable / Rollback & Status ---

    public async Task DisableRemoteAccessAsync(DisableOptions options, CancellationToken ct)
    {
        var state = await LoadStateAsync(ct);

        if (options.RemoveHhjFirewallRule)
        {
            await RunPowerShellAsync(FirewallReconciler.BuildRemoveHhjRuleScript(), TimeSpan.FromSeconds(15), ct);
            state.FirewallRuleCreatedByHhj = false;
        }

        if (options.ReEnablePreviouslyDisabledRules)
        {
            foreach (var r in state.DisabledFirewallRules.Where(x => x.WasEnabled).ToList())
            {
                await RunPowerShellAsync(FirewallReconciler.BuildEnableRuleScript(r.Name), TimeSpan.FromSeconds(15), ct);
                state.DisabledFirewallRules.Remove(r);
            }
        }

        if (options.RemoveHhjAuthorizedKeys)
        {
            var paths = state.AddedAuthorizedKeys.Select(k => k.FilePath)
                .Append(AdminAuthorizedKeysPath)
                .Distinct(StringComparer.OrdinalIgnoreCase);
            foreach (var p in paths)
            {
                if (!fs.FileExists(p)) continue;
                var content = await fs.ReadAllTextAsync(p, ct);
                var (updated, removed) = PublicKeyParser.RevokeHhjKeys(content, fingerprintSha256: null);
                if (removed > 0) await fs.WriteAllTextAsync(p, updated, ct);
            }
            state.AddedAuthorizedKeys.Clear();
        }

        if (options.RestoreDefaultShell && state.DefaultShellChangedByHhj)
        {
            if (state.DefaultShellPreviouslyExisted && state.DefaultShellPreviousValue is not null)
                registry.SetString(RegistryHiveKind.LocalMachine, OpenSshRegKey, DefaultShellValueName, state.DefaultShellPreviousValue);
            else
                registry.DeleteValue(RegistryHiveKind.LocalMachine, OpenSshRegKey, DefaultShellValueName);

            state.DefaultShellChangedByHhj = false;
        }

        if (options.StopAndRestoreSshd)
        {
            var svc = services.GetService("sshd");
            if (svc.Exists)
            {
                if (string.Equals(svc.Status, "Running", StringComparison.OrdinalIgnoreCase))
                    await services.StopAsync("sshd", ct);

                var targetStart = options.DisableSshdEntirely
                    ? "Disabled"
                    : (state.SshdOriginalStartType ?? "Manual");
                await services.SetStartTypeAsync("sshd", targetStart, ct);
            }
        }

        if (options.UninstallOpenSshIfInstalledByHhj && state.OpenSshInstalledByHhj)
        {
            await RunPowerShellAsync("Remove-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null",
                TimeSpan.FromMinutes(10), ct);
            state.OpenSshInstalledByHhj = false;
        }

        if (options.LogoutTailscale && fs.FileExists(PreCheckEvaluator.TailscaleExePath))
        {
            await LogoutTailscaleAsync(ct);
        }

        await SaveStateAsync(state, ct);
        logger.LogInformation("Remote access disable/rollback completed.");
    }

    public async Task<string> GetStatusJsonAsync(CancellationToken ct)
    {
        var sshd = services.GetService("sshd");
        var ts = await GetTailscaleStatusAsync(ct);
        var state = await LoadStateAsync(ct);
        var payload = new
        {
            computerName = privileges.GetComputerName(),
            sshdExists = sshd.Exists,
            sshdStatus = sshd.Status,
            sshdStartType = sshd.StartType,
            tailscaleState = ts?.BackendState,
            tailscaleDns = ts?.SelfDnsName,
            tailscaleIps = ts?.SelfIps,
            authorizedKeyCount = state.AddedAuthorizedKeys.Count,
            firewallRuleManaged = state.FirewallRuleCreatedByHhj,
        };
        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }

    private Task<ProcessRunResult> RunPowerShellAsync(string script, TimeSpan timeout, CancellationToken ct)
    {
        var encoded = FirewallReconciler.ToEncodedCommand(script);
        return process.RunAsync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], timeout, ct);
    }
}
