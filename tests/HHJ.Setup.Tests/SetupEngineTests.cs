using System.Buffers.Binary;
using System.Text;
using HHJ.Agent.Setup.Engine.Abstractions;
using HHJ.Agent.Setup.Engine.Engine;
using HHJ.Agent.Setup.Engine.Firewall;
using HHJ.Agent.Setup.Engine.OpenSsh;
using HHJ.Agent.Setup.Engine.State;
using HHJ.Agent.Setup.Engine.Tailscale;
using HHJ.Agent.Setup.Engine.Validation;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace HHJ.Setup.Tests;

public sealed class SetupEngineTests
{
    // Generated and verified via `ssh-keygen -t ed25519` + `ssh-keygen -lf`
    private const string RealEd25519Pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJb3RuOxfhHyV+FBuoBwhdnUqVrz8qNafJZvLABnrvq4 test@hhj";
    private const string ExpectedEd25519Fp = "YV1vhAodcl6w9Yr/dIOFx/jun0+gMqNOUoLEzJoSguA";

    [Fact]
    public void PublicKeyParser_ComputesExactOpenSshFingerprintAndRejectsInvalidKeys()
    {
        var ok = PublicKeyParser.Parse(RealEd25519Pub);
        Assert.True(ok.IsValid);
        Assert.Equal("ssh-ed25519", ok.Key!.KeyType);
        Assert.Equal(ExpectedEd25519Fp, ok.Key.FingerprintSha256);

        var priv = PublicKeyParser.Parse("-----BEGIN OPENSSH PRIVATE KEY-----");
        Assert.False(priv.IsValid);
        Assert.Contains("PRIVATE", priv.Error!, StringComparison.OrdinalIgnoreCase);

        var weakRsa = BuildRsaPublicKeyLine(2048);
        Assert.False(PublicKeyParser.Parse(weakRsa).IsValid);

        var strongRsa = BuildRsaPublicKeyLine(3072);
        var strongParsed = PublicKeyParser.Parse(strongRsa);
        Assert.True(strongParsed.IsValid);
        Assert.Equal(3072, strongParsed.Key!.RsaKeyBits);
    }

    [Fact]
    public void PublicKeyParser_MergeIsIdempotentAndRevokePreservesUserKeys()
    {
        var parsed = PublicKeyParser.Parse(RealEd25519Pub).Key!;
        var hhjLine = PublicKeyParser.FormatHhjLine(parsed, new DateOnly(2026, 11, 20), "laptop");

        const string existing = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockOtherUserKey1234567890 user-own-key\r\n";
        var (merged1, added1) = PublicKeyParser.MergeAuthorizedKeys(existing, hhjLine, parsed);
        Assert.True(added1);

        var (merged2, added2) = PublicKeyParser.MergeAuthorizedKeys(merged1, hhjLine, parsed);
        Assert.False(added2);
        Assert.Equal(merged1, merged2);

        var listed = PublicKeyParser.ListHhjKeys(merged2);
        Assert.Single(listed);
        Assert.Equal(ExpectedEd25519Fp, listed[0].FingerprintSha256);

        var (revoked, count) = PublicKeyParser.RevokeHhjKeys(merged2, ExpectedEd25519Fp);
        Assert.Equal(1, count);
        Assert.Contains("user-own-key", revoked);
        Assert.DoesNotContain("hhj-remote-manager", revoked);
    }

    [Fact]
    public void SshdConfigParser_ParsesPortAuthAndMatchAdministrators()
    {
        const string cfg = """
            # Comment
            port 2222
            PubkeyAuthentication yes
            PasswordAuthentication no

            Match Group administrators
                AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
            """;
        var parsed = SshdConfigParser.Parse(cfg);
        Assert.Equal(2222, parsed.Port);
        Assert.True(parsed.PubkeyAuthentication);
        Assert.False(parsed.PasswordAuthentication);
        Assert.True(parsed.HasMatchAdministratorsBlock);
        Assert.Equal("__PROGRAMDATA__/ssh/administrators_authorized_keys", parsed.AdministratorsAuthorizedKeysFile);
    }

    [Fact]
    public void FirewallReconciler_DetectsCreateNoChangeUpdateAndBroadRules()
    {
        var existingBroad = new FirewallRuleSnapshot(
            "OpenSSH-Server-In-TCP", "OpenSSH Server", true, "Inbound", "Allow",
            "TCP", "22", "Any", @"C:\Windows\System32\OpenSSH\sshd.exe", "Any");

        var plan1 = FirewallReconciler.Reconcile([existingBroad], 22, PreCheckEvaluator.SshdExePath, "Tailscale");
        Assert.Equal(HhjRuleAction.Create, plan1.Action);
        Assert.Single(plan1.BroadRules);
        Assert.Equal("OpenSSH-Server-In-TCP", plan1.BroadRules[0].Name);

        var matchingHhj = new FirewallRuleSnapshot(
            FirewallReconciler.HhjRuleName, FirewallReconciler.HhjRuleGroup, true, "Inbound", "Allow",
            "TCP", "22", "100.64.0.0/10, fd7a:115c:a1e0::/48", PreCheckEvaluator.SshdExePath, "Tailscale");

        var plan2 = FirewallReconciler.Reconcile([matchingHhj], 22, PreCheckEvaluator.SshdExePath, "Tailscale");
        Assert.Equal(HhjRuleAction.NoChange, plan2.Action);
        Assert.Empty(plan2.BroadRules);

        var plan3 = FirewallReconciler.Reconcile([matchingHhj], 2222, PreCheckEvaluator.SshdExePath, null);
        Assert.Equal(HhjRuleAction.UpdateInPlace, plan3.Action);
        Assert.Single(plan3.Warnings);
    }

    [Fact]
    public void TailscaleParser_ParsesRealisticStatusAndMasksSecrets()
    {
        const string json = """
            {
              "BackendState": "Running",
              "AuthURL": "",
              "Self": {
                "UserID": 42,
                "DNSName": "brother-pc.tail1234.ts.net.",
                "TailscaleIPs": ["100.101.102.103", "fd7a:115c:a1e0::1"]
              },
              "CurrentTailnet": {
                "Name": "heshan@example.com",
                "MagicDNSSuffix": "tail1234.ts.net"
              },
              "User": {
                "42": { "LoginName": "heshan@example.com" }
              }
            }
            """;
        var status = TailscaleParser.ParseStatusJson(json);
        Assert.Equal("Running", status.BackendState);
        Assert.Equal("brother-pc.tail1234.ts.net", status.SelfDnsName);
        Assert.Equal(["100.101.102.103", "fd7a:115c:a1e0::1"], status.SelfIps);
        Assert.Equal("heshan@example.com", status.LoggedInUser);

        Assert.Equal("https://login.tailscale.com/a/12345abc",
            TailscaleParser.ExtractAuthUrl("To authenticate, visit:\n\thttps://login.tailscale.com/a/12345abc\n"));

        Assert.Equal("tailscale up --auth-key=***REDACTED***",
            TailscaleParser.MaskSecret("tailscale up --auth-key=tskey-auth-secret", "tskey-auth-secret"));

        Assert.True(TailscaleParser.IsValidTailscaleHostname("brother-pc-01"));
        Assert.False(TailscaleParser.IsValidTailscaleHostname("-bad"));
    }

    [Fact]
    public async Task SetupOrchestrator_IsIdempotentAndRollsBackCleanly()
    {
        var fs = new FakeFileSystem();
        var reg = new FakeRegistry();
        var svc = new FakeServiceManager();
        var proc = new FakeProcessRunner();
        var net = new FakeNetworkProbe();
        var priv = new FakePrivilegeChecker();
        var acls = new FakeAclManager();

        var orch = new SetupOrchestrator(proc, fs, reg, svc, net, priv,
            new FakeDownloader(), new FakeVerifier(), acls, NullLogger<SetupOrchestrator>.Instance);

        var preCheck = new PreCheckEvaluator(priv, reg, fs, svc, net, proc);
        var report = await preCheck.EvaluateAsync(CancellationToken.None);
        Assert.True(report.CanProceed);

        var state = await orch.LoadStateAsync(CancellationToken.None);
        await orch.ConfigureOpenSshAsync("OpenSSH.Server~~~~0.0.1.0", true, state, CancellationToken.None);
        var user = priv.GetLocalUsers()[0];
        await orch.AuthorizePublicKeyAsync(RealEd25519Pub, user, "laptop", state, CancellationToken.None);
        // Second run must not duplicate keys
        await orch.AuthorizePublicKeyAsync(RealEd25519Pub, user, "laptop", state, CancellationToken.None);

        var keys = await orch.ListHhjKeysAsync(user, CancellationToken.None);
        Assert.Single(keys);
        Assert.Equal(SetupOrchestrator.PowerShellExePath,
            reg.GetString(RegistryHiveKind.LocalMachine, SetupOrchestrator.OpenSshRegKey, SetupOrchestrator.DefaultShellValueName));

        // Rollback
        await orch.DisableRemoteAccessAsync(new DisableOptions(), CancellationToken.None);
        Assert.Empty(await orch.ListHhjKeysAsync(user, CancellationToken.None));
        Assert.False(reg.ValueExists(RegistryHiveKind.LocalMachine, SetupOrchestrator.OpenSshRegKey, SetupOrchestrator.DefaultShellValueName));
    }

    private static string BuildRsaPublicKeyLine(int bits)
    {
        var byteLen = bits / 8;
        var modulus = new byte[byteLen + 1];
        modulus[0] = 0x00;
        modulus[1] = 0x80; // MSB set so bit count == bits
        using var ms = new MemoryStream();
        WriteSshBytes(ms, "ssh-rsa"u8);
        WriteSshBytes(ms, [0x01, 0x00, 0x01]);
        WriteSshBytes(ms, modulus);
        return $"ssh-rsa {Convert.ToBase64String(ms.ToArray())} rsa-test";
    }

    private static void WriteSshBytes(Stream s, ReadOnlySpan<byte> b)
    {
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(len, (uint)b.Length);
        s.Write(len);
        s.Write(b);
    }

    // --- Fakes ---
    private sealed class FakeFileSystem : IFileSystem
    {
        private readonly Dictionary<string, string> _files = new(StringComparer.OrdinalIgnoreCase);
        public bool FileExists(string path) => _files.ContainsKey(path);
        public bool DirectoryExists(string path) => true;
        public void CreateDirectory(string path) { }
        public Task<string> ReadAllTextAsync(string path, CancellationToken ct = default) => Task.FromResult(_files[path]);
        public Task WriteAllTextAsync(string path, string content, CancellationToken ct = default) { _files[path] = content; return Task.CompletedTask; }
        public void DeleteFile(string path) => _files.Remove(path);
    }

    private sealed class FakeRegistry : IRegistryReader
    {
        private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase)
        {
            [@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName"] = "Windows 11 Pro",
            [@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuild"] = "22631",
        };
        public string? GetString(RegistryHiveKind h, string k, string v) => _values.GetValueOrDefault($"{k}\\{v}");
        public int? GetDword(RegistryHiveKind h, string k, string v) => null;
        public bool ValueExists(RegistryHiveKind h, string k, string v) => _values.ContainsKey($"{k}\\{v}");
        public void SetString(RegistryHiveKind h, string k, string v, string val) => _values[$"{k}\\{v}"] = val;
        public void DeleteValue(RegistryHiveKind h, string k, string v) => _values.Remove($"{k}\\{v}");
    }

    private sealed class FakeServiceManager : IServiceManager
    {
        public ServiceSnapshot Snapshot { get; private set; } = new(true, "Stopped", "Manual");
        public ServiceSnapshot GetService(string name) => Snapshot;
        public Task SetStartTypeAsync(string name, string startType, CancellationToken ct) { Snapshot = Snapshot with { StartType = startType }; return Task.CompletedTask; }
        public Task StartAsync(string name, CancellationToken ct) { Snapshot = Snapshot with { Status = "Running" }; return Task.CompletedTask; }
        public Task StopAsync(string name, CancellationToken ct) { Snapshot = Snapshot with { Status = "Stopped" }; return Task.CompletedTask; }
    }

    private sealed class FakeProcessRunner : IProcessRunner
    {
        public Task<ProcessRunResult> RunAsync(string fileName, IReadOnlyList<string> args, TimeSpan timeout, CancellationToken ct) =>
            Task.FromResult(new ProcessRunResult(0, "{}", ""));
    }

    private sealed class FakeNetworkProbe : INetworkProbe
    {
        public bool IsNetworkAvailable() => true;
        public Task<bool> CanResolveDnsAsync(string hostName, CancellationToken ct) => Task.FromResult(true);
        public IReadOnlyCollection<int> GetActiveTcpListenerPorts() => [22];
        public Task<string?> ProbeSshBannerAsync(string host, int port, TimeSpan timeout, CancellationToken ct) => Task.FromResult<string?>("SSH-2.0-OpenSSH_for_Windows_9.5");
    }

    private sealed class FakePrivilegeChecker : IPrivilegeChecker
    {
        public bool IsAdministrator() => true;
        public string GetOsArchitecture() => "X64";
        public string GetComputerName() => "BROTHER-PC";
        public string GetCurrentUsername() => "heshan";
        public IReadOnlyList<LocalUserAccount> GetLocalUsers() => [new LocalUserAccount("heshan", true, true)];
    }

    private sealed class FakeAclManager : IAclManager
    {
        public void ApplyAdministratorsAuthorizedKeysAcl(string filePath) { }
        public void ApplyUserAuthorizedKeysAcl(string filePath, string username) { }
        public void ApplyAdminOnlyDirectoryAcl(string directoryPath) { }
    }

    private sealed class FakeDownloader : IPackageDownloader
    {
        public Task DownloadFileAsync(string url, string destinationPath, IProgress<double>? progress, CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class FakeVerifier : IAuthenticodeVerifier
    {
        public SignatureCheckResult VerifySignedByPublisher(string filePath, string expectedOrganization) => new(true, expectedOrganization, null);
    }
}
