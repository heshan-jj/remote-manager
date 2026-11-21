using System.Net.Sockets;
using HHJ.RemoteManager.Core.Connections;
using HHJ.RemoteManager.Core.Devices;
using HHJ.RemoteManager.Core.Security;
using HHJ.RemoteManager.Infrastructure.Persistence;
using HHJ.RemoteManager.Infrastructure.Security;
using HHJ.RemoteManager.Infrastructure.Ssh;
using Renci.SshNet.Common;
using Xunit;

namespace HHJ.Infrastructure.Tests;

public sealed class InfrastructureTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), "hhj-infra-tests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_tempDir)) Directory.Delete(_tempDir, recursive: true);
    }

    [Fact]
    public void OpenSshKeyGenerator_GeneratesValidEcdsaP256KeyAndFingerprint()
    {
        var pair = OpenSshKeyGenerator.GenerateEcdsaP256("unit-test");
        Assert.Equal("ecdsa-sha2-nistp256", pair.Algorithm);
        Assert.Contains("BEGIN EC PRIVATE KEY", pair.PrivateKeyPem);
        Assert.StartsWith("ecdsa-sha2-nistp256 AAAA", pair.PublicKeyLine);
        Assert.False(string.IsNullOrWhiteSpace(pair.FingerprintSha256));
    }

    [Fact]
    public async Task JsonSshKeyStore_GeneratesLoadsAndDeletesKeySafely()
    {
        var protector = new XorFakeProtector();
        var creds = new InMemoryCredentialStore();
        var store = new JsonSshKeyStore(_tempDir, protector, creds);

        var created = await store.GenerateAsync("Laptop Key");
        Assert.Single(await store.ListAsync());
        Assert.True(File.Exists(created.PrivateKeyPath));

        using (var mat = await store.LoadPrivateKeyAsync(created.Id))
        {
            Assert.NotEmpty(mat.KeyBytes);
            Assert.Contains("BEGIN EC PRIVATE KEY", System.Text.Encoding.UTF8.GetString(mat.KeyBytes));
        }

        await store.DeleteAsync(created.Id);
        Assert.Empty(await store.ListAsync());
        Assert.False(File.Exists(created.PrivateKeyPath));
    }

    [Fact]
    public async Task JsonDeviceRepository_RoundTripsProfilesAtomically()
    {
        var repo = new JsonDeviceRepository(Path.Combine(_tempDir, "devices.json"));
        var dev = new DeviceProfile
        {
            DisplayName = "Brother-PC",
            Address = "100.64.1.2",
            Port = 22,
            Username = "heshan",
            KeyId = "k1",
            HostKey = new PinnedHostKey("ssh-ed25519", "fp123", DateTimeOffset.UtcNow),
        };

        await repo.SaveAsync([dev]);
        var loaded = await repo.LoadAsync();
        Assert.Single(loaded);
        Assert.Equal("Brother-PC", loaded[0].DisplayName);
        Assert.Equal("fp123", loaded[0].HostKey?.FingerprintSha256);
    }

    [Fact]
    public void SshFailureClassification_DistinguishesAuthNetworkSshAndHostKey()
    {
        Assert.Equal(FailureKind.AuthenticationFailed,
            SshNetSessionFactory.Classify(new SshAuthenticationException("denied"), null).Kind);
        Assert.Equal(FailureKind.SshUnavailable,
            SshNetSessionFactory.Classify(new SocketException((int)SocketError.ConnectionRefused), null).Kind);
        Assert.Equal(FailureKind.VpnUnreachable,
            SshNetSessionFactory.Classify(new SocketException((int)SocketError.HostNotFound), null).Kind);
        Assert.Equal(FailureKind.Timeout,
            SshNetSessionFactory.Classify(new SshOperationTimeoutException("timeout"), null).Kind);
        Assert.Equal(FailureKind.HostKeyMismatch,
            SshNetSessionFactory.Classify(new SshConnectionException("mismatch"), FailureKind.HostKeyMismatch, new HostKeyInfo("ssh-ed25519", "new")).Kind);
    }

    private sealed class XorFakeProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext.Select(b => (byte)(b ^ 0x5A)).ToArray();
        public byte[] Unprotect(byte[] ciphertext) => ciphertext.Select(b => (byte)(b ^ 0x5A)).ToArray();
    }

    private sealed class InMemoryCredentialStore : ICredentialStore
    {
        private readonly Dictionary<string, string> _map = [];
        public void Write(string target, string userName, string secret) => _map[target] = secret;
        public string? Read(string target) => _map.GetValueOrDefault(target);
        public bool Delete(string target) => _map.Remove(target);
    }
}
