using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HHJ.RemoteManager.Core.Security;
using HHJ.RemoteManager.Core.Ssh;
using Renci.SshNet;

namespace HHJ.RemoteManager.Infrastructure.Security;

/// <summary>
/// Manages SSH key metadata in <c>keys.json</c>. Generated private keys are encrypted with
/// <see cref="ISecretProtector"/> (DPAPI CurrentUser on Windows); imported external key files
/// are referenced in place and any passphrase is stored in <see cref="ICredentialStore"/>.
/// </summary>
public sealed class JsonSshKeyStore : ISshKeyStore
{
    private const string CredentialPrefix = "HHJRemoteManager:SshKey:";

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _rootDir;
    private readonly string _indexPath;
    private readonly string _keysDir;
    private readonly ISecretProtector _protector;
    private readonly ICredentialStore _credentials;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public JsonSshKeyStore(string rootDir, ISecretProtector protector, ICredentialStore credentials)
    {
        _rootDir = rootDir;
        _indexPath = Path.Combine(rootDir, "keys.json");
        _keysDir = Path.Combine(rootDir, "keys");
        _protector = protector;
        _credentials = credentials;
    }

    public async Task<IReadOnlyList<SshKeyInfo>> ListAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return await LoadIndexUnlockedAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<SshKeyInfo?> GetAsync(string id, CancellationToken cancellationToken = default)
    {
        var all = await ListAsync(cancellationToken);
        return all.FirstOrDefault(k => string.Equals(k.Id, id, StringComparison.OrdinalIgnoreCase));
    }

    public async Task<SshKeyInfo> GenerateAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(_keysDir);
            var id = Guid.NewGuid().ToString("N");
            var pair = OpenSshKeyGenerator.GenerateEcdsaP256($"hhj-{SanitizeComment(name)}");
            var pemBytes = Encoding.UTF8.GetBytes(pair.PrivateKeyPem);
            try
            {
                var protectedBytes = _protector.Protect(pemBytes);
                var blobPath = Path.Combine(_keysDir, id + ".dpapi");
                await File.WriteAllBytesAsync(blobPath, protectedBytes, cancellationToken);

                var info = new SshKeyInfo
                {
                    Id = id,
                    Name = name.Trim(),
                    Storage = SshKeyStorage.ManagedDpapi,
                    Algorithm = pair.Algorithm,
                    PublicKey = pair.PublicKeyLine,
                    FingerprintSha256 = pair.FingerprintSha256,
                    PrivateKeyPath = blobPath,
                    HasPassphrase = false,
                    CreatedUtc = DateTimeOffset.UtcNow,
                };

                var list = await LoadIndexUnlockedAsync(cancellationToken);
                list.Add(info);
                await SaveIndexUnlockedAsync(list, cancellationToken);
                return info;
            }
            finally
            {
                Array.Clear(pemBytes);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<SshKeyInfo> ImportAsync(string name, string privateKeyPath, string? passphrase, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyPath);
        if (!File.Exists(privateKeyPath))
            throw new FileNotFoundException("The selected SSH private key file does not exist.", privateKeyPath);

        using var keyFile = string.IsNullOrEmpty(passphrase)
            ? new PrivateKeyFile(privateKeyPath)
            : new PrivateKeyFile(privateKeyPath, passphrase);

        var hostAlg = keyFile.HostKeyAlgorithms.First();
        var pubBlob = hostAlg.Data;
        var algo = hostAlg.Name;
        var fp = Convert.ToBase64String(SHA256.HashData(pubBlob)).TrimEnd('=');
        var pubLine = $"{algo} {Convert.ToBase64String(pubBlob)} hhj-{SanitizeComment(name)}";

        await _gate.WaitAsync(cancellationToken);
        try
        {
            var id = Guid.NewGuid().ToString("N");
            if (!string.IsNullOrEmpty(passphrase))
            {
                _credentials.Write(CredentialPrefix + id, name.Trim(), passphrase);
            }

            var info = new SshKeyInfo
            {
                Id = id,
                Name = name.Trim(),
                Storage = SshKeyStorage.ExternalFile,
                Algorithm = algo,
                PublicKey = pubLine,
                FingerprintSha256 = fp,
                PrivateKeyPath = Path.GetFullPath(privateKeyPath),
                HasPassphrase = !string.IsNullOrEmpty(passphrase),
                CreatedUtc = DateTimeOffset.UtcNow,
            };

            var list = await LoadIndexUnlockedAsync(cancellationToken);
            list.Add(info);
            await SaveIndexUnlockedAsync(list, cancellationToken);
            return info;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task DeleteAsync(string id, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var list = await LoadIndexUnlockedAsync(cancellationToken);
            var target = list.FirstOrDefault(k => string.Equals(k.Id, id, StringComparison.OrdinalIgnoreCase));
            if (target is null) return;

            list.Remove(target);
            await SaveIndexUnlockedAsync(list, cancellationToken);

            if (target.Storage == SshKeyStorage.ManagedDpapi && File.Exists(target.PrivateKeyPath))
                File.Delete(target.PrivateKeyPath);

            if (target.HasPassphrase)
                _credentials.Delete(CredentialPrefix + target.Id);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<PrivateKeyMaterial> LoadPrivateKeyAsync(string id, CancellationToken cancellationToken = default)
    {
        var info = await GetAsync(id, cancellationToken)
                   ?? throw new KeyNotFoundException($"SSH key '{id}' was not found.");

        if (info.Storage == SshKeyStorage.ManagedDpapi)
        {
            var encrypted = await File.ReadAllBytesAsync(info.PrivateKeyPath, cancellationToken);
            var plaintext = _protector.Unprotect(encrypted);
            return new PrivateKeyMaterial(plaintext, null);
        }

        var raw = await File.ReadAllBytesAsync(info.PrivateKeyPath, cancellationToken);
        var passphrase = info.HasPassphrase ? _credentials.Read(CredentialPrefix + info.Id) : null;
        return new PrivateKeyMaterial(raw, passphrase);
    }

    private async Task<List<SshKeyInfo>> LoadIndexUnlockedAsync(CancellationToken ct)
    {
        if (!File.Exists(_indexPath)) return [];
        await using var stream = File.OpenRead(_indexPath);
        return await JsonSerializer.DeserializeAsync<List<SshKeyInfo>>(stream, JsonOptions, ct) ?? [];
    }

    private async Task SaveIndexUnlockedAsync(List<SshKeyInfo> list, CancellationToken ct)
    {
        Directory.CreateDirectory(_rootDir);
        var tmp = _indexPath + ".tmp";
        await using (var stream = File.Create(tmp))
        {
            await JsonSerializer.SerializeAsync(stream, list, JsonOptions, ct);
        }
        File.Move(tmp, _indexPath, overwrite: true);
    }

    private static string SanitizeComment(string s) =>
        new(s.Trim().Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '-').ToArray());
}
