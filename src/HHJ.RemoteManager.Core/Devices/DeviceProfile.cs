using System.Text.Json.Serialization;

namespace HHJ.RemoteManager.Core.Devices;

/// <summary>
/// A managed endpoint profile. Contains no secrets: the private key is referenced by id and
/// protected separately (DPAPI / Windows Credential Manager).
/// </summary>
public sealed class DeviceProfile
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Friendly name chosen by the administrator, e.g. "Brother-PC".</summary>
    public string DisplayName { get; set; } = "";

    /// <summary>Tailscale MagicDNS name or private (tailnet) IP address used to connect.</summary>
    public string Address { get; set; } = "";

    public int Port { get; set; } = 22;

    /// <summary>Authorized Windows account used for SSH logon.</summary>
    public string Username { get; set; } = "";

    /// <summary>Reference to an <see cref="Security.SshKeyInfo"/> managed by the key store.</summary>
    public string? KeyId { get; set; }

    /// <summary>Pinned host key, set only after the administrator explicitly trusts it.</summary>
    public PinnedHostKey? HostKey { get; set; }

    /// <summary>Computer name reported by the endpoint (informational, discovered on connect).</summary>
    public string? ReportedComputerName { get; set; }

    public DateTimeOffset? LastConnectedUtc { get; set; }
    public DateTimeOffset? LastTelemetryUtc { get; set; }

    public List<string> Tags { get; set; } = [];

    public string? Notes { get; set; }

    public DeviceProfile Clone() => new()
    {
        Id = Id,
        DisplayName = DisplayName,
        Address = Address,
        Port = Port,
        Username = Username,
        KeyId = KeyId,
        HostKey = HostKey is null ? null : HostKey with { },
        ReportedComputerName = ReportedComputerName,
        LastConnectedUtc = LastConnectedUtc,
        LastTelemetryUtc = LastTelemetryUtc,
        Tags = [.. Tags],
        Notes = Notes,
    };
}

/// <summary>SSH host key pinned for a device (algorithm + OpenSSH-style SHA256 fingerprint).</summary>
public sealed record PinnedHostKey(string Algorithm, string FingerprintSha256, DateTimeOffset TrustedUtc)
{
    [JsonIgnore]
    public string Display => $"{Algorithm} SHA256:{FingerprintSha256}";
}
