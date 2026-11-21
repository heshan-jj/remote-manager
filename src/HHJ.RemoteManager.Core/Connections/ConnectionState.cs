namespace HHJ.RemoteManager.Core.Connections;

/// <summary>User-visible connection state of a managed device.</summary>
public enum ConnectionState
{
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    /// <summary>The SSH server rejected the key / account (network and SSH are fine).</summary>
    AuthenticationFailed,
    /// <summary>The address could not be resolved or reached (Tailscale down, device offline).</summary>
    VpnUnreachable,
    /// <summary>The host is reachable but nothing accepts SSH on the port (sshd stopped / blocked).</summary>
    SshUnavailable,
    /// <summary>Logged on, but Windows denied the requested operation.</summary>
    PermissionDenied,
    /// <summary>First connection: host key not yet trusted by the administrator.</summary>
    HostKeyUntrusted,
    /// <summary>The host key differs from the pinned key — possible re-install or MITM.</summary>
    HostKeyMismatch,
    /// <summary>Any other failure.</summary>
    Error,
}

public enum FailureKind
{
    None,
    AuthenticationFailed,
    VpnUnreachable,
    SshUnavailable,
    PermissionDenied,
    HostKeyUntrusted,
    HostKeyMismatch,
    Timeout,
    KeyUnavailable,
    Cancelled,
    Unknown,
}

/// <summary>Observed host key presented by the server.</summary>
public sealed record HostKeyInfo(string Algorithm, string FingerprintSha256)
{
    public string Display => $"{Algorithm} SHA256:{FingerprintSha256}";
}

/// <summary>A classified connection/command failure with a user-friendly explanation.</summary>
public sealed record ConnectionFailure(FailureKind Kind, string Message, string? Detail = null, HostKeyInfo? PresentedHostKey = null)
{
    public ConnectionState ToState() => Kind switch
    {
        FailureKind.AuthenticationFailed => ConnectionState.AuthenticationFailed,
        FailureKind.KeyUnavailable => ConnectionState.AuthenticationFailed,
        FailureKind.VpnUnreachable => ConnectionState.VpnUnreachable,
        FailureKind.Timeout => ConnectionState.VpnUnreachable,
        FailureKind.SshUnavailable => ConnectionState.SshUnavailable,
        FailureKind.PermissionDenied => ConnectionState.PermissionDenied,
        FailureKind.HostKeyUntrusted => ConnectionState.HostKeyUntrusted,
        FailureKind.HostKeyMismatch => ConnectionState.HostKeyMismatch,
        FailureKind.Cancelled => ConnectionState.Disconnected,
        _ => ConnectionState.Error,
    };

    /// <summary>Whether automatic reconnection makes sense (transient network problems only).</summary>
    public bool IsTransient => Kind is FailureKind.VpnUnreachable or FailureKind.Timeout or FailureKind.SshUnavailable or FailureKind.Unknown;
}

/// <summary>Raised by SSH infrastructure for classified failures.</summary>
public sealed class SshConnectException(ConnectionFailure failure, Exception? inner = null)
    : Exception(failure.Message, inner)
{
    public ConnectionFailure Failure { get; } = failure;
}

/// <summary>Raised when a remote command reports that Windows denied access.</summary>
public sealed class RemoteAccessDeniedException(string message) : Exception(message);

/// <summary>Raised when the remote script output cannot be parsed.</summary>
public sealed class TelemetryParseException(string message, Exception? inner = null) : Exception(message, inner);
