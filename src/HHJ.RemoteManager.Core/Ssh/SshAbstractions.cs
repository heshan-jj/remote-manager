using HHJ.RemoteManager.Core.Connections;

namespace HHJ.RemoteManager.Core.Ssh;

/// <summary>Parameters for establishing an SSH session. Contains key material only in memory.</summary>
public sealed class SshConnectionRequest
{
    public required string Host { get; init; }
    public int Port { get; init; } = 22;
    public required string Username { get; init; }

    /// <summary>Loader that returns the private key (OpenSSH/PEM text) — invoked only during connect.</summary>
    public required Func<CancellationToken, Task<PrivateKeyMaterial>> PrivateKeyProvider { get; init; }

    /// <summary>Pinned host key. If null the connection is refused with <see cref="FailureKind.HostKeyUntrusted"/>.</summary>
    public HostKeyInfo? ExpectedHostKey { get; init; }

    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan KeepAliveInterval { get; init; } = TimeSpan.FromSeconds(20);
}

/// <summary>Decrypted private key held in memory for the duration of a connect attempt.</summary>
public sealed class PrivateKeyMaterial(byte[] keyBytes, string? passphrase) : IDisposable
{
    public byte[] KeyBytes { get; } = keyBytes;
    public string? Passphrase { get; } = passphrase;

    public void Dispose() => Array.Clear(KeyBytes);
}

public sealed record SshCommandResult(int ExitCode, string StdOut, string StdErr, TimeSpan Duration);

public interface ISshSessionFactory
{
    /// <summary>Connects and authenticates. Throws <see cref="SshConnectException"/> with a classified failure.</summary>
    Task<ISshSession> ConnectAsync(SshConnectionRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Connects only far enough to obtain the server host key (no authentication), so the
    /// administrator can verify the fingerprint before trusting it.
    /// </summary>
    Task<HostKeyInfo> ProbeHostKeyAsync(string host, int port, TimeSpan timeout, CancellationToken cancellationToken);
}

public interface ISshSession : IAsyncDisposable
{
    bool IsConnected { get; }
    HostKeyInfo HostKey { get; }
    string ServerVersion { get; }

    /// <summary>Raised when the transport drops unexpectedly.</summary>
    event EventHandler<Exception?>? Disconnected;

    /// <summary>Runs a non-interactive command (exec channel). Throws <see cref="TimeoutException"/> on timeout.</summary>
    Task<SshCommandResult> RunAsync(string commandText, TimeSpan timeout, CancellationToken cancellationToken);

    /// <summary>Opens an interactive PTY shell channel.</summary>
    Task<IShellChannel> OpenShellAsync(int columns, int rows, CancellationToken cancellationToken);
}

/// <summary>Interactive PTY channel used by the embedded terminal.</summary>
public interface IShellChannel : IAsyncDisposable
{
    event EventHandler<ReadOnlyMemory<byte>>? DataReceived;
    event EventHandler? Closed;
    bool IsOpen { get; }
    Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken);
    void Resize(int columns, int rows);
}
