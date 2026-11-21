using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;
using HHJ.RemoteManager.Core.Connections;
using HHJ.RemoteManager.Core.Ssh;
using Microsoft.Extensions.Logging;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace HHJ.RemoteManager.Infrastructure.Ssh;

public sealed class SshNetSessionFactory(ILoggerFactory loggerFactory) : ISshSessionFactory
{
    private readonly ILogger<SshNetSessionFactory> _logger = loggerFactory.CreateLogger<SshNetSessionFactory>();

    public async Task<HostKeyInfo> ProbeHostKeyAsync(string host, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        HostKeyInfo? captured = null;
        var auth = new NoneAuthenticationMethod("probe");
        var info = new ConnectionInfo(host, port, "probe", auth) { Timeout = timeout };

        using var client = new SshClient(info);
        client.HostKeyReceived += (_, e) =>
        {
            captured = ToHostKeyInfo(e);
            // Reject right after capturing the host key so no authentication is attempted.
            e.CanTrust = false;
        };

        try
        {
            await client.ConnectAsync(cancellationToken);
        }
        catch (Exception ex) when (captured is not null && ex is SshConnectionException or SshException)
        {
            return captured;
        }
        catch (Exception ex)
        {
            throw new SshConnectException(Classify(ex, hostKeyOutcome: null), ex);
        }

        return captured ?? throw new SshConnectException(new ConnectionFailure(FailureKind.SshUnavailable, "The server did not present an SSH host key."));
    }

    public async Task<ISshSession> ConnectAsync(SshConnectionRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        using var keyMaterial = await request.PrivateKeyProvider(cancellationToken);
        using var keyStream = new MemoryStream(keyMaterial.KeyBytes, writable: false);
        PrivateKeyFile keyFile;
        try
        {
            keyFile = string.IsNullOrEmpty(keyMaterial.Passphrase)
                ? new PrivateKeyFile(keyStream)
                : new PrivateKeyFile(keyStream, keyMaterial.Passphrase);
        }
        catch (Exception ex) when (ex is SshPassPhraseNullOrEmptyException or SshException or FormatException)
        {
            throw new SshConnectException(
                new ConnectionFailure(FailureKind.KeyUnavailable, "The SSH private key could not be unlocked or parsed.", ex.Message), ex);
        }

        var connInfo = new PrivateKeyConnectionInfo(request.Host, request.Port, request.Username, keyFile)
        {
            Timeout = request.ConnectTimeout,
        };

        var client = new SshClient(connInfo)
        {
            KeepAliveInterval = request.KeepAliveInterval,
        };

        HostKeyInfo? presented = null;
        FailureKind? hostKeyOutcome = null;

        client.HostKeyReceived += (_, e) =>
        {
            presented = ToHostKeyInfo(e);
            if (request.ExpectedHostKey is null)
            {
                hostKeyOutcome = FailureKind.HostKeyUntrusted;
                e.CanTrust = false;
                return;
            }

            var matches = string.Equals(request.ExpectedHostKey.Algorithm, presented.Algorithm, StringComparison.OrdinalIgnoreCase) &&
                          string.Equals(request.ExpectedHostKey.FingerprintSha256, presented.FingerprintSha256, StringComparison.Ordinal);
            if (!matches)
            {
                hostKeyOutcome = FailureKind.HostKeyMismatch;
                e.CanTrust = false;
                return;
            }

            e.CanTrust = true;
        };

        try
        {
            await client.ConnectAsync(cancellationToken);
            if (presented is null)
            {
                client.Dispose();
                throw new SshConnectException(new ConnectionFailure(FailureKind.SshUnavailable, "No host key was received."));
            }

            _logger.LogInformation("SSH connected to {Host}:{Port} ({Server})",
                request.Host, request.Port, client.ConnectionInfo.ServerVersion);

            return new SshNetSession(client, presented, loggerFactory.CreateLogger<SshNetSession>());
        }
        catch (SshConnectException)
        {
            client.Dispose();
            throw;
        }
        catch (Exception ex)
        {
            client.Dispose();
            throw new SshConnectException(Classify(ex, hostKeyOutcome, presented), ex);
        }
    }

    private static HostKeyInfo ToHostKeyInfo(HostKeyEventArgs e)
    {
        // Compute standard OpenSSH unpadded base64 SHA-256 over the raw host key blob.
        var hash = SHA256.HashData(e.HostKey);
        var fp = Convert.ToBase64String(hash).TrimEnd('=');
        return new HostKeyInfo(e.HostKeyName, fp);
    }

    internal static ConnectionFailure Classify(Exception ex, FailureKind? hostKeyOutcome, HostKeyInfo? presented = null)
    {
        if (hostKeyOutcome == FailureKind.HostKeyUntrusted)
        {
            return new ConnectionFailure(FailureKind.HostKeyUntrusted,
                "This device's SSH host key is not yet trusted. Verify the fingerprint before connecting.",
                Detail: presented?.Display, PresentedHostKey: presented);
        }
        if (hostKeyOutcome == FailureKind.HostKeyMismatch)
        {
            return new ConnectionFailure(FailureKind.HostKeyMismatch,
                "The remote SSH host key has changed since it was last trusted. Confirm this is expected (e.g. OpenSSH reinstalled) before trusting the new key.",
                Detail: presented?.Display, PresentedHostKey: presented);
        }
        if (ex is OperationCanceledException)
        {
            return new ConnectionFailure(FailureKind.Cancelled, "Connection cancelled.");
        }
        if (ex is SshAuthenticationException)
        {
            return new ConnectionFailure(FailureKind.AuthenticationFailed,
                "SSH authentication failed. Verify the username and that the matching public key is authorized on the endpoint.",
                ex.Message);
        }
        if (ex is SshOperationTimeoutException or TimeoutException)
        {
            return new ConnectionFailure(FailureKind.Timeout,
                "Timed out waiting for the remote computer. Check that it is powered on and Tailscale is connected.",
                ex.Message);
        }

        var sock = FindSocketException(ex);
        if (sock is not null)
        {
            return sock.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => new ConnectionFailure(FailureKind.SshUnavailable,
                    "The remote computer is reachable, but SSH refused the connection. Check that the sshd service is running and the firewall allows Tailscale.",
                    sock.Message),
                SocketError.HostNotFound or SocketError.NoData or SocketError.TryAgain => new ConnectionFailure(FailureKind.VpnUnreachable,
                    "Could not resolve the device hostname. Check MagicDNS and Tailscale connectivity.",
                    sock.Message),
                SocketError.TimedOut => new ConnectionFailure(FailureKind.Timeout,
                    "Connection timed out. The remote computer may be offline or behind a blocking network.",
                    sock.Message),
                _ => new ConnectionFailure(FailureKind.VpnUnreachable,
                    "The remote computer is unreachable over the VPN.",
                    sock.Message),
            };
        }

        return new ConnectionFailure(FailureKind.Unknown, ex.Message, ex.ToString());
    }

    private static SocketException? FindSocketException(Exception? ex)
    {
        while (ex is not null)
        {
            if (ex is SocketException s) return s;
            ex = ex.InnerException;
        }
        return null;
    }
}

internal sealed class SshNetSession : ISshSession
{
    private readonly SshClient _client;
    private readonly ILogger<SshNetSession> _logger;
    private int _disposed;

    public SshNetSession(SshClient client, HostKeyInfo hostKey, ILogger<SshNetSession> logger)
    {
        _client = client;
        HostKey = hostKey;
        _logger = logger;
        _client.ErrorOccurred += OnClientError;
    }

    public bool IsConnected => Volatile.Read(ref _disposed) == 0 && _client.IsConnected;
    public HostKeyInfo HostKey { get; }
    public string ServerVersion => _client.ConnectionInfo.ServerVersion ?? "SSH-2.0";

    public event EventHandler<Exception?>? Disconnected;

    private void OnClientError(object? sender, ExceptionEventArgs e)
    {
        _logger.LogWarning(e.Exception, "SSH transport error");
        Disconnected?.Invoke(this, e.Exception);
    }

    public async Task<SshCommandResult> RunAsync(string commandText, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        using var cmd = _client.CreateCommand(commandText);
        cmd.CommandTimeout = timeout;
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        var sw = Stopwatch.StartNew();
        try
        {
            await cmd.ExecuteAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"SSH command timed out after {timeout.TotalSeconds:0.#}s.");
        }
        sw.Stop();

        return new SshCommandResult(cmd.ExitStatus ?? -1, cmd.Result, cmd.Error, sw.Elapsed);
    }

    public Task<IShellChannel> OpenShellAsync(int columns, int rows, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();

        var stream = _client.CreateShellStream(
            "xterm-256color",
            (uint)Math.Max(columns, 20),
            (uint)Math.Max(rows, 5),
            0, 0, 65536);

        return Task.FromResult<IShellChannel>(new SshNetShellChannel(stream));
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _client.ErrorOccurred -= OnClientError;
            try { if (_client.IsConnected) _client.Disconnect(); } catch { }
            _client.Dispose();
        }
        return ValueTask.CompletedTask;
    }
}

internal sealed class SshNetShellChannel : IShellChannel
{
    private readonly ShellStream _stream;
    private int _disposed;

    public SshNetShellChannel(ShellStream stream)
    {
        _stream = stream;
        _stream.DataReceived += OnData;
        _stream.Closed += OnClosed;
    }

    public bool IsOpen => Volatile.Read(ref _disposed) == 0 && _stream.CanRead && _stream.CanWrite;

    public event EventHandler<ReadOnlyMemory<byte>>? DataReceived;
    public event EventHandler? Closed;

    private void OnData(object? sender, ShellDataEventArgs e)
    {
        if (e.Data is { Length: > 0 })
            DataReceived?.Invoke(this, e.Data);
    }

    private void OnClosed(object? sender, EventArgs e) => Closed?.Invoke(this, EventArgs.Empty);

    public async Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _disposed) != 0) return;
        await _stream.WriteAsync(data, cancellationToken);
        _stream.Flush();
    }

    public void Resize(int columns, int rows)
    {
        if (Volatile.Read(ref _disposed) != 0) return;
        try
        {
            _stream.ChangeWindowSize((uint)Math.Max(columns, 20), (uint)Math.Max(rows, 5), 0, 0);
        }
        catch { /* Channel may already be closing */ }
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _stream.DataReceived -= OnData;
            _stream.Closed -= OnClosed;
            _stream.Dispose();
        }
        return ValueTask.CompletedTask;
    }
}
