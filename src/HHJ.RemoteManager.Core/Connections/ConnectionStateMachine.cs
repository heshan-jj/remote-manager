namespace HHJ.RemoteManager.Core.Connections;

/// <summary>
/// Guards connection state transitions so that the UI can never show contradictory states
/// (e.g. "Connected" after the user pressed Disconnect while a connect was in flight).
/// Thread-safe.
/// </summary>
public sealed class ConnectionStateMachine
{
    private readonly Lock _gate = new();

    public ConnectionStateMachine(ConnectionState initial = ConnectionState.Disconnected) => State = initial;

    public ConnectionState State { get; private set; }

    public ConnectionFailure? LastFailure { get; private set; }

    public event EventHandler<ConnectionStateChangedEventArgs>? StateChanged;

    public static bool IsFailure(ConnectionState s) => s is ConnectionState.AuthenticationFailed
        or ConnectionState.VpnUnreachable or ConnectionState.SshUnavailable or ConnectionState.PermissionDenied
        or ConnectionState.HostKeyUntrusted or ConnectionState.HostKeyMismatch or ConnectionState.Error;

    public static bool IsAllowed(ConnectionState from, ConnectionState to)
    {
        if (from == to) return false;
        if (to == ConnectionState.Disconnected) return true; // user can always disconnect / cancel

        return from switch
        {
            ConnectionState.Disconnected => to is ConnectionState.Connecting,
            ConnectionState.Connecting => to is ConnectionState.Connected || IsFailure(to),
            ConnectionState.Connected => to is ConnectionState.Reconnecting or ConnectionState.Connecting,
            ConnectionState.Reconnecting => to is ConnectionState.Connected || IsFailure(to),
            _ when IsFailure(from) => to is ConnectionState.Connecting or ConnectionState.Reconnecting || (IsFailure(to)),
            _ => false,
        };
    }

    /// <summary>Attempts a transition; returns false (and changes nothing) if it is not allowed.</summary>
    public bool TryTransition(ConnectionState to, ConnectionFailure? failure = null)
    {
        ConnectionStateChangedEventArgs args;
        lock (_gate)
        {
            if (!IsAllowed(State, to)) return false;
            var from = State;
            State = to;
            LastFailure = IsFailure(to) ? failure : (to == ConnectionState.Connected ? null : LastFailure);
            args = new ConnectionStateChangedEventArgs(from, to, failure);
        }
        StateChanged?.Invoke(this, args);
        return true;
    }

    public bool Fail(ConnectionFailure failure) => TryTransition(failure.ToState(), failure);
}

public sealed record ConnectionStateChangedEventArgs(ConnectionState From, ConnectionState To, ConnectionFailure? Failure);
