using HHJ.RemoteManager.Core.Remote;
using Microsoft.Extensions.Logging;

namespace HHJ.RemoteManager.Core.Telemetry;

/// <summary>
/// Periodically polls lightweight metrics from an endpoint without overlapping requests.
/// Supports pause/resume, configurable intervals (2, 5, 10, 30s), and clean cancellation.
/// </summary>
public sealed class TelemetryPoller : IAsyncDisposable
{
    public static readonly int[] SupportedIntervalsSeconds = [2, 5, 10, 30];

    private readonly RemoteEndpointClient _client;
    private readonly MetricsCalculator _calculator = new();
    private readonly ILogger _logger;
    private readonly TimeProvider _time;
    private readonly Lock _gate = new();

    private CancellationTokenSource? _cts;
    private Task? _loopTask;
    private int _intervalSeconds = 5;
    private volatile bool _paused;

    public TelemetryPoller(RemoteEndpointClient client, ILogger logger, TimeProvider? timeProvider = null)
    {
        _client = client;
        _logger = logger;
        _time = timeProvider ?? TimeProvider.System;
    }

    public int IntervalSeconds
    {
        get => _intervalSeconds;
        set
        {
            if (Array.IndexOf(SupportedIntervalsSeconds, value) < 0)
                throw new ArgumentOutOfRangeException(nameof(value), "Interval must be 2, 5, 10 or 30 seconds.");
            _intervalSeconds = value;
        }
    }

    public bool IsPaused
    {
        get => _paused;
        set => _paused = value;
    }

    public event EventHandler<MetricsSnapshot>? SampleReceived;
    public event EventHandler<Exception>? PollFailed;

    public void Start()
    {
        lock (_gate)
        {
            if (_loopTask is not null) return;
            _calculator.Reset();
            _cts = new CancellationTokenSource();
            _loopTask = RunLoopAsync(_cts.Token);
        }
    }

    public async Task StopAsync()
    {
        CancellationTokenSource? cts;
        Task? task;
        lock (_gate)
        {
            cts = _cts;
            task = _loopTask;
            _cts = null;
            _loopTask = null;
        }

        if (cts is not null)
        {
            await cts.CancelAsync();
            if (task is not null)
            {
                try { await task; }
                catch (OperationCanceledException) { }
            }
            cts.Dispose();
        }
    }

    private async Task RunLoopAsync(CancellationToken ct)
    {
        // Poll immediately on start, then wait for the configured interval.
        // Because we await each poll before waiting, requests never overlap.
        while (!ct.IsCancellationRequested)
        {
            if (!_paused)
            {
                try
                {
                    var (sample, rtt) = await _client.GetMetricsSampleAsync(ct);
                    var snapshot = _calculator.Compute(sample, _time.GetUtcNow(), rtt);
                    SampleReceived?.Invoke(this, snapshot);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Telemetry poll failed");
                    PollFailed?.Invoke(this, ex);
                }
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(_intervalSeconds), _time, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
        }
    }

    public async ValueTask DisposeAsync() => await StopAsync();
}
