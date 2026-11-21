using HHJ.Shared.Contracts.Telemetry;

namespace HHJ.RemoteManager.Core.Telemetry;

public sealed record DiskUsage(string DeviceId, string? Label, string? FileSystem, ulong TotalBytes, ulong FreeBytes)
{
    public ulong UsedBytes => TotalBytes >= FreeBytes ? TotalBytes - FreeBytes : 0;
    public double? UsedPercent => CounterMath.Percent(UsedBytes, TotalBytes);
}

public sealed record NetworkThroughput(
    string Name,
    double? ReceiveBytesPerSecond,
    double? SendBytesPerSecond,
    ulong TotalBytesReceived,
    ulong TotalBytesSent,
    ulong? LinkSpeedBitsPerSecond);

/// <summary>Computed, display-ready metrics for one poll. Values are null when not (yet) measurable.</summary>
public sealed record MetricsSnapshot
{
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>Total CPU %, from counter deltas. Null on the first sample (needs two readings).</summary>
    public double? CpuPercent { get; init; }

    /// <summary>True if <see cref="CpuPercent"/> came from Win32_Processor.LoadPercentage because raw counters were unavailable.</summary>
    public bool CpuIsApproximate { get; init; }

    public IReadOnlyList<double?> PerCoreCpuPercent { get; init; } = [];

    public ulong? MemoryTotalBytes { get; init; }
    public ulong? MemoryAvailableBytes { get; init; }
    public ulong? MemoryUsedBytes => MemoryTotalBytes is { } t && MemoryAvailableBytes is { } a && t >= a ? t - a : null;
    public double? MemoryPercent => MemoryTotalBytes is { } t && MemoryUsedBytes is { } u ? CounterMath.Percent(u, t) : null;

    public TimeSpan? Uptime { get; init; }

    public IReadOnlyList<DiskUsage> Disks { get; init; } = [];
    public IReadOnlyList<NetworkThroughput> Network { get; init; } = [];

    public double? TotalReceiveBytesPerSecond => SumOrNull(Network.Select(n => n.ReceiveBytesPerSecond));
    public double? TotalSendBytesPerSecond => SumOrNull(Network.Select(n => n.SendBytesPerSecond));

    /// <summary>Wall-clock duration of the telemetry command (SSH round trip + remote execution).</summary>
    public TimeSpan CommandRoundTrip { get; init; }

    public IReadOnlyList<string> RemoteErrors { get; init; } = [];

    private static double? SumOrNull(IEnumerable<double?> values)
    {
        double sum = 0;
        var any = false;
        foreach (var v in values)
        {
            if (v is null) continue;
            sum += v.Value;
            any = true;
        }
        return any ? sum : null;
    }
}

/// <summary>
/// Turns consecutive raw samples into rates/percentages. Keeps only the previous sample.
/// Not thread-safe; owned by a single poller.
/// </summary>
public sealed class MetricsCalculator
{
    private MetricsSampleDto? _previous;

    public void Reset() => _previous = null;

    public MetricsSnapshot Compute(MetricsSampleDto current, DateTimeOffset now, TimeSpan roundTrip)
    {
        ArgumentNullException.ThrowIfNull(current);
        var previous = _previous;

        double? cpuTotal = null;
        var approximate = false;
        var perCore = new List<double?>();

        if (current.Cpu.Count > 0)
        {
            var prevByName = previous?.Cpu.ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);
            foreach (var c in current.Cpu.OrderBy(c => CoreSortKey(c.Name)))
            {
                double? pct = null;
                if (prevByName is not null && prevByName.TryGetValue(c.Name, out var p))
                {
                    pct = CounterMath.CpuPercentFromInverseTimer(p.PercentProcessorTimeRaw, p.TimestampSys100Ns,
                        c.PercentProcessorTimeRaw, c.TimestampSys100Ns);
                }

                if (c.Name == "_Total") cpuTotal = pct;
                else perCore.Add(pct);
            }
        }
        else if (current.CpuLoadPercentFallback is { } load)
        {
            cpuTotal = CounterMath.Clamp(load);
            approximate = true;
        }

        var network = new List<NetworkThroughput>();
        var prevNet = previous?.Network.GroupBy(n => n.Name).ToDictionary(g => g.Key, g => g.First());
        foreach (var n in current.Network)
        {
            double? rx = null, tx = null;
            if (prevNet is not null && prevNet.TryGetValue(n.Name, out var p))
            {
                rx = CounterMath.RatePerSecond(p.BytesReceived, p.TimestampSys100Ns, n.BytesReceived, n.TimestampSys100Ns);
                tx = CounterMath.RatePerSecond(p.BytesSent, p.TimestampSys100Ns, n.BytesSent, n.TimestampSys100Ns);
            }
            network.Add(new NetworkThroughput(n.Name, rx, tx, n.BytesReceived, n.BytesSent,
                n.CurrentBandwidthBitsPerSecond is > 0 ? n.CurrentBandwidthBitsPerSecond : null));
        }

        var disks = current.Disks
            .Where(d => d.SizeBytes is > 0)
            .Select(d => new DiskUsage(d.DeviceId, string.IsNullOrWhiteSpace(d.VolumeName) ? null : d.VolumeName, d.FileSystem,
                d.SizeBytes!.Value, Math.Min(d.FreeBytes ?? 0, d.SizeBytes!.Value)))
            .OrderBy(d => d.DeviceId, StringComparer.OrdinalIgnoreCase)
            .ToList();

        _previous = current;

        return new MetricsSnapshot
        {
            Timestamp = now,
            CpuPercent = cpuTotal,
            CpuIsApproximate = approximate,
            PerCoreCpuPercent = perCore,
            MemoryTotalBytes = current.MemoryTotalKb * 1024,
            MemoryAvailableBytes = current.MemoryAvailableKb * 1024,
            Uptime = current.UptimeSeconds is { } s and >= 0 ? TimeSpan.FromSeconds(s) : null,
            Disks = disks,
            Network = network,
            CommandRoundTrip = roundTrip,
            RemoteErrors = current.Errors,
        };
    }

    // "_Total" first, then numeric cores ("0", "1", ... or "0,1" on multi-group systems).
    private static (int, int, int, string) CoreSortKey(string name)
    {
        if (name == "_Total") return (0, 0, 0, name);
        var parts = name.Split(',');
        if (parts.Length == 2 && int.TryParse(parts[0], out var g) && int.TryParse(parts[1], out var c)) return (1, g, c, name);
        if (int.TryParse(name, out var n)) return (1, 0, n, name);
        return (2, 0, 0, name);
    }
}
