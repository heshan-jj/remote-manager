namespace HHJ.RemoteManager.Core.Telemetry;

/// <summary>Timestamped numeric value used for charts.</summary>
public readonly record struct MetricPoint(DateTimeOffset Time, double Value);

/// <summary>
/// Bounded, thread-safe ring buffer of metric points. Memory use is fixed regardless of how long
/// the application stays connected.
/// </summary>
public sealed class MetricHistory
{
    private readonly MetricPoint[] _buffer;
    private readonly Lock _gate = new();
    private int _start;
    private int _count;

    public MetricHistory(int capacity)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _buffer = new MetricPoint[capacity];
    }

    public int Capacity => _buffer.Length;

    public int Count { get { lock (_gate) return _count; } }

    public void Add(MetricPoint point)
    {
        lock (_gate)
        {
            var index = (_start + _count) % _buffer.Length;
            _buffer[index] = point;
            if (_count < _buffer.Length) _count++;
            else _start = (_start + 1) % _buffer.Length;
        }
    }

    public void Add(DateTimeOffset time, double value) => Add(new MetricPoint(time, value));

    public MetricPoint[] Snapshot()
    {
        lock (_gate)
        {
            var result = new MetricPoint[_count];
            for (var i = 0; i < _count; i++) result[i] = _buffer[(_start + i) % _buffer.Length];
            return result;
        }
    }

    public MetricPoint? Latest
    {
        get
        {
            lock (_gate) return _count == 0 ? null : _buffer[(_start + _count - 1) % _buffer.Length];
        }
    }

    public void Clear()
    {
        lock (_gate) { _start = 0; _count = 0; }
    }
}
