using HHJ.Shared.Contracts.Telemetry;

namespace HHJ.RemoteManager.Core.Telemetry;

public sealed record ProcessInfo(
    int Id,
    string Name,
    double? CpuPercent,
    ulong WorkingSetBytes,
    string? Path,
    string State,
    int? SessionId,
    int? ThreadCount);

/// <summary>
/// Calculates per-process CPU % from two consecutive raw samples (never from cumulative CPU time).
/// Processes are matched on PID *and* name to avoid attributing a reused PID's history.
/// </summary>
public sealed class ProcessCpuTracker
{
    private Dictionary<int, (string Name, ulong Raw)> _previous = [];
    private ulong _previousStamp;

    public void Reset()
    {
        _previous = [];
        _previousStamp = 0;
    }

    public IReadOnlyList<ProcessInfo> Compute(ProcessListDto list)
    {
        ArgumentNullException.ThrowIfNull(list);
        var logical = list.LogicalProcessors > 0 ? list.LogicalProcessors : Environment.ProcessorCount;
        var result = new List<ProcessInfo>(list.Processes.Count);
        var current = new Dictionary<int, (string, ulong)>(list.Processes.Count);

        foreach (var p in list.Processes)
        {
            double? cpu = null;
            if (p.CpuTimeRaw is { } raw)
            {
                current[p.Id] = (p.Name, raw);
                if (_previousStamp != 0 && _previous.TryGetValue(p.Id, out var prev) &&
                    string.Equals(prev.Name, p.Name, StringComparison.OrdinalIgnoreCase))
                {
                    cpu = CounterMath.ProcessCpuPercent(prev.Raw, _previousStamp, raw, list.TimestampSys100Ns, logical);
                }
            }

            var state = p.Responding switch
            {
                false => "Not responding",
                _ => "Running",
            };

            result.Add(new ProcessInfo(p.Id, p.Name, cpu, p.WorkingSetBytes, p.Path, state, p.SessionId, p.ThreadCount));
        }

        if (list.TimestampSys100Ns != 0)
        {
            _previous = current;
            _previousStamp = list.TimestampSys100Ns;
        }

        return result;
    }
}
