namespace HHJ.RemoteManager.Core.Telemetry;

/// <summary>
/// Counter math for Windows raw performance data. All functions are pure and unit tested.
/// </summary>
public static class CounterMath
{
    /// <summary>
    /// CPU utilisation from two samples of a PERF_100NSEC_TIMER_INV counter
    /// (Win32_PerfRawData_PerfOS_Processor.PercentProcessorTime, which counts idle time):
    /// <c>100 * (1 - ΔN / ΔD)</c> where D is Timestamp_Sys100NS.
    /// Returns null if the samples are not usable (no elapsed time, counter reset).
    /// </summary>
    public static double? CpuPercentFromInverseTimer(ulong idle0, ulong stamp0, ulong idle1, ulong stamp1)
    {
        if (stamp1 <= stamp0 || idle1 < idle0) return null;
        var elapsed = (double)(stamp1 - stamp0);
        var idle = (double)(idle1 - idle0);
        return Clamp(100.0 * (1.0 - idle / elapsed));
    }

    /// <summary>
    /// Process CPU utilisation from two samples of a PERF_100NSEC_TIMER counter
    /// (Win32_PerfRawData_PerfProc_Process.PercentProcessorTime, which counts busy time summed
    /// across processors), normalised to 0-100 % of total machine capacity like Task Manager.
    /// </summary>
    public static double? ProcessCpuPercent(ulong busy0, ulong stamp0, ulong busy1, ulong stamp1, int logicalProcessors)
    {
        if (stamp1 <= stamp0 || busy1 < busy0 || logicalProcessors <= 0) return null;
        var elapsed = (double)(stamp1 - stamp0);
        return Clamp(100.0 * (busy1 - busy0) / elapsed / logicalProcessors);
    }

    /// <summary>
    /// Rate (units per second) from two cumulative counter readings and their timestamps in
    /// 100 ns units. Returns null on counter reset/wrap or zero elapsed time.
    /// </summary>
    public static double? RatePerSecond(ulong value0, ulong stamp0, ulong value1, ulong stamp1)
    {
        if (stamp1 <= stamp0 || value1 < value0) return null;
        var seconds = (stamp1 - stamp0) / 10_000_000.0;
        return (value1 - value0) / seconds;
    }

    public static double Clamp(double percent) => double.IsNaN(percent) ? 0 : Math.Clamp(percent, 0, 100);

    /// <summary>Percent of <paramref name="part"/> in <paramref name="total"/>, or null if total is zero.</summary>
    public static double? Percent(double part, double total) => total <= 0 ? null : Clamp(100.0 * part / total);
}
