using System.Globalization;

namespace HHJ.RemoteManager.Core.Telemetry;

/// <summary>Human-readable formatting of sizes, rates and durations (binary units, invariant-safe).</summary>
public static class UnitFormatter
{
    private static readonly string[] ByteUnits = ["B", "KB", "MB", "GB", "TB", "PB"];

    public static string Bytes(double? bytes, int decimals = 1)
    {
        if (bytes is null || double.IsNaN(bytes.Value) || bytes < 0) return "—";
        var value = bytes.Value;
        var unit = 0;
        while (value >= 1024 && unit < ByteUnits.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return unit == 0
            ? string.Create(CultureInfo.CurrentCulture, $"{value:0} {ByteUnits[unit]}")
            : string.Create(CultureInfo.CurrentCulture, $"{value.ToString("N" + decimals, CultureInfo.CurrentCulture)} {ByteUnits[unit]}");
    }

    public static string BytesPerSecond(double? bytesPerSecond) =>
        bytesPerSecond is null ? "—" : Bytes(bytesPerSecond) + "/s";

    /// <summary>Network link speeds are conventionally decimal bits per second.</summary>
    public static string BitsPerSecond(double? bitsPerSecond)
    {
        if (bitsPerSecond is null || bitsPerSecond < 0) return "—";
        var v = bitsPerSecond.Value;
        string[] units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
        var i = 0;
        while (v >= 1000 && i < units.Length - 1) { v /= 1000; i++; }
        return string.Create(CultureInfo.CurrentCulture, $"{v:0.#} {units[i]}");
    }

    public static string Percent(double? percent, int decimals = 0) =>
        percent is null ? "—" : percent.Value.ToString("N" + decimals, CultureInfo.CurrentCulture) + " %";

    public static string Duration(TimeSpan? span)
    {
        if (span is null || span.Value < TimeSpan.Zero) return "—";
        var s = span.Value;
        if (s.TotalDays >= 1) return string.Create(CultureInfo.CurrentCulture, $"{(int)s.TotalDays}d {s.Hours}h {s.Minutes}m");
        if (s.TotalHours >= 1) return string.Create(CultureInfo.CurrentCulture, $"{s.Hours}h {s.Minutes}m");
        if (s.TotalMinutes >= 1) return string.Create(CultureInfo.CurrentCulture, $"{s.Minutes}m {s.Seconds}s");
        return string.Create(CultureInfo.CurrentCulture, $"{s.Seconds}s");
    }

    public static string Milliseconds(TimeSpan? span) =>
        span is null ? "—" : string.Create(CultureInfo.CurrentCulture, $"{span.Value.TotalMilliseconds:0} ms");

    public static string RelativeTime(DateTimeOffset? when, DateTimeOffset now)
    {
        if (when is null) return "never";
        var d = now - when.Value;
        if (d < TimeSpan.FromSeconds(10)) return "just now";
        if (d < TimeSpan.FromMinutes(1)) return string.Create(CultureInfo.CurrentCulture, $"{(int)d.TotalSeconds}s ago");
        if (d < TimeSpan.FromHours(1)) return string.Create(CultureInfo.CurrentCulture, $"{(int)d.TotalMinutes} min ago");
        if (d < TimeSpan.FromDays(1)) return string.Create(CultureInfo.CurrentCulture, $"{(int)d.TotalHours} h ago");
        return when.Value.ToLocalTime().ToString("g", CultureInfo.CurrentCulture);
    }
}
