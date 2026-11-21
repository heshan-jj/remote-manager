using HHJ.RemoteManager.Core.Telemetry;
using HHJ.Shared.Contracts.Telemetry;
using Xunit;

namespace HHJ.Core.Tests;

public sealed class CounterMathAndTelemetryTests
{
    [Fact]
    public void CpuPercentFromInverseTimer_ComputesExpectedDelta()
    {
        // 10 seconds elapsed (100_000_000 * 100ns), 7 seconds idle -> 30% busy
        var pct = CounterMath.CpuPercentFromInverseTimer(
            idle0: 1_000_000_000, stamp0: 1_000_000_000,
            idle1: 1_700_000_000, stamp1: 2_000_000_000);
        Assert.NotNull(pct);
        Assert.Equal(30.0, pct!.Value, precision: 4);
    }

    [Fact]
    public void CpuPercentFromInverseTimer_ReturnsNullOnResetOrZeroElapsed()
    {
        Assert.Null(CounterMath.CpuPercentFromInverseTimer(100, 500, 200, 500));
        Assert.Null(CounterMath.CpuPercentFromInverseTimer(200, 500, 100, 600));
    }

    [Fact]
    public void ProcessCpuPercent_NormalizesByLogicalProcessors()
    {
        // 1 second (10_000_000 ticks) of CPU across 4 logical cores -> 25%
        var pct = CounterMath.ProcessCpuPercent(1000, 1_000_000_000, 1000 + 10_000_000, 1_010_000_000, 4);
        Assert.NotNull(pct);
        Assert.Equal(25.0, pct!.Value, precision: 4);
    }

    [Fact]
    public void RatePerSecond_ComputesBytesPerSecond()
    {
        // 2 MB in 2 seconds -> 1_048_576 B/s
        var rate = CounterMath.RatePerSecond(0, 0, 2 * 1024 * 1024, 20_000_000);
        Assert.NotNull(rate);
        Assert.Equal(1_048_576.0, rate!.Value, precision: 2);
    }

    [Fact]
    public void MetricsCalculator_RequiresTwoSamplesForCpuAndNetworkRates()
    {
        var calc = new MetricsCalculator();
        var s1 = new MetricsSampleDto
        {
            Cpu = [new CpuCounterDto { Name = "_Total", PercentProcessorTimeRaw = 100_000_000, TimestampSys100Ns = 100_000_000 }],
            Network = [new NetworkCounterDto { Name = "Tailscale", BytesReceived = 1000, BytesSent = 500, TimestampSys100Ns = 100_000_000 }],
            MemoryTotalKb = 16_000_000,
            MemoryAvailableKb = 8_000_000,
        };
        var s2 = new MetricsSampleDto
        {
            Cpu = [new CpuCounterDto { Name = "_Total", PercentProcessorTimeRaw = 106_000_000, TimestampSys100Ns = 110_000_000 }],
            Network = [new NetworkCounterDto { Name = "Tailscale", BytesReceived = 11_000, BytesSent = 2500, TimestampSys100Ns = 110_000_000 }],
            MemoryTotalKb = 16_000_000,
            MemoryAvailableKb = 4_000_000,
        };

        var snap1 = calc.Compute(s1, DateTimeOffset.UtcNow, TimeSpan.FromMilliseconds(40));
        Assert.Null(snap1.CpuPercent);
        Assert.Null(snap1.TotalReceiveBytesPerSecond);
        Assert.Equal(50.0, snap1.MemoryPercent!.Value, precision: 2);

        var snap2 = calc.Compute(s2, DateTimeOffset.UtcNow, TimeSpan.FromMilliseconds(45));
        Assert.Equal(40.0, snap2.CpuPercent!.Value, precision: 2);
        Assert.Equal(10_000.0, snap2.TotalReceiveBytesPerSecond!.Value, precision: 2);
        Assert.Equal(2_000.0, snap2.TotalSendBytesPerSecond!.Value, precision: 2);
        Assert.Equal(75.0, snap2.MemoryPercent!.Value, precision: 2);
    }

    [Fact]
    public void TelemetryJson_HandlesBomBannerAndSingleElementArrays()
    {
        const string stdout = "\uFEFFWelcome banner\n{\"v\":1,\"cpu\":{\"name\":\"_Total\",\"time\":10,\"stamp\":20},\"disks\":{\"id\":\"C:\",\"size\":1000,\"free\":400}}";
        var dto = TelemetryJson.Parse<MetricsSampleDto>(stdout);
        Assert.Single(dto.Cpu);
        Assert.Equal("_Total", dto.Cpu[0].Name);
        Assert.Single(dto.Disks);
        Assert.Equal("C:", dto.Disks[0].DeviceId);
    }

    [Fact]
    public void TelemetryJson_CleansClixmlStdErr()
    {
        const string clixml = "#< CLIXML\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">Access is denied_x000D__x000A_</S></Objs>";
        Assert.Equal("Access is denied", TelemetryJson.CleanStdErr(clixml));
    }

    [Fact]
    public void MetricHistory_IsBoundedRingBuffer()
    {
        var hist = new MetricHistory(3);
        var t0 = DateTimeOffset.UtcNow;
        hist.Add(t0, 1);
        hist.Add(t0.AddSeconds(1), 2);
        hist.Add(t0.AddSeconds(2), 3);
        hist.Add(t0.AddSeconds(3), 4);

        var snap = hist.Snapshot();
        Assert.Equal(3, snap.Length);
        Assert.Equal([2, 3, 4], snap.Select(p => p.Value).ToArray());
    }

    [Fact]
    public void UnitFormatter_FormatsBytesAndDurations()
    {
        Assert.Equal("—", UnitFormatter.Bytes(null));
        Assert.Contains("GB", UnitFormatter.Bytes(2.0 * 1024 * 1024 * 1024));
        Assert.Equal("2d 3h 4m", UnitFormatter.Duration(new TimeSpan(2, 3, 4, 5)));
    }
}
