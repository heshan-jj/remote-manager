using HHJ.RemoteManager.Core.Connections;
using HHJ.RemoteManager.Core.Ssh;
using HHJ.RemoteManager.Core.Telemetry;
using HHJ.Shared.Contracts.Telemetry;

namespace HHJ.RemoteManager.Core.Remote;

public sealed record EndpointProbeDto
{
    public bool Ok { get; set; }
    public string? ComputerName { get; set; }
    public string? UserName { get; set; }
    public bool IsAdmin { get; set; }
    public string? PsVersion { get; set; }
}

/// <summary>
/// High-level typed RPC over an <see cref="ISshSession"/>. All commands use
/// <see cref="PowerShellCommand.Build"/> (-EncodedCommand) and structured JSON.
/// </summary>
public sealed class RemoteEndpointClient(ISshSession session)
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan InventoryTimeout = TimeSpan.FromSeconds(30);

    public async Task<EndpointProbeDto> ProbeAsync(CancellationToken ct)
    {
        var (dto, _) = await RunJsonAsync<EndpointProbeDto>(RemoteScripts.Probe, DefaultTimeout, ct);
        return dto;
    }

    public async Task<(MetricsSampleDto Sample, TimeSpan RoundTrip)> GetMetricsSampleAsync(CancellationToken ct) =>
        await RunJsonAsync<MetricsSampleDto>(RemoteScripts.MetricsSample, DefaultTimeout, ct);

    public async Task<SystemInfoDto> GetSystemInfoAsync(CancellationToken ct)
    {
        var (dto, _) = await RunJsonAsync<SystemInfoDto>(RemoteScripts.SystemInfo, InventoryTimeout, ct);
        return dto;
    }

    public async Task<ProcessListDto> GetProcessesAsync(CancellationToken ct)
    {
        var (dto, _) = await RunJsonAsync<ProcessListDto>(RemoteScripts.Processes, DefaultTimeout, ct);
        return dto;
    }

    public async Task<ServiceListDto> GetServicesAsync(CancellationToken ct)
    {
        var (dto, _) = await RunJsonAsync<ServiceListDto>(RemoteScripts.Services, InventoryTimeout, ct);
        return dto;
    }

    public async Task<InstalledSoftwareListDto> GetInstalledSoftwareAsync(CancellationToken ct)
    {
        var (dto, _) = await RunJsonAsync<InstalledSoftwareListDto>(RemoteScripts.InstalledSoftware, InventoryTimeout, ct);
        return dto;
    }

    public async Task<EventLogSummaryDto> GetEventLogSummaryAsync(int hours, int maxEvents, CancellationToken ct)
    {
        var (dto, _) = await RunJsonAsync<EventLogSummaryDto>(
            RemoteScripts.EventLogSummary(hours, maxEvents), InventoryTimeout, ct);
        return dto;
    }

    public async Task<ActionResultDto> ControlServiceAsync(string serviceName, RemoteScripts.ServiceAction action, CancellationToken ct) =>
        await RunActionAsync(RemoteScripts.ServiceControl(serviceName, action), ct);

    public async Task<ActionResultDto> StopProcessAsync(int pid, string expectedName, CancellationToken ct) =>
        await RunActionAsync(RemoteScripts.StopProcess(pid, expectedName), ct);

    public async Task<ActionResultDto> SchedulePowerAsync(RemoteScripts.PowerAction action, int delaySeconds, CancellationToken ct) =>
        await RunActionAsync(RemoteScripts.SchedulePower(action, delaySeconds), ct);

    public async Task<ActionResultDto> CancelPowerAsync(CancellationToken ct) =>
        await RunActionAsync(RemoteScripts.CancelPowerAction, ct);

    public async Task<ActionResultDto> FlushDnsAsync(CancellationToken ct) =>
        await RunActionAsync(RemoteScripts.FlushDns, ct);

    private async Task<ActionResultDto> RunActionAsync(string script, CancellationToken ct)
    {
        var (dto, _) = await RunJsonAsync<ActionResultDto>(script, DefaultTimeout, ct);
        if (dto.AccessDenied)
        {
            throw new RemoteAccessDeniedException(dto.Error ?? "Access is denied by Windows.");
        }
        return dto;
    }

    private async Task<(T Result, TimeSpan Duration)> RunJsonAsync<T>(string script, TimeSpan timeout, CancellationToken ct)
    {
        var cmd = PowerShellCommand.Build(script);
        var result = await session.RunAsync(cmd, timeout, ct);
        if (result.ExitCode != 0 && string.IsNullOrWhiteSpace(result.StdOut))
        {
            var err = TelemetryJson.CleanStdErr(result.StdErr);
            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(err)
                    ? $"Remote PowerShell exited with code {result.ExitCode}."
                    : err);
        }
        return (TelemetryJson.Parse<T>(result.StdOut), result.Duration);
    }
}
