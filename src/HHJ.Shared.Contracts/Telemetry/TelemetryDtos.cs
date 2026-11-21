using System.Text.Json.Serialization;

namespace HHJ.Shared.Contracts.Telemetry;

// These DTOs mirror, field-for-field, the JSON emitted by the PowerShell scripts in
// HHJ.RemoteManager.Core.Remote.RemoteScripts. Raw performance-counter values are transported
// unmodified so that rates/percentages are calculated client-side from counter deltas.

/// <summary>Lightweight, frequently polled sample (CPU, memory, network, disks).</summary>
public sealed class MetricsSampleDto
{
    [JsonPropertyName("v")] public int SchemaVersion { get; set; }
    [JsonPropertyName("collectedUtc")] public string? CollectedUtc { get; set; }
    [JsonPropertyName("cpu")] public List<CpuCounterDto> Cpu { get; set; } = [];
    [JsonPropertyName("cpuLoad")] public double? CpuLoadPercentFallback { get; set; }
    [JsonPropertyName("memTotalKb")] public ulong? MemoryTotalKb { get; set; }
    [JsonPropertyName("memFreeKb")] public ulong? MemoryAvailableKb { get; set; }
    [JsonPropertyName("uptimeSeconds")] public long? UptimeSeconds { get; set; }
    [JsonPropertyName("net")] public List<NetworkCounterDto> Network { get; set; } = [];
    [JsonPropertyName("disks")] public List<LogicalDiskDto> Disks { get; set; } = [];
    [JsonPropertyName("errors")] public List<string> Errors { get; set; } = [];
}

/// <summary>Raw Win32_PerfRawData_PerfOS_Processor counter (PERF_100NSEC_TIMER_INV).</summary>
public sealed class CpuCounterDto
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("time")] public ulong PercentProcessorTimeRaw { get; set; }
    [JsonPropertyName("stamp")] public ulong TimestampSys100Ns { get; set; }
}

/// <summary>Raw Win32_PerfRawData_Tcpip_NetworkInterface counters (cumulative byte counts).</summary>
public sealed class NetworkCounterDto
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("rx")] public ulong BytesReceived { get; set; }
    [JsonPropertyName("tx")] public ulong BytesSent { get; set; }
    [JsonPropertyName("bandwidth")] public ulong? CurrentBandwidthBitsPerSecond { get; set; }
    [JsonPropertyName("stamp")] public ulong TimestampSys100Ns { get; set; }
}

public sealed class LogicalDiskDto
{
    [JsonPropertyName("id")] public string DeviceId { get; set; } = "";
    [JsonPropertyName("label")] public string? VolumeName { get; set; }
    [JsonPropertyName("fs")] public string? FileSystem { get; set; }
    [JsonPropertyName("size")] public ulong? SizeBytes { get; set; }
    [JsonPropertyName("free")] public ulong? FreeBytes { get; set; }
}

/// <summary>Expensive, infrequently refreshed system inventory.</summary>
public sealed class SystemInfoDto
{
    [JsonPropertyName("computerName")] public string? ComputerName { get; set; }
    [JsonPropertyName("osCaption")] public string? OsCaption { get; set; }
    [JsonPropertyName("osVersion")] public string? OsVersion { get; set; }
    [JsonPropertyName("osBuild")] public string? OsBuild { get; set; }
    [JsonPropertyName("displayVersion")] public string? DisplayVersion { get; set; }
    [JsonPropertyName("osArchitecture")] public string? OsArchitecture { get; set; }
    [JsonPropertyName("lastBootUtc")] public string? LastBootUtc { get; set; }
    [JsonPropertyName("cpuName")] public string? CpuName { get; set; }
    [JsonPropertyName("cpuCores")] public int? CpuCores { get; set; }
    [JsonPropertyName("cpuLogical")] public int? CpuLogicalProcessors { get; set; }
    [JsonPropertyName("cpuSockets")] public int? CpuSockets { get; set; }
    [JsonPropertyName("cpuMaxClockMhz")] public int? CpuMaxClockMhz { get; set; }
    [JsonPropertyName("physicalMemoryBytes")] public ulong? PhysicalMemoryBytes { get; set; }
    [JsonPropertyName("manufacturer")] public string? Manufacturer { get; set; }
    [JsonPropertyName("model")] public string? Model { get; set; }
    [JsonPropertyName("sshdStatus")] public string? SshdStatus { get; set; }
    [JsonPropertyName("sshdStartType")] public string? SshdStartType { get; set; }
    [JsonPropertyName("psVersion")] public string? PowerShellVersion { get; set; }
    [JsonPropertyName("userName")] public string? UserName { get; set; }
    [JsonPropertyName("isAdmin")] public bool? IsAdministrator { get; set; }
    [JsonPropertyName("adapters")] public List<NetworkAdapterDto> Adapters { get; set; } = [];
    [JsonPropertyName("errors")] public List<string> Errors { get; set; } = [];
}

public sealed class NetworkAdapterDto
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("description")] public string? Description { get; set; }
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("linkSpeed")] public string? LinkSpeed { get; set; }
    [JsonPropertyName("mac")] public string? MacAddress { get; set; }
    [JsonPropertyName("ipv4")] public List<string> IPv4 { get; set; } = [];
}

/// <summary>One process row. CPU is transported as raw counters for delta calculation.</summary>
public sealed class ProcessDto
{
    [JsonPropertyName("pid")] public int Id { get; set; }
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("ws")] public ulong WorkingSetBytes { get; set; }
    [JsonPropertyName("path")] public string? Path { get; set; }
    [JsonPropertyName("responding")] public bool? Responding { get; set; }
    [JsonPropertyName("session")] public int? SessionId { get; set; }
    [JsonPropertyName("threads")] public int? ThreadCount { get; set; }
    [JsonPropertyName("cpuRaw")] public ulong? CpuTimeRaw { get; set; }
}

public sealed class ProcessListDto
{
    [JsonPropertyName("stamp")] public ulong TimestampSys100Ns { get; set; }
    [JsonPropertyName("logical")] public int LogicalProcessors { get; set; }
    [JsonPropertyName("processes")] public List<ProcessDto> Processes { get; set; } = [];
    [JsonPropertyName("errors")] public List<string> Errors { get; set; } = [];
}

public sealed class ServiceDto
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("displayName")] public string? DisplayName { get; set; }
    [JsonPropertyName("state")] public string? State { get; set; }
    [JsonPropertyName("startMode")] public string? StartMode { get; set; }
    [JsonPropertyName("pid")] public int? ProcessId { get; set; }
    [JsonPropertyName("account")] public string? Account { get; set; }
}

public sealed class ServiceListDto
{
    [JsonPropertyName("services")] public List<ServiceDto> Services { get; set; } = [];
    [JsonPropertyName("errors")] public List<string> Errors { get; set; } = [];
}

/// <summary>Result of an administrative action executed remotely.</summary>
public sealed class ActionResultDto
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("denied")] public bool AccessDenied { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
    [JsonPropertyName("state")] public string? State { get; set; }
}

public sealed class EventLogEntryDto
{
    [JsonPropertyName("time")] public string? TimeUtc { get; set; }
    [JsonPropertyName("log")] public string? LogName { get; set; }
    [JsonPropertyName("level")] public string? Level { get; set; }
    [JsonPropertyName("id")] public int EventId { get; set; }
    [JsonPropertyName("source")] public string? Source { get; set; }
    [JsonPropertyName("message")] public string? Message { get; set; }
}

public sealed class EventLogSummaryDto
{
    [JsonPropertyName("entries")] public List<EventLogEntryDto> Entries { get; set; } = [];
    [JsonPropertyName("errors")] public List<string> Errors { get; set; } = [];
}

public sealed class InstalledSoftwareDto
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("version")] public string? Version { get; set; }
    [JsonPropertyName("publisher")] public string? Publisher { get; set; }
    [JsonPropertyName("installDate")] public string? InstallDate { get; set; }
}

public sealed class InstalledSoftwareListDto
{
    [JsonPropertyName("items")] public List<InstalledSoftwareDto> Items { get; set; } = [];
    [JsonPropertyName("errors")] public List<string> Errors { get; set; } = [];
}
