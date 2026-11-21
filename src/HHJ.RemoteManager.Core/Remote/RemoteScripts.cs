using System.Globalization;

namespace HHJ.RemoteManager.Core.Remote;

/// <summary>
/// Read-only and administrative PowerShell scripts executed on the managed endpoint.
/// Compatible with Windows PowerShell 5.1 (in-box on Windows 10/11). Every script emits exactly one
/// compressed JSON document on stdout; errors are reported inside the JSON instead of console tables,
/// so parsing is independent of the endpoint's display language.
/// </summary>
public static class RemoteScripts
{
    /// <summary>Common prelude: fail fast, no progress records, UTF-8 output without BOM.</summary>
    private const string Prelude = """
        $ErrorActionPreference='Stop'
        $ProgressPreference='SilentlyContinue'
        [Console]::OutputEncoding=New-Object System.Text.UTF8Encoding $false
        function IsDenied($e){$x=$e;while($x){if($x -is [UnauthorizedAccessException]){return $true};if($x -is [ComponentModel.Win32Exception] -and $x.NativeErrorCode -eq 5){return $true};$x=$x.InnerException};return $false}
        """;

    /// <summary>Simple round-trip used after connecting to verify that PowerShell runs.</summary>
    public static readonly string Probe = Prelude + """

        $id=[Security.Principal.WindowsIdentity]::GetCurrent()
        $adm=(New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        ConvertTo-Json -InputObject ([ordered]@{ok=$true;computerName=$env:COMPUTERNAME;userName=$id.Name;isAdmin=$adm;psVersion=$PSVersionTable.PSVersion.ToString()}) -Compress
        """;

    /// <summary>Lightweight sample: raw CPU counters, memory, raw network counters, fixed disks.</summary>
    public static readonly string MetricsSample = Prelude + """

        $r=[ordered]@{v=1;errors=@()}
        try{$r.cpu=@(Get-CimInstance Win32_PerfRawData_PerfOS_Processor -Property Name,PercentProcessorTime,Timestamp_Sys100NS|ForEach-Object{[ordered]@{name=$_.Name;time=[uint64]$_.PercentProcessorTime;stamp=[uint64]$_.Timestamp_Sys100NS}})}catch{$r.errors+=('cpu: '+$_.Exception.Message);try{$r.cpuLoad=[double](@(Get-CimInstance Win32_Processor -Property LoadPercentage)|Measure-Object LoadPercentage -Average).Average}catch{}}
        try{$o=Get-CimInstance Win32_OperatingSystem -Property TotalVisibleMemorySize,FreePhysicalMemory,LastBootUpTime;$r.memTotalKb=[uint64]$o.TotalVisibleMemorySize;$r.memFreeKb=[uint64]$o.FreePhysicalMemory;$r.uptimeSeconds=[int64]((Get-Date)-$o.LastBootUpTime).TotalSeconds}catch{$r.errors+=('memory: '+$_.Exception.Message)}
        try{$r.net=@(Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface -Property Name,BytesReceivedPersec,BytesSentPersec,CurrentBandwidth,Timestamp_Sys100NS|ForEach-Object{[ordered]@{name=$_.Name;rx=[uint64]$_.BytesReceivedPersec;tx=[uint64]$_.BytesSentPersec;bandwidth=[uint64]$_.CurrentBandwidth;stamp=[uint64]$_.Timestamp_Sys100NS}})}catch{$r.errors+=('network: '+$_.Exception.Message)}
        try{$r.disks=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -Property DeviceID,VolumeName,FileSystem,Size,FreeSpace|ForEach-Object{[ordered]@{id=$_.DeviceID;label=$_.VolumeName;fs=$_.FileSystem;size=[uint64]$_.Size;free=[uint64]$_.FreeSpace}})}catch{$r.errors+=('disks: '+$_.Exception.Message)}
        $r.collectedUtc=[DateTime]::UtcNow.ToString('o')
        ConvertTo-Json -InputObject $r -Depth 5 -Compress
        """;

    /// <summary>Expensive inventory: OS, CPU, memory, adapters, sshd status. Refreshed rarely.</summary>
    public static readonly string SystemInfo = Prelude + """

        $r=[ordered]@{errors=@()}
        try{$o=Get-CimInstance Win32_OperatingSystem;$r.computerName=$o.CSName;$r.osCaption=$o.Caption;$r.osVersion=$o.Version;$r.osBuild=$o.BuildNumber;$r.osArchitecture=$o.OSArchitecture;$r.lastBootUtc=$o.LastBootUpTime.ToUniversalTime().ToString('o')}catch{$r.errors+=('os: '+$_.Exception.Message)}
        try{$cv=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion';$r.displayVersion=$cv.DisplayVersion;if($cv.UBR -ne $null){$r.osBuild=[string]$cv.CurrentBuild+'.'+[string]$cv.UBR}}catch{}
        try{$p=@(Get-CimInstance Win32_Processor);$r.cpuName=([string]$p[0].Name).Trim();$r.cpuCores=[int]($p|Measure-Object NumberOfCores -Sum).Sum;$r.cpuLogical=[int]($p|Measure-Object NumberOfLogicalProcessors -Sum).Sum;$r.cpuSockets=$p.Count;$r.cpuMaxClockMhz=[int]$p[0].MaxClockSpeed}catch{$r.errors+=('cpu: '+$_.Exception.Message)}
        try{$cs=Get-CimInstance Win32_ComputerSystem;$r.physicalMemoryBytes=[uint64]$cs.TotalPhysicalMemory;$r.manufacturer=$cs.Manufacturer;$r.model=$cs.Model}catch{$r.errors+=('computer: '+$_.Exception.Message)}
        try{$s=Get-Service -Name sshd;$r.sshdStatus=[string]$s.Status;$r.sshdStartType=[string]$s.StartType}catch{$r.sshdStatus='NotFound'}
        $r.psVersion=$PSVersionTable.PSVersion.ToString()
        $id=[Security.Principal.WindowsIdentity]::GetCurrent();$r.userName=$id.Name;$r.isAdmin=(New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        try{$r.adapters=@(Get-NetAdapter|ForEach-Object{$i=$_.ifIndex;[ordered]@{name=$_.Name;description=$_.InterfaceDescription;status=[string]$_.Status;linkSpeed=[string]$_.LinkSpeed;mac=$_.MacAddress;ipv4=@(Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue|ForEach-Object{$_.IPAddress})}})}catch{$r.errors+=('adapters: '+$_.Exception.Message)}
        ConvertTo-Json -InputObject $r -Depth 5 -Compress
        """;

    /// <summary>Process list with raw per-process CPU counters (PERF_100NSEC_TIMER) for delta calculation.</summary>
    public static readonly string Processes = Prelude + """

        $r=[ordered]@{stamp=[uint64]0;logical=[Environment]::ProcessorCount;errors=@()}
        $cpu=@{}
        try{Get-CimInstance Win32_PerfRawData_PerfProc_Process -Property Name,IDProcess,PercentProcessorTime,Timestamp_Sys100NS|ForEach-Object{if($_.Name -ne '_Total'){$cpu[[int]$_.IDProcess]=[uint64]$_.PercentProcessorTime};$r.stamp=[uint64]$_.Timestamp_Sys100NS}}catch{$r.errors+=('cpu: '+$_.Exception.Message)}
        $r.processes=@(Get-Process|ForEach-Object{$p=$_;$path=$null;$t=$null;try{$path=$p.Path}catch{};try{$t=$p.Threads.Count}catch{};[ordered]@{pid=$p.Id;name=$p.ProcessName;ws=[uint64]$p.WorkingSet64;path=$path;responding=$p.Responding;session=$p.SessionId;threads=$t;cpuRaw=$cpu[$p.Id]}})
        ConvertTo-Json -InputObject $r -Depth 4 -Compress
        """;

    public static readonly string Services = Prelude + """

        $r=[ordered]@{errors=@()}
        try{$r.services=@(Get-CimInstance Win32_Service -Property Name,DisplayName,State,StartMode,ProcessId,StartName|ForEach-Object{[ordered]@{name=$_.Name;displayName=$_.DisplayName;state=[string]$_.State;startMode=[string]$_.StartMode;pid=[int]$_.ProcessId;account=$_.StartName}})}catch{$r.services=@();$r.errors+=('services: '+$_.Exception.Message)}
        ConvertTo-Json -InputObject $r -Depth 4 -Compress
        """;

    public static readonly string InstalledSoftware = Prelude + """

        $r=[ordered]@{errors=@()}
        $k='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        try{$r.items=@(Get-ItemProperty $k -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName -and -not $_.SystemComponent}|Sort-Object DisplayName -Unique|ForEach-Object{[ordered]@{name=[string]$_.DisplayName;version=[string]$_.DisplayVersion;publisher=[string]$_.Publisher;installDate=[string]$_.InstallDate}})}catch{$r.items=@();$r.errors+=$_.Exception.Message}
        ConvertTo-Json -InputObject $r -Depth 4 -Compress
        """;

    public enum ServiceAction { Start, Stop, Restart }

    /// <summary>Starts/stops/restarts a service. Never uses -Force: dependent services are not stopped implicitly.</summary>
    public static string ServiceControl(string serviceName, ServiceAction action)
    {
        if (!PowerShellCommand.IsValidServiceName(serviceName))
            throw new ArgumentException("Invalid service name.", nameof(serviceName));

        var verb = action switch
        {
            ServiceAction.Start => "Start-Service -Name $n",
            ServiceAction.Stop => "Stop-Service -Name $n",
            ServiceAction.Restart => "Restart-Service -Name $n",
            _ => throw new ArgumentOutOfRangeException(nameof(action)),
        };

        return Prelude + $$"""

            $n={{PowerShellCommand.Literal(serviceName)}}
            $r=[ordered]@{ok=$false;denied=$false}
            try{{{verb}};$r.ok=$true;$r.state=[string](Get-Service -Name $n).Status}catch{$r.error=$_.Exception.Message;$r.denied=(IsDenied $_.Exception)}
            ConvertTo-Json -InputObject $r -Compress
            """;
    }

    /// <summary>
    /// Ends a process. The expected process name guards against PID reuse between the
    /// administrator's confirmation and execution.
    /// </summary>
    public static string StopProcess(int processId, string expectedName)
    {
        if (processId <= 4) throw new ArgumentOutOfRangeException(nameof(processId), "System processes cannot be ended.");
        if (!PowerShellCommand.IsValidProcessName(expectedName))
            throw new ArgumentException("Invalid process name.", nameof(expectedName));

        return Prelude + $$"""

            $id={{processId.ToString(CultureInfo.InvariantCulture)}};$x={{PowerShellCommand.Literal(expectedName)}}
            $r=[ordered]@{ok=$false;denied=$false}
            try{$p=Get-Process -Id $id;if($p.ProcessName -ne $x){throw ('PID '+$id+' now belongs to '+$p.ProcessName+'; refresh and try again.')};Stop-Process -Id $id -Force;$r.ok=$true}catch{$r.error=$_.Exception.Message;$r.denied=(IsDenied $_.Exception)}
            ConvertTo-Json -InputObject $r -Compress
            """;
    }

    public enum PowerAction { Restart, Shutdown }

    /// <summary>
    /// Schedules a restart/shutdown with shutdown.exe so that a signed-in user sees a visible
    /// warning and can be told why; the administrator can cancel with <see cref="CancelPowerAction"/>.
    /// </summary>
    public static string SchedulePower(PowerAction action, int delaySeconds)
    {
        if (delaySeconds is < 0 or > 600) throw new ArgumentOutOfRangeException(nameof(delaySeconds));
        var flag = action == PowerAction.Restart ? "/r" : "/s";
        return Prelude + $$"""

            $r=[ordered]@{ok=$false;denied=$false}
            $out=& shutdown.exe {{flag}} /t {{delaySeconds.ToString(CultureInfo.InvariantCulture)}} /d p:4:1 /c 'Requested by the administrator via HHJ Remote Manager.' 2>&1
            if($LASTEXITCODE -eq 0){$r.ok=$true}else{$r.error=('shutdown.exe exit code '+$LASTEXITCODE+': '+($out -join ' '));$r.denied=($LASTEXITCODE -eq 5)}
            ConvertTo-Json -InputObject $r -Compress
            """;
    }

    public static readonly string CancelPowerAction = Prelude + """

        $r=[ordered]@{ok=$false;denied=$false}
        $out=& shutdown.exe /a 2>&1
        if($LASTEXITCODE -eq 0){$r.ok=$true}else{$r.error=('shutdown.exe exit code '+$LASTEXITCODE+': '+($out -join ' '));$r.denied=($LASTEXITCODE -eq 5)}
        ConvertTo-Json -InputObject $r -Compress
        """;

    /// <summary>Flushes the DNS client cache (requires administrator rights on the endpoint).</summary>
    public static readonly string FlushDns = Prelude + """

        $r=[ordered]@{ok=$false;denied=$false}
        try{Clear-DnsClientCache;$r.ok=$true}catch{$r.error=$_.Exception.Message;$r.denied=(IsDenied $_.Exception) -or ($_.Exception.Message -match '0x80041003|Access')}
        ConvertTo-Json -InputObject $r -Compress
        """;

    /// <summary>Recent critical/error/warning events from the System and Application logs.</summary>
    public static string EventLogSummary(int hours, int maxEvents)
    {
        if (hours is < 1 or > 720) throw new ArgumentOutOfRangeException(nameof(hours));
        if (maxEvents is < 1 or > 500) throw new ArgumentOutOfRangeException(nameof(maxEvents));
        var h = hours.ToString(CultureInfo.InvariantCulture);
        var n = maxEvents.ToString(CultureInfo.InvariantCulture);
        return Prelude + """

            $r=[ordered]@{errors=@()}
            $since=(Get-Date).AddHours(-__HOURS__);$e=@()
            foreach($l in 'System','Application'){try{$e+=@(Get-WinEvent -FilterHashtable @{LogName=$l;Level=1,2,3;StartTime=$since} -MaxEvents __MAX__)}catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){$r.errors+=($l+': '+$_.Exception.Message)}}}
            $r.entries=@($e|Sort-Object TimeCreated -Descending|Select-Object -First __MAX__|ForEach-Object{$m=[string]$_.Message;if($m){$m=($m -split "`r?`n")[0].Trim();if($m.Length -gt 300){$m=$m.Substring(0,300)}};[ordered]@{time=$_.TimeCreated.ToUniversalTime().ToString('o');log=$_.LogName;level=[string]$_.LevelDisplayName;id=$_.Id;source=$_.ProviderName;message=$m}})
            ConvertTo-Json -InputObject $r -Depth 4 -Compress
            """.Replace("__HOURS__", h, StringComparison.Ordinal).Replace("__MAX__", n, StringComparison.Ordinal);
    }
}
