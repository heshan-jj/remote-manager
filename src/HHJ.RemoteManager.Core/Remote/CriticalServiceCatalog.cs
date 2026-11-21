namespace HHJ.RemoteManager.Core.Remote;

/// <summary>
/// Identifies Windows services whose disruption can lock out remote management or destabilise
/// the operating system, so the UI can warn and require explicit confirmation.
/// </summary>
public static class CriticalServiceCatalog
{
    public enum RiskLevel { Normal, Caution, Critical }

    public sealed record ServiceRisk(RiskLevel Level, string? Reason);

    private static readonly Dictionary<string, ServiceRisk> Known = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sshd"] = new(RiskLevel.Critical, "Stopping or restarting OpenSSH Server will drop this remote management session."),
        ["Tailscale"] = new(RiskLevel.Critical, "Stopping or restarting Tailscale will drop the VPN tunnel and disconnect this session."),
        ["RpcSs"] = new(RiskLevel.Critical, "Remote Procedure Call (RPC) is essential to Windows; stopping it can crash or freeze the OS."),
        ["DcomLaunch"] = new(RiskLevel.Critical, "DCOM Server Process Launcher is essential to Windows."),
        ["Winmgmt"] = new(RiskLevel.Caution, "Windows Management Instrumentation (WMI/CIM) is used for performance and service monitoring."),
        ["mpssvc"] = new(RiskLevel.Critical, "Windows Defender Firewall protects the host; stopping it affects network security."),
        ["WinDefend"] = new(RiskLevel.Caution, "Microsoft Defender Antivirus protects the host."),
        ["Dhcp"] = new(RiskLevel.Caution, "Stopping DHCP Client may cause the computer to lose its IP address."),
        ["Dnscache"] = new(RiskLevel.Caution, "Stopping DNS Client may break name resolution including MagicDNS."),
        ["Netman"] = new(RiskLevel.Caution, "Network Connections manages network adapters."),
        ["EventLog"] = new(RiskLevel.Caution, "Windows Event Log records system and security diagnostics."),
        ["LanmanServer"] = new(RiskLevel.Normal, null),
    };

    public static ServiceRisk Assess(string serviceName) =>
        Known.TryGetValue(serviceName, out var risk) ? risk : new(RiskLevel.Normal, null);
}
