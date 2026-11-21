using System.Globalization;
using System.Text;

namespace HHJ.Agent.Setup.Engine.Firewall;

public sealed record FirewallRuleSnapshot(
    string Name,
    string? Group,
    bool Enabled,
    string Direction,
    string Action,
    string? Protocol,
    string? LocalPort,
    string? RemoteAddress,
    string? Program,
    string? InterfaceAlias);

public sealed record DesiredFirewallRule(
    string Name,
    string Group,
    int LocalPort,
    string ProgramPath,
    IReadOnlyList<string> RemoteAddresses,
    string? InterfaceAlias);

public enum HhjRuleAction { Create, UpdateInPlace, NoChange }

public sealed record BroadRuleFinding(string Name, string Reason, string? RemoteAddress);

public sealed record FirewallPlan(
    HhjRuleAction Action,
    DesiredFirewallRule Desired,
    IReadOnlyList<BroadRuleFinding> BroadRules,
    IReadOnlyList<string> Warnings);

/// <summary>
/// Pure firewall reconciliation logic + safe PowerShell NetSecurity script builder (-EncodedCommand).
/// </summary>
public static class FirewallReconciler
{
    public const string HhjRuleName = "HHJ Remote Manager - OpenSSH (Tailscale only)";
    public const string HhjRuleGroup = "HHJ Remote Manager";
    public static readonly string[] TailscaleCidrs = ["100.64.0.0/10", "fd7a:115c:a1e0::/48"];

    public static FirewallPlan Reconcile(
        IReadOnlyList<FirewallRuleSnapshot> existingRules,
        int sshdPort,
        string sshdExePath,
        string? tailscaleInterfaceAlias)
    {
        var desired = new DesiredFirewallRule(
            HhjRuleName,
            HhjRuleGroup,
            sshdPort,
            sshdExePath,
            TailscaleCidrs,
            string.IsNullOrWhiteSpace(tailscaleInterfaceAlias) ? null : tailscaleInterfaceAlias.Trim());

        var warnings = new List<string>();
        if (desired.InterfaceAlias is null)
        {
            warnings.Add("Tailscale network adapter was not detected; the rule will be scoped by Tailscale IP ranges (100.64.0.0/10, fd7a:115c:a1e0::/48) only.");
        }

        var existingHhj = existingRules.FirstOrDefault(r =>
            string.Equals(r.Name, HhjRuleName, StringComparison.OrdinalIgnoreCase));

        HhjRuleAction action;
        if (existingHhj is null)
        {
            action = HhjRuleAction.Create;
        }
        else if (MatchesDesired(existingHhj, desired))
        {
            action = HhjRuleAction.NoChange;
        }
        else
        {
            action = HhjRuleAction.UpdateInPlace;
        }

        var broad = new List<BroadRuleFinding>();
        var portStr = sshdPort.ToString(CultureInfo.InvariantCulture);

        foreach (var r in existingRules)
        {
            if (string.Equals(r.Name, HhjRuleName, StringComparison.OrdinalIgnoreCase)) continue;
            if (!r.Enabled) continue;
            if (!string.Equals(r.Direction, "Inbound", StringComparison.OrdinalIgnoreCase)) continue;
            if (!string.Equals(r.Action, "Allow", StringComparison.OrdinalIgnoreCase)) continue;

            var affectsPort = string.Equals(r.LocalPort, portStr, StringComparison.OrdinalIgnoreCase) ||
                              string.Equals(r.LocalPort, "Any", StringComparison.OrdinalIgnoreCase);
            var affectsProgram = !string.IsNullOrWhiteSpace(r.Program) &&
                                 r.Program.EndsWith("sshd.exe", StringComparison.OrdinalIgnoreCase);

            if (!affectsPort && !affectsProgram) continue;

            var isAnyRemote = string.IsNullOrWhiteSpace(r.RemoteAddress) ||
                              r.RemoteAddress.Equals("Any", StringComparison.OrdinalIgnoreCase) ||
                              r.RemoteAddress.Equals("*", StringComparison.OrdinalIgnoreCase);

            if (isAnyRemote)
            {
                broad.Add(new BroadRuleFinding(
                    r.Name,
                    $"Enabled inbound Allow rule '{r.Name}' permits connections from ANY remote IP address on port {r.LocalPort ?? "Any"}.",
                    r.RemoteAddress ?? "Any"));
            }
        }

        return new FirewallPlan(action, desired, broad, warnings);
    }

    private static bool MatchesDesired(FirewallRuleSnapshot existing, DesiredFirewallRule desired)
    {
        if (!existing.Enabled) return false;
        if (!string.Equals(existing.Direction, "Inbound", StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.Equals(existing.Action, "Allow", StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.Equals(existing.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.Equals(existing.LocalPort, desired.LocalPort.ToString(CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.Equals(existing.Program, desired.ProgramPath, StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.Equals(existing.InterfaceAlias ?? "", desired.InterfaceAlias ?? "", StringComparison.OrdinalIgnoreCase)) return false;

        var existingAddrs = (existing.RemoteAddress ?? "")
            .Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var desiredAddrs = desired.RemoteAddresses
            .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return existingAddrs.SequenceEqual(desiredAddrs, StringComparer.OrdinalIgnoreCase);
    }

    public static string BuildApplyScript(DesiredFirewallRule rule)
    {
        var name = PsLiteral(rule.Name);
        var group = PsLiteral(rule.Group);
        var prog = PsLiteral(rule.ProgramPath);
        var port = rule.LocalPort.ToString(CultureInfo.InvariantCulture);
        var addrs = string.Join(",", rule.RemoteAddresses.Select(PsLiteral));
        var ifaceParam = rule.InterfaceAlias is not null
            ? $"-InterfaceAlias {PsLiteral(rule.InterfaceAlias)}"
            : "-InterfaceAlias Any";

        return $$"""
            $ErrorActionPreference='Stop'
            $existing = Get-NetFirewallRule -DisplayName {{name}} -ErrorAction SilentlyContinue
            if ($existing) { Remove-NetFirewallRule -DisplayName {{name}} }
            New-NetFirewallRule -Name {{name}} -DisplayName {{name}} -Group {{group}} -Direction Inbound -Action Allow -Enabled True -Protocol TCP -LocalPort {{port}} -Program {{prog}} -RemoteAddress @({{addrs}}) {{ifaceParam}} -Profile Any | Out-Null
            """;
    }

    public static string BuildDisableRuleScript(string ruleName) =>
        $"$ErrorActionPreference='Stop'; Disable-NetFirewallRule -DisplayName {PsLiteral(ruleName)}";

    public static string BuildEnableRuleScript(string ruleName) =>
        $"$ErrorActionPreference='Stop'; Enable-NetFirewallRule -DisplayName {PsLiteral(ruleName)}";

    public static string BuildRemoveHhjRuleScript() =>
        $"$ErrorActionPreference='SilentlyContinue'; Remove-NetFirewallRule -DisplayName {PsLiteral(HhjRuleName)}";

    public static string PsLiteral(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var sb = new StringBuilder(value.Length + 2).Append('\'');
        foreach (var c in value)
        {
            sb.Append(c);
            if (c is '\'' or '\u2018' or '\u2019' or '\u201A' or '\u201B') sb.Append(c);
        }
        return sb.Append('\'').ToString();
    }

    public static string ToEncodedCommand(string script) =>
        Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
}
