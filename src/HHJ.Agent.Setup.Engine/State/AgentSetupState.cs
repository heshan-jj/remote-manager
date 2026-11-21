using System.Text.Json;

namespace HHJ.Agent.Setup.Engine.State;

/// <summary>
/// Persists ONLY changes made by HHJ Agent Setup (<c>C:\ProgramData\HHJ\AgentSetup\state.json</c>),
/// enabling clean rollback and idempotent re-runs.
/// </summary>
public sealed class AgentSetupState
{
    public int SchemaVersion { get; set; } = 1;
    public DateTimeOffset? FirstConfiguredUtc { get; set; }
    public DateTimeOffset? LastUpdatedUtc { get; set; }

    public bool OpenSshInstalledByHhj { get; set; }
    public string? SshdOriginalStartType { get; set; }
    public bool DefaultShellChangedByHhj { get; set; }
    public bool DefaultShellPreviouslyExisted { get; set; }
    public string? DefaultShellPreviousValue { get; set; }

    public bool TailscaleInstalledByHhj { get; set; }

    public bool FirewallRuleCreatedByHhj { get; set; }
    public List<DisabledFirewallRuleRecord> DisabledFirewallRules { get; set; } = [];

    public List<AddedAuthorizedKeyRecord> AddedAuthorizedKeys { get; set; } = [];
}

public sealed class DisabledFirewallRuleRecord
{
    public string Name { get; set; } = "";
    public bool WasEnabled { get; set; } = true;
}

public sealed class AddedAuthorizedKeyRecord
{
    public string FilePath { get; set; } = "";
    public string FingerprintSha256 { get; set; } = "";
    public string Username { get; set; } = "";
    public DateTimeOffset AddedUtc { get; set; }
}

public static class AgentSetupStateStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static string Serialize(AgentSetupState state) =>
        JsonSerializer.Serialize(state, JsonOptions);

    public static AgentSetupState Deserialize(string json) =>
        JsonSerializer.Deserialize<AgentSetupState>(json, JsonOptions) ?? new AgentSetupState();
}
