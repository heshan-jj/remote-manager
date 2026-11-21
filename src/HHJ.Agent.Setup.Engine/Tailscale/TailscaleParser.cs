using System.Text.Json;
using System.Text.RegularExpressions;

namespace HHJ.Agent.Setup.Engine.Tailscale;

public sealed record TailscaleStatusInfo(
    string BackendState,
    string? SelfDnsName,
    IReadOnlyList<string> SelfIps,
    string? TailnetName,
    string? MagicDnsSuffix,
    string? LoggedInUser,
    string? AuthUrl);

/// <summary>
/// Parses <c>tailscale status --json</c>, extracts login URLs, validates hostnames,
/// and masks sensitive auth keys before logging.
/// </summary>
public static partial class TailscaleParser
{
    public const string OfficialMsiUrl = "https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi";
    public const string ExpectedPublisherOrganization = "Tailscale Inc.";

    [GeneratedRegex(@"^[a-z0-9-]{1,63}$")]
    private static partial Regex HostnameRegex();

    [GeneratedRegex(@"https://login\.tailscale\.com/[^\s""'<>]+", RegexOptions.IgnoreCase)]
    private static partial Regex AuthUrlRegex();

    public static bool IsValidTailscaleHostname(string? name) =>
        !string.IsNullOrEmpty(name) &&
        !name.StartsWith('-') &&
        !name.EndsWith('-') &&
        HostnameRegex().IsMatch(name);

    public static string? ExtractAuthUrl(string? output)
    {
        if (string.IsNullOrWhiteSpace(output)) return null;
        var m = AuthUrlRegex().Match(output);
        return m.Success ? m.Value.TrimEnd('.', ',', ';', ')') : null;
    }

    public static string MaskSecret(string text, string? secret)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(secret)) return text;
        return text.Replace(secret, "***REDACTED***", StringComparison.Ordinal);
    }

    public static TailscaleStatusInfo ParseStatusJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var backendState = root.TryGetProperty("BackendState", out var bs) ? bs.GetString() ?? "Unknown" : "Unknown";
        var authUrl = root.TryGetProperty("AuthURL", out var au) ? au.GetString() : null;
        if (string.IsNullOrWhiteSpace(authUrl)) authUrl = null;

        string? selfDns = null;
        var ips = new List<string>();
        long? selfUserId = null;

        if (root.TryGetProperty("Self", out var self) && self.ValueKind == JsonValueKind.Object)
        {
            if (self.TryGetProperty("DNSName", out var dns))
                selfDns = dns.GetString()?.TrimEnd('.');

            if (self.TryGetProperty("TailscaleIPs", out var ipArr) && ipArr.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in ipArr.EnumerateArray())
                {
                    var s = item.GetString();
                    if (!string.IsNullOrWhiteSpace(s)) ips.Add(s);
                }
            }

            if (self.TryGetProperty("UserID", out var uid) && uid.TryGetInt64(out var id))
                selfUserId = id;
        }

        string? tailnetName = null;
        string? magicSuffix = null;
        if (root.TryGetProperty("CurrentTailnet", out var tn) && tn.ValueKind == JsonValueKind.Object)
        {
            if (tn.TryGetProperty("Name", out var n)) tailnetName = n.GetString();
            if (tn.TryGetProperty("MagicDNSSuffix", out var ms)) magicSuffix = ms.GetString();
        }

        string? loginName = null;
        if (selfUserId is { } targetUid &&
            root.TryGetProperty("User", out var users) &&
            users.ValueKind == JsonValueKind.Object)
        {
            var key = targetUid.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (users.TryGetProperty(key, out var uObj) &&
                uObj.TryGetProperty("LoginName", out var ln))
            {
                loginName = ln.GetString();
            }
        }

        return new TailscaleStatusInfo(backendState, selfDns, ips, tailnetName, magicSuffix, loginName, authUrl);
    }
}
