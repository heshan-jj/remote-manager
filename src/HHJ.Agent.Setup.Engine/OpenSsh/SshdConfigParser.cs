namespace HHJ.Agent.Setup.Engine.OpenSsh;

public sealed record SshdConfigSummary(
    int Port,
    bool? PasswordAuthentication,
    bool? PubkeyAuthentication,
    bool HasMatchAdministratorsBlock,
    string? AdministratorsAuthorizedKeysFile);

/// <summary>
/// Read-only parser for Windows OpenSSH <c>sshd_config</c>. Never modifies the file.
/// </summary>
public static class SshdConfigParser
{
    public static SshdConfigSummary Parse(string? content)
    {
        var port = 22;
        bool? passwordAuth = null;
        bool? pubkeyAuth = null;
        var inMatchAdmin = false;
        var hasMatchAdmin = false;
        string? adminAuthKeys = null;

        if (string.IsNullOrWhiteSpace(content))
            return new(port, passwordAuth, pubkeyAuth, hasMatchAdmin, adminAuthKeys);

        foreach (var rawLine in content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var line = StripComment(rawLine).Trim();
            if (line.Length == 0) continue;

            var parts = line.Split([' ', '\t'], 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;

            var key = parts[0];
            var val = parts[1].Trim();

            if (key.Equals("Match", StringComparison.OrdinalIgnoreCase))
            {
                inMatchAdmin = val.Contains("Group", StringComparison.OrdinalIgnoreCase) &&
                               val.Contains("administrators", StringComparison.OrdinalIgnoreCase);
                if (inMatchAdmin) hasMatchAdmin = true;
                continue;
            }

            if (inMatchAdmin)
            {
                if (key.Equals("AuthorizedKeysFile", StringComparison.OrdinalIgnoreCase))
                    adminAuthKeys = val;
                continue;
            }

            if (key.Equals("Port", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(val, out var parsedPort) && parsedPort is >= 1 and <= 65535)
            {
                port = parsedPort;
            }
            else if (key.Equals("PasswordAuthentication", StringComparison.OrdinalIgnoreCase))
            {
                passwordAuth = ParseYesNo(val);
            }
            else if (key.Equals("PubkeyAuthentication", StringComparison.OrdinalIgnoreCase))
            {
                pubkeyAuth = ParseYesNo(val);
            }
        }

        return new SshdConfigSummary(port, passwordAuth, pubkeyAuth, hasMatchAdmin, adminAuthKeys);
    }

    private static string StripComment(string line)
    {
        var idx = line.IndexOf('#');
        return idx >= 0 ? line[..idx] : line;
    }

    private static bool? ParseYesNo(string val) =>
        val.Equals("yes", StringComparison.OrdinalIgnoreCase) ? true :
        val.Equals("no", StringComparison.OrdinalIgnoreCase) ? false : null;
}
