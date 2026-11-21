using System.Text;
using System.Text.RegularExpressions;

namespace HHJ.RemoteManager.Core.Remote;

/// <summary>
/// Builds PowerShell invocations that are safe to send over an SSH exec channel regardless of
/// whether the endpoint's OpenSSH default shell is cmd.exe or PowerShell.
/// Scripts are passed with -EncodedCommand (Base64 UTF-16LE), so no part of the script is ever
/// parsed by cmd.exe and no configuration value can break out into the outer shell.
/// </summary>
public static partial class PowerShellCommand
{
    /// <summary>cmd.exe's maximum command-line length (the strictest limit we may run into).</summary>
    public const int MaxCommandLineLength = 8191;

    private const string Launcher = "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ";

    /// <summary>Removes comments/indentation to keep the encoded command small.</summary>
    public static string Minify(string script)
    {
        var sb = new StringBuilder(script.Length);
        foreach (var raw in script.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            sb.Append(line).Append('\n');
        }
        return sb.ToString();
    }

    public static string Encode(string script) =>
        Convert.ToBase64String(Encoding.Unicode.GetBytes(Minify(script)));

    /// <summary>Returns the full command line to run over SSH.</summary>
    public static string Build(string script)
    {
        var command = Launcher + Encode(script);
        if (command.Length > MaxCommandLineLength)
        {
            throw new InvalidOperationException(
                $"Encoded PowerShell command is {command.Length} characters, exceeding the {MaxCommandLineLength}-character limit.");
        }
        return command;
    }

    /// <summary>
    /// Quotes a value as a PowerShell single-quoted (verbatim) string literal. PowerShell treats
    /// the Unicode quotation marks U+2018..U+201B as single quotes too, so they are doubled as well.
    /// </summary>
    public static string Literal(string value)
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

    // Windows service key names: no slashes; we additionally restrict to a conservative set.
    [GeneratedRegex(@"^[A-Za-z0-9_.\-$@{}]{1,256}$")]
    private static partial Regex ServiceNameRegex();

    [GeneratedRegex(@"^[\p{L}\p{N}_.\- ()+#]{1,260}$")]
    private static partial Regex ProcessNameRegex();

    public static bool IsValidServiceName(string? name) => name is not null && ServiceNameRegex().IsMatch(name);

    public static bool IsValidProcessName(string? name) => name is not null && ProcessNameRegex().IsMatch(name);
}
