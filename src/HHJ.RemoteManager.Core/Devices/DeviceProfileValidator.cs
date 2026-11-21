using System.Net;
using System.Text.RegularExpressions;

namespace HHJ.RemoteManager.Core.Devices;

public sealed record ValidationResult(IReadOnlyList<string> Errors)
{
    public bool IsValid => Errors.Count == 0;
    public static readonly ValidationResult Success = new([]);
}

/// <summary>
/// Validates device profiles. Values are never interpolated into shell commands, but strict
/// validation still prevents malformed configuration and confusing failures.
/// </summary>
public static partial class DeviceProfileValidator
{
    public const int MaxDisplayNameLength = 64;
    public const int MaxTagLength = 32;
    public const int MaxTags = 16;

    // RFC 1123 host names (labels 1-63 chars, letters/digits/hyphen, no leading/trailing hyphen).
    [GeneratedRegex(@"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")]
    private static partial Regex HostNameRegex();

    // Windows local/Microsoft-account style user names, optionally DOMAIN\user or user@domain.
    // Excludes characters Windows forbids in account names: " / \ [ ] : ; | = , + * ? < >
    [GeneratedRegex(@"^(?:[A-Za-z0-9][A-Za-z0-9._-]{0,14}\\)?[^""/\\\[\]:;|=,+*?<>@\s][^""/\\\[\]:;|=,+*?<>\s]{0,103}(?:@[A-Za-z0-9.-]{1,253})?$")]
    private static partial Regex UserNameRegex();

    [GeneratedRegex(@"^[\p{L}\p{N} _.\-()]+$")]
    private static partial Regex DisplayNameRegex();

    [GeneratedRegex(@"^[\p{L}\p{N}_.\-]+$")]
    private static partial Regex TagRegex();

    public static bool IsValidAddress(string? address)
    {
        if (string.IsNullOrWhiteSpace(address)) return false;
        address = address.Trim();
        if (IPAddress.TryParse(address, out _)) return true;
        return HostNameRegex().IsMatch(address);
    }

    public static bool IsValidUserName(string? user) =>
        !string.IsNullOrWhiteSpace(user) && UserNameRegex().IsMatch(user);

    public static ValidationResult Validate(DeviceProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(profile.DisplayName))
            errors.Add("Display name is required.");
        else if (profile.DisplayName.Length > MaxDisplayNameLength)
            errors.Add($"Display name must be at most {MaxDisplayNameLength} characters.");
        else if (!DisplayNameRegex().IsMatch(profile.DisplayName))
            errors.Add("Display name may contain letters, digits, spaces, '.', '-', '_' and parentheses only.");

        if (!IsValidAddress(profile.Address))
            errors.Add("Address must be a valid host name (e.g. brother-pc.tailnet-name.ts.net) or IP address.");

        if (profile.Port is < 1 or > 65535)
            errors.Add("SSH port must be between 1 and 65535.");

        if (!IsValidUserName(profile.Username))
            errors.Add("Username is not a valid Windows account name.");

        if (string.IsNullOrWhiteSpace(profile.KeyId))
            errors.Add("Select an SSH key for public-key authentication.");

        if (profile.Tags.Count > MaxTags)
            errors.Add($"At most {MaxTags} tags are allowed.");
        foreach (var tag in profile.Tags)
        {
            if (tag.Length is 0 or > MaxTagLength || !TagRegex().IsMatch(tag))
            {
                errors.Add($"Invalid tag '{tag}'. Tags may contain letters, digits, '.', '-' and '_' (max {MaxTagLength}).");
            }
        }

        return errors.Count == 0 ? ValidationResult.Success : new ValidationResult(errors);
    }

    /// <summary>Parses a comma/space separated tag string into a normalised, de-duplicated list.</summary>
    public static List<string> ParseTags(string? text) =>
        string.IsNullOrWhiteSpace(text)
            ? []
            : text.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                  .Distinct(StringComparer.OrdinalIgnoreCase)
                  .ToList();
}
