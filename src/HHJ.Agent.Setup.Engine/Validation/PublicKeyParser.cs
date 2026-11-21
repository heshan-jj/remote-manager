using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace HHJ.Agent.Setup.Engine.Validation;

public sealed record ParsedPublicKey(
    string KeyType,
    string Base64Blob,
    string FingerprintSha256,
    int? RsaKeyBits,
    string? OriginalComment);

public sealed record PublicKeyParseResult(bool IsValid, ParsedPublicKey? Key, string? Error);

public sealed record AuthorizedKeyEntry(
    string RawLine,
    string KeyType,
    string Base64Blob,
    string FingerprintSha256,
    bool IsHhjManaged,
    string? HhjDate,
    string? HhjLabel);

/// <summary>
/// Strictly validates OpenSSH public keys, computes OpenSSH-compatible SHA-256 fingerprints,
/// and performs idempotent merge/revoke operations on authorized_keys files.
/// </summary>
public static class PublicKeyParser
{
    public const string HhjMarkerPrefix = "hhj-remote-manager:";
    public const int MinimumRsaBits = 3072;

    private static readonly HashSet<string> SupportedTypes = new(StringComparer.Ordinal)
    {
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "ssh-rsa",
    };

    public static PublicKeyParseResult Parse(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return new(false, null, "Please paste an OpenSSH public key.");

        var trimmed = input.Trim();
        if (trimmed.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            return new(false, null, "This looks like a PRIVATE key. Never paste a private key here — paste the public key (.pub) line instead.");

        if (trimmed.Contains('\n') || trimmed.Contains('\r'))
            return new(false, null, "A public key must be a single line.");

        var parts = trimmed.Split([' ', '\t'], 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            return new(false, null, "Invalid OpenSSH public key format. Expected '<type> <base64> [comment]'.");

        var type = parts[0];
        var b64 = parts[1];
        var comment = parts.Length == 3 ? parts[2].Trim() : null;

        if (!SupportedTypes.Contains(type))
            return new(false, null, $"Unsupported key type '{type}'. Supported types: ssh-ed25519, ecdsa-sha2-nistp256/384/521, ssh-rsa.");

        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(b64);
        }
        catch (FormatException)
        {
            return new(false, null, "The public key base64 payload is invalid.");
        }

        if (blob.Length < 8)
            return new(false, null, "The public key blob is too short.");

        if (!TryReadSshString(blob, 0, out var embeddedTypeBytes, out var offset))
            return new(false, null, "Malformed SSH wire-format public key blob.");

        var embeddedType = Encoding.ASCII.GetString(embeddedTypeBytes);
        if (!string.Equals(embeddedType, type, StringComparison.Ordinal))
            return new(false, null, $"Key type mismatch: line starts with '{type}' but blob contains '{embeddedType}'.");

        int? rsaBits = null;
        if (type == "ssh-rsa")
        {
            // Wire format: "ssh-rsa" || mpint e || mpint n
            if (!TryReadSshString(blob, offset, out _, out offset) ||
                !TryReadSshString(blob, offset, out var modulus, out _))
            {
                return new(false, null, "Malformed ssh-rsa public key blob.");
            }
            rsaBits = CountModulusBits(modulus);
            if (rsaBits < MinimumRsaBits)
                return new(false, null, $"RSA key is {rsaBits} bits; at least {MinimumRsaBits} bits are required.");
        }

        var fp = Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=');
        return new(true, new ParsedPublicKey(type, b64, fp, rsaBits, comment), null);
    }

    public static string FormatHhjLine(ParsedPublicKey key, DateOnly date, string label = "admin")
    {
        var safeLabel = SanitizeLabel(label);
        return $"{key.KeyType} {key.Base64Blob} {HhjMarkerPrefix}{date:yyyy-MM-dd}:{safeLabel}";
    }

    public static (string UpdatedContent, bool Added) MergeAuthorizedKeys(string existingContent, string formattedHhjLine, ParsedPublicKey parsed)
    {
        var lines = SplitLines(existingContent);
        foreach (var line in lines)
        {
            var t = line.Trim();
            if (t.Length == 0 || t.StartsWith('#')) continue;
            var parts = t.Split([' ', '\t'], 3, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 &&
                string.Equals(parts[0], parsed.KeyType, StringComparison.Ordinal) &&
                string.Equals(parts[1], parsed.Base64Blob, StringComparison.Ordinal))
            {
                return (NormalizeTrailingNewline(lines), false);
            }
        }

        lines.Add(formattedHhjLine);
        return (NormalizeTrailingNewline(lines), true);
    }

    public static IReadOnlyList<AuthorizedKeyEntry> ListHhjKeys(string content)
    {
        var result = new List<AuthorizedKeyEntry>();
        foreach (var raw in SplitLines(content))
        {
            var t = raw.Trim();
            if (t.Length == 0 || t.StartsWith('#')) continue;
            var parsed = Parse(t);
            if (!parsed.IsValid || parsed.Key is null) continue;

            var comment = parsed.Key.OriginalComment;
            if (comment is not null && comment.StartsWith(HhjMarkerPrefix, StringComparison.OrdinalIgnoreCase))
            {
                var rest = comment[HhjMarkerPrefix.Length..];
                var colon = rest.IndexOf(':');
                var date = colon > 0 ? rest[..colon] : rest;
                var label = colon > 0 ? rest[(colon + 1)..] : "";
                result.Add(new AuthorizedKeyEntry(t, parsed.Key.KeyType, parsed.Key.Base64Blob, parsed.Key.FingerprintSha256, true, date, label));
            }
        }
        return result;
    }

    public static (string UpdatedContent, int RemovedCount) RevokeHhjKeys(string existingContent, string? fingerprintSha256 = null)
    {
        var lines = SplitLines(existingContent);
        var kept = new List<string>(lines.Count);
        var removed = 0;

        foreach (var raw in lines)
        {
            var t = raw.Trim();
            if (t.Length > 0 && !t.StartsWith('#'))
            {
                var parsed = Parse(t);
                var comment = parsed.Key?.OriginalComment;
                var isHhj = parsed.IsValid && comment is not null &&
                            comment.StartsWith(HhjMarkerPrefix, StringComparison.OrdinalIgnoreCase);
                if (isHhj && (fingerprintSha256 is null ||
                              string.Equals(parsed.Key!.FingerprintSha256, fingerprintSha256, StringComparison.Ordinal)))
                {
                    removed++;
                    continue;
                }
            }
            kept.Add(raw);
        }

        return (NormalizeTrailingNewline(kept), removed);
    }

    private static bool TryReadSshString(byte[] blob, int offset, out ReadOnlySpan<byte> data, out int nextOffset)
    {
        data = default;
        nextOffset = offset;
        if (offset + 4 > blob.Length) return false;
        var len = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(offset, 4));
        if (len > int.MaxValue || offset + 4 + (int)len > blob.Length) return false;
        data = blob.AsSpan(offset + 4, (int)len);
        nextOffset = offset + 4 + (int)len;
        return true;
    }

    private static int CountModulusBits(ReadOnlySpan<byte> mpint)
    {
        var i = 0;
        while (i < mpint.Length && mpint[i] == 0) i++;
        if (i >= mpint.Length) return 0;
        var leadingByte = mpint[i];
        var highBit = 8 - int.LeadingZeroCount(leadingByte) + 24; // LeadingZeroCount on uint
        return (mpint.Length - i - 1) * 8 + highBit;
    }

    private static List<string> SplitLines(string content) =>
        string.IsNullOrEmpty(content)
            ? []
            : content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n').ToList();

    private static string NormalizeTrailingNewline(List<string> lines)
    {
        while (lines.Count > 0 && string.IsNullOrWhiteSpace(lines[^1])) lines.RemoveAt(lines.Count - 1);
        return lines.Count == 0 ? "" : string.Join("\r\n", lines) + "\r\n";
    }

    private static string SanitizeLabel(string label)
    {
        var clean = new string(label.Trim().Where(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.').ToArray());
        return string.IsNullOrEmpty(clean) ? "admin" : clean;
    }
}
