using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using HHJ.RemoteManager.Core.Connections;

namespace HHJ.RemoteManager.Core.Telemetry;

/// <summary>
/// Parses the JSON documents produced by <see cref="Remote.RemoteScripts"/>. Tolerates a UTF-8 BOM,
/// stray banner lines, and Windows PowerShell 5.1's habit of collapsing single-element arrays.
/// </summary>
public static partial class TelemetryJson
{
    public static readonly JsonSerializerOptions Options = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var o = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            NumberHandling = JsonNumberHandling.AllowReadingFromString,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        };
        o.Converters.Add(new SingleOrArrayListConverterFactory());
        return o;
    }

    /// <summary>Extracts the last line of <paramref name="stdout"/> that looks like a JSON document.</summary>
    public static string ExtractJson(string? stdout)
    {
        if (string.IsNullOrWhiteSpace(stdout)) throw new TelemetryParseException("The remote command produced no output.");
        var text = stdout.Replace("\uFEFF", "", StringComparison.Ordinal);
        var lines = text.Split('\n');
        for (var i = lines.Length - 1; i >= 0; i--)
        {
            var line = lines[i].Trim();
            if (line.Length >= 2 && ((line[0] == '{' && line[^1] == '}') || (line[0] == '[' && line[^1] == ']')))
                return line;
        }
        throw new TelemetryParseException("The remote command did not return JSON. Output began with: " + Truncate(text.Trim(), 200));
    }

    public static T Parse<T>(string? stdout)
    {
        var json = ExtractJson(stdout);
        try
        {
            return JsonSerializer.Deserialize<T>(json, Options)
                   ?? throw new TelemetryParseException("The remote command returned an empty JSON document.");
        }
        catch (JsonException ex)
        {
            throw new TelemetryParseException($"Invalid telemetry JSON: {ex.Message}", ex);
        }
    }

    [GeneratedRegex(@"<S S=""Error"">(.*?)</S>", RegexOptions.Singleline)]
    private static partial Regex ClixmlErrorRegex();

    /// <summary>
    /// Converts Windows PowerShell's CLIXML-serialised stderr (emitted when stderr is redirected) into
    /// plain text. Non-CLIXML input is returned trimmed.
    /// </summary>
    public static string CleanStdErr(string? stderr)
    {
        if (string.IsNullOrWhiteSpace(stderr)) return "";
        if (!stderr.Contains("#< CLIXML", StringComparison.Ordinal)) return stderr.Trim();
        var parts = ClixmlErrorRegex().Matches(stderr).Select(m => m.Groups[1].Value
            .Replace("_x000D_", "", StringComparison.Ordinal)
            .Replace("_x000A_", " ", StringComparison.Ordinal)
            .Replace("&lt;", "<", StringComparison.Ordinal)
            .Replace("&gt;", ">", StringComparison.Ordinal)
            .Replace("&quot;", "\"", StringComparison.Ordinal)
            .Replace("&apos;", "'", StringComparison.Ordinal)
            .Replace("&amp;", "&", StringComparison.Ordinal));
        return string.Join("", parts).Trim();
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    /// <summary>Reads either a JSON array or a single object/value into a <see cref="List{T}"/>.</summary>
    private sealed class SingleOrArrayListConverterFactory : JsonConverterFactory
    {
        public override bool CanConvert(Type typeToConvert) =>
            typeToConvert.IsGenericType && typeToConvert.GetGenericTypeDefinition() == typeof(List<>);

        public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options)
        {
            var elementType = typeToConvert.GetGenericArguments()[0];
            return (JsonConverter)Activator.CreateInstance(typeof(SingleOrArrayListConverter<>).MakeGenericType(elementType))!;
        }
    }

    private sealed class SingleOrArrayListConverter<T> : JsonConverter<List<T>>
    {
        public override List<T>? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.Null:
                    return [];
                case JsonTokenType.StartArray:
                    var list = new List<T>();
                    while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                    {
                        var item = JsonSerializer.Deserialize<T>(ref reader, options);
                        if (item is not null) list.Add(item);
                    }
                    return list;
                default:
                    var single = JsonSerializer.Deserialize<T>(ref reader, options);
                    return single is null ? [] : [single];
            }
        }

        public override void Write(Utf8JsonWriter writer, List<T> value, JsonSerializerOptions options)
        {
            writer.WriteStartArray();
            foreach (var item in value) JsonSerializer.Serialize(writer, item, options);
            writer.WriteEndArray();
        }
    }
}
