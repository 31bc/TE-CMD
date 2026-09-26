using System.Text.Json;

namespace TECmd;

/// <summary>
/// Optional defaults from <c>config\config.json</c> next to the executable.
/// Command line options always win over the file.
/// </summary>
sealed class AppConfig
{
    public string? Output;
    public int? MinString;
    public bool? Color;

    public static AppConfig Load()
    {
        var cfg = new AppConfig();
        string path = Path.Combine(AppContext.BaseDirectory, "config", "config.json");
        if (!File.Exists(path)) return cfg;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return cfg;
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                switch (p.Name.ToLowerInvariant())
                {
                    case "output":
                        cfg.Output = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : null;
                        break;
                    case "minstring":
                    case "min-string":
                        if (p.Value.ValueKind == JsonValueKind.Number && p.Value.TryGetInt32(out int n) && n > 0)
                            cfg.MinString = n;
                        break;
                    case "color":
                        if (p.Value.ValueKind is JsonValueKind.True or JsonValueKind.False)
                            cfg.Color = p.Value.GetBoolean();
                        break;
                }
            }
        }
        catch { /* a broken config file must never stop the tool */ }
        return cfg;
    }

    /// <summary>File defaults. Command line options always win.</summary>
    public void ApplyTo(CliOptions opt)
    {
        if (!opt.OutputGiven)
        {
            string value = string.IsNullOrWhiteSpace(Output) ? "output" : Output!;
            opt.OutputBase = Path.IsPathRooted(value) ? value : Path.Combine(AppContext.BaseDirectory, value);
        }
        if (!opt.MinStringGiven && MinString is int m && m > 0) opt.MinString = m;
        if (Color == false) opt.NoColor = true;
    }

    /// <summary>Written on first run when config\config.json is missing.</summary>
    public static string DefaultJson() =>
        "{\n" +
        "  \"output\": \"output\",\n" +
        "  \"minString\": 5,\n" +
        "  \"color\": true\n" +
        "}\n";
}
