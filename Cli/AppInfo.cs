using System.Reflection;

namespace TECmd;

/// <summary>
/// Single source of truth for the product identity.
///
/// The version is declared once in TE-CMD.csproj (&lt;Version&gt;) and reaches
/// every consumer (help text, --version, ZIP names, manifests, README) through
/// the assembly attributes. Nothing is written down twice.
/// </summary>
static class AppInfo
{
    public static string Version { get; } = ReadVersion();
    public static string EngineVersion { get; } = ReadAssemblyVersion();

    public static string Description => $"{Product} v{Version} / DecompilerSuite CLI Edition";
    public const string Product = "TE-CMD";

    static string ReadVersion()
    {
        var asm = Assembly.GetExecutingAssembly();
        string? v = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (string.IsNullOrWhiteSpace(v)) v = asm.GetName().Version?.ToString() ?? "1.0.0";
        int plus = v.IndexOf('+');
        if (plus > 0) v = v[..plus];
        return v.Trim();
    }

    static string ReadAssemblyVersion()
    {
        var asm = Assembly.GetExecutingAssembly();
        return asm.GetCustomAttribute<AssemblyFileVersionAttribute>()?.Version ?? "?";
    }
}
