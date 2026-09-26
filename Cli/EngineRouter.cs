using DecompilerSuite.Engines;
using DecompilerSuite.Helpers;

namespace TECmd;

/// <summary>
/// Maps a PackerType onto the DecompilerSuite engine and keeps the GUI
/// auto-correction behaviour (wrong engine selection falls back automatically).
/// </summary>
static class EngineRouter
{
    public static bool IsExtractEngine(PackerType mode) => mode switch
    {
        PackerType.PyInstaller => true,
        PackerType.Nuitka => true,
        PackerType.Pyz => true,
        PackerType.PyArmor => true,
        PackerType.Themida => true,
        _ => false,
    };

    /// <summary>Engine selection used by the GUI radio buttons (Auto = detected).</summary>
    public static PackerType ResolveMode(string? engineId, PackerType detected)
    {
        if (engineId != null && engineId != "auto") return FromId(engineId);
        return detected == PackerType.Unknown ? PackerType.Cpp : detected;
    }

    public static PackerType FromId(string id) => id switch
    {
        "pyinstaller" => PackerType.PyInstaller,
        "nuitka" => PackerType.Nuitka,
        "dotnet" => PackerType.DotNet,
        "cpp" => PackerType.Cpp,
        "pyarmor" => PackerType.PyArmor,
        "pyz" => PackerType.Pyz,
        "themida" => PackerType.Themida,
        _ => PackerType.Unknown,
    };

    public static string IdOf(PackerType mode) => mode switch
    {
        PackerType.PyInstaller => "pyinstaller",
        PackerType.Nuitka => "nuitka",
        PackerType.DotNet => "dotnet",
        PackerType.Cpp => "cpp",
        PackerType.PyArmor => "pyarmor",
        PackerType.Pyz => "pyz",
        PackerType.Themida => "themida",
        _ => "unknown",
    };

    /// <summary>Runs the engine and returns the id of the engine that actually ran.</summary>
    public static async Task<PackerType> RunAsync(PackerType mode, string file, string outDir, PackerType detected, CliLog log)
    {
        try
        {
            await DispatchAsync(mode, file, outDir, log);
            return mode;
        }
        catch (Exception ex) when (ex.Message.Contains("managed metadata") || ex.Message.Contains("PE file"))
        {
            // Same auto correction as MainWindow.DecompileWithResultsAsync
            log.Warn($"{Detector.Describe(mode)} failed: not a .NET file");
            PackerType fallback = detected != PackerType.Unknown ? detected : PackerType.PyInstaller;
            if (fallback != PackerType.PyInstaller && fallback != PackerType.Cpp) fallback = PackerType.PyInstaller;
            log.Info($"auto-correcting to {Detector.Describe(fallback)}");
            await DispatchAsync(fallback, file, outDir, log);
            return fallback;
        }
    }

    static async Task DispatchAsync(PackerType mode, string file, string outDir, CliLog log)
    {
        var cb = log.ForEngine;
        switch (mode)
        {
            case PackerType.PyInstaller:
                await PyInstallerEngine.ExtractAsync(file, outDir, cb);
                break;
            case PackerType.Nuitka:
                await NuitkaEngine.ExtractAsync(file, outDir, cb);
                break;
            case PackerType.DotNet:
                await DotNetEngine.DecompileAsync(file, outDir, cb);
                break;
            case PackerType.PyArmor:
                await PyArmorEngine.ExtractAsync(file, outDir, cb);
                break;
            case PackerType.Themida:
                await ThemidaEngine.ExtractAsync(file, outDir, cb);
                break;
            case PackerType.Pyz:
                await PyzEngine.ExtractAsync(file, outDir, cb);
                break;
            default:
                await CppEngine.AnalyzeAsync(file, outDir, cb);
                break;
        }
    }
}
