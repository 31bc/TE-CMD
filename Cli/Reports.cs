using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DecompilerSuite.Helpers;

namespace TECmd;

/// <summary>
/// Reporting helpers. The text report is a port of the GUI results view
/// (MainWindow.CollectAnalysisFromDir / FriendlyError), the JSON report is new
/// for the CLI and only contains values that were really measured.
/// </summary>
static class Reports
{
    public static string CollectAnalysis(string target, string engine)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Engine: {engine}");
        sb.AppendLine($"Output: {target}");
        sb.AppendLine();
        try
        {
            var allFiles = Directory.GetFiles(target, "*", SearchOption.AllDirectories);
            sb.AppendLine($"Total files: {allFiles.Length}");
            sb.AppendLine();

            var groups = allFiles.GroupBy(f => Path.GetExtension(f).ToLower()).OrderByDescending(g => g.Count());
            sb.AppendLine("File types:");
            foreach (var g in groups) sb.AppendLine($"  {g.Key}: {g.Count()} files");
            sb.AppendLine();

            var pyFiles = allFiles.Where(f => f.EndsWith(".py")).ToArray();
            var csFiles = allFiles.Where(f => f.EndsWith(".cs")).ToArray();
            var dllFiles = allFiles.Where(f => f.EndsWith(".dll")).ToArray();
            var pydFiles = allFiles.Where(f => f.EndsWith(".pyd")).ToArray();

            if (pyFiles.Length > 0)
            {
                sb.AppendLine("Python source files:");
                AppendCapped(sb, target, pyFiles);
            }
            if (csFiles.Length > 0)
            {
                sb.AppendLine("C# source files:");
                AppendCapped(sb, target, csFiles);
            }
            if (dllFiles.Length > 0)
            {
                sb.AppendLine($"DLL files: {dllFiles.Length}");
                foreach (var f in dllFiles.Take(10)) sb.AppendLine($"  {Path.GetRelativePath(target, f)}");
            }
            if (pydFiles.Length > 0)
            {
                sb.AppendLine($"PYD files: {pydFiles.Length}");
                foreach (var f in pydFiles.Take(10)) sb.AppendLine($"  {Path.GetRelativePath(target, f)}");
            }

            long totalSize = allFiles.Sum(f => new FileInfo(f).Length);
            sb.AppendLine($"\nTotal size: {totalSize / 1024.0:F1} KB");
        }
        catch { }
        return sb.ToString();
    }

    /// <summary>Console listing limit - the GUI scrolls this list in a pane, the CLI would flood stdout.</summary>
    const int ListingLimit = 40;

    static void AppendCapped(StringBuilder sb, string root, string[] files)
    {
        foreach (var f in files.Take(ListingLimit))
            sb.AppendLine($"  {Path.GetRelativePath(root, f)}");
        if (files.Length > ListingLimit)
            sb.AppendLine($"  ... (+{files.Length - ListingLimit} more - see the output folder)");
    }

    public static string FriendlyError(Exception ex)
    {
        var m = ex.Message;
        if (m.Contains("managed metadata"))
            return "file is not C#/.NET - auto correction will try the detected engine (use 'auto')";
        if (m.Contains("Bad MAGIC"))
            return "new Python version not fully supported - fallback disassembly used";
        if (m.Contains("An error occurred trying to start process"))
            return "failed to start an external tool - is python on PATH? (run 'TE-CMD.exe check')";
        if (m.Contains("Could not find file") || m.Contains("No such file"))
            return m;
        return m;
    }

    public static (int files, long bytes, int py, int cs) OutputStats(string outDir)
    {
        if (string.IsNullOrEmpty(outDir) || !Directory.Exists(outDir)) return (0, 0, 0, 0);
        var all = Directory.GetFiles(outDir, "*", SearchOption.AllDirectories);
        long bytes = 0;
        foreach (var f in all)
        {
            try { bytes += new FileInfo(f).Length; } catch { }
        }
        return (all.Length, bytes, all.Count(f => f.EndsWith(".py")), all.Count(f => f.EndsWith(".cs")));
    }

    public static Dictionary<string, object?> BuildJson(
        string command,
        string path,
        PackerType detected,
        IReadOnlyList<string> detectedAll,
        string? engineId,
        string? outDir,
        string status,
        int exitCode,
        double seconds)
    {
        var fi = new FileInfo(path);
        long sizeBytes = 0;
        try { sizeBytes = fi.Exists ? fi.Length : 0; } catch { }
        var (files, bytes, py, cs) = OutputStats(outDir ?? "");
        var (types, methods, resources) = DotNetStats(path);

        return new Dictionary<string, object?>
        {
            ["target"] = path,
            ["command"] = command,
            ["sizeBytes"] = sizeBytes,
            ["sha256"] = Sha256(path),
            ["format"] = Detector.Describe(detected),
            ["formatId"] = EngineRouter.IdOf(detected),
            ["detected"] = detectedAll.ToList(),
            ["architecture"] = Architecture(path),
            ["engine"] = engineId,
            ["output"] = outDir == null ? null : new Dictionary<string, object?>
            {
                ["path"] = Path.GetFullPath(outDir),
                ["files"] = files,
                ["bytes"] = bytes,
            },
            ["source"] = new Dictionary<string, object?> { ["python"] = py, ["csharp"] = cs },
            ["analysis"] = new Dictionary<string, object?>
            {
                ["functions"] = methods,
                ["types"] = types,
                ["strings"] = CountStrings(path),
                ["resources"] = resources,
            },
            ["durationSeconds"] = Math.Round(seconds, 3),
            ["status"] = status,
            ["exitCode"] = exitCode,
        };
    }

    public static void WriteJson(object payload)
    {
        var opts = new JsonSerializerOptions { WriteIndented = true };
        Console.Out.WriteLine(JsonSerializer.Serialize(payload, opts));
    }

    static string Sha256(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
        }
        catch { return ""; }
    }

    /// <summary>PE architecture from the optional header magic (same rule as the engines use).</summary>
    public static string? Architecture(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            var buf = new byte[0x40];
            if (fs.Read(buf, 0, 0x40) < 0x40) return null;
            if (buf[0] != 'M' || buf[1] != 'Z') return null;
            int pe = BitConverter.ToInt32(buf, 0x3C);
            if (pe <= 0 || pe + 26 > fs.Length) return null;
            fs.Position = pe;
            var sig = new byte[4];
            if (fs.Read(sig, 0, 4) < 4) return null;
            if (sig[0] != 'P' || sig[1] != 'E' || sig[2] != 0 || sig[3] != 0) return null;
            fs.Position = pe + 24;
            var magic = new byte[2];
            if (fs.Read(magic, 0, 2) < 2) return null;
            ushort m = BitConverter.ToUInt16(magic, 0);
            return m switch { 0x20b => "64-bit", 0x10b => "32-bit", _ => null };
        }
        catch { return null; }
    }

    /// <summary>Real metadata counts for .NET targets (same reader DotNetEngine logs from).</summary>
    public static (int? types, int? methods, int? resources) DotNetStats(string path)
    {
        try
        {
            using var pe = new PEReader(File.OpenRead(path));
            if (!pe.HasMetadata) return (null, null, null);
            var reader = pe.GetMetadataReader();
            return (reader.TypeDefinitions.Count, reader.MethodDefinitions.Count, reader.ManifestResources.Count);
        }
        catch { return (null, null, null); }
    }

    /// <summary>Strings report - identical call to the GUI "Strings" button.</summary>
    public static int CountStrings(string path, int minLen = 5)
    {
        try { return PeHelper.ExtractStrings(path, minLen).Count; }
        catch { return 0; }
    }

    public static string CommandName(CliCommand command) => command switch
    {
        CliCommand.Analyze => "analyze",
        CliCommand.Decompile => "decompile",
        CliCommand.Extract => "extract",
        CliCommand.Info => "info",
        CliCommand.Strings => "strings",
        CliCommand.Ultra => "ultra",
        CliCommand.Check => "check",
        CliCommand.Help => "help",
        CliCommand.Version => "version",
        _ => "auto",
    };
}
