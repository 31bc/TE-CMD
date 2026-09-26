using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DecompilerSuite.Engines;

static class RevenantEngine
{
    public static async Task<bool> TryExtractAsync(string exePath, string outDir, Action<string> log)
    {
        string? script = FindScript();
        if (script == null) { log("  Revenant script not found"); return false; }
        long origSize = new FileInfo(exePath).Length;
        log($"[Revenant] Nuitka native -> Python | Original: {origSize / 1024} KB");

        string revOut = Path.Combine(outDir, "revenant_out");
        Directory.CreateDirectory(revOut);

        // Step 1: List modules
        await ListModules(exePath, script, log);

        // Step 2: Run main extraction
        log("[Revenant] Running static analysis (may take minutes)...");
        var psi = new ProcessStartInfo("python", $" \"{script}\" --source \"{exePath}\" --output \"{revOut}\"")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.Environment["PYTHONUTF8"] = "1";

        using var p = Process.Start(psi);
        if (p == null) { log("  Failed to start python"); return false; }

        var stdoutLines = new List<string>();
        var stderrLines = new List<string>();

        p.OutputDataReceived += (s, e) => { if (e.Data != null) stdoutLines.Add(e.Data); };
        p.ErrorDataReceived += (s, e) => { if (e.Data != null) stderrLines.Add(e.Data); };
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();

        bool exited = p.WaitForExit(600000); // 10 min timeout
        if (!exited)
        {
            try { p.Kill(); } catch { }
            log("[Revenant] Timeout (10 min) - trying fallback extraction");
            return await FallbackExtract(exePath, outDir, log);
        }

        // Log output (last 80 lines)
        foreach (var l in stdoutLines.TakeLast(80))
            if (!string.IsNullOrWhiteSpace(l)) log("  " + l.Trim());
        if (stderrLines.Count > 0)
        {
            var firstErr = stderrLines.FirstOrDefault(l => !string.IsNullOrWhiteSpace(l));
            if (firstErr != null) log("  err: " + firstErr.Trim());
        }

        if (!Directory.Exists(revOut) || Directory.GetFiles(revOut, "*", SearchOption.AllDirectories).Length == 0)
        {
            log("[Revenant] No output from script - trying C# fallback");
            return await FallbackExtract(exePath, outDir, log);
        }

        long total = Directory.GetFiles(revOut, "*", SearchOption.AllDirectories).Sum(f => new FileInfo(f).Length);
        log($"[Revenant] Output: {total / 1024} KB vs original {origSize / 1024} KB");
        if (total > origSize * 3) { log("[Revenant] REJECT: output > 3x original"); return false; }

        // Copy results
        foreach (var f in Directory.GetFiles(revOut, "*", SearchOption.AllDirectories))
        {
            string rel = Path.GetRelativePath(revOut, f);
            string dst = Path.Combine(outDir, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
            File.Copy(f, dst, true);
        }

        int pyCount = Directory.GetFiles(outDir, "*.py", SearchOption.AllDirectories).Length;
        int nbcCount = Directory.GetFiles(outDir, "*.nbc", SearchOption.AllDirectories).Length;
        int pycCount = Directory.GetFiles(outDir, "*.pyc", SearchOption.AllDirectories).Length;
        log($"[Revenant] Results: {pyCount} .py  {pycCount} .pyc  {nbcCount} .nbc");

        var report = Path.Combine(revOut, "REPORT.json");
        if (File.Exists(report))
        {
            try { File.Copy(report, Path.Combine(outDir, "REPORT.json"), true); } catch { }
            log("[Revenant] REPORT.json copied");
        }

        return pyCount + pycCount + nbcCount > 0;
    }

    static async Task ListModules(string exePath, string script, Action<string> log)
    {
        try
        {
            var psi = new ProcessStartInfo("python", $" \"{script}\" --source \"{exePath}\" --list-modules")
            {
                RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false, CreateNoWindow = true
            };
            using var pl = Process.Start(psi);
            if (pl != null)
            {
                string o = await pl.StandardOutput.ReadToEndAsync();
                await pl.WaitForExitAsync();
                var lines = o.Split('\n')
                    .Where(l => !string.IsNullOrWhiteSpace(l) && !l.Contains("===") && !l.StartsWith("["))
                    .Take(20).ToList();
                if (lines.Count > 0)
                {
                    log($"[Revenant] Modules ({lines.Count} sample):");
                    foreach (var l in lines.Take(10)) log($"    * {l.Trim()}");
                }
            }
        }
        catch { }
    }

    static async Task<bool> FallbackExtract(string exePath, string outDir, Action<string> log)
    {
        log("[Revenant] C# fallback: extracting constants and strings from native binary...");
        try
        {
            var data = await File.ReadAllBytesAsync(exePath);
            var txt = Encoding.ASCII.GetString(data);

            // Extract Python source hints
            var pyHints = Regex.Matches(txt, @"(import |from |def |class |return |if |for |while |print\(|self\.)([^\0]){0,200}");
            if (pyHints.Count > 0)
            {
                var sb = new StringBuilder();
                sb.AppendLine("# Revenant Fallback - Python source fragments recovered from native binary");
                sb.AppendLine($"# Source: {Path.GetFileName(exePath)}");
                sb.AppendLine($"# Size: {data.Length} bytes");
                sb.AppendLine($"# Fragments: {pyHints.Count}");
                sb.AppendLine();
                foreach (Match m in pyHints.Take(500))
                    sb.AppendLine(m.Value.Trim());
                string dst = Path.Combine(outDir, "recovered_fragments.py");
                await File.WriteAllTextAsync(dst, sb.ToString(), Encoding.UTF8);
                log($"[Revenant] recovered_fragments.py: {pyHints.Count} Python hints");
            }

            // Extract strings
            var strings = ExtractStrings(data);
            await File.WriteAllTextAsync(Path.Combine(outDir, "strings.txt"),
                string.Join("\n", strings.Take(3000)), Encoding.UTF8);
            log($"[Revenant] strings.txt: {strings.Count} strings");

            // Extract constant blobs
            int blobCount = ExtractConstantBlobs(data, outDir);
            log($"[Revenant] {blobCount} constant blobs extracted");

            // Extract module names
            var modules = Regex.Matches(txt, @"([\w_]+\.py(?:d|w)?)", RegexOptions.Compiled);
            var uniqueMods = modules.Select(m => m.Value).Distinct()
                .Where(m => m.Contains('.') && m.Length > 4 && m.Length < 40)
                .Take(200).ToList();
            if (uniqueMods.Count > 0)
            {
                await File.WriteAllLinesAsync(Path.Combine(outDir, "module_names.txt"), uniqueMods, Encoding.UTF8);
                log($"[Revenant] module_names.txt: {uniqueMods.Count} modules");
            }

            return blobCount > 0 || strings.Count > 100;
        }
        catch (Exception ex)
        {
            log($"[Revenant] Fallback error: {ex.Message}");
            return false;
        }
    }

    static int ExtractConstantBlobs(byte[] data, string outDir)
    {
        int count = 0;
        // Look for marshal code objects (start with type byte 0x63 = 'c' for code object)
        // followed by typical code object structure
        for (int i = 0; i < data.Length - 100; i++)
        {
            // Python marshal code object starts with 'c' (0x63) + 4 bytes
            if (data[i] == 0x63 && i + 4 < data.Length)
            {
                // Check if next 4 bytes look like reasonable code object fields
                int magic = BitConverter.ToInt32(data, i + 1);
                if (magic > 0 && magic < 100000)
                {
                    // Try to extract a reasonable chunk
                    int len = Math.Min(10000, data.Length - i);
                    var slice = data[i..(i + len)];
                    // Skip if mostly zeros
                    if (slice.Count(b => b == 0) > len * 0.3) continue;
                    try
                    {
                        File.WriteAllBytes(Path.Combine(outDir, $"blob_{count:D3}.bin"), slice);
                        count++;
                    }
                    catch { }
                    if (count >= 30) break;
                    i += len;
                }
            }
        }
        return count;
    }

    static List<string> ExtractStrings(byte[] data)
    {
        var sb = new StringBuilder();
        var res = new List<string>();
        foreach (var b in data)
        {
            if (b >= 32 && b <= 126) sb.Append((char)b);
            else
            {
                if (sb.Length > 6) res.Add(sb.ToString());
                sb.Clear();
            }
        }
        return res.Distinct().Where(s => s.Length > 7 && s.Length < 300).ToList();
    }

    static string? FindScript()
    {
        string[] cands = new[]{
            Path.Combine(AppContext.BaseDirectory,"Assets","nuitka-revenant","nuitka_decompiler.py"),
            Path.Combine(Directory.GetCurrentDirectory(),"Assets","nuitka-revenant","nuitka_decompiler.py"),
        };
        return cands.FirstOrDefault(File.Exists);
    }
}
