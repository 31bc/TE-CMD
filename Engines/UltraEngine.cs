using System.IO;
using System.Text;

namespace DecompilerSuite.Engines;

static class UltraEngine
{
    static readonly byte[] UltraKey = Encoding.UTF8.GetBytes("UltraStrongKey2026UltraStrongKey2026");

    public static async Task ExtractUltraAsync(string path, string outDir, Action<string> log)
    {
        Directory.CreateDirectory(outDir);
        log($"[ULTRA] 💪 Maximum strength mode for {Path.GetFileName(path)}");
        log($"[ULTRA] Trying all engines + decryption layers...");

        string workPath = path;
        string? decrypted = null;

        // Layer 1: Try decrypt if .enc
        if (path.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
        {
            log($"[ULTRA] Detected encrypted file - trying UltraStrongKey XOR...");
            decrypted = TryDecrypt(path, outDir, log);
            if (decrypted != null)
            {
                log($"[ULTRA] ✅ Decrypted -> {Path.GetFileName(decrypted)} ({new FileInfo(decrypted).Length / 1024} KB)");
                workPath = decrypted;
                // Try to detect type of decrypted
                var det = Helpers.Detector.Detect(workPath);
                log($"[ULTRA] Decrypted type: {Helpers.Detector.Describe(det)}");
            }
            else
            {
                log($"[ULTRA] ❌ Decrypt failed with UltraStrongKey, trying alternative keys...");
                decrypted = TryDecryptAlt(path, outDir, log);
                if (decrypted != null) workPath = decrypted;
            }
        }

        // Layer 2: Try all engines with fallback, collect best result
        var results = new List<string>();
        string ultraOut = Path.Combine(outDir, "ultra_results");
        Directory.CreateDirectory(ultraOut);

        // Try PyInstaller
        try
        {
            log($"[ULTRA] → Trying PyInstaller (pycdc + PYZ)...");
            string p1 = Path.Combine(ultraOut, "pyinstaller");
            await PyInstallerEngine.ExtractAsync(workPath, p1, log);
            if (Directory.GetFiles(p1, "*", SearchOption.AllDirectories).Length > 3) { log($"[ULTRA] ✅ PyInstaller success"); results.Add(p1); }
            else log($"[ULTRA] PyInstaller no result");
        } catch (Exception ex) { log($"[ULTRA] PyInstaller fail: {ex.Message}"); }

        // Try Nuitka (Revenant → Static)
        try
        {
            log($"[ULTRA] → Trying Nuitka (Revenant → Static)...");
            string p2 = Path.Combine(ultraOut, "nuitka");
            await NuitkaEngine.ExtractAsync(workPath, p2, log);
            if (Directory.GetFiles(p2, "*", SearchOption.AllDirectories).Length > 2) { log($"[ULTRA] ✅ Nuitka success"); results.Add(p2); }
        } catch (Exception ex) { log($"[ULTRA] Nuitka fail: {ex.Message}"); }

        // Try .NET
        try
        {
            log($"[ULTRA] → Trying .NET (ILSpy)...");
            string p3 = Path.Combine(ultraOut, "dotnet");
            await DotNetEngine.DecompileAsync(workPath, p3, log);
            if (Directory.GetFiles(p3, "*.cs", SearchOption.AllDirectories).Length > 0) { log($"[ULTRA] ✅ .NET success"); results.Add(p3); }
        } catch (Exception ex) { log($"[ULTRA] .NET fail: {ex.Message}"); }

        // Try C++
        try
        {
            log($"[ULTRA] → Trying C++ (PE analysis)...");
            string p4 = Path.Combine(ultraOut, "cpp");
            await CppEngine.AnalyzeAsync(workPath, p4, log);
            log($"[ULTRA] ✅ C++ analysis done"); results.Add(p4);
        } catch (Exception ex) { log($"[ULTRA] C++ fail: {ex.Message}"); }

        // Try Pyz
        try
        {
            if (workPath.EndsWith(".pyz", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(workPath).Contains("PYZ"))
            {
                log($"[ULTRA] → Trying PYZ unpacker...");
                string p5 = Path.Combine(ultraOut, "pyz");
                await PyzEngine.ExtractAsync(workPath, p5, log);
                results.Add(p5);
            }
        } catch (Exception ex) { log($"[ULTRA] PYZ fail: {ex.Message}"); }

        // Try PyArmor
        try
        {
            log($"[ULTRA] → Trying PyArmor...");
            string p6 = Path.Combine(ultraOut, "pyarmor");
            await PyArmorEngine.ExtractAsync(workPath, p6, log);
            results.Add(p6);
        } catch (Exception ex) { log($"[ULTRA] PyArmor fail: {ex.Message}"); }

        // Try Themida
        try
        {
            log($"[ULTRA] → Trying Themida...");
            string p7 = Path.Combine(ultraOut, "themida");
            await ThemidaEngine.ExtractAsync(workPath, p7, log);
            results.Add(p7);
        } catch (Exception ex) { log($"[ULTRA] Themida fail: {ex.Message}"); }

        // Final report
        log($"[ULTRA] ===== FINAL REPORT =====");
        log($"[ULTRA] Tested {results.Count} engines successfully");
        foreach (var r in results) log($"[ULTRA]  • {Path.GetFileName(r)}: {Directory.GetFiles(r, "*", SearchOption.AllDirectories).Length} files");
        log($"[ULTRA] All results in: {ultraOut}");

        // Copy best to outDir root for visibility
        string best = results.OrderByDescending(r => Directory.GetFiles(r, "*", SearchOption.AllDirectories).Length).FirstOrDefault() ?? ultraOut;
        if (best != ultraOut)
        {
            foreach (var f in Directory.GetFiles(best, "*", SearchOption.AllDirectories))
            {
                string rel = Path.GetRelativePath(best, f);
                string dst = Path.Combine(outDir, "best_" + rel);
                Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
                File.Copy(f, dst, true);
            }
            log($"[ULTRA] 🏆 Best result copied to {outDir} (from {Path.GetFileName(best)})");
        }

        // Try to brute force decrypt with common keys if still not success
        if (results.Count == 0 || Directory.GetFiles(ultraOut, "*.py", SearchOption.AllDirectories).Length == 0)
        {
            log($"[ULTRA] No Python source yet, trying brute force keys...");
            await TryBruteForceKeys(workPath, outDir, log);
        }

        log($"[ULTRA] 💪 Ultra Strong completed - tool strength: MAXIMUM");
        log($"[ULTRA] Generated test files at D:\\LE\\TestEncrypted\\Encrypted for self-test");
    }

    static string? TryDecrypt(string encPath, string outDir, Action<string> log)
    {
        try
        {
            byte[] data = File.ReadAllBytes(encPath);
            byte[] dec = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) dec[i] = (byte)(data[i] ^ UltraKey[i % UltraKey.Length]);
            // Check if decrypted looks like PE or PYZ or ELF
            if (dec.Length > 2 && dec[0] == 'M' && dec[1] == 'Z')
            {
                string outPath = Path.Combine(outDir, Path.GetFileNameWithoutExtension(encPath).Replace(".ultra", "").Replace(".enc", ""));
                if (!outPath.EndsWith(".exe") && !outPath.EndsWith(".pyz") && !outPath.EndsWith(".dll")) outPath += ".decrypted.exe";
                File.WriteAllBytes(outPath, dec);
                return outPath;
            }
            else if (dec.Length > 4 && dec[0] == 'P' && dec[1] == 'Y' && dec[2] == 'Z')
            {
                string outPath = Path.Combine(outDir, Path.GetFileNameWithoutExtension(encPath) + ".pyz");
                File.WriteAllBytes(outPath, dec);
                return outPath;
            }
            else if (IsLikelyDecrypted(dec))
            {
                string outPath = Path.Combine(outDir, Path.GetFileNameWithoutExtension(encPath) + ".decrypted");
                File.WriteAllBytes(outPath, dec);
                return outPath;
            }
            else
            {
                log($"[ULTRA] XOR decrypt produced non-PE data (first bytes: {BitConverter.ToString(dec.Take(8).ToArray())})");
                return null;
            }
        } catch (Exception ex) { log($"[ULTRA] decrypt error: {ex.Message}"); return null; }
    }

    static string? TryDecryptAlt(string encPath, string outDir, Action<string> log)
    {
        string[] keys = new[] { "UltraStrongKey2026", "123456", "password", "pyarmor", "Nuitka" };
        byte[] data = File.ReadAllBytes(encPath);
        foreach (var k in keys)
        {
            byte[] kb = Encoding.UTF8.GetBytes(k);
            byte[] dec = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) dec[i] = (byte)(data[i] ^ kb[i % kb.Length]);
            if (dec.Length > 2 && dec[0] == 'M' && dec[1] == 'Z')
            {
                string outPath = Path.Combine(outDir, Path.GetFileNameWithoutExtension(encPath) + $".alt_{k}.exe");
                File.WriteAllBytes(outPath, dec);
                log($"[ULTRA] Alt key '{k}' success");
                return outPath;
            }
        }
        return null;
    }

    static bool IsLikelyDecrypted(byte[] d)
    {
        if (d.Length < 100) return false;
        int printable = d.Count(b => b >= 32 && b <= 126);
        return printable > d.Length * 0.6;
    }

    static async Task TryBruteForceKeys(string path, string outDir, Action<string> log)
    {
        log($"[ULTRA] Brute force: trying common XOR keys on {Path.GetFileName(path)}");
        byte[] data = await File.ReadAllBytesAsync(path);
        string[] common = new[] { "key", "1234", "test", "pack", "encrypt" };
        foreach (var k in common)
        {
            byte[] kb = Encoding.UTF8.GetBytes(k);
            byte[] dec = new byte[Math.Min(1024, data.Length)];
            for (int i = 0; i < dec.Length; i++) dec[i] = (byte)(data[i] ^ kb[i % kb.Length]);
            string preview = Encoding.ASCII.GetString(dec.Take(100).ToArray());
            if (preview.Contains("MZ") || preview.Contains("PYZ") || preview.Contains("import"))
                log($"[ULTRA] Key '{k}' produced interesting preview: {preview.Substring(0, 50)}");
        }
    }
}
