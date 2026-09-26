using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace DecompilerSuite.Engines;

static class ThemidaEngine
{
    public static async Task ExtractAsync(string exePath, string outDir, Action<string> log)
    {
        Directory.CreateDirectory(outDir);
        long origSize = new FileInfo(exePath).Length;
        log($"[Themida] Analyzing {Path.GetFileName(exePath)} ({origSize / 1024} KB) ...");

        // Step 1: Detect Themida version
        var data = await File.ReadAllBytesAsync(exePath);
        var txt = Encoding.ASCII.GetString(data);
        bool isThemida = txt.Contains("Themida") || txt.Contains("WinLicense")
            || txt.Contains(".Themida") || txt.Contains(".winlice");
        bool hasVM = txt.Contains("vm_start") || txt.Contains("VMP");
        log($"[Themida] Detected: {isThemida} VM: {hasVM}");

        // Step 2: Run static unpacker
            string? unpackerScript = FindUnpackerScript();
        if (unpackerScript != null)
        {
            log($"[Themida] Running static unpacker...");
            string unpackOut = Path.Combine(outDir, "themida_extracted");
            Directory.CreateDirectory(unpackOut);

            var psi = new ProcessStartInfo("python", $" \"{unpackerScript}\" \"{exePath}\" \"{unpackOut}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.Environment["PYTHONUTF8"] = "1";

            using var p = Process.Start(psi);
            if (p != null)
            {
                var stdoutLines = new List<string>();
                p.OutputDataReceived += (s, e) => { if (e.Data != null) stdoutLines.Add(e.Data); };
                p.ErrorDataReceived += (s, e) => { if (e.Data != null) stdoutLines.Add("[err] " + e.Data); };
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                p.WaitForExit(120000);

                foreach (var l in stdoutLines.TakeLast(40))
                    if (!string.IsNullOrWhiteSpace(l)) log("  " + l.Trim());

                // Copy results
                if (Directory.Exists(unpackOut))
                {
                    var files = Directory.GetFiles(unpackOut, "*", SearchOption.AllDirectories);
                    foreach (var f in files)
                    {
                        string rel = Path.GetRelativePath(unpackOut, f);
                        string dst = Path.Combine(outDir, rel);
                        Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
                        File.Copy(f, dst, true);
                    }
                    log($"[Themida] Extracted {files.Length} files");

                    // Check for unpacked PE
                    var unpacked = Directory.GetFiles(unpackOut, "unpacked.exe", SearchOption.AllDirectories).FirstOrDefault();
                    if (unpacked != null)
                    {
                        log($"[Themida] Found unpacked PE - decompiling with Nuitka...");
                        await NuitkaEngine.ExtractAsync(unpacked, Path.Combine(outDir, "nuitka_after_themida"), log);
                    }
                }
            }
        }
        else
        {
            log("[Themida] Static unpacker not found - using built-in analysis");
        }

        // Step 3: Built-in PE analysis
        log("[Themida] Running built-in PE analysis...");
        await BuiltInAnalysis(data, exePath, outDir, log);

        // Step 4: Try Nuitka/PyInstaller extraction on original
        log("[Themida] Trying extraction engines on original...");
        if (isThemida)
        {
            // Themida often wraps Nuitka or PyInstaller
            string nuitkaOut = Path.Combine(outDir, "nuitka_attempt");
            string? mainDll = await NuitkaEngine.TryOnefileExtract(exePath, nuitkaOut, log);
            if (mainDll != null)
            {
                log("[Themida] Nuitka payload found inside Themida!");
            }
        }

        int totalFiles = Directory.GetFiles(outDir, "*", SearchOption.AllDirectories).Length;
        log($"[Themida] Total output: {totalFiles} files");
    }

    static async Task BuiltInAnalysis(byte[] data, string exePath, string outDir, Action<string> log)
    {
        // Extract PE sections
        try
        {
            int peOff = BitConverter.ToInt32(data, 0x3C);
            short numSections = BitConverter.ToInt16(data, peOff + 6);
            int optOff = peOff + 24;
            short optSize = BitConverter.ToInt16(data, peOff + 20);
            int sectionOff = optOff + optSize;

            var sections = new List<(string name, int vaddr, int vsize, int rawPtr, int rawSize)>();
            for (int i = 0; i < numSections; i++)
            {
                int off = sectionOff + i * 40;
                string name = Encoding.ASCII.GetString(data, off, 8).TrimEnd('\0');
                int vsize = BitConverter.ToInt32(data, off + 8);
                int vaddr = BitConverter.ToInt32(data, off + 12);
                int rawSize = BitConverter.ToInt32(data, off + 16);
                int rawPtr = BitConverter.ToInt32(data, off + 20);
                sections.Add((name, vaddr, vsize, rawPtr, rawSize));
            }

            // Extract sections
            string secDir = Path.Combine(outDir, "sections");
            Directory.CreateDirectory(secDir);
            foreach (var (name, vaddr, vsize, rawPtr, rawSize) in sections)
            {
                if (rawSize > 0 && rawPtr > 0 && rawPtr + rawSize <= data.Length)
                {
                    byte[] sectionData = new byte[rawSize];
                    Array.Copy(data, rawPtr, sectionData, 0, rawSize);
                    File.WriteAllBytes(Path.Combine(secDir, $"{name}.bin"), sectionData);
                    log($"  Section {name}: {rawSize / 1024} KB");
                }
            }

            // Check for overlay
            var lastSection = sections.OrderByDescending(s => s.rawPtr + s.rawSize).First();
            int overlayStart = lastSection.rawPtr + lastSection.rawSize;
            if (overlayStart < data.Length)
            {
                int overlaySize = data.Length - overlayStart;
                byte[] overlay = new byte[overlaySize];
                Array.Copy(data, overlayStart, overlay, 0, overlaySize);
                File.WriteAllBytes(Path.Combine(outDir, "overlay.bin"), overlay);
                log($"  Overlay: {overlaySize / 1024} KB");

                // Scan overlay for PE headers
                for (int i = 0; i < Math.Min(overlaySize - 100, 10000); i++)
                {
                    if (overlay[i] == 0x4D && overlay[i + 1] == 0x5A)
                    {
                        try
                        {
                            int peCheck = BitConverter.ToInt32(overlay, i + 0x3C);
                            if (peCheck > 0 && peCheck < 1024 && overlay[i + peCheck] == 0x50 && overlay[i + peCheck + 1] == 0x45)
                            {
                                log($"  PE header found in overlay at offset {i}");
                                File.WriteAllBytes(Path.Combine(outDir, "unpacked_from_overlay.exe"), overlay[i..]);
                                break;
                            }
                        }
                        catch { }
                    }
                }
            }

            // Extract strings
            var strings = ExtractStrings(data);
            File.WriteAllLines(Path.Combine(outDir, "themida_strings.txt"), strings.Take(2000));
            log($"  Strings: {strings.Count}");
        }
        catch (Exception ex)
        {
            log($"  Analysis error: {ex.Message}");
        }
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

    static string? FindUnpackerScript()
    {
        string[] cands = new[]{
            Path.Combine(AppContext.BaseDirectory,"Assets","themida-unpacker","themida_unpacker.py"),
            Path.Combine(Directory.GetCurrentDirectory(),"Assets","themida-unpacker","themida_unpacker.py"),
        };
        return cands.FirstOrDefault(File.Exists);
    }
}
