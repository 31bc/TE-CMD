using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DecompilerSuite.Engines;

static class NuitkaEngine
{
    public static async Task ExtractAsync(string exePath, string outDir, Action<string> log)
    {
        Directory.CreateDirectory(outDir);
        long origSize = new FileInfo(exePath).Length;
        log($"[Nuitka] Detecting Nuitka OneFile/Standalone ... (OneFile -> Revenant -> Static -> Themida -> Legacy) | Original: {origSize/1024} KB");
        string nuitkaDir = Path.Combine(outDir, "nuitka_extracted");
        Directory.CreateDirectory(nuitkaDir);

        // STEP 0: Try Nuitka onefile zstd extraction (extract payload from .rdata)
        string? mainDll = await TryOnefileExtract(exePath, nuitkaDir, log);
        if (mainDll != null)
        {
            log($"[OneFile] Extracted main.dll ({new FileInfo(mainDll).Length/1024} KB) from onefile payload");
            // Try Revenant on the extracted main.dll
            string revOut = Path.Combine(outDir, "revenant_out");
            if (await RevenantEngine.TryExtractAsync(mainDll, revOut, log) && ValidateOutput(revOut, origSize, log))
            {
                log("[Revenant] SUCCESS - extracted main.dll -> Python");
                await FallbackEnhance(mainDll, revOut, log);
                return;
            }
            // Try static unpacker on extracted main.dll
            if (await TryStaticUnpacker(mainDll, nuitkaDir, log) && ValidateOutput(nuitkaDir, origSize, log))
            {
                log("[Static] SUCCESS via static-unpacker on extracted main.dll");
                await FallbackEnhance(mainDll, nuitkaDir, log);
                return;
            }
            // If Revenant/Static fail, at least we have the DLLs - analyze them
            log("[OneFile] Revenant/Static failed on main.dll - analyzing extracted files...");
            AnalyzeExtractedDlls(nuitkaDir, log);
            return;
        }

        var txt = Encoding.ASCII.GetString(await File.ReadAllBytesAsync(exePath));
        if (txt.Contains("Themida") || txt.Contains("WinLicense"))
        {
            log("[Themida] Detected Themida/WinLicense + Nuitka - trying Themida unpack first");
            await ThemidaEngine.ExtractAsync(exePath, nuitkaDir, log);
            var payload = Directory.GetFiles(nuitkaDir,"*.exe",SearchOption.AllDirectories).FirstOrDefault() ?? Directory.GetFiles(nuitkaDir,"*.bin",SearchOption.AllDirectories).FirstOrDefault();
            if (payload!=null && File.Exists(payload))
            {
                long payloadSize = new FileInfo(payload).Length;
                if (payloadSize > origSize) { log($"[Smart] Payload {payloadSize} > original {origSize} -> wrong decrypt, discarding"); File.Delete(payload); }
                else
                {
                    log($"[Smart] Now decompiling Nuitka payload after Themida: {Path.GetFileName(payload)} ({payloadSize/1024} KB)");
                    string revOut = Path.Combine(outDir, "revenant_after_themida");
                    if (await RevenantEngine.TryExtractAsync(payload, revOut, log) && ValidateOutput(revOut, origSize, log)) return;
                    if (await TryStaticUnpacker(payload, nuitkaDir, log) && ValidateOutput(nuitkaDir, origSize, log)) return;
                }
            }
        }

        if (await RevenantEngine.TryExtractAsync(exePath, nuitkaDir, log))
        {
            if (ValidateOutput(nuitkaDir, origSize, log))
            {
                log("[Revenant] SUCCESS - native -> Python (2nd gen)");
                await FallbackEnhance(exePath, nuitkaDir, log);
                return;
            }
            else log("[Smart] Revenant output failed size validation (larger than original) -> trying next");
        }

        if (await TryStaticUnpacker(exePath, nuitkaDir, log))
        {
            if (ValidateOutput(nuitkaDir, origSize, log))
            {
                log("[Static] SUCCESS via DimaReverse/static-unpacker v7.6");
                await FallbackEnhance(exePath, nuitkaDir, log);
                return;
            }
            else log("[Smart] Static output failed size validation -> trying legacy");
        }

        log("[Fallback] Revenant/Static failed validation - using legacy C# engine");
        await LegacyExtract(exePath, nuitkaDir, log);
    }

    internal static async Task<string?> TryOnefileExtract(string exePath, string outDir, Action<string> log)
    {
        try
        {
            var data = await File.ReadAllBytesAsync(exePath);

            // Find .rdata section
            int peOff = BitConverter.ToInt32(data, 0x3C);
            short numSections = BitConverter.ToInt16(data, peOff + 6);
            int optOff = peOff + 24;
            short optSize = BitConverter.ToInt16(data, peOff + 20);
            int sectionOff = optOff + optSize;

            int rdataPtr = 0, rdataSize = 0;
            for (int i = 0; i < numSections; i++)
            {
                int off = sectionOff + i * 40;
                string name = Encoding.ASCII.GetString(data, off, 8).TrimEnd('\0');
                int rawSize = BitConverter.ToInt32(data, off + 16);
                int rawPtr = BitConverter.ToInt32(data, off + 20);
                if (name == ".rdata") { rdataPtr = rawPtr; rdataSize = rawSize; }
            }
            if (rdataPtr == 0) return null;

            // Find zstd magic in .rdata
            byte[] rdata = new byte[rdataSize];
            Array.Copy(data, rdataPtr, rdata, 0, rdataSize);
            int zstdPos = -1;
            for (int i = 0; i < rdataSize - 4; i++)
            {
                if (rdata[i] == 0x28 && rdata[i+1] == 0xB5 && rdata[i+2] == 0x2F && rdata[i+3] == 0xFD)
                { zstdPos = i; break; }
            }
            if (zstdPos < 0) return null;

            log("[OneFile] Found zstd payload in .rdata - decompressing...");
            byte[] compressedPayload = new byte[rdataSize - zstdPos];
            Array.Copy(rdata, zstdPos, compressedPayload, 0, compressedPayload.Length);

            // Decompress zstd
            byte[]? payload = DecompressZstd(compressedPayload);
            if (payload == null || payload.Length < 100) { log("[OneFile] Zstd decompress failed"); return null; }
            log($"[OneFile] Payload decompressed: {payload.Length/1024} KB");

            // Parse Nuitka onefile format: UTF-16LE name + \0\0 + uint64 size + data
            int pos = 0;
            int fileCount = 0;
            while (pos < payload.Length - 10)
            {
                // Read UTF-16LE filename
                var nameChars = new List<char>();
                while (pos + 1 < payload.Length)
                {
                    char lo = (char)payload[pos];
                    char hi = (char)payload[pos + 1];
                    pos += 2;
                    if (lo == 0 && hi == 0) break;
                    nameChars.Add((char)(lo | (hi << 8)));
                }
                string name = new string(nameChars.ToArray());
                if (name.Length < 4) continue;

                // Read uint64 LE size
                if (pos + 8 > payload.Length) break;
                long fileSize = BitConverter.ToInt64(payload, pos);
                pos += 8;

                if (fileSize <= 0 || fileSize > payload.Length - pos) break;

                byte[] fileData = new byte[fileSize];
                Array.Copy(payload, pos, fileData, 0, (int)fileSize);
                pos += (int)fileSize;

                string outPath = Path.Combine(outDir, name.Replace('\\', '/'));
                Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
                await File.WriteAllBytesAsync(outPath, fileData);
                fileCount++;

                string sz = fileSize > 1024*1024 ? $"{fileSize/1024/1024:F1}MB" : $"{fileSize/1024}KB";
                log($"  [{fileCount,2}] {name}: {sz}");
            }

            log($"[OneFile] Extracted {fileCount} files from onefile payload");
            string? mainDll = Directory.GetFiles(outDir, "main.dll", SearchOption.TopDirectoryOnly).FirstOrDefault();
            return mainDll;
        }
        catch (Exception ex) { log($"[OneFile] Error: {ex.Message}"); return null; }
    }

    static byte[]? DecompressZstd(byte[] compressed)
    {
        try
        {
            // Use Python zstandard via process since .NET may not have it
            string tmpIn = Path.Combine(Path.GetTempPath(), "nz_in.bin");
            string tmpOut = Path.Combine(Path.GetTempPath(), "nz_out.bin");
            File.WriteAllBytes(tmpIn, compressed);
            var psi = new ProcessStartInfo("python", $"-c \"import zstandard;f=open(r'{tmpIn}','rb');d=zstandard.ZstdDecompressor();open(r'{tmpOut}','wb').write(d.decompress(f.read(),max_output_size=500*1024*1024))\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true };
            using var p = Process.Start(psi);
            if (p != null) { p.WaitForExit(120000); string err = p.StandardError.ReadToEnd(); if (!string.IsNullOrWhiteSpace(err)) return null; }
            if (File.Exists(tmpOut)) { byte[] result = File.ReadAllBytes(tmpOut); File.Delete(tmpOut); File.Delete(tmpIn); return result; }
            File.Delete(tmpIn);
            return null;
        }
        catch { return null; }
    }

    static void AnalyzeExtractedDlls(string dir, Action<string> log)
    {
        var files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories);
        log($"[OneFile] Analyzing {files.Length} extracted files:");
        foreach (var f in files)
        {
            var fi = new FileInfo(f);
            string ext = fi.Extension.ToLower();
            string rel = Path.GetRelativePath(dir, f);
            string sz = fi.Length > 1024*1024 ? $"{fi.Length/1024/1024:F1}MB" : $"{fi.Length/1024}KB";
            if (ext == ".dll" || ext == ".pyd")
            {
                // Check if it's a Python extension
                var data = File.ReadAllBytes(f);
                bool isPython = data.Length > 100 && data.Skip(60).Take(4).SequenceEqual(new byte[]{0x50,0x45,0x00,0x00});
                log($"  {rel}: {sz} {(ext==".pyd" ? "[Python Extension]" : "")}");
            }
            else log($"  {rel}: {sz}");
        }
    }

    static bool ValidateOutput(string outDir, long origSize, Action<string> log)
    {
        try
        {
            var files = Directory.GetFiles(outDir, "*", SearchOption.AllDirectories);
            long total = files.Sum(f => new FileInfo(f).Length);
            log($"[Smart] Validate: {files.Length} files, total {total/1024} KB vs original {origSize/1024} KB");
            // Rule 1: Total output should not be massively larger than original (allow 3x for decompressed)
            if (total > origSize * 3)
            {
                log($"[Smart] FAIL: total output {total} > 3x original {origSize} -> wrong decrypt (decrypted larger than encrypted)");
                return false;
            }
            // Rule 2: Any single file should not be larger than original
            foreach (var f in files)
            {
                long sz = new FileInfo(f).Length;
                if (sz > origSize && sz > 50*1024*1024) // 50MB threshold
                {
                    log($"[Smart] FAIL: file {Path.GetFileName(f)} {sz} > original -> wrong");
                    return false;
                }
            }
            // Rule 3: Entropy check - decrypted Python should have lower entropy than encrypted
            // Encrypted blob has high entropy ~7.9, decrypted should be ~5-6
            // We check a sample .py file if exists
            var samplePy = files.FirstOrDefault(f => f.EndsWith(".py"));
            if (samplePy != null)
            {
                var data = File.ReadAllBytes(samplePy);
                double ent = CalcEntropy(data);
                log($"[Smart] Sample {Path.GetFileName(samplePy)} entropy {ent:F2} (expected 4.5-6.5 for Python)");
                if (ent > 7.5) { log("[Smart] FAIL: entropy too high -> still encrypted"); return false; }
            }
            log("[Smart] PASS: size and entropy validation OK");
            return true;
        } catch (Exception ex) { log($"[Smart] Validate error: {ex.Message}"); return true; }
    }

    static double CalcEntropy(byte[] d)
    {
        if (d.Length==0) return 0;
        var freq = new int[256];
        foreach(var b in d) freq[b]++;
        double e=0;
        foreach(var c in freq) if(c>0){ double p=(double)c/d.Length; e-=p*Math.Log2(p); }
        return e;
    }

    static async Task<bool> TryStaticUnpacker(string exe, string outDir, Action<string> log)
    {
        try
        {
            string baseDir = AppContext.BaseDirectory;
            string[] candidates = new[]
            {
                Path.Combine(baseDir, "Assets", "nuitka-static-unpacker", "nuitka_decompiler.py"),
                Path.Combine(Directory.GetCurrentDirectory(), "Assets", "nuitka-static-unpacker", "nuitka_decompiler.py")
            };
            string? script = candidates.FirstOrDefault(File.Exists);
            if (script == null) { log("  unpacker script not found"); return false; }
            log($"  Found unpacker: {Path.GetFileName(script)}");

            string listScript = Path.Combine(Path.GetDirectoryName(script)!, "list_modules.py");
            if (File.Exists(listScript))
            {
                try
                {
                    var psiList = new ProcessStartInfo("python", $" \"{listScript}\" \"{exe}\" --filter \"\"") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                    using var pl = Process.Start(psiList);
                    if (pl != null)
                    {
                        string o = await pl.StandardOutput.ReadToEndAsync();
                        await pl.WaitForExitAsync();
                        var mods = o.Split('\n').Where(l=>!string.IsNullOrWhiteSpace(l)).Take(30).ToList();
                        if (mods.Count > 0) { log($"  Modules detected ({mods.Count} sample):"); foreach(var m in mods.Take(10)) log($"    * {m.Trim()}"); }
                    }
                } catch { }
            }

            string unpackOut = Path.Combine(outDir, "static_unpacker_out");
            Directory.CreateDirectory(unpackOut);
            log($"  Running: nuitka_decompiler.py --source \"{Path.GetFileName(exe)}\" --output \"{unpackOut}\" ...");
            var psi = new ProcessStartInfo("python", $" \"{script}\" --source \"{exe}\" --output \"{unpackOut}\"") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            psi.Environment["PYTHONUTF8"] = "1";
            using var p = Process.Start(psi);
            if (p == null) { log("  failed to start python"); return false; }
            var outTask = p.StandardOutput.ReadToEndAsync();
            var errTask = p.StandardError.ReadToEndAsync();
            bool exited = p.WaitForExit(300000);
            if (!exited) { try{ p.Kill(); }catch{} log("  Timeout (5 min)"); return false; }
            string stdout = await outTask;
            string stderr = await errTask;
            foreach(var line in stdout.Split('\n').Take(60)) if(!string.IsNullOrWhiteSpace(line)) log("  " + line.Trim());
            if (!string.IsNullOrWhiteSpace(stderr)) log("  err: " + stderr.Split('\n').FirstOrDefault()?.Trim());
            if (!Directory.Exists(unpackOut) || Directory.GetFiles(unpackOut,"*",SearchOption.AllDirectories).Length==0)
            {
                log("  No output - maybe onefile needs external extraction");
                return false;
            }
            long origSize = new FileInfo(exe).Length;
            long totalOut = Directory.GetFiles(unpackOut,"*",SearchOption.AllDirectories).Sum(f=>new FileInfo(f).Length);
            log($"  [Smart] Static output total {totalOut/1024} KB vs original {origSize/1024} KB");
            if (totalOut > origSize * 3) { log("  [Smart] REJECT: output > 3x original -> wrong decrypt (commercial key failed), trying alternative d0-d7"); return false; }

            foreach(var f in Directory.GetFiles(unpackOut,"*",SearchOption.AllDirectories))
            {
                string rel = Path.GetRelativePath(unpackOut, f);
                string dst = Path.Combine(outDir, rel);
                Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
                try{ File.Copy(f, dst, true); }catch{}
            }
            var report = Path.Combine(unpackOut, "REPORT.json");
            if (File.Exists(report))
            {
                try
                {
                    var json = await File.ReadAllTextAsync(report);
                    using var doc = JsonDocument.Parse(json);
                    int mods = 0;
                    if (doc.RootElement.TryGetProperty("modules", out var m)) mods = m.GetArrayLength();
                    log($"  REPORT.json: {mods} modules");
                    File.Copy(report, Path.Combine(outDir, "REPORT.json"), true);
                } catch { }
            }
            var aiReady = Path.Combine(unpackOut, "AI_READY_NBC");
            if (Directory.Exists(aiReady))
            {
                int nbc = Directory.GetFiles(aiReady,"*.nbc",SearchOption.AllDirectories).Length;
                log($"  AI_READY_NBC: {nbc} .nbc files");
            }
            int pycCount = Directory.GetFiles(outDir,"*.pyc",SearchOption.AllDirectories).Length;
            int pyCount = Directory.GetFiles(outDir,"*.py",SearchOption.AllDirectories).Length;
            log($"  pyc: {pycCount}  py: {pyCount}");
            var secrets = Path.Combine(unpackOut, "secrets.txt");
            if (File.Exists(secrets))
            {
                var s = await File.ReadAllLinesAsync(secrets);
                if (s.Length>0) { log($"  secrets.txt: {s.Length} potential secrets"); File.Copy(secrets, Path.Combine(outDir,"secrets.txt"), true); }
            }
            return Directory.GetFiles(outDir,"*",SearchOption.AllDirectories).Length > 3;
        }
        catch(Exception ex) { log($"  static unpacker exception: {ex.Message}"); return false; }
    }

    static async Task FallbackEnhance(string exe, string outDir, Action<string> log)
    {
        try
        {
            var data = await File.ReadAllBytesAsync(exe);
            var txt = Encoding.ASCII.GetString(data);
            var markers = Regex.Matches(txt, @"Nuitka[^\0]{0,80}");
            if (markers.Count>0) await File.WriteAllTextAsync(Path.Combine(outDir, "nuitka_markers.txt"), string.Join("\n", markers.Take(100).Select(m=>m.Value.Trim())));
            var strs = ExtractStrings(data);
            await File.WriteAllTextAsync(Path.Combine(outDir, "strings_extra.txt"), string.Join("\n", strs.Take(3000)));
            log($"  strings_extra.txt: {strs.Count}");
        } catch { }
    }

    static async Task LegacyExtract(string exePath, string nuitkaDir, Action<string> log)
    {
        var data = await File.ReadAllBytesAsync(exePath);
        var text = Encoding.ASCII.GetString(data);
        var markers = Regex.Matches(text, @"Nuitka[^\0]{0,80}");
        log($"Nuitka markers: {markers.Count}");
        foreach (Match m in markers.Take(20)) log($"  > {m.Value.Trim()}");
        var pyMarkers = Regex.Matches(text, @"(import |def |class )[^\0]{0,120}");
        if (pyMarkers.Count > 0)
        {
            log($"Python code hints: {pyMarkers.Count}");
            await File.WriteAllTextAsync(Path.Combine(nuitkaDir, "hints.txt"), string.Join("\n", pyMarkers.Take(400).Select(m=>m.Value)), Encoding.UTF8);
        }
        var constBlobs = ExtractBlobs(data, log);
        log($"Const blobs found: {constBlobs.Count}");
        for(int i=0;i<constBlobs.Count;i++)
            await File.WriteAllBytesAsync(Path.Combine(nuitkaDir, $"blob_{i:D3}.bin"), constBlobs[i]);
        var strings = ExtractStrings(data);
        await File.WriteAllTextAsync(Path.Combine(nuitkaDir, "strings.txt"), string.Join("\n", strings.Take(2000)), Encoding.UTF8);
        await File.WriteAllTextAsync(Path.Combine(nuitkaDir, "python_sources.txt"), TryRecoverSources(text, log), Encoding.UTF8);
        File.WriteAllBytes(Path.Combine(nuitkaDir, "overlay.bin"), data.Skip(Math.Max(0,data.Length- 2_000_000)).ToArray());
        log("Nuitka compiles to C++ - extraction gives constants and strings");
        log("Legacy completed - try static-unpacker for better results");
    }

    static List<byte[]> ExtractBlobs(byte[] d, Action<string> log)
    {
        var list = new List<byte[]>();
        for(int i=0;i<d.Length-200;i++)
        {
            if (d[i]==0x63 && d[i+1]==0x00 && d[i+2]==0x00 && d[i+3]==0x00)
            {
                int len = Math.Min(5000, d.Length-i);
                var slice = d[i..(i+len)];
                if (slice.Count(b=> b==0)>20) continue;
                list.Add(slice);
                if (list.Count>=25) break;
                i+=len;
            }
        }
        return list;
    }

    static List<string> ExtractStrings(byte[] d)
    {
        var sb=new StringBuilder(); var res=new List<string>();
        foreach(var b in d)
        {
            if(b>=32 && b<=126) sb.Append((char)b);
            else { if(sb.Length>6) res.Add(sb.ToString()); sb.Clear(); }
        }
        return res.Distinct().Where(s=>s.Length>7 && s.Length<300).ToList();
    }

    static string TryRecoverSources(string text, Action<string> log)
    {
        var sb=new StringBuilder();
        sb.AppendLine("# Nuitka recovery - Python source fragments");
        sb.AppendLine("# Nuitka compiles to C++ so full .py recovery is partial");
        var lines = text.Split('\n','\r').Where(l=>l.Contains("def ")||l.Contains("import ")||l.Contains(".py")).Take(500);
        foreach(var l in lines) sb.AppendLine(l.Trim());
        return sb.ToString();
    }
}
