using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace DecompilerSuite.Engines;

static class PyInstallerEngine
{
    public static async Task ExtractAsync(string exePath, string outDir, Action<string> log)
    {
        Directory.CreateDirectory(outDir);
        log($"[PyInstaller] Scanning {Path.GetFileName(exePath)} ...");
        string pyiDir = Path.Combine(outDir, "pyinstaller_extracted");
        Directory.CreateDirectory(pyiDir);
        bool ok = await TryPythonExtractAsync(exePath, pyiDir, log);
        if (!ok)
        {
            log("[PyInstaller] Python extract failed, using C# native extraction...");
            var data = await File.ReadAllBytesAsync(exePath);
            int count = NativeExtract(data, pyiDir, log);
            log($"[PyInstaller] C# extracted {count} files");
            ok = count > 2;
        }
        var all = Directory.GetFiles(pyiDir, "*", SearchOption.AllDirectories);
        log($"[PyInstaller] Total {all.Length} files");
        var mainScriptsDir = Path.Combine(pyiDir, "main_scripts");
        string decPy = Path.Combine(outDir, "decompiled_py");
        Directory.CreateDirectory(decPy);
        if (Directory.Exists(mainScriptsDir))
        {
            foreach (var mp in Directory.GetFiles(mainScriptsDir, "*.pyc"))
            {
                string name = Path.GetFileNameWithoutExtension(mp);
                string dst = Path.Combine(decPy, name + ".py");
                if (name == "Magic") TryDecompileMagic(mp, dst, log);
                else
                {
                    string? script2 = FindScript("pyc_decompile.py");
                    if (script2 != null)
                    {
                        var psi2 = new ProcessStartInfo("python", $" \"{script2}\" \"{mp}\" \"{dst}\"")
                        {
                            RedirectStandardOutput = true, RedirectStandardError = true,
                            UseShellExecute = false, CreateNoWindow = true
                        };
                        using var pr2 = Process.Start(psi2);
                        if (pr2 != null)
                        {
                            var stdout = await pr2.StandardOutput.ReadToEndAsync();
                            var stderr = await pr2.StandardError.ReadToEndAsync();
                            bool exited = pr2.WaitForExit(20000);
                            if (!exited) try { pr2.Kill(); } catch { }
                            if (File.Exists(dst))
                            {
                                long sz = new FileInfo(dst).Length;
                                log($"  [OK] {name}.py ({sz} bytes)");
                            }
                        }
                    }
                }
            }
        }
        else
        {
            var magic = Directory.GetFiles(pyiDir, "Magic", SearchOption.AllDirectories).FirstOrDefault();
            if (magic != null)
            {
                string dst = Path.Combine(decPy, "Magic.py");
                TryDecompileMagic(magic, dst, log);
            }
        }
        await BulkDecompilePycsAsync(pyiDir, decPy, log);
        var mains = Directory.GetFiles(decPy, "*.py").Where(f => !f.Contains("PYZ")).Take(10).Select(f => $"{Path.GetFileName(f)} ({new FileInfo(f).Length}B)");
        log($"[PyInstaller] Decompiled files: {string.Join(", ", mains)}");
        File.WriteAllText(Path.Combine(outDir, "info.txt"), $"PyInstaller {all.Length} files {DateTime.Now}", Encoding.UTF8);
        log($"[PyInstaller] Done - source in decompiled_py/");
    }

    static async Task<bool> TryPythonExtractAsync(string exe, string outDir, Action<string> log)
    {
        try
        {
            string? script = FindScript("pyi_extract.py");
            if (script == null) return false;
            var psi = new ProcessStartInfo("python", $" \"{script}\" \"{exe}\" \"{outDir}\"")
            {
                RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false, CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return false;
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();
            bool exited = p.WaitForExit(60000);
            if (!exited) { try { p.Kill(); } catch { } log("[PyInstaller] Extract timeout (60s)"); return false; }
            string o = await stdoutTask;
            string e = await stderrTask;
            if (!string.IsNullOrWhiteSpace(o)) foreach (var l in o.Split('\n')) if (l.Trim().Length > 0) log("  " + l.Trim());
            if (!string.IsNullOrWhiteSpace(e)) foreach (var l in e.Split('\n')) if (l.Trim().Length > 0) log("  [err] " + l.Trim());
            return p.ExitCode == 0 && Directory.GetFiles(outDir, "*", SearchOption.AllDirectories).Length > 3;
        }
        catch (Exception ex) { log("[PyInstaller] " + ex.Message); return false; }
    }

    static void TryDecompileMagic(string src, string dst, Action<string> log)
    {
        try
        {
            string? script = FindScript("magic_decompile.py");
            if (script == null) return;
            var psi = new ProcessStartInfo("python", $" \"{script}\" \"{src}\" \"{dst}\"")
            {
                RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false, CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return;
            string o = p.StandardOutput.ReadToEnd();
            p.WaitForExit(15000);
            if (!string.IsNullOrWhiteSpace(o)) log("  " + o.Trim());
            if (File.Exists(dst)) log($"  [OK] Magic.py ({new FileInfo(dst).Length} bytes)");
        }
        catch (Exception ex) { log("  Magic decompile: " + ex.Message); }
    }

    static async Task BulkDecompilePycsAsync(string pyiDir, string decDir, Action<string> log)
    {
        try
        {
            var pycs = Directory.GetFiles(pyiDir, "*.pyc", SearchOption.AllDirectories).Distinct().ToList();
            var magicRaw = Directory.GetFiles(pyiDir, "Magic", SearchOption.AllDirectories);
            foreach (var m in magicRaw) if (!pycs.Contains(m)) pycs.Add(m);
            var mainScripts = Path.Combine(pyiDir, "main_scripts");
            if (Directory.Exists(mainScripts)) pycs.AddRange(Directory.GetFiles(mainScripts, "*.pyc").Where(p => !pycs.Contains(p)));
            if (pycs.Count == 0) { log("[PyInstaller] No pyc files to decompile"); return; }
            log($"[PyInstaller] Decompiling {pycs.Count} pyc files...");
            string? script = FindScript("pyc_decompile.py");
            if (script == null) { log("[PyInstaller] pyc_decompile.py missing"); return; }
            Directory.CreateDirectory(decDir);
            int done = 0;
            int failed = 0;
            foreach (var pyc in pycs.Take(300))
            {
                string rel = Path.GetRelativePath(pyiDir, pyc);
                string dst;
                if (rel.StartsWith("PYZ_extracted")) dst = Path.Combine(decDir, Path.ChangeExtension(rel.Replace("PYZ_extracted", "PYZ"), ".py"));
                else if (rel.StartsWith("main_scripts")) dst = Path.Combine(decDir, Path.GetFileNameWithoutExtension(rel) + ".py");
                else dst = Path.Combine(decDir, Path.ChangeExtension(rel, ".py"));
                if (dst.EndsWith(".pyc.py")) dst = dst.Replace(".pyc.py", ".py");
                Directory.CreateDirectory(Path.GetDirectoryName(dst) ?? decDir);
                if (File.Exists(dst)) { done++; continue; }
                var psi = new ProcessStartInfo("python", $" \"{script}\" \"{pyc}\" \"{dst}\"")
                {
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    UseShellExecute = false, CreateNoWindow = true
                };
                using var pr = Process.Start(psi);
                if (pr != null)
                {
                    bool exited = pr.WaitForExit(10000);
                    if (!exited) { try { pr.Kill(); } catch { } failed++; }
                    else done++;
                }
                if (done % 50 == 0 && done > 0) log($"  [{done}/{pycs.Count}] ...");
            }
            log($"[PyInstaller] Decompiled {done} files ({failed} failed)");
        }
        catch (Exception ex) { log("[PyInstaller] bulk err: " + ex.Message); }
    }

    static string? FindScript(string name)
    {
        string[] cands = new[]{
            Path.Combine(AppContext.BaseDirectory, "Assets", name),
            Path.Combine(Directory.GetCurrentDirectory(), "Assets", name)
        };
        return cands.FirstOrDefault(File.Exists);
    }

    static int NativeExtract(byte[] data, string outDir, Action<string> log)
    {
        try
        {
            byte[] magic = new byte[] { 0x4D, 0x45, 0x49, 0x0C, 0x0B, 0x0A, 0x0B, 0x0E };
            int cookiePos = -1;
            for (int i = data.Length - 88 - 16; i >= Math.Max(0, data.Length - 300000); i--)
            {
                bool m = true; for (int j = 0; j < 8; j++) if (data[i + j] != magic[j]) { m = false; break; }
                if (m) { cookiePos = i; break; }
            }
            if (cookiePos < 0) { log("[PyInstaller] No cookie found"); return 0; }
            int len = BE(data, cookiePos + 8);
            int toc = BE(data, cookiePos + 12);
            int tocLen = BE(data, cookiePos + 16);
            int pyver = BE(data, cookiePos + 20);
            string pylib = Encoding.ASCII.GetString(data, cookiePos + 24, 64).Split('\0')[0];
            log($"[PyInstaller] cookie len={len} pyver={pyver} pylib={pylib}");
            int pkgStart = data.Length - len;
            if (pkgStart < 0) pkgStart = 0;
            int tocOff = pkgStart + toc;
            File.WriteAllBytes(Path.Combine(outDir, "overlay.bin"), data[pkgStart..]);
            int pos = tocOff, count = 0;
            while (pos + 18 <= tocOff + tocLen && pos + 18 <= data.Length)
            {
                int entrySize = BE(data, pos);
                if (entrySize <= 0 || entrySize > 2000000) break;
                int dpos = BE(data, pos + 4);
                int dlen = BE(data, pos + 8);
                int ulen = BE(data, pos + 12);
                byte flag = data[pos + 16];
                if (pos + entrySize > data.Length) break;
                string name = Encoding.UTF8.GetString(data, pos + 18, entrySize - 18).Split('\0')[0];
                if (string.IsNullOrWhiteSpace(name)) { pos += entrySize; continue; }
                name = name.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar);
                string dest = Path.Combine(outDir, name);
                Directory.CreateDirectory(Path.GetDirectoryName(dest) ?? outDir);
                int absPos = pkgStart + dpos;
                if (absPos < 0 || absPos + dlen > data.Length) { pos += entrySize; continue; }
                byte[] raw = new byte[dlen];
                Array.Copy(data, absPos, raw, 0, dlen);
                if (flag == 1) try { raw = Decompress(raw); } catch { }
                File.WriteAllBytes(dest, raw);
                count++;
                pos += entrySize;
            }
            return count;
        }
        catch (Exception ex) { log("[PyInstaller] Native: " + ex.Message); return 0; }
    }

    static int BE(byte[] d, int o) => (d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3];
    static byte[] Decompress(byte[] data)
    {
        using var ms = new MemoryStream(data);
        using var zs = new ZLibStream(ms, CompressionMode.Decompress);
        using var outMs = new MemoryStream();
        zs.CopyTo(outMs);
        return outMs.ToArray();
    }
}
