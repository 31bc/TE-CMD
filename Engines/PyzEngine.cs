using System.Diagnostics;
using System.IO;
using System.Text;

namespace DecompilerSuite.Engines;

static class PyzEngine
{
    public static async Task ExtractAsync(string inputPath, string outDir, Action<string> log)
    {
        Directory.CreateDirectory(outDir);
        log($"[KILLER PYZ] Extracting {Path.GetFileName(inputPath)} ...");
        long origSize = new FileInfo(inputPath).Length;

        // If input is an EXE (starts with MZ), first extract PYZ from it using pyi_extract.py
        string pyzPath = inputPath;
        byte[] header = new byte[2];
        using (var fs = File.OpenRead(inputPath)) { if (fs.Read(header, 0, 2) < 2) header = new byte[2]; }
        bool isExe = header[0] == 0x4D && header[1] == 0x5A; // MZ

        if (isExe)
        {
            // Check if this is actually a Nuitka OneFile (not PyInstaller)
            if (Helpers.Detector.Detect(inputPath) == Helpers.PackerType.Nuitka)
            {
                log("[Killer] Detected Nuitka OneFile - redirecting to NuitkaEngine...");
                await NuitkaEngine.ExtractAsync(inputPath, outDir, log);
                return;
            }
            log("[Killer] Input is EXE - extracting PYZ archive first...");
            string preDir = Path.Combine(outDir, "_pyi_pre_extract");
            Directory.CreateDirectory(preDir);
            string? pyiScript = FindPyiExtract();
            if (pyiScript != null)
            {
                var psi0 = new ProcessStartInfo("python", $" \"{pyiScript}\" \"{inputPath}\" \"{preDir}\"")
                {
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    UseShellExecute = false, CreateNoWindow = true
                };
                using var p0 = Process.Start(psi0);
                if (p0 != null)
                {
                    string out0 = await p0.StandardOutput.ReadToEndAsync();
                    string err0 = await p0.StandardError.ReadToEndAsync();
                    await p0.WaitForExitAsync();
                    foreach (var l in out0.Split('\n')) if (!string.IsNullOrWhiteSpace(l)) log("  " + l.Trim());
                    if (!string.IsNullOrWhiteSpace(err0)) log("  pyi_err: " + err0.Trim());
                }

                // Find extracted PYZ file
                var pyzFiles = Directory.GetFiles(preDir, "*.pyz", SearchOption.AllDirectories);
                var pyzFile = pyzFiles.FirstOrDefault(f => Path.GetFileName(f).StartsWith("PYZ"));
                if (pyzFile == null)
                    pyzFile = Directory.GetFiles(preDir, "*", SearchOption.AllDirectories)
                        .FirstOrDefault(f => { try { using var s = File.OpenRead(f); byte[] m = new byte[4]; return s.Read(m, 0, 4) == 4 && m[0]=='P' && m[1]=='Y' && m[2]=='Z' && m[3]==0; } catch { return false; } });

                if (pyzFile != null)
                {
                    log($"[Killer] Found PYZ: {Path.GetFileName(pyzFile)} ({new FileInfo(pyzFile).Length / 1024} KB)");
                    pyzPath = pyzFile;
                }
                else
                {
                    log("[Killer] No PYZ found in extraction, trying all .pyc files directly...");
                    var allPyc = Directory.GetFiles(preDir, "*.pyc", SearchOption.AllDirectories);
                    if (allPyc.Length > 0)
                    {
                        log($"[Killer] Found {allPyc.Length} .pyc files - decompiling directly...");
                        string decDir = Path.Combine(outDir, "decompiled_py");
                        Directory.CreateDirectory(decDir);
                        string? decompScript = FindPycDecompile();
                        if (decompScript != null)
                        {
                            int done = 0;
                            foreach (var pyc in allPyc.Take(300))
                            {
                                string dst = Path.Combine(decDir, Path.ChangeExtension(Path.GetRelativePath(preDir, pyc), ".py"));
                                Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
                                var psi2 = new ProcessStartInfo("python", $" \"{decompScript}\" \"{pyc}\" \"{dst}\"")
                                { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                                using var pr = Process.Start(psi2);
                                if (pr != null) { await pr.WaitForExitAsync(); done++; }
                            }
                            log($"[Killer] Decompiled {done} pyc files -> {decDir}");
                        }
                        return;
                    }
                    log("[Killer] No .pyc found either, falling back...");
                }
            }
            else
            {
                log("[Killer] pyi_extract.py not found, cannot extract PYZ from EXE");
            }
        }

        // Now extract PYZ with extractor.py
        string? script = FindScript();
        if (script == null)
        {
            log("[Killer] extractor.py not found, using fallback");
            await Fallback(pyzPath, outDir, log);
            return;
        }
        log($"[Killer] Using pyz-unpacker: {Path.GetFileName(script)} (supports dict/list TOC, rebuilds valid .pyc)");
        var psi = new ProcessStartInfo("python", $" \"{script}\" \"{pyzPath}\" \"{outDir}\"") { RedirectStandardOutput=true, RedirectStandardError=true, UseShellExecute=false, CreateNoWindow=true };
        using var p = Process.Start(psi);
        if (p==null) { log("[Killer] failed start"); await Fallback(pyzPath,outDir,log); return; }
        string o = await p.StandardOutput.ReadToEndAsync();
        string e = await p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        foreach(var l in o.Split('\n')) if(!string.IsNullOrWhiteSpace(l)) log("  "+l.Trim());
        if(!string.IsNullOrWhiteSpace(e)) log("  err: "+e.Trim());
        var pycs = Directory.GetFiles(outDir,"*.pyc",SearchOption.AllDirectories);
        log($"[Killer] PYZ extracted: {pycs.Length} .pyc");
        long total = pycs.Sum(f=>new FileInfo(f).Length);
        log($"[Killer] Total pyc size {total/1024} KB vs original {origSize/1024} KB");
        if (total > origSize * 5) log("[Killer] Warning: total > 5x original - may include decompressed, but check");
        if (pycs.Length==0) await Fallback(pyzPath,outDir,log);
        else
        {
            string sample = pycs.FirstOrDefault()!;
            if (sample!=null)
            {
                string samplePy = Path.Combine(outDir, Path.GetFileNameWithoutExtension(sample)+"_sample.py");
                    string? decomp = FindPycDecompile();
                if (decomp != null && File.Exists(sample))
                {
                    var psi2 = new ProcessStartInfo("python",$" \"{decomp}\" \"{sample}\" \"{samplePy}\""){ RedirectStandardOutput=true, UseShellExecute=false, CreateNoWindow=true };
                    using var p2=Process.Start(psi2);
                    if(p2!=null) await p2.WaitForExitAsync();
                    if(File.Exists(samplePy)) log($"[Killer] Sample decompiled: {Path.GetFileName(samplePy)} ({new FileInfo(samplePy).Length} bytes)");
                }
            }
        }
    }

    static string? FindScript()
    {
        string[] cands = new[]{
            Path.Combine(AppContext.BaseDirectory,"Assets","pyz-unpacker","extractor.py"),
            Path.Combine(Directory.GetCurrentDirectory(),"Assets","pyz-unpacker","extractor.py")
        };
        return cands.FirstOrDefault(File.Exists);
    }

    static string? FindPyiExtract()
    {
        string[] cands = new[]{
            Path.Combine(AppContext.BaseDirectory,"Assets","pyi_extract.py"),
            Path.Combine(Directory.GetCurrentDirectory(),"Assets","pyi_extract.py")
        };
        return cands.FirstOrDefault(File.Exists);
    }

    static string? FindPycDecompile()
    {
        string[] cands = new[]{
            Path.Combine(AppContext.BaseDirectory,"Assets","pyc_decompile.py"),
            Path.Combine(Directory.GetCurrentDirectory(),"Assets","pyc_decompile.py")
        };
        return cands.FirstOrDefault(File.Exists);
    }

    static async Task Fallback(string pyz, string outDir, Action<string> log)
    {
        log("[Killer] Fallback: trying pyc_decompile bulk");
        string? script = FindPycDecompile();
        if (script == null) return;
        var psi = new ProcessStartInfo("python", $" \"{script}\" \"{pyz}\" \"{outDir}\""){ RedirectStandardOutput=true, UseShellExecute=false, CreateNoWindow=true };
        using var p = Process.Start(psi);
        if(p!=null) await p.WaitForExitAsync();
    }
}
