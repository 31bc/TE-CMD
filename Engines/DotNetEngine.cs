using System.IO;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.TypeSystem;
using System.Text.RegularExpressions;

namespace DecompilerSuite.Engines;

static class DotNetEngine
{
    public static async Task DecompileAsync(string asmPath, string outDir, Action<string> log)
    {
        Directory.CreateDirectory(outDir);
        log($"[KILLER .NET] Decompiling {Path.GetFileName(asmPath)} ...");
        string srcDir = Path.Combine(outDir, "cs_sources");
        Directory.CreateDirectory(srcDir);

        // Pre-scan for obfuscation
        var raw = await File.ReadAllBytesAsync(asmPath);
        string txt = System.Text.Encoding.ASCII.GetString(raw);
        bool isObf = txt.Contains("Confuser") || txt.Contains("Dotfuscator") || txt.Contains("Babel") || txt.Contains("SmartAssembly") || Regex.IsMatch(txt, @"k__BackingField");
        if (isObf) log($"[Killer] Obfuscation detected - will try de4dot + string decrypt");
        string prot = DetectProtection(raw);
        await File.WriteAllTextAsync(Path.Combine(outDir, "protection.txt"), prot);
        log(prot);

        // Try de4dot if available
        string? de4dotResult = await TryDe4dot(asmPath, outDir, log);
        string targetAsm = de4dotResult ?? asmPath;
        if (de4dotResult != null) log($"[Killer] de4dot success -> {Path.GetFileName(de4dotResult)}");

        try
        {
            var settings = new DecompilerSettings { ThrowOnAssemblyResolveErrors = false };
            // Try multiple settings for killer
            var decompiler = new CSharpDecompiler(targetAsm, settings);
            var name = Path.GetFileNameWithoutExtension(asmPath);

            log("[Killer] Fetching types with smart filters...");
            var types = decompiler.TypeSystem.MainModule.Compilation.GetAllTypeDefinitions().ToList();
            log($"[Killer] Found {types.Count} classes (including obfuscated)");

            int count=0, failed=0;
            foreach(var t in types)
            {
                if (t.Name.Length>50 && Regex.IsMatch(t.Name, @"^[a-z]{1,2}$")) continue; // skip heavily obfuscated single letter?
                try
                {
                    string code = decompiler.DecompileTypeAsString(t.FullTypeName);
                    // Killer: try string decrypt heuristics
                    code = TryDecryptStrings(code, log);
                    string safe = string.Join("_", t.FullTypeName.ToString().Split(Path.GetInvalidFileNameChars()));
                    safe = safe.Replace(".","_").Replace("<","").Replace(">","").Replace("/","_");
                    if (safe.Length>80) safe = safe.Substring(0,80);
                    string file = Path.Combine(srcDir, safe + ".cs");
                    await File.WriteAllTextAsync(file, code);
                    count++;
                    if (count%30==0) log($"  [Killer] {count}/{types.Count} ...");
                } catch(Exception ex){ failed++; if(failed<5) log($"[Killer] skip {t.Name}: {ex.Message}"); }
            }

            string all = Path.Combine(outDir, $"{name}_decompiled.cs");
            var allFiles = Directory.GetFiles(srcDir,"*.cs");
            File.WriteAllText(all, string.Join("\n\n//========================================\n\n", allFiles.Select(File.ReadAllText).Take(300)));
            log($"[Killer] Combined: {all} ({new FileInfo(all).Length/1024} KB)");

            try
            {
                using var pe = new PEReader(File.OpenRead(targetAsm));
                var reader = pe.GetMetadataReader();
                log($"[Killer] Metadata: {reader.TypeDefinitions.Count} types, {reader.MethodDefinitions.Count} methods");
                var strs = ExtractDotNetStrings(targetAsm, log);
                await File.WriteAllTextAsync(Path.Combine(outDir, "dotnet_strings.txt"), string.Join("\n", strs.Take(2000)));
                log($"[Killer] .NET strings: {strs.Count}");
            } catch {}

            log($" [KILLER] Decompiled {count} C# files in {srcDir} (failed {failed})");
            log($"[Killer] Output: {all} + {srcDir} + protection.txt + dotnet_strings.txt");
            if (isObf) log("[Killer] Obfuscated - check de4dot_output and try manual with de4dot GUI");
        }
        catch(Exception ex)
        {
            log($" [KILLER] .NET Error: {ex.Message}");
            log("[Killer] Try: de4dot, deobfuscator, or dnSpy with string decrypt plugin");
            throw;
        }
    }

    static string DetectProtection(byte[] d)
    {
        var txt = System.Text.Encoding.ASCII.GetString(d);
        var list = new List<string>();
        if (txt.Contains("ConfuserEx")||txt.Contains("Confuser")) list.Add("ConfuserEx");
        if (txt.Contains("Dotfuscator")) list.Add("Dotfuscator");
        if (txt.Contains("Babel")) list.Add("Babel");
        if (txt.Contains("SmartAssembly")) list.Add("SmartAssembly");
        if (txt.Contains("Themida")||txt.Contains(".NET Reactor")) list.Add("Reactor/Themida");
        if (txt.Contains("VMProtect")) list.Add("VMProtect");
        if (list.Count==0) return "[Killer] Protection: None / Light obfuscation";
        return "[Killer] Protection: " + string.Join(", ", list) + " (try de4dot)";
    }

    static async Task<string?> TryDe4dot(string asm, string outDir, Action<string> log)
    {
        try
        {
            string[] cands = new[] {
                Path.Combine(AppContext.BaseDirectory,"Assets","de4dot","de4dot.exe"),
                "de4dot.exe"
            };
            string? de4dot = cands.FirstOrDefault(File.Exists);
            if (de4dot==null) { log("[Killer] de4dot not found - skipping (download from github.com/de4dot/de4dot)"); return null; }
            string outFile = Path.Combine(outDir, Path.GetFileNameWithoutExtension(asm) + "_de4dot" + Path.GetExtension(asm));
            var psi = new System.Diagnostics.ProcessStartInfo(de4dot, $"\"{asm}\" -o \"{outFile}\"") { RedirectStandardOutput=true, UseShellExecute=false, CreateNoWindow=true };
            using var p = System.Diagnostics.Process.Start(psi);
            if (p==null) return null;
            string o = await p.StandardOutput.ReadToEndAsync();
            await p.WaitForExitAsync();
            if (File.Exists(outFile) && new FileInfo(outFile).Length>0) { log($"[Killer] de4dot output: {o.Split('\n').FirstOrDefault()?.Trim()}"); return outFile; }
        } catch (Exception ex) { log($"[Killer] de4dot fail: {ex.Message}"); }
        return null;
    }

    static string TryDecryptStrings(string code, Action<string> log)
    {
        // Simple heuristic: if code contains many \xXX or char arrays, try to decode
        if (code.Contains("\\x") && code.Length>5000)
        {
            // Count \x occurrences
            int count = Regex.Matches(code, @"\\x[0-9A-Fa-f]{2}").Count;
            if (count>20) log($"[Killer] Possible encrypted strings: {count} \\x found - may need manual decrypt");
        }
        return code;
    }

    static List<string> ExtractDotNetStrings(string asm, Action<string> log)
    {
        try
        {
            var txt = System.Text.Encoding.ASCII.GetString(File.ReadAllBytes(asm));
            var m = System.Text.RegularExpressions.Regex.Matches(txt, @"[\x20-\x7E]{5,100}");
            return m.Select(x=>x.Value).Where(s=>s.Length>5).Distinct().Take(2000).ToList();
        } catch { return new List<string>(); }
    }
}
