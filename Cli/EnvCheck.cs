using System.Diagnostics;
using System.Reflection;

namespace TECmd;

/// <summary>
/// `TE-CMD.exe check` - reports the tools the DecompilerSuite engines actually start.
/// Every entry here is a real dependency of an engine or of one of the Assets scripts.
/// </summary>
static class EnvCheck
{
    sealed record Item(string Name, bool Required, string Detail, bool Ok);

    public static int Run(CliLog log)
    {
        var items = new List<Item>();
        string baseDir = AppContext.BaseDirectory;

        var asm = Assembly.GetExecutingAssembly();
        string cliVer = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.0.0";
        string engineVer = asm.GetCustomAttribute<AssemblyFileVersionAttribute>()?.Version ?? "?";
        items.Add(new Item("Core", true, $"TE-CMD v{cliVer} / DecompilerSuite {engineVer}",
            File.Exists(Path.Combine(baseDir, "TE-CMD.dll"))));

        // runtime: self-contained package or installed .NET runtime
        bool bundled = File.Exists(Path.Combine(baseDir, "hostfxr.dll")) && File.Exists(Path.Combine(baseDir, "coreclr.dll"));
        items.Add(new Item(".NET runtime", true,
            bundled ? "self-contained (bundled in this folder)" : "framework dependent - .NET 10 runtime required",
            true));

        // ILSpy engine used by the dotnet decompiler (DotNetEngine)
        items.Add(new Item("ILSpy decompiler", true, "ICSharpCode.Decompiler.dll",
            File.Exists(Path.Combine(baseDir, "ICSharpCode.Decompiler.dll"))));

        string? assets = FindAssetsDir(baseDir);
        string assetsName = assets == null ? "assets\\" : Path.GetFileName(assets) + Path.DirectorySeparatorChar;

        string[] required =
        {
            "pyi_extract.py",
            "pyc_decompile.py",
            "magic_decompile.py",
            "cpp_capstone.py",
            "pyz-unpacker/extractor.py",
            "pyarmor-unpacker/pyarmor_unpacker.py",
            "themida-unpacker/themida_unpacker.py",
            "nuitka-revenant/nuitka_decompiler.py",
            "nuitka-static-unpacker/nuitka_decompiler.py",
            "nuitka-static-unpacker/list_modules.py",
        };
        int found = 0;
        foreach (var rel in required)
        {
            string? full = assets == null ? null : Path.Combine(assets, rel.Replace('/', Path.DirectorySeparatorChar));
            if (full != null && File.Exists(full)) found++;
        }
        items.Add(new Item(assetsName + "scripts", true, $"{found}/{required.Length} helper scripts", found == required.Length));

        foreach (var tool in new[] { "pycdc.exe", "pycdas.exe" })
        {
            string? full = assets == null ? null : Path.Combine(assets, tool);
            items.Add(new Item(tool, true, full != null && File.Exists(full) ? assetsName + tool : "missing", File.Exists(full)));
        }

        // python - started by PyInstaller/Nuitka/PYZ/PyArmor/Themida/Capstone engines
        string? python = ProbePython(out string pythonDetail);
        items.Add(new Item("Python", true, pythonDetail, python != null));

        // Optional tools referenced by the engines
        string de4dot = assets == null ? "" : Path.Combine(assets, "de4dot", "de4dot.exe");
        items.Add(new Item("de4dot", false,
            File.Exists(de4dot) ? "found" : "not installed (optional, .NET deobfuscation disabled)", File.Exists(de4dot)));

        // python modules used by the Assets scripts
        if (python != null)
        {
            foreach (var (module, detail) in ProbeModules(python))
                items.Add(new Item("python:" + module, false, detail, detail == "importable"));
        }
        else
        {
            items.Add(new Item("python packages", false, "skipped - python missing", false));
        }

        log.Result("TE-CMD Dependency Check");
        log.Result("");
        foreach (var it in items)
        {
            string mark = it.Ok ? "✓" : (it.Required ? "✗" : "–");
            log.Result($"  {it.Name,-22}{mark}  {it.Detail}");
        }

        var missing = items.Where(i => i.Required && !i.Ok).ToList();
        log.Result("");
        log.Result("Summary:");
        log.Result(missing.Count == 0
            ? "All required components are ready."
            : missing.Count + " required component(s) missing: " + string.Join(", ", missing.Select(m => m.Name)));
        return missing.Count == 0 ? 0 : 1;
    }

    static string? FindAssetsDir(string baseDir)
    {
        try
        {
            var hit = Directory.GetDirectories(baseDir)
                .FirstOrDefault(d => string.Equals(Path.GetFileName(d), "assets", StringComparison.OrdinalIgnoreCase));
            if (hit != null) return hit;
        }
        catch { }
        string fallback = Path.Combine(baseDir, "assets");
        return Directory.Exists(fallback) ? fallback : null;
    }

    static string? ProbePython(out string detail)
    {
        try
        {
            var psi = new ProcessStartInfo("python", "--version")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p == null) { detail = "could not start python"; return null; }
            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            if (!p.WaitForExit(15000)) { try { p.Kill(); } catch { } detail = "python timed out"; return null; }
            string version = (stdout + stderr).Trim();
            if (p.ExitCode != 0) { detail = $"python exited with {p.ExitCode}"; return null; }
            detail = string.IsNullOrEmpty(version) ? "python found" : version;
            return "python";
        }
        catch (Exception ex)
        {
            detail = "python not found on PATH";
            _ = ex;
            return null;
        }
    }

    static List<(string module, string detail)> ProbeModules(string python)
    {
        var result = new List<(string, string)>();
        string[] modules =
        {
            "zstandard",      // NuitkaEngine one-file zstd payload
            "capstone",       // Assets/cpp_capstone.py
            "pefile",         // Assets/cpp_capstone.py
            "Crypto",         // Assets/pyarmor-unpacker (pycryptodome)
            "cryptography",   // Assets/pyarmor-unpacker
            "decompyle3",     // Assets/pyc_decompile.py fallback
            "uncompyle6",     // Assets/pyc_decompile.py fallback
            "tkinter",        // Assets/magic_decompile.py
            "keyboard",       // Assets/magic_decompile.py
        };

        string script = string.Join(Environment.NewLine,
            "import importlib.util as u",
            "mods = " + "[" + string.Join(", ", modules.Select(m => "'" + m + "'")) + "]",
            "for m in mods:",
            "    try:",
            "        print(m + '=' + ('importable' if u.find_spec(m) else 'missing'))",
            "    except Exception:",
            "        print(m + '=missing')");

        string temp = Path.Combine(Path.GetTempPath(), $"tecmd_check_{Guid.NewGuid():N}.py");
        try
        {
            File.WriteAllText(temp, script);
            var psi = new ProcessStartInfo(python, $"\"{temp}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p == null) return modules.Select(m => (m, "probe failed")).ToList();
            string stdout = p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit(15000);

            var found = new Dictionary<string, string>();
            foreach (var line in stdout.Split('\n'))
            {
                var t = line.Trim();
                int eq = t.IndexOf('=');
                if (eq > 0) found[t[..eq]] = t[(eq + 1)..];
            }
            foreach (var m in modules)
            {
                string state = found.TryGetValue(m, out var v) ? v : "missing";
                result.Add((m, state == "importable" ? "importable" : "missing"));
            }
            return result;
        }
        catch
        {
            return modules.Select(m => (m, "probe failed")).ToList();
        }
        finally
        {
            try { File.Delete(temp); } catch { }
        }
    }
}
