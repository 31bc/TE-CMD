using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TECmd;

/// <summary>
/// `TE-CMD.exe package` - builds the release packages.
///
/// Three artifacts, one pipeline:
///
///   tool    release\   -> dist\TE-CMD-v&lt;v&gt;-win-x64.zip    portable runtime
///   source  stage\source -> dist\TE-CMD-v&lt;v&gt;-source.zip   buildable source
///   full    stage\full   -> dist\TE-CMD-v&lt;v&gt;-full.zip     source+tool+samples
///
/// Stages: clean -> publish (0 errors / 0 warnings) -> collect runtime/assets
/// -> stage source -> assemble full -> normalize + leak scan -> ZIP + SHA256 ->
/// verify (tool from a clean dir, source rebuild, full structure, ZIP smoke,
/// hashes, licenses) -> release manifest.
/// </summary>
static class PackageBuilder
{
    public const string Product = AppInfo.Product;
    public const string Platform = "win-x64";

    static readonly string[] RequiredAssets =
    {
        "pyi_extract.py",
        "pyc_decompile.py",
        "magic_decompile.py",
        "pycdc.exe",
        "pycdas.exe",
        "cpp_capstone.py",
        "pyz-unpacker/extractor.py",
        "pyarmor-unpacker/pyarmor_unpacker.py",
        "themida-unpacker/themida_unpacker.py",
        "nuitka-revenant/nuitka_decompiler.py",
        "nuitka-static-unpacker/nuitka_decompiler.py",
        "nuitka-static-unpacker/list_modules.py",
    };

    /// <summary>
    /// Developer path patterns that must not survive into any package.
    /// Written as concatenations on purpose: this file holds the scanner, so the
    /// literal patterns must not appear here or the scan would flag itself.
    /// </summary>
    static readonly string[] ForbiddenPathPatterns =
    {
        @"C:\" + @"Users",
        @"D:\" + @"LE",
        "Desktop" + @"\TE-CMD",
        "Downloads" + @"\DecompilerSuite",
        "AppData" + @"\Local\Temp",
        @"\" + @"Administrator" + @"\",
    };

    /// <summary>File names that mark a package as dirty (temporary / user files).</summary>
    static readonly string[] TemporaryFilePatterns =
    {
        ".tmp", ".log", ".user", ".suo", ".cache", ".bak", ".orig", ".swp",
    };

    static readonly string[] TemporaryFileNames =
    {
        "Thumbs.db", "desktop.ini", ".DS_Store",
    };

    /// <summary>One release artifact (zip file + the folder it is built from).</summary>
    sealed class PackageInfo
    {
        public required string Key;        // tool | source | full
        public required string Title;      // TOOL | SOURCE | FULL
        public required string ZipBase;    // TE-CMD-v1.0.0-win-x64
        public required string RootName;   // folder inside the archive
        public required string SourceDir;  // folder whose content becomes the archive
        public string ZipPath = "";        // finished archive (dist\<ZipBase>.zip)
        public int Files;
        public long UnpackedBytes;
        public long ZipBytes;
        public string Sha = "";
    }


    sealed class StepException : Exception
    {
        public readonly string Label;
        public StepException(string label, string message) : base(message) { Label = label; }
    }

    public static async Task<int> RunAsync(CliOptions opt, CliLog log)
    {
        // ---------------------------------------------------------- selection
        bool all = !opt.AnyPackageFlag;                 // plain 'package'
        bool selected = opt.PackageTool || opt.PackageSource || opt.PackageFull;

        bool doClean = all || opt.PackageClean;
        bool doBuild = all || selected;
        bool doZip = all || selected || opt.PackageZip;
        bool doVerify = all || opt.PackageVerify;

        bool wantTool = !selected || opt.PackageTool;
        bool wantSource = !selected || opt.PackageSource;
        bool wantFull = !selected || opt.PackageFull;
        // the full archive is source + tool, so asking for it pulls both in
        if (doBuild && wantFull) { wantTool = true; wantSource = true; }

        var results = new List<(string label, bool ok)>();
        var verifyReport = new Dictionary<string, string>();
        var rebuilt = new List<string>();          // package keys zipped in this run
        string? fail = null;

        string? projectRoot = FindProjectRoot();
        if (projectRoot == null)
        {
            Console.Error.WriteLine($"error: package needs the {Product} source tree (no TE-CMD.csproj found above {AppContext.BaseDirectory})");
            return Program.ExitFailure;
        }

        string csproj = Path.Combine(projectRoot, "TE-CMD.csproj");
        string tfm = ReadTargetFramework(csproj);
        string baseDir = opt.OutputGiven ? Path.GetFullPath(opt.OutputBase) : projectRoot;
        string releaseDir = Path.Combine(baseDir, "release");
        string stageDir = Path.Combine(baseDir, "stage");
        string sourceStage = Path.Combine(stageDir, "source");
        string fullStage = Path.Combine(stageDir, "full");
        string distDir = Path.Combine(baseDir, "dist");
        string version = AppInfo.Version;

        var packages = new List<PackageInfo>();
        if (wantTool)
            packages.Add(new PackageInfo
            {
                Key = "tool", Title = "TOOL",
                ZipBase = $"{Product}-v{version}-{Platform}", RootName = Product,
                SourceDir = releaseDir,
            });
        if (wantSource)
            packages.Add(new PackageInfo
            {
                Key = "source", Title = "SOURCE",
                ZipBase = $"{Product}-v{version}-source", RootName = $"{Product}-source",
                SourceDir = sourceStage,
            });
        if (wantFull)
            packages.Add(new PackageInfo
            {
                Key = "full", Title = "FULL",
                ZipBase = $"{Product}-v{version}-full", RootName = $"{Product}-Full",
                SourceDir = fullStage,
            });
        foreach (var p in packages)
            p.ZipPath = Path.Combine(distDir, p.ZipBase + ".zip");

        string steps = string.Join(" ",
            (doClean ? new[] { "clean" } : Array.Empty<string>())
            .Concat(doBuild ? new[] { "build" } : Array.Empty<string>())
            .Concat(doZip ? new[] { "zip" } : Array.Empty<string>())
            .Concat(doVerify ? new[] { "verify" } : Array.Empty<string>()));

        Say($"{Product} release builder  ({Product} v{version} / {Platform} / Release)");
        Say($"  source     {projectRoot}");
        Say($"  packages   {string.Join(", ", packages.Select(p => p.Key))}");
        Say($"  steps      {steps}");
        Say($"  release    {releaseDir}");
        Say($"  stage      {stageDir}");
        Say($"  dist       {distDir}");
        Say("");

        try
        {
            if (doClean)
            {
                Say("[..] cleaning previous release artifacts");
                GuardNotRunningFromPackage(releaseDir, stageDir, distDir);
                CleanArtifacts(baseDir, projectRoot, tfm);
                if (!doBuild) results.Add(("Release artifacts cleaned", true));
            }

            // ------------------------------------------------------- tool package
            if (doBuild && wantTool)
            {
                Say("[..] building release (dotnet publish -c Release -r win-x64 --self-contained)");
                await BuildReleaseAsync(csproj, projectRoot, releaseDir);
                results.Add(("Release build", true));

                // 1) external tools + scripts that the engines start
                Say("[..] collecting dependencies (assets, helper scripts, tools)");
                RenameAssets(releaseDir);
                TrimAssets(Path.Combine(releaseDir, "assets"));
                VerifyRequiredAssets(releaseDir);
                results.Add(("Dependencies collected", true));

                // 2) .NET runtime files
                Say("[..] collecting runtime files (self-contained .NET)");
                CollectRuntime(releaseDir);
                results.Add(("Runtime files collected", true));

                // 3) configuration + documentation + licenses
                Say("[..] collecting configuration");
                CollectConfiguration(releaseDir, version);
                results.Add(("Configuration collected", true));

                // 4) machine specific paths
                Say("[..] normalizing paths");
                ScanForMachinePaths(releaseDir, "Paths normalized");
                results.Add(("Paths normalized", true));

                // 5) completeness
                Say("[..] checking package completeness");
                VerifyPackageComplete(releaseDir);
                results.Add(("Package created", true));
            }

            // ----------------------------------------------------- source package
            if (doBuild && wantSource)
            {
                Say("[..] staging the source package (buildable project tree)");
                StageSourcePackage(projectRoot, sourceStage);
                results.Add(("Source collected", true));

                ScanForMachinePaths(sourceStage, "Source paths clean");
                results.Add(("Source paths clean", true));

                VerifySourceComplete(sourceStage);
                results.Add(("Source package created", true));
            }

            // ------------------------------------------------------- full package
            if (doBuild && wantFull)
            {
                Say("[..] assembling the full package (source + tool + samples + docs)");
                AssembleFullPackage(projectRoot, sourceStage, releaseDir, fullStage, version);
                results.Add(("Full package assembled", true));

                ScanForMachinePaths(fullStage, "Full paths clean");
                results.Add(("Full package created", true));
            }

            // ------------------------------------------------------- leak scan
            var scanDirs = packages.Where(p => Directory.Exists(p.SourceDir)).Select(p => p.SourceDir).ToList();
            if ((doBuild || doZip || doVerify) && scanDirs.Count > 0)
            {
                Say("[..] scanning packages (machine paths, debug symbols, temporary files)");
                var health = HealthScan(scanDirs);
                results.Add(("Path leak scan", true));
                verifyReport["Path Leak Scan"] =
                    $"PASS (leaks {health.Leaks} / pdb {health.Pdbs} / temp {health.Temps})";
                Console.WriteLine($"      Path leaks: {health.Leaks}   PDB files: {health.Pdbs}   Temporary files: {health.Temps}");
            }

            if (doZip || doVerify)
            {
                foreach (var p in packages)
                {
                    bool present = Directory.Exists(p.SourceDir)
                        && (p.Key != "tool" || File.Exists(Path.Combine(p.SourceDir, Product + ".exe")));
                    if (!present)
                        throw new StepException(doVerify ? "Package verification" : "ZIP created",
                            $"no {p.Key} package in {p.SourceDir} - run 'TE-CMD.exe package' first");
                }
            }

            // ------------------------------------------------- tool folder check
            if (doVerify && wantTool)
            {
                Say("[..] verifying the tool package from a clean directory");
                await VerifyAsync(releaseDir, projectRoot, full: doZip);
                results.Add(("Tool package verification", true));
                verifyReport["Tool"] = "PASS";
            }

            // ------------------------------------------------------------ zip
            if (doZip)
            {
                foreach (var p in packages)
                {
                    Say($"[..] creating ZIP ({p.Key}): {p.ZipBase}.zip");
                    (p.Sha, p.ZipBytes) = CreateZipAndChecksum(p.SourceDir, distDir, p.ZipBase, p.RootName);
                    p.Files = CountFiles(p.SourceDir);
                    p.UnpackedBytes = DirSize(p.SourceDir);
                    rebuilt.Add(p.Key);
                    results.Add(($"{p.Title} ZIP created", true));
                }
                results.Add(("SHA256 generated", true));
            }
            else
            {
                foreach (var p in packages)
                {
                    p.Files = CountFiles(p.SourceDir);
                    p.UnpackedBytes = DirSize(p.SourceDir);
                    string zipPath = Path.Combine(distDir, p.ZipBase + ".zip");
                    if (File.Exists(zipPath))
                    {
                        p.ZipBytes = new FileInfo(zipPath).Length;
                        p.Sha = Sha256File(zipPath);
                    }
                }
            }

            // ------------------------------------------------------- verification
            if (doVerify)
            {
                foreach (var p in packages)
                {
                    string zipPath = Path.Combine(distDir, p.ZipBase + ".zip");
                    if (!File.Exists(zipPath))
                        throw new StepException("ZIP smoke test", $"missing {zipPath} - run 'TE-CMD.exe package' first");
                }

                foreach (var p in packages)
                {
                    Say($"[..] verifying the {p.Key} archive from a clean directory");
                    string extracted = ExtractZip(distDir, p);
                    switch (p.Key)
                    {
                        case "tool":
                            await VerifyToolExtractedAsync(extracted, projectRoot);
                            verifyReport["Tool"] = verifyReport.GetValueOrDefault("Tool", "PASS");
                            break;
                        case "source":
                            await VerifySourceExtractedAsync(extracted);
                            verifyReport["Source Build"] = "PASS";
                            results.Add(("Source build verification", true));
                            break;
                        case "full":
                            await VerifyFullExtractedAsync(extracted, projectRoot);
                            verifyReport["Full"] = "PASS";
                            results.Add(("Full package verification", true));
                            break;
                    }
                }
                verifyReport["ZIP Smoke Test"] = "PASS";
                results.Add(("ZIP smoke test", true));

                VerifyChecksums(distDir, packages);
                verifyReport["Hash Verification"] = "PASS";
                results.Add(("SHA256 verification", true));

                VerifyLicenses(packages, projectRoot, version);
                verifyReport["License Check"] = "PASS";
                results.Add(("License check", true));
            }

            // --------------------------------------------------------- manifest
            if ((doZip || doVerify) && packages.Any(p => File.Exists(Path.Combine(distDir, p.ZipBase + ".zip"))))
            {
                WriteManifest(distDir, packages, version, verifyReport, projectRoot, rebuilt);
                results.Add(("Release manifest written", true));
            }
        }
        catch (StepException ex)
        {
            results.Add((ex.Label, false));
            fail = ex.Message;
        }
        catch (Exception ex)
        {
            results.Add(("unexpected error", false));
            fail = ex.GetType().Name + ": " + ex.Message;
        }

        return Finish(results, fail, packages, verifyReport);
    }

    // ------------------------------------------------------------------ steps

    /// <summary>
    /// Packaging must never delete the executable it is running from (that is what
    /// happens when a packaged copy inside release\ is used to rebuild itself).
    /// </summary>
    static void GuardNotRunningFromPackage(params string[] dirs)
    {
        string exe = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, Product + ".exe");
        foreach (var dir in dirs)
        {
            string prefix = dir.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (exe.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                throw new StepException("Release artifacts cleaned",
                    $"this executable runs from {dir} - packaging would delete itself.\n" +
                    $"Run the packaged copy from another folder, or build with '{Product}.exe package' from the development output.");
        }
    }

    static void CleanArtifacts(string baseDir, string projectRoot, string tfm)
    {
        foreach (var dir in new[]
        {
            Path.Combine(baseDir, "release"),
            Path.Combine(baseDir, "stage"),
            Path.Combine(baseDir, "dist"),
            Path.Combine(baseDir, ".package-staging"),
        })
        {
            if (!Directory.Exists(dir)) continue;
            TryDeleteDirectory(dir, out string? err);
            if (Directory.Exists(dir))
                throw new StepException("Release artifacts cleaned", $"cannot delete {dir}: {err ?? "in use"}");
        }

        // verification scratch folders
        foreach (var name in new[] { "TE-CMD-package-verify", "TE-CMD-zip-verify", "TE-CMD-source-verify", "TE-CMD-full-verify" })
            TryDeleteDirectory(Path.Combine(Path.GetTempPath(), name), out _);

        // Release intermediates: dropping them guarantees a fresh compile, so an
        // old executable can never be packaged silently.
        TryDeleteDirectory(Path.Combine(projectRoot, "obj", "Release"), out _);

        // previous RID build output (may be locked if a published exe was started from there)
        string ridOut = Path.Combine(projectRoot, "bin", "Release", tfm, Platform);
        if (Directory.Exists(ridOut))
        {
            TryDeleteDirectory(ridOut, out string? err);
            if (Directory.Exists(ridOut))
                Console.WriteLine($"      note: {ridOut} is in use - a fresh publish is written to the release folder instead");
        }
    }

    static async Task BuildReleaseAsync(string csproj, string projectRoot, string releaseDir)
    {
        if (!FindDotnet(out string dotnet, out string dotnetErr))
            throw new StepException("Release build", dotnetErr);

        if (Directory.Exists(releaseDir))
        {
            TryDeleteDirectory(releaseDir, out string? err);
            if (Directory.Exists(releaseDir))
                throw new StepException("Release build", $"cannot recreate {releaseDir}: {err ?? "in use"}");
        }
        Directory.CreateDirectory(releaseDir);

        string args = string.Join(" ",
            "publish", $"\"{csproj}\"",
            "-c Release",
            $"-r {Platform}",
            "--self-contained true",
            $"-o \"{releaseDir}\"",
            "-p:DebugType=None -p:DebugSymbols=false",
            "-v minimal");

        var (exit, output) = await RunCapturedAsync(dotnet, args, projectRoot, 900_000, null);

        foreach (var line in output.Split('\n'))
        {
            var t = line.TrimEnd('\r');
            if (t.Contains(": error ") || t.Contains(": warning "))
                Console.WriteLine("      " + t);
        }

        int warnings = LastCount(output, "Warning(s)");
        int errors = LastCount(output, "Error(s)");
        bool hasErrorLines = output.Contains(": error ");

        if (exit != 0 || errors > 0 || hasErrorLines)
            throw new StepException("Release build", $"publish failed (exit {exit}, {errors} errors) - packaging stopped");
        if (warnings > 0)
            throw new StepException("Release build", $"build produced {warnings} warning(s) - packaging requires 0 warnings");

        // no debug symbols, no stray PDB
        foreach (var pdb in Directory.GetFiles(releaseDir, "*.pdb", SearchOption.TopDirectoryOnly))
            File.Delete(pdb);

        foreach (var required in new[] { "TE-CMD.exe", "TE-CMD.dll", "TE-CMD.deps.json", "TE-CMD.runtimeconfig.json" })
            if (!File.Exists(Path.Combine(releaseDir, required)))
                throw new StepException("Release build", $"publish output is missing {required}");

        // freshness: never package a stale executable
        string dll = Path.Combine(releaseDir, "TE-CMD.dll");
        var dllTime = File.GetLastWriteTimeUtc(dll);
        var newestSource = NewestSourceTime(projectRoot);
        if (dllTime < newestSource)
            throw new StepException("Release build",
                $"published TE-CMD.dll ({dllTime:HH:mm:ss}) is older than the newest source file ({newestSource:HH:mm:ss}) - stale build");

        Console.WriteLine($"      build ok: 0 errors, 0 warnings, {DirSize(releaseDir) / 1024 / 1024} MB published");
    }

    static void RenameAssets(string releaseDir)
    {
        string from = Path.Combine(releaseDir, "Assets");
        string to = Path.Combine(releaseDir, "assets");
        if (!Directory.Exists(from)) return;
        // case only rename: move through a temporary name so it works on a case insensitive volume
        string tmp = Path.Combine(releaseDir, "assets.tmp");
        if (Directory.Exists(tmp)) TryDeleteDirectory(tmp, out _);
        Directory.Move(from, tmp);
        if (Directory.Exists(to)) TryDeleteDirectory(to, out _);
        Directory.Move(tmp, to);
    }

    static void TrimAssets(string assetsDir)
    {
        if (!Directory.Exists(assetsDir)) return;

        // development / repository metadata that no engine reads at runtime
        string[] dropDirs = { ".github", "docs", "examples", "nuitka-nbc-rebuilder-skill" };
        string[] dropFiles = { ".gitignore", ".gitattributes", ".editorconfig" };
        string[] dropPrefixes = { "CONTRIBUTING", "SECURITY", "ETHICS", "CHANGELOG" };
        string[] dropExact = { "icon.ico", "icon.png" };

        foreach (var d in Directory.GetDirectories(assetsDir, "*", SearchOption.AllDirectories))
        {
            string name = Path.GetFileName(d);
            if (Array.IndexOf(dropDirs, name) >= 0)
                TryDeleteDirectory(d, out _);
        }
        foreach (var f in Directory.GetFiles(assetsDir, "*", SearchOption.AllDirectories))
        {
            string name = Path.GetFileName(f);
            bool drop = Array.IndexOf(dropFiles, name) >= 0
                        || Array.IndexOf(dropExact, name) >= 0
                        || Array.Exists(dropPrefixes, p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase));
            if (drop) TryDeleteFile(f, out _);
        }
        // remove directories left empty by the trim
        foreach (var d in Directory.GetDirectories(assetsDir, "*", SearchOption.AllDirectories).OrderByDescending(s => s.Length))
        {
            if (Directory.Exists(d) && Directory.GetFileSystemEntries(d).Length == 0)
                TryDeleteDirectory(d, out _);
        }
    }

    static void VerifyRequiredAssets(string releaseDir)
    {
        string assets = Path.Combine(releaseDir, "assets");
        var missing = new List<string>();
        foreach (var rel in RequiredAssets)
        {
            string full = Path.Combine(assets, rel.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(full)) missing.Add("assets/" + rel);
        }
        if (missing.Count > 0)
            throw new StepException("Dependencies collected", "missing packaged dependencies: " + string.Join(", ", missing));
    }

    static void CollectRuntime(string releaseDir)
    {
        string[] required = { "hostfxr.dll", "hostpolicy.dll", "coreclr.dll", "mscorlib.dll", "System.Private.CoreLib.dll" };
        var missing = required.Where(f => !File.Exists(Path.Combine(releaseDir, f))).ToList();
        if (missing.Count > 0)
            throw new StepException("Runtime files collected",
                "not a self-contained build (missing " + string.Join(", ", missing) + ") - .NET runtime would be required on the target machine");

        string rc = Path.Combine(releaseDir, "TE-CMD.runtimeconfig.json");
        string text = File.ReadAllText(rc);
        if (!text.Contains("includedFrameworks"))
            throw new StepException("Runtime files collected", "TE-CMD.runtimeconfig.json does not declare an included framework - publish is framework dependent");

        if (Directory.GetFiles(releaseDir, "*.pdb", SearchOption.TopDirectoryOnly).Length > 0)
            throw new StepException("Runtime files collected", "debug symbols must not be packaged");
    }

    static void CollectConfiguration(string releaseDir, string version)
    {
        // config\config.json
        string configDir = Path.Combine(releaseDir, "config");
        Directory.CreateDirectory(configDir);
        string configJson = Path.Combine(configDir, "config.json");
        if (!File.Exists(configJson))
            File.WriteAllText(configJson, AppConfig.DefaultJson(), new UTF8Encoding(false));

        // output\ (created by the application on first run, shipped so the layout is visible)
        Directory.CreateDirectory(Path.Combine(releaseDir, "output"));

        // licenses\
        string licenseDir = Path.Combine(releaseDir, "licenses");
        Directory.CreateDirectory(licenseDir);
        string assets = Path.Combine(releaseDir, "assets");
        if (Directory.Exists(assets))
        {
            foreach (var f in Directory.GetFiles(assets, "LICENSE*", SearchOption.AllDirectories))
            {
                string rel = Path.GetRelativePath(assets, f);
                string dest = Path.Combine(licenseDir, rel.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                File.Copy(f, dest, true);
            }
        }
        File.WriteAllText(Path.Combine(licenseDir, "THIRD-PARTY-NOTICES.txt"), ThirdPartyNotices(version), new UTF8Encoding(false));

        // the same notice at the package root: a reader must find it without
        // having to know the folder layout
        File.WriteAllText(Path.Combine(releaseDir, "THIRD-PARTY-NOTICES.txt"), ThirdPartyNotices(version), new UTF8Encoding(false));

        // README.txt (public name for the developer README, machine paths removed)
        File.WriteAllText(Path.Combine(releaseDir, "README.txt"), ReadmeText(version), new UTF8Encoding(false));
    }

    static void ScanForMachinePaths(string dir, string failLabel)
    {
        var textExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".json", ".txt", ".md", ".py", ".yml", ".yaml", ".config", ".xml", ".ps1", ".bat", ".cmd", ".cs", ".csproj",
            ".toml", ".cfg", ".ini", ".props", ".targets", ".editorconfig", ".gitignore", ".gitattributes"
        };

        var hits = new List<string>();
        foreach (var f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
        {
            string name = Path.GetFileName(f);
            string ext = Path.GetExtension(f);
            bool scan = textExt.Contains(ext)
                        || name is "TE-CMD.exe" or "TE-CMD.dll"
                        || name.StartsWith("LICENSE", StringComparison.OrdinalIgnoreCase)
                        || Path.GetFileNameWithoutExtension(name).Equals("LICENSE", StringComparison.OrdinalIgnoreCase);
            if (!scan) continue;

            string content;
            try { content = File.ReadAllText(f); }
            catch { continue; }

            foreach (var pattern in ForbiddenPathPatterns)
            {
                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    hits.Add(Path.GetRelativePath(dir, f) + " -> " + pattern);
                    break;
                }
            }
        }

        if (hits.Count > 0)
            throw new StepException(failLabel,
                "machine specific paths found in the package: " + string.Join("; ", hits.Take(5)));
    }

    // ------------------------------------------------------- package health

    readonly record struct Health(int Leaks, int Pdbs, int Temps);

    /// <summary>
    /// Counts what must never ship: developer paths, debug symbols, temporary
    /// and user files. Any hit fails the build.
    /// </summary>
    static Health HealthScan(IReadOnlyList<string> dirs)
    {
        int leaks = 0, pdbs = 0, temps = 0;
        var examples = new List<string>();

        foreach (var dir in dirs)
        {
            foreach (var f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
            {
                string name = Path.GetFileName(f);
                string ext = Path.GetExtension(f);

                if (ext.Equals(".pdb", StringComparison.OrdinalIgnoreCase))
                {
                    pdbs++;
                    examples.Add("pdb: " + Path.GetRelativePath(dir, f));
                    continue;
                }

                if (TemporaryFilePatterns.Contains(ext, StringComparer.OrdinalIgnoreCase)
                    || TemporaryFileNames.Contains(name, StringComparer.OrdinalIgnoreCase))
                {
                    temps++;
                    examples.Add("temp: " + Path.GetRelativePath(dir, f));
                    continue;
                }

                // developer paths: text content plus the binaries we own
                bool scan = IsTextFile(f)
                            || ext is ".exe" or ".dll"
                            || name.StartsWith("LICENSE", StringComparison.OrdinalIgnoreCase);
                if (!scan) continue;

                string content;
                try { content = File.ReadAllText(f); }
                catch { continue; }

                foreach (var pattern in ForbiddenPathPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        leaks++;
                        examples.Add(Path.GetRelativePath(dir, f) + " -> " + pattern);
                        break;
                    }
                }
            }
        }

        if (leaks > 0 || pdbs > 0 || temps > 0)
            throw new StepException("Path leak scan",
                $"Path leaks: {leaks}   PDB files: {pdbs}   Temporary files: {temps}\n" +
                string.Join("\n", examples.Take(8)));

        return new Health(leaks, pdbs, temps);
    }

    static void VerifyPackageComplete(string releaseDir)
    {
        var mustExist = new List<string>
        {
            "TE-CMD.exe", "TE-CMD.dll", "TE-CMD.deps.json", "TE-CMD.runtimeconfig.json",
            "ICSharpCode.Decompiler.dll",
            "config/config.json", "README.txt",
            "licenses/THIRD-PARTY-NOTICES.txt",
            "assets/pyi_extract.py", "assets/pycdc.exe", "assets/pycdas.exe",
        };
        var missing = mustExist.Where(rel => !File.Exists(Path.Combine(releaseDir, rel.Replace('/', Path.DirectorySeparatorChar)))).ToList();
        if (missing.Count > 0)
            throw new StepException("Package created", "package is incomplete: " + string.Join(", ", missing));

        int files = Directory.GetFiles(releaseDir, "*", SearchOption.AllDirectories).Length;
        Console.WriteLine($"      {files} files, {DirSize(releaseDir) / 1024 / 1024} MB");
    }

    // ---------------------------------------------------------- source package

    /// <summary>
    /// Copies the real project tree into the source package: everything the
    /// compiler and the engines need, nothing that only exists on a developer
    /// machine (bin, obj, previous packages, harness, generated output).
    /// </summary>
    static void StageSourcePackage(string projectRoot, string sourceStage)
    {
        if (Directory.Exists(sourceStage))
        {
            TryDeleteDirectory(sourceStage, out string? err);
            if (Directory.Exists(sourceStage))
                throw new StepException("Source collected", $"cannot recreate {sourceStage}: {err ?? "in use"}");
        }
        Directory.CreateDirectory(sourceStage);

        // directories that never belong into a source release - applied at every
        // depth, so the bin\ and obj\ folders of the sample projects cannot bring
        // developer paths along
        string[] denyDirs =
        {
            "bin", "obj", "release", "dist", "stage", "output", "tools",
            ".git", ".vs", ".idea", ".github", "__pycache__", "node_modules",
        };
        // files that are build output / user state
        string[] denyFiles = { "*.pdb", "*.user", "*.suo", "*.cache", "*.tmp", "*.log", "Thumbs.db", "desktop.ini" };

        int copied = 0;
        CopyTreeFiltered(projectRoot, sourceStage, denyDirs, denyFiles, ref copied);

        // the tree must be buildable: those are the roots of the build
        string[] mustExist =
        {
            "TE-CMD.csproj", "Program.cs",
            "Cli", "Engines", "Helpers", "Assets", "config", "README.md", "BUILD.md",
        };
        var missing = mustExist.Where(rel => !File.Exists(Path.Combine(sourceStage, rel))
                                             && !Directory.Exists(Path.Combine(sourceStage, rel))).ToList();
        if (missing.Count > 0)
            throw new StepException("Source collected", "source package is missing: " + string.Join(", ", missing));

        Console.WriteLine($"      {copied} files, {DirSize(sourceStage) / 1024 / 1024} MB");
    }

    /// <summary>Recursive copy that honours the deny lists at every level.</summary>
    static void CopyTreeFiltered(string source, string dest, string[] denyDirs, string[] denyFiles, ref int copied)
    {
        Directory.CreateDirectory(dest);

        foreach (var dir in Directory.GetDirectories(source))
        {
            string name = Path.GetFileName(dir);
            if (Array.IndexOf(denyDirs, name) >= 0) continue;
            CopyTreeFiltered(dir, Path.Combine(dest, name), denyDirs, denyFiles, ref copied);
        }

        foreach (var file in Directory.GetFiles(source))
        {
            string name = Path.GetFileName(file);
            if (Array.Exists(denyFiles, pat => MatchesPattern(name, pat))) continue;
            File.Copy(file, Path.Combine(dest, name), true);
            copied++;
        }
    }

    static bool MatchesPattern(string name, string pattern) =>
        pattern.StartsWith("*.", StringComparison.Ordinal)
            ? name.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase)
            : name.Equals(pattern, StringComparison.OrdinalIgnoreCase);

    static void VerifySourceComplete(string sourceStage)
    {
        // Assets are Content of the project - without them the build produces a
        // tool that cannot find its engine scripts.
        string[] required =
        {
            "TE-CMD.csproj", "Program.cs",
            Path.Combine("Cli", "CliOptions.cs"),
            Path.Combine("Cli", "PackageBuilder.cs"),
            Path.Combine("Engines", "DotNetEngine.cs"),
            Path.Combine("Helpers", "Detector.cs"),
            Path.Combine("Assets", "pyi_extract.py"),
            Path.Combine("Assets", "pycdc.exe"),
            Path.Combine("config", "config.json"),
            "README.md", "BUILD.md",
        };
        var missing = required.Where(rel => !File.Exists(Path.Combine(sourceStage, rel))).ToList();
        if (missing.Count > 0)
            throw new StepException("Source package created", "source package is incomplete: " + string.Join(", ", missing));

        if (Directory.GetFiles(sourceStage, "*.pdb", SearchOption.AllDirectories).Length > 0)
            throw new StepException("Source package created", "source package must not contain .pdb files");

        Console.WriteLine($"      {CountFiles(sourceStage)} files, {DirSize(sourceStage) / 1024 / 1024} MB");
    }

    // ----------------------------------------------------------- full package

    /// <summary>
    /// Full archive for developers / archiving:
    ///
    ///   TE-CMD-Full\
    ///     source\   buildable project      tool\   portable release
    ///     samples\  test targets           docs\   documentation
    ///     licenses\ third party licenses   README.txt  BUILD.md  RELEASE-MANIFEST.json
    /// </summary>
    static void AssembleFullPackage(string projectRoot, string sourceStage, string releaseDir, string fullStage, string version)
    {
        if (Directory.Exists(fullStage))
        {
            TryDeleteDirectory(fullStage, out string? err);
            if (Directory.Exists(fullStage))
                throw new StepException("Full package assembled", $"cannot recreate {fullStage}: {err ?? "in use"}");
        }
        Directory.CreateDirectory(fullStage);

        if (!Directory.Exists(sourceStage))
            throw new StepException("Full package assembled", "the source package is missing - run the build step first");
        if (!File.Exists(Path.Combine(releaseDir, Product + ".exe")))
            throw new StepException("Full package assembled", "the tool package is missing - run the build step first");

        // 1) source (already sanitized and trimmed by the source stage)
        CopyDirectory(sourceStage, Path.Combine(fullStage, "source"));

        // 2) portable tool
        CopyDirectory(releaseDir, Path.Combine(fullStage, "tool"));

        // 3) test samples - build output of the samples projects is not shipped
        string samplesSrc = Path.Combine(projectRoot, "samples");
        if (Directory.Exists(samplesSrc))
        {
            string samplesDst = Path.Combine(fullStage, "samples");
            Directory.CreateDirectory(samplesDst);
            foreach (var file in Directory.GetFiles(samplesSrc, "*", SearchOption.TopDirectoryOnly))
                File.Copy(file, Path.Combine(samplesDst, Path.GetFileName(file)), true);

            string netSrc = Path.Combine(samplesSrc, "sample-net");
            if (Directory.Exists(netSrc))
            {
                string netDst = Path.Combine(samplesDst, "sample-net");
                Directory.CreateDirectory(netDst);
                foreach (var file in Directory.GetFiles(netSrc, "*", SearchOption.TopDirectoryOnly))
                    File.Copy(file, Path.Combine(netDst, Path.GetFileName(file)), true);
            }
        }

        // 4) documentation
        string docs = Path.Combine(fullStage, "docs");
        Directory.CreateDirectory(docs);
        string readme = Path.Combine(projectRoot, "README.md");
        if (File.Exists(readme)) File.Copy(readme, Path.Combine(docs, "README.md"), true);
        string build = Path.Combine(projectRoot, "BUILD.md");
        if (File.Exists(build)) File.Copy(build, Path.Combine(docs, "BUILD.md"), true);

        // 5) licenses: every license of every bundled component
        CopyLicensesTo(releaseDir, Path.Combine(fullStage, "licenses"));

        // 6) package guide + machine readable manifest of this archive
        File.WriteAllText(Path.Combine(fullStage, "README.txt"), FullReadmeText(version), new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(fullStage, "BUILD.md"),
            File.Exists(build) ? File.ReadAllText(build) : BuildText(version), new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(fullStage, "RELEASE-MANIFEST.json"),
            FullManifestJson(version, sourceStage, releaseDir, fullStage), new UTF8Encoding(false));

        Console.WriteLine($"      {CountFiles(fullStage)} files, {DirSize(fullStage) / 1024 / 1024} MB");
    }

    static void CopyLicensesTo(string releaseDir, string destDir)
    {
        Directory.CreateDirectory(destDir);
        string assets = Path.Combine(releaseDir, "assets");
        if (Directory.Exists(assets))
        {
            foreach (var f in Directory.GetFiles(assets, "LICENSE*", SearchOption.AllDirectories))
            {
                string rel = Path.GetRelativePath(assets, f);
                string target = Path.Combine(destDir, rel.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.Copy(f, target, true);
            }
        }
        string rootNotices = Path.Combine(releaseDir, "THIRD-PARTY-NOTICES.txt");
        if (File.Exists(rootNotices)) File.Copy(rootNotices, Path.Combine(destDir, "THIRD-PARTY-NOTICES.txt"), true);
        string licenseNotices = Path.Combine(releaseDir, "licenses", "THIRD-PARTY-NOTICES.txt");
        if (File.Exists(licenseNotices) && !File.Exists(Path.Combine(destDir, "THIRD-PARTY-NOTICES.txt")))
            File.Copy(licenseNotices, Path.Combine(destDir, "THIRD-PARTY-NOTICES.txt"), true);
    }

    // -------------------------------------------------------------- verification

    static string ExtractZip(string distDir, PackageInfo pkg)
    {
        string zipPath = Path.Combine(distDir, pkg.ZipBase + ".zip");
        if (!File.Exists(zipPath))
            throw new StepException("ZIP smoke test", $"missing {zipPath}");

        string root = Path.Combine(Path.GetTempPath(), "TE-CMD-zip-verify");
        try
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
        catch (Exception ex)
        {
            throw new StepException("ZIP smoke test", $"cannot prepare {root}: {ex.Message}");
        }

        try { ZipFile.ExtractToDirectory(zipPath, root); }
        catch (Exception ex) { throw new StepException("ZIP smoke test", "extract failed: " + ex.Message); }

        string extracted = Path.Combine(root, pkg.RootName);
        if (!Directory.Exists(extracted))
            throw new StepException("ZIP smoke test",
                $"the archive does not contain the expected root folder '{pkg.RootName}'");
        return extracted;
    }

    /// <summary>Runs the packaged executable from the extracted archive.</summary>
    static async Task VerifyToolExtractedAsync(string appDir, string projectRoot)
    {
        string exe = Path.Combine(appDir, Product + ".exe");
        if (!File.Exists(exe))
            throw new StepException("ZIP smoke test", "the extracted archive does not contain " + Product + ".exe");

        string dataDir = Path.Combine(Path.GetDirectoryName(appDir)!, "data");
        Directory.CreateDirectory(dataDir);
        string outDir = Path.Combine(Path.GetDirectoryName(appDir)!, "out");
        string sample = Path.Combine(projectRoot, "samples", "SampleNet.dll");
        if (File.Exists(sample)) File.Copy(sample, Path.Combine(dataDir, "SampleNet.dll"), true);

        var cases = new List<(string name, string args, int expect, Func<string, bool>? check)>
        {
            ("version", "--version", 0, s => s.Contains($"{Product} v")),
            ("check", "--check", 0, s => s.Contains("✓")),
            ("help", "--help", 0, s => s.Contains("Usage:")),
        };
        if (File.Exists(sample))
            cases.Add(("decompile (.NET)", $"decompile --engine dotnet \"{Path.Combine(dataDir, "SampleNet.dll")}\" -o \"{outDir}\" -q",
                0, s => s.Contains(".cs")));

        foreach (var (name, args, expect, check) in cases)
        {
            var (exit, output) = await RunCapturedAsync(exe, args, appDir, 300_000, null);
            bool ok = exit == expect && (check == null || check(output));
            Console.WriteLine($"      {(ok ? "[ok]" : "[!!]")} zip tool: {name} (exit {exit}, expected {expect})");
            if (!ok) throw ZipCaseFailed(name, exit, expect, output);
        }
    }

    /// <summary>Source archive: clean tree, no developer paths, restore + build.</summary>
    static async Task VerifySourceExtractedAsync(string srcDir)
    {
        if (!File.Exists(Path.Combine(srcDir, "TE-CMD.csproj")))
            throw new StepException("Source build verification", "the archive does not contain TE-CMD.csproj");

        ScanForMachinePaths(srcDir, "Source build verification");

        if (!FindDotnet(out string dotnet, out string dotnetErr))
            throw new StepException("Source build verification", dotnetErr);

        var (restoreExit, restoreOut) = await RunCapturedAsync(dotnet, "restore \"TE-CMD.csproj\"", srcDir, 600_000, null);
        Console.WriteLine($"      {(restoreExit == 0 ? "[ok]" : "[!!]")} dotnet restore (exit {restoreExit})");
        if (restoreExit != 0)
            throw new StepException("Source build verification", "dotnet restore failed:\n" + Tail(restoreOut));

        var (buildExit, buildOut) = await RunCapturedAsync(dotnet, "build \"TE-CMD.csproj\" -c Release --nologo", srcDir, 900_000, null);
        foreach (var line in buildOut.Split('\n'))
        {
            var t = line.TrimEnd('\r');
            if (t.Contains(": error ") || t.Contains(": warning ")) Console.WriteLine("      " + t);
        }
        int warnings = LastCount(buildOut, "Warning(s)");
        int errors = LastCount(buildOut, "Error(s)");
        bool ok = buildExit == 0 && errors == 0 && warnings == 0 && !buildOut.Contains(": error ");
        Console.WriteLine($"      {(ok ? "[ok]" : "[!!]")} dotnet build -c Release (exit {buildExit}, {errors} errors, {warnings} warnings)");
        if (!ok)
            throw new StepException("Source build verification", $"the source package does not build (exit {buildExit}, {errors} errors, {warnings} warnings):\n" + Tail(buildOut));
    }

    /// <summary>Full archive: structure, docs, samples, licenses and a running tool.</summary>
    static async Task VerifyFullExtractedAsync(string fullDir, string projectRoot)
    {
        string[] required =
        {
            "source/TE-CMD.csproj", "source/Program.cs", "source/Cli", "source/Engines", "source/Helpers",
            "source/Assets", "source/README.md", "source/BUILD.md",
            "tool/TE-CMD.exe", "tool/TE-CMD.dll", "tool/assets", "tool/licenses/THIRD-PARTY-NOTICES.txt",
            "samples", "docs/README.md", "licenses/THIRD-PARTY-NOTICES.txt",
            "README.txt", "BUILD.md", "RELEASE-MANIFEST.json",
        };
        var missing = required.Where(rel => !File.Exists(Path.Combine(fullDir, rel.Replace('/', Path.DirectorySeparatorChar)))
                                             && !Directory.Exists(Path.Combine(fullDir, rel.Replace('/', Path.DirectorySeparatorChar)))).ToList();
        if (missing.Count > 0)
            throw new StepException("Full package verification", "full package is incomplete: " + string.Join(", ", missing));

        int samples = Directory.GetFiles(Path.Combine(fullDir, "samples"), "*", SearchOption.AllDirectories).Length;
        if (samples == 0)
            throw new StepException("Full package verification", "the full package contains no test samples");

        ScanForMachinePaths(fullDir, "Full package verification");

        // the tool inside the archive must run from its new location
        string exe = Path.Combine(fullDir, "tool", Product + ".exe");
        var (exit, output) = await RunCapturedAsync(exe, "--check", Path.Combine(fullDir, "tool"), 300_000, null);
        bool ok = exit == 0 && output.Contains("✓");
        Console.WriteLine($"      {(ok ? "[ok]" : "[!!]")} full: tool --check (exit {exit})");
        if (!ok) throw new StepException("Full package verification", "the packaged tool does not run from the full archive:\n" + Tail(output));

        Console.WriteLine($"      verified {CountFiles(fullDir)} files ({samples} sample files)");
    }

    static StepException ZipCaseFailed(string name, int exit, int expect, string output) =>
        new("ZIP smoke test", $"case '{name}' failed (exit {exit}, expected {expect})\n{Tail(output)}");

    /// <summary>Every .sha256 file must match the archive, and Get-FileHash must agree.</summary>
    static void VerifyChecksums(string distDir, List<PackageInfo> packages)
    {
        foreach (var p in packages)
        {
            string zipPath = Path.Combine(distDir, p.ZipBase + ".zip");
            string shaPath = zipPath[..^4] + ".sha256";     // <name>.zip -> <name>.sha256
            if (!File.Exists(zipPath))
                throw new StepException("SHA256 verification", $"missing {zipPath}");
            if (!File.Exists(shaPath))
                throw new StepException("SHA256 verification", $"missing {Path.GetFileName(shaPath)}");

            string actual = Sha256File(zipPath);
            string recorded = (SafeRead(shaPath).Split('\n').FirstOrDefault() ?? "").Trim();
            int sp = recorded.IndexOf(' ');
            if (sp > 0) recorded = recorded[..sp];
            if (!string.Equals(actual, recorded, StringComparison.OrdinalIgnoreCase))
                throw new StepException("SHA256 verification",
                    $"{p.ZipBase}: checksum file does not match the archive");

            if (!string.IsNullOrEmpty(p.Sha) && !string.Equals(actual, p.Sha, StringComparison.OrdinalIgnoreCase))
                throw new StepException("SHA256 verification", $"{p.ZipBase}: in memory hash differs from the archive");
            p.Sha = actual;
        }
    }

    /// <summary>Licenses of every bundled component must travel with the packages.</summary>
    static void VerifyLicenses(List<PackageInfo> packages, string projectRoot, string version)
    {
        foreach (var p in packages)
        {
            if (p.Key == "source")
            {
                // licenses live with the assets they belong to
                int n = Directory.GetFiles(p.SourceDir, "LICENSE*", SearchOption.AllDirectories).Length;
                if (n == 0)
                    throw new StepException("License check", "the source package contains no license files");
                continue;
            }

            string notices = Path.Combine(p.SourceDir, "THIRD-PARTY-NOTICES.txt");
            string nested = Path.Combine(p.SourceDir, "licenses", "THIRD-PARTY-NOTICES.txt");
            if (!File.Exists(notices) && !File.Exists(nested))
                throw new StepException("License check", $"{p.Key} package has no THIRD-PARTY-NOTICES.txt");

            string licensesDir = Path.Combine(p.SourceDir, "licenses");
            if (p.Key == "tool" && (!Directory.Exists(licensesDir) || Directory.GetFiles(licensesDir, "LICENSE*", SearchOption.AllDirectories).Length == 0))
                throw new StepException("License check", "the tool package contains no third party license files");

            if (p.Key == "full")
            {
                string fullLicenses = Path.Combine(p.SourceDir, "licenses");
                if (!Directory.Exists(fullLicenses) || Directory.GetFiles(fullLicenses, "*", SearchOption.AllDirectories).Length == 0)
                    throw new StepException("License check", "the full package licenses folder is empty");
            }
        }
    }

    /// <summary>
    /// The tool package must work from a clean directory: no development folder
    /// in sight, no usable .NET installation (empty DOTNET_ROOT), real test
    /// targets copied out of the development tree.
    /// </summary>
    static async Task VerifyAsync(string releaseDir, string projectRoot, bool full)
    {
        string verifyRoot = Path.Combine(Path.GetTempPath(), "TE-CMD-package-verify");
        try
        {
            if (Directory.Exists(verifyRoot)) Directory.Delete(verifyRoot, true);
        }
        catch (Exception ex)
        {
            throw new StepException("Clean verification", $"cannot prepare {verifyRoot}: {ex.Message}");
        }

        string appDir = Path.Combine(verifyRoot, "app");
        string dataDir = Path.Combine(verifyRoot, "testdata");
        string outDir = Path.Combine(verifyRoot, "out");
        Directory.CreateDirectory(appDir);
        Directory.CreateDirectory(dataDir);

        if (Path.GetFullPath(appDir).StartsWith(Path.GetFullPath(projectRoot), StringComparison.OrdinalIgnoreCase))
            throw new StepException("Clean verification", "verification directory must be outside the development folder");

        CopyDirectory(releaseDir, appDir);

        // test targets are copied OUT of the development folder, the package never sees it
        foreach (var sample in new[] { "sample-native.exe", "sample-script.py", "sample-pyi.exe" })
        {
            string src = Path.Combine(projectRoot, "samples", sample);
            if (File.Exists(src)) File.Copy(src, Path.Combine(dataDir, sample), true);
        }
        // .NET target: a dedicated sample assembly (the bundled ILSpy engine cannot
        // read net10 assemblies, so the packaged TE-CMD.dll itself is no test target)
        string dotnetSample = Path.Combine(projectRoot, "samples", "SampleNet.dll");
        if (!File.Exists(dotnetSample))
            throw new StepException("Clean verification", "missing test data: samples\\SampleNet.dll");
        File.Copy(dotnetSample, Path.Combine(dataDir, "SampleNet.dll"), true);

        string exe = Path.Combine(appDir, "TE-CMD.exe");
        if (!File.Exists(exe))
            throw new StepException("Clean verification", "TE-CMD.exe missing from the package");

        // prove the package does not depend on the machine's .NET installation
        string emptyDotnetRoot = Path.Combine(verifyRoot, "no-dotnet");
        Directory.CreateDirectory(emptyDotnetRoot);
        var env = new Dictionary<string, string>
        {
            ["DOTNET_ROOT"] = emptyDotnetRoot,
            ["DOTNET_MULTILEVEL_LOOKUP"] = "0",
        };

        var data = new Dictionary<string, string>
        {
            ["native"] = Path.Combine(dataDir, "sample-native.exe"),
            ["script"] = Path.Combine(dataDir, "sample-script.py"),
            ["pyinst"] = Path.Combine(dataDir, "sample-pyi.exe"),
            ["dotnet"] = Path.Combine(dataDir, "SampleNet.dll"),
        };

        var cases = new List<(string name, string args, int expect, Func<string, bool>? check)>
        {
            ("version", "--version", 0, s => s.Contains("TE-CMD v")),
            ("help", "--help", 0, s => s.Contains("Usage:")),
            ("check", "--check", 0, s => s.Contains("✓")),
            ("info", $"info \"{data["native"]}\" -o \"{outDir}\" -q", 0,
                s => File.Exists(Path.Combine(outDir, "sample-native_pe", "pe_report.txt")) || s.Contains("pe_report")),
            ("strings", $"strings \"{data["native"]}\" -o \"{outDir}\" -q", 0, s => s.Contains("strings ->")),
            ("analyze", $"analyze \"{data["native"]}\" -o \"{outDir}\" -q", 0, s => s.Contains("Status")),
            ("decompile (script)", $"decompile \"{data["script"]}\" -o \"{outDir}\" -q", 0, s => s.Contains("Status")),
            ("decompile (.NET)", $"decompile --engine dotnet \"{data["dotnet"]}\" -o \"{outDir}\" -q", 0,
                s => s.Contains(".cs")),
            ("exit code: not found", $"info \"{Path.Combine(dataDir, "does-not-exist.exe")}\" -o \"{outDir}\" -q", 3, null),
            ("exit code: unsupported", $"extract \"{data["native"]}\" -o \"{outDir}\" -q", 4, null),
            ("exit code: bad option", "--bogus", 2, null),
        };

        if (full && File.Exists(data["pyinst"]))
            cases.Insert(9, ("extract (PyInstaller)", $"extract \"{data["pyinst"]}\" -o \"{outDir}\" -q", 0,
                s => File.Exists(Path.Combine(outDir, "sample-pyi_out", "decompiled_py", "sample-script.py")) || s.Contains("Status")));

        foreach (var (name, args, expect, check) in cases)
        {
            var (exit, output) = await RunCapturedAsync(exe, args, appDir, name.StartsWith("extract") ? 900_000 : 300_000, env);
            bool ok = exit == expect && (check == null || check(output));
            Console.WriteLine($"      {(ok ? "[ok]" : "[!!]")} {name} (exit {exit}, expected {expect})");
            if (!ok)
            {
                string tail = string.Join("\n", output.Split('\n').Reverse().Take(12).Reverse()).Trim();
                throw new StepException("Clean verification",
                    $"case '{name}' failed (exit {exit}, expected {expect})\n{tail}");
            }
        }

        // the package output must not reference the development folder
        var leaks = Directory.GetFiles(verifyRoot, "*", SearchOption.AllDirectories)
            .Where(IsTextFile)
            .Select(f => Path.GetRelativePath(verifyRoot, f))
            .Where(rel => SafeRead(Path.Combine(verifyRoot, rel)).Contains("Desktop\\TE-CMD", StringComparison.OrdinalIgnoreCase))
            .Take(3)
            .ToList();
        if (leaks.Count > 0)
            throw new StepException("Clean verification",
                "development paths leaked into package output: " + string.Join(", ", leaks));

        Console.WriteLine($"      verified from {appDir}");
    }

    // ---------------------------------------------------------------------- zip

    /// <summary>
    /// Writes the archive with a single root folder (spec: every zip entry sits
    /// below one clearly named folder) plus its .sha256 file next to it.
    /// </summary>
    static (string sha, long size) CreateZipAndChecksum(string sourceDir, string distDir, string zipBase, string rootName)
    {
        if (!Directory.Exists(sourceDir))
            throw new StepException("ZIP created", $"no package found in {sourceDir}");

        Directory.CreateDirectory(distDir);
        string zipPath = Path.Combine(distDir, zipBase + ".zip");
        if (File.Exists(zipPath)) TryDeleteFile(zipPath, out _);

        try
        {
            using var fs = File.Create(zipPath);
            using var archive = new ZipArchive(fs, ZipArchiveMode.Create);
            string root = sourceDir.TrimEnd(Path.DirectorySeparatorChar);

            foreach (var dir in Directory.GetDirectories(root, "*", SearchOption.AllDirectories))
            {
                string rel = dir.Substring(root.Length).TrimStart(Path.DirectorySeparatorChar).Replace('\\', '/');
                if (rel.Length == 0) continue;
                archive.CreateEntry(rootName + "/" + rel + "/", CompressionLevel.NoCompression);
            }

            foreach (var file in Directory.GetFiles(root, "*", SearchOption.AllDirectories))
            {
                string rel = file.Substring(root.Length).TrimStart(Path.DirectorySeparatorChar).Replace('\\', '/');
                var entry = archive.CreateEntry(rootName + "/" + rel, CompressionLevel.Optimal);
                try { entry.LastWriteTime = File.GetLastWriteTime(file); } catch { }
                using var es = entry.Open();
                using var src = File.OpenRead(file);
                src.CopyTo(es);
            }
        }
        catch (Exception ex)
        {
            throw new StepException("ZIP created", "zip failed: " + ex.Message);
        }

        string sha = Sha256File(zipPath);
        long size = new FileInfo(zipPath).Length;

        // "<hash>  <name>" so 'sha256sum -c' and 'Get-FileHash' can verify it:
        // TE-CMD-v1.0.0-win-x64.zip  ->  TE-CMD-v1.0.0-win-x64.sha256
        File.WriteAllText(zipPath[..^4] + ".sha256",
            $"{sha}  {zipBase}.zip\n", new UTF8Encoding(false));

        // naming used by the single-package releases
        TryDeleteFile(Path.Combine(distDir, zipBase + ".zip.sha256"), out _);

        return (sha, size);
    }

    // archive verification: ExtractZip + VerifyToolExtractedAsync /
    // VerifySourceExtractedAsync / VerifyFullExtractedAsync

    /// <summary>
    /// Machine readable record of what was produced: one entry per archive
    /// (name, hash, size, file count), the build result and the verification
    /// report. Written only after the archives exist.
    /// </summary>
    static void WriteManifest(string distDir, List<PackageInfo> packages, string version, Dictionary<string, string> verifyReport, string projectRoot, IReadOnlyCollection<string> rebuilt)
    {
        var artifacts = new List<Dictionary<string, object?>>();
        foreach (var p in packages.Where(p => File.Exists(Path.Combine(distDir, p.ZipBase + ".zip"))))
        {
            var artifact = new Dictionary<string, object?>
            {
                ["key"] = p.Key,
                ["title"] = p.Title,
                ["zip"] = $"{p.ZipBase}.zip",
                ["checksumFile"] = $"{p.ZipBase}.sha256",
                ["sha256"] = p.Sha,
                ["zipBytes"] = p.ZipBytes,
                ["unpackedBytes"] = p.UnpackedBytes,
                ["fileCount"] = p.Files,
                ["rootFolder"] = p.RootName,
            };
            // the tool archive lists its own content so a release can be audited
            // without unpacking it
            if (p.Key == "tool" && Directory.Exists(p.SourceDir))
                artifact["files"] = Directory.GetFiles(p.SourceDir, "*", SearchOption.AllDirectories)
                    .Select(f => Path.GetRelativePath(p.SourceDir, f).Replace('\\', '/'))
                    .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                    .ToList();
            artifacts.Add(artifact);
        }

        // a run that rebuilt only one package must not erase the record of the
        // others: archives still present in dist\ keep their entry and their
        // verification rows
        var verification = verifyReport.ToDictionary(kv => kv.Key, kv => (object?)kv.Value);
        (artifacts, verification) = MergePreviousManifest(distDir, artifacts, verification, rebuilt);

        var manifest = new Dictionary<string, object?>
        {
            ["product"] = Product,
            ["version"] = version,
            ["platform"] = Platform,
            ["buildConfiguration"] = "Release",
            ["targetFramework"] = ReadTargetFramework(Path.Combine(projectRoot, "TE-CMD.csproj")),
            ["selfContained"] = true,
            ["created"] = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["executable"] = Product + ".exe",
            ["gitCommit"] = (string?)null,
            ["build"] = new Dictionary<string, object?>
            {
                ["status"] = "ok",
                ["errors"] = 0,
                ["warnings"] = 0,
                ["command"] = $"dotnet publish -c Release -r {Platform} --self-contained true",
            },
            ["verification"] = verification
                .OrderBy(kv => { int i = VerificationOrder().IndexOf(kv.Key); return i < 0 ? 99 : i; })
                .ToDictionary(kv => kv.Key, kv => kv.Value),
            ["artifacts"] = artifacts
                .OrderBy(a => { int i = PackageOrder().IndexOf(a.TryGetValue("key", out var k) ? k as string ?? "" : ""); return i < 0 ? 99 : i; })
                .ToList(),
            ["dependencies"] = Dependencies(),
        };

        var opts = new JsonSerializerOptions { WriteIndented = true };
        File.WriteAllText(Path.Combine(distDir, "release-manifest.json"),
            JsonSerializer.Serialize(manifest, opts), new UTF8Encoding(false));
    }

    static List<string> VerificationOrder() => new()
    {
        "Tool", "Source Build", "Full", "ZIP Smoke Test", "Path Leak Scan", "License Check", "Hash Verification",
    };

    static List<string> PackageOrder() => new() { "tool", "source", "full" };

    /// <summary>
    /// Carries the entries of the previous manifest over when their archive is
    /// still in dist\ but was not part of this run - and the verification rows
    /// only as long as they still describe an archive that did not change.
    /// </summary>
    static (List<Dictionary<string, object?>> artifacts, Dictionary<string, object?> verification)
        MergePreviousManifest(string distDir, List<Dictionary<string, object?>> current,
            Dictionary<string, object?> verification, IReadOnlyCollection<string> rebuilt)
    {
        var artifacts = new List<Dictionary<string, object?>>(current);
        string path = Path.Combine(distDir, "release-manifest.json");
        if (!File.Exists(path)) return (artifacts, verification);

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var root = doc.RootElement;

            var have = current.Select(a => a.TryGetValue("key", out var k) ? k as string : null)
                              .ToHashSet(StringComparer.Ordinal);

            if (root.TryGetProperty("artifacts", out var oldArtifacts) && oldArtifacts.ValueKind == JsonValueKind.Array)
            {
                var previous = JsonSerializer.Deserialize<List<Dictionary<string, object?>>>(oldArtifacts.GetRawText()) ?? new();
                foreach (var artifact in previous)
                {
                    if (!artifact.TryGetValue("key", out var k) || k is not string key || have.Contains(key)) continue;
                    string zipName = artifact.TryGetValue("zip", out var z) && z is string file ? file : key + ".zip";
                    if (!File.Exists(Path.Combine(distDir, zipName))) continue;
                    artifacts.Add(artifact);
                }
            }

            if (root.TryGetProperty("verification", out var oldVerify) && oldVerify.ValueKind == JsonValueKind.Object)
            {
                var previous = JsonSerializer.Deserialize<Dictionary<string, object?>>(oldVerify.GetRawText()) ?? new();
                foreach (var kv in previous)
                {
                    if (verification.ContainsKey(kv.Key)) continue;

                    string? owner = RowOwner(kv.Key);
                    if (owner != null)
                    {
                        // a row describing an archive that was rebuilt or removed is stale
                        if (rebuilt.Contains(owner)) continue;
                        if (!artifacts.Any(a => a.TryGetValue("key", out var k) && k as string == owner)) continue;
                    }
                    else if (rebuilt.Count > 0)
                    {
                        // rows shared by every archive lose their meaning once one changes
                        continue;
                    }

                    verification[kv.Key] = kv.Value;
                }
            }
        }
        catch
        {
            // an unreadable previous manifest must not block the new one
        }

        return (artifacts, verification);
    }

    /// <summary>The package a verification row belongs to (null = shared by all).</summary>
    static string? RowOwner(string row) => row switch
    {
        "Tool" => "tool",
        "Source Build" => "source",
        "Full" => "full",
        _ => null,
    };

    static List<string> Dependencies() => new()
    {
        "self-contained .NET runtime for win-x64 (bundled next to TE-CMD.exe)",
        "ICSharpCode.Decompiler 8.2.0.7535 / ILSpy decompiler engine (bundled)",
        "assets\\ : python helper scripts, pycdc.exe, pycdas.exe, unpacker scripts (bundled)",
        "Python 3.x on PATH (external - required by the Python/Nuitka/PYZ/PyArmor/Themida/Capstone engines)",
        "python packages zstandard, capstone, pefile, pycryptodome, cryptography, decompyle3, uncompyle6, tkinter, keyboard (external, per engine)",
        "de4dot.exe (optional, not bundled - .NET deobfuscation stays disabled)",
    };

    // ------------------------------------------------------------------ helpers

    /// <summary>
    /// Final report: step checklist, one block per package (zip, unpacked size,
    /// file count, hash) and the verification matrix. "RELEASE READY" is only
    /// printed when every step and every check passed.
    /// </summary>
    static int Finish(List<(string label, bool ok)> results, string? fail, List<PackageInfo> packages, Dictionary<string, string> verifyReport)
    {
        Console.WriteLine();
        Console.WriteLine("============================================================");
        Console.WriteLine($"             {Product} RELEASE BUILDER");
        Console.WriteLine("============================================================");
        Console.WriteLine();

        foreach (var (label, ok) in results)
            Console.WriteLine($"[{(ok ? "✓" : "✗")}] {label}");

        if (fail != null)
        {
            Console.WriteLine();
            Console.WriteLine("FAILED:");
            Console.WriteLine(fail);
            Console.WriteLine("============================================================");
            return Program.ExitFailure;
        }

        foreach (var p in packages.Where(p => p.Sha != ""))
        {
            Console.WriteLine();
            Console.WriteLine($"{p.Title,-7} {p.ZipBase}.zip");
            Console.WriteLine($"        {FormatSize(p.ZipBytes)} zip   {FormatSize(p.UnpackedBytes)} unpacked   {p.Files} files   root {p.RootName}\\");
            Console.WriteLine($"        sha256  {p.Sha}");
            if (p.ZipPath != "") Console.WriteLine($"        path    {p.ZipPath}");
        }

        if (verifyReport.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("VERIFY");
            int width = verifyReport.Keys.Max(k => k.Length) + 2;
            foreach (var key in VerificationOrder().Where(verifyReport.ContainsKey))
                Console.WriteLine($"  {key.PadRight(width)} {verifyReport[key]}");
            foreach (var kv in verifyReport.Where(kv => !VerificationOrder().Contains(kv.Key)))
                Console.WriteLine($"  {kv.Key.PadRight(width)} {kv.Value}");
        }

        Console.WriteLine();
        Console.WriteLine("============================================================");
        // no archive in this run (for example 'package --clean') - then there is
        // nothing that could be called ready
        Console.WriteLine(packages.Any(p => p.Sha != "") ? "RELEASE READY" : "DONE");
        Console.WriteLine("============================================================");
        return Program.ExitOk;
    }

    static void Say(string message) => Console.Out.WriteLine(message);

    static string? FindProjectRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "TE-CMD.csproj"))) return dir.FullName;
            dir = dir.Parent;
        }
        return null;
    }

    static string ReadTargetFramework(string csproj)
    {
        try
        {
            foreach (var line in File.ReadLines(csproj))
            {
                int s = line.IndexOf("<TargetFramework>", StringComparison.Ordinal);
                if (s < 0) continue;
                int e = line.IndexOf("</TargetFramework>", StringComparison.Ordinal);
                if (e > s) return line[(s + 17)..e].Trim();
            }
        }
        catch { }
        return "net10.0";
    }

    static bool FindDotnet(out string dotnet, out string error)
    {
        dotnet = "dotnet";
        error = "";
        try
        {
            var psi = new ProcessStartInfo("dotnet", "--version")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p == null) { error = "cannot start dotnet"; return false; }
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            if (!p.WaitForExit(20_000)) { try { p.Kill(); } catch { } error = "dotnet --version timed out"; return false; }
            if (p.ExitCode != 0) { error = "dotnet SDK not found on PATH (packaging requires the .NET SDK)"; return false; }
            return true;
        }
        catch
        {
            error = "dotnet SDK not found on PATH (packaging requires the .NET SDK)";
            return false;
        }
    }

    /// <summary>
    /// Newest compile relevant source file. Only files that actually produce
    /// TE-CMD.dll count: a touched asset or a json written by the publish itself
    /// must not make the check report a stale build.
    /// </summary>
    static DateTime NewestSourceTime(string projectRoot)
    {
        string[] skip =
        {
            $"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}",
            $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
            $"{Path.DirectorySeparatorChar}output{Path.DirectorySeparatorChar}",
            $"{Path.DirectorySeparatorChar}release{Path.DirectorySeparatorChar}",
            $"{Path.DirectorySeparatorChar}dist{Path.DirectorySeparatorChar}",
            $"{Path.DirectorySeparatorChar}.package-staging{Path.DirectorySeparatorChar}",
            $"{Path.DirectorySeparatorChar}tools{Path.DirectorySeparatorChar}",
            $"{Path.DirectorySeparatorChar}samples{Path.DirectorySeparatorChar}",
        };

        var newest = DateTime.MinValue;
        foreach (var f in Directory.GetFiles(projectRoot, "*.*", SearchOption.AllDirectories))
        {
            if (Array.Exists(skip, s => f.Contains(s, StringComparison.OrdinalIgnoreCase))) continue;
            string ext = Path.GetExtension(f);
            if (ext is not (".cs" or ".csproj" or ".props" or ".targets")) continue;
            var t = File.GetLastWriteTimeUtc(f);
            if (t > newest) newest = t;
        }
        return newest;
    }

    static async Task<(int exit, string output)> RunCapturedAsync(string exe, string args, string? workDir, int timeoutMs, IDictionary<string, string>? env)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = workDir ?? Environment.CurrentDirectory,
        };
        if (env != null)
            foreach (var kv in env) psi.Environment[kv.Key] = kv.Value;

        var sb = new StringBuilder();
        using var p = new Process { StartInfo = psi };
        p.OutputDataReceived += (_, e) => { if (e.Data != null) { lock (sb) sb.AppendLine(e.Data); } };
        p.ErrorDataReceived += (_, e) => { if (e.Data != null) { lock (sb) sb.AppendLine(e.Data); } };

        try { p.Start(); }
        catch (Exception ex) { return (-1, "cannot start " + exe + ": " + ex.Message); }

        p.BeginOutputReadLine();
        p.BeginErrorReadLine();

        if (!p.WaitForExit(timeoutMs))
        {
            try { p.Kill(true); } catch { }
            try { p.WaitForExit(10_000); } catch { }
            lock (sb) sb.AppendLine("[timeout]");
            return (-1, sb.ToString());
        }
        p.WaitForExit();
        lock (sb) return (p.ExitCode, sb.ToString());
    }

    static int LastCount(string text, string token)
    {
        int last = -1;
        int idx = 0;
        while ((idx = text.IndexOf(token, idx, StringComparison.Ordinal)) >= 0)
        {
            last = idx;
            idx += token.Length;
        }
        if (last < 0) return 0;
        int end = last;
        int start = end - 1;
        while (start >= 0 && char.IsDigit(text[start])) start--;
        if (!int.TryParse(text[(start + 1)..end], out int n)) return 0;
        return n;
    }

    static string Tail(string text, int lines = 12)
    {
        var parts = text.Replace("\r\n", "\n").Split('\n');
        return string.Join("\n", parts.Reverse().Take(lines).Reverse()).Trim();
    }

    static string ReadmeText(string version)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{Product} v{version} - DecompilerSuite CLI Edition");
        sb.AppendLine(new string('=', 60));
        sb.AppendLine();
        sb.AppendLine("Portable command line front end for the DecompilerSuite 3.0.0.0 engines.");
        sb.AppendLine("Static analysis only - the file you analyze is never executed.");
        sb.AppendLine();
        sb.AppendLine("REQUIREMENTS");
        sb.AppendLine("  Windows x64");
        sb.AppendLine("  Nothing else to install - the .NET runtime is bundled in this folder.");
        sb.AppendLine("  Python 3.x on PATH for the Python/Nuitka/PYZ/PyArmor/Themida/Capstone engines");
        sb.AppendLine("  (run 'TE-CMD.exe --check' to see what is available).");
        sb.AppendLine();
        sb.AppendLine("QUICK START");
        sb.AppendLine("  TE-CMD.exe --help");
        sb.AppendLine("  TE-CMD.exe --check");
        sb.AppendLine("  TE-CMD.exe <file>                 auto detect + decompile/analyze");
        sb.AppendLine("  TE-CMD.exe analyze <file>         static analysis only");
        sb.AppendLine("  TE-CMD.exe decompile <file>       run the engine for the detected format");
        sb.AppendLine("  TE-CMD.exe extract <file>         unpacking engine (pyinstaller/nuitka/pyz/...)");
        sb.AppendLine("  TE-CMD.exe info <file>            PE report + protection scan");
        sb.AppendLine("  TE-CMD.exe strings <file>         extract strings");
        sb.AppendLine("  TE-CMD.exe ultra <file>           Ultra Strong (all engines)");
        sb.AppendLine();
        sb.AppendLine("FOLDERS CREATED ON FIRST RUN");
        sb.AppendLine("  output\\   results (default output directory)");
        sb.AppendLine("  config\\   configuration (config.json)");
        sb.AppendLine("  licenses\\ third party licenses / notices");
        sb.AppendLine();
        sb.AppendLine("OPTIONS");
        sb.AppendLine("  -o, --output <dir>   output directory (default: output\\ next to TE-CMD.exe)");
        sb.AppendLine("  -e, --engine <name>  force an engine: auto|pyinstaller|nuitka|dotnet|cpp|pyarmor|pyz|themida");
        sb.AppendLine("  --json               machine readable report on stdout");
        sb.AppendLine("  -q / -v              quiet / verbose   --no-color   --force   --min-string <n>");
        sb.AppendLine();
        sb.AppendLine("EXIT CODES");
        sb.AppendLine("  0 success   1 analysis failure   2 bad arguments   3 target not found");
        sb.AppendLine("  4 unsupported target for that command   130 interrupted");
        sb.AppendLine();
        sb.AppendLine("This package is portable: extract it anywhere and run TE-CMD.exe.");
        return sb.ToString();
    }

    /// <summary>Guide shipped at the root of the full archive.</summary>
    static string FullReadmeText(string version)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{Product} Full Package v{version}");
        sb.AppendLine(new string('=', 60));
        sb.AppendLine();
        sb.AppendLine("Everything that belongs to the project in one archive:");
        sb.AppendLine();
        sb.AppendLine("  tool\\      portable build - extract and run tool\\TE-CMD.exe");
        sb.AppendLine("  source\\    source tree - dotnet restore && dotnet build -c Release");
        sb.AppendLine("  samples\\   test targets (native PE, Python script, PyInstaller, .NET)");
        sb.AppendLine("  docs\\      documentation (README.md, BUILD.md)");
        sb.AppendLine("  licenses\\  licenses and notices of every bundled component");
        sb.AppendLine("  README.txt          how to use the tool");
        sb.AppendLine("  BUILD.md            how to build from source");
        sb.AppendLine("  RELEASE-MANIFEST.json  machine readable content list");
        sb.AppendLine();
        sb.AppendLine("QUICK START");
        sb.AppendLine("  tool\\TE-CMD.exe --help");
        sb.AppendLine("  tool\\TE-CMD.exe --check");
        sb.AppendLine("  tool\\TE-CMD.exe analyze samples\\sample-script.py");
        sb.AppendLine();
        sb.AppendLine("BUILDING THE SOURCE");
        sb.AppendLine("  Requirements: .NET SDK 10 (see BUILD.md)");
        sb.AppendLine("  cd source");
        sb.AppendLine("  dotnet restore");
        sb.AppendLine("  dotnet build -c Release");
        sb.AppendLine();
        sb.AppendLine("Static analysis only - analyzed files are never executed.");
        return sb.ToString();
    }

    /// <summary>Fallback BUILD.md for the full archive if the root copy is missing.</summary>
    static string BuildText(string version)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Building {Product} v{version}");
        sb.AppendLine(new string('=', 60));
        sb.AppendLine();
        sb.AppendLine("REQUIREMENTS");
        sb.AppendLine("  .NET SDK 10.0 or newer (dotnet --version must work)");
        sb.AppendLine();
        sb.AppendLine("BUILD");
        sb.AppendLine("  dotnet restore TE-CMD.csproj");
        sb.AppendLine("  dotnet build TE-CMD.csproj -c Release");
        sb.AppendLine();
        sb.AppendLine("PORTABLE BUILD");
        sb.AppendLine("  dotnet publish TE-CMD.csproj -c Release -r win-x64 --self-contained true \\");
        sb.AppendLine("    -p:DebugType=None -p:DebugSymbols=false -o release");
        sb.AppendLine();
        sb.AppendLine("The packaged tool does not need the SDK on the target machine.");
        return sb.ToString();
    }

    /// <summary>Machine readable content list embedded in the full archive.</summary>
    static string FullManifestJson(string version, string sourceStage, string releaseDir, string fullStage)
    {
        var manifest = new Dictionary<string, object?>
        {
            ["product"] = Product,
            ["version"] = version,
            ["platform"] = Platform,
            ["package"] = "full",
            ["created"] = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["contents"] = new Dictionary<string, object?>
            {
                ["source"] = new Dictionary<string, object?>
                {
                    ["files"] = CountFiles(sourceStage),
                    ["bytes"] = DirSize(sourceStage),
                    ["build"] = "dotnet restore && dotnet build -c Release",
                },
                ["tool"] = new Dictionary<string, object?>
                {
                    ["files"] = CountFiles(releaseDir),
                    ["bytes"] = DirSize(releaseDir),
                    ["executable"] = Product + ".exe",
                    ["selfContained"] = true,
                },
                ["samples"] = CountFiles(Path.Combine(fullStage, "samples")),
                ["docs"] = CountFiles(Path.Combine(fullStage, "docs")),
                ["licenses"] = CountFiles(Path.Combine(fullStage, "licenses")),
                ["totalFiles"] = CountFiles(fullStage),
                ["totalBytes"] = DirSize(fullStage),
            },
            ["dependencies"] = Dependencies(),
        };

        var opts = new JsonSerializerOptions { WriteIndented = true };
        return JsonSerializer.Serialize(manifest, opts);
    }

    static string ThirdPartyNotices(string version) =>
        $"THIRD PARTY NOTICES - {Product} v{version}\n" +
        new string('=', 60) + "\n\n" +
        "This package bundles the following third party components.\n" +
        "License texts that ship with the components are copied into this folder.\n\n" +
        "1. ICSharpCode.Decompiler (ILSpy decompiler engine) 8.2.0.7535\n" +
        "   Used to decompile .NET assemblies. License: MIT (icsharpcode/ILSpy).\n\n" +
        "2. python helper scripts (pyi_extract.py, pyc_decompile.py,\n" +
        "   magic_decompile.py, cpp_capstone.py) - part of this project.\n\n" +
        "3. pycdc.exe / pycdas.exe\n" +
        "   Bytecode decompiler binaries (zrax/pycdc). Original license:\n" +
        "   https://github.com/zrax/pycdc\n\n" +
        "4. Nuitka unpacker helpers (nuitka-revenant, nuitka-static-unpacker,\n" +
        "   nuitka-themida-unpacker) - license files in this folder.\n\n" +
        "5. pyz-unpacker, pyarmor-unpacker - license files in this folder.\n\n" +
        "6. Python packages used at runtime when installed (not bundled):\n" +
        "   capstone, pefile, zstandard, pycryptodome, cryptography,\n" +
        "   decompyle3, uncompyle6, keyboard - see their upstream licenses.\n";

    static void CopyDirectory(string source, string dest)
    {
        Directory.CreateDirectory(dest);
        foreach (var dir in Directory.GetDirectories(source, "*", SearchOption.AllDirectories))
            Directory.CreateDirectory(Path.Combine(dest, Path.GetRelativePath(source, dir)));
        foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
        {
            string target = Path.Combine(dest, Path.GetRelativePath(source, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, true);
        }
    }

    static void TryDeleteDirectory(string dir, out string? error)
    {
        error = null;
        if (!Directory.Exists(dir)) return;
        for (int i = 0; i < 4; i++)
        {
            try { Directory.Delete(dir, true); if (!Directory.Exists(dir)) return; }
            catch (Exception ex) { error = ex.Message; }
            Thread.Sleep(150);
        }
        try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch (Exception ex) { error = ex.Message; }
    }

    static void TryDeleteFile(string file, out string? error)
    {
        error = null;
        try { if (File.Exists(file)) File.Delete(file); }
        catch (Exception ex) { error = ex.Message; }
    }

    static long DirSize(string dir)
    {
        try { return Directory.GetFiles(dir, "*", SearchOption.AllDirectories).Sum(f => new FileInfo(f).Length); }
        catch { return 0; }
    }

    static int CountFiles(string dir)
    {
        try { return Directory.GetFiles(dir, "*", SearchOption.AllDirectories).Length; }
        catch { return 0; }
    }

    static string Sha256File(string path)
    {
        using var fs = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
    }

    static string FormatSize(long bytes)
    {
        if (bytes >= 1_000_000_000) return $"{bytes / 1_000_000_000.0:F2} GB";
        if (bytes >= 1_000_000) return $"{bytes / 1_000_000.0:F1} MB";
        return $"{bytes / 1024.0:F1} KB";
    }

    static bool IsTextFile(string path)
    {
        var ext = Path.GetExtension(path);
        return ext is ".json" or ".txt" or ".md" or ".py" or ".log" or ".csv" or ".xml" or ".config";
    }

    static string SafeRead(string path)
    {
        try { return File.ReadAllText(path); } catch { return ""; }
    }
}
