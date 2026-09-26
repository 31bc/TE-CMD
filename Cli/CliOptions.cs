namespace TECmd;

enum CliCommand
{
    Auto,
    Analyze,
    Decompile,
    Info,
    Strings,
    Extract,
    Ultra,
    Check,
    Help,
    Version,
    Package,
}

sealed class CliUsageException : Exception
{
    public CliUsageException(string message) : base(message) { }
}

sealed class CliOptions
{
    public CliCommand Command = CliCommand.Auto;
    public readonly List<string> Targets = new();
    public string OutputBase = "output";
    public string? EngineId;              // null = auto detect (GUI "Auto" radio button)
    public bool Json;
    public bool Quiet;
    public bool Verbose;
    public bool NoColor;
    public bool Force;
    public int MinString = 5;             // GUI passes 5 to PeHelper.ExtractStrings
    public bool OutputGiven;               // -o was used (meaning differs for 'package')
    public bool MinStringGiven;
    public bool PackageClean;              // 'package --clean'
    public bool PackageVerify;             // 'package --verify'
    public bool PackageZip;                // 'package --zip'
    public bool PackageTool;               // 'package --tool'   (selection)
    public bool PackageSource;             // 'package --source' (selection)
    public bool PackageFull;               // 'package --full'   (selection)

    /// <summary>Any 'package' flag was used.</summary>
    public bool AnyPackageFlag =>
        PackageClean || PackageVerify || PackageZip || PackageTool || PackageSource || PackageFull;


    public static CliOptions Parse(string[] args)
    {
        var o = new CliOptions();
        bool commandSeen = false;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            if (a.Length == 0) continue;

            if (a[0] == '-')
            {
                string name = a;
                string? inline = null;
                int eq = a.IndexOf('=');
                if (a.StartsWith("--", StringComparison.Ordinal) && eq > 2)
                {
                    name = a[..eq];
                    inline = a[(eq + 1)..];
                }

                string Next(string opt)
                {
                    if (inline != null) return inline;
                    if (i + 1 >= args.Length) throw new CliUsageException($"option '{opt}' requires a value");
                    return args[++i];
                }

                switch (name)
                {
                    case "-h":
                    case "--help":
                        o.Command = CliCommand.Help;
                        return o;
                    case "--version":
                        o.Command = CliCommand.Version;
                        return o;
                    case "--check":
                        o.Command = CliCommand.Check;
                        return o;
                    case "-o":
                    case "--output":
                        o.OutputBase = Next(name);
                        o.OutputGiven = true;
                        break;
                    case "--clean":
                        o.PackageClean = true;
                        break;
                    case "--verify":
                        o.PackageVerify = true;
                        break;
                    case "--zip":
                        o.PackageZip = true;
                        break;
                    case "--tool":
                        o.PackageTool = true;
                        break;
                    case "--source":
                        o.PackageSource = true;
                        break;
                    case "--full":
                        o.PackageFull = true;
                        break;
                    case "-e":
                    case "--engine":
                        o.EngineId = NormalizeEngine(Next(name));
                        break;
                    case "--json":
                        o.Json = true;
                        break;
                    case "-q":
                    case "--quiet":
                        o.Quiet = true;
                        break;
                    case "-v":
                    case "--verbose":
                        o.Verbose = true;
                        o.Quiet = false;
                        break;
                    case "--no-color":
                        o.NoColor = true;
                        break;
                    case "--force":
                        o.Force = true;
                        break;
                    case "--min-string":
                        string raw = Next(name);
                        if (!int.TryParse(raw, out int n) || n < 1)
                            throw new CliUsageException($"invalid value for --min-string: '{raw}'");
                        o.MinString = n;
                        o.MinStringGiven = true;
                        break;
                    default:
                        throw new CliUsageException($"unknown option '{name}'");
                }
                continue;
            }

            if (!commandSeen && TryCommand(a, out var cmd))
            {
                o.Command = cmd;
                commandSeen = true;
            }
            else if (commandSeen && TryCommand(a, out _))
            {
                throw new CliUsageException($"unexpected command '{a}' (a command may only appear once)");
            }
            else
            {
                o.Targets.Add(a);
            }
        }

        if (o.AnyPackageFlag && o.Command != CliCommand.Package)
            throw new CliUsageException(
                "'--clean', '--verify', '--zip', '--tool', '--source' and '--full' are only valid with the 'package' command");

        if (o.Command == CliCommand.Package && o.Targets.Count > 0)
            throw new CliUsageException($"'package' does not take a target file (got '{o.Targets[0]}')");

        if (o.Command == CliCommand.Auto && o.Targets.Count > 0
            && !File.Exists(o.Targets[0]) && !LooksLikePath(o.Targets[0]))
            throw new CliUsageException($"unknown command '{o.Targets[0]}'");

        if (o.Command == CliCommand.Auto && o.Targets.Count == 0)
            throw new CliUsageException("no target file specified");

        if (o.Quiet && o.Verbose) o.Quiet = false;
        return o;
    }

    static bool LooksLikePath(string value) =>
        value.Contains('\\') || value.Contains('/') || value.Contains('.');

    static bool TryCommand(string value, out CliCommand command)
    {
        switch (value.ToLowerInvariant())
        {
            case "analyze": command = CliCommand.Analyze; return true;
            case "decompile": command = CliCommand.Decompile; return true;
            case "info": command = CliCommand.Info; return true;
            case "strings": command = CliCommand.Strings; return true;
            case "extract": command = CliCommand.Extract; return true;
            case "ultra": command = CliCommand.Ultra; return true;
            case "check": command = CliCommand.Check; return true;
            case "help": command = CliCommand.Help; return true;
            case "version": command = CliCommand.Version; return true;
            case "package": command = CliCommand.Package; return true;
            default: command = default; return false;
        }
    }

    static string NormalizeEngine(string value)
    {
        switch (value.Trim().ToLowerInvariant())
        {
            case "auto": return "auto";
            case "pyinstaller": case "pyinst": case "py": return "pyinstaller";
            case "nuitka": return "nuitka";
            case "dotnet": case "net": case "csharp": case "cs": return "dotnet";
            case "cpp": case "c": case "native": case "c++": return "cpp";
            case "pyarmor": return "pyarmor";
            case "pyz": return "pyz";
            case "themida": return "themida";
            default:
                throw new CliUsageException(
                    $"unknown engine '{value}' (expected: auto, pyinstaller, nuitka, dotnet, cpp, pyarmor, pyz, themida)");
        }
    }

    public static void PrintUsage(TextWriter w)
    {
        w.WriteLine($"{AppInfo.Description}");
        w.WriteLine();
        w.WriteLine("Usage:");
        w.WriteLine("  TE-CMD.exe <file> [options]                 auto-detect + run the matching engine");
        w.WriteLine("  TE-CMD.exe <command> <file...> [options]");
        w.WriteLine();
        w.WriteLine("Commands:");
        w.WriteLine("  (none)       same as 'decompile' with automatic engine selection");
        w.WriteLine("  analyze      static analysis only: PE report, sections, strings, imports,");
        w.WriteLine("               hex dump, compiler, protection, yara, entropy, anti-debug");
        w.WriteLine("  decompile    run the DecompilerSuite engine for the detected format");
        w.WriteLine("  extract      run an unpacking engine (pyinstaller, nuitka, pyz, pyarmor, themida)");
        w.WriteLine("  info         detection, PE info, protection scan -> <name>_pe\\pe_report.txt");
        w.WriteLine("  strings      extract strings -> <name>_strings\\strings.txt");
        w.WriteLine("  ultra        Ultra Strong: try every engine + decryption layers");
        w.WriteLine("  check        report the dependencies used by the engines");
        w.WriteLine("  package      build the release packages (tool / source / full):");
        w.WriteLine("               publish, collect, normalize, ZIP, SHA256, verify");
        w.WriteLine("  help         show this help");
        w.WriteLine("  version      show version");
        w.WriteLine();
        w.WriteLine("Options:");
        w.WriteLine("  -o, --output <dir>     output base directory (default: .\\output)");
        w.WriteLine("  -e, --engine <name>    force an engine instead of auto detection:");
        w.WriteLine("                         auto | pyinstaller | nuitka | dotnet | cpp |");
        w.WriteLine("                         pyarmor | pyz | themida");
        w.WriteLine("  --json                 print a machine readable JSON report on stdout");
        w.WriteLine("  -q, --quiet            only errors and the final summary");
        w.WriteLine("  -v, --verbose          detailed engine/tool output");
        w.WriteLine("  --no-color             disable ANSI colors");
        w.WriteLine("  --force                delete the target output directory before running");
        w.WriteLine("  --min-string <n>       minimum length for 'strings' (default: 5)");
        w.WriteLine("  --check                report engine dependencies");
        w.WriteLine("  --version              show version");
        w.WriteLine("  -h, --help             show this help");
        w.WriteLine();
        w.WriteLine("Packaging (only with 'package'):");
        w.WriteLine("  --tool                 only the tool package (end user runtime)");
        w.WriteLine("  --source               only the source package (buildable project)");
        w.WriteLine("  --full                 only the full archive (source + tool + samples)");
        w.WriteLine("  --clean                only remove release\\, stage\\, dist\\ and build artifacts");
        w.WriteLine("  --verify               only verify packages that already exist");
        w.WriteLine("  --zip                  only create the ZIP + checksum files");
        w.WriteLine("  -o, --output <dir>     where release\\, stage\\ and dist\\ are created");
        w.WriteLine("                         (default: the TE-CMD source folder)");
        w.WriteLine("  without any of these flags 'package' builds, zips and verifies all");
        w.WriteLine("  three packages. Flags combine: TE-CMD.exe package --tool --zip --verify");
        w.WriteLine();
        w.WriteLine("Release artifacts (dist\\):");
        w.WriteLine("  TE-CMD-v<version>-win-x64.zip    portable runtime for the end user");
        w.WriteLine("  TE-CMD-v<version>-source.zip     buildable source tree");
        w.WriteLine("  TE-CMD-v<version>-full.zip       source + tool + samples + docs");
        w.WriteLine("  each with a .sha256 file and one release-manifest.json");
        w.WriteLine();
        w.WriteLine("Output layout (same model as the DecompilerSuite GUI):");
        w.WriteLine("  <output>\\<name>_out          engine output (decompile / extract / analyze)");
        w.WriteLine("  <output>\\<name>_ultra_out    Ultra Strong output");
        w.WriteLine("  <output>\\<name>_strings      strings output");
        w.WriteLine("  <output>\\<name>_pe           PE / protection report");
        w.WriteLine();
        w.WriteLine("Exit codes:");
        w.WriteLine("  0  success            1  analysis or dependency failure");
        w.WriteLine("  2  bad command/args   3  target not found");
        w.WriteLine("  4  unsupported target for that command   130  interrupted (Ctrl+C)");
        w.WriteLine();
        w.WriteLine("Examples:");
        w.WriteLine("  TE-CMD.exe app.exe");
        w.WriteLine("  TE-CMD.exe decompile app.exe -o D:\\out -v");
        w.WriteLine("  TE-CMD.exe extract app.exe --engine pyinstaller");
        w.WriteLine("  TE-CMD.exe analyze app.exe --json > report.json");
        w.WriteLine("  TE-CMD.exe info app.dll");
        w.WriteLine("  TE-CMD.exe check");
        w.WriteLine("  TE-CMD.exe package                    build + verify all release packages");
        w.WriteLine("  TE-CMD.exe package --tool --verify    only the tool package, verified");
    }
}
