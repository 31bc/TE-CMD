using System.Diagnostics;
using System.Reflection;
using System.Text;
using DecompilerSuite.Engines;
using DecompilerSuite.Helpers;

namespace TECmd;

static class Program
{
    public const int ExitOk = 0;
    public const int ExitFailure = 1;
    public const int ExitUsage = 2;
    public const int ExitNotFound = 3;
    public const int ExitUnsupported = 4;
    public const int ExitInterrupted = 130;

    static readonly CancellationTokenSource Interrupt = new();
    static volatile bool _interrupted;

    static async Task<int> Main(string[] args)
    {
        try { Console.OutputEncoding = new UTF8Encoding(false); } catch { }

        CliOptions opt;
        try
        {
            opt = CliOptions.Parse(args);
        }
        catch (CliUsageException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            Console.Error.WriteLine("Try 'TE-CMD.exe --help' for usage.");
            return ExitUsage;
        }

        // defaults from config\config.json (command line always wins) - before the
        // logger so config color settings take effect
        AppConfig.Load().ApplyTo(opt);

        var log = new CliLog(opt);

        // first run: create the folders the tool needs (no admin rights required)
        EnsureAppDirectories(opt);

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            if (_interrupted) return;
            _interrupted = true;
            Interrupt.Cancel();
            log.Error("interrupted (Ctrl+C) - finishing current step");
            _ = Task.Run(async () =>
            {
                await Task.Delay(5000);
                Environment.Exit(ExitInterrupted);
            });
        };

        switch (opt.Command)
        {
            case CliCommand.Help:
                CliOptions.PrintUsage(Console.Out);
                return ExitOk;
            case CliCommand.Version:
                PrintVersion();
                return ExitOk;
            case CliCommand.Check:
                return EnvCheck.Run(log);
            case CliCommand.Package:
                return await PackageBuilder.RunAsync(opt, log);
        }

        if (opt.Targets.Count == 0)
        {
            Console.Error.WriteLine("error: no target file specified");
            Console.Error.WriteLine("Try 'TE-CMD.exe --help' for usage.");
            return ExitUsage;
        }

        try
        {
            Directory.CreateDirectory(Path.GetFullPath(opt.OutputBase));
        }
        catch (Exception ex)
        {
            log.Error($"cannot create output directory '{opt.OutputBase}': {ex.Message}");
            return ExitFailure;
        }

        var session = new Session(opt, log);
        int result = ExitOk;

        for (int i = 0; i < opt.Targets.Count; i++)
        {
            if (_interrupted)
            {
                result = ExitInterrupted;
                break;
            }
            if (opt.Targets.Count > 1)
                log.Info($"--- [{i + 1}/{opt.Targets.Count}] {opt.Targets[i]} ---");

            int rc = await RunTargetAsync(opt.Targets[i], session);
            if (rc == ExitInterrupted)
            {
                result = ExitInterrupted;
                break;
            }
            if (rc != ExitOk && result == ExitOk) result = rc;
        }

        if (opt.Json && session.Json.Count > 0)
            Reports.WriteJson(session.Json.Count == 1 ? (object)session.Json[0] : session.Json);

        return result;
    }

    /// <summary>
    /// Folders the tool needs, created on first run next to the executable.
    /// Only output\ and config\ are needed - no cache/log/temp folders are
    /// created because nothing writes them.
    /// </summary>
    static void EnsureAppDirectories(CliOptions opt)
    {
        try { Directory.CreateDirectory(Path.GetFullPath(opt.OutputBase)); } catch { }
        try
        {
            string cfgDir = Path.Combine(AppContext.BaseDirectory, "config");
            string cfgFile = Path.Combine(cfgDir, "config.json");
            if (!File.Exists(cfgFile))
            {
                Directory.CreateDirectory(cfgDir);
                File.WriteAllText(cfgFile, AppConfig.DefaultJson());
            }
        }
        catch { }
    }

    static void PrintVersion()
    {
        Console.Out.WriteLine(AppInfo.Description);
        Console.Out.WriteLine($"Engine: DecompilerSuite {AppInfo.EngineVersion}");
    }

    static async Task<int> RunTargetAsync(string target, Session session)
    {
        var opt = session.Opt;
        var log = session.Log;
        var sw = Stopwatch.StartNew();

        string path;
        try { path = Path.GetFullPath(target); }
        catch { path = target; }

        if (!File.Exists(path))
        {
            log.Error($"target not found: {path}");
            sw.Stop();
            AddJson(session, path, PackerType.Unknown, Array.Empty<string>(), null, null, "failed", ExitNotFound, sw.Elapsed.TotalSeconds);
            return ExitNotFound;
        }

        PackerType detected;
        List<string> detectedAll;
        try
        {
            detected = Detector.Detect(path);
            detectedAll = Detector.DetectAll(path);
        }
        catch (Exception ex)
        {
            log.Error($"detection failed: {ex.Message}");
            sw.Stop();
            AddJson(session, path, PackerType.Unknown, Array.Empty<string>(), null, null, "failed", ExitFailure, sw.Elapsed.TotalSeconds);
            return ExitFailure;
        }

        log.Info($"Detected: {Detector.Describe(detected)}");
        log.Verbose($"Detection: {string.Join(", ", detectedAll)}");

        PackerType mode = EngineRouter.ResolveMode(opt.EngineId, detected);
        log.Verbose($"Engine mode: {Detector.Describe(mode)}");

        if (opt.Command == CliCommand.Extract && !EngineRouter.IsExtractEngine(mode))
        {
            log.Error($"'extract' does not support {Detector.Describe(detected)} - use 'decompile' or 'analyze'");
            sw.Stop();
            AddJson(session, path, detected, detectedAll, null, null, "unsupported", ExitUnsupported, sw.Elapsed.TotalSeconds);
            return ExitUnsupported;
        }

        string outDir = OutputDirFor(opt.Command, path, opt.OutputBase);
        if (opt.Force && Directory.Exists(outDir))
        {
            log.Verbose($"--force: removing {outDir}");
            try { Directory.Delete(outDir, true); }
            catch (Exception ex)
            {
                log.Error($"cannot clear output directory '{outDir}': {ex.Message}");
                return ExitFailure;
            }
        }

        string? engineId = EngineRouter.IdOf(mode);
        string status = "ok";
        int rc = ExitOk;
        string? direct = null;

        try
        {
            switch (opt.Command)
            {
                case CliCommand.Info:
                {
                    engineId = null;
                    string report = BuildInfoReport(path);
                    Directory.CreateDirectory(outDir);
                    string reportPath = Path.Combine(outDir, "pe_report.txt");
                    await File.WriteAllTextAsync(reportPath, report, Encoding.UTF8);
                    direct = report.TrimEnd() + Environment.NewLine + Environment.NewLine + $"Report: {reportPath}";
                    break;
                }
                case CliCommand.Strings:
                {
                    engineId = null;
                    var strings = PeHelper.ExtractStrings(path, opt.MinString);
                    Directory.CreateDirectory(outDir);
                    string stringsPath = Path.Combine(outDir, "strings.txt");
                    await File.WriteAllLinesAsync(stringsPath, strings, Encoding.UTF8);
                    direct = $"{strings.Count} strings -> {stringsPath}";
                    break;
                }
                case CliCommand.Analyze:
                    engineId = "cpp";
                    await CppEngine.AnalyzeAsync(path, outDir, log.ForEngine);
                    break;
                case CliCommand.Ultra:
                    engineId = "ultra";
                    await UltraEngine.ExtractUltraAsync(path, outDir, log.ForEngine);
                    break;
                default:
                {
                    PackerType used = await EngineRouter.RunAsync(mode, path, outDir, detected, log);
                    engineId = EngineRouter.IdOf(used);
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            log.Error(Reports.FriendlyError(ex));
            status = "failed";
            rc = ExitFailure;
        }

        sw.Stop();
        if (_interrupted && rc == ExitOk) rc = ExitInterrupted;

        if (opt.Command == CliCommand.Info)
        {
            log.Result(direct ?? "");
        }
        else if (opt.Command == CliCommand.Strings)
        {
            log.Result(direct ?? "");
        }
        else if (rc != ExitInterrupted)
        {
            var (files, bytes, py, cs) = Reports.OutputStats(outDir);
            var fi = new FileInfo(path);
            log.Result($"Target  : {path} ({fi.Length / 1024.0:F1} KB)");
            log.Result($"Format  : {Detector.Describe(detected)}");
            log.Result($"Engine  : {EngineLabel(opt.Command, engineId)}");
            log.Result($"Output  : {Path.GetFullPath(outDir)}");
            log.Result($"Files   : {files} ({bytes / 1024.0:F1} KB)");
            if (py + cs > 0) log.Result($"Source  : {cs} .cs, {py} .py");
            log.Result($"Duration: {sw.Elapsed.TotalSeconds:F1}s");
            log.Result($"Status  : {status}");
            if (files > 0)
            {
                log.Result("");
                log.Result(Reports.CollectAnalysis(outDir, EngineLabel(opt.Command, engineId)).TrimEnd());
            }
        }

        AddJson(session, path, detected, detectedAll, engineId, outDir, status, rc, sw.Elapsed.TotalSeconds);
        return rc;
    }

    static string OutputDirFor(CliCommand command, string path, string outputBase)
    {
        string name = Path.GetFileNameWithoutExtension(path);
        return command switch
        {
            CliCommand.Ultra => Path.Combine(outputBase, name + "_ultra_out"),
            CliCommand.Strings => Path.Combine(outputBase, name + "_strings"),
            CliCommand.Info => Path.Combine(outputBase, name + "_pe"),
            _ => Path.Combine(outputBase, name + "_out"),
        };
    }

    static string BuildInfoReport(string path)
    {
        var sb = new StringBuilder();
        sb.AppendLine(PeHelper.GetPeInfo(path));
        sb.AppendLine(PeHelper.DetectProtection(path));
        sb.AppendLine(PeHelper.GetSectionsInfo(path));
        return sb.ToString();
    }

    static string EngineLabel(CliCommand command, string? engineId)
    {
        if (command == CliCommand.Analyze) return "static analysis (C/C++ analyzer)";
        if (command == CliCommand.Ultra) return "Ultra Strong (all engines)";
        if (engineId == null) return "none";
        return Detector.Describe(EngineRouter.FromId(engineId));
    }

    static void AddJson(Session session, string path, PackerType detected, IReadOnlyList<string> detectedAll,
        string? engineId, string? outDir, string status, int exitCode, double seconds)
    {
        if (!session.Opt.Json) return;
        session.Json.Add(Reports.BuildJson(
            Reports.CommandName(session.Opt.Command), path, detected, detectedAll,
            engineId, outDir, status, exitCode, seconds));
    }
}

sealed class Session
{
    public readonly CliOptions Opt;
    public readonly CliLog Log;
    public readonly List<Dictionary<string, object?>> Json = new();

    public Session(CliOptions opt, CliLog log)
    {
        Opt = opt;
        Log = log;
    }
}
