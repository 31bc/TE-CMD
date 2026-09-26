namespace TECmd;

/// <summary>
/// Terminal logger. Engine progress lines are written to stderr with the same
/// [HH:mm:ss] prefix the GUI log box uses, results go to stdout.
/// </summary>
sealed class CliLog
{
    readonly CliOptions _opt;
    readonly bool _color;

    public CliLog(CliOptions opt)
    {
        _opt = opt;
        _color = !opt.NoColor && !Console.IsErrorRedirected;
    }

    /// <summary>Callback used by the DecompilerSuite engines (Action&lt;string&gt; log).</summary>
    public Action<string> ForEngine => Info;

    public void Info(string message)
    {
        if (_opt.Quiet) return;
        Write(true, message, null);
    }

    public void Verbose(string message)
    {
        if (_opt.Quiet || !_opt.Verbose) return;
        Write(true, message, null);
    }

    public void Warn(string message)
    {
        if (_opt.Quiet) return;
        Write(true, "warning: " + message, "33");
    }

    public void Error(string message)
    {
        Write(true, "error: " + message, "31");
    }

    /// <summary>Command result - stdout, suppressed when --json owns stdout.</summary>
    public void Result(string message)
    {
        if (_opt.Json) return;
        Console.Out.WriteLine(message);
    }

    void Write(bool line, string message, string? ansi)
    {
        var writer = Console.Error;
        string stamp = $"[{DateTime.Now:HH:mm:ss}] ";
        if (_color)
        {
            writer.Write($"\x1b[90m{stamp}\x1b[0m");
            if (ansi != null) writer.Write($"\x1b[{ansi}m{message}\x1b[0m");
            else writer.Write(message);
        }
        else
        {
            writer.Write(stamp);
            writer.Write(message);
        }
        if (line) writer.WriteLine();
    }
}
