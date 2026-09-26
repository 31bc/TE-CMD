# TE-CMD

Portable Windows command line front end for the DecompilerSuite 3.0.0.0 analysis
engines: format detection, static PE analysis, .NET decompilation and unpacking
of Python packed programs - all from a single self-contained executable.

Version 1.0.0 - Windows x64 - static analysis only (the analyzed file is never
executed).

## Overview

DecompilerSuite 3.0.0.0 ships as a WPF GUI. TE-CMD is the same product as a
command line tool: the detection code, the helper code and all engines are the
DecompilerSuite sources, copied verbatim, and only the front end (window,
dialogs, license screen, progress bar) was replaced by a CLI.

That makes the tool scriptable and automatable:

- batch runs over many files, exit codes that mean something,
- `--json` reports for pipelines,
- no GUI, no installation, no registry, no administrator rights,
- a portable release that carries its own .NET runtime.

Typical use: triage an unknown executable, see what protects it, recover source
from a packed or frozen Python program, decompile a .NET assembly, or produce a
machine readable report for a pipeline.

## Features

- **Automatic format detection** - content based heuristics (not file
  extensions): .NET metadata, PyInstaller magic, Nuitka one-file markers,
  PyArmor, Themida/WinLicense, PYZ archives, plain PE.
- **Protection indicators** - PyInstaller, Nuitka, Nuitka OneFile, PyArmor,
  Themida/WinLicense, UPX, VMProtect, Enigma, .NET.
- **Static analysis of native PE files** - report, sections, strings, imports,
  hex dump, compiler fingerprint, protection scan, YARA style pattern scan,
  entropy, anti-debug indicators, optional Capstone disassembly.
- **PE information and protection scan** - `info` command.
- **.NET decompilation** - ILSpy engine (`ICSharpCode.Decompiler`), per type
  source files, optional de4dot deobfuscation when de4dot is installed.
- **PyInstaller extraction** - archive unpacking plus bytecode decompilation of
  the embedded PYZ modules (`pycdc`/`pycdas`).
- **Nuitka extraction** - one-file payload extraction (zstandard) followed by
  static source recovery (Revenant engine).
- **PYZ archive extraction**, **PyArmor extraction**, **Themida/WinLicense
  extraction helpers**.
- **Strings extraction** with a configurable minimum length.
- **Ultra Strong** - every engine in sequence plus a brute force pass over
  embedded crypto keys.
- **Batch processing** - several targets per command line.
- **JSON output** - `--json` prints one structured report on stdout.
- **Dependency check** - `check` reports every runtime dependency and its state.
- **Release packaging** - `package` builds and verifies the three release
  archives (tool / source / full) with SHA256 checksums and a manifest.

## Supported File Types

Detected by content (see `Helpers\Detector.cs`):

| Detected format | Detection basis | Engine used |
|---|---|---|
| C/C++ native PE (x86/x64) | any PE file as fallback | `CppEngine` static analysis |
| .NET assembly (`exe`/`dll`) | CLR header in the PE optional header | `DotNetEngine` (ILSpy) |
| PyInstaller executable/archive | `MEI\x0C\x0B\x0A\x0B\x0E` magic, `pyi-` strings | `PyInstallerEngine` |
| Nuitka / Nuitka OneFile | `Nuitka`, `compiled by Nuitka`, onefile markers | `NuitkaEngine` + `RevenantEngine` |
| PyArmor obfuscated | `pyarmor`, `pytransform` | `PyArmorEngine` |
| Themida / WinLicense | `Themida`, `WinLicense`, `Oreans` | `ThemidaEngine` |
| PYZ archive | `PYZ` + `pyz` markers | `PyzEngine` |
| Anything else | no match | falls back to the generic analyzer, or `exit 4` for commands that need a specific format |

Protection indicators reported alongside detection: UPX, VMProtect, Enigma.

Plain text/scripts that are not PE files are handled by the generic analyzer
and produce a report - TE-CMD does not decompile `.py` source files.

## Engines

Nine engine classes, all invoked through the same
`Action<string> log` hook:

| Engine | What it does | External requirements |
|---|---|---|
| `CppEngine` | native PE static analysis ("C++ Killer"): `pe_report.txt`, `sections.txt`, `strings.txt`, `imports.txt`, `hexdump.txt`, `compiler.txt`, `protection.txt`, `yara.txt`, `entropy.txt`, `anti.txt`, `capstone.asm` | Python + `capstone` (optional, for disassembly) |
| `DotNetEngine` | .NET decompilation through ILSpy, optional deobfuscation | bundled ILSpy; `Assets\de4dot\de4dot.exe` optional |
| `PyInstallerEngine` | PyInstaller unpack, PYZ extraction, bytecode decompilation | Python, `pycdc.exe`/`pycdas.exe`, `zstandard` |
| `NuitkaEngine` | Nuitka one-file extraction, payload recovery | Python, `zstandard` |
| `RevenantEngine` | static Nuitka source recovery, called by `NuitkaEngine` | Python |
| `PyzEngine` | PYZ archive extraction and decompilation | Python |
| `PyArmorEngine` | PyArmor unpacking | Python |
| `ThemidaEngine` | Themida/WinLicense extraction helpers | Python |
| `UltraEngine` | runs every engine in sequence, then brute forces embedded keys | everything above |

Engines are selected automatically from the detection result; `-e/--engine`
forces a specific one, and the GUI's auto correction (a wrong engine falls back
to the detected format) is preserved.

## CLI Usage

```
TE-CMD.exe <file> [options]          auto-detect and run the matching engine
TE-CMD.exe <command> <file...> [options]

Commands:
  (none)       same as 'decompile' with automatic engine selection
  analyze      static analysis only: PE report, sections, strings, imports,
               hex dump, compiler, protection, yara, entropy, anti-debug
  decompile    run the DecompilerSuite engine for the detected format
  extract      unpacking engine (pyinstaller, nuitka, pyz, pyarmor, themida)
  info         detection, PE info, protection scan -> <name>_pe\pe_report.txt
  strings      extract strings -> <name>_strings\strings.txt
  ultra        Ultra Strong: every engine + decryption layers
  check        report the dependencies used by the engines
  package      build the release packages (tool / source / full)
  help         show help
  version      show version
```

## Options

| Option | Meaning |
|---|---|
| `-o, --output <dir>` | output base directory (default: `.\output`) |
| `-e, --engine <name>` | force an engine: `auto`, `pyinstaller`, `nuitka`, `dotnet`, `cpp`, `pyarmor`, `pyz`, `themida` |
| `--json` | machine readable JSON report on stdout |
| `-q, --quiet` | only errors and the final summary |
| `-v, --verbose` | detailed engine/tool output |
| `--no-color` | disable ANSI colors |
| `--force` | delete the target output directory before running |
| `--min-string <n>` | minimum length for `strings` (default 5) |
| `--check` | report engine dependencies |
| `--version` | show version |
| `-h, --help` | show help |

Packaging flags (only with `package`): `--tool`, `--source`, `--full`,
`--clean`, `--verify`, `--zip`, plus `-o/--output` to place `release\`,
`stage\` and `dist\` somewhere else.

Exit codes: `0` success, `1` analysis/dependency failure, `2` bad arguments,
`3` target not found, `4` unsupported target for that command, `130`
interrupted.

## Examples

```
TE-CMD.exe --check
TE-CMD.exe info sample.exe
TE-CMD.exe analyze sample.exe
TE-CMD.exe decompile sample.exe
TE-CMD.exe decompile assembly.dll -e dotnet -o out
TE-CMD.exe extract sample-pyi.exe --engine pyinstaller
TE-CMD.exe strings sample.exe --min-string 8
TE-CMD.exe ultra sample.exe -v
TE-CMD.exe analyze sample.exe --json > report.json
TE-CMD.exe decompile a.exe b.dll c.exe -o out        (batch)
TE-CMD.exe package                                   (build + verify releases)
```

Test targets live in `samples\`: `sample-native.exe`, `sample-script.py`,
`sample-pyi.exe`, `SampleNet.dll`.

## Output

Same model as the DecompilerSuite GUI, written under the output base
(`-o`, default `.\output`):

| Directory | Written by |
|---|---|
| `<output>\<name>_out` | `decompile` / `extract` / `analyze` |
| `<output>\<name>_ultra_out` | `ultra` |
| `<output>\<name>_strings\strings.txt` | `strings` |
| `<output>\<name>_pe\pe_report.txt` | `info` |

Inside an engine output folder the analysis reports are `pe_report.txt`,
`sections.txt`, `strings.txt`, `imports.txt`, `hexdump.txt`, `compiler.txt`,
`protection.txt`, `yara.txt`, `entropy.txt`, `anti.txt` and - when Python and
Capstone are available - `capstone.asm`.

`config\config.json` next to the executable supplies defaults (`output`,
`minString`, `color`); the command line always wins. It is created on first
run together with the output folder - nothing else is written (no cache, no
logs, no temp folders).

## Installation

1. Download `TE-CMD-v1.0.0-win-x64.zip` from the
   [Releases page](https://github.com/31bc/TE-CMD/releases/tag/v1.0.0).
2. Extract it anywhere.
3. Run `TE-CMD.exe --check` to see which optional components are available.

The release is self-contained: the .NET 10 runtime for win-x64 is bundled, no
runtime installation is required. `TE-CMD.exe package` from the source tree
produces the same archives.

## Requirements

**Bundled in the release (nothing to install):**

- self-contained .NET 10 runtime for win-x64
- ILSpy decompiler engine (`ICSharpCode.Decompiler` 8.2.0.7535)
- `assets\`: python helper scripts, `pycdc.exe`, `pycdas.exe`, unpacker scripts
- `config\config.json`, `licenses\`, `THIRD-PARTY-NOTICES.txt`, `README.txt`

**External (needed only for the engines that use them):**

| Component | Used by | State |
|---|---|---|
| Python 3.x on `PATH` | PyInstaller, Nuitka, PYZ, PyArmor, Themida, Capstone | optional - those engines skip with a log line when missing |
| pip: `zstandard`, `capstone`, `pefile`, `pycryptodome`, `cryptography`, `decompyle3`, `uncompyle6`, `tkinter`, `keyboard` | the individual scripts | optional, per engine |
| `Assets\de4dot\de4dot.exe` | .NET deobfuscation | optional - not bundled, step disabled when absent |

`TE-CMD.exe check` prints the state of every one of these.

## Architecture

```
Program.cs          entry point, dispatch, exit codes, config apply, first run
Cli\                options/parsing, logging, JSON reports, engine routing,
                    dependency check, release packaging
Engines\            the DecompilerSuite engines (copied verbatim)
Helpers\            Detector (format detection) + PeHelper (PE helpers)
Assets\             scripts and helper binaries started by the engines
config\config.json  defaults for output folder, min string length, color
samples\            test targets used by the verification run
```

Data flow: argument parsing -> `Detector.Detect` -> `EngineRouter` (engine
selection + GUI style auto correction) -> engine -> files and reports under
`<output>\<name>_...` -> summary on stdout (`--json` for the structured form).

Engines receive only a log callback; they never touch the console directly, so
the same code is usable from any front end.

## Security

- Static analysis only: the target file is never run as a program by TE-CMD.
- External helpers are started from fixed `assets\` scripts with the target
  passed as data input, never as the program to execute.
- TE-CMD's own code makes no network calls: there is no license check, no
  activation, no telemetry.
- Writes only to the output folder and to `config\`/`licenses\` next to the
  executable.
- The release is scanned for developer paths, debug symbols and temporary
  files before it is published (`package` fails the build if it finds any).

## Limitations

- Windows x64 only.
- The bundled ILSpy engine (`ICSharpCode.Decompiler` 8.2.0) reads assemblies up
  to .NET 8. Assemblies compiled for .NET 10 - including `TE-CMD.dll` itself -
  fail with `Argument must be between 0 and 2. (Parameter 'fieldCount')` and
  exit code 1. That is the engine as DecompilerSuite ships it; the verification
  uses `samples\SampleNet.dll` (netstandard2.0) as the .NET target.
- Python based engines need Python and their pip modules; missing optional
  components disable that engine instead of failing the run.
- de4dot is not bundled: without it the .NET deobfuscation steps are skipped.
- `decompile`/`extract` exit with 0 even when an engine could not unpack the
  file - the log explains why. This matches the GUI, which also reports
  success and shows the log.
- No disassembler/debugger for arbitrary binaries: Ghidra, IDA and Rizin are
  not used by TE-CMD (some engine log lines merely suggest them as a next
  step). `capstone.asm` comes from a small Capstone helper script.
- Detection quirks come from the original `Detector` and are kept identical to
  the GUI. Example: a .NET assembly whose own strings contain "PyInstaller" is
  reported as `PyInstaller` - use `-e dotnet` for such a file.

## Third-Party Components

| Component | Version | License | Bundled |
|---|---|---|---|
| ICSharpCode.Decompiler (ILSpy) | 8.2.0.7535 | MIT | yes |
| pycdc.exe / pycdas.exe | - | zrax/pycdc upstream | yes |
| Nuitka unpacker helpers (nuitka-revenant, nuitka-static-unpacker, nuitka-themida-unpacker) | - | see `licenses\` | yes |
| pyz-unpacker, pyarmor-unpacker | - | see `licenses\` | yes |
| Python helper scripts (`pyi_extract.py`, `pyc_decompile.py`, `magic_decompile.py`, `cpp_capstone.py`) | - | part of this project | yes |
| .NET runtime win-x64 | 10.0 | MIT (.NET) | yes |
| Python and pip packages (`zstandard`, `capstone`, `pefile`, `pycryptodome`, `cryptography`, `decompyle3`, `uncompyle6`, `tkinter`, `keyboard`) | - | upstream | no (external) |
| de4dot | - | upstream | no (optional) |

Full texts ship in the release under `licenses\` plus
`THIRD-PARTY-NOTICES.txt`.

## License

No license has been specified.

The third party components keep their own licenses, which are shipped in
`licenses\`.

## Download

- **Windows x64 (portable, runtime bundled):**
  [TE-CMD-v1.0.0-win-x64.zip](https://github.com/31bc/TE-CMD/releases/download/v1.0.0/TE-CMD-v1.0.0-win-x64.zip)
- **Source:**
  [TE-CMD-v1.0.0-source.zip](https://github.com/31bc/TE-CMD/releases/download/v1.0.0/TE-CMD-v1.0.0-source.zip)
  or clone `https://github.com/31bc/TE-CMD`
- **Full archive (source + tool + samples + docs):**
  [TE-CMD-v1.0.0-full.zip](https://github.com/31bc/TE-CMD/releases/download/v1.0.0/TE-CMD-v1.0.0-full.zip)

Every archive has a `.sha256` file next to it; `release-manifest.json` lists
the artifacts, their hashes, sizes and the verification results.

## Release

Published on the Releases page of this repository as `v1.0.0`, with three
archives built by `TE-CMD.exe package`:

| Archive | Content |
|---|---|
| `TE-CMD-v1.0.0-win-x64.zip` | portable tool package, root folder `TE-CMD\` |
| `TE-CMD-v1.0.0-source.zip` | buildable source tree, root folder `TE-CMD-source\` |
| `TE-CMD-v1.0.0-full.zip` | source + tool + samples + docs + licenses, root `TE-CMD-Full\` |

Building from source: `dotnet restore` then `dotnet build TE-CMD.csproj -c
Release` (see `BUILD.md`). The packaging step verifies the tool from a clean
directory, rebuilds the source archive, checks the archives, re-computes every
SHA256 and scans for leaked developer paths before it prints `RELEASE READY`.
