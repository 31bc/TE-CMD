# Building TE-CMD

`TE-CMD.exe` is the command line edition of DecompilerSuite 3.0.0.0: detection
code, helper code and all nine engines are the DecompilerSuite sources, only the
front end is a CLI. Nothing in the tool ever executes the file you analyze.

## Requirements

| What | Needed for |
|---|---|
| .NET SDK 10.0 or newer (`dotnet --version` must work) | building / packaging |
| Windows x64 | running the published tool |
| Python 3.x on PATH | Python/Nuitka/PYZ/PyArmor/Themida/Capstone engines at run time |
| pip packages `zstandard`, `capstone`, `pefile`, `pycryptodome`, `cryptography`, `decompyle3`, `uncompyle6`, `tkinter`, `keyboard` | the individual engines (optional, per engine) |

The released tool package is self-contained: the target machine needs neither
the .NET SDK nor the .NET runtime.

## Build

```
dotnet restore TE-CMD.csproj
dotnet build TE-CMD.csproj -c Release
```

Output: `bin\Release\net10.0\TE-CMD.exe` (framework dependent, needs a .NET 10
runtime). `Assets\` is copied next to the executable automatically; the engines
resolve scripts through `AppContext.BaseDirectory\Assets`.

The .NET decompile test target is test data, built separately:

```
dotnet build samples\sample-net\SampleNet.csproj -c Release
copy samples\sample-net\bin\Release\netstandard2.0\SampleNet.dll samples\SampleNet.dll
```

## Portable build

```
dotnet publish TE-CMD.csproj -c Release -r win-x64 --self-contained true ^
  -p:DebugType=None -p:DebugSymbols=false -o release
```

`-p:DebugType=None` keeps `.pdb` files out of the package.

## Release packages

```
TE-CMD.exe package                 all three packages + verification
TE-CMD.exe package --tool          portable tool package only
TE-CMD.exe package --source        source package only
TE-CMD.exe package --full          full package only (builds tool + source too)
TE-CMD.exe package --clean         remove release\, stage\, dist\, obj\Release
TE-CMD.exe package --verify        verify existing packages
TE-CMD.exe package --zip           (re)create the ZIPs + checksums
TE-CMD.exe package --output <dir>  put release\, stage\ and dist\ elsewhere
```

Artifacts in `dist\`:

| File | Content |
|---|---|
| `TE-CMD-v<version>-win-x64.zip` / `.sha256` | portable tool, root folder `TE-CMD\` |
| `TE-CMD-v<version>-source.zip` / `.sha256` | buildable source tree, root folder `TE-CMD-source\` |
| `TE-CMD-v<version>-full.zip` / `.sha256` | source + tool + samples + docs + licenses, root folder `TE-CMD-Full\` |
| `release-manifest.json` | artifacts, hashes, sizes, file counts, build and verification results |

Verify a checksum with `Get-FileHash <zip>` or `sha256sum -c <name>.sha256`.

Packaging requires the .NET SDK: it runs `dotnet publish` and rebuilds the
source archive to prove it compiles. `RELEASE READY` is printed only when every
step and every check passed; any failure exits with code 1.

## Source layout

```
TE-CMD.csproj        net10.0, Version 1.0.0, Assets + config as content
Program.cs           entry point, exit codes, config apply, first run folders
Cli\                 options/parsing, logging, reports, engine routing, packaging
Engines\             DecompilerSuite engines (copied verbatim)
Helpers\             Detector + PeHelper (copied verbatim)
Assets\              engine scripts, pycdc.exe / pycdas.exe, unpackers, licenses
config\config.json   defaults for output folder, min string length, color
samples\             test targets (native PE, script, PyInstaller, .NET)
tools\               development harness - never packaged
output\              default output folder (created on first run)
```

## Dependencies

- self-contained .NET runtime for win-x64 (bundled next to `TE-CMD.exe`)
- `ICSharpCode.Decompiler` 8.2.0.7535 (ILSpy decompiler engine, bundled)
- `assets\` python helper scripts and `pycdc.exe` / `pycdas.exe` (bundled)
- Python 3.x on PATH plus the pip packages listed above (external)
- `de4dot.exe` (optional, not bundled - .NET deobfuscation stays disabled)

## Development notes

- Exit codes: `0` success, `1` analysis/dependency failure, `2` bad arguments,
  `3` target not found, `4` unsupported target, `130` interrupted.
- Engines are called with `Action<string> log` as the log hook; numbers printed
  by the tool are never fabricated.
- The bundled ILSpy engine reads assemblies up to .NET 8; .NET 10 assemblies
  (including `TE-CMD.dll` itself) fail with `fieldCount` - use
  `samples\SampleNet.dll` as the .NET test target.
- Packaging refuses to run from inside `release\` or `stage\` so it can never
  delete the executable it is running from.
