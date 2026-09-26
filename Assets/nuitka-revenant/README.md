# REVENANT NUITKA UNPACKER

### Static Nuitka decompiler — native code back to readable Python

> Reverse engineering should not be a closed room.

REVENANT is the second generation of my Nuitka reverse-engineering work. It analyzes Nuitka-compiled Windows binaries and rebuilds Python source from static evidence: constants, module metadata, code objects, native x86-64 instructions, source-line markers and control flow.

It does not execute the target. It does not pretend that optimized native code still contains every detail of the original `.py` file. What it does is recover as much as the binary can actually prove, produce parseable Python, and mark the parts that remain uncertain instead of quietly inventing them.

On supported patterns, the result can get surprisingly close to the original structure and logic. It is not perfect yet. It is already useful.

This project is independent and is not affiliated with or endorsed by the Nuitka project.

## Why this is different

My first public project, [nuitka-static-unpacker](https://github.com/DimaReverse/nuitka-static-unpacker), focused on unpacking: constants, modules, bytecode artifacts and forensic reports.

REVENANT goes further. The goal here is source recovery directly from Nuitka's native output.

The decompiler combines several kinds of evidence:

- Nuitka constants blobs and module tables
- code-object metadata, signatures and source line numbers
- native function makers and implementation pointers
- x86-64 register and stack simulation
- Nuitka helper calls, Python C-API calls and numeric slots
- structured control-flow and source-line walkers
- syntax validation and a per-module recovery audit

This is not a `.pyc` decompiler with a different name. Nuitka turns Python into native code, so the hard part is translating Nuitka's generated machine-code patterns back into Python statements and control flow.

## Current capabilities

- Static analysis of Nuitka `.exe` and `.dll` targets on Windows
- Open-source and supported Nuitka Commercial layouts
- Constants and encrypted metadata recovery where the format is recognized
- Module listing and selective module analysis
- Imports, classes, functions, arguments, defaults, constants and docstrings
- Best-effort recovery of assignments, calls, attributes, operators, loops, conditions, iteration, unpacking and formatted strings
- Cross-version analysis: the host interpreter does not need to match the target Python version
- Single-module or whole-source-tree emission
- Resume and partial-module refinement for long runs
- Parseable output contract with JSON audits
- Conservative defaults: low-confidence native reconstruction is marked or quarantined
- Optional `.nbc` evidence bundles for manual or assisted reconstruction

The default source-emission path is static. The script still contains an optional dynamic laboratory mode inherited from earlier research, but it is not required for source recovery and must only be used on processes you are authorized to instrument.

## Honest limits

No native decompiler can guarantee a perfect 1:1 copy of every original Python file.

Compilation can remove comments and formatting, rename or eliminate temporary values, inline operations, merge branches and transform control flow. Complex nested loops, multi-arm conditions, exception handling and heavily optimized expressions can still be incomplete or approximate.

REVENANT follows a simple rule: incomplete evidence is better than invented code. A valid Python file is not automatically a semantically exact Python file, so every output should be read together with its audit.

The current implementation is best described as a research preview:

- Windows PE/x86-64 is the verified path.
- Python 3.10 and 3.11 targets have been tested end to end from a Python 3.12 host.
- Other target versions have compatibility logic, but they need broader regression coverage before I will call them verified.
- Onefile executables may require extraction of the inner Nuitka payload before analysis.
- Protected or substantially modified layouts can fail cleanly or produce partial output.

## Measured results

These are regression results from the latest local development run. They are examples, not universal success rates.

| Target | Build | Result |
| --- | --- | --- |
| `bidbot_v4.dll` / `__main__` | Python 3.10, open-source Nuitka | 33/34 code objects matched, 21 bodies recovered, output parses |
| `Panel.exe` / `__main__` | Python 3.11, commercial layout | 795/981 code objects matched, 722 bodies recovered, output parses |
| `wmi` | Python 3.11 dependency module | 91/98 matched, 69 bodies recovered, output parses |
| `typing_extensions` | Python 3.11 dependency module | 149/191 matched, 63 bodies recovered, output parses |
| `steampy.guard` | Python 3.11 dependency module | 4/4 matched, 2 bodies recovered, output parses |

“Body recovered” means that the tool emitted evidence-backed statements for that function. It does not mean every statement is identical to the pre-compilation source.

## Requirements

- Python 3.8 or newer
- [`pefile`](https://github.com/erocarrera/pefile)
- [`capstone`](https://www.capstone-engine.org/)
- [`zstandard`](https://github.com/indygreg/python-zstandard) for compressed blobs
- [`xdis`](https://github.com/rocky/python-xdis) for optional cross-version marshal support

Install the recommended dependencies:

```bash
python -m pip install pefile capstone zstandard xdis
```

Optional `.pyc` backends such as `decompyle3`, `uncompyle6` or `pycdc` are only used by the legacy artifact pipeline. Native source emission does not depend on them.

## Quick start

Use the tool only on software you own, samples you are authorized to inspect, defensive malware-analysis targets, or reversing challenges where analysis is explicitly allowed.

List the modules first:

```bash
python nuitka_decompiler.py \
  --source authorized_target.exe \
  --list-modules
```

Recover one module and write its audit:

```bash
python nuitka_decompiler.py \
  --source authorized_target.exe \
  --live-decompile __main__ \
  --emit-source recovered_main.py
```

Recover the application's source tree:

```bash
python nuitka_decompiler.py \
  --source authorized_target.exe \
  --emit-all-source recovered_source \
  --only "__main__,myapp.*"
```

Use the faster, more conservative profile:

```bash
python nuitka_decompiler.py \
  --source authorized_target.exe \
  --emit-all-source recovered_source \
  --emit-fast
```

Refine only modules that were still partial in a previous run:

```bash
python nuitka_decompiler.py \
  --source authorized_target.exe \
  --emit-all-source recovered_source \
  --refine-partial
```

If Python-version detection is wrong, override it explicitly:

```bash
python nuitka_decompiler.py \
  --source authorized_target.exe \
  --target-python 3.11 \
  --emit-all-source recovered_source
```

Run `python nuitka_decompiler.py --help` for the complete option list.

## Reading the output

Whole-binary recovery writes a Python source tree and `LIVE_RECOVERY_REPORT.json`. Single-module emission writes the `.py` file and a neighboring `.audit.json` file.

The audit records information such as:

- detected Python version and Nuitka edition
- code objects discovered and matched to native implementations
- function bodies recovered
- placeholders and quarantined fragments
- parse status and completeness status
- analysis budgets and recovery paths used

Keep recovery comments during review. `--clean` makes output easier to read, but it intentionally removes some provenance notes. `--allow-partial-executable` is unsafe and should only be enabled when you understand that unresolved temporary values may remain in executable-looking code.

## Roadmap

The next work is not “add more guesses.” It is to close specific, reproducible native patterns:

- tri-state boolean branches with real statements inside the true arm
- binding values created inside branches and formatted strings
- nested loop and multi-arm condition reconstruction
- stronger `try` / `except` / `finally` structure recovery
- regression targets for Python 3.12 and 3.13
- ELF support after the PE pipeline is stable
- smaller modules, clearer architecture and an automated public test corpus

If you can provide a minimal Nuitka-compiled sample together with its original source and build command, that is far more useful than a screenshot saying “it failed.” A good regression case can improve the decompiler for everyone.

## The story behind this release

Today I am open-sourcing the second generation of my Nuitka decompiler.

I do not want to introduce it as a perfect tool, because it is not one. I want to introduce it honestly: this repository contains years of attempts, wrong ideas, rewrites, broken outputs and nights spent looking at machine code until something that seemed unreadable slowly started to make sense.

The first version of this project opened the container. It recovered constants, modules, metadata, bytecode artifacts and other pieces hidden inside Nuitka binaries. At the time, even that felt like breaking through a wall. But it was never the end of the question for me. I did not only want to know what was packed inside a binary. I wanted to know how far we could travel in the opposite direction: from native code back to a Python program a human could read and understand.

That is what this second version tries to do.

It follows code objects into native implementations, reads Nuitka helper patterns, tracks values through registers and stack slots, uses source-line evidence to reconnect functions, and rebuilds statements and control flow. On some functions, the result comes surprisingly close to the original source. On others, optimization has removed too much information or transformed the structure too heavily. There are still difficult loops, branches, exception paths and expressions that need more work.

I am not ashamed of those limits. In fact, being explicit about them is one of the reasons I am publishing the project now.

Reverse engineering already contains enough false certainty. A decompiler can produce beautiful Python that parses and still be wrong. I would rather show a `pass`, preserve a recovery comment or mark a fragment as uncertain than fill a missing function with something that merely looks believable. This project should become more accurate because people bring evidence, not because it becomes better at hiding its mistakes.

For me, however, this release has never been only a technical milestone.

I started taking reverse engineering seriously during one of the most difficult periods of my life. At school I experienced bullying, isolation and the feeling that every year was becoming harder than the one before it. I lost confidence in myself and in the idea that the people and systems around me would recognize what I could actually do.

Being autistic often meant that people talked about me instead of talking with me. Too many conversations began with my supposed limits. Decisions about education, support and independence could feel as if they had already been made before I entered the room. I was surrounded by documents, appointments and labels, while the person inside all of that paperwork was easy to ignore.

There were periods when my social life almost disappeared. A large part of my world fit inside one room: a computer, an internet connection and whatever I could learn on my own. Some nights had hyperpop playing too loudly in the background. Sometimes I opened an FPS game because I needed my brain to stop for a while. Then I returned to a disassembler and tried again.

The computer did not care whether I behaved in the way other people expected. Machine code did not judge the way I spoke or the way I processed things. It did not know what a school document said about me. It was difficult, but it was honest. If a program behaved in a certain way, there was a reason somewhere in the bytes. If I was patient enough, I could find a piece of that reason.

That mattered to me more than I knew how to explain at the time.

Every small discovery gave me something concrete when the rest of my life felt stuck. Recovering one constant, recognizing one generated structure, understanding one native helper or fixing one incorrect function body meant that I was still capable of moving forward. The progress was slow and often frustrating, but it belonged to me.

This project did not come from a company, a research grant or a carefully planned roadmap. It came from curiosity and stubbornness. It grew through failed experiments, huge scripts, test binaries, regressions, temporary fixes that had to be removed, and the decision to keep looking when the output was still wrong. The code carries that history. It is not architecturally perfect, just as the journey behind it was not clean or linear.

But it works. Not everywhere, not with everything, and not at a magical 1:1 level — but well enough to prove that serious static source recovery from Nuitka native code is a real direction, not just an idea.

I am releasing it because I do not want reverse engineering to remain a closed room.

It should not belong only to companies that can afford expensive tooling. It should not depend on knowing the right people or being invited into private groups where knowledge is protected like status. It should not be kept unnecessarily obscure so that newcomers are forced to repeat years of work in isolation.

There will always be knowledge that requires effort. I am not trying to remove the challenge. I am trying to remove the locked door.

I want a curious person, maybe alone in front of a computer as I often was, to find this repository and have somewhere to begin. I want them to read the code, question it, break it and understand one more thing about how compiled Python works. I want somebody to solve a pattern I could not solve. I want somebody to build a cleaner and more powerful decompiler from these ideas. If this project is eventually surpassed because I opened it, that will be a success.

This is also why I am releasing the second version before every problem is finished. Closed research can keep improving forever without ever helping anyone else. Open research can be tested against binaries I have never seen, Python versions I have not covered and compiler patterns I would not discover alone. Its weaknesses become visible, but so does the path to fixing them.

If you are a reverse engineer, test it and try to break it. If a function is reconstructed incorrectly, reduce it to a reproducible sample. If you understand the missing native pattern, document it. If you can improve the implementation, open a pull request. If you believe one of my conclusions is wrong, bring evidence and challenge it. That is not an attack on the project; that is how the project should grow.

If you are learning, do not be intimidated by the size of the code or by the people who make this field look inaccessible. Start with one function, one helper or one instruction sequence. You do not have to understand the entire binary before your contribution has value.

If you use REVENANT to recover your own lost work, analyze malware, audit an authorized build, study compiler behavior or create something better, tell me. Knowing that this code became useful outside the room where it was written would mean more to me than a download number.

I am still working toward my own independence and toward a future in reverse engineering and software security. I still have things to prove to myself. Publishing this code is part of that process: taking something born during a difficult period and turning it into something open, useful and alive.

This is not an endpoint. It is a road I am opening.

Knowledge becomes stronger when it stops being afraid of being shared.

This is **REVENANT**.

— **DimaReverse**

## Responsible use

This repository is intended for legitimate reverse engineering, interoperability research, malware analysis, defensive security, education and recovery of software you own.

Do not use it to steal proprietary source, bypass licensing or access controls, extract credentials for unauthorized access, or violate applicable law, contracts or software licenses. When authorization is unclear, do not analyze the target.

## Contributing

Issues and pull requests are welcome. The most useful reports include:

1. a minimal reproducible Python source file;
2. the exact Python and Nuitka versions;
3. the full Nuitka build command;
4. the resulting test binary or a reproducible way to build it;
5. the recovery audit and the smallest incorrect output fragment.

Please remove secrets and unrelated proprietary code before sharing a sample.

## License

Released under the MIT License. See `LICENSE`.
