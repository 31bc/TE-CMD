# Contributing

Contributions are welcome, especially small reproducible cases that improve native-to-Python recovery without introducing sample-specific guesses.

## Reporting a recovery bug

Please include:

1. a minimal Python program that reproduces the problem;
2. the exact Python and Nuitka versions;
3. the complete Nuitka build command;
4. the smallest redistributable target or instructions to build it;
5. the generated `.py` fragment and its audit;
6. the expected source fragment;
7. the host operating system and Python version.

Remove tokens, credentials, personal information and unrelated proprietary code before sharing anything publicly. Reports containing material you are not allowed to redistribute will be closed.

## Pull requests

- Keep recovery evidence-based and format-independent where possible.
- Do not add hardcoded addresses, sample names or product-specific behavior to the universal path.
- Prefer a conservative incomplete result over convincing but unsupported Python.
- Add or describe a regression sample for every recovery change.
- Confirm that `python -m py_compile nuitka_decompiler.py` succeeds.
- Explain coverage gained and any known trade-offs.

Large architectural changes should begin with an issue so the approach can be discussed before implementation.
