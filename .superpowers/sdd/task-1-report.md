# Task 1 Report: Official Luau Differential Harness

## Delivered

- Added `luau_decompiler.differential` with frozen `ProcessResult`, `DifferentialResult`, and `LuauToolchain` records.
- Added exact result comparison in timeout, return-code, stdout, then stderr order.
- Added compilation through official `luau-compile --binary`, Flow parsing/decompilation, isolated UTF-8 runtime execution, temporary-file cleanup, and timeout normalization.
- Added `flow-differential` with file/directory support, required compiler/runtime paths, text/JSON output, and nonzero results for mismatches, timeouts, tool failures, and parse/decompile failures.
- Added deterministic control-flow, multi-return, and closure/table fixtures.
- Registered the console script and documented its official `--binary` invocation.

## TDD Record

1. Initial comparison tests: RED as expected because `luau_decompiler.differential` did not exist; GREEN after the records and comparison implementation.
2. Toolchain and round-trip tests: RED as expected because `LuauToolchain` and the public functions were absent; GREEN after the compiler/runtime implementation.
3. The first toolchain green attempt exposed Windows newline conversion in text temporary files. Root cause was default universal newline handling; `newline=""` now preserves supplied UTF-8 source bytes. Focused tests then passed.
4. CLI tests: RED as expected because `luau_decompiler.differential_cli` did not exist; GREEN after the CLI and fixtures were added.
5. Official Luau correction: changed the command test to require `--binary`; RED showed the old positional `binary` argument, then GREEN after the implementation and README were corrected.
6. Parser-limit diagnostics: RED showed a v12 `ValueError` escaping the CLI; GREEN after the CLI began reporting it as a per-fixture error and returning exit code 1.

## Verification

- `python -m unittest tests.test_differential -v`: PASS, 11 tests.
- `PYTHONPATH="$PWD;$PWD\\tests" python -m unittest tests.test_differential tests.test_cli -v`: PASS, 14 tests.
  The unmodified direct command without `PYTHONPATH` fails before Task 1 because `tests/test_cli.py` imports `test_chunk` as a top-level module; full discovery supplies that test path.
- `python -m unittest discover -s tests`: PASS, 279 tests.
- `python -m compileall -q luau_decompiler tests tools`: PASS.
- `git diff --check`: PASS; only standard Windows line-ending warnings were emitted.
- Editable installation succeeded and installed `flow-differential`.

## Official Luau 0.729 Check

Tools used:

- `C:\\Users\\Admin\\AppData\\Local\\FlowDecompiler\\tools\\luau-0.729\\luau-compile.exe`
- `C:\\Users\\Admin\\AppData\\Local\\FlowDecompiler\\tools\\luau-0.729\\luau.exe`

`luau-compile --binary tests\\fixtures\\differential\\multi_return.luau` returned 0 and emitted 170 bytes whose first byte is `0x0c`, confirming the actual official compiler command and bytecode version 12.

The live gate was intentionally run:

```powershell
flow-differential tests\fixtures\differential --compiler C:\Users\Admin\AppData\Local\FlowDecompiler\tools\luau-0.729\luau-compile.exe --runtime C:\Users\Admin\AppData\Local\FlowDecompiler\tools\luau-0.729\luau.exe --json
```

It exits 1 and reports each fixture clearly as:

`bytecode version mismatch: expected [3..11], got 12`

This is the expected blocked live verification. No v12 parsing was added because Task 3 explicitly owns that scope.

## Scope Notes

- The initial plan's positional `binary` spelling was corrected to the installed official tool's required `--binary` mode.
- A concurrent modification in `docs/superpowers/plans/2026-07-13-semantic-core.md` was left untouched and is not part of this task's commit.
