# Quality Harness And Syntax Validity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reusable Flow-only corpus quality report and raise the current live-capture syntax-validity result from 50/59 parsed samples to 59/59.

**Architecture:** Add a focused `quality.py` analysis module and installed `flow-quality` CLI without changing the existing decompile commands. Fix three evidence-backed printer/control-flow defects behind small helpers: unsafe receiver grouping, ambiguous parenthesized statement boundaries, and instruction emission after terminal returns.

**Tech Stack:** Python 3.10+, dataclasses, pathlib, subprocess, argparse, Tk-independent Flow APIs, `unittest`, Luau compiler `--null` syntax mode.

## Global Constraints

- Preserve the current CLI, UI, installer, and raw/base64 input behavior.
- Flow remains the only decompiler; no external decompiler calls or dependencies.
- The Luau compiler is optional and supplied explicitly with `--compiler`; parsing and source metrics work without it.
- Never commit `live_samples/` or `big_print_sample.b64`.
- Every behavior change starts with a failing test.
- Unknown or uncertain semantics remain visible instead of being fabricated.
- Baseline: 60 local `.b64` captures, 59 parsed, 50 syntax-valid, 9 syntax-invalid, 1 invalid input (`local_test.b64`).

---

### Task 1: Corpus Quality Model And CLI

**Files:**
- Create: `luau_decompiler/quality.py`
- Create: `luau_decompiler/quality_cli.py`
- Create: `tests/test_quality.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Produces: `SyntaxResult`, `SampleQuality`, `QualityReport`, `check_luau_syntax()`, `analyze_sample()`, `analyze_corpus()`, and `quality_cli.main()`.
- Consumes: `maybe_base64_decode()`, `parse_chunk()`, and `decompile_chunk()`.

- [ ] **Step 1: Write failing metric-model tests**

Add `tests/test_quality.py` with a valid sample from the existing fixture builder and malformed bytes:

```python
from pathlib import Path
import tempfile
import unittest

from luau_decompiler.quality import analyze_corpus, analyze_sample
from test_chunk import make_namecall_chunk


class QualityTests(unittest.TestCase):
    def test_analyze_sample_reports_chunk_and_source_metrics(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "namecall.luauc"
            path.write_bytes(make_namecall_chunk())

            result = analyze_sample(path)

        self.assertTrue(result.parsed)
        self.assertEqual(result.proto_count, 1)
        self.assertEqual(result.instruction_count, 4)
        self.assertEqual(result.unknown_opcode_count, 0)
        self.assertGreater(result.output_line_count, 0)
        self.assertIsNone(result.syntax_valid)

    def test_analyze_sample_keeps_parse_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad.luauc"
            path.write_bytes(b"\xff")

            result = analyze_sample(path)

        self.assertFalse(result.parsed)
        self.assertIn("bytecode version mismatch", result.parse_error)

    def test_analyze_corpus_aggregates_pass_and_failure_counts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "good.luauc").write_bytes(make_namecall_chunk())
            (root / "bad.luauc").write_bytes(b"\xff")

            report = analyze_corpus(sorted(root.iterdir()))

        self.assertEqual(report.samples_total, 2)
        self.assertEqual(report.parse_passed, 1)
        self.assertEqual(report.parse_failed, 1)
```

- [ ] **Step 2: Run the model tests and verify the missing module failure**

Run: `python -m unittest tests.test_quality -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'luau_decompiler.quality'`.

- [ ] **Step 3: Implement immutable quality records and corpus analysis**

Create `luau_decompiler/quality.py` with these public records and signatures:

```python
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

from .binary import maybe_base64_decode
from .chunk import parse_chunk
from .decompile import decompile_chunk


@dataclass(frozen=True)
class SyntaxResult:
    valid: bool
    error: str | None = None


@dataclass(frozen=True)
class SampleQuality:
    path: str
    parsed: bool
    parse_error: str | None = None
    proto_count: int = 0
    instruction_count: int = 0
    unknown_opcode_count: int = 0
    evidence_comment_count: int = 0
    unsupported_comment_count: int = 0
    output_line_count: int = 0
    syntax_valid: bool | None = None
    syntax_error: str | None = None


@dataclass(frozen=True)
class QualityReport:
    samples: tuple[SampleQuality, ...]
    samples_total: int
    parse_passed: int
    parse_failed: int
    syntax_checked: int
    syntax_passed: int
    syntax_failed: int
    proto_count: int
    instruction_count: int
    unknown_opcode_count: int
    evidence_comment_count: int
    unsupported_comment_count: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


SyntaxChecker = Callable[[str], SyntaxResult]
```

Implement `analyze_sample(path: Path, syntax_checker: SyntaxChecker | None = None) -> SampleQuality` so it:

1. Reads raw bytes and base64-decodes `.b64`, `.base64`, and `.txt` inputs.
2. Parses and decompiles the main proto.
3. Counts all protos/instructions/unknown opcodes in the chunk.
4. Counts evidence lines beginning with `-- pc `.
5. Counts unsupported lines containing `unsupported` or `encoded opcode`.
6. Runs `syntax_checker(source)` only when supplied.
7. Returns a failed record instead of raising for malformed input.

Implement `analyze_corpus(paths: Iterable[Path], syntax_checker: SyntaxChecker | None = None) -> QualityReport` by sorting paths by their string form, calling `analyze_sample`, and summing every field in `QualityReport`.

- [ ] **Step 4: Add compiler and CLI tests**

Add the module imports and a second test class using `unittest.mock.patch`:

```python
from contextlib import redirect_stdout
import io
import json
from unittest.mock import Mock, patch

from luau_decompiler.quality import SyntaxResult, check_luau_syntax
from luau_decompiler.quality_cli import main


class CompilerQualityTests(unittest.TestCase):
    def test_check_luau_syntax_uses_null_mode(self):
        completed = Mock(returncode=0, stdout="", stderr="")
        with patch("luau_decompiler.quality.subprocess.run", return_value=completed) as run:
            result = check_luau_syntax("return 1\n", Path("luau-compile"))
        self.assertTrue(result.valid)
        self.assertEqual(run.call_args.args[0][1], "--null")

    def test_quality_cli_emits_json_and_fails_on_syntax_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "namecall.luauc"
            path.write_bytes(make_namecall_chunk())
            stdout = io.StringIO()
            with patch(
                "luau_decompiler.quality_cli.check_luau_syntax",
                return_value=SyntaxResult(False, "bad syntax"),
            ), redirect_stdout(stdout):
                result = main([str(path), "--compiler", "luau-compile", "--json", "--fail-on-syntax"])
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(stdout.getvalue())["syntax_failed"], 1)
```

- [ ] **Step 5: Run the new tests and verify missing interfaces fail**

Run: `python -m unittest tests.test_quality -v`

Expected: FAIL because `check_luau_syntax` and `quality_cli` do not exist yet.

- [ ] **Step 6: Implement syntax checking and the installed quality CLI**

Add `check_luau_syntax(source: str, compiler: Path) -> SyntaxResult` to `quality.py`. Write source into a temporary `.luau` file with UTF-8 and no BOM, then call:

```python
completed = subprocess.run(
    [str(compiler), "--null", str(source_path)],
    capture_output=True,
    text=True,
    timeout=30,
)
```

Return `SyntaxResult(True)` for exit code zero. Otherwise return the stripped stderr/stdout with the temporary path replaced by `<output>`.

Create `luau_decompiler/quality_cli.py` with arguments:

```python
parser.add_argument("roots", nargs="+", type=Path)
parser.add_argument("--compiler", type=Path)
parser.add_argument("--json", action="store_true")
parser.add_argument("--fail-on-parse", action="store_true")
parser.add_argument("--fail-on-syntax", action="store_true")
```

Expand directory roots recursively for `*.b64`, `*.base64`, and `*.luauc`; keep explicit file roots directly, including explicit `.txt` inputs. This prevents generated `*.disasm.txt` and `*.summary.txt` artifacts from being mistaken for bytecode during a directory scan. Emit `report.to_dict()` as indented JSON for `--json`, otherwise print a compact totals table followed by failed sample paths/errors. Return `1` only when the requested fail-on condition is nonzero.

Add the installed command to `pyproject.toml`:

```toml
flow-quality = "luau_decompiler.quality_cli:main"
```

- [ ] **Step 7: Run quality tests and the existing focused suite**

Run: `python -m unittest tests.test_quality tests.test_cli tests.test_chunk tests.test_disasm -v`

Expected: PASS.

- [ ] **Step 8: Commit the quality harness**

```powershell
git add pyproject.toml luau_decompiler\quality.py luau_decompiler\quality_cli.py tests\test_quality.py
git commit -m "Add Flow corpus quality reporting"
```

---

### Task 2: Syntax-Safe Receiver Grouping

**Files:**
- Modify: `luau_decompiler/decompile.py:150-250`
- Modify: `tests/test_chunk.py`

**Interfaces:**
- Produces: `_receiver_expr(value: str) -> str` used by field, index, call, and namecall rendering.
- Fixes: direct table-constructor indexing and method calls on literal receivers.

- [ ] **Step 1: Write failing receiver tests**

Import `_field_expr`, `_index_expr`, and `_namecall_expr` in `tests/test_chunk.py`, then add:

```python
def test_table_literal_receiver_is_grouped_for_index(self):
    self.assertEqual(_index_expr("{value = 1}", "key"), "({value = 1})[key]")

def test_multiline_table_literal_receiver_is_grouped_for_index(self):
    table = "{\n    value = 1,\n}"
    self.assertEqual(_index_expr(table, "key"), f"({table})[key]")

def test_nil_receiver_is_grouped_for_namecall(self):
    self.assertEqual(_namecall_expr("nil", "GetFullName", []), "(nil):GetFullName()")

def test_boolean_receiver_is_grouped_for_field(self):
    self.assertEqual(_field_expr("true", "value"), "(true).value")
```

- [ ] **Step 2: Run the receiver tests and verify failures**

Run: `python -m unittest tests.test_chunk.ChunkTests.test_table_literal_receiver_is_grouped_for_index tests.test_chunk.ChunkTests.test_multiline_table_literal_receiver_is_grouped_for_index tests.test_chunk.ChunkTests.test_nil_receiver_is_grouped_for_namecall tests.test_chunk.ChunkTests.test_boolean_receiver_is_grouped_for_field -v`

Expected: FAIL with ungrouped receiver strings.

- [ ] **Step 3: Implement one receiver-grouping boundary**

Add this focused helper near `_group_if_needed`:

```python
def _receiver_expr(value: str) -> str:
    grouped = _group_if_needed(value)
    if grouped != value:
        return grouped
    if value in {"nil", "true", "false"}:
        return f"({value})"
    if value.startswith("{") and value.endswith("}"):
        return f"({value})"
    if _unquote_string_literal(value) is not None:
        return f"({value})"
    return value
```

Use `_receiver_expr` in `_field_expr`, `_index_expr`, and `_namecall_expr`. Keep `_call_target_expr` unchanged because direct function calls have different grammar.

- [ ] **Step 4: Run focused and full chunk tests**

Run: `python -m unittest tests.test_chunk -v`

Expected: PASS.

- [ ] **Step 5: Commit receiver grouping**

```powershell
git add luau_decompiler\decompile.py tests\test_chunk.py
git commit -m "Group literal and table receivers"
```

---

### Task 3: Parenthesized Statement Separation

**Files:**
- Modify: `luau_decompiler/decompile.py:580-605`
- Modify: `tests/test_chunk.py`

**Interfaces:**
- Produces: `_needs_statement_separator(previous: str, indent: str, current: str) -> bool`.
- Consumes: the existing nested `emit_line()` function.

- [ ] **Step 1: Write failing separator tests**

Add a small public-at-module helper test surface:

```python
from luau_decompiler.decompile import _needs_statement_separator

def test_parenthesized_assignment_after_call_needs_separator(self):
    self.assertTrue(_needs_statement_separator("    r9:Add()", "    ", "(state or fallback).active = true"))

def test_parenthesized_call_after_call_needs_separator(self):
    self.assertTrue(_needs_statement_separator("    r9:Add()", "    ", "((state or fallback).Leaving):Fire()"))

def test_parenthesized_statement_at_new_indent_does_not_modify_parent(self):
    self.assertFalse(_needs_statement_separator("if ready then", "    ", "(state).active = true"))

def test_non_parenthesized_statement_needs_no_separator(self):
    self.assertFalse(_needs_statement_separator("    r9:Add()", "    ", "state.active = true"))
```

- [ ] **Step 2: Run separator tests and verify the import failure**

Run: `python -m unittest tests.test_chunk.ChunkTests.test_parenthesized_assignment_after_call_needs_separator tests.test_chunk.ChunkTests.test_parenthesized_call_after_call_needs_separator tests.test_chunk.ChunkTests.test_parenthesized_statement_at_new_indent_does_not_modify_parent tests.test_chunk.ChunkTests.test_non_parenthesized_statement_needs_no_separator -v`

Expected: FAIL because `_needs_statement_separator` is missing.

- [ ] **Step 3: Implement statement-boundary detection**

Add:

```python
def _needs_statement_separator(previous: str, indent: str, current: str) -> bool:
    if not current.startswith("("):
        return False
    previous_indent = previous[: len(previous) - len(previous.lstrip())]
    if previous_indent != indent:
        return False
    stripped = previous.strip()
    if not stripped or stripped.startswith("--"):
        return False
    return not stripped.endswith(("then", "do", "else", "{", "(", "[", ",", ";"))
```

At the start of `emit_line`, split `value` once. Before appending the first physical line, call the helper. When true, append `;` to `lines[-1]`. Then append current/multiline content exactly as before. The separator belongs at the end of the previous statement, which Luau accepts; do not emit a line beginning with `;`.

- [ ] **Step 4: Run chunk and quality tests**

Run: `python -m unittest tests.test_chunk tests.test_quality -v`

Expected: PASS.

- [ ] **Step 5: Commit statement separation**

```powershell
git add luau_decompiler\decompile.py tests\test_chunk.py
git commit -m "Separate parenthesized Luau statements"
```

---

### Task 4: Stop Emitting Dead Instructions After Return

**Files:**
- Modify: `luau_decompiler/decompile.py:4135-4150`
- Modify: `tests/test_chunk.py`

**Interfaces:**
- Changes: `decompile_range()` treats every `RETURN` as a terminal instruction for its current structured range.
- Preserves: existing branch joins because each branch is already decompiled through its own bounded `decompile_range()` call.

- [ ] **Step 1: Add a handcrafted return/dead-write fixture**

Add `make_return_then_dead_global_chunk()` beside the existing global assignment fixtures:

```python
def make_return_then_dead_global_chunk():
    strings = ["deadValue"]
    words = [
        encode_ad("LOADN", 0, -1),
        encode_abc("RETURN", 0, 2, 0),
        encode_ad("LOADN", 0, 99),
        encode_abc("SETGLOBAL", 0, 0, 0),
        0,
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)
```

- [ ] **Step 2: Write the failing terminal-return test**

```python
def test_decompile_stops_current_range_after_return(self):
    source = decompile_chunk(parse_chunk(make_return_then_dead_global_chunk()))

    self.assertIn("return -1", source)
    self.assertNotIn("deadValue", source)
    self.assertNotIn("99", source)
```

- [ ] **Step 3: Run the test and verify dead output is present**

Run: `python -m unittest tests.test_chunk.ChunkTests.test_decompile_stops_current_range_after_return -v`

Expected: FAIL because the current loop continues after `RETURN`.

- [ ] **Step 4: Make return terminal inside the active range**

Replace the `elif name == "RETURN":` branch with the same value behavior plus one terminal `break`:

```python
elif name == "RETURN":
    if insn.b == 0:
        values = open_args(insn.a)
        open_results = None
        if values:
            emit_line(indent, f"return {', '.join(values)}")
        elif insn is not last_instruction:
            emit_line(indent, "return")
    elif insn.b <= 1:
        open_results = None
        if insn is not last_instruction:
            emit_line(indent, "return")
    else:
        open_results = None
        values = [return_reg(insn.a + offset, insn.pc) for offset in range(insn.b - 1)]
        emit_line(indent, f"return {', '.join(values)}")
    break
```

Do not jump to `stop_pc`; returning ends only the current recursive range and lets the parent structurer continue at its own join point.

- [ ] **Step 5: Run control-flow and full chunk tests**

Run: `python -m unittest tests.test_chunk tests.test_control_flow_extra tests.test_cfg -v`

Expected: PASS.

- [ ] **Step 6: Commit terminal-return handling**

```powershell
git add luau_decompiler\decompile.py tests\test_chunk.py
git commit -m "Stop reconstruction after terminal returns"
```

---

### Task 5: Live Corpus Gate, Documentation, And Release Verification

**Files:**
- Modify: `README.md`
- Test: complete repository and installed package

**Interfaces:**
- Consumes: `flow-quality` and the three syntax fixes.
- Produces: documented quality command and a recorded 59/59 syntax-valid acceptance result.

- [ ] **Step 1: Run the quality gate against existing captures**

Run:

```powershell
python -m luau_decompiler.quality_cli live_samples `
  --compiler "C:\Users\Admin\Desktop\flow\.tools\luau-0.728\luau-compile.exe" `
  --json --fail-on-syntax
```

Expected totals:

```json
{
  "samples_total": 60,
  "parse_passed": 59,
  "parse_failed": 1,
  "syntax_checked": 59,
  "syntax_passed": 59,
  "syntax_failed": 0
}
```

The one parse failure remains the known non-bytecode `live_samples/local_test.b64`; `--fail-on-syntax` must return exit code `0` because all parsed outputs compile.

- [ ] **Step 2: Update README quality instructions**

Add a `## Quality Report` section after `## Tests`:

````markdown
## Quality Report

Run Flow over a directory of raw or base64 chunks:

```powershell
flow-quality live_samples --json
```

To syntax-check reconstructed source with a local Luau compiler:

```powershell
flow-quality live_samples --compiler C:\path\to\luau-compile.exe --fail-on-syntax
```

The report separates parse failures, unknown instructions, reconstruction evidence comments, and Luau syntax failures. A lower comment count is not treated as an improvement unless semantic regression tests also pass.
````

- [ ] **Step 3: Run complete verification**

Run:

```powershell
python -m unittest discover -s tests -v
python -m compileall -q luau_decompiler
git diff --check
```

Expected: all tests pass, compilation succeeds, and `git diff --check` prints no errors.

- [ ] **Step 4: Reinstall and smoke-test the packaged command**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -NoDesktopShortcut
$quality = "$env:LOCALAPPDATA\FlowDecompiler\.venv\Scripts\flow-quality.exe"
& $quality live_samples --compiler "C:\Users\Admin\Desktop\flow\.tools\luau-0.728\luau-compile.exe" --fail-on-syntax
```

Expected: installation succeeds and the installed command reports `syntax_failed: 0` with exit code `0`.

- [ ] **Step 5: Commit documentation**

```powershell
git add README.md
git commit -m "Document Flow quality reporting"
```

- [ ] **Step 6: Final repository check**

Run: `git status --short`

Expected: only the pre-existing untracked `big_print_sample.b64` remains. Do not stage it.

## Deferred Follow-Up Plans

After this plan is complete, use the quality report to create separate plans for:

1. Decoder/chunk diagnostic completeness and bounded malformed-input fuzzing.
2. Explicit register/value IR for open calls, aliases, and multi-return semantics.
3. Closure/upvalue identity and lifetime recovery.
4. CFG region structuring for the remaining evidence comments.
5. Deterministic naming and readability improvements after semantic gates are green.

Roblox MCP tools are not exposed in the current session tool list, so this first plan uses the 60 existing live captures. A later capture pass should add newly observed failures when the MCP connector becomes callable.
