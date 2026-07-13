# Flow Semantic Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a hybrid semantic core that measurably improves Flow's control-flow and value fidelity, validates observable behavior with official Luau tools, hardens malformed-input handling, and exposes useful diagnostics without breaking existing workflows.

**Architecture:** Add focused differential, graph-analysis, value-IR, region, fallback, and diagnostic modules around the existing parser and reconstructor. Integrate each layer incrementally into `decompile.py`, retaining proven legacy paths while replacing raw control-flow evidence with graph-backed structure or a semantics-preserving fallback.

**Tech Stack:** Python 3.10+, standard library dataclasses/enum/subprocess/tempfile/time, `unittest`, official Luau 0.729 CLI tools, Tkinter, existing Flow parser/disassembler/reconstructor.

## Global Constraints

- Preserve `flow-decompiler`, `flow-decompiler-ui`, and `flow-quality` commands.
- Preserve raw bytecode and `.b64`, `.base64`, and explicit `.txt` inputs.
- Preserve `--disasm`, `--summary`, current default source mode, installer behavior, startup settings, and saved UI settings.
- Add diagnostics through opt-in flags and UI controls only.
- Keep Python 3.10 as the minimum version and add no required third-party runtime dependencies.
- Keep Flow local and independent of Fission, lua.expert, or any remote decompiler.
- Every production behavior change starts with a focused failing test and a verified RED result.
- Never hide an uncertain edge or side effect merely to reduce evidence counts.
- Keep the 80 valid live captures syntax-valid with zero unknown opcodes and zero unsupported comments.
- Do not add `live_samples/`, `big_print_sample.b64`, generated reports, or worktree scratch files to git.

---

### Task 1: Official Luau Differential Harness

**Files:**
- Create: `luau_decompiler/differential.py`
- Create: `luau_decompiler/differential_cli.py`
- Create: `tests/test_differential.py`
- Create: `tests/fixtures/differential/control_flow.luau`
- Create: `tests/fixtures/differential/multi_return.luau`
- Create: `tests/fixtures/differential/closures_tables.luau`
- Modify: `pyproject.toml`
- Modify: `README.md`

**Interfaces:**
- Produces: `ProcessResult`, `DifferentialResult`, `LuauToolchain`, `compile_source()`, `execute_source()`, `check_roundtrip()`, and installed `flow-differential`.
- Consumes: `parse_chunk()` and `decompile_chunk()`.

- [ ] **Step 1: Write failing model and comparison tests**

Add tests for immutable result records and exact observation comparison:

```python
from luau_decompiler.differential import ProcessResult, compare_results


def test_compare_results_accepts_identical_observations(self):
    result = compare_results(ProcessResult(0, "ok\n", ""), ProcessResult(0, "ok\n", ""))
    self.assertTrue(result.equivalent)
    self.assertIsNone(result.mismatch)


def test_compare_results_reports_stdout_mismatch(self):
    result = compare_results(ProcessResult(0, "left\n", ""), ProcessResult(0, "right\n", ""))
    self.assertFalse(result.equivalent)
    self.assertIn("stdout", result.mismatch or "")
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `python -m unittest tests.test_differential -v`

Expected: FAIL because `luau_decompiler.differential` does not exist.

- [ ] **Step 3: Implement process records and exact comparison**

Create immutable `ProcessResult(returncode, stdout, stderr, timed_out=False)` and `DifferentialResult(equivalent, original, reconstructed, source, reconstructed_source, mismatch=None)`. Compare timeout, return code, stdout, and stderr in that order and report the first differing field.

- [ ] **Step 4: Add failing toolchain command and timeout tests**

Patch `subprocess.run` only at the external process boundary. Verify compiler arguments are `[compiler, "--binary", source_path]`, runtime arguments are `[runtime, source_path]`, UTF-8 is used, and `TimeoutExpired` becomes a timed-out `ProcessResult`.

- [ ] **Step 5: Implement compilation, execution, and roundtrip checking**

Use this interface:

Define frozen `LuauToolchain(compiler: Path, runtime: Path, timeout_seconds: float = 5.0)` and the exact public signatures `compile_source(source: str, toolchain: LuauToolchain) -> bytes`, `execute_source(source: str, toolchain: LuauToolchain) -> ProcessResult`, and `check_roundtrip(source: str, toolchain: LuauToolchain) -> DifferentialResult`.

Write temporary files with `delete=False`, clean them in `finally`, compile bytes from stdout without text conversion, decompile through Flow, then execute original and reconstructed sources separately.

- [ ] **Step 6: Add CLI and fixture tests, then implement `flow-differential`**

The CLI accepts source files/directories plus required `--compiler` and `--runtime`, supports `--json`, prints one result per fixture, and returns nonzero when any fixture mismatches or tool execution fails. Add `flow-differential = "luau_decompiler.differential_cli:main"` to `[project.scripts]`.

- [ ] **Step 7: Run focused, full, and official-tool tests**

Run `python -m unittest tests.test_differential tests.test_cli -v`, then `python -m unittest discover -s tests`; expect PASS. Run the fixtures with the installed Luau 0.729 compiler/runtime; every fixture must report equivalent.

- [ ] **Step 8: Commit**

```powershell
git add luau_decompiler/differential.py luau_decompiler/differential_cli.py tests/test_differential.py tests/fixtures/differential pyproject.toml README.md
git commit -m "Add Luau differential correctness harness"
```

---

### Task 2: Complete CFG Facts

**Files:**
- Modify: `luau_decompiler/cfg.py`
- Modify: `tests/test_cfg.py`

**Interfaces:**
- Produces: immutable `LoopInfo`, `StrongComponent`, and `ControlFlowFacts`; `analyze_cfg(graph)`.
- Preserves: `BasicBlock`, `ControlFlowGraph`, `build_cfg()`, and `block_at()` behavior.

- [ ] **Step 1: Write failing predecessor, reachability, and dominance tests**

Construct a diamond graph and assert predecessors, entry dominance, nearest common post-dominator, and exclusion of an unreachable block. Post-dominance must be conservative across infinite paths: a cyclic region that can either repeat forever or exit must not manufacture the exit as a mandatory join.

- [ ] **Step 2: Verify RED**

Run `python -m unittest tests.test_cfg -v`; expect failure because `analyze_cfg` is missing.

- [ ] **Step 3: Implement indexed graph facts**

Add:

```python
@dataclass(frozen=True)
class LoopInfo:
    header: int
    latch: int
    nodes: frozenset[int]
    exits: tuple[int, ...]


@dataclass(frozen=True)
class StrongComponent:
    nodes: tuple[int, ...]
    entries: tuple[int, ...]
    irreducible: bool


@dataclass(frozen=True)
class ControlFlowFacts:
    predecessors: dict[int, tuple[int, ...]]
    reachable: frozenset[int]
    dominators: dict[int, frozenset[int]]
    post_dominators: dict[int, frozenset[int]]
    immediate_dominator: dict[int, int | None]
    immediate_post_dominator: dict[int, int | None]
    back_edges: tuple[tuple[int, int], ...]
    loops: tuple[LoopInfo, ...]
    components: tuple[StrongComponent, ...]
```

Use iterative set intersection for dominators/post-dominators and Tarjan's algorithm for SCCs. Sort public tuple outputs.

- [ ] **Step 4: Write failing natural-loop and irreducible-SCC tests**

Cover a single natural loop, nested loop, two-entry SCC, terminal-only graph, empty graph, and AUX words that must never become block leaders. Add dead-code regressions after unconditional jumps and returns: the next real instruction must start an unreachable block so a buried instruction can never replace the true terminator or erase its edge.

- [ ] **Step 5: Implement back edges, natural loops, SCC entries, and O(1) lookup**

A back edge exists only when the header dominates the latch. Build natural-loop nodes by walking predecessors. Mark an SCC irreducible when more than one member receives an edge from outside. Cache start-PC and instruction-PC maps in `ControlFlowGraph` without changing public behavior, including mutations to the public block and instruction lists.

- [ ] **Step 6: Verify and commit**

Run focused CFG/control-flow tests and the full suite; expect PASS. Commit `luau_decompiler/cfg.py` and `tests/test_cfg.py` as `Add complete control flow graph facts`.

---

### Task 3: Bounded Parser And Contextual Errors

**Files:**
- Modify: `luau_decompiler/binary.py`
- Modify: `luau_decompiler/chunk.py`
- Modify: `luau_decompiler/opcodes.py`
- Create: `tests/test_parser_limits.py`

**Interfaces:**
- Produces: `ParseLimits`, `ChunkDecodeError`, and `parse_chunk(data, limits=None)`.
- Preserves: default successful parsing for all existing chunks.

- [ ] **Step 1: Write failing oversized-count, contextual-EOF, and Luau v12 tests**

Assert declared string/instruction counts over tiny configured limits fail before allocation, and truncated data reports section plus byte offset. Compile an official Luau 0.729 fixture with `--fflags=LuauBytecodeCostModel=true`; verify Flow initially rejects version 12, then preserve the fixture as the authoritative framing/cost regression.

- [ ] **Step 2: Verify RED**

Run `python -m unittest tests.test_parser_limits -v`; expect missing-symbol failure.

- [ ] **Step 3: Implement reader context and bounded counts**

Add `ChunkDecodeError(message, offset, section, proto_id=None)` and:

```python
@dataclass(frozen=True)
class ParseLimits:
    max_chunk_bytes: int = 64 * 1024 * 1024
    max_strings: int = 1_000_000
    max_string_bytes: int = 16 * 1024 * 1024
    max_protos: int = 100_000
    max_instructions_per_proto: int = 2_000_000
    max_total_instructions: int = 5_000_000
    max_constants_per_proto: int = 1_000_000
    max_children_per_proto: int = 100_000
    max_debug_locals_per_proto: int = 1_000_000
    max_upvalues_per_proto: int = 1_000_000
    max_line_info_per_proto: int = 2_000_000
    max_feedback_per_proto: int = 1_000_000
    max_typeinfo_bytes: int = 16 * 1024 * 1024
    max_proto_nesting: int = 10_000
```

Implement `_read_count(reader, section, limit, proto_id=None)` and wrap low-level EOF/index/tag failures with preserved exception chaining.

Raise `VERSION_MAX` to 12 and implement Luau's exact v12 proto layout from the tagged 0.729 source: read a varint serialized-size prefix before each proto, treat that size as a hard proto boundary, parse the existing body, read a varint64 cost after feedback when `LPF_INLINABLE` (`1 << 3`) is set, and advance to the declared proto end so future trailing fields remain forward-compatible. Store optional `serialized_size` and `cost` metadata on the parsed proto. Reject undersized, overrun, truncated, and out-of-chunk boundaries contextually; do not guess or scan for the next proto.

- [ ] **Step 4: Add total, constant, child, string-byte, index, and v12-boundary validation tests**

Use deliberately tiny limits with existing valid fixture builders. Verify one-at-limit passes, every declared limit has one focused failure, and out-of-range `main_proto`/child references fail contextually. Cover v12 proto sizes at exact boundary, too small, too large, truncated, unknown trailing bytes, inlinable cost present, and non-inlinable cost absent.

- [ ] **Step 5: Integrate all variable-size loops, verify, and commit**

Check counts before allocation/reads, track total instructions incrementally, run parser/chunk/CLI tests, full tests, the official v12 fixture, and the external corpus. Commit as `Harden chunk parsing with bounded diagnostics`.

---

### Task 4: Versioned Value IR Foundation

**Files:**
- Create: `luau_decompiler/value_ir.py`
- Create: `tests/test_value_ir.py`
- Modify: `luau_decompiler/decompile.py`
- Modify: `tests/test_chunk.py`

**Interfaces:**
- Produces: `Effect`, `Value`, `RegisterVersion`, `CallResultGroup`, `BlockState`, `merge_states()`, and `requires_materialization()`.
- Consumes: CFG block starts and instruction PCs.

- [ ] **Step 1: Write failing register-version and state-merge tests**

Cover same-definition merge, different-definition phi merge, missing predecessor, table identity preservation, and fixed/open call groups.

- [ ] **Step 2: Verify RED**

Run `python -m unittest tests.test_value_ir -v`; expect missing-module failure.

- [ ] **Step 3: Implement immutable IR and deterministic merges**

Use a closed `Effect` enum (`PURE`, `READ`, `WRITE`, `CALL`, `UNKNOWN`) and frozen records for literals, expressions, calls, tables, closures, unknowns, and phi values. Preserve source PC and identity. Keep identical versions when predecessors agree; otherwise create a sorted `PhiValue`. Missing values become an `UnknownValue` with a reason.

- [ ] **Step 4: Integrate side-effect materialization**

Route call/table/index reuse decisions through `requires_materialization(value, use_count)`. Keep `_may_have_constructor_side_effect` as a temporary compatibility adapter for paths without IR values.

- [ ] **Step 5: Add behavior regressions**

Add failing-then-passing tests for duplicated calls, indexed reads, table aliases, reused binary values, moved multi-results, open calls, and recursive captured closures. Assert single evaluation, stable object/closure identity, and syntax-valid source shape. The official `closures_tables.luau` differential fixture must become equivalent in this task; `captures.luau` must also become equivalent when its remaining mismatch is closure identity. Keep loop-carried register and branch-region repairs in Tasks 5 and 6 instead of adding opcode-specific workarounds here.

- [ ] **Step 6: Verify and commit**

Run value/chunk tests, full tests, and differential fixtures. Commit as `Add versioned value semantics`.

---

### Task 5: Graph-Backed Region Recovery

**Files:**
- Create: `luau_decompiler/regions.py`
- Create: `tests/test_regions.py`
- Modify: `luau_decompiler/decompile.py`
- Modify: `tests/test_control_flow_extra.py`
- Modify: `tests/test_chunk.py`

**Interfaces:**
- Produces: `BranchRegion`, `LoopRegion`, `IrreducibleRegion`, `RegionMap`, and `recover_regions(graph, facts)`.
- Consumes: `ControlFlowGraph` and `ControlFlowFacts` from Task 2.

- [ ] **Step 1: Write failing post-dominator branch tests**

Cover diamond `if/else`, `if` without `else`, `elseif`, nested branch, early return, and shared join. Assert header, true/false entries, join PC, and single ownership of shared joins.

- [ ] **Step 2: Verify RED**

Run `python -m unittest tests.test_regions -v`; expect missing-module failure.

- [ ] **Step 3: Implement branch regions**

Only accept a joined branch when both successors are reachable and their nearest common post-dominator is a valid join. Represent direct terminal/early-return arms with `join=None` instead of inventing an `else` or claiming ownership of the following fallback block. Use immutable records:

```python
@dataclass(frozen=True)
class BranchRegion:
    header: int
    true_entry: int
    false_entry: int
    join: int | None


class EdgeRole(Enum):
    NORMAL = "normal"
    BODY = "body"
    EXIT = "exit"
    BACK = "back"
    BREAK = "break"
    CONTINUE = "continue"
```

- [ ] **Step 4: Write failing loop and edge-role tests**

Cover while, repeat, numeric for, generic for, nested break, nested continue, and a branch join that must not be called continue.

- [ ] **Step 5: Implement loop regions and edge roles**

Build loop regions from natural-loop facts plus opcode families. Normalize `FORNPREP`/`FORNLOOP` and `FORGPREP*`/`FORGLOOP` shapes when prep/latch edges are not represented as ordinary natural loops. Bind the numeric current/start register `R[A+2]` as the visible induction variable while rendering the body; generic-for result variables begin at `R[A+3]`. The existing numeric limit/step layout (`R[A]`, `R[A+1]`) is already correct. Classify edges from membership and dominance rather than distance.

- [ ] **Step 6: Integrate facts into `decompile_proto`**

Build CFG/facts/regions once per prototype. Let graph-backed joins and edge roles run before legacy pattern fallbacks. Replace distance-only `break`/`continue` decisions while preserving all outputs already covered by exact tests. Merge Task 4 `BlockState` predecessors at loop headers/exits so repeat/while loop-carried values are materialized rather than restoring stale pre-loop string expressions.

- [ ] **Step 7: Minimize live evidence regressions**

Create synthetic regression chunks from reducible raw-flow sites in `ClientFX`, `VictoryScreen`, `M2`, and `Hypershot_Tool`. Assert structured output and absence of the former `-- pc` lines.

- [ ] **Step 8: Verify and commit**

Run region/control-flow/chunk tests, the full suite, differential fixtures, live Roblox scratch samples, and corpus syntax gate. `control_flow.luau`, `loops.luau`, and `short_circuit_branches.luau` must join the existing five equivalent fixtures, with no timeout. Evidence must not increase, and the live `DeepEquals` reducible `FORGLOOP` comment should disappear without syntax or runtime regression. Commit as `Recover control flow from graph regions`.

---

### Task 6: Irreducible State-Machine Fallback

**Files:**
- Create: `luau_decompiler/fallback.py`
- Create: `tests/test_fallback.py`
- Modify: `luau_decompiler/decompile.py`
- Modify: `tests/test_chunk.py`

**Interfaces:**
- Produces: `FallbackBlock`, `FallbackRegion`, `render_state_machine()`.
- Consumes: irreducible components from Task 2, edge roles from Task 5, and a statement translator callback supplied by `decompile_proto`.

- [ ] **Step 1: Write failing renderer tests**

Use a two-entry SCC with one conditional edge and one terminal return. Assert one evaluation of each condition, every state appears once, every edge assigns a next state or terminates, generated names avoid collisions, and rendered source compiles.

- [ ] **Step 2: Verify RED**

Run `python -m unittest tests.test_fallback -v`; expect missing-module failure.

- [ ] **Step 3: Implement deterministic fallback records and printer**

Use:

Define frozen `FallbackBlock` with `state`, `statements`, `condition`, `true_state`, `false_state`, and `terminal`; frozen `FallbackRegion(entry_state, blocks)`; and `render_state_machine(region: FallbackRegion, *, indent: int, reserved_names: set[str]) -> list[str]`.

Emit a collision-free state local, one `while true`, deterministic `if/elseif`, and a final error branch for impossible internal states.

- [ ] **Step 4: Extract side-effect-safe block translation**

Move the non-control instruction families required by fallback out of the nested `emit_range` switch into a helper receiving explicit register/value/table/capture state. Structured emission must call the same helper for migrated families so behavior cannot diverge silently.

- [ ] **Step 5: Integrate fallback per irreducible component**

Select fallback only for reachable multi-entry SCCs. Preserve structured blocks before/after it. Replace repeated raw jumps inside the component with one concise `-- flow: irreducible region` diagnostic.

- [ ] **Step 6: Add a protected-flow regression**

Minimize one multi-entry region from `BladeBall_PRY.b64`. Assert all reachable edges are represented, no raw `JUMP`/`JUMPBACK` evidence remains inside the region, and the result compiles.

- [ ] **Step 7: Verify and commit**

Run fallback/chunk tests, differential fixtures, full tests, and corpus gates. The protected sample must have fewer raw-flow evidence comments and no new unsupported output. Commit as `Preserve irreducible control flow with state fallback`.

---

### Task 7: Stage Diagnostics, CLI, And UI Details

**Files:**
- Create: `luau_decompiler/diagnostics.py`
- Create: `tests/test_diagnostics.py`
- Modify: `luau_decompiler/cli.py`
- Modify: `luau_decompiler/ui.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_ui.py`

**Interfaces:**
- Produces: `StageTiming`, `ProtoDiagnostics`, `DecompileDiagnostics`, and `decompile_with_diagnostics()`.
- Adds: CLI `--diagnostics` JSON output and UI `Diagnostics` mode.

- [ ] **Step 1: Write failing diagnostic aggregation tests**

Assert deterministic fields for bytecode version, proto/instruction count, reachable/unreachable blocks, natural/irreducible regions, evidence reasons, and nonnegative stage durations.

- [ ] **Step 2: Verify RED**

Run `python -m unittest tests.test_diagnostics -v`; expect missing-module failure.

- [ ] **Step 3: Implement optional timing and graph summaries**

Use `time.perf_counter()` around decode, CFG, region, reconstruction, and print boundaries. Collection occurs only when requested and never changes normal source.

- [ ] **Step 4: Add CLI tests and `--diagnostics`**

`flow-decompiler input --diagnostics` prints JSON instead of source. It is mutually exclusive with `--disasm` and `--summary`; invalid combinations return argparse code 2.

Add a Windows-console regression using a text stream configured as CP1252 and reconstructed source containing `U+2605 BLACK STAR`. Route CLI writes through a UTF-8-safe helper that uses the stream's binary buffer when the active text encoding cannot represent the output; preserve ordinary redirected text streams and do not replace characters.

- [ ] **Step 5: Add UI tests and Diagnostics mode**

Extend `MODES`, add one compact mode button, render formatted JSON through the existing worker queue, and preserve stale-render cancellation/loading behavior.

- [ ] **Step 6: Verify and commit**

Run diagnostics/CLI/UI tests and full tests. Commit as `Expose semantic reconstruction diagnostics`.

---

### Task 8: Corpus, Performance, Installer, And Release Gate

**Files:**
- Modify: `luau_decompiler/quality.py`
- Modify: `luau_decompiler/quality_cli.py`
- Modify: `tests/test_quality.py`
- Modify: `README.md`
- Modify: `pyproject.toml`
- Modify: `install.ps1` only if entry-point installation requires it

**Interfaces:**
- Extends quality output with structured-region, irreducible-region, and evidence-reason totals.
- Produces the final verified release candidate.

- [ ] **Step 1: Write failing quality aggregation tests**

Add semantic diagnostic totals to `SampleQuality` and `QualityReport` while preserving all existing fields and JSON names.

- [ ] **Step 2: Verify RED and implement integration**

Run `python -m unittest tests.test_quality -v`; expect missing-field failure. Aggregate Task 7 diagnostics, rerun, and expect PASS.

- [ ] **Step 3: Run unit and differential gates**

Run `python -m unittest discover -s tests` and `flow-differential` with Luau 0.729. All tests and deterministic fixtures must pass.

- [ ] **Step 4: Run live corpus gate**

Run `flow-quality` against the original checkout's `live_samples` with the official compiler. Require 80 valid parses, 80 syntax passes, zero syntax failures, zero unknown opcodes, zero unsupported comments, no evidence increase above 342, and removal of targeted reducible raw-flow evidence.

- [ ] **Step 5: Measure performance**

Run each documented benchmark five times after one warmup and compare medians. Neither may regress by more than 20 percent.

- [ ] **Step 6: Verify installation**

Create a clean temporary venv, install editable, run help for all four commands, import `luau_decompiler.ui`, and smoke-test the existing installer with `-NoDesktopShortcut` where safe.

- [ ] **Step 7: Update documentation and version**

Document architecture, differential checks, limits, diagnostics, measured corpus/evidence/performance results, and compatibility. Bump `pyproject.toml` only after every gate passes.

- [ ] **Step 8: Run final repository checks**

Run `python -m compileall -q luau_decompiler tests tools`, `git diff --check`, and `git status --short`. Confirm no live/generated files are staged.

- [ ] **Step 9: Commit**

Stage only the quality, test, README, version, and necessary installer changes. Commit as `Release Flow semantic core`.
