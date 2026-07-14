# Flow Semantic Core Design

## Goal

Make Flow materially more accurate on real Roblox Luau by replacing local jump heuristics with reusable control-flow and value facts, validating reconstructed programs against official Luau tools, and preserving behavior when a graph cannot be rendered as ordinary structured source.

This is a major semantic-quality release. It is not a promise to recover comments, original names, erased syntax choices, encrypted payloads, or the original source of arbitrary custom virtual machines.

## Baseline

Flow 0.2.2 currently has:

- 268 passing unit and integration tests.
- 80 valid live captures containing 4,416 prototypes and 539,890 decoded instructions.
- 80/80 syntax-valid reconstructed outputs with the bundled Luau 0.729 compiler.
- Zero unknown opcodes and zero unsupported comments on the live corpus.
- 342 evidence comments, including 293 raw control-flow instructions in one protected capture.
- A 4,500-line `decompile.py` that mixes value tracking, region recognition, statement construction, and printing.

The release must improve semantic evidence without lowering any existing parser, syntax, CLI, UI, or performance gate.

## Chosen Approach

Use an incremental hybrid semantic core.

New CFG, data-flow, region, and diagnostic modules will provide explicit facts to the existing reconstructor. Proven reconstruction paths remain available while high-risk control-flow cases move to the new core. This avoids a single all-or-nothing rewrite and lets every behavior change begin with a failing regression test.

Two alternatives were rejected:

- A complete rewrite would create too large a regression surface before the new model had differential evidence.
- More local heuristics would increase coupling in `decompile.py` and would not solve joins, aliases, or irreducible control flow systematically.

## Pipeline

Flow will expose six internal stages:

1. **Decode:** Parse the chunk, validate bounded counts and instruction widths, and preserve exact PC/raw-word context.
2. **CFG facts:** Build blocks, successors, predecessors, reachability, dominators, post-dominators, back edges, natural loops, and strongly connected components.
3. **Value flow:** Track versioned register definitions, block inputs, joins, side effects, open/fixed call results, varargs, table identity, and capture identity.
4. **Regions:** Recover structured conditions, branches, loops, breaks, continues, and joins from graph facts.
5. **Fallback:** Render irreducible regions as an explicit program-counter state machine rather than silently dropping edges or leaving executable jumps as comments.
6. **Printer:** Emit deterministic, syntax-valid Luau and attach precise diagnostics only where semantics remain uncertain.

The existing CLI and UI continue to call `decompile_chunk`. New stages are internal and do not break public command names or input formats.

## CFG Facts

`cfg.py` will evolve from basic block construction into immutable graph analysis.

For every prototype it will provide:

- Instruction-to-block and PC-to-block lookup.
- Successor and predecessor sets.
- Reachable and unreachable blocks.
- Immediate dominator and post-dominator relationships.
- Back edges and natural loop membership.
- Strongly connected components and irreducible component detection.
- Deterministic block order independent of dictionary insertion behavior.

Terminal instructions have no fallthrough. AUX words remain attached to their owning instruction and never become block leaders.

## Value Flow

A focused `value_ir.py` module will represent values independently from source strings.

The initial IR includes:

- Register versions keyed by definition PC.
- Literals, globals, imports, fields, indexes, unary/binary expressions, calls, varargs, closures, and phi-like joins.
- Fixed and open call-result groups.
- Side-effect classification so calls and indexed reads are not duplicated or reordered.
- Table allocation identity and ordered mutations.
- Value and reference captures with stable identity across child closures.
- Explicit unknown values carrying proto, PC, opcode, and reason.

The IR is intentionally small. It will not try to model Roblox runtime object types or infer behavior not present in bytecode.

## Region Recovery

`regions.py` will consume CFG and value facts and return structured regions.

The first release covers:

- `if`, `elseif`, and `else` using post-dominator joins.
- Short-circuit `and` and `or` where branch values meet at one join.
- `while`, `repeat`, numeric `for`, and generic `for` using loop headers and back edges.
- Nested `break` and `continue` resolved against loop membership rather than target-distance guesses.
- Early returns and unreachable tails.
- Nested regions without duplicating shared join statements.

Regions that fail structural preconditions are not forced into misleading high-level syntax.

## Irreducible Fallback

Some protected or flattened functions have multiple-entry loops or branch patterns that cannot be expressed faithfully with ordinary Luau structured control flow.

For these regions Flow will emit a local state machine:

```lua
local flowState = 0
while true do
    if flowState == 0 then
        -- translated block statements
        flowState = 2
    elseif flowState == 2 then
        -- translated branch and next state
    else
        break
    end
end
```

The fallback must:

- Preserve every reachable edge and terminal action.
- Evaluate branch conditions and side effects once.
- Use collision-free generated names.
- Remain syntax-valid for large graphs and stay below Luau local/register limits.
- Be selected per irreducible region, not automatically for the whole prototype.
- Emit one concise region diagnostic instead of one raw comment per jump.

Readability is secondary to semantic honesty in this mode.

## Differential Correctness Harness

Syntax validity is necessary but not sufficient. A new differential harness will use official Luau binaries to:

1. Compile source fixtures to bytecode.
2. Decompile the bytecode with Flow.
3. Execute original and reconstructed source in separate sandboxed Luau processes.
4. Compare exit status and deterministic serialized output.

Fixtures must avoid filesystem, network, timing, randomness, Roblox APIs, and undefined table iteration order. They will cover:

- Arithmetic, comparisons, precedence, and short-circuit behavior.
- Nested branches and early returns.
- Numeric, generic, while, and repeat loops with break/continue.
- Fixed/open multi-return calls and varargs.
- Table construction, aliases, mutation order, and method calls.
- Closures, recursive functions, value captures, and reference captures.

The harness records compiler, runtime, timeout, and mismatch diagnostics. A timeout kills the child process and fails the fixture deterministically.

## Parser Hardening

Malformed input must fail without hangs, uncontrolled allocation, or vague tracebacks.

The parser will add configurable internal limits for:

- Chunk bytes.
- String count and individual string bytes.
- Prototype count and nesting.
- Instructions per prototype and total instructions.
- Constants, child references, locals, upvalues, and line metadata.

Errors include section, byte offset, proto ID when known, observed value, and allowed limit. Defaults must comfortably exceed the largest valid live sample.

Compatibility includes official Luau 0.729 bytecode version 12. Flow will honor each proto's declared serialized-size boundary, preserve optional inlining-cost metadata, reject framing overruns contextually, and skip only explicitly declared trailing proto bytes for forward compatibility.

## Diagnostics And Performance

Each decompilation will collect optional stage diagnostics:

- Decode, CFG, value-flow, region, and print duration.
- Structured and fallback region counts.
- Reachable/unreachable block counts.
- Unknown-value and evidence counts grouped by reason.
- Prototype and instruction totals.

Diagnostics are available through a new CLI JSON mode and a compact UI details view. Normal source output remains unchanged unless reconstruction improves.

Graph analyses are cached once per prototype. Algorithms use worklists and indexed PC/block maps rather than repeated full instruction scans.

Performance gates on the development machine:

- No more than 20 percent regression on the 136,822-instruction benchmark.
- No more than 20 percent regression on the 385-prototype UI benchmark.
- Differential fixtures complete within explicit per-process timeouts.

## Compatibility

- Preserve `flow-decompiler`, `flow-decompiler-ui`, and `flow-quality` commands.
- Preserve raw bytecode and `.b64`, `.base64`, and explicit `.txt` inputs.
- Preserve `--disasm`, `--summary`, current default source mode, installer behavior, startup settings, and saved UI settings.
- Add diagnostics through opt-in flags and UI controls only.
- Keep Python 3.10 as the minimum version and add no required third-party runtime dependencies.
- Keep Flow local and independent of Fission, lua.expert, or any remote decompiler.

## Testing And Release Gates

Every behavior change follows red-green-refactor and starts with a focused failing test.

The release gate requires:

- All existing tests pass.
- New CFG, value-flow, region, fallback, parser-limit, diagnostic, CLI, and UI tests pass.
- Every deterministic differential fixture matches original observable behavior.
- All 80 valid live captures parse and compile as Luau.
- Zero unknown opcodes and zero unsupported comments on the live corpus.
- No increase in total evidence comments unless a regression test proves the added diagnostic prevents fabricated behavior.
- Raw structured-flow evidence is eliminated from ordinary reducible samples targeted by this release.
- Performance stays within the stated limits.
- Editable install, installed CLI, installed UI import, and installer smoke tests pass.
- `git diff --check` passes and generated/live capture files remain untracked.

## Delivery Slices

1. Differential harness and immutable baseline metrics.
2. Full CFG facts with graph-level tests.
3. Versioned register/value foundation and side-effect model.
4. Post-dominator branch recovery and loop membership.
5. Irreducible-region state-machine fallback.
6. Parser limits and actionable diagnostics.
7. CLI/UI diagnostics and performance caching.
8. Corpus-driven fixes, documentation, installer verification, and release preparation.

Each slice must leave the repository green and independently reviewable.
