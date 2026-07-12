# Flow Decompiler Quality Program

## Goal

Improve Flow across the three outcomes that matter for real Roblox Luau work:

1. Decode and parse more valid bytecode without crashing or dropping instructions.
2. Preserve program semantics across registers, calls, closures, tables, and control flow.
3. Emit readable Luau without hiding uncertainty or inventing unsupported behavior.

This is a staged quality program, not a claim that arbitrary future, malformed, encrypted, or virtualized bytecode can always be reconstructed into original source.

## Compatibility

- Preserve the existing CLI commands, flags, output modes, UI workflow, installer, and accepted input formats.
- Keep existing successful reconstructions stable unless a test demonstrates that the old output is incorrect.
- Continue accepting raw Luau chunks and base64 text.
- Keep Flow as the only decompiler in the documented Roblox workflow.

## Architecture

Flow will move incrementally toward a five-stage pipeline:

1. **Decode:** Parse the chunk and decode every supported Luau opcode and AUX word into explicit instruction data.
2. **Control flow:** Build basic blocks, edges, dominance facts, loop regions, and branch joins.
3. **Value IR:** Track register versions, multi-return values, open calls, table identity, captures, and side effects without immediately formatting source text.
4. **Structured AST:** Recover expressions, statements, conditions, loops, closures, and assignments from IR and CFG evidence.
5. **Printer:** Emit valid, readable Luau with deterministic formatting and precise evidence comments where reconstruction is incomplete.

The migration will be incremental. Existing proven reconstruction paths can remain while focused instruction families move behind explicit IR interfaces. A full rewrite is out of scope for a single change set.

## Work Stages

### Stage 1: Corpus And Quality Harness

- Inventory opcode, AUX, chunk-version, and data-type coverage.
- Build source-to-bytecode fixtures for language features when a compatible Luau compiler is available.
- Add curated raw chunks for parser edge cases and Roblox-encoded opcode streams.
- Add sanitized live samples captured through Roblox MCP when its tools are exposed to the session.
- Record deterministic quality metrics for each corpus run.

### Stage 2: Decoder And Parser Completeness

- Validate instruction widths and AUX consumption centrally.
- Reject truncated or invalid chunks with byte offsets and actionable errors.
- Preserve unknown instructions in disassembly instead of desynchronizing later instructions.
- Cover constants, userdata types, vectors, debug metadata, nested protos, and chunk-version differences.

### Stage 3: Register And Call Semantics

- Model register versions and snapshots explicitly.
- Preserve call argument ranges, fixed/open result counts, varargs, and FASTCALL fallbacks.
- Preserve table identity, aliases, mutation order, and multi-return assignment behavior.
- Prevent stale or overwritten register expressions from leaking into later statements.

### Stage 4: Closures And Control Flow

- Preserve value and reference captures, upvalue identity, recursive closures, and closure lifetimes.
- Improve branch joins, short-circuit expressions, loops, break/continue, repeat-until, and generic/numeric for reconstruction.
- Use CFG evidence to avoid emitting unreachable or duplicated statements.

### Stage 5: Readability

- Infer stable names from debug metadata, Roblox service/import paths, common object roles, and usage.
- Materialize locals only when needed for identity, mutation, reuse, or clarity.
- Normalize expression precedence, table formatting, closure formatting, and statement ordering.
- Keep output deterministic so regressions are easy to review.

## Quality Metrics

Every improvement pass will report:

- Corpus files parsed successfully.
- Protos and instructions decoded.
- Unknown or unsupported opcode count.
- Evidence/unsupported comment count.
- Reconstructed output that passes Luau syntax compilation when a compiler is available.
- Expected structural assertions for calls, closures, loops, assignments, and returns.
- Crash count and malformed-input diagnostic coverage.
- Existing regression suite pass count.

Metrics guide work but do not replace semantic assertions. Fewer comments are not an improvement if the tool silently emits incorrect source.

## Live MCP Workflow

When Roblox executor MCP tools are callable:

1. List clients and select the intended session.
2. Locate representative LocalScripts and ModuleScripts without executing game-changing code.
3. Capture exact `getscriptbytecode` bytes and store sanitized base64 fixtures under a deliberate test-data location.
4. Run Flow source, disassembly, and summary modes on the same bytes.
5. Convert concrete failures into minimized regression tests before changing reconstruction code.

Read-only discovery and bytecode capture are preferred. Executing behavior-changing code in an unfamiliar live game still requires explicit confirmation.

## Error Handling

- Parser errors identify the byte offset, section, and expected data where possible.
- Unsupported instructions remain visible with PC, opcode, operands, and raw word.
- Reconstruction must not silently discard side effects or replace uncertain values with fabricated constants.
- A failed high-level reconstruction should still allow disassembly and summary modes when the chunk was parsed successfully.
- Malformed input must fail deterministically without hangs or unbounded allocation.

## Testing Strategy

- Use test-driven development for each discovered failure: failing fixture first, focused implementation second.
- Keep unit tests for binary parsing, opcode decoding, CFG edges, IR behavior, and printing.
- Add integration tests that run CLI modes over the corpus.
- Add property/fuzz tests for bounded binary-reader failures and instruction-width synchronization.
- Re-run the complete existing suite after each focused slice.
- Install the package and smoke-test the installed CLI/UI before release.

## Initial Implementation Slice

The first slice will establish the corpus/metrics harness and use it to select the highest-impact concrete decoder or reconstruction failures. It will not begin with cosmetic renaming or broad refactoring. The first code changes must be justified by failing corpus cases and must preserve existing CLI/UI behavior.

## Non-Goals

- Recovering original local names when no debug metadata or semantic evidence exists.
- Guaranteed devirtualization of custom VM obfuscators.
- Exact recovery of comments, formatting, or source constructs erased during compilation.
- Replacing Flow with or depending on another decompiler.
- A single high-risk rewrite of the current reconstruction engine.
