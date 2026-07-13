# Flow Decompiler

Flow Decompiler is a local Luau bytecode parser, disassembler, CFG builder, and source reconstruction tool.

It is built for Roblox Luau bytecode work. It can parse serialized chunks, decode Roblox encoded opcode streams, print disassembly, summarize bytecode evidence, and reconstruct readable Luau for common script shapes.

## Install

```powershell
python -m pip install -e .
```

Python 3.10 or newer is required.

## Use

From the repo:

```powershell
python -m luau_decompiler path\to\chunk.luauc
python -m luau_decompiler path\to\bytecode.b64
python -m luau_decompiler path\to\bytecode.b64 --disasm
python -m luau_decompiler path\to\bytecode.b64 --summary
```

After install:

```powershell
flow-decompiler path\to\bytecode.b64
flow-decompiler-ui
```

`.b64`, `.base64`, and `.txt` inputs are read as base64 text. Other inputs are read as raw bytecode.

## Executor Capture

In a Roblox executor:

```lua
local encoder = base64_encode or (crypt and crypt.base64 and crypt.base64.encode)
local bytecode = getscriptbytecode(targetScript)
writefile("target.bytecode.b64", encoder(bytecode))
```

Then decompile the saved file:

```powershell
flow-decompiler target.bytecode.b64
```

For local live captures, start the receiver:

```powershell
python tools\receive_bytecode.py --out live_samples --count 1
```

Then POST base64 bytecode to `http://127.0.0.1:18765`. The helper writes each POST body as a `.b64` file, using the optional `x-sample-name` header for the filename.

Captured `.b64` files can be opened in the UI:

```powershell
python -m luau_decompiler.ui live_samples\target.bytecode.b64
```

They can also be used with the CLI:

```powershell
flow-decompiler live_samples\target.bytecode.b64
flow-decompiler live_samples\target.bytecode.b64 --disasm
```

## What It Handles

- Luau bytecode versions 3 through 11
- Roblox encoded opcode streams from live `getscriptbytecode` captures
- imports, constants, protos, debug locals, upvalues, line info, and feedback slots
- calls, namecalls, field access, globals, arithmetic, logic, concat, vectors, table literals, and closures
- `if`, `elseif`, `while`, `repeat`, numeric `for`, generic `for`, `break`, and `continue`
- Luau if-expressions, including simple `elseif` expression chains
- readable Roblox idioms such as `game:GetService`, `WaitForChild`, `CharacterAdded:Wait`, `FireServer`, and `InvokeServer`
- safe materialization of reused call results so side-effecting calls are not duplicated
- register-aware local spilling and wide-result packing to stay below Luau's 200-local limit
- readable function assignments, table methods, closure captures, and common module patterns

Unsupported instructions are left as comments instead of being hidden.

## Tests

```powershell
python -m unittest discover -s tests
```

## Quality Report

Run Flow across a directory of raw or base64 chunks:

```powershell
flow-quality live_samples
flow-quality live_samples --json
```

To syntax-check every reconstructed source file with an official Luau compiler:

```powershell
flow-quality live_samples --compiler C:\path\to\luau-compile.exe --fail-on-syntax
```

The report separates parse failures, unknown instructions, evidence comments, unsupported output, and Luau syntax failures. Explicit `.txt` files remain accepted, while directory scans only include `.b64`, `.base64`, and `.luauc` files so generated reports are not mistaken for bytecode.

The current regression corpus contains 80 valid live captures with 4,416 protos and 539,890 decoded instructions. Flow 0.2.2 produces syntax-valid Luau for all 80, with zero unknown opcodes and zero unsupported comments. Invalid or non-bytecode files are reported separately instead of being hidden.

## Performance

Flow caches repeated control-flow analysis and indexes jump targets once per prototype. On the development test machine, a 136,822-instruction capture completes in about 2.4 seconds, and a 385-proto UI capture with 20,768 instructions completes in about 1.9 seconds. Large UI results are inserted in chunks so the window remains responsive.

## Notes

This is a source reconstruction tool, not a promise of original source. Decompiled variable names and structure are best-effort unless the bytecode includes debug metadata.
