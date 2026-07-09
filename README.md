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

## What It Handles

- Luau bytecode versions 3 through 11
- Roblox encoded opcode streams from live `getscriptbytecode` captures
- imports, constants, protos, debug locals, upvalues, line info, and feedback slots
- calls, namecalls, field access, globals, arithmetic, logic, concat, vectors, table literals, and closures
- `if`, `elseif`, `while`, `repeat`, numeric `for`, generic `for`, `break`, and `continue`
- Luau if-expressions, including simple `elseif` expression chains
- readable Roblox idioms such as `game:GetService`, `WaitForChild`, `CharacterAdded:Wait`, `FireServer`, and `InvokeServer`
- safe materialization of reused call results so side-effecting calls are not duplicated
- readable function assignments, table methods, closure captures, and common module patterns

Unsupported instructions are left as comments instead of being hidden.

## Compare With Fission

If a local Fission server is running at `http://127.0.0.1:31337/luau/decompile`:

```powershell
python tools\compare_fission.py sample_namecall.b64 work_sample.b64 --keep-going
python tools\compare_fission.py work_sample.b64 --json
```

The comparison reports local output, Fission output, line counts, evidence comments, unsupported comments, exact matches, and body-exact matches.

## Tests

```powershell
python -m unittest discover -s tests
```

## Notes

This is a source reconstruction tool, not a promise of original source. Decompiled variable names and structure are best-effort unless the bytecode includes debug metadata.
