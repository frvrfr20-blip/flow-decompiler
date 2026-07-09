from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .binary import maybe_base64_decode
from .chunk import parse_chunk
from .analysis import summarize_proto
from .decompile import decompile_chunk


def _load(path: Path) -> bytes:
    data = path.read_bytes()
    if path.suffix.lower() in {".b64", ".base64", ".txt"}:
        return maybe_base64_decode(data)
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Flow Decompiler: parse and reconstruct Luau bytecode chunks.")
    parser.add_argument("input", type=Path, help="Luau bytecode chunk, or base64 text with .b64/.txt suffix")
    parser.add_argument("--proto", type=int, default=None, help="Proto id to emit; defaults to chunk main proto")
    parser.add_argument("--disasm", action="store_true", help="Print disassembly instead of source skeleton")
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print JSON import/namecall/call/closure evidence instead of source",
    )
    args = parser.parse_args(argv)

    chunk = parse_chunk(_load(args.input))
    proto = chunk.protos[chunk.main_proto if args.proto is None else args.proto]

    if args.summary:
        print(json.dumps(asdict(summarize_proto(proto, chunk.protos)), indent=2))
    elif args.disasm:
        for insn in proto.instructions:
            print(insn.disassemble())
    else:
        print(decompile_chunk(chunk, args.proto), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
