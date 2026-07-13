from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from .differential import LuauToolchain, check_roundtrip


def _collect_sources(roots: list[Path]) -> list[Path]:
    paths: dict[str, Path] = {}
    for root in roots:
        if root.is_dir():
            for path in root.rglob("*.luau"):
                if path.is_file():
                    paths[str(path.resolve()).lower()] = path
        else:
            paths[str(root.resolve()).lower()] = root
    return sorted(paths.values(), key=str)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare original Luau fixtures with Flow reconstructions.")
    parser.add_argument("roots", nargs="+", type=Path, help="Luau source files or directories of .luau fixtures")
    parser.add_argument("--compiler", type=Path, required=True, help="Official Luau compiler executable")
    parser.add_argument("--runtime", type=Path, required=True, help="Official Luau runtime executable")
    parser.add_argument("--json", action="store_true", help="Print fixture results as JSON")
    return parser


def _failed_result(result) -> bool:
    return (
        not result.equivalent
        or result.original.timed_out
        or result.reconstructed.timed_out
        or result.original.returncode == -1
        or result.reconstructed.returncode == -1
    )


def _execution_failure(result: dict[str, object]) -> str | None:
    failures: list[str] = []
    for label in ("original", "reconstructed"):
        process = result[label]
        if not isinstance(process, dict):
            continue
        if process["timed_out"]:
            failures.append(f"{label} timed out")
        elif process["returncode"] == -1:
            failures.append(f"{label} could not run")
    return "; ".join(failures) or None


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    toolchain = LuauToolchain(args.compiler, args.runtime)
    results: list[dict[str, object]] = []
    failed = False
    for path in _collect_sources(args.roots):
        try:
            result = check_roundtrip(path.read_text(encoding="utf-8"), toolchain)
        except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
            results.append({"path": str(path), "error": str(exc)})
            failed = True
            continue
        results.append({"path": str(path), **asdict(result)})
        failed = failed or _failed_result(result)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            if "error" in result:
                print(f"{result['path']}: error: {result['error']}")
            elif failure := _execution_failure(result):
                print(f"{result['path']}: tool execution failed: {failure}")
            elif result["equivalent"]:
                print(f"{result['path']}: equivalent")
            else:
                print(f"{result['path']}: mismatch: {result['mismatch']}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
