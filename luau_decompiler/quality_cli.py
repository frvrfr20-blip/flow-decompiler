from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil

from .quality import QualityReport, analyze_corpus, check_luau_syntax


CORPUS_SUFFIXES = {".b64", ".base64", ".luauc"}


def _resolve_compiler(value: Path) -> Path | None:
    if value.is_file():
        return value.resolve()
    command = shutil.which(str(value))
    return Path(command) if command else None


def _collect_paths(roots: list[Path]) -> list[Path]:
    paths: dict[str, Path] = {}
    for root in roots:
        if root.is_dir():
            for path in root.rglob("*"):
                if path.is_file() and path.suffix.lower() in CORPUS_SUFFIXES:
                    paths[str(path.resolve()).lower()] = path
        else:
            paths[str(root.resolve()).lower()] = root
    return sorted(paths.values(), key=str)


def _print_text(report: QualityReport) -> None:
    print(f"samples: {report.samples_total}")
    print(f"parse: {report.parse_passed} passed, {report.parse_failed} failed")
    if report.syntax_checked:
        print(f"syntax: {report.syntax_passed} passed, {report.syntax_failed} failed")
    else:
        print("syntax: not checked")
    print(f"protos: {report.proto_count}")
    print(f"instructions: {report.instruction_count}")
    print(f"unknown opcodes: {report.unknown_opcode_count}")
    print(f"evidence comments: {report.evidence_comment_count}")
    print(f"unsupported comments: {report.unsupported_comment_count}")
    for sample in report.samples:
        error = sample.parse_error or sample.syntax_error
        if error:
            print(f"\n{sample.path}\n{error}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Measure Flow Decompiler output across a bytecode corpus.")
    parser.add_argument("roots", nargs="+", type=Path, help="Bytecode files or directories to scan")
    parser.add_argument("--compiler", type=Path, help="Optional luau-compile executable for syntax checks")
    parser.add_argument("--json", action="store_true", help="Print the full report as JSON")
    parser.add_argument("--fail-on-parse", action="store_true", help="Exit nonzero when a sample cannot be parsed")
    parser.add_argument("--fail-on-syntax", action="store_true", help="Exit nonzero when reconstructed Luau is invalid")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    syntax_checker = None
    if args.compiler is not None:
        compiler = _resolve_compiler(args.compiler)
        if compiler is None:
            parser.error(f"compiler was not found: {args.compiler}")
        syntax_checker = lambda source: check_luau_syntax(source, compiler)
    report = analyze_corpus(_collect_paths(args.roots), syntax_checker)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_text(report)
    if args.fail_on_parse and report.parse_failed:
        return 1
    if args.fail_on_syntax and report.syntax_failed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
