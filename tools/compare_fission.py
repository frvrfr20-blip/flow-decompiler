from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from luau_decompiler.compare import ComparisonFailure, DEFAULT_FISSION_ENDPOINT, compare_path, compare_path_record, summarize_results


def _print_text_report(results) -> None:
    for index, result in enumerate(results):
        if index:
            print()
        print(result.path)
        if isinstance(result, ComparisonFailure):
            print(f"  failed at {result.stage}: {result.error}")
            if result.ours:
                print(
                    "  ours: "
                    f"{result.ours_metrics.lines if result.ours_metrics else 0} lines, "
                    f"{result.ours_metrics.evidence_comments if result.ours_metrics else 0} evidence comments, "
                    f"{result.ours_metrics.unsupported_comments if result.ours_metrics else 0} unsupported comments"
                )
                print("  ours source:")
                print(_indent(result.ours.rstrip() or "<empty>"))
            continue
        print(f"  exact: {result.exact}")
        print(f"  body exact: {result.body_exact}")
        print(
            "  ours: "
            f"{result.ours_metrics.lines} lines, "
            f"{result.ours_metrics.evidence_comments} evidence comments, "
            f"{result.ours_metrics.unsupported_comments} unsupported comments"
        )
        print(
            "  fission: "
            f"{result.fission_metrics.lines} lines, "
            f"{result.fission_metrics.evidence_comments} evidence comments, "
            f"{result.fission_metrics.unsupported_comments} unsupported comments"
        )
        print("  ours source:")
        print(_indent(result.ours.rstrip() or "<empty>"))
        print("  fission source:")
        print(_indent(result.fission.rstrip() or "<empty>"))
    if len(results) > 1:
        summary = summarize_results(results)
        print()
        print("Aggregate")
        print(f"  inputs: {summary.total}")
        print(f"  succeeded: {summary.succeeded}")
        print(f"  failed: {summary.failed}")
        print(f"  exact: {summary.exact}/{summary.succeeded}")
        print(f"  body exact: {summary.body_exact}/{summary.succeeded}")
        print(f"  mismatched: {summary.mismatched}")
        print(f"  body mismatched: {summary.body_mismatched}")
        print(
            "  ours totals: "
            f"{summary.ours_lines} lines, "
            f"{summary.ours_evidence_comments} evidence comments, "
            f"{summary.ours_unsupported_comments} unsupported comments"
        )
        print(
            "  fission totals: "
            f"{summary.fission_lines} lines, "
            f"{summary.fission_evidence_comments} evidence comments, "
            f"{summary.fission_unsupported_comments} unsupported comments"
        )


def _indent(text: str) -> str:
    return "\n".join(f"    {line}" for line in text.splitlines())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare Flow Decompiler output with a local Fission server.")
    parser.add_argument("inputs", nargs="+", type=Path, help="Luau bytecode chunk files or base64 text files")
    parser.add_argument("--endpoint", default=DEFAULT_FISSION_ENDPOINT, help="Fission HTTP decompile endpoint")
    parser.add_argument("--timeout", type=float, default=10, help="HTTP timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--keep-going", action="store_true", help="Record per-input failures and continue the batch")
    args = parser.parse_args(argv)

    try:
        if args.keep_going:
            results = [compare_path_record(path, endpoint=args.endpoint, timeout=args.timeout) for path in args.inputs]
        else:
            results = [compare_path(path, endpoint=args.endpoint, timeout=args.timeout) for path in args.inputs]
    except Exception as exc:
        print(f"comparison aborted: {exc}", file=sys.stderr)
        print("Use --keep-going to record per-input failure stages across a batch.", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps([asdict(result) for result in results], indent=2))
    else:
        _print_text_report(results)
    return 1 if any(isinstance(result, ComparisonFailure) for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
