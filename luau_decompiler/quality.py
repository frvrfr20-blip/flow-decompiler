from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
import subprocess
import tempfile

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


def _load_sample(path: Path) -> bytes:
    data = path.read_bytes()
    if path.suffix.lower() in {".b64", ".base64", ".txt"}:
        return maybe_base64_decode(data)
    return data


def check_luau_syntax(source: str, compiler: Path) -> SyntaxResult:
    source_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".luau",
            encoding="utf-8",
            delete=False,
        ) as handle:
            handle.write(source)
            source_path = Path(handle.name)
        completed = subprocess.run(
            [str(compiler), "--null", str(source_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return SyntaxResult(False, str(exc))
    finally:
        if source_path is not None:
            source_path.unlink(missing_ok=True)

    if completed.returncode == 0:
        return SyntaxResult(True)
    error = (completed.stderr or completed.stdout).strip()
    error = error.replace(str(source_path), "<output>").replace(source_path.as_posix(), "<output>")
    return SyntaxResult(False, error or "Luau syntax check failed")


def analyze_sample(path: Path, syntax_checker: SyntaxChecker | None = None) -> SampleQuality:
    try:
        chunk = parse_chunk(_load_sample(path))
        source = decompile_chunk(chunk)
    except Exception as exc:
        return SampleQuality(path=str(path), parsed=False, parse_error=str(exc))

    source_lines = source.splitlines()
    evidence_comments = sum(line.lstrip().startswith("-- pc ") for line in source_lines)
    unsupported_comments = sum(
        "unsupported" in line.lower() or "encoded opcode" in line.lower()
        for line in source_lines
        if line.lstrip().startswith("--")
    )
    syntax = syntax_checker(source) if syntax_checker is not None else None
    return SampleQuality(
        path=str(path),
        parsed=True,
        proto_count=len(chunk.protos),
        instruction_count=sum(len(proto.instructions) for proto in chunk.protos),
        unknown_opcode_count=sum(
            insn.op.name.startswith(("UNKNOWN_", "ENCODED_"))
            for proto in chunk.protos
            for insn in proto.instructions
        ),
        evidence_comment_count=evidence_comments,
        unsupported_comment_count=unsupported_comments,
        output_line_count=len(source_lines),
        syntax_valid=syntax.valid if syntax is not None else None,
        syntax_error=syntax.error if syntax is not None else None,
    )


def analyze_corpus(paths: Iterable[Path], syntax_checker: SyntaxChecker | None = None) -> QualityReport:
    samples = tuple(analyze_sample(path, syntax_checker) for path in sorted(paths, key=str))
    parsed = tuple(sample for sample in samples if sample.parsed)
    syntax_checked = tuple(sample for sample in parsed if sample.syntax_valid is not None)
    return QualityReport(
        samples=samples,
        samples_total=len(samples),
        parse_passed=len(parsed),
        parse_failed=len(samples) - len(parsed),
        syntax_checked=len(syntax_checked),
        syntax_passed=sum(sample.syntax_valid is True for sample in syntax_checked),
        syntax_failed=sum(sample.syntax_valid is False for sample in syntax_checked),
        proto_count=sum(sample.proto_count for sample in parsed),
        instruction_count=sum(sample.instruction_count for sample in parsed),
        unknown_opcode_count=sum(sample.unknown_opcode_count for sample in parsed),
        evidence_comment_count=sum(sample.evidence_comment_count for sample in parsed),
        unsupported_comment_count=sum(sample.unsupported_comment_count for sample in parsed),
    )
