from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
import tempfile

from .chunk import parse_chunk
from .decompile import decompile_chunk


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass(frozen=True)
class DifferentialResult:
    equivalent: bool
    original: ProcessResult
    reconstructed: ProcessResult
    source: str
    reconstructed_source: str
    mismatch: str | None = None


@dataclass(frozen=True)
class LuauToolchain:
    compiler: Path
    runtime: Path
    timeout_seconds: float = 5.0


def compare_results(
    original: ProcessResult,
    reconstructed: ProcessResult,
    source: str = "",
    reconstructed_source: str = "",
) -> DifferentialResult:
    for field in ("timed_out", "returncode", "stdout", "stderr"):
        if getattr(original, field) != getattr(reconstructed, field):
            return DifferentialResult(
                False,
                original,
                reconstructed,
                source,
                reconstructed_source,
                f"{field} differs",
            )
    return DifferentialResult(True, original, reconstructed, source, reconstructed_source)


def compile_source(source: str, toolchain: LuauToolchain) -> bytes:
    source_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".luau",
            encoding="utf-8",
            newline="",
            delete=False,
        ) as handle:
            handle.write(source)
            source_path = Path(handle.name)
        completed = subprocess.run(
            [str(toolchain.compiler), "--binary", str(source_path)],
            capture_output=True,
            timeout=toolchain.timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Luau compilation failed: {exc}") from exc
    finally:
        if source_path is not None:
            source_path.unlink(missing_ok=True)

    if completed.returncode != 0:
        error = (completed.stderr or completed.stdout).decode("utf-8", errors="replace").strip()
        raise RuntimeError(error or "Luau compilation failed")
    return completed.stdout


def execute_source(source: str, toolchain: LuauToolchain) -> ProcessResult:
    source_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".luau",
            encoding="utf-8",
            newline="",
            delete=False,
        ) as handle:
            handle.write(source)
            source_path = Path(handle.name)
        completed = subprocess.run(
            [str(toolchain.runtime), str(source_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=toolchain.timeout_seconds,
        )
        return ProcessResult(completed.returncode, completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired as exc:
        return ProcessResult(-1, "", str(exc), timed_out=True)
    except OSError as exc:
        return ProcessResult(-1, "", str(exc))
    finally:
        if source_path is not None:
            source_path.unlink(missing_ok=True)


def check_roundtrip(source: str, toolchain: LuauToolchain) -> DifferentialResult:
    bytecode = compile_source(source, toolchain)
    reconstructed_source = decompile_chunk(parse_chunk(bytecode))
    original = execute_source(source, toolchain)
    reconstructed = execute_source(reconstructed_source, toolchain)
    return compare_results(original, reconstructed, source, reconstructed_source)
