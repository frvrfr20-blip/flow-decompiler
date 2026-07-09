from __future__ import annotations

import base64
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .binary import maybe_base64_decode
from .chunk import parse_chunk
from .decompile import decompile_chunk


DEFAULT_FISSION_ENDPOINT = "http://127.0.0.1:31337/luau/decompile"
BASE64_SUFFIXES = {".b64", ".base64", ".txt"}


@dataclass(frozen=True)
class SourceMetrics:
    lines: int
    evidence_comments: int
    unsupported_comments: int


@dataclass(frozen=True)
class ComparisonResult:
    path: str
    exact: bool
    body_exact: bool
    ours: str
    fission: str
    ours_metrics: SourceMetrics
    fission_metrics: SourceMetrics


@dataclass(frozen=True)
class ComparisonFailure:
    path: str
    stage: str
    error: str
    ours: str = ""
    ours_metrics: SourceMetrics | None = None


@dataclass(frozen=True)
class ComparisonSummary:
    total: int
    succeeded: int
    failed: int
    exact: int
    body_exact: int
    mismatched: int
    body_mismatched: int
    ours_lines: int
    fission_lines: int
    ours_evidence_comments: int
    fission_evidence_comments: int
    ours_unsupported_comments: int
    fission_unsupported_comments: int


def load_input_as_base64(path: Path) -> str:
    data = path.read_bytes()
    if path.suffix.lower() in BASE64_SUFFIXES:
        stripped = b"".join(data.split())
        try:
            base64.b64decode(stripped, validate=True)
        except Exception as exc:
            raise ValueError(f"{path} is marked as base64 but does not contain valid base64") from exc
        return stripped.decode("ascii")
    return base64.b64encode(data).decode("ascii")


def decompile_ours_from_base64(base64_text: str) -> str:
    return decompile_chunk(parse_chunk(maybe_base64_decode(base64_text.encode("ascii"))))


def decompile_fission(
    base64_text: str,
    *,
    endpoint: str = DEFAULT_FISSION_ENDPOINT,
    timeout: float = 10,
) -> str:
    request = urllib.request.Request(
        endpoint,
        data=base64_text.encode("ascii"),
        headers={"content-type": "text/plain; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Fission returned HTTP {exc.code}: {body}") from exc
    except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
        raise RuntimeError(f"could not reach Fission at {endpoint}: {exc}") from exc


def source_metrics(source: str) -> SourceMetrics:
    lines = [line for line in source.splitlines() if line.strip()]
    evidence_comments = 0
    unsupported_comments = 0
    for line in lines:
        normalized = line.strip().lower()
        marks_gap = (
            normalized.startswith("-- pc")
            or "unsupported" in normalized
            or "encoded opcode" in normalized
        )
        if normalized.startswith("--") and marks_gap:
            evidence_comments += 1
        if "unsupported" in normalized or "encoded opcode" in normalized:
            unsupported_comments += 1
    return SourceMetrics(
        lines=len(lines),
        evidence_comments=evidence_comments,
        unsupported_comments=unsupported_comments,
    )


def source_body(source: str) -> str:
    lines = source.splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped:
            index += 1
            continue
        if stripped.startswith("--[["):
            if "]]" in stripped:
                index += 1
                continue
            index += 1
            while index < len(lines) and "]]" not in lines[index]:
                index += 1
            if index < len(lines):
                index += 1
            continue
        if stripped.startswith("--"):
            index += 1
            continue
        break
    return "\n".join(line.rstrip() for line in lines[index:]).strip()


def compare_path(
    path: Path,
    *,
    endpoint: str = DEFAULT_FISSION_ENDPOINT,
    timeout: float = 10,
) -> ComparisonResult:
    base64_text = load_input_as_base64(path)
    ours = decompile_ours_from_base64(base64_text)
    fission = decompile_fission(base64_text, endpoint=endpoint, timeout=timeout)
    return ComparisonResult(
        path=str(path),
        exact=ours.strip() == fission.strip(),
        body_exact=source_body(ours) == source_body(fission),
        ours=ours,
        fission=fission,
        ours_metrics=source_metrics(ours),
        fission_metrics=source_metrics(fission),
    )


def compare_path_record(
    path: Path,
    *,
    endpoint: str = DEFAULT_FISSION_ENDPOINT,
    timeout: float = 10,
) -> ComparisonResult | ComparisonFailure:
    try:
        base64_text = load_input_as_base64(path)
    except Exception as exc:
        return ComparisonFailure(path=str(path), stage="load", error=str(exc))
    try:
        ours = decompile_ours_from_base64(base64_text)
    except Exception as exc:
        return ComparisonFailure(path=str(path), stage="ours", error=str(exc))
    ours_metrics = source_metrics(ours)
    try:
        fission = decompile_fission(base64_text, endpoint=endpoint, timeout=timeout)
    except Exception as exc:
        return ComparisonFailure(
            path=str(path),
            stage="fission",
            error=str(exc),
            ours=ours,
            ours_metrics=ours_metrics,
        )
    return ComparisonResult(
        path=str(path),
        exact=ours.strip() == fission.strip(),
        body_exact=source_body(ours) == source_body(fission),
        ours=ours,
        fission=fission,
        ours_metrics=ours_metrics,
        fission_metrics=source_metrics(fission),
    )


def summarize_results(results: Iterable[ComparisonResult | ComparisonFailure]) -> ComparisonSummary:
    results = list(results)
    successes = [result for result in results if isinstance(result, ComparisonResult)]
    failures = [result for result in results if isinstance(result, ComparisonFailure)]
    exact = sum(1 for result in successes if result.exact)
    body_exact = sum(1 for result in successes if result.body_exact)
    return ComparisonSummary(
        total=len(results),
        succeeded=len(successes),
        failed=len(failures),
        exact=exact,
        body_exact=body_exact,
        mismatched=len(successes) - exact,
        body_mismatched=len(successes) - body_exact,
        ours_lines=sum(result.ours_metrics.lines for result in successes)
        + sum(result.ours_metrics.lines for result in failures if result.ours_metrics is not None),
        fission_lines=sum(result.fission_metrics.lines for result in successes),
        ours_evidence_comments=sum(result.ours_metrics.evidence_comments for result in successes)
        + sum(result.ours_metrics.evidence_comments for result in failures if result.ours_metrics is not None),
        fission_evidence_comments=sum(result.fission_metrics.evidence_comments for result in successes),
        ours_unsupported_comments=sum(result.ours_metrics.unsupported_comments for result in successes)
        + sum(result.ours_metrics.unsupported_comments for result in failures if result.ours_metrics is not None),
        fission_unsupported_comments=sum(result.fission_metrics.unsupported_comments for result in successes),
    )
