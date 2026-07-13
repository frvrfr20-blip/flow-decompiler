from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from luau_decompiler.quality import (
    SyntaxResult,
    analyze_corpus,
    analyze_sample,
    check_luau_syntax,
)
from luau_decompiler.quality_cli import main
from tests.test_chunk import make_namecall_chunk


class QualityTests(unittest.TestCase):
    def test_analyze_sample_reports_chunk_and_source_metrics(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "namecall.luauc"
            path.write_bytes(make_namecall_chunk())

            result = analyze_sample(path)

        self.assertTrue(result.parsed)
        self.assertEqual(result.proto_count, 1)
        self.assertEqual(result.instruction_count, 4)
        self.assertEqual(result.unknown_opcode_count, 0)
        self.assertGreater(result.output_line_count, 0)
        self.assertIsNone(result.syntax_valid)

    def test_analyze_sample_keeps_parse_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad.luauc"
            path.write_bytes(b"\xff")

            result = analyze_sample(path)

        self.assertFalse(result.parsed)
        self.assertIn("bytecode version mismatch", result.parse_error or "")

    def test_analyze_corpus_aggregates_pass_and_failure_counts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "good.luauc").write_bytes(make_namecall_chunk())
            (root / "bad.luauc").write_bytes(b"\xff")

            report = analyze_corpus(sorted(root.iterdir()))

        self.assertEqual(report.samples_total, 2)
        self.assertEqual(report.parse_passed, 1)
        self.assertEqual(report.parse_failed, 1)

    def test_fresh_mcp_capture_is_analyzable(self):
        path = Path(__file__).parent / "fixtures" / "mcp_default_assign.b64"

        result = analyze_sample(path)

        self.assertTrue(result.parsed, result.parse_error)
        self.assertGreater(result.instruction_count, 0)
        self.assertEqual(result.unknown_opcode_count, 0)


class CompilerQualityTests(unittest.TestCase):
    def test_check_luau_syntax_uses_null_mode(self):
        completed = Mock(returncode=0, stdout="", stderr="")
        with patch("luau_decompiler.quality.subprocess.run", return_value=completed) as run:
            result = check_luau_syntax("return 1\n", Path("luau-compile"))

        self.assertTrue(result.valid)
        self.assertEqual(run.call_args.args[0][1], "--null")

    def test_quality_cli_emits_json_and_fails_on_syntax_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "namecall.luauc"
            path.write_bytes(make_namecall_chunk())
            stdout = io.StringIO()
            with patch(
                "luau_decompiler.quality_cli.check_luau_syntax",
                return_value=SyntaxResult(False, "bad syntax"),
            ), patch(
                "luau_decompiler.quality_cli._resolve_compiler",
                return_value=Path("luau-compile"),
            ), redirect_stdout(stdout):
                result = main([str(path), "--compiler", "luau-compile", "--json", "--fail-on-syntax"])

        self.assertEqual(result, 1)
        self.assertEqual(json.loads(stdout.getvalue())["syntax_failed"], 1)

    def test_directory_scan_ignores_generated_text_reports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "sample.b64").write_bytes(make_namecall_chunk())
            (root / "sample.disasm.txt").write_text("not bytecode", encoding="utf-8")
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                result = main([str(root), "--json"])

        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout.getvalue())["samples_total"], 1)

    def test_quality_cli_rejects_missing_compiler_before_analysis(self):
        stderr = io.StringIO()

        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            main(["sample.b64", "--compiler", "definitely-missing-luau-compile"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("compiler was not found", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
