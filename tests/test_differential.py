from __future__ import annotations

from dataclasses import FrozenInstanceError
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from luau_decompiler.differential import (
    LuauToolchain,
    ProcessResult,
    check_roundtrip,
    compare_results,
    compile_source,
    execute_source,
)
from luau_decompiler.differential_cli import main


class DifferentialComparisonTests(unittest.TestCase):
    def test_compare_results_accepts_identical_observations(self):
        result = compare_results(
            ProcessResult(0, "ok\n", ""),
            ProcessResult(0, "ok\n", ""),
        )

        self.assertTrue(result.equivalent)
        self.assertIsNone(result.mismatch)

    def test_compare_results_reports_stdout_mismatch(self):
        result = compare_results(
            ProcessResult(0, "left\n", ""),
            ProcessResult(0, "right\n", ""),
        )

        self.assertFalse(result.equivalent)
        self.assertIn("stdout", result.mismatch or "")

    def test_process_results_are_immutable(self):
        result = ProcessResult(0, "", "")

        with self.assertRaises(FrozenInstanceError):
            result.stdout = "changed"


class DifferentialToolchainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.toolchain = LuauToolchain(Path("luau-compile"), Path("luau"), timeout_seconds=2.5)

    def test_compile_source_uses_official_binary_mode_and_utf8_source(self):
        source = 'print("caf\u00e9")\n'

        def completed(args, **_kwargs):
            self.assertEqual(args[:2], ["luau-compile", "--binary"])
            self.assertEqual(Path(args[2]).read_bytes(), source.encode("utf-8"))
            return Mock(returncode=0, stdout=b"bytecode", stderr=b"")

        with patch("luau_decompiler.differential.subprocess.run", side_effect=completed) as run:
            result = compile_source(source, self.toolchain)

        self.assertEqual(result, b"bytecode")
        self.assertEqual(run.call_args.kwargs, {"capture_output": True, "timeout": 2.5})

    def test_execute_source_uses_runtime_command_and_utf8_text_output(self):
        source = 'print("caf\u00e9")\n'

        def completed(args, **_kwargs):
            self.assertEqual(args[0], "luau")
            self.assertEqual(Path(args[1]).read_bytes(), source.encode("utf-8"))
            return Mock(returncode=3, stdout="out\n", stderr="err\n")

        with patch("luau_decompiler.differential.subprocess.run", side_effect=completed) as run:
            result = execute_source(source, self.toolchain)

        self.assertEqual(result, ProcessResult(3, "out\n", "err\n"))
        self.assertEqual(
            run.call_args.kwargs,
            {"capture_output": True, "text": True, "encoding": "utf-8", "timeout": 2.5},
        )

    def test_execute_source_normalizes_timeouts(self):
        timeout = subprocess.TimeoutExpired(["luau", "fixture.luau"], 2.5)

        with patch("luau_decompiler.differential.subprocess.run", side_effect=timeout):
            result = execute_source("print('never')\n", self.toolchain)

        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, -1)
        self.assertIn("timed out", result.stderr)

    def test_check_roundtrip_compiles_decompiles_and_compares_execution(self):
        original = ProcessResult(0, "same\n", "")
        reconstructed = ProcessResult(0, "same\n", "")
        chunk = object()
        with patch("luau_decompiler.differential.compile_source", return_value=b"bytecode") as compile_run, patch(
            "luau_decompiler.differential.parse_chunk", return_value=chunk
        ) as parse, patch("luau_decompiler.differential.decompile_chunk", return_value="print('same')\n") as decompile, patch(
            "luau_decompiler.differential._execute_path",
            side_effect=[original, reconstructed],
        ) as execute:
            result = check_roundtrip("print('same')\n", self.toolchain)

        self.assertTrue(result.equivalent)
        self.assertEqual(result.source, "print('same')\n")
        self.assertEqual(result.reconstructed_source, "print('same')\n")
        compile_run.assert_called_once_with("print('same')\n", self.toolchain)
        parse.assert_called_once_with(b"bytecode")
        decompile.assert_called_once_with(chunk)
        self.assertEqual(execute.call_args_list[0].args[1], self.toolchain)
        self.assertEqual(execute.call_args_list[1].args[1], self.toolchain)
        self.assertEqual(execute.call_args_list[0].args[0], execute.call_args_list[1].args[0])

    def test_check_roundtrip_reuses_one_path_for_exact_stderr_comparison(self):
        chunk = object()
        execution_paths: list[str] = []

        def completed(args, **_kwargs):
            execution_paths.append(args[1])
            return Mock(returncode=1, stdout="", stderr=f"{args[1]}: boom\n")

        with patch("luau_decompiler.differential.compile_source", return_value=b"bytecode"), patch(
            "luau_decompiler.differential.parse_chunk", return_value=chunk
        ), patch("luau_decompiler.differential.decompile_chunk", return_value="error('boom')\n"), patch(
            "luau_decompiler.differential.subprocess.run", side_effect=completed
        ):
            result = check_roundtrip("error('boom')\n", self.toolchain)

        self.assertTrue(result.equivalent)
        self.assertEqual(len(execution_paths), 2)
        self.assertEqual(execution_paths[0], execution_paths[1])


class DifferentialCliTests(unittest.TestCase):
    def test_repository_fixtures_are_discovered_and_executed(self):
        fixtures = Path(__file__).parent / "fixtures" / "differential"
        expected_names = {
            "control_flow.luau",
            "multi_return.luau",
            "closures_tables.luau",
            "short_circuit_branches.luau",
            "loops.luau",
            "varargs_results.luau",
            "tables_methods.luau",
            "captures.luau",
        }
        original = ProcessResult(0, "ok\n", "")
        equivalent = compare_results(original, original)
        stdout = io.StringIO()

        with patch(
            "luau_decompiler.differential_cli.check_roundtrip",
            return_value=equivalent,
        ) as check, redirect_stdout(stdout):
            result = main([str(fixtures), "--compiler", "luau-compile", "--runtime", "luau", "--json"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual({Path(item["path"]).name for item in payload}, expected_names)
        self.assertEqual(check.call_count, len(expected_names))

    def test_cli_reports_each_directory_fixture_as_json_and_fails_mismatches(self):
        original = ProcessResult(0, "ok\n", "")
        equivalent = compare_results(original, original, "print('ok')\n", "print('ok')\n")
        mismatch = compare_results(
            original,
            ProcessResult(0, "different\n", ""),
            "print('ok')\n",
            "print('different')\n",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "first.luau").write_text("print('first')\n", encoding="utf-8")
            nested = root / "nested"
            nested.mkdir()
            (nested / "second.luau").write_text("print('second')\n", encoding="utf-8")
            (root / "ignored.txt").write_text("not a fixture\n", encoding="utf-8")
            stdout = io.StringIO()

            with patch(
                "luau_decompiler.differential_cli.check_roundtrip",
                side_effect=[equivalent, mismatch],
            ) as check, redirect_stdout(stdout):
                result = main([str(root), "--compiler", "luau-compile", "--runtime", "luau", "--json"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(result, 1)
        self.assertEqual([item["path"] for item in payload], [str(root / "first.luau"), str(nested / "second.luau")])
        self.assertTrue(payload[0]["equivalent"])
        self.assertFalse(payload[1]["equivalent"])
        self.assertEqual(check.call_count, 2)

    def test_cli_requires_both_official_tool_paths(self):
        stderr = io.StringIO()

        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            main(["fixture.luau"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--compiler", stderr.getvalue())

    def test_cli_fails_when_a_tool_cannot_process_a_fixture(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = Path(temp_dir) / "fixture.luau"
            fixture.write_text("print('fixture')\n", encoding="utf-8")
            stdout = io.StringIO()

            with patch(
                "luau_decompiler.differential_cli.check_roundtrip",
                side_effect=RuntimeError("compiler was not found"),
            ), redirect_stdout(stdout):
                result = main([str(fixture), "--compiler", "luau-compile", "--runtime", "luau", "--json"])

        self.assertEqual(result, 1)
        self.assertEqual(json.loads(stdout.getvalue()), [{"path": str(fixture), "error": "compiler was not found"}])

    def test_cli_reports_matched_timeouts_before_equivalence_in_text_mode(self):
        timed_out = ProcessResult(-1, "", "timed out", timed_out=True)
        equivalent = compare_results(timed_out, timed_out)
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = Path(temp_dir) / "fixture.luau"
            fixture.write_text("print('fixture')\n", encoding="utf-8")
            stdout = io.StringIO()

            with patch("luau_decompiler.differential_cli.check_roundtrip", return_value=equivalent), redirect_stdout(stdout):
                result = main([str(fixture), "--compiler", "luau-compile", "--runtime", "luau"])

        self.assertEqual(result, 1)
        self.assertIn("tool execution failed", stdout.getvalue())
        self.assertIn("timed out", stdout.getvalue())
        self.assertNotIn("equivalent", stdout.getvalue())

    def test_cli_reports_matched_tool_failures_before_equivalence_in_text_mode(self):
        failed = ProcessResult(-1, "", "executable not found")
        equivalent = compare_results(failed, failed)
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = Path(temp_dir) / "fixture.luau"
            fixture.write_text("print('fixture')\n", encoding="utf-8")
            stdout = io.StringIO()

            with patch("luau_decompiler.differential_cli.check_roundtrip", return_value=equivalent), redirect_stdout(stdout):
                result = main([str(fixture), "--compiler", "luau-compile", "--runtime", "luau"])

        self.assertEqual(result, 1)
        self.assertIn("tool execution failed", stdout.getvalue())
        self.assertNotIn("equivalent", stdout.getvalue())

    def test_cli_reports_parser_limit_failures_per_fixture(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = Path(temp_dir) / "fixture.luau"
            fixture.write_text("print('fixture')\n", encoding="utf-8")
            stdout = io.StringIO()

            with patch(
                "luau_decompiler.differential_cli.check_roundtrip",
                side_effect=ValueError("bytecode version 12 is outside supported range"),
            ), redirect_stdout(stdout):
                result = main([str(fixture), "--compiler", "luau-compile", "--runtime", "luau", "--json"])

        self.assertEqual(result, 1)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            [{"path": str(fixture), "error": "bytecode version 12 is outside supported range"}],
        )


if __name__ == "__main__":
    unittest.main()
