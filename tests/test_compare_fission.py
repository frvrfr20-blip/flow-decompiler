import base64
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path

from luau_decompiler import compare as compare_module
from luau_decompiler.compare import (
    ComparisonFailure,
    ComparisonResult,
    SourceMetrics,
    compare_path,
    compare_path_record,
    decompile_fission,
    load_input_as_base64,
    source_metrics,
)
from tools.compare_fission import _print_text_report, main as compare_main

from test_chunk import make_global_call_chunk


class _FissionHandler(BaseHTTPRequestHandler):
    body = b""
    response = b'print("fission")\n'

    def log_message(self, *_args):
        return

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        type(self).body = self.rfile.read(length)
        self.send_response(200)
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(type(self).response)


class CompareFissionTests(unittest.TestCase):
    def _serve_fission(self, response=b'print("fission")\n'):
        _FissionHandler.body = b""
        _FissionHandler.response = response
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FissionHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}/luau/decompile"

    def test_load_input_as_base64_preserves_text_files_and_encodes_raw_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            raw = temp_path / "chunk.luauc"
            text = temp_path / "chunk.b64"
            raw.write_bytes(b"\x04\x03raw")
            text.write_text("  YWJj\n", encoding="ascii")

            self.assertEqual(load_input_as_base64(text), "YWJj")
            self.assertEqual(load_input_as_base64(raw), base64.b64encode(b"\x04\x03raw").decode("ascii"))

    def test_decompile_fission_posts_raw_base64_body(self):
        endpoint = self._serve_fission()

        source = decompile_fission("YWJj", endpoint=endpoint, timeout=2)

        self.assertEqual(source, 'print("fission")\n')
        self.assertEqual(_FissionHandler.body, b"YWJj")

    def test_source_metrics_count_comments_that_mark_decompiler_gaps(self):
        metrics = source_metrics("-- pc 3: encoded opcode stream\nprint(x)\n-- unsupported FASTCALL\n")

        self.assertEqual(metrics.lines, 3)
        self.assertEqual(metrics.evidence_comments, 2)
        self.assertEqual(metrics.unsupported_comments, 2)

    def test_compare_path_reports_ours_fission_and_metrics(self):
        endpoint = self._serve_fission()
        encoded = base64.b64encode(make_global_call_chunk()).decode("ascii")
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "global_call.b64"
            path.write_text(encoded, encoding="ascii")

            result = compare_path(path, endpoint=endpoint, timeout=2)

        self.assertEqual(result.path.endswith("global_call.b64"), True)
        self.assertIn('print("hi")', result.ours)
        self.assertEqual(result.fission, 'print("fission")\n')
        self.assertEqual(result.exact, False)
        self.assertEqual(result.body_exact, False)
        self.assertGreaterEqual(result.ours_metrics.lines, 1)
        self.assertEqual(result.fission_metrics.lines, 1)

    def test_compare_path_reports_body_exact_ignoring_decompiler_preambles(self):
        endpoint = self._serve_fission(
            b"--[[ Decompiled with Fission ]]\n"
            b'print("hi")\n'
        )
        encoded = base64.b64encode(make_global_call_chunk()).decode("ascii")
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "global_call.b64"
            path.write_text(encoded, encoding="ascii")

            result = compare_path(path, endpoint=endpoint, timeout=2)

        self.assertEqual(result.exact, False)
        self.assertEqual(result.body_exact, True)

    def test_summarize_results_counts_matches_and_metrics(self):
        results = [
            ComparisonResult(
                path="one.b64",
                exact=True,
                body_exact=True,
                ours='print("one")\n',
                fission='print("one")\n',
                ours_metrics=SourceMetrics(lines=1, evidence_comments=0, unsupported_comments=0),
                fission_metrics=SourceMetrics(lines=1, evidence_comments=0, unsupported_comments=0),
            ),
            ComparisonResult(
                path="two.b64",
                exact=False,
                body_exact=True,
                ours="-- unsupported\nreturn nil\n",
                fission="return nil\n",
                ours_metrics=SourceMetrics(lines=2, evidence_comments=1, unsupported_comments=1),
                fission_metrics=SourceMetrics(lines=1, evidence_comments=0, unsupported_comments=0),
            ),
            ComparisonResult(
                path="three.b64",
                exact=False,
                body_exact=False,
                ours="return 1\n",
                fission="return 2\n",
                ours_metrics=SourceMetrics(lines=1, evidence_comments=0, unsupported_comments=0),
                fission_metrics=SourceMetrics(lines=1, evidence_comments=0, unsupported_comments=0),
            ),
        ]

        self.assertTrue(hasattr(compare_module, "summarize_results"))
        summary = compare_module.summarize_results(results)

        self.assertEqual(summary.total, 3)
        self.assertEqual(summary.exact, 1)
        self.assertEqual(summary.body_exact, 2)
        self.assertEqual(summary.mismatched, 2)
        self.assertEqual(summary.body_mismatched, 1)
        self.assertEqual(summary.ours_lines, 4)
        self.assertEqual(summary.fission_lines, 3)
        self.assertEqual(summary.ours_evidence_comments, 1)
        self.assertEqual(summary.fission_evidence_comments, 0)
        self.assertEqual(summary.ours_unsupported_comments, 1)
        self.assertEqual(summary.fission_unsupported_comments, 0)

    def test_text_report_prints_aggregate_for_multiple_results(self):
        results = [
            ComparisonResult(
                path="one.b64",
                exact=True,
                body_exact=True,
                ours='print("one")\n',
                fission='print("one")\n',
                ours_metrics=SourceMetrics(lines=1, evidence_comments=0, unsupported_comments=0),
                fission_metrics=SourceMetrics(lines=1, evidence_comments=0, unsupported_comments=0),
            ),
            ComparisonResult(
                path="two.b64",
                exact=False,
                body_exact=True,
                ours="-- unsupported\nreturn nil\n",
                fission="return nil\n",
                ours_metrics=SourceMetrics(lines=2, evidence_comments=1, unsupported_comments=1),
                fission_metrics=SourceMetrics(lines=1, evidence_comments=0, unsupported_comments=0),
            ),
        ]
        output = StringIO()

        with redirect_stdout(output):
            _print_text_report(results)

        text = output.getvalue()
        self.assertIn("Aggregate", text)
        self.assertIn("inputs: 2", text)
        self.assertIn("exact: 1/2", text)
        self.assertIn("body exact: 2/2", text)
        self.assertIn("ours totals: 3 lines, 1 evidence comments, 1 unsupported comments", text)
        self.assertIn("fission totals: 2 lines, 0 evidence comments, 0 unsupported comments", text)

    def test_compare_path_record_keeps_ours_output_when_fission_fails(self):
        class FailingHandler(_FissionHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", "0"))
                type(self).body = self.rfile.read(length)
                self.send_response(500)
                self.send_header("content-type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"fission blew up")

        server = ThreadingHTTPServer(("127.0.0.1", 0), FailingHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = f"http://127.0.0.1:{server.server_port}/luau/decompile"
        encoded = base64.b64encode(make_global_call_chunk()).decode("ascii")
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "global_call.b64"
            path.write_text(encoded, encoding="ascii")

            result = compare_path_record(path, endpoint=endpoint, timeout=2)

        self.assertIsInstance(result, ComparisonFailure)
        self.assertEqual(result.stage, "fission")
        self.assertIn("Fission returned HTTP 500", result.error)
        self.assertIn('print("hi")', result.ours)
        self.assertGreaterEqual(result.ours_metrics.lines, 1)

    def test_text_report_prints_failed_records_in_aggregate(self):
        results = [
            ComparisonResult(
                path="ok.b64",
                exact=True,
                body_exact=True,
                ours="return 1\n",
                fission="return 1\n",
                ours_metrics=SourceMetrics(lines=1, evidence_comments=0, unsupported_comments=0),
                fission_metrics=SourceMetrics(lines=1, evidence_comments=0, unsupported_comments=0),
            ),
            ComparisonFailure(
                path="bad.b64",
                stage="fission",
                error="Fission returned HTTP 500",
                ours="return 2\n",
                ours_metrics=SourceMetrics(lines=1, evidence_comments=0, unsupported_comments=0),
            ),
        ]
        output = StringIO()

        with redirect_stdout(output):
            _print_text_report(results)

        text = output.getvalue()
        self.assertIn("bad.b64", text)
        self.assertIn("failed at fission: Fission returned HTTP 500", text)
        self.assertIn("inputs: 2", text)
        self.assertIn("failed: 1", text)
        self.assertIn("succeeded: 1", text)

    def test_cli_keep_going_emits_json_failures_and_continues(self):
        class FailingHandler(_FissionHandler):
            count = 0

            def do_POST(self):
                type(self).count += 1
                length = int(self.headers.get("content-length", "0"))
                type(self).body = self.rfile.read(length)
                if type(self).count == 1:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b"nope")
                    return
                self.send_response(200)
                self.send_header("content-type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b'print("second")\n')

        server = ThreadingHTTPServer(("127.0.0.1", 0), FailingHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = f"http://127.0.0.1:{server.server_port}/luau/decompile"
        encoded = base64.b64encode(make_global_call_chunk()).decode("ascii")
        with tempfile.TemporaryDirectory() as temp_dir:
            first = Path(temp_dir) / "first.b64"
            second = Path(temp_dir) / "second.b64"
            first.write_text(encoded, encoding="ascii")
            second.write_text(encoded, encoding="ascii")
            output = StringIO()

            with redirect_stdout(output):
                exit_code = compare_main([str(first), str(second), "--endpoint", endpoint, "--json", "--keep-going"])

        payload = __import__("json").loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(payload[0]["stage"], "fission")
        self.assertEqual(payload[1]["fission"], 'print("second")\n')


if __name__ == "__main__":
    unittest.main()
