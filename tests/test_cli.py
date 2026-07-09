import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from luau_decompiler.cli import main

from test_chunk import make_child_closure_chunk, make_global_call_chunk, make_namecall_chunk


class CliTests(unittest.TestCase):
    def test_summary_outputs_imports_namecalls_and_calls_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "namecall.b64"
            path.write_text(base64.b64encode(make_namecall_chunk()).decode("ascii"), encoding="ascii")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([str(path), "--summary"])

        payload = json.loads(stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertEqual(payload["imports"], ["game"])
        self.assertEqual(payload["namecalls"], ["FireServer"])
        self.assertEqual(payload["calls"], [{"pc": 4, "receiver": "game", "method": "FireServer", "args": []}])

    def test_summary_outputs_global_call_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "global_call.b64"
            path.write_text(base64.b64encode(make_global_call_chunk()).decode("ascii"), encoding="ascii")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([str(path), "--summary"])

        payload = json.loads(stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertEqual(payload["imports"], [])
        self.assertEqual(payload["namecalls"], [])
        self.assertEqual(payload["calls"], [{"pc": 3, "function": "print", "args": ["'hi'"]}])

    def test_summary_outputs_closure_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "child_closure.b64"
            path.write_text(
                base64.b64encode(make_child_closure_chunk()).decode("ascii"),
                encoding="ascii",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([str(path), "--summary"])

        payload = json.loads(stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertEqual(
            payload["closures"],
            [
                {
                    "pc": 0,
                    "kind": "NEWCLOSURE",
                    "register": 0,
                    "child_proto": 1,
                    "debugname": None,
                    "linedefined": 0,
                    "numparams": 1,
                    "is_vararg": False,
                    "numupvalues": 0,
                    "params": ["value"],
                    "upvalues": [],
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
