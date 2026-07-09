from __future__ import annotations

import http.client
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tools import receive_bytecode


def _unused_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_server(port: int, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 5
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(f"receiver exited early with {process.returncode}\n{stdout}\n{stderr}")
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
            connection.request("GET", "/")
            response = connection.getresponse()
            response.read()
            connection.close()
            if response.status == 200:
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    raise AssertionError(f"receiver did not start on localhost:{port}") from last_error


class ReceiveBytecodeTests(unittest.TestCase):
    def test_safe_name_removes_path_traversal_and_uses_sample_for_blank_names(self):
        self.assertEqual(receive_bytecode._safe_name("../../evil path?:name"), "evil_path_name")
        self.assertEqual(receive_bytecode._safe_name("..."), "sample")
        self.assertEqual(receive_bytecode._safe_name(None), "sample")

    def test_safe_name_limits_names_to_120_characters(self):
        self.assertEqual(receive_bytecode._safe_name("a" * 130), "a" * 120)

    def test_post_writes_body_to_sanitized_b64_filename(self):
        script = Path(__file__).resolve().parents[1] / "tools" / "receive_bytecode.py"
        body = b"YmFzZTY0IGx1YXUgYnl0ZWNvZGU="

        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "samples"
            port = _unused_local_port()
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(script),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--out",
                    str(out_dir),
                    "--count",
                    "1",
                ],
                cwd=script.parents[1],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                _wait_for_server(port, process)
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                connection.request(
                    "POST",
                    "/",
                    body=body,
                    headers={"X-Sample-Name": "../../incoming bytecode?"},
                )
                response = connection.getresponse()
                response_body = response.read().decode("utf-8")
                connection.close()

                stdout, stderr = process.communicate(timeout=5)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=5)

            expected_path = out_dir / "incoming_bytecode.b64"
            self.assertEqual(response.status, 200)
            self.assertEqual(Path(response_body), expected_path.resolve())
            self.assertEqual(expected_path.read_bytes(), body)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertIn("received 1 sample(s)", stdout)


if __name__ == "__main__":
    unittest.main()
