from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import threading


def _safe_name(value: str | None) -> str:
    value = value or "sample"
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return value[:120].strip("._") or "sample"


def main() -> int:
    parser = argparse.ArgumentParser(description="Receive base64 Luau bytecode samples over local HTTP POST.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18765)
    parser.add_argument("--out", type=Path, default=Path("live_samples"))
    parser.add_argument("--count", type=int, default=1, help="Number of POSTs to accept before exiting.")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    state = {"seen": 0}
    server: ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def do_POST(self) -> None:
            size = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(size)
            name = _safe_name(self.headers.get("x-sample-name")) + ".b64"
            path = args.out / name
            path.write_bytes(body)
            state["seen"] += 1

            self.send_response(200)
            self.end_headers()
            self.wfile.write(str(path.resolve()).encode("utf-8"))
            if state["seen"] >= args.count:
                threading.Thread(target=server.shutdown, daemon=True).start()

        def log_message(self, *_: object) -> None:
            return

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"listening on http://{args.host}:{args.port} -> {args.out.resolve()}", flush=True)
    server.serve_forever()
    print(f"received {state['seen']} sample(s)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
