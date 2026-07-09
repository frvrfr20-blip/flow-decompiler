from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .analysis import summarize_proto
from .binary import maybe_base64_decode
from .chunk import parse_chunk
from .decompile import decompile_chunk


MODES = ("decompile", "disasm", "summary")


def _load_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if path.suffix.lower() in {".b64", ".base64", ".txt"}:
        return maybe_base64_decode(data)
    return data


def render_file(path: str | Path, mode: str = "decompile", proto: int | None = None) -> str:
    if mode not in MODES:
        raise ValueError(f"unknown mode: {mode}")

    source = Path(path)
    chunk = parse_chunk(_load_bytes(source))
    proto_id = chunk.main_proto if proto is None else proto
    selected = chunk.protos[proto_id]

    if mode == "summary":
        return json.dumps(asdict(summarize_proto(selected, chunk.protos)), indent=2)
    if mode == "disasm":
        return "\n".join(insn.disassemble() for insn in selected.instructions) + "\n"
    return decompile_chunk(chunk, proto)


class FlowDecompilerApp:
    def __init__(self, root: tk.Tk, initial_file: str | None = None) -> None:
        self.root = root
        self.path: Path | None = Path(initial_file) if initial_file else None
        self.mode = tk.StringVar(value="decompile")
        self.proto = tk.StringVar(value="auto")
        self.status = tk.StringVar(value="Ready")
        self.file_label = tk.StringVar(value=self.path.name if self.path else "No file selected")

        self._configure_root()
        self._build()
        if self.path:
            self._run()

    def _configure_root(self) -> None:
        self.root.title("Flow Decompiler")
        self.root.geometry("980x680")
        self.root.minsize(820, 560)
        self.root.configure(bg="#0f141b")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10), background="#0f141b", foreground="#e8edf2")
        style.configure("Frame.TFrame", background="#0f141b")
        style.configure("Panel.TFrame", background="#151c24")
        style.configure("Title.TLabel", background="#0f141b", foreground="#f4f7fb", font=("Segoe UI", 18, "bold"))
        style.configure("Subtle.TLabel", background="#0f141b", foreground="#8f9baa")
        style.configure("Status.TLabel", background="#0b1016", foreground="#8f9baa", padding=(12, 7))
        style.configure("TButton", background="#202a35", foreground="#f4f7fb", borderwidth=0, padding=(13, 8))
        style.map("TButton", background=[("active", "#2c3948"), ("pressed", "#1a222c")])
        style.configure("Accent.TButton", background="#2a7f62", foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", "#319273"), ("pressed", "#236d54")])
        style.configure("Mode.TButton", background="#1a222c", foreground="#cbd5e1", padding=(12, 7))
        style.map("Mode.TButton", background=[("active", "#263240"), ("pressed", "#263240")])
        style.configure("TEntry", fieldbackground="#0f141b", foreground="#e8edf2", bordercolor="#2c3948")

    def _build(self) -> None:
        outer = ttk.Frame(self.root, style="Frame.TFrame", padding=18)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer, style="Frame.TFrame")
        header.pack(fill="x")

        title_block = ttk.Frame(header, style="Frame.TFrame")
        title_block.pack(side="left", fill="x", expand=True)
        ttk.Label(title_block, text="Flow Decompiler", style="Title.TLabel").pack(anchor="w")
        ttk.Label(title_block, textvariable=self.file_label, style="Subtle.TLabel").pack(anchor="w", pady=(4, 0))

        ttk.Button(header, text="Open", style="Accent.TButton", command=self._open).pack(side="right", padx=(8, 0))
        ttk.Button(header, text="Save", command=self._save).pack(side="right", padx=(8, 0))
        ttk.Button(header, text="Copy", command=self._copy).pack(side="right", padx=(8, 0))

        controls = ttk.Frame(outer, style="Panel.TFrame", padding=(12, 10))
        controls.pack(fill="x", pady=(16, 12))

        for mode, label in (("decompile", "Decompile"), ("disasm", "Disasm"), ("summary", "Summary")):
            ttk.Button(
                controls,
                text=label,
                style="Mode.TButton",
                command=lambda value=mode: self._set_mode(value),
            ).pack(side="left", padx=(0, 8))

        ttk.Label(controls, text="Proto", background="#151c24", foreground="#8f9baa").pack(side="left", padx=(12, 6))
        proto_entry = ttk.Entry(controls, width=8, textvariable=self.proto)
        proto_entry.pack(side="left")
        proto_entry.bind("<Return>", lambda _event: self._run())

        ttk.Button(controls, text="Run", style="Accent.TButton", command=self._run).pack(side="right")
        ttk.Button(controls, text="Clear", command=self._clear).pack(side="right", padx=(0, 8))

        body = ttk.Frame(outer, style="Panel.TFrame", padding=1)
        body.pack(fill="both", expand=True)

        self.output = tk.Text(
            body,
            bg="#0b1016",
            fg="#e8edf2",
            insertbackground="#e8edf2",
            selectbackground="#2a7f62",
            selectforeground="#ffffff",
            relief="flat",
            bd=0,
            wrap="none",
            undo=True,
            padx=14,
            pady=14,
            font=("Cascadia Mono", 10),
        )
        self.output.pack(side="left", fill="both", expand=True)

        yscroll = ttk.Scrollbar(body, orient="vertical", command=self.output.yview)
        yscroll.pack(side="right", fill="y")
        self.output.configure(yscrollcommand=yscroll.set)

        xscroll = ttk.Scrollbar(outer, orient="horizontal", command=self.output.xview)
        xscroll.pack(fill="x")
        self.output.configure(xscrollcommand=xscroll.set)

        ttk.Label(self.root, textvariable=self.status, style="Status.TLabel").pack(side="bottom", fill="x")

    def _parse_proto(self) -> int | None:
        value = self.proto.get().strip().lower()
        if value in {"", "auto"}:
            return None
        try:
            return int(value)
        except ValueError as exc:
            raise ValueError("Proto must be an integer or auto") from exc

    def _set_mode(self, mode: str) -> None:
        self.mode.set(mode)
        self._run()

    def _open(self) -> None:
        selected = filedialog.askopenfilename(
            title="Open bytecode",
            filetypes=(
                ("Luau bytecode", "*.luauc *.b64 *.base64 *.txt"),
                ("All files", "*.*"),
            ),
        )
        if not selected:
            return
        self.path = Path(selected)
        self.file_label.set(str(self.path))
        self._run()

    def _run(self) -> None:
        if not self.path:
            self.status.set("Open a bytecode file first")
            return
        try:
            output = render_file(self.path, self.mode.get(), self._parse_proto())
        except Exception as exc:  # UI boundary: show parser/decompiler failures without closing the app.
            self.status.set("Error")
            messagebox.showerror("Flow Decompiler", str(exc))
            return
        self.output.delete("1.0", "end")
        self.output.insert("1.0", output)
        self.status.set(f"{self.mode.get().title()} complete")

    def _save(self) -> None:
        text = self.output.get("1.0", "end-1c")
        if not text:
            self.status.set("Nothing to save")
            return
        selected = filedialog.asksaveasfilename(
            title="Save output",
            defaultextension=".luau",
            filetypes=(("Luau", "*.luau"), ("Text", "*.txt"), ("All files", "*.*")),
        )
        if not selected:
            return
        Path(selected).write_text(text, encoding="utf-8")
        self.status.set(f"Saved {Path(selected).name}")

    def _copy(self) -> None:
        text = self.output.get("1.0", "end-1c")
        if not text:
            self.status.set("Nothing to copy")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status.set("Copied")

    def _clear(self) -> None:
        self.output.delete("1.0", "end")
        self.status.set("Cleared")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Flow Decompiler UI")
    parser.add_argument("input", nargs="?", help="Optional bytecode file to open")
    args = parser.parse_args(argv)

    root = tk.Tk()
    FlowDecompilerApp(root, args.input)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
