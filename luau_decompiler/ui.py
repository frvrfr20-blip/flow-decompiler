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

UI_COLORS = {
    "bg": "#111214",
    "panel": "#16181c",
    "panel_alt": "#1b1f25",
    "line": "#2a2e36",
    "output": "#0d0f12",
    "control": "#20242b",
    "control_hover": "#2a3038",
    "active": "#263149",
    "text": "#e7e9ee",
    "muted": "#8f98a6",
    "accent": "#6f8fdb",
    "accent_hover": "#7a9bea",
}


class AutoScrollbar(tk.Scrollbar):
    def __init__(self, master: tk.Misc, **kwargs: object) -> None:
        super().__init__(master, **kwargs)
        self._pack_options: dict[str, object] | None = None

    def pack(self, **kwargs: object) -> None:  # type: ignore[override]
        self._pack_options = kwargs
        super().pack(**kwargs)

    def set(self, first: str, last: str) -> None:
        if float(first) <= 0.0 and float(last) >= 1.0:
            self.pack_forget()
        elif self._pack_options:
            super().pack(**self._pack_options)
        super().set(first, last)


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
        self.status = tk.StringVar(value="Ready")
        self.file_label = tk.StringVar(value=self.path.name if self.path else "No file selected")
        self.mode_buttons: dict[str, tk.Button] = {}

        self._configure_root()
        self._build()
        if self.path:
            self._run()

    def _configure_root(self) -> None:
        self.root.title("Flow Decompiler")
        self.root.geometry("940x620")
        self.root.minsize(760, 500)
        self.root.configure(bg=UI_COLORS["bg"])

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 9), background=UI_COLORS["bg"], foreground=UI_COLORS["text"])

    def _build(self) -> None:
        outer = tk.Frame(self.root, bg=UI_COLORS["bg"], padx=14, pady=12)
        outer.pack(fill="both", expand=True)

        header = tk.Frame(outer, bg=UI_COLORS["bg"])
        header.pack(fill="x")

        tk.Label(
            header,
            text="Flow",
            bg=UI_COLORS["bg"],
            fg=UI_COLORS["text"],
            font=("Segoe UI Semibold", 11),
        ).pack(side="left")

        path_chip = tk.Label(
            header,
            textvariable=self.file_label,
            anchor="w",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["muted"],
            padx=10,
            pady=6,
            font=("Segoe UI", 9),
            highlightbackground=UI_COLORS["line"],
            highlightcolor=UI_COLORS["line"],
            highlightthickness=1,
        )
        path_chip.pack(side="left", fill="x", expand=True, padx=(12, 10))

        self._button(header, "Open", self._open, "accent").pack(side="right")
        self._button(header, "Save", self._save).pack(side="right", padx=(0, 8))
        self._button(header, "Copy", self._copy).pack(side="right", padx=(0, 8))

        controls = tk.Frame(
            outer,
            bg=UI_COLORS["panel"],
            padx=8,
            pady=8,
            highlightbackground=UI_COLORS["line"],
            highlightcolor=UI_COLORS["line"],
            highlightthickness=1,
        )
        controls.pack(fill="x", pady=(12, 10))

        mode_bar = tk.Frame(controls, bg=UI_COLORS["panel"], padx=1, pady=1)
        mode_bar.pack(side="left")
        for mode, label in (("decompile", "Decompile"), ("disasm", "Disasm"), ("summary", "Summary")):
            button = self._button(mode_bar, label, lambda value=mode: self._set_mode(value), "mode")
            button.pack(side="left", padx=(0, 1))
            self.mode_buttons[mode] = button

        self._button(controls, "Run", self._run, "accent").pack(side="right")
        self._button(controls, "Clear", self._clear).pack(side="right", padx=(0, 8))

        body = tk.Frame(
            outer,
            bg=UI_COLORS["line"],
            padx=1,
            pady=1,
            highlightbackground=UI_COLORS["line"],
            highlightcolor=UI_COLORS["line"],
            highlightthickness=1,
        )
        body.pack(fill="both", expand=True)

        self.output = tk.Text(
            body,
            bg=UI_COLORS["output"],
            fg=UI_COLORS["text"],
            insertbackground=UI_COLORS["text"],
            selectbackground=UI_COLORS["active"],
            selectforeground="#ffffff",
            relief="flat",
            bd=0,
            wrap="none",
            undo=True,
            padx=12,
            pady=10,
            font=("Cascadia Mono", 10),
        )
        self.output.pack(side="left", fill="both", expand=True)

        yscroll = AutoScrollbar(
            body,
            orient="vertical",
            command=self.output.yview,
            bg=UI_COLORS["panel_alt"],
            activebackground=UI_COLORS["control_hover"],
            troughcolor=UI_COLORS["output"],
            relief="flat",
            bd=0,
            highlightthickness=0,
            width=12,
        )
        yscroll.pack(side="right", fill="y")
        self.output.configure(yscrollcommand=yscroll.set)

        xscroll = AutoScrollbar(
            outer,
            orient="horizontal",
            command=self.output.xview,
            bg=UI_COLORS["panel_alt"],
            activebackground=UI_COLORS["control_hover"],
            troughcolor=UI_COLORS["output"],
            relief="flat",
            bd=0,
            highlightthickness=0,
            width=12,
        )
        xscroll.pack(fill="x")
        self.output.configure(xscrollcommand=xscroll.set)

        tk.Label(
            self.root,
            textvariable=self.status,
            anchor="w",
            bg=UI_COLORS["bg"],
            fg=UI_COLORS["muted"],
            padx=14,
            pady=7,
            font=("Segoe UI", 9),
        ).pack(side="bottom", fill="x")
        self._refresh_mode_buttons()

    def _button(self, parent: tk.Misc, text: str, command: object, kind: str = "default") -> tk.Button:
        if kind == "accent":
            bg = UI_COLORS["accent"]
            hover = UI_COLORS["accent_hover"]
            fg = "#ffffff"
        elif kind == "mode":
            bg = UI_COLORS["panel"]
            hover = UI_COLORS["control_hover"]
            fg = UI_COLORS["muted"]
        else:
            bg = UI_COLORS["control"]
            hover = UI_COLORS["control_hover"]
            fg = UI_COLORS["text"]

        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=hover,
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=14,
            pady=7,
            cursor="hand2",
            font=("Segoe UI", 9),
            highlightthickness=0,
        )
        button.bind("<Enter>", lambda _event: button.configure(bg=hover))
        button.bind("<Leave>", lambda _event: self._restore_button(button, kind))
        return button

    def _restore_button(self, button: tk.Button, kind: str) -> None:
        if kind == "accent":
            button.configure(bg=UI_COLORS["accent"], fg="#ffffff")
        elif button in self.mode_buttons.values():
            self._refresh_mode_buttons()
        else:
            button.configure(bg=UI_COLORS["control"], fg=UI_COLORS["text"])

    def _refresh_mode_buttons(self) -> None:
        for mode, button in self.mode_buttons.items():
            if mode == self.mode.get():
                button.configure(bg=UI_COLORS["active"], fg=UI_COLORS["text"])
            else:
                button.configure(bg=UI_COLORS["panel"], fg=UI_COLORS["muted"])

    def _set_mode(self, mode: str) -> None:
        self.mode.set(mode)
        self._refresh_mode_buttons()
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
            output = render_file(self.path, self.mode.get())
        except Exception as exc:  # UI boundary: show parser/decompiler failures without closing the app.
            self.status.set("Error")
            messagebox.showerror("Flow Decompiler", str(exc))
            return
        self.output.delete("1.0", "end")
        self.output.insert("1.0", output)
        self.status.set(f"{self.path.name} -> {self.mode.get()}")

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
