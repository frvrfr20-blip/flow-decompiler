from __future__ import annotations

import argparse
from collections.abc import Callable
import json
import math
import queue
import threading
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


class LoadingIndicator(tk.Canvas):
    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(
            parent,
            width=64,
            height=18,
            bd=0,
            relief="flat",
            highlightthickness=0,
            bg=UI_COLORS["bg"],
        )
        self.running = False
        self.phase = 0.0
        self._after_id: str | None = None

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self.grid(row=0, column=1, sticky="e", padx=(10, 0))
        self._tick()

    def stop(self) -> None:
        self.running = False
        if self._after_id:
            self.after_cancel(self._after_id)
            self._after_id = None
        self.delete("all")
        self.grid_remove()

    def _tick(self) -> None:
        if not self.running:
            return
        self.phase += 0.28
        self.delete("all")
        self.create_line(8, 9, 56, 9, fill=UI_COLORS["line"], width=1)
        for index in range(4):
            wave = (math.sin(self.phase - index * 0.75) + 1.0) / 2.0
            radius = 2.2 + wave * 2.2
            x = 12 + index * 13
            y = 9 + math.sin(self.phase + index * 0.9) * 3
            fill = UI_COLORS["accent"] if wave > 0.48 else UI_COLORS["muted"]
            self.create_oval(x - radius, y - radius, x + radius, y + radius, fill=fill, outline="")
        self._after_id = self.after(42, self._tick)


class ToolTip:
    def __init__(self, widget: tk.Widget, text: str) -> None:
        self.widget = widget
        self.text = text
        self.window: tk.Toplevel | None = None
        self.after_id: str | None = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self.hide, add="+")
        widget.bind("<ButtonPress>", self.hide, add="+")

    def _schedule(self, _event: tk.Event[tk.Widget]) -> None:
        self.hide()
        self.after_id = self.widget.after(450, self.show)

    def show(self) -> None:
        if self.window:
            return
        x = self.widget.winfo_rootx() + 8
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self.window = tk.Toplevel(self.widget)
        self.window.wm_overrideredirect(True)
        self.window.wm_geometry(f"+{x}+{y}")
        tk.Label(
            self.window,
            text=self.text,
            bg=UI_COLORS["panel_alt"],
            fg=UI_COLORS["text"],
            padx=8,
            pady=4,
            font=("Segoe UI", 8),
            highlightbackground=UI_COLORS["line"],
            highlightthickness=1,
        ).pack()

    def hide(self, _event: tk.Event[tk.Widget] | None = None) -> None:
        if self.after_id:
            self.widget.after_cancel(self.after_id)
            self.after_id = None
        if self.window:
            self.window.destroy()
            self.window = None


class IconButton(tk.Canvas):
    def __init__(
        self,
        parent: tk.Misc,
        icon: str,
        command: Callable[[], None],
        tooltip: str,
        kind: str = "default",
    ) -> None:
        self.kind = kind
        self.icon = icon
        self.command = command
        self.hovered = False
        super().__init__(
            parent,
            width=38,
            height=32,
            bd=0,
            relief="flat",
            highlightthickness=1,
            highlightbackground=UI_COLORS["bg"],
            cursor="hand2",
            takefocus=1,
        )
        self._paint()
        ToolTip(self, tooltip)
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)
        self.bind("<Button-1>", self._click)
        self.bind("<Return>", self._click)
        self.bind("<space>", self._click)
        self.bind("<FocusIn>", lambda _event: self.configure(highlightbackground=UI_COLORS["accent"]))
        self.bind("<FocusOut>", lambda _event: self.configure(highlightbackground=UI_COLORS["bg"]))

    def _colors(self) -> tuple[str, str]:
        if self.kind == "accent":
            return (UI_COLORS["accent_hover"] if self.hovered else UI_COLORS["accent"], "#ffffff")
        return (UI_COLORS["control_hover"] if self.hovered else UI_COLORS["control"], UI_COLORS["text"])

    def _paint(self) -> None:
        bg, fg = self._colors()
        self.configure(bg=bg)
        self.delete("all")
        self._draw_lucide(self.icon, fg)

    def _enter(self, _event: tk.Event[tk.Widget]) -> None:
        self.hovered = True
        self._paint()

    def _leave(self, _event: tk.Event[tk.Widget]) -> None:
        self.hovered = False
        self._paint()

    def _click(self, _event: tk.Event[tk.Widget]) -> str:
        self.command()
        return "break"

    def _xy(self, x: float, y: float) -> tuple[float, float]:
        return 10 + x * 0.75, 7 + y * 0.75

    def _line(self, points: list[tuple[float, float]], color: str) -> None:
        coords: list[float] = []
        for x, y in points:
            coords.extend(self._xy(x, y))
        self.create_line(*coords, fill=color, width=2, capstyle="round", joinstyle="round")

    def _rect(self, x1: float, y1: float, x2: float, y2: float, color: str) -> None:
        ax, ay = self._xy(x1, y1)
        bx, by = self._xy(x2, y2)
        self.create_rectangle(ax, ay, bx, by, outline=color, width=2)

    def _poly(self, points: list[tuple[float, float]], color: str) -> None:
        coords: list[float] = []
        for x, y in points:
            coords.extend(self._xy(x, y))
        self.create_polygon(*coords, fill="", outline=color, width=2, joinstyle="round")

    def _draw_lucide(self, icon: str, color: str) -> None:
        if icon == "folder-open":
            self._line([(3, 6), (8, 6), (10, 8), (21, 8), (21, 11)], color)
            self._line([(3, 6), (3, 19), (18, 19), (22, 11), (7, 11), (3, 19)], color)
        elif icon == "copy":
            self._rect(8, 8, 20, 20, color)
            self._line([(4, 16), (4, 4), (16, 4)], color)
            self._line([(4, 4), (16, 4), (16, 6)], color)
        elif icon == "save":
            self._rect(5, 3, 19, 21, color)
            self._line([(8, 3), (8, 9), (16, 9), (16, 3)], color)
            self._line([(8, 21), (8, 15), (16, 15), (16, 21)], color)
        elif icon == "play":
            self._poly([(8, 5), (19, 12), (8, 19)], color)
        elif icon == "trash-2":
            self._line([(3, 6), (21, 6)], color)
            self._line([(8, 6), (8, 4), (16, 4), (16, 6)], color)
            self._line([(6, 6), (7, 21), (17, 21), (18, 6)], color)
            self._line([(10, 10), (10, 17)], color)
            self._line([(14, 10), (14, 17)], color)


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
        self.render_queue: queue.Queue[tuple[int, str, str | None, str, str]] = queue.Queue()
        self.render_token = 0

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

        self._icon_button(header, "folder-open", self._open, "Open", "accent").pack(side="right")
        self._icon_button(header, "save", self._save, "Save").pack(side="right", padx=(0, 8))
        self._icon_button(header, "copy", self._copy, "Copy").pack(side="right", padx=(0, 8))

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

        self._icon_button(controls, "play", self._run, "Run", "accent").pack(side="right")
        self._icon_button(controls, "trash-2", self._clear, "Clear").pack(side="right", padx=(0, 8))

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

        footer = tk.Frame(self.root, bg=UI_COLORS["bg"], padx=14, pady=7)
        footer.pack(side="bottom", fill="x")
        footer.columnconfigure(0, weight=1)
        tk.Label(
            footer,
            textvariable=self.status,
            anchor="w",
            bg=UI_COLORS["bg"],
            fg=UI_COLORS["muted"],
            font=("Segoe UI", 9),
        ).grid(row=0, column=0, sticky="ew")
        self.loader = LoadingIndicator(footer)
        self._refresh_mode_buttons()

    def _icon_button(
        self,
        parent: tk.Misc,
        icon: str,
        command: Callable[[], None],
        tooltip: str,
        kind: str = "default",
    ) -> IconButton:
        return IconButton(parent, icon, command, tooltip, kind)

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

    def _set_busy(self, busy: bool, status: str) -> None:
        self.status.set(status)
        if busy:
            self.loader.start()
        else:
            self.loader.stop()

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

        self.render_token += 1
        token = self.render_token
        path = self.path
        mode = self.mode.get()
        self._set_busy(True, f"{path.name} -> {mode}")

        thread = threading.Thread(target=self._render_worker, args=(token, path, mode), daemon=True)
        thread.start()
        self.root.after(40, self._poll_render)

    def _render_worker(self, token: int, path: Path, mode: str) -> None:
        try:
            output = render_file(path, mode)
            self.render_queue.put((token, output, None, path.name, mode))
        except Exception as exc:
            self.render_queue.put((token, "", str(exc), path.name, mode))

    def _poll_render(self) -> None:
        try:
            token, output, error, filename, mode = self.render_queue.get_nowait()
        except queue.Empty:
            if self.loader.running:
                self.root.after(40, self._poll_render)
            return

        if token != self.render_token:
            self.root.after(1, self._poll_render)
            return

        self._set_busy(False, f"{filename} -> {mode}")
        if error:
            self.status.set("Error")
            messagebox.showerror("Flow Decompiler", error)
            return
        self.output.delete("1.0", "end")
        self.output.insert("1.0", output)

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
