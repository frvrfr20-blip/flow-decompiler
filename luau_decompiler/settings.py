from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


STARTUP_ARGUMENTS = "-m luau_decompiler.ui --minimized"


@dataclass(frozen=True)
class FlowSettings:
    launch_at_sign_in: bool = False


ShortcutWriter = Callable[[Path, Path, str, Path], None]


def default_settings_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    base = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
    return base / "FlowDecompiler" / "settings.json"


def startup_shortcut_path() -> Path:
    app_data = os.environ.get("APPDATA")
    base = Path(app_data) if app_data else Path.home() / "AppData" / "Roaming"
    return base / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "Flow Decompiler.lnk"


def load_settings(path: Path | None = None) -> FlowSettings:
    settings_path = path or default_settings_path()
    try:
        payload = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return FlowSettings()

    if not isinstance(payload, dict):
        return FlowSettings()
    enabled = payload.get("launch_at_sign_in")
    return FlowSettings(launch_at_sign_in=enabled if isinstance(enabled, bool) else False)


def save_settings(settings: FlowSettings, path: Path | None = None) -> None:
    settings_path = path or default_settings_path()
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=settings_path.parent,
            prefix=f".{settings_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            json.dump(asdict(settings), handle, indent=2)
            handle.write("\n")
            temporary_path = Path(handle.name)
        temporary_path.replace(settings_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def startup_command(executable: Path | None = None) -> tuple[Path, str, Path]:
    target = Path(executable or sys.executable).resolve()
    if target.name.lower() == "python.exe":
        target = target.with_name("pythonw.exe")
    elif target.name.lower() != "pythonw.exe":
        raise ValueError(f"startup requires pythonw.exe, got {target.name}")
    if not target.exists():
        raise FileNotFoundError(f"pythonw.exe was not found at {target}")
    return target, STARTUP_ARGUMENTS, default_settings_path().parent


def write_startup_shortcut(path: Path, target: Path, arguments: str, working_directory: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update(
        {
            "FLOW_SHORTCUT_PATH": str(path),
            "FLOW_SHORTCUT_TARGET": str(target),
            "FLOW_SHORTCUT_ARGUMENTS": arguments,
            "FLOW_SHORTCUT_WORKDIR": str(working_directory),
        }
    )
    script = (
        "$shell = New-Object -ComObject WScript.Shell; "
        "$shortcut = $shell.CreateShortcut($env:FLOW_SHORTCUT_PATH); "
        "$shortcut.TargetPath = $env:FLOW_SHORTCUT_TARGET; "
        "$shortcut.Arguments = $env:FLOW_SHORTCUT_ARGUMENTS; "
        "$shortcut.WorkingDirectory = $env:FLOW_SHORTCUT_WORKDIR; "
        "$shortcut.Description = 'Flow Decompiler'; "
        "$shortcut.Save()"
    )
    subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        check=True,
        env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def set_launch_at_sign_in(
    enabled: bool,
    *,
    settings_path: Path | None = None,
    shortcut_path: Path | None = None,
    shortcut_writer: ShortcutWriter = write_startup_shortcut,
    executable: Path | None = None,
) -> FlowSettings:
    shortcut = shortcut_path or startup_shortcut_path()
    had_shortcut = shortcut.exists()
    previous_shortcut = shortcut.read_bytes() if had_shortcut else None
    try:
        if enabled:
            target, arguments, working_directory = startup_command(executable)
            shortcut_writer(shortcut, target, arguments, working_directory)
        else:
            shortcut.unlink(missing_ok=True)

        settings = FlowSettings(launch_at_sign_in=enabled)
        save_settings(settings, settings_path)
        return settings
    except Exception:
        try:
            if previous_shortcut is not None:
                shortcut.parent.mkdir(parents=True, exist_ok=True)
                shortcut.write_bytes(previous_shortcut)
            else:
                shortcut.unlink(missing_ok=True)
        except OSError:
            pass
        raise
