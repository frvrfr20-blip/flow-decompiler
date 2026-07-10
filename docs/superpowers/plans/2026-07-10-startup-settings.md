# Startup Settings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a persistent `Launch at sign-in` UI option that starts Flow minimized and document an AI-first Flow/MCP workflow.

**Architecture:** Put Windows settings and Startup shortcut operations in a focused `settings.py` module. Keep presentation in the existing Tkinter UI and reuse the same settings API from the UI and future agents. Use a per-user `.lnk` targeting `pythonw.exe`; do not add dependencies, services, scheduled tasks, or registry keys.

**Tech Stack:** Python 3.10+, Tkinter, JSON, PowerShell/WScript Shell, unittest, Windows Startup folder.

## Global Constraints

- Store settings at `%LOCALAPPDATA%\FlowDecompiler\settings.json`.
- Start with `pythonw.exe -m luau_decompiler.ui --minimized`.
- Keep the UI compact and use the existing Lucide-style icon system.
- Do not enable the real startup shortcut during automated tests.
- Make Flow the primary provider in the Roblox executor skill; retain lua.expert and Fission as verification providers.

---

### Task 1: Settings And Startup Module

**Files:**
- Create: `luau_decompiler/settings.py`
- Create: `tests/test_settings.py`

**Interfaces:**
- Produces: `FlowSettings`, `load_settings()`, `save_settings()`, `set_launch_at_sign_in()`, `startup_shortcut_path()`, and `startup_command()`.

- [ ] **Step 1: Write failing settings tests**

```python
def test_missing_settings_use_disabled_default(self):
    self.assertFalse(load_settings(self.path).launch_at_sign_in)

def test_setting_round_trip(self):
    save_settings(FlowSettings(launch_at_sign_in=True), self.path)
    self.assertTrue(load_settings(self.path).launch_at_sign_in)

def test_enable_writes_shortcut_before_saving(self):
    set_launch_at_sign_in(True, settings_path=self.path, shortcut_path=self.shortcut, shortcut_writer=self.writer)
    self.assertTrue(self.shortcut.exists())
```

- [ ] **Step 2: Run `python -m unittest tests.test_settings -v` and verify failures for missing interfaces.**

- [ ] **Step 3: Implement JSON and shortcut operations**

```python
@dataclass(frozen=True)
class FlowSettings:
    launch_at_sign_in: bool = False

def set_launch_at_sign_in(enabled: bool, *, settings_path: Path = SETTINGS_PATH, shortcut_path: Path | None = None) -> FlowSettings:
    if enabled:
        write_startup_shortcut(shortcut_path or startup_shortcut_path())
    else:
        (shortcut_path or startup_shortcut_path()).unlink(missing_ok=True)
    settings = FlowSettings(launch_at_sign_in=enabled)
    save_settings(settings, settings_path)
    return settings
```

- [ ] **Step 4: Run `python -m unittest tests.test_settings -v`; expect all settings tests to pass.**

### Task 2: UI And Installer Integration

**Files:**
- Modify: `luau_decompiler/ui.py`
- Modify: `install.ps1`
- Modify: `tests/test_ui.py`

**Interfaces:**
- Consumes: Task 1 settings API.
- Produces: a settings dialog, a Lucide settings icon, and `--minimized` startup behavior.

- [ ] **Step 1: Write failing UI argument tests**

```python
def test_ui_parser_accepts_minimized(self):
    self.assertTrue(_build_parser().parse_args(["--minimized"]).minimized)
```

- [ ] **Step 2: Run `python -m unittest tests.test_ui -v`; expect `_build_parser` failure.**

- [ ] **Step 3: Add the settings dialog and minimized startup**

```python
parser.add_argument("--minimized", action="store_true")
if args.minimized:
    root.after_idle(root.iconify)
```

Add a header settings icon. Its modal contains one `Checkbutton` bound to `launch_at_sign_in`; toggling calls `set_launch_at_sign_in`, updates the status bar, and restores the previous checkbox value on error.

- [ ] **Step 4: Remove the startup shortcut during uninstall**

```powershell
$StartupShortcut = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\Flow Decompiler.lnk"
Remove-Item -LiteralPath $StartupShortcut -Force -ErrorAction SilentlyContinue
```

- [ ] **Step 5: Run `python -m unittest tests.test_ui tests.test_settings -v`; expect all tests to pass.**

### Task 3: Agent Skill And Final Verification

**Files:**
- Modify: `C:\Users\Admin\.codex\skills\roblox-exploit-scripting\SKILL.md`

**Interfaces:**
- Documents the installed Flow executable, repo commands, MCP capture receiver, UI modes, startup setting, and provider fallback order.

- [ ] **Step 1: Replace the Fission-first section with Flow-first instructions.**

Use these commands verbatim:

```powershell
& "$env:LOCALAPPDATA\FlowDecompiler\.venv\Scripts\python.exe" -m luau_decompiler target.b64
& "$env:LOCALAPPDATA\FlowDecompiler\.venv\Scripts\pythonw.exe" -m luau_decompiler.ui
```

Document receiver startup and the executor POST to `http://127.0.0.1:18765`, then compare important output with lua.expert and Fission.

- [ ] **Step 2: Validate the skill.**

Run:

```powershell
python C:\Users\Admin\.codex\skills\.system\skill-creator\scripts\quick_validate.py C:\Users\Admin\.codex\skills\roblox-exploit-scripting
```

Expected: validation succeeds with no frontmatter or naming errors.

- [ ] **Step 3: Run complete verification.**

```powershell
python -m unittest discover -s tests
python -m compileall -q luau_decompiler tests tools
git diff --check
```

Expected: all tests pass, compilation is quiet, and diff check reports no errors.

- [ ] **Step 4: Launch `python -m luau_decompiler.ui --minimized` for a Windows smoke check and confirm the process starts with an iconified root.**

- [ ] **Step 5: Commit and push the implementation without adding `big_print_sample.b64`.**
