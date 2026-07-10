from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from luau_decompiler.settings import (
    FlowSettings,
    load_settings,
    save_settings,
    set_launch_at_sign_in,
    startup_command,
)


class SettingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.settings_path = self.root / "settings.json"
        self.shortcut_path = self.root / "Startup" / "Flow Decompiler.lnk"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_missing_settings_use_disabled_default(self):
        self.assertFalse(load_settings(self.settings_path).launch_at_sign_in)

    def test_malformed_settings_use_disabled_default(self):
        self.settings_path.write_text("not-json", encoding="utf-8")

        self.assertFalse(load_settings(self.settings_path).launch_at_sign_in)

    def test_setting_round_trip(self):
        save_settings(FlowSettings(launch_at_sign_in=True), self.settings_path)

        self.assertTrue(load_settings(self.settings_path).launch_at_sign_in)

    def test_startup_command_prefers_pythonw_sibling(self):
        python = self.root / "Scripts" / "python.exe"
        python.parent.mkdir()
        python.touch()
        pythonw = python.with_name("pythonw.exe")
        pythonw.touch()

        target, arguments, _working_directory = startup_command(python)

        self.assertEqual(target, pythonw)
        self.assertEqual(arguments, "-m luau_decompiler.ui --minimized")

    def test_startup_command_rejects_missing_pythonw(self):
        python = self.root / "Scripts" / "python.exe"
        python.parent.mkdir()
        python.touch()

        with self.assertRaises(FileNotFoundError):
            startup_command(python)

    def test_enable_writes_shortcut_before_saving(self):
        calls: list[tuple[Path, Path, str, Path]] = []
        python = self.root / "python.exe"
        python.touch()
        python.with_name("pythonw.exe").touch()

        def writer(path: Path, target: Path, arguments: str, working_directory: Path) -> None:
            self.assertFalse(self.settings_path.exists())
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
            calls.append((path, target, arguments, working_directory))

        settings = set_launch_at_sign_in(
            True,
            settings_path=self.settings_path,
            shortcut_path=self.shortcut_path,
            shortcut_writer=writer,
            executable=python,
        )

        self.assertTrue(settings.launch_at_sign_in)
        self.assertTrue(load_settings(self.settings_path).launch_at_sign_in)
        self.assertEqual(calls[0][0], self.shortcut_path)
        self.assertEqual(calls[0][2], "-m luau_decompiler.ui --minimized")

    def test_enable_rolls_back_shortcut_when_settings_save_fails(self):
        python = self.root / "python.exe"
        python.touch()
        python.with_name("pythonw.exe").touch()

        def writer(path: Path, *_args: object) -> None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"new shortcut")

        with patch("luau_decompiler.settings.save_settings", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                set_launch_at_sign_in(
                    True,
                    settings_path=self.settings_path,
                    shortcut_path=self.shortcut_path,
                    shortcut_writer=writer,
                    executable=python,
                )

        self.assertFalse(self.shortcut_path.exists())

    def test_disable_removes_shortcut_and_saves_setting(self):
        self.shortcut_path.parent.mkdir(parents=True)
        self.shortcut_path.touch()
        save_settings(FlowSettings(launch_at_sign_in=True), self.settings_path)

        settings = set_launch_at_sign_in(
            False,
            settings_path=self.settings_path,
            shortcut_path=self.shortcut_path,
        )

        self.assertFalse(settings.launch_at_sign_in)
        self.assertFalse(self.shortcut_path.exists())
        self.assertFalse(load_settings(self.settings_path).launch_at_sign_in)

    def test_disable_restores_shortcut_when_settings_save_fails(self):
        self.shortcut_path.parent.mkdir(parents=True)
        self.shortcut_path.write_bytes(b"existing shortcut")

        with patch("luau_decompiler.settings.save_settings", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                set_launch_at_sign_in(False, shortcut_path=self.shortcut_path)

        self.assertEqual(self.shortcut_path.read_bytes(), b"existing shortcut")


if __name__ == "__main__":
    unittest.main()
