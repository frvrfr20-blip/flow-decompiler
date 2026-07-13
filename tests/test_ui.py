from __future__ import annotations

from pathlib import Path
import unittest

from luau_decompiler.ui import (
    OUTPUT_INSERT_CHUNK_SIZE,
    FlowDecompilerApp,
    _active_source,
    _apply_startup_state,
    _build_parser,
)


class UiInputStateTests(unittest.TestCase):
    def test_ui_parser_accepts_minimized(self):
        self.assertTrue(_build_parser().parse_args(["--minimized"]).minimized)

    def test_minimized_launch_schedules_iconify(self):
        class Root:
            def __init__(self):
                self.callback = None

            def iconify(self):
                return None

            def after_idle(self, callback):
                self.callback = callback

        root = Root()

        _apply_startup_state(root, minimized=True)

        self.assertEqual(root.callback, root.iconify)

    def test_pasted_text_overrides_selected_file_after_user_edit(self):
        selected = Path("old.b64")

        state = _active_source(selected, "new-bytecode", "", output_is_result=False)

        self.assertEqual(state.source, "new-bytecode")
        self.assertIsNone(state.path)
        self.assertEqual(state.input_text, "new-bytecode")
        self.assertEqual(state.label, "pasted input")

    def test_previous_output_reruns_stored_pasted_input(self):
        state = _active_source(None, "-- decompiled output", "original-bytecode", output_is_result=True)

        self.assertEqual(state.source, "original-bytecode")
        self.assertEqual(state.input_text, "original-bytecode")
        self.assertEqual(state.label, "pasted input")

    def test_previous_output_with_selected_file_reruns_file(self):
        selected = Path("sample.b64")

        state = _active_source(selected, "-- decompiled output", "", output_is_result=True)

        self.assertEqual(state.source, selected)
        self.assertEqual(state.path, selected)
        self.assertEqual(state.label, "sample.b64")

    def test_large_output_is_inserted_in_idle_chunks(self):
        class Root:
            def __init__(self):
                self.callbacks = []

            def after_idle(self, callback):
                self.callbacks.append(callback)

        class Output:
            def __init__(self):
                self.parts = []
                self.modified = None

            def insert(self, index, value):
                self.assert_index = index
                self.parts.append(value)

            def edit_modified(self, value):
                self.modified = value

        app = FlowDecompilerApp.__new__(FlowDecompilerApp)
        app.root = Root()
        app.output = Output()
        app.render_token = 7
        app.updating_output = True
        app.output_is_result = False
        busy_states = []
        app._set_busy = lambda busy, status: busy_states.append((busy, status))
        text = "x" * (OUTPUT_INSERT_CHUNK_SIZE * 2 + 17)

        app._insert_output_chunk(7, text, 0, "large.b64", "decompile")
        while app.root.callbacks:
            app.root.callbacks.pop(0)()

        self.assertEqual("".join(app.output.parts), text)
        self.assertTrue(all(len(part) <= OUTPUT_INSERT_CHUNK_SIZE for part in app.output.parts))
        self.assertGreater(len(app.output.parts), 1)
        self.assertEqual(app.output.assert_index, "end-1c")
        self.assertFalse(app.updating_output)
        self.assertTrue(app.output_is_result)
        self.assertEqual(busy_states, [(False, "large.b64 -> decompile")])


if __name__ == "__main__":
    unittest.main()
