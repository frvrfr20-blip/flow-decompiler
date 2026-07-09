import unittest

from luau_decompiler.analysis import summarize_proto
from luau_decompiler.chunk import parse_chunk

from test_chunk import (
    make_captured_upvalue_closure_chunk,
    make_child_closure_chunk,
    make_inferred_require_module_local_chunk,
    make_namecall_chunk,
    make_udata_namecall_chunk,
)


class AnalysisTests(unittest.TestCase):
    def test_summary_finds_imports_and_namecalls(self):
        chunk = parse_chunk(make_namecall_chunk())
        summary = summarize_proto(chunk.protos[0])

        self.assertEqual(summary.imports, ["game"])
        self.assertEqual(summary.namecalls, ["FireServer"])
        self.assertEqual(summary.calls[0].method, "FireServer")
        self.assertEqual(summary.calls[0].receiver, "game")

    def test_summary_tracks_call_results_as_namecall_receivers(self):
        chunk = parse_chunk(make_inferred_require_module_local_chunk())
        summary = summarize_proto(chunk.protos[0])

        init_call = next(call for call in summary.calls if call.method == "initClient")
        set_user_call = next(call for call in summary.calls if call.method == "setUserId")

        self.assertEqual(
            init_call.receiver,
            "require(game:GetService('ReplicatedStorage').Packages.GameAnalytics)",
        )
        self.assertEqual(
            set_user_call.receiver,
            "require(game:GetService('ReplicatedStorage').Packages.GameAnalytics)",
        )
        self.assertEqual(set_user_call.args, ["'maker'"])

    def test_summary_uses_low_16_aux_key_for_udata_namecalls(self):
        chunk = parse_chunk(make_udata_namecall_chunk())
        summary = summarize_proto(chunk.protos[0])

        self.assertEqual(summary.namecalls, ["FireServer"])
        self.assertEqual(summary.calls[0].method, "FireServer")
        self.assertEqual(summary.calls[0].receiver, "obj")
        self.assertEqual(summary.calls[0].args, ["'hi'"])

    def test_summary_includes_newclosure_child_metadata(self):
        chunk = parse_chunk(make_child_closure_chunk())
        summary = summarize_proto(chunk.protos[0], chunk.protos)

        self.assertEqual(len(summary.closures), 1)
        closure = summary.closures[0]
        self.assertEqual(closure.pc, 0)
        self.assertEqual(closure.kind, "NEWCLOSURE")
        self.assertEqual(closure.register, 0)
        self.assertEqual(closure.child_proto, 1)
        self.assertIsNone(closure.debugname)
        self.assertEqual(closure.linedefined, 0)
        self.assertEqual(closure.numparams, 1)
        self.assertFalse(closure.is_vararg)
        self.assertEqual(closure.numupvalues, 0)
        self.assertEqual(closure.params, ["value"])
        self.assertEqual(closure.upvalues, [])

    def test_summary_includes_closure_upvalue_names(self):
        chunk = parse_chunk(make_captured_upvalue_closure_chunk())
        summary = summarize_proto(chunk.protos[0], chunk.protos)

        self.assertEqual(len(summary.closures), 1)
        closure = summary.closures[0]
        self.assertEqual(closure.pc, 1)
        self.assertEqual(closure.kind, "NEWCLOSURE")
        self.assertEqual(closure.register, 1)
        self.assertEqual(closure.child_proto, 1)
        self.assertEqual(closure.numupvalues, 1)
        self.assertEqual(closure.params, [])
        self.assertEqual(closure.upvalues, ["x"])


if __name__ == "__main__":
    unittest.main()
