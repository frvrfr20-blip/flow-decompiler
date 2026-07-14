import struct
import unittest
from unittest.mock import patch

import luau_decompiler.regions as regions
from luau_decompiler.chunk import parse_chunk
from luau_decompiler.decompile import decompile_chunk
from tests.test_chunk import (
    import_id,
    make_generic_for_named_call_chunk,
    make_repeat_break_preserves_body_order_chunk,
    make_while_conditional_continue_chunk,
    string_table,
    varint,
)
from luau_decompiler.disasm import encode_abc, encode_ad


def _make_v4_chunk(words, strings, maxstack, constants=(), debug_locals=()):
    out = bytearray([4, 3])
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([maxstack, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(len(constants))
    for kind, value in constants:
        if kind == "string":
            out.append(3)
            out += varint(value + 1)
        elif kind == "import":
            out.append(4)
            out += struct.pack("<I", import_id(*value))
        else:
            raise AssertionError(f"unsupported test constant: {kind}")
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1 if debug_locals else 0)
    if debug_locals:
        out += varint(len(debug_locals))
        for name, start_pc, end_pc, register in debug_locals:
            out += varint(strings.index(name) + 1)
            out += varint(start_pc)
            out += varint(end_pc)
            out.append(register)
        out += varint(0)
    out += varint(0)
    return bytes(out)


def make_official_numeric_for_visible_value_chunk():
    """Modern FORNPREP keeps the loop's visible, evolving value in A + 2."""
    words = [
        encode_ad("LOADN", 2, 1),
        encode_ad("LOADN", 0, 3),
        encode_ad("LOADN", 1, 1),
        encode_ad("FORNPREP", 0, 5),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_abc("MOVE", 4, 2, 0),
        encode_abc("CALL", 3, 2, 1),
        encode_ad("FORNLOOP", 0, -5),
        encode_abc("RETURN", 0, 1, 0),
    ]
    return _make_v4_chunk(words, ["print"], 5, (("string", 0), ("import", (0,))))


def make_official_numeric_for_break_continue_chunk():
    strings = ["print", "stop", "skip"]
    words = [
        encode_ad("LOADN", 2, 1),
        encode_ad("LOADN", 0, 3),
        encode_ad("LOADN", 1, 1),
        encode_ad("FORNPREP", 0, 9),
        encode_ad("JUMPIFNOT", 3, 1),
        encode_ad("JUMP", 0, 7),
        encode_ad("JUMPIFNOT", 4, 1),
        encode_ad("JUMP", 0, 4),
        encode_ad("GETIMPORT", 5, 1),
        import_id(0),
        encode_abc("MOVE", 6, 2, 0),
        encode_abc("CALL", 5, 2, 1),
        encode_ad("FORNLOOP", 0, -9),
        encode_abc("RETURN", 0, 1, 0),
    ]
    return _make_v4_chunk(
        words,
        strings,
        7,
        (("string", 0), ("import", (0,))),
        (("stop", 0, 14, 3), ("skip", 0, 14, 4)),
    )


def make_generic_for_break_continue_chunk():
    strings = ["next", "items", "print", "key", "stop", "skip"]
    words = [
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_ad("GETIMPORT", 1, 3),
        import_id(2),
        encode_abc("LOADNIL", 2, 0, 0),
        encode_ad("FORGPREP", 0, 8),
        encode_ad("JUMPIFNOT", 4, 1),
        encode_ad("JUMP", 0, 8),
        encode_ad("JUMPIFNOT", 5, 1),
        encode_ad("JUMP", 0, 4),
        encode_ad("GETIMPORT", 6, 5),
        import_id(4),
        encode_abc("MOVE", 7, 3, 0),
        encode_abc("CALL", 6, 2, 1),
        encode_ad("FORGLOOP", 0, -9),
        1,
        encode_abc("RETURN", 0, 1, 0),
    ]
    return _make_v4_chunk(
        words,
        strings,
        8,
        (
            ("string", 0),
            ("import", (0,)),
            ("string", 1),
            ("import", (1,)),
            ("string", 2),
            ("import", (2,)),
        ),
        (("key", 6, 16, 3), ("stop", 0, 16, 4), ("skip", 0, 16, 5)),
    )


def make_repeat_loop_carried_scalar_chunk():
    strings = ["count"]
    words = [
        encode_ad("LOADN", 0, 0),
        encode_ad("LOADN", 1, 1),
        encode_abc("ADD", 0, 0, 1),
        encode_ad("LOADN", 2, 3),
        encode_ad("JUMPIFLT", 0, -3),
        2,
        encode_abc("RETURN", 0, 2, 0),
    ]
    return _make_v4_chunk(words, strings, 3, debug_locals=(("count", 0, 7, 0),))


def make_while_continue_to_latch_chunk():
    strings = ["tick", "skip"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIFNOT", 0, 6),
        encode_ad("JUMPIFNOT", 1, 1),
        encode_ad("JUMP", 0, 3),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_abc("CALL", 2, 1, 1),
        encode_ad("JUMPBACK", 0, -8),
        encode_abc("RETURN", 0, 1, 0),
    ]
    return _make_v4_chunk(
        words,
        strings,
        3,
        (("string", 0), ("import", (0,))),
        (("skip", 0, 9, 1),),
    )


def make_repeat_continue_to_condition_chunk():
    strings = ["tick", "done", "skip"]
    words = [
        encode_ad("JUMPIFNOT", 1, 1),
        encode_ad("JUMP", 0, 3),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_abc("CALL", 2, 1, 1),
        encode_ad("JUMPIFNOT", 0, -6),
        encode_abc("RETURN", 0, 1, 0),
    ]
    return _make_v4_chunk(
        words,
        strings,
        3,
        (("string", 0), ("import", (0,))),
        (("done", 0, 7, 0), ("skip", 0, 7, 1)),
    )


def make_short_circuit_early_return_guard_chunk():
    strings = ["first", "fallback", "left", "right"]
    words = [
        encode_ad("JUMPIFNOT", 0, 1),
        encode_ad("JUMPIF", 1, 2),
        encode_ad("LOADK", 2, 0),
        encode_abc("RETURN", 2, 2, 0),
        encode_ad("LOADK", 2, 1),
        encode_abc("RETURN", 2, 2, 0),
    ]
    return _make_v4_chunk(
        words,
        strings,
        3,
        (("string", 0), ("string", 1), ("string", 2), ("string", 3)),
        (("left", 0, 6, 0), ("right", 0, 6, 1)),
    )


def make_terminal_if_else_with_forward_join_chunk():
    words = [
        encode_ad("JUMPIFNOT", 0, 7),
        encode_ad("JUMPIFNOT", 1, 3),
        encode_ad("JUMPIFNOT", 2, 2),
        encode_ad("LOADK", 3, 0),
        encode_ad("JUMP", 0, 5),
        encode_ad("LOADK", 3, 1),
        encode_abc("NOP", 0, 0, 0),
        encode_ad("JUMP", 0, 2),
        encode_ad("LOADK", 3, 2),
        encode_abc("RETURN", 3, 2, 0),
        encode_abc("RETURN", 3, 2, 0),
    ]
    return _make_v4_chunk(
        words,
        ["cached", "computed", "fallback"],
        4,
        (("string", 0), ("string", 1), ("string", 2)),
    )


def make_terminal_guard_with_preserved_fallback_chunk():
    words = [
        encode_ad("LOADK", 2, 0),
        encode_ad("JUMPIFNOT", 0, 4),
        encode_ad("JUMPIFNOT", 1, 3),
        encode_ad("JUMPIFNOT", 3, 2),
        encode_ad("LOADK", 2, 1),
        encode_abc("RETURN", 2, 2, 0),
        encode_abc("RETURN", 2, 2, 0),
    ]
    return _make_v4_chunk(
        words,
        ["fallback", "first"],
        4,
        (("string", 0), ("string", 1)),
    )


def make_nested_numeric_for_chunk():
    words = [
        encode_ad("LOADN", 2, 1),
        encode_ad("LOADN", 0, 2),
        encode_ad("LOADN", 1, 1),
        encode_ad("FORNPREP", 0, 11),
        encode_ad("LOADN", 5, 1),
        encode_ad("LOADN", 3, 2),
        encode_ad("LOADN", 4, 1),
        encode_ad("FORNPREP", 3, 6),
        encode_ad("GETIMPORT", 6, 1),
        import_id(0),
        encode_abc("MOVE", 7, 2, 0),
        encode_abc("MOVE", 8, 5, 0),
        encode_abc("CALL", 6, 3, 1),
        encode_ad("FORNLOOP", 3, -6),
        encode_ad("FORNLOOP", 0, -11),
        encode_abc("RETURN", 0, 1, 0),
    ]
    return _make_v4_chunk(
        words,
        ["print"],
        9,
        (("string", 0), ("import", (0,))),
    )


def make_numeric_for_side_effect_before_break_chunk():
    words = [
        encode_ad("LOADN", 2, 1),
        encode_ad("LOADN", 0, 3),
        encode_ad("LOADN", 1, 1),
        encode_ad("FORNPREP", 0, 6),
        encode_ad("JUMPIFNOT", 3, 4),
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_abc("CALL", 4, 1, 1),
        encode_ad("JUMP", 0, 1),
        encode_ad("FORNLOOP", 0, -6),
        encode_abc("RETURN", 0, 1, 0),
    ]
    return _make_v4_chunk(
        words,
        ["before_break", "stop"],
        5,
        (("string", 0), ("import", (0,))),
        (("stop", 0, 11, 3),),
    )


class ControlFlowExtraTests(unittest.TestCase):
    def test_official_numeric_for_uses_a_plus_2_visible_value(self):
        source = decompile_chunk(parse_chunk(make_official_numeric_for_visible_value_chunk()))

        self.assertIn("for r2 = 1, 3, 1 do\n    print(r2)\nend", source)
        self.assertNotIn("for r3 =", source)

    def test_numeric_for_break_and_continue_keep_their_control_targets(self):
        source = decompile_chunk(parse_chunk(make_official_numeric_for_break_continue_chunk()))

        self.assertIn(
            "for r2 = 1, 3, 1 do\n"
            "    if r3 then\n"
            "        break\n"
            "    end\n"
            "    if r4 then\n"
            "        continue\n"
            "    end\n"
            "    print(r2)\n"
            "end",
            source,
        )
        self.assertNotIn("-- pc", source)

    def test_generic_for_break_and_continue_keep_their_control_targets(self):
        source = decompile_chunk(parse_chunk(make_generic_for_break_continue_chunk()))

        self.assertIn(
            "for key in next, items do\n"
            "    if r4 then\n"
            "        break\n"
            "    end\n"
            "    if r5 then\n"
            "        continue\n"
            "    end\n"
            "    print(key)\n"
            "end",
            source,
        )
        self.assertNotIn("FORGPREP", source)
        self.assertNotIn("FORGLOOP", source)
        self.assertNotIn("-- pc", source)

    def test_repeat_loop_carried_scalar_keeps_one_storage_across_condition_and_return(self):
        source = decompile_chunk(parse_chunk(make_repeat_loop_carried_scalar_chunk()))

        self.assertIn(
            "local count = 0\n"
            "repeat\n"
            "    count = count + 1\n"
            "until count >= 3\n"
            "return count",
            source,
        )
        self.assertNotIn("return r0", source)

    def test_while_continue_jumps_to_the_latch(self):
        source = decompile_chunk(parse_chunk(make_while_continue_to_latch_chunk()))

        self.assertIn(
            "while true do\n"
            "    if r1 then\n"
            "        continue\n"
            "    end\n"
            "    tick()\n"
            "end",
            source,
        )
        self.assertNotIn("JUMPBACK", source)

    def test_repeat_continue_jumps_to_the_condition(self):
        source = decompile_chunk(parse_chunk(make_repeat_continue_to_condition_chunk()))

        self.assertIn(
            "repeat\n"
            "    if r1 then\n"
            "        continue\n"
            "    end\n"
            "    tick()\n"
            "until r0",
            source,
        )
        self.assertNotIn("JUMPIFNOT", source)

    def test_short_circuit_early_return_keeps_fallback_after_guard(self):
        source = decompile_chunk(parse_chunk(make_short_circuit_early_return_guard_chunk()))

        self.assertIn(
            'if (not r0) or (not r1) then\n'
            '    return "first"\n'
            "end\n"
            'return "fallback"',
            source,
        )
        self.assertNotIn("else", source)

    def test_terminal_if_else_does_not_hoist_the_returning_else_arm(self):
        source = decompile_chunk(parse_chunk(make_terminal_if_else_with_forward_join_chunk()))

        self.assertIn("else", source)
        self.assertIn('r3 = "fallback"\n    return r3', source)
        self.assertLess(source.index("else"), source.index('r3 = "fallback"'))

    def test_terminal_guard_restores_register_state_for_fallback(self):
        source = decompile_chunk(parse_chunk(make_terminal_guard_with_preserved_fallback_chunk()))

        self.assertIn('return "first"', source)
        self.assertTrue(source.rstrip().endswith('return "fallback"'))

    def test_nested_numeric_for_loops_keep_distinct_latches(self):
        source = decompile_chunk(parse_chunk(make_nested_numeric_for_chunk()))

        self.assertIn(
            "for r2 = 1, 2, 1 do\n"
            "    for r5 = 1, 2, 1 do\n"
            "        print(r2, r5)\n"
            "    end\n"
            "end",
            source,
        )
        self.assertNotIn("FORNPREP", source)
        self.assertNotIn("FORNLOOP", source)
        self.assertNotIn("-- pc", source)

    def test_side_effect_before_break_is_not_dropped(self):
        source = decompile_chunk(parse_chunk(make_numeric_for_side_effect_before_break_chunk()))

        self.assertIn(
            "if stop then\n"
            "        before_break()\n"
            "        break\n"
            "    end",
            source,
        )
        self.assertLess(source.index("before_break()"), source.index("break"))
        self.assertNotIn("-- pc", source)

    def test_structured_generic_for_uses_recovered_region_map_without_raw_evidence(self):
        chunk = parse_chunk(make_generic_for_named_call_chunk())

        with patch(
            "luau_decompiler.decompile.recover_regions",
            wraps=regions.recover_regions,
            create=True,
        ) as recover_regions:
            source = decompile_chunk(chunk)

        self.assertIn("for key, value in next, items do\n    print(key, value)\nend", source)
        self.assertNotIn("-- pc", source)
        self.assertNotIn("FORGPREP", source)
        self.assertNotIn("FORGLOOP", source)
        recover_regions.assert_called()

    def test_while_conditional_continue_keeps_following_body_statement_in_loop(self):
        chunk = parse_chunk(make_while_conditional_continue_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("while true do\n    if ", source)
        self.assertIn('then\n        continue\n    end\n    print("tick")\nend', source)
        self.assertLess(source.index("continue"), source.index('print("tick")'))
        self.assertNotIn("JUMPIFNOT", source)
        self.assertNotIn("JUMPBACK", source)

    def test_if_break_in_loop_preserves_statement_order_after_break_branch(self):
        chunk = parse_chunk(make_repeat_break_preserves_body_order_chunk())

        source = decompile_chunk(chunk)

        expected = (
            "local x = 0\n"
            "repeat\n"
            "    x = x + 1\n"
            "    if x == 5 then\n"
            "        break\n"
            "    end\n"
            "    step(x)\n"
            "until x >= 10\n"
            "return x"
        )
        self.assertIn(expected, source)
        self.assertLess(source.index("break"), source.index("step(x)"))
        self.assertEqual(source.count("step(x)"), 1)
        self.assertNotIn("-- pc", source)


if __name__ == "__main__":
    unittest.main()
