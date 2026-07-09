import unittest

from luau_decompiler.chunk import parse_chunk
from luau_decompiler.decompile import decompile_chunk
from tests.test_chunk import (
    make_repeat_break_preserves_body_order_chunk,
    make_while_conditional_continue_chunk,
)


class ControlFlowExtraTests(unittest.TestCase):
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
