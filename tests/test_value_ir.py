from __future__ import annotations

from dataclasses import FrozenInstanceError
import unittest

from luau_decompiler.value_ir import (
    BlockState,
    CallResultGroup,
    CallValue,
    Effect,
    ExpressionValue,
    LiteralValue,
    RegisterVersion,
    TableValue,
    UnknownValue,
    merge_states,
    requires_materialization,
)


class ValueIrTests(unittest.TestCase):
    def test_values_are_immutable_and_keep_source_identity(self):
        value = ExpressionValue(12, "+", (LiteralValue(10, 1), LiteralValue(11, 2)))

        self.assertEqual(value.source_pc, 12)
        self.assertEqual(value.effect, Effect.PURE)
        with self.assertRaises(FrozenInstanceError):
            value.source_pc = 13

    def test_same_definition_merge_preserves_register_version(self):
        version = RegisterVersion(3, 14, LiteralValue(14, "same"))
        state = BlockState(((3, version),))

        merged = merge_states(20, (state, state))

        self.assertEqual(merged.get(3), version)

    def test_different_definitions_merge_to_sorted_phi_inputs(self):
        left = BlockState(((1, RegisterVersion(1, 8, LiteralValue(8, "left"))),))
        right = BlockState(((1, RegisterVersion(1, 4, LiteralValue(4, "right"))),))

        merged = merge_states(20, (left, right))
        value = merged.get(1).value

        self.assertEqual(value.source_pc, 20)
        self.assertEqual([item.definition_pc for item in value.inputs], [4, 8])

    def test_missing_predecessor_becomes_unknown_phi_input(self):
        present = BlockState(((2, RegisterVersion(2, 5, LiteralValue(5, 1))),))

        merged = merge_states(9, (BlockState(), present))
        value = merged.get(2).value

        missing = next(item.value for item in value.inputs if isinstance(item.value, UnknownValue))
        self.assertEqual(missing.reason, "missing predecessor definition")

    def test_table_identity_survives_register_aliases(self):
        table = TableValue(7, "table@7")
        state = BlockState(
            (
                (0, RegisterVersion(0, 7, table)),
                (1, RegisterVersion(1, 8, table)),
            )
        )

        self.assertIs(state.get(0).value, state.get(1).value)
        self.assertEqual(table.identity, "table@7")

    def test_call_result_groups_distinguish_fixed_and_open_results(self):
        fixed = CallResultGroup(10, 2, 3)
        open_group = CallResultGroup(11, 4, None)

        self.assertEqual(fixed.result_count, 3)
        self.assertFalse(fixed.is_open)
        self.assertTrue(open_group.is_open)
        self.assertEqual(open_group.result(2).result_index, 2)

    def test_materialization_is_required_for_reused_effectful_values_only(self):
        pure = ExpressionValue(3, "+", (LiteralValue(1, 1), LiteralValue(2, 2)))
        call = CallValue(4, "compute", ())
        indexed_read = ExpressionValue(5, "[]", (LiteralValue(1, "table"), LiteralValue(2, "key")), Effect.READ)

        self.assertFalse(requires_materialization(pure, 2))
        self.assertFalse(requires_materialization(call, 1))
        self.assertTrue(requires_materialization(call, 2))
        self.assertTrue(requires_materialization(indexed_read, 2))


if __name__ == "__main__":
    unittest.main()
