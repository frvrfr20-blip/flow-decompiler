from __future__ import annotations

from dataclasses import FrozenInstanceError
from itertools import permutations
import unittest

from luau_decompiler.value_ir import (
    BlockState,
    CallResultGroup,
    CallValue,
    ClosureValue,
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

    def test_equal_pc_phi_inputs_are_independent_of_predecessor_order(self):
        left = BlockState(((1, RegisterVersion(1, 4, LiteralValue(4, "left"))),))
        right = BlockState(((1, RegisterVersion(1, 4, LiteralValue(4, "right"))),))

        forward = merge_states(20, (left, right)).get(1).value
        reversed_order = merge_states(20, (right, left)).get(1).value

        self.assertEqual(forward, reversed_order)
        self.assertEqual([item.value.literal for item in forward.inputs], ["left", "right"])

    def test_equal_pc_phi_inputs_have_one_order_for_all_predecessor_permutations(self):
        states = tuple(
            BlockState(((1, RegisterVersion(1, 4, LiteralValue(4, literal))),))
            for literal in ("middle", "last", "first")
        )

        merged_values = {
            merge_states(20, order).get(1).value
            for order in permutations(states)
        }

        self.assertEqual(len(merged_values), 1)
        value = merged_values.pop()
        self.assertEqual([item.value.literal for item in value.inputs], ["first", "last", "middle"])

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

    def test_block_state_retains_fixed_call_group_through_move(self):
        group = CallResultGroup(10, 2, 3)

        state = BlockState().with_call_results(group).with_alias(8, 3, 12)
        moved = state.get(8).value

        self.assertIs(moved.group, group)
        self.assertEqual(moved.result_index, 1)

    def test_block_state_resolves_and_moves_open_call_results(self):
        group = CallResultGroup(10, 2, None)

        state = BlockState().with_call_results(group).with_alias(8, 5, 12)
        moved = state.get(8).value

        self.assertIs(moved.group, group)
        self.assertEqual(moved.result_index, 3)

    def test_open_call_group_replaces_stale_register_definitions(self):
        stale = RegisterVersion(3, 4, LiteralValue(4, "stale"))
        group = CallResultGroup(10, 2, None)

        state = BlockState(((3, stale),)).with_call_results(group)
        result = state.get(3).value

        self.assertIs(result.group, group)
        self.assertEqual(result.result_index, 1)

    def test_closure_capture_identity_requires_materialization_when_reused(self):
        table = TableValue(4)
        closure = ClosureValue(5, 2, (table,))

        self.assertIs(closure.captures[0], table)
        self.assertTrue(requires_materialization(closure, 2))

    def test_materialization_is_required_for_reused_effectful_values_only(self):
        pure = ExpressionValue(3, "+", (LiteralValue(1, 1), LiteralValue(2, 2)))
        call = CallValue(4, "compute", ())
        indexed_read = ExpressionValue(5, "[]", (LiteralValue(1, "table"), LiteralValue(2, "key")), Effect.READ)

        self.assertFalse(requires_materialization(pure, 2))
        self.assertFalse(requires_materialization(call, 1))
        self.assertTrue(requires_materialization(call, 2))
        self.assertTrue(requires_materialization(indexed_read, 2))

    def test_literal_values_recursively_freeze_mutable_payloads(self):
        payload = {"items": [1, {"tags": {"a", "b"}}]}

        value = LiteralValue(4, payload)
        frozen = value.literal
        payload["items"].append(2)
        payload["items"][1]["tags"].add("c")

        self.assertEqual(value.literal, frozen)
        self.assertEqual(
            value.literal,
            (("items", (1, (("tags", frozenset({"a", "b"})),))),),
        )
        self.assertIsInstance(hash(value), int)

    def test_expression_effect_composes_effectful_inputs(self):
        call = CallValue(3, "compute", ())
        read = ExpressionValue(4, "[]", (LiteralValue(1, "table"),), Effect.READ)
        write = TableValue(4)
        unknown = UnknownValue(4, "opaque")

        call_expression = ExpressionValue(5, "+", (call, LiteralValue(5, 1)))
        read_expression = ExpressionValue(6, "+", (read, LiteralValue(6, 1)))
        write_expression = ExpressionValue(7, "+", (write, LiteralValue(7, 1)))
        unknown_expression = ExpressionValue(7, "+", (unknown, LiteralValue(7, 1)))

        self.assertEqual(call_expression.effect, Effect.CALL)
        self.assertEqual(read_expression.effect, Effect.READ)
        self.assertEqual(write_expression.effect, Effect.WRITE)
        self.assertEqual(unknown_expression.effect, Effect.UNKNOWN)
        self.assertTrue(requires_materialization(call_expression, 2))
        self.assertTrue(requires_materialization(read_expression, 2))
        self.assertTrue(requires_materialization(write_expression, 2))
        self.assertTrue(requires_materialization(unknown_expression, 2))


if __name__ == "__main__":
    unittest.main()
