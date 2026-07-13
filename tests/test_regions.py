import unittest
from collections.abc import Mapping
from dataclasses import FrozenInstanceError

from luau_decompiler.cfg import analyze_cfg, build_cfg
from luau_decompiler.disasm import decode_words, encode_abc, encode_ad
from luau_decompiler.regions import EdgeRole, LoopKind, recover_regions


def regions(words):
    graph = build_cfg(decode_words(words))
    return graph, recover_regions(graph, analyze_cfg(graph))


class RegionTests(unittest.TestCase):
    def test_diamond_uses_opcode_true_and_false_entries_not_successor_order(self):
        graph, result = regions(
            [
                encode_ad("JUMPIF", 0, 2),
                encode_abc("NOP", 0, 0, 0),
                encode_ad("JUMP", 0, 1),
                encode_abc("NOP", 0, 0, 0),
                encode_abc("RETURN", 0, 1, 0),
            ]
        )

        branch = result.branch_at(0)

        self.assertEqual((branch.header, branch.true_entry, branch.false_entry, branch.join), (0, 3, 1, 4))
        self.assertEqual(graph.block_at(0).successors, [3, 1])
        self.assertEqual(result.edge_role(1, 4), EdgeRole.NORMAL)

    def test_if_without_else_uses_empty_arm_at_join(self):
        _, result = regions(
            [
                encode_ad("JUMPIFNOT", 0, 3),
                encode_abc("NOP", 0, 0, 0),
                encode_ad("JUMP", 0, 1),
                encode_abc("NOP", 0, 0, 0),
                encode_abc("RETURN", 0, 1, 0),
            ]
        )

        branch = result.branch_at(0)

        self.assertEqual((branch.true_entry, branch.false_entry, branch.join), (1, 4, 4))

    def test_elseif_and_outer_branch_share_one_deterministic_join_owner(self):
        _, result = regions(
            [
                encode_ad("JUMPIF", 0, 2),
                encode_ad("JUMPIF", 1, 2),
                encode_ad("JUMP", 0, 2),
                encode_ad("JUMP", 0, 1),
                encode_ad("JUMP", 0, 0),
                encode_abc("RETURN", 0, 1, 0),
            ]
        )

        self.assertEqual(result.branch_at(0).join, 5)
        self.assertEqual(result.branch_at(1).join, 5)
        self.assertEqual(result.join_owners, {5: 0})

    def test_nested_branches_are_recovered_without_duplicate_join_ownership(self):
        _, result = regions(
            [
                encode_ad("JUMPIF", 0, 3),
                encode_ad("JUMPIFNOT", 1, 2),
                encode_abc("NOP", 0, 0, 0),
                encode_ad("JUMP", 0, 2),
                encode_ad("JUMP", 0, 1),
                encode_abc("NOP", 0, 0, 0),
                encode_abc("RETURN", 0, 1, 0),
            ]
        )

        self.assertEqual(result.branch_at(0).join, 6)
        self.assertEqual(result.branch_at(1).join, 6)
        self.assertEqual(result.join_owners[6], 0)

    def test_terminal_arms_have_no_invented_join_or_else_ownership(self):
        _, result = regions(
            [
                encode_ad("JUMPIF", 0, 2),
                encode_abc("RETURN", 0, 1, 0),
                encode_abc("NOP", 0, 0, 0),
                encode_abc("RETURN", 0, 1, 0),
                encode_abc("RETURN", 0, 1, 0),
            ]
        )

        branch = result.branch_at(0)
        self.assertEqual((branch.true_entry, branch.false_entry, branch.join), (3, 1, None))
        self.assertEqual(result.join_owners, {})

    def test_unreachable_and_irreducible_conditionals_are_declined(self):
        unreachable = build_cfg(
            decode_words(
                [
                    encode_abc("RETURN", 0, 1, 0),
                    encode_ad("JUMPIF", 0, 1),
                    encode_abc("RETURN", 0, 1, 0),
                    encode_abc("RETURN", 0, 1, 0),
                ]
            )
        )
        unreachable_result = recover_regions(unreachable, analyze_cfg(unreachable))

        irreducible_graph = build_cfg(
            decode_words(
                [
                    encode_ad("JUMPIF", 0, 1),
                    encode_ad("JUMP", 0, 0),
                    encode_ad("JUMPIF", 1, -2),
                    encode_abc("RETURN", 0, 1, 0),
                ]
            )
        )
        irreducible_result = recover_regions(irreducible_graph, analyze_cfg(irreducible_graph))

        self.assertEqual(unreachable_result.branches, {})
        self.assertNotIn(2, irreducible_result.branches)
        self.assertEqual(tuple(region.nodes for region in irreducible_result.irreducible), ((1, 2),))

    def test_infinite_cycle_ambiguity_declines_branch_join(self):
        _, result = regions(
            [
                encode_ad("JUMPIF", 0, -1),
                encode_abc("RETURN", 0, 1, 0),
            ]
        )

        self.assertEqual(result.branches, {})

    def test_while_region_and_structural_edge_roles(self):
        _, result = regions(
            [
                encode_ad("JUMPIFNOT", 0, 2),
                encode_abc("NOP", 0, 0, 0),
                encode_ad("JUMPBACK", 0, -3),
                encode_abc("RETURN", 0, 1, 0),
            ]
        )

        loop = result.loop_at(0)

        self.assertEqual((loop.kind, loop.prep, loop.header, loop.body, loop.latch, loop.continue_target, loop.exits), (LoopKind.WHILE, None, 0, 1, 2, 0, (3,)))
        self.assertEqual(result.edge_role(0, 1), EdgeRole.BODY)
        self.assertEqual(result.edge_role(0, 3), EdgeRole.EXIT)
        self.assertEqual(loop.latch_block, 1)
        self.assertEqual(result.edge_role(1, 0), EdgeRole.BACK)

    def test_repeat_region_continues_at_condition_latch(self):
        _, result = regions(
            [
                encode_abc("NOP", 0, 0, 0),
                encode_ad("JUMPIFNOT", 0, -2),
                encode_abc("RETURN", 0, 1, 0),
            ]
        )

        loop = result.loop_at(0)

        self.assertEqual((loop.kind, loop.body, loop.latch, loop.continue_target, loop.exits), (LoopKind.REPEAT, 0, 1, 1, (2,)))
        self.assertEqual(loop.latch_block, 0)
        self.assertEqual(result.edge_role(0, 0), EdgeRole.BACK)

    def test_numeric_for_normalizes_prep_and_uses_a_plus_two_visible_register(self):
        _, result = regions(
            [
                encode_ad("FORNPREP", 1, 4),
                encode_abc("NOP", 0, 0, 0),
                encode_abc("NOP", 0, 0, 0),
                encode_abc("NOP", 0, 0, 0),
                encode_ad("FORNLOOP", 1, -4),
                encode_abc("RETURN", 0, 1, 0),
            ]
        )

        loop = result.loop_at(1)

        self.assertEqual((loop.kind, loop.prep, loop.header, loop.body, loop.latch, loop.continue_target), (LoopKind.NUMERIC_FOR, 0, 1, 1, 4, 4))
        self.assertEqual(loop.visible_register, 3)
        self.assertIsNone(loop.result_base)
        self.assertEqual(result.edge_role(0, 1), EdgeRole.BODY)
        self.assertEqual(result.edge_role(0, 5), EdgeRole.EXIT)
        self.assertEqual(loop.latch_block, 1)
        self.assertEqual(result.edge_role(1, 1), EdgeRole.BACK)

    def test_generic_for_normalizes_prep_and_uses_a_plus_three_result_base(self):
        _, result = regions(
            [
                encode_ad("FORGPREP_NEXT", 2, 6),
                encode_abc("NOP", 0, 0, 0),
                encode_abc("NOP", 0, 0, 0),
                encode_abc("NOP", 0, 0, 0),
                encode_abc("NOP", 0, 0, 0),
                encode_ad("FORGLOOP", 2, -5),
                2,
                encode_abc("RETURN", 0, 1, 0),
            ]
        )

        loop = result.loop_at(1)

        self.assertEqual((loop.kind, loop.prep, loop.header, loop.body, loop.latch, loop.continue_target), (LoopKind.GENERIC_FOR, 0, 1, 1, 5, 5))
        self.assertIsNone(loop.visible_register)
        self.assertEqual(loop.result_base, 5)

    def test_generic_for_prep_variants_accept_a_direct_latch_edge(self):
        for prep_opcode in ("FORGPREP", "FORGPREP_INEXT"):
            with self.subTest(prep_opcode=prep_opcode):
                _, result = regions(
                    [
                        encode_ad(prep_opcode, 0, 4),
                        encode_abc("NOP", 0, 0, 0),
                        encode_abc("NOP", 0, 0, 0),
                        encode_abc("NOP", 0, 0, 0),
                        encode_abc("NOP", 0, 0, 0),
                        encode_ad("FORGLOOP", 0, -5),
                        1,
                        encode_abc("RETURN", 0, 1, 0),
                    ]
                )

                loop = result.loop_at(1)

                self.assertEqual((loop.kind, loop.prep, loop.latch, loop.latch_block), (LoopKind.GENERIC_FOR, 0, 5, 5))
                self.assertEqual(result.edge_role(0, 1), EdgeRole.BODY)
                self.assertEqual(result.edge_role(0, 5), EdgeRole.BODY)

    def test_break_continue_and_branch_join_have_distinct_edge_roles(self):
        _, result = regions(
            [
                encode_ad("JUMPIFNOT", 0, 4),
                encode_ad("JUMPIF", 1, 3),
                encode_ad("JUMPIF", 2, -3),
                encode_ad("JUMPBACK", 0, -4),
                encode_abc("NOP", 0, 0, 0),
                encode_abc("RETURN", 0, 1, 0),
            ]
        )

        self.assertEqual(result.edge_role(1, 5), EdgeRole.BREAK)
        self.assertEqual(result.edge_role(2, 0), EdgeRole.CONTINUE)
        self.assertEqual(result.edge_role(3, 0), EdgeRole.BACK)

    def test_nested_loops_assign_break_to_innermost_owner(self):
        graph = build_cfg(
            decode_words(
                [
                    encode_ad("JUMPIFNOT", 0, 5),
                    encode_ad("JUMPIFNOT", 1, 2),
                    encode_ad("JUMPIF", 2, 1),
                    encode_ad("JUMPBACK", 0, -3),
                    encode_abc("NOP", 0, 0, 0),
                    encode_ad("JUMPBACK", 0, -6),
                    encode_abc("RETURN", 0, 1, 0),
                ]
            )
        )
        result = recover_regions(graph, analyze_cfg(graph))

        self.assertEqual(result.edge_role(2, 4), EdgeRole.BREAK)
        self.assertEqual(result.loop_at(1).exits, (4,))
        self.assertEqual(result.loop_at(0).exits, (6,))

    def test_output_is_immutable_and_reanalysis_is_deterministic_after_graph_mutation(self):
        graph, first = regions(
            [
                encode_ad("JUMPIFNOT", 0, 2),
                encode_abc("NOP", 0, 0, 0),
                encode_ad("JUMPBACK", 0, -3),
                encode_abc("RETURN", 0, 1, 0),
            ]
        )

        for name in ("branches", "loops", "join_owners", "edge_roles", "block_loops"):
            value = getattr(first, name)
            self.assertIsInstance(value, Mapping)
            with self.assertRaises(TypeError):
                value[0] = None
        with self.assertRaises(FrozenInstanceError):
            first.loop_at(0).header = 9
        self.assertEqual(first, recover_regions(graph, analyze_cfg(graph)))

        graph.blocks[0].successors[:] = [1]
        changed = recover_regions(graph, analyze_cfg(graph))

        self.assertNotEqual(first, changed)
        self.assertEqual(first.edge_role(0, 3), EdgeRole.EXIT)


if __name__ == "__main__":
    unittest.main()
