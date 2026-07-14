import unittest
from collections.abc import Mapping
from dataclasses import FrozenInstanceError

from luau_decompiler.cfg import analyze_cfg, build_cfg
from luau_decompiler.disasm import decode_words, encode_abc, encode_ad
from luau_decompiler.regions import EdgeRole, LoopKind, recover_regions


# Exact main-proto words emitted by official Luau 0.729 at -O1.
CONTROL_FLOW_0729_WORDS = (
    0x00000041,
    0x00000004,
    0x00010304,
    0x00050104,
    0x00010204,
    0x00070138,
    0x0003042B,
    0x0003044F,
    0x80000001,
    0x03000021,
    0x00010017,
    0x03000022,
    0xFFF90139,
    0x00000104,
    0x00030204,
    0x00040120,
    0x00000002,
    0x01000021,
    0x02010127,
    0xFFFA0018,
    0x02000028,
    0x00030204,
    0x0002001C,
    0x00000002,
    0xFFFB0018,
    0x0004020C,
    0x40300000,
    0x00000306,
    0x01020215,
    0x00010016,
)

LOOPS_0729_WORDS = (
    0x00000041,
    0x00000004,
    0x00010304,
    0x00080104,
    0x00010204,
    0x00070138,
    0x0006034F,
    0x00000000,
    0x0103042B,
    0x0002044F,
    0x00000002,
    0x03000021,
    0xFFF90139,
    0x0004010C,
    0x40300000,
    0x00000235,
    0x00000004,
    0x00020404,
    0x00030504,
    0x00040604,
    0x00050704,
    0x05040237,
    0x00000001,
    0x04020115,
    0x0005013B,
    0x0006054F,
    0x00000005,
    0x0002054F,
    0x00000001,
    0x05000021,
    0xFFFA013A,
    0x80000002,
    0x00000104,
    0x00050204,
    0x00080120,
    0x00000002,
    0x06010127,
    0x0004014F,
    0x00000001,
    0x0003014F,
    0x00000007,
    0x01000021,
    0xFFF60018,
    0x00000204,
    0x06020227,
    0x0002024F,
    0x00000001,
    0x02000021,
    0x00040304,
    0x0002031C,
    0x00000002,
    0xFFF80018,
    0x0009030C,
    0x40800000,
    0x00000406,
    0x01020315,
    0x00010016,
)

# Function 1 (classify) from short_circuit_branches.luau under Luau 0.729.
SHORT_CIRCUIT_CLASSIFY_0729_WORDS = (
    0x00000104,
    0x00030020,
    0x00000001,
    0x00000105,
    0x00020116,
    0x0003004F,
    0x00000001,
    0x0003004F,
    0x80000002,
    0x00030105,
    0x00020116,
    0x000A0104,
    0x00080120,
    0x00000000,
    0x0400012B,
    0x0003014F,
    0x00000001,
    0x0003004F,
    0x80000005,
    0x00060105,
    0x00020116,
    0x00070105,
    0x00020116,
)


def regions(words):
    graph = build_cfg(decode_words(words))
    return graph, recover_regions(graph, analyze_cfg(graph))


def conditional_diamond(opcode, *, aux=None):
    if aux is None:
        return [
            encode_ad(opcode, 0, 2),
            encode_abc("NOP", 0, 0, 0),
            encode_ad("JUMP", 0, 1),
            encode_abc("NOP", 0, 0, 0),
            encode_abc("RETURN", 0, 1, 0),
        ]
    return [
        encode_ad(opcode, 0, 3),
        aux,
        encode_abc("NOP", 0, 0, 0),
        encode_ad("JUMP", 0, 1),
        encode_abc("NOP", 0, 0, 0),
        encode_abc("RETURN", 0, 1, 0),
    ]


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

    def test_branch_polarity_normalizes_register_compare_pairs(self):
        cases = (
            ("JUMPIF", None, True),
            ("JUMPIFNOT", None, False),
            ("JUMPIFEQ", 1, True),
            ("JUMPIFNOTEQ", 1, False),
            ("JUMPIFLT", 1, True),
            ("JUMPIFNOTLT", 1, False),
            ("JUMPIFLE", 1, True),
            ("JUMPIFNOTLE", 1, False),
        )
        for opcode, aux, jump_is_true in cases:
            with self.subTest(opcode=opcode):
                _, result = regions(conditional_diamond(opcode, aux=aux))
                branch = result.branch_at(0)
                target = 3 if aux is None else 4
                fallthrough = 1 if aux is None else 2
                expected = (target, fallthrough) if jump_is_true else (fallthrough, target)
                self.assertEqual((branch.true_entry, branch.false_entry), expected)

    def test_branch_polarity_honors_constant_compare_aux_not_bit(self):
        for opcode in ("JUMPXEQKNIL", "JUMPXEQKB", "JUMPXEQKN", "JUMPXEQKS"):
            with self.subTest(opcode=opcode, not_bit=False):
                _, result = regions(conditional_diamond(opcode, aux=1))
                self.assertEqual(
                    (result.branch_at(0).true_entry, result.branch_at(0).false_entry),
                    (4, 2),
                )
            with self.subTest(opcode=opcode, not_bit=True):
                _, result = regions(conditional_diamond(opcode, aux=0x80000001))
                self.assertEqual(
                    (result.branch_at(0).true_entry, result.branch_at(0).false_entry),
                    (2, 4),
                )

    def test_official_short_circuit_fixture_preserves_inverted_branch_polarity(self):
        _, result = regions(SHORT_CIRCUIT_CLASSIFY_0729_WORDS)

        self.assertEqual(
            (result.branch_at(0).true_entry, result.branch_at(0).false_entry),
            (3, 5),
        )
        self.assertEqual(
            (result.branch_at(7).true_entry, result.branch_at(7).false_entry),
            (9, 11),
        )
        self.assertEqual(
            (result.branch_at(11).true_entry, result.branch_at(11).false_entry),
            (14, 21),
        )
        self.assertEqual(
            (result.branch_at(17).true_entry, result.branch_at(17).false_entry),
            (19, 21),
        )

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

        self.assertEqual(
            (
                loop.kind,
                loop.prep,
                loop.header,
                loop.body,
                loop.latch,
                loop.continue_target,
                loop.exits,
            ),
            (LoopKind.WHILE, None, 0, 1, 2, 2, (3,)),
        )
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

        self.assertEqual(
            (loop.kind, loop.body, loop.latch, loop.continue_target, loop.exits),
            (LoopKind.REPEAT, 0, 1, 1, (2,)),
        )
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

        self.assertEqual(
            (
                loop.kind,
                loop.prep,
                loop.header,
                loop.body,
                loop.latch,
                loop.continue_target,
            ),
            (LoopKind.NUMERIC_FOR, 0, 1, 1, 4, 4),
        )
        self.assertEqual(loop.visible_register, 3)
        self.assertIsNone(loop.result_base)
        self.assertEqual(result.edge_role(0, 1), EdgeRole.BODY)
        self.assertEqual(result.edge_role(0, 5), EdgeRole.EXIT)
        self.assertEqual(loop.latch_block, 1)
        self.assertEqual(result.edge_role(1, 1), EdgeRole.BACK)
        self.assertEqual(result.edge_role(1, 5), EdgeRole.EXIT)

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

        self.assertEqual(
            (
                loop.kind,
                loop.prep,
                loop.header,
                loop.body,
                loop.latch,
                loop.continue_target,
            ),
            (LoopKind.GENERIC_FOR, 0, 1, 1, 5, 5),
        )
        self.assertIsNone(loop.visible_register)
        self.assertEqual(loop.result_base, 5)
        self.assertEqual(result.edge_role(1, 7), EdgeRole.EXIT)

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

                self.assertEqual(
                    (loop.kind, loop.prep, loop.latch, loop.latch_block),
                    (LoopKind.GENERIC_FOR, 0, 5, 5),
                )
                self.assertEqual(result.edge_role(0, 1), EdgeRole.BODY)
                self.assertEqual(result.edge_role(0, 5), EdgeRole.BODY)
                self.assertEqual(result.edge_role(5, 7), EdgeRole.EXIT)

    def test_official_control_flow_regions_recover_repeat_and_normal_if_else_join(self):
        _, result = regions(CONTROL_FLOW_0729_WORDS)

        numeric = result.loop_at(6)
        repeated = result.loop_at(20)

        self.assertEqual(numeric.visible_register, 3)
        self.assertEqual(result.edge_role(12, 13), EdgeRole.EXIT)
        self.assertEqual(result.edge_role(9, 12), EdgeRole.NORMAL)
        self.assertEqual(result.edge_role(11, 12), EdgeRole.NORMAL)
        self.assertEqual(result.branch_at(6).join, 12)
        self.assertEqual(
            (result.branch_at(6).true_entry, result.branch_at(6).false_entry),
            (9, 11),
        )
        self.assertEqual(repeated.kind, LoopKind.REPEAT)
        self.assertEqual(repeated.continue_target, 20)
        self.assertEqual(result.edge_role(20, 25), EdgeRole.EXIT)
        self.assertEqual(result.edge_role(24, 20), EdgeRole.BACK)

    def test_official_loops_regions_distinguish_continue_join_break_and_exit_edges(self):
        _, result = regions(LOOPS_0729_WORDS)

        numeric = result.loop_at(6)
        generic = result.loop_at(25)
        while_loop = result.loop_at(33)
        repeated = result.loop_at(44)

        self.assertEqual(numeric.visible_register, 3)
        self.assertEqual(generic.result_base, 4)
        self.assertEqual(result.edge_role(12, 13), EdgeRole.EXIT)
        self.assertEqual(result.edge_role(30, 32), EdgeRole.EXIT)
        self.assertEqual(result.edge_role(8, 12), EdgeRole.CONTINUE)
        self.assertEqual(result.edge_role(11, 12), EdgeRole.NORMAL)
        self.assertEqual(result.edge_role(27, 30), EdgeRole.CONTINUE)
        self.assertEqual(result.edge_role(29, 30), EdgeRole.NORMAL)

        self.assertEqual(while_loop.kind, LoopKind.WHILE)
        self.assertEqual(while_loop.continue_target, 42)
        self.assertEqual(result.edge_role(33, 43), EdgeRole.EXIT)
        self.assertEqual(result.edge_role(36, 42), EdgeRole.CONTINUE)
        self.assertEqual(result.edge_role(41, 42), EdgeRole.NORMAL)
        self.assertEqual(result.edge_role(39, 43), EdgeRole.BREAK)

        self.assertEqual(repeated.kind, LoopKind.REPEAT)
        self.assertEqual(repeated.continue_target, 48)
        self.assertEqual(result.edge_role(44, 48), EdgeRole.CONTINUE)
        self.assertEqual(result.edge_role(47, 48), EdgeRole.NORMAL)
        self.assertEqual(result.edge_role(48, 52), EdgeRole.EXIT)
        self.assertEqual(result.edge_role(51, 44), EdgeRole.BACK)

    def test_break_continue_and_branch_join_have_distinct_edge_roles(self):
        _, result = regions(
            [
                encode_ad("JUMPIFNOT", 0, 5),
                encode_ad("JUMPIF", 1, 4),
                encode_ad("JUMPIF", 2, 2),
                encode_abc("NOP", 0, 0, 0),
                encode_ad("JUMP", 0, 0),
                encode_ad("JUMPBACK", 0, -6),
                encode_abc("NOP", 0, 0, 0),
                encode_abc("RETURN", 0, 1, 0),
            ]
        )

        self.assertEqual(result.edge_role(1, 6), EdgeRole.BREAK)
        self.assertEqual(result.edge_role(2, 5), EdgeRole.CONTINUE)
        self.assertEqual(result.edge_role(3, 5), EdgeRole.NORMAL)
        self.assertEqual(result.edge_role(5, 0), EdgeRole.BACK)

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
