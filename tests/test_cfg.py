import unittest

from luau_decompiler.cfg import (
    BasicBlock,
    ControlFlowGraph,
    LoopInfo,
    StrongComponent,
    analyze_cfg,
    build_cfg,
)
from luau_decompiler.disasm import decode_words, encode_abc, encode_ad


class CfgTests(unittest.TestCase):
    def test_analyze_cfg_reports_diamond_facts_and_excludes_unreachable_block(self):
        graph = ControlFlowGraph(
            [
                BasicBlock(0, 0, [], [1, 2]),
                BasicBlock(1, 1, [], [3]),
                BasicBlock(2, 2, [], [3]),
                BasicBlock(3, 3, [], []),
                BasicBlock(4, 4, [], []),
            ]
        )

        facts = analyze_cfg(graph)

        self.assertEqual(facts.predecessors, {0: (), 1: (0,), 2: (0,), 3: (1, 2), 4: ()})
        self.assertEqual(facts.reachable, frozenset({0, 1, 2, 3}))
        self.assertEqual(facts.dominators[3], frozenset({0, 3}))
        self.assertEqual(facts.immediate_dominator[3], 0)
        self.assertEqual(facts.post_dominators[0], frozenset({0, 3}))
        self.assertEqual(facts.immediate_post_dominator[0], 3)
        self.assertEqual(facts.dominators[4], frozenset({4}))

    def test_analyze_cfg_reports_single_natural_loop_and_exit(self):
        graph = ControlFlowGraph(
            [
                BasicBlock(0, 0, [], [1]),
                BasicBlock(1, 1, [], [2, 4]),
                BasicBlock(2, 2, [], [3]),
                BasicBlock(3, 3, [], [1, 4]),
                BasicBlock(4, 4, [], []),
            ]
        )

        facts = analyze_cfg(graph)

        self.assertEqual(facts.back_edges, ((3, 1),))
        self.assertEqual(
            facts.loops,
            (LoopInfo(1, 3, frozenset({1, 2, 3}), (4,)),),
        )

    def test_analyze_cfg_reports_nested_natural_loops_in_sorted_order(self):
        graph = ControlFlowGraph(
            [
                BasicBlock(0, 0, [], [1]),
                BasicBlock(1, 1, [], [2, 7]),
                BasicBlock(2, 2, [], [3]),
                BasicBlock(3, 3, [], [4, 6]),
                BasicBlock(4, 4, [], [5]),
                BasicBlock(5, 5, [], [3]),
                BasicBlock(6, 6, [], [1]),
                BasicBlock(7, 7, [], []),
            ]
        )

        facts = analyze_cfg(graph)

        self.assertEqual(facts.back_edges, ((5, 3), (6, 1)))
        self.assertEqual(
            facts.loops,
            (
                LoopInfo(1, 6, frozenset({1, 2, 3, 4, 5, 6}), (7,)),
                LoopInfo(3, 5, frozenset({3, 4, 5}), (6,)),
            ),
        )

    def test_analyze_cfg_reports_multi_entry_strong_component_as_irreducible(self):
        graph = ControlFlowGraph(
            [
                BasicBlock(0, 0, [], [1, 2]),
                BasicBlock(1, 1, [], [2]),
                BasicBlock(2, 2, [], [1, 3]),
                BasicBlock(3, 3, [], []),
            ]
        )

        facts = analyze_cfg(graph)

        self.assertIn(StrongComponent((1, 2), (1, 2), True), facts.components)
        self.assertEqual(facts.back_edges, ())

    def test_analyze_cfg_handles_multiple_terminals_and_non_exiting_component(self):
        graph = ControlFlowGraph(
            [
                BasicBlock(0, 0, [], [1, 2]),
                BasicBlock(1, 1, [], []),
                BasicBlock(2, 2, [], []),
                BasicBlock(3, 3, [], [3]),
            ]
        )

        facts = analyze_cfg(graph)

        self.assertEqual(facts.post_dominators[0], frozenset({0}))
        self.assertIsNone(facts.immediate_post_dominator[0])
        self.assertEqual(facts.post_dominators[3], frozenset({3}))
        self.assertIsNone(facts.immediate_post_dominator[3])
        self.assertEqual(facts.back_edges, ((3, 3),))
        self.assertEqual(facts.loops, (LoopInfo(3, 3, frozenset({3}), ()),))

    def test_analyze_cfg_handles_terminal_only_and_empty_graphs(self):
        terminal_facts = analyze_cfg(ControlFlowGraph([BasicBlock(0, 0, [], [])]))
        empty_facts = analyze_cfg(ControlFlowGraph([]))

        self.assertEqual(terminal_facts.predecessors, {0: ()})
        self.assertEqual(terminal_facts.reachable, frozenset({0}))
        self.assertEqual(terminal_facts.dominators[0], frozenset({0}))
        self.assertEqual(terminal_facts.post_dominators[0], frozenset({0}))
        self.assertIsNone(terminal_facts.immediate_dominator[0])
        self.assertIsNone(terminal_facts.immediate_post_dominator[0])
        self.assertEqual(empty_facts.predecessors, {})
        self.assertEqual(empty_facts.reachable, frozenset())
        self.assertEqual(empty_facts.components, ())

    def test_cfg_splits_jump_targets_and_fallthrough(self):
        words = [
            encode_ad("JUMPIFNOT", 0, 2),
            encode_abc("LOADNIL", 1, 0, 0),
            encode_ad("JUMP", 0, 1),
            encode_abc("LOADB", 1, 1, 0),
            encode_abc("RETURN", 1, 2, 0),
        ]

        cfg = build_cfg(decode_words(words))

        self.assertEqual([block.start_pc for block in cfg.blocks], [0, 1, 3, 4])
        self.assertEqual(cfg.block_at(0).successors, [3, 1])
        self.assertEqual(cfg.block_at(1).successors, [4])
        self.assertEqual(cfg.block_at(3).successors, [4])
        self.assertEqual(cfg.block_at(4).successors, [])

    def test_cfg_splits_aux_conditional_jump_fallthrough_after_aux(self):
        words = [
            encode_ad("JUMPXEQKS", 0, 3),
            0,
            encode_abc("LOADNIL", 1, 0, 0),
            encode_ad("JUMP", 0, 1),
            encode_abc("LOADB", 1, 1, 0),
            encode_abc("RETURN", 1, 2, 0),
        ]

        cfg = build_cfg(decode_words(words))

        self.assertEqual([block.start_pc for block in cfg.blocks], [0, 2, 4, 5])
        self.assertEqual(cfg.block_at(0).successors, [4, 2])
        self.assertEqual(cfg.block_at(2).successors, [5])
        self.assertEqual(cfg.block_at(4).successors, [5])
        self.assertEqual(cfg.block_at(5).successors, [])
        self.assertNotIn(1, cfg._blocks_by_start_pc)
        self.assertNotIn(1, cfg._blocks_by_instruction_pc)

    def test_cfg_starts_a_disconnected_block_after_terminal_instruction(self):
        words = [
            encode_abc("RETURN", 0, 1, 0),
            encode_abc("LOADNIL", 1, 0, 0),
            encode_abc("RETURN", 1, 2, 0),
        ]

        cfg = build_cfg(decode_words(words))

        self.assertEqual([block.start_pc for block in cfg.blocks], [0, 1])
        self.assertEqual([instruction.pc for instruction in cfg.block_at(0).instructions], [0])
        self.assertEqual([instruction.pc for instruction in cfg.block_at(1).instructions], [1, 2])
        with self.assertRaises(KeyError):
            cfg.block_at(2)

    def test_cfg_keeps_dead_instructions_after_jump_out_of_jump_block(self):
        words = [
            encode_ad("JUMP", 0, 2),
            encode_abc("LOADNIL", 1, 0, 0),
            encode_abc("RETURN", 1, 2, 0),
            encode_abc("RETURN", 0, 1, 0),
        ]

        cfg = build_cfg(decode_words(words))

        self.assertEqual([block.start_pc for block in cfg.blocks], [0, 1, 3])
        self.assertEqual([instruction.pc for instruction in cfg.block_at(0).instructions], [0])
        self.assertEqual(cfg.block_at(0).successors, [3])
        self.assertEqual([instruction.pc for instruction in cfg.block_at(1).instructions], [1, 2])

    def test_cfg_does_not_fabricate_out_of_range_jump_target(self):
        cfg = build_cfg(
            decode_words(
                [
                    encode_ad("JUMP", 0, 9),
                    encode_abc("RETURN", 0, 1, 0),
                ]
            )
        )

        facts = analyze_cfg(cfg)

        self.assertEqual([block.start_pc for block in cfg.blocks], [0, 1])
        self.assertEqual(cfg.block_at(0).successors, [])
        self.assertEqual(facts.predecessors, {0: (), 1: ()})
        self.assertNotIn(10, facts.predecessors)


if __name__ == "__main__":
    unittest.main()
