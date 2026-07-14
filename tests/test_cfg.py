import gc
import time
import unittest
from collections.abc import Mapping

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

    def test_analyze_cfg_keeps_post_dominators_conservative_at_non_exiting_boundary(self):
        graph = ControlFlowGraph(
            [
                BasicBlock(0, 0, [], [1]),
                BasicBlock(1, 1, [], [3, 5]),
                BasicBlock(2, 2, [], [2]),
                BasicBlock(3, 3, [], []),
                BasicBlock(4, 4, [], [0, 3]),
                BasicBlock(5, 5, [], [0, 1, 2, 3]),
            ]
        )

        facts = analyze_cfg(graph)

        self.assertEqual(facts.post_dominators[4], frozenset({4}))
        self.assertIsNone(facts.immediate_post_dominator[4])

    def test_analyze_cfg_treats_cycles_with_exits_as_post_dominance_frontiers(self):
        self_loop_facts = analyze_cfg(
            ControlFlowGraph(
                [
                    BasicBlock(0, 0, [], [0, 1]),
                    BasicBlock(1, 1, [], []),
                ]
            )
        )
        cycle_facts = analyze_cfg(
            ControlFlowGraph(
                [
                    BasicBlock(0, 0, [], [1]),
                    BasicBlock(1, 1, [], [2, 3]),
                    BasicBlock(2, 2, [], [1]),
                    BasicBlock(3, 3, [], []),
                ]
            )
        )

        self.assertEqual(self_loop_facts.post_dominators[0], frozenset({0}))
        self.assertIsNone(self_loop_facts.immediate_post_dominator[0])
        self.assertEqual(cycle_facts.post_dominators[1], frozenset({1}))
        self.assertIsNone(cycle_facts.immediate_post_dominator[1])
        self.assertEqual(cycle_facts.post_dominators[2], frozenset({2}))
        self.assertIsNone(cycle_facts.immediate_post_dominator[2])
        self.assertEqual(cycle_facts.post_dominators[0], frozenset({0, 1}))
        self.assertEqual(cycle_facts.immediate_post_dominator[0], 1)

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

    def test_analyze_cfg_exposes_read_only_mapping_facts(self):
        facts = analyze_cfg(ControlFlowGraph([BasicBlock(0, 0, [], [])]))

        for name in (
            "predecessors",
            "dominators",
            "post_dominators",
            "immediate_dominator",
            "immediate_post_dominator",
        ):
            mapping = getattr(facts, name)
            self.assertIsInstance(mapping, Mapping)
            self.assertEqual(dict(mapping), mapping)
            with self.assertRaises(TypeError):
                mapping[0] = None

    def test_cfg_block_at_observes_list_mutations(self):
        original = BasicBlock(0, 0, [], [])
        graph = ControlFlowGraph([original])
        appended = BasicBlock(1, 1, [], [])
        replacement = BasicBlock(2, 2, [], [])

        graph.blocks.append(appended)
        self.assertIs(graph.block_at(1), appended)

        graph.blocks.remove(appended)
        with self.assertRaises(KeyError):
            graph.block_at(1)

        graph.blocks[0] = replacement
        self.assertIs(graph.block_at(2), replacement)
        with self.assertRaises(KeyError):
            graph.block_at(0)

        reassigned = BasicBlock(3, 3, [], [])
        graph.blocks = [reassigned]
        self.assertIs(graph.block_at(3), reassigned)
        with self.assertRaises(KeyError):
            graph.block_at(2)

    def test_cfg_block_at_observes_block_start_pc_changes(self):
        block = BasicBlock(0, 0, [], [])
        graph = ControlFlowGraph([block])

        block.start_pc = 7

        self.assertIs(graph.block_at(7), block)
        with self.assertRaises(KeyError):
            graph.block_at(0)

    def test_cfg_constructed_from_another_graphs_blocks_owns_its_callback(self):
        instruction = decode_words([encode_abc("RETURN", 0, 1, 0)])[0]
        block = BasicBlock(0, 0, [instruction], [])
        first = ControlFlowGraph([block])
        second = ControlFlowGraph(first.blocks)

        self.assertIsNot(first.blocks, second.blocks)
        self.assertEqual(len(block._observers), 2)

        block.start_pc = 7

        self.assertTrue(first._indexes_dirty)
        self.assertTrue(second._indexes_dirty)
        self.assertIs(first.block_at(7), block)
        self.assertIs(second.block_at(7), block)

        block.instructions.clear()

        self.assertTrue(first._indexes_dirty)
        self.assertTrue(second._indexes_dirty)
        first._refresh_indexes()
        second._refresh_indexes()
        self.assertEqual(first._blocks_by_instruction_pc, {})
        self.assertEqual(second._blocks_by_instruction_pc, {})

    def test_block_constructed_from_another_blocks_instructions_owns_its_callback(self):
        instruction = decode_words([encode_abc("RETURN", 0, 1, 0)])[0]
        source = BasicBlock(0, 0, [instruction], [])
        copied = BasicBlock(1, 1, source.instructions, [])
        source_graph = ControlFlowGraph([source])
        copied_graph = ControlFlowGraph([copied])

        self.assertIsNot(source.instructions, copied.instructions)

        copied.instructions.clear()

        self.assertFalse(source_graph._indexes_dirty)
        self.assertTrue(copied_graph._indexes_dirty)
        source_graph._refresh_indexes()
        copied_graph._refresh_indexes()
        self.assertIn(instruction.pc, source_graph._blocks_by_instruction_pc)
        self.assertEqual(copied_graph._blocks_by_instruction_pc, {})

    def test_cfg_and_block_keep_owned_list_identity_for_in_place_mutations(self):
        instruction = decode_words([encode_abc("RETURN", 0, 1, 0)])[0]
        block = BasicBlock(0, 0, [instruction], [])
        graph = ControlFlowGraph([block])
        blocks = graph.blocks
        instructions = block.instructions

        graph.blocks = blocks
        block.instructions = instructions
        self.assertIs(graph.blocks, blocks)
        self.assertIs(block.instructions, instructions)
        self.assertFalse(graph._indexes_dirty)

        graph.blocks = [BasicBlock(1, 1, [], [])]
        block.instructions = []
        graph.blocks = blocks
        block.instructions = instructions
        self.assertIs(graph.blocks, blocks)
        self.assertIs(block.instructions, instructions)

        graph.blocks += []
        block.instructions += []
        self.assertIs(graph.blocks, blocks)
        self.assertIs(block.instructions, instructions)
        self.assertTrue(graph._indexes_dirty)

        graph._refresh_indexes()
        graph.blocks *= 1
        block.instructions *= 1
        self.assertIs(graph.blocks, blocks)
        self.assertIs(block.instructions, instructions)
        self.assertTrue(graph._indexes_dirty)

    def test_cfg_instruction_pc_index_maps_decoded_words_and_excludes_aux_words(self):
        cfg = build_cfg(
            decode_words(
                [
                    encode_ad("JUMPXEQKS", 0, 3),
                    0,
                    encode_abc("LOADNIL", 1, 0, 0),
                    encode_abc("RETURN", 1, 2, 0),
                ]
            )
        )

        self.assertIs(cfg._blocks_by_instruction_pc[0], cfg.block_at(0))
        self.assertIs(cfg._blocks_by_instruction_pc[2], cfg.block_at(2))
        self.assertIs(cfg._blocks_by_instruction_pc[3], cfg.block_at(2))
        self.assertNotIn(1, cfg._blocks_by_instruction_pc)

    def test_cfg_instruction_pc_index_observes_all_instruction_list_mutations(self):
        instructions = decode_words(
            [
                encode_abc("RETURN", 0, 1, 0),
                encode_ad("JUMPXEQKS", 0, 3),
                0,
                encode_abc("LOADNIL", 1, 0, 0),
            ]
        )
        cfg = build_cfg([instructions[0]])
        block = cfg.blocks[0]

        def assert_indexed(*pcs: int) -> None:
            self.assertTrue(cfg._indexes_dirty)
            cfg._refresh_indexes()
            self.assertEqual(set(cfg._blocks_by_instruction_pc), set(pcs))
            self.assertNotIn(2, cfg._blocks_by_instruction_pc)
            self.assertFalse(cfg._indexes_dirty)

        self.assertIsInstance(block.instructions, list)
        block.instructions.append(instructions[1])
        assert_indexed(0, 1)

        block.instructions.remove(instructions[1])
        assert_indexed(0)

        block.instructions[0] = instructions[2]
        assert_indexed(3)

        block.instructions[:] = [instructions[0], instructions[1]]
        assert_indexed(0, 1)

        block.instructions += [instructions[2]]
        assert_indexed(0, 1, 3)

        block.instructions *= 0
        assert_indexed()

        block.instructions = [instructions[1]]
        assert_indexed(1)

    def test_cfg_prunes_dead_observers_and_keeps_shared_observers_active(self):
        block = BasicBlock(0, 0, [], [])
        first = ControlFlowGraph([block])
        second = ControlFlowGraph([block])
        instruction = decode_words(
            [
                encode_abc("RETURN", 0, 1, 0),
                encode_abc("LOADNIL", 0, 0, 0),
            ]
        )[1]

        self.assertEqual(len(block._observers), 2)
        block.instructions.append(instruction)
        self.assertTrue(first._indexes_dirty)
        self.assertTrue(second._indexes_dirty)
        first._refresh_indexes()
        second._refresh_indexes()
        self.assertIs(first._blocks_by_instruction_pc[1], block)
        self.assertIs(second._blocks_by_instruction_pc[1], block)

        for _ in range(100):
            graph = ControlFlowGraph([block])
            del graph
        gc.collect()
        third = ControlFlowGraph([block])
        self.assertEqual(len(block._observers), 3)
        self.assertFalse(any(observer() is None for observer in block._observers))
        del third
        gc.collect()

        first.blocks = []
        second.blocks = []
        self.assertEqual(block._observers, [])

    def test_analyze_cfg_handles_large_linear_graph_within_budget(self):
        node_count = 2_000
        graph = ControlFlowGraph(
            [
                BasicBlock(node, node, [], [node + 1] if node + 1 < node_count else [])
                for node in range(node_count)
            ]
        )

        started = time.perf_counter()
        facts = analyze_cfg(graph)
        elapsed = time.perf_counter() - started

        self.assertLess(elapsed, 15.0)
        self.assertEqual(facts.immediate_dominator[node_count - 1], node_count - 2)
        self.assertEqual(facts.immediate_post_dominator[0], 1)
        self.assertEqual(len(facts.components), node_count)
        self.assertEqual(facts.components[0], StrongComponent((0,), (), False))
        self.assertEqual(
            facts.components[-1],
            StrongComponent((node_count - 1,), (node_count - 1,), False),
        )

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

    def test_cfg_partitioning_scales_linearly_with_leader_count(self):
        def build_branch_chain(size: int) -> tuple[ControlFlowGraph, int]:
            pc_reads = 0

            class CountingInstruction:
                def __init__(self, pc: int) -> None:
                    self._pc = pc
                    self.jump_target = pc + 1 if pc + 1 < size else None
                    self.next_pc = pc + 1
                    self.is_fallthrough = False

                @property
                def pc(self) -> int:
                    nonlocal pc_reads
                    pc_reads += 1
                    return self._pc

            graph = build_cfg([CountingInstruction(pc) for pc in range(size)])
            return graph, pc_reads

        small_graph, small_reads = build_branch_chain(64)
        large_graph, large_reads = build_branch_chain(128)

        self.assertEqual(len(small_graph.blocks), 64)
        self.assertEqual(len(large_graph.blocks), 128)
        self.assertEqual(large_graph.block_at(63).successors, [64])
        self.assertEqual(large_graph.block_at(127).successors, [])
        self.assertLess(large_reads, small_reads * 3)

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
