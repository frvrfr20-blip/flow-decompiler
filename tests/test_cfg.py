import unittest

from luau_decompiler.cfg import build_cfg
from luau_decompiler.disasm import decode_words, encode_abc, encode_ad


class CfgTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
