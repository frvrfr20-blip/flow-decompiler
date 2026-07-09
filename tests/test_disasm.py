import unittest

from luau_decompiler.disasm import decode_roblox_words, decode_words, encode_abc, encode_ad, encode_e
from luau_decompiler.opcodes import op_index


class DisasmTests(unittest.TestCase):
    def test_decode_signed_ad_and_e_fields(self):
        words = [
            encode_ad("LOADN", 2, -7),
            encode_e("JUMPX", -3),
        ]

        insns = decode_words(words)

        self.assertEqual(insns[0].op.name, "LOADN")
        self.assertEqual(insns[0].a, 2)
        self.assertEqual(insns[0].d, -7)
        self.assertEqual(insns[1].op.name, "JUMPX")
        self.assertEqual(insns[1].e, -3)

    def test_decode_aux_words_and_namecall_fields(self):
        words = [
            encode_abc("NAMECALL", 1, 0, 77),
            5,
            encode_abc("CALL", 1, 2, 1),
        ]

        insns = decode_words(words)

        self.assertEqual(len(insns), 2)
        self.assertEqual(insns[0].pc, 0)
        self.assertEqual(insns[0].next_pc, 2)
        self.assertEqual(insns[0].op.name, "NAMECALL")
        self.assertEqual(insns[0].a, 1)
        self.assertEqual(insns[0].b, 0)
        self.assertEqual(insns[0].c, 77)
        self.assertEqual(insns[0].aux, 5)
        self.assertEqual(insns[1].pc, 2)
        self.assertEqual(insns[1].op.code, op_index("CALL"))

    def test_decode_roblox_encoded_opcode_byte(self):
        insns = decode_roblox_words([0x000100A4, 0x40000000])

        self.assertEqual(insns[0].op.name, "GETIMPORT")
        self.assertEqual(insns[0].word & 0xFF, op_index("GETIMPORT"))
        self.assertEqual(insns[0].a, 0)
        self.assertEqual(insns[0].d, 1)
        self.assertEqual(insns[0].aux, 0x40000000)


if __name__ == "__main__":
    unittest.main()
