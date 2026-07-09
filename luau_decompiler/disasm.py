from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .opcodes import FASTCALL_OPS, JUMP_D_OPS, NO_FALLTHROUGH_OPS, SKIP_C_OPS, Opcode, encoded_opcode, opcode, op_index, unknown_opcode


def _s16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _s24(value: int) -> int:
    value &= 0xFFFFFF
    return value - 0x1000000 if value & 0x800000 else value


@dataclass(frozen=True)
class Instruction:
    pc: int
    word: int
    op: Opcode
    a: int
    b: int
    c: int
    d: int
    e: int
    aux: int | None
    next_pc: int

    @property
    def raw_words(self) -> tuple[int, ...]:
        return (self.word,) if self.aux is None else (self.word, self.aux)

    @property
    def is_fallthrough(self) -> bool:
        return self.op.name not in NO_FALLTHROUGH_OPS

    @property
    def jump_target(self) -> int | None:
        name = self.op.name
        if name in JUMP_D_OPS:
            return self.pc + self.d + 1
        if name in FASTCALL_OPS:
            return self.pc + self.c + 2
        if name in SKIP_C_OPS and self.c:
            return self.pc + self.c + 1
        if name == "JUMPX":
            return self.pc + self.e + 1
        return None

    def disassemble(self) -> str:
        parts = [f"{self.pc:04d}", self.op.name]
        if self.op.name in {"LOADN", "LOADK", "GETIMPORT", "NEWCLOSURE", "DUPCLOSURE"}:
            parts.append(f"R{self.a}")
            parts.append(str(self.d))
        elif self.op.name in JUMP_D_OPS:
            parts.append(f"R{self.a}")
            parts.append(f"{self.d} -> {self.jump_target}")
        elif self.op.name == "JUMPX":
            parts.append(f"{self.e} -> {self.jump_target}")
        else:
            parts.append(f"A={self.a}")
            parts.append(f"B={self.b}")
            parts.append(f"C={self.c}")
        if self.aux is not None:
            parts.append(f"AUX={self.aux}")
        return " ".join(parts)


def encode_abc(name: str, a: int, b: int, c: int) -> int:
    return op_index(name) | ((a & 0xFF) << 8) | ((b & 0xFF) << 16) | ((c & 0xFF) << 24)


def encode_ad(name: str, a: int, d: int) -> int:
    return op_index(name) | ((a & 0xFF) << 8) | ((d & 0xFFFF) << 16)


def encode_e(name: str, e: int) -> int:
    return op_index(name) | ((e & 0xFFFFFF) << 8)


def _make_instruction(pc: int, word: int, op: Opcode, aux: int | None = None) -> Instruction:
    word &= 0xFFFFFFFF
    a = (word >> 8) & 0xFF
    b = (word >> 16) & 0xFF
    c = (word >> 24) & 0xFF
    d = _s16(word >> 16)
    e = _s24(word >> 8)
    return Instruction(pc, word, op, a, b, c, d, e, aux, pc + op.length)


def _instruction_from_op(words: list[int], pc: int, op: Opcode) -> Instruction:
    word = words[pc] & 0xFFFFFFFF
    aux = None
    if op.has_aux:
        if pc + 1 >= len(words):
            raise ValueError(f"{op.name} at pc {pc} requires AUX word")
        aux = words[pc + 1] & 0xFFFFFFFF
    return _make_instruction(pc, word, op, aux)


def decode_instruction(words: list[int], pc: int, *, tolerate_unknown: bool = False) -> Instruction:
    op_byte = words[pc] & 0xFF
    try:
        op = opcode(op_byte)
    except ValueError:
        if not tolerate_unknown:
            raise
        op = unknown_opcode(op_byte)
    return _instruction_from_op(words, pc, op)


def decode_words(words: Iterable[int], *, tolerate_unknown: bool = False) -> list[Instruction]:
    raw = [int(word) & 0xFFFFFFFF for word in words]
    out: list[Instruction] = []
    pc = 0
    while pc < len(raw):
        insn = decode_instruction(raw, pc, tolerate_unknown=tolerate_unknown)
        out.append(insn)
        pc = insn.next_pc
    return out


def decode_encoded_words(words: Iterable[int]) -> list[Instruction]:
    raw = [int(word) & 0xFFFFFFFF for word in words]
    return [_instruction_from_op(raw, pc, encoded_opcode(raw[pc] & 0xFF)) for pc in range(len(raw))]


def decode_roblox_word(word: int) -> int:
    word &= 0xFFFFFFFF
    decoded_opcode = ((word & 0xFF) * 203) & 0xFF
    return (word & 0xFFFFFF00) | decoded_opcode


def decode_roblox_words(words: Iterable[int], *, tolerate_unknown: bool = False) -> list[Instruction]:
    raw = [int(word) & 0xFFFFFFFF for word in words]
    out: list[Instruction] = []
    pc = 0
    while pc < len(raw):
        word = decode_roblox_word(raw[pc])
        op_byte = word & 0xFF
        try:
            op = opcode(op_byte)
        except ValueError:
            if not tolerate_unknown:
                raise
            op = unknown_opcode(op_byte)
        aux = None
        if op.has_aux:
            if pc + 1 >= len(raw):
                raise ValueError(f"{op.name} at pc {pc} requires AUX word")
            aux = raw[pc + 1]
        insn = _make_instruction(pc, word, op, aux)
        out.append(insn)
        pc = insn.next_pc
    return out
