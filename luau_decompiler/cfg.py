from __future__ import annotations

from dataclasses import dataclass

from .disasm import Instruction


@dataclass
class BasicBlock:
    start_pc: int
    end_pc: int
    instructions: list[Instruction]
    successors: list[int]


@dataclass
class ControlFlowGraph:
    blocks: list[BasicBlock]

    def block_at(self, pc: int) -> BasicBlock:
        for block in self.blocks:
            if block.start_pc == pc:
                return block
        raise KeyError(pc)


def build_cfg(instructions: list[Instruction]) -> ControlFlowGraph:
    if not instructions:
        return ControlFlowGraph([])

    by_pc = {insn.pc: insn for insn in instructions}
    pcs = [insn.pc for insn in instructions]
    leaders = {instructions[0].pc}

    for insn in instructions:
        target = insn.jump_target
        if target is not None and target in by_pc:
            leaders.add(target)
        if target is not None and insn.is_fallthrough and insn.next_pc in by_pc:
            leaders.add(insn.next_pc)

    sorted_leaders = sorted(leaders)
    blocks: list[BasicBlock] = []

    for i, leader in enumerate(sorted_leaders):
        next_leader = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else None
        block_insns = [insn for insn in instructions if insn.pc >= leader and (next_leader is None or insn.pc < next_leader)]
        if not block_insns:
            continue

        last = block_insns[-1]
        successors = []
        target = last.jump_target
        if target is not None and target in by_pc:
            successors.append(target)
        if last.is_fallthrough and last.next_pc in by_pc and last.next_pc not in successors:
            successors.append(last.next_pc)

        blocks.append(BasicBlock(leader, last.pc, block_insns, successors))

    return ControlFlowGraph(blocks)
