from __future__ import annotations

from dataclasses import dataclass, field

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
    _blocks_by_start_pc: dict[int, BasicBlock] = field(init=False, repr=False)
    _blocks_by_instruction_pc: dict[int, BasicBlock] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._blocks_by_start_pc = {block.start_pc: block for block in self.blocks}
        self._blocks_by_instruction_pc = {
            instruction.pc: block
            for block in self.blocks
            for instruction in block.instructions
        }

    def block_at(self, pc: int) -> BasicBlock:
        return self._blocks_by_start_pc[pc]


@dataclass(frozen=True)
class LoopInfo:
    header: int
    latch: int
    nodes: frozenset[int]
    exits: tuple[int, ...]


@dataclass(frozen=True)
class StrongComponent:
    nodes: tuple[int, ...]
    entries: tuple[int, ...]
    irreducible: bool


@dataclass(frozen=True)
class ControlFlowFacts:
    predecessors: dict[int, tuple[int, ...]]
    reachable: frozenset[int]
    dominators: dict[int, frozenset[int]]
    post_dominators: dict[int, frozenset[int]]
    immediate_dominator: dict[int, int | None]
    immediate_post_dominator: dict[int, int | None]
    back_edges: tuple[tuple[int, int], ...]
    loops: tuple[LoopInfo, ...]
    components: tuple[StrongComponent, ...]


def analyze_cfg(graph: ControlFlowGraph) -> ControlFlowFacts:
    nodes = tuple(sorted(graph._blocks_by_start_pc))
    successors = {
        node: tuple(
            sorted(
                successor
                for successor in set(graph._blocks_by_start_pc[node].successors)
                if successor in graph._blocks_by_start_pc
            )
        )
        for node in nodes
    }
    predecessors = {node: [] for node in nodes}
    for node in nodes:
        for successor in successors[node]:
            predecessors[successor].append(node)
    sorted_predecessors = {
        node: tuple(sorted(predecessors[node]))
        for node in nodes
    }

    reachable: set[int] = set()
    if nodes:
        pending = [nodes[0]]
        while pending:
            node = pending.pop()
            if node in reachable:
                continue
            reachable.add(node)
            pending.extend(successors[node])

    dominators = {node: frozenset({node}) for node in nodes}
    if nodes:
        entry = nodes[0]
        reachable_nodes = frozenset(reachable)
        for node in reachable - {entry}:
            dominators[node] = reachable_nodes

        changed = True
        while changed:
            changed = False
            for node in nodes:
                if node == entry or node not in reachable:
                    continue
                incoming = [
                    dominators[predecessor]
                    for predecessor in sorted_predecessors[node]
                    if predecessor in reachable
                ]
                common = set.intersection(*(set(values) for values in incoming)) if incoming else set()
                updated = frozenset(common | {node})
                if updated != dominators[node]:
                    dominators[node] = updated
                    changed = True

    exits = {node for node in nodes if not successors[node]}
    can_exit = set(exits)
    pending = list(exits)
    while pending:
        node = pending.pop()
        for predecessor in sorted_predecessors[node]:
            if predecessor not in can_exit:
                can_exit.add(predecessor)
                pending.append(predecessor)

    post_dominators = {node: frozenset({node}) for node in nodes}
    for node in can_exit - exits:
        post_dominators[node] = frozenset(can_exit)

    changed = True
    while changed:
        changed = False
        for node in nodes:
            if node not in can_exit or node in exits:
                continue
            if any(successor not in can_exit for successor in successors[node]):
                updated = frozenset({node})
            else:
                outgoing = [post_dominators[successor] for successor in successors[node]]
                common = set.intersection(*(set(values) for values in outgoing)) if outgoing else set()
                updated = frozenset(common | {node})
            if updated != post_dominators[node]:
                post_dominators[node] = updated
                changed = True

    return ControlFlowFacts(
        predecessors=sorted_predecessors,
        reachable=frozenset(reachable),
        dominators=dominators,
        post_dominators=post_dominators,
        immediate_dominator=_immediate_relations(dominators),
        immediate_post_dominator=_immediate_relations(post_dominators),
        back_edges=_back_edges(successors, dominators),
        loops=_natural_loops(successors, sorted_predecessors, dominators),
        components=_strong_components(successors, sorted_predecessors),
    )


def _immediate_relations(
    relations: dict[int, frozenset[int]],
) -> dict[int, int | None]:
    immediate: dict[int, int | None] = {}
    for node, values in relations.items():
        strict_values = sorted(values - {node})
        immediate[node] = next(
            (
                candidate
                for candidate in strict_values
                if not any(
                    candidate in relations[other]
                    for other in strict_values
                    if other != candidate
                )
            ),
            None,
        )
    return immediate


def _back_edges(
    successors: dict[int, tuple[int, ...]],
    dominators: dict[int, frozenset[int]],
) -> tuple[tuple[int, int], ...]:
    return tuple(
        sorted(
            (latch, header)
            for latch, targets in successors.items()
            for header in targets
            if header in dominators[latch]
        )
    )


def _natural_loops(
    successors: dict[int, tuple[int, ...]],
    predecessors: dict[int, tuple[int, ...]],
    dominators: dict[int, frozenset[int]],
) -> tuple[LoopInfo, ...]:
    loops: list[LoopInfo] = []
    for latch, header in _back_edges(successors, dominators):
        nodes = {header, latch}
        pending = [latch]
        while pending:
            node = pending.pop()
            for predecessor in predecessors[node]:
                if predecessor != header and predecessor not in nodes:
                    nodes.add(predecessor)
                    pending.append(predecessor)
        exits = tuple(
            sorted(
                {
                    successor
                    for node in nodes
                    for successor in successors[node]
                    if successor not in nodes
                }
            )
        )
        loops.append(LoopInfo(header, latch, frozenset(nodes), exits))
    return tuple(
        sorted(
            loops,
            key=lambda loop: (loop.header, loop.latch, tuple(sorted(loop.nodes)), loop.exits),
        )
    )


def _strong_components(
    successors: dict[int, tuple[int, ...]],
    predecessors: dict[int, tuple[int, ...]],
) -> tuple[StrongComponent, ...]:
    indices: dict[int, int] = {}
    low_links: dict[int, int] = {}
    stack: list[int] = []
    on_stack: set[int] = set()
    components: list[StrongComponent] = []
    next_index = 0

    def visit(node: int) -> None:
        nonlocal next_index
        indices[node] = next_index
        low_links[node] = next_index
        next_index += 1
        stack.append(node)
        on_stack.add(node)

        for successor in successors[node]:
            if successor not in indices:
                visit(successor)
                low_links[node] = min(low_links[node], low_links[successor])
            elif successor in on_stack:
                low_links[node] = min(low_links[node], indices[successor])

        if low_links[node] != indices[node]:
            return

        nodes: list[int] = []
        while True:
            member = stack.pop()
            on_stack.remove(member)
            nodes.append(member)
            if member == node:
                break
        component_nodes = tuple(sorted(nodes))
        node_set = set(component_nodes)
        entries = tuple(
            member
            for member in component_nodes
            if any(predecessor not in node_set for predecessor in predecessors[member])
        )
        components.append(
            StrongComponent(component_nodes, entries, len(entries) > 1)
        )

    for node in sorted(successors):
        if node not in indices:
            visit(node)

    return tuple(sorted(components, key=lambda component: component.nodes))


def build_cfg(instructions: list[Instruction]) -> ControlFlowGraph:
    if not instructions:
        return ControlFlowGraph([])

    sorted_instructions = sorted(instructions, key=lambda instruction: instruction.pc)
    by_pc = {insn.pc: insn for insn in sorted_instructions}
    leaders = {sorted_instructions[0].pc}

    for insn in sorted_instructions:
        target = insn.jump_target
        if target is not None and target in by_pc:
            leaders.add(target)
        if target is not None and insn.is_fallthrough and insn.next_pc in by_pc:
            leaders.add(insn.next_pc)
        if not insn.is_fallthrough and insn.next_pc in by_pc:
            leaders.add(insn.next_pc)

    sorted_leaders = sorted(leaders)
    blocks: list[BasicBlock] = []

    for i, leader in enumerate(sorted_leaders):
        next_leader = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else None
        block_insns = [
            insn
            for insn in sorted_instructions
            if insn.pc >= leader and (next_leader is None or insn.pc < next_leader)
        ]
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
