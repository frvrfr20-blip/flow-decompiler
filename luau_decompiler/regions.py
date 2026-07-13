from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from .cfg import ControlFlowFacts, ControlFlowGraph, LoopInfo


class EdgeRole(Enum):
    NORMAL = "normal"
    BODY = "body"
    EXIT = "exit"
    BACK = "back"
    BREAK = "break"
    CONTINUE = "continue"


class LoopKind(Enum):
    WHILE = "while"
    REPEAT = "repeat"
    NUMERIC_FOR = "numeric_for"
    GENERIC_FOR = "generic_for"
    LOOP = "loop"


@dataclass(frozen=True)
class BranchRegion:
    header: int
    true_entry: int
    false_entry: int
    join: int | None


@dataclass(frozen=True)
class LoopRegion:
    kind: LoopKind
    header: int
    body: int
    latch: int
    latch_block: int
    continue_target: int
    exits: tuple[int, ...]
    nodes: frozenset[int]
    prep: int | None = None
    visible_register: int | None = None
    result_base: int | None = None


@dataclass(frozen=True)
class IrreducibleRegion:
    nodes: tuple[int, ...]
    entries: tuple[int, ...]


@dataclass(frozen=True)
class RegionMap:
    branches: Mapping[int, BranchRegion]
    loops: Mapping[int, LoopRegion]
    irreducible: tuple[IrreducibleRegion, ...]
    join_owners: Mapping[int, int]
    edge_roles: Mapping[tuple[int, int], EdgeRole]
    block_loops: Mapping[int, tuple[int, ...]]

    def branch_at(self, header: int) -> BranchRegion:
        return self.branches[header]

    def loop_at(self, header: int) -> LoopRegion:
        return self.loops[header]

    def edge_role(self, source: int, target: int) -> EdgeRole:
        return self.edge_roles.get((source, target), EdgeRole.NORMAL)

    def loops_at(self, block: int) -> tuple[LoopRegion, ...]:
        return tuple(self.loops[header] for header in self.block_loops.get(block, ()))


_CONDITIONAL_OPS = frozenset(
    {
        "JUMPIF",
        "JUMPIFNOT",
        "JUMPIFEQ",
        "JUMPIFLE",
        "JUMPIFLT",
        "JUMPIFNOTEQ",
        "JUMPIFNOTLE",
        "JUMPIFNOTLT",
        "JUMPXEQKNIL",
        "JUMPXEQKB",
        "JUMPXEQKN",
        "JUMPXEQKS",
    }
)
_FOR_PREP_OPS = frozenset({"FORGPREP", "FORGPREP_INEXT", "FORGPREP_NEXT"})


def recover_regions(graph: ControlFlowGraph, facts: ControlFlowFacts) -> RegionMap:
    """Recover only graph facts whose structured interpretation is proven locally."""
    graph._refresh_indexes()
    blocks = {block.start_pc: block for block in graph.blocks}
    successors = {
        start: tuple(sorted({target for target in block.successors if target in blocks}))
        for start, block in sorted(blocks.items())
    }
    irreducible_nodes = frozenset(
        node
        for component in facts.components
        if component.irreducible
        for node in component.nodes
    )
    cyclic_nodes = frozenset(
        node
        for component in facts.components
        if len(component.nodes) > 1
        for node in component.nodes
    ) | frozenset(node for edge in facts.back_edges for node in edge)
    irreducible = tuple(
        IrreducibleRegion(component.nodes, component.entries)
        for component in facts.components
        if component.irreducible
    )

    branches = _recover_branches(
        blocks, successors, facts, irreducible_nodes, cyclic_nodes
    )
    join_owners = _join_owners(branches)
    loops = _recover_loops(blocks, successors, facts, irreducible_nodes)
    block_loops = _block_loops(loops, successors)
    edge_roles = _edge_roles(successors, loops, block_loops)

    return RegionMap(
        branches=_frozen_mapping(branches),
        loops=_frozen_mapping(loops),
        irreducible=irreducible,
        join_owners=_frozen_mapping(join_owners),
        edge_roles=_frozen_mapping(edge_roles),
        block_loops=_frozen_mapping(block_loops),
    )


def _recover_branches(
    blocks: Mapping[int, object],
    successors: Mapping[int, tuple[int, ...]],
    facts: ControlFlowFacts,
    irreducible_nodes: frozenset[int],
    cyclic_nodes: frozenset[int],
) -> dict[int, BranchRegion]:
    branches: dict[int, BranchRegion] = {}
    for header in sorted(blocks):
        if header not in facts.reachable or header in irreducible_nodes:
            continue
        terminal = _terminal(blocks[header])
        if terminal is None or terminal.op.name not in _CONDITIONAL_OPS:
            continue
        entries = _branch_entries(terminal, successors[header])
        if entries is None or any(entry in irreducible_nodes for entry in entries):
            continue
        true_entry, false_entry = entries
        if true_entry not in facts.reachable or false_entry not in facts.reachable:
            continue

        join = facts.immediate_post_dominator.get(header)
        if _valid_join(join, entries, facts, irreducible_nodes):
            branches[header] = BranchRegion(header, true_entry, false_entry, join)
            continue

        # A direct terminal arm is useful branch evidence, but it owns no later block.
        if (
            (not successors[true_entry] or not successors[false_entry])
            and not any(
                successors[entry] and entry in cyclic_nodes
                for entry in entries
            )
        ):
            branches[header] = BranchRegion(header, true_entry, false_entry, None)
    return branches


def _branch_entries(terminal: object, targets: tuple[int, ...]) -> tuple[int, int] | None:
    jump_target = terminal.jump_target
    fallthrough = terminal.next_pc
    if jump_target not in targets or fallthrough not in targets:
        return None
    if terminal.op.name == "JUMPIFNOT":
        return fallthrough, jump_target
    return jump_target, fallthrough


def _valid_join(
    join: int | None,
    entries: tuple[int, int],
    facts: ControlFlowFacts,
    irreducible_nodes: frozenset[int],
) -> bool:
    if join is None or join in irreducible_nodes or join not in facts.reachable:
        return False
    return all(join in facts.post_dominators.get(entry, frozenset()) for entry in entries)


def _join_owners(branches: Mapping[int, BranchRegion]) -> dict[int, int]:
    owners: dict[int, int] = {}
    for header, branch in sorted(branches.items()):
        if branch.join is not None:
            owners.setdefault(branch.join, header)
    return owners


def _recover_loops(
    blocks: Mapping[int, object],
    successors: Mapping[int, tuple[int, ...]],
    facts: ControlFlowFacts,
    irreducible_nodes: frozenset[int],
) -> dict[int, LoopRegion]:
    loops_by_header: dict[int, LoopRegion] = {}
    natural_by_latch = {loop.latch: loop for loop in facts.loops}

    # FOR*PREP sits outside the natural loop, so normalize the whole shape first.
    for prep in sorted(blocks):
        terminal = _terminal(blocks[prep])
        if terminal is None:
            continue
        name = terminal.op.name
        if name != "FORNPREP" and name not in _FOR_PREP_OPS:
            continue
        body = terminal.next_pc
        if body not in blocks or prep not in facts.reachable:
            continue
        matching_latch = _matching_for_latch(blocks, terminal, body, name)
        if matching_latch is None:
            continue
        latch_block, latch = matching_latch
        natural = natural_by_latch.get(latch_block)
        if natural is not None and natural.header != body:
            continue
        normalized = _normalized_for_nodes(
            body, latch_block, prep, natural, successors, facts
        )
        if normalized is None:
            continue
        nodes, exits = normalized
        if natural is not None and nodes & irreducible_nodes:
            continue
        if name == "FORNPREP":
            region = LoopRegion(
                LoopKind.NUMERIC_FOR,
                body,
                body,
                latch,
                latch_block,
                latch,
                exits,
                nodes,
                prep=prep,
                visible_register=terminal.a + 2,
            )
        else:
            region = LoopRegion(
                LoopKind.GENERIC_FOR,
                body,
                body,
                latch,
                latch_block,
                latch,
                exits,
                nodes,
                prep=prep,
                result_base=terminal.a + 3,
            )
        loops_by_header[region.header] = region

    for natural in facts.loops:
        if natural.nodes & irreducible_nodes:
            continue
        if natural.header not in facts.reachable:
            continue
        terminal = _terminal(blocks.get(natural.latch))
        if terminal is None:
            continue
        existing = loops_by_header.get(natural.header)
        if existing is not None and not (
            existing.kind == LoopKind.REPEAT and terminal.op.name == "JUMPBACK"
        ):
            continue
        if terminal.op.name == "JUMPBACK":
            header_terminal = _terminal(blocks.get(natural.header))
            if header_terminal is not None and header_terminal.op.name in _CONDITIONAL_OPS:
                body = _first_inside_successor(
                    natural.header, natural.nodes, successors, natural.header
                )
                if body is None:
                    continue
                loops_by_header[natural.header] = LoopRegion(
                    LoopKind.WHILE,
                    natural.header,
                    body,
                    terminal.pc,
                    natural.latch,
                    natural.header,
                    natural.exits,
                    natural.nodes,
                )
            continue
        if terminal.op.name in _CONDITIONAL_OPS and terminal.jump_target == natural.header:
            loops_by_header[natural.header] = LoopRegion(
                LoopKind.REPEAT,
                natural.header,
                natural.header,
                terminal.pc,
                natural.latch,
                terminal.pc,
                natural.exits,
                natural.nodes,
            )
    return dict(sorted(loops_by_header.items()))


def _matching_for_latch(
    blocks: Mapping[int, object],
    prep_terminal: object,
    body: int,
    prep_name: str,
) -> tuple[int, int] | None:
    latch_name = "FORNLOOP" if prep_name == "FORNPREP" else "FORGLOOP"
    candidates = []
    for start, block in blocks.items():
        terminal = _terminal(block)
        if (
            terminal is not None
            and terminal.op.name == latch_name
            and terminal.a == prep_terminal.a
            and terminal.jump_target == body
        ):
            candidates.append((start, terminal.pc))
    return min(candidates) if candidates else None


def _normalized_for_nodes(
    body: int,
    latch: int,
    prep: int,
    natural: LoopInfo | None,
    successors: Mapping[int, tuple[int, ...]],
    facts: ControlFlowFacts,
) -> tuple[frozenset[int], tuple[int, ...]] | None:
    if natural is not None:
        nodes = frozenset(node for node in natural.nodes if node != prep)
    else:
        forward = _reachable_from(body, successors)
        reverse = _reaching(latch, facts.predecessors)
        nodes = frozenset(forward & reverse)
    if body not in nodes or latch not in nodes:
        return None
    if any(
        predecessor != prep
        for node in nodes
        for predecessor in facts.predecessors[node]
        if predecessor not in nodes
    ):
        return None
    exits = tuple(
        sorted(
            {
                target
                for node in nodes
                for target in successors[node]
                if target not in nodes
            }
        )
    )
    return nodes, exits


def _reachable_from(start: int, successors: Mapping[int, tuple[int, ...]]) -> set[int]:
    seen: set[int] = set()
    pending = [start]
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        seen.add(node)
        pending.extend(successors[node])
    return seen


def _reaching(start: int, predecessors: Mapping[int, tuple[int, ...]]) -> set[int]:
    seen: set[int] = set()
    pending = [start]
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        seen.add(node)
        pending.extend(predecessors[node])
    return seen


def _first_inside_successor(
    source: int,
    nodes: frozenset[int],
    successors: Mapping[int, tuple[int, ...]],
    exclude: int,
) -> int | None:
    candidates = [target for target in successors[source] if target in nodes and target != exclude]
    return min(candidates) if candidates else None


def _block_loops(
    loops: Mapping[int, LoopRegion],
    successors: Mapping[int, tuple[int, ...]],
) -> dict[int, tuple[int, ...]]:
    values: dict[int, tuple[int, ...]] = {}
    all_nodes = sorted({node for loop in loops.values() for node in loop.nodes} | set(successors))
    for node in all_nodes:
        containing = sorted(
            (loop for loop in loops.values() if node in loop.nodes),
            key=lambda loop: (len(loop.nodes), loop.header, loop.latch),
        )
        if containing:
            values[node] = tuple(loop.header for loop in containing)
    return values


def _edge_roles(
    successors: Mapping[int, tuple[int, ...]],
    loops: Mapping[int, LoopRegion],
    block_loops: Mapping[int, tuple[int, ...]],
) -> dict[tuple[int, int], EdgeRole]:
    roles = {(source, target): EdgeRole.NORMAL for source, targets in successors.items() for target in targets}
    for loop in loops.values():
        if loop.prep is not None:
            for target in successors.get(loop.prep, ()):
                if target == loop.body or target == loop.latch:
                    roles[(loop.prep, target)] = EdgeRole.BODY
                elif target in loop.exits:
                    roles[(loop.prep, target)] = EdgeRole.EXIT

    for source, targets in successors.items():
        owner_headers = block_loops.get(source)
        if not owner_headers:
            continue
        loop = loops[owner_headers[0]]
        for target in targets:
            edge = (source, target)
            if source == loop.latch_block and target == loop.header:
                roles[edge] = EdgeRole.BACK
            elif source == loop.header and target in loop.nodes and target != loop.header:
                roles[edge] = EdgeRole.BODY
            elif source == loop.header and target not in loop.nodes:
                roles[edge] = EdgeRole.EXIT
            elif (
                source != loop.latch_block
                and target == _continue_block(loop)
                and target in loop.nodes
            ):
                roles[edge] = EdgeRole.CONTINUE
            elif target not in loop.nodes:
                roles[edge] = EdgeRole.BREAK
    return roles


def _continue_block(loop: LoopRegion) -> int:
    return loop.latch_block if loop.continue_target == loop.latch else loop.continue_target


def _terminal(block: object) -> object | None:
    if block is None or not block.instructions:
        return None
    return block.instructions[-1]


def _frozen_mapping(values: Mapping[object, object]) -> Mapping:
    return MappingProxyType(dict(sorted(values.items())))
