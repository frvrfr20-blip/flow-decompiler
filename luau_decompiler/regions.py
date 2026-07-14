from __future__ import annotations

from collections import defaultdict
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
_INVERTED_CONDITIONAL_OPS = frozenset(
    {"JUMPIFNOT", "JUMPIFNOTEQ", "JUMPIFNOTLE", "JUMPIFNOTLT"}
)
_CONSTANT_COMPARE_OPS = frozenset(
    {"JUMPXEQKNIL", "JUMPXEQKB", "JUMPXEQKN", "JUMPXEQKS"}
)


def recover_regions(graph: ControlFlowGraph, facts: ControlFlowFacts) -> RegionMap:
    """Recover only graph facts whose structured interpretation is proven locally."""
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

    loops = _recover_loops(blocks, successors, facts, irreducible_nodes)
    block_loops = _block_loops(loops)
    branches = _recover_branches(
        blocks,
        successors,
        facts,
        irreducible_nodes,
        cyclic_nodes,
        loops,
        block_loops,
    )
    join_owners = _join_owners(branches)
    edge_roles = _edge_roles(blocks, successors, loops, block_loops)

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
    loops: Mapping[int, LoopRegion],
    block_loops: Mapping[int, tuple[int, ...]],
) -> dict[int, BranchRegion]:
    branches: dict[int, BranchRegion] = {}
    loop_post_dominators: dict[int, Mapping[int, frozenset[int]]] = {}
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
        owner_headers = block_loops.get(header, ())
        if owner_headers:
            loop = loops[owner_headers[0]]
            local_facts = loop_post_dominators.setdefault(
                loop.header,
                _loop_post_dominators(loop, successors),
            )
            join = _nearest_common_post_dominator(entries, header, local_facts)
            if join is not None:
                branches[header] = BranchRegion(
                    header, true_entry, false_entry, join
                )
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
    inverted = terminal.op.name in _INVERTED_CONDITIONAL_OPS or (
        terminal.op.name in _CONSTANT_COMPARE_OPS
        and terminal.aux is not None
        and bool(terminal.aux & 0x80000000)
    )
    if inverted:
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
    latch_index = _index_for_latches(blocks)

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
        latch_name = "FORNLOOP" if name == "FORNPREP" else "FORGLOOP"
        matching_latches = latch_index.get((latch_name, terminal.a, body), ())
        if not matching_latches:
            continue
        latch_block, latch = matching_latches[0]
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
            body = _while_body(
                natural.header,
                header_terminal,
                natural.nodes,
                successors,
            )
            if body is not None:
                loops_by_header[natural.header] = LoopRegion(
                    LoopKind.WHILE,
                    natural.header,
                    body,
                    terminal.pc,
                    natural.latch,
                    terminal.pc,
                    natural.exits,
                    natural.nodes,
                )
                continue
            guard = _repeat_guard(natural, blocks, successors)
            if guard is not None:
                loops_by_header[natural.header] = LoopRegion(
                    LoopKind.REPEAT,
                    natural.header,
                    natural.header,
                    terminal.pc,
                    natural.latch,
                    guard,
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


def _index_for_latches(
    blocks: Mapping[int, object],
) -> Mapping[tuple[str, int, int], tuple[tuple[int, int], ...]]:
    candidates: dict[tuple[str, int, int], list[tuple[int, int]]] = defaultdict(list)
    for start, block in sorted(blocks.items()):
        terminal = _terminal(block)
        if (
            terminal is not None
            and terminal.op.name in {"FORNLOOP", "FORGLOOP"}
            and terminal.jump_target is not None
        ):
            key = (terminal.op.name, terminal.a, terminal.jump_target)
            candidates[key].append((start, terminal.pc))
    return {
        key: tuple(values)
        for key, values in sorted(candidates.items())
    }


def _while_body(
    header: int,
    terminal: object | None,
    nodes: frozenset[int],
    successors: Mapping[int, tuple[int, ...]],
) -> int | None:
    if terminal is None or terminal.op.name not in _CONDITIONAL_OPS:
        return None
    entries = _branch_entries(terminal, successors[header])
    if entries is None:
        return None
    true_entry, false_entry = entries
    if true_entry in nodes and false_entry not in nodes:
        return true_entry
    return None


def _repeat_guard(
    natural: LoopInfo,
    blocks: Mapping[int, object],
    successors: Mapping[int, tuple[int, ...]],
) -> int | None:
    for node in sorted(natural.nodes):
        terminal = _terminal(blocks.get(node))
        if terminal is None or terminal.op.name not in _CONDITIONAL_OPS:
            continue
        entries = _branch_entries(terminal, successors[node])
        if entries is None:
            continue
        true_entry, false_entry = entries
        if true_entry not in natural.nodes and false_entry == natural.latch:
            return node
    return None


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


def _block_loops(
    loops: Mapping[int, LoopRegion],
) -> dict[int, tuple[int, ...]]:
    containing: dict[int, list[LoopRegion]] = defaultdict(list)
    for loop in loops.values():
        for node in loop.nodes:
            containing[node].append(loop)
    return {
        node: tuple(
            loop.header
            for loop in sorted(
                members,
                key=lambda loop: (len(loop.nodes), loop.header, loop.latch),
            )
        )
        for node, members in sorted(containing.items())
    }


def _loop_post_dominators(
    loop: LoopRegion,
    successors: Mapping[int, tuple[int, ...]],
) -> Mapping[int, frozenset[int]]:
    sink = object()
    local_successors: dict[object, tuple[object, ...]] = {sink: ()}
    for node in loop.nodes:
        targets: list[object] = []
        for target in successors[node]:
            if node == loop.latch_block and target == loop.header:
                targets.append(sink)
            elif target not in loop.nodes:
                targets.append(sink)
            else:
                targets.append(target)
        local_successors[node] = tuple(dict.fromkeys(targets)) or (sink,)

    reverse = {node: [] for node in local_successors}
    for node, targets in local_successors.items():
        for target in targets:
            reverse[target].append(node)
    can_finish = {sink}
    pending: list[object] = [sink]
    while pending:
        node = pending.pop()
        for predecessor in reverse[node]:
            if predecessor not in can_finish:
                can_finish.add(predecessor)
                pending.append(predecessor)

    universe = set(can_finish)
    post_dominators: dict[object, set[object]] = {
        node: ({sink} if node is sink else set(universe))
        for node in can_finish
    }
    changed = True
    while changed:
        changed = False
        for node in sorted(loop.nodes):
            if node not in can_finish:
                continue
            targets = [
                target
                for target in local_successors[node]
                if target in can_finish
            ]
            common = set(post_dominators[targets[0]])
            for target in targets[1:]:
                common.intersection_update(post_dominators[target])
            updated = {node} | common
            if updated != post_dominators[node]:
                post_dominators[node] = updated
                changed = True

    return {
        node: frozenset(value for value in values if value is not sink)
        for node, values in post_dominators.items()
        if node is not sink
    }


def _nearest_common_post_dominator(
    entries: tuple[int, int],
    header: int,
    post_dominators: Mapping[int, frozenset[int]],
) -> int | None:
    if any(entry not in post_dominators for entry in entries):
        return None
    candidates = (
        post_dominators[entries[0]] & post_dominators[entries[1]]
    ) - {header}
    if not candidates:
        return None
    return max(candidates, key=lambda node: (len(post_dominators[node]), -node))


def _edge_roles(
    blocks: Mapping[int, object],
    successors: Mapping[int, tuple[int, ...]],
    loops: Mapping[int, LoopRegion],
    block_loops: Mapping[int, tuple[int, ...]],
) -> dict[tuple[int, int], EdgeRole]:
    roles = {
        (source, target): EdgeRole.NORMAL
        for source, targets in successors.items()
        for target in targets
    }
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
            elif target not in loop.nodes:
                roles[edge] = (
                    EdgeRole.EXIT
                    if _is_structural_exit(source, loop)
                    else EdgeRole.BREAK
                )
            elif _is_continue_edge(
                source,
                target,
                loop,
                blocks,
                successors,
            ):
                roles[edge] = EdgeRole.CONTINUE
            elif (
                loop.kind == LoopKind.WHILE
                and source == loop.header
                and target == loop.body
            ):
                roles[edge] = EdgeRole.BODY
    return roles


def _is_structural_exit(source: int, loop: LoopRegion) -> bool:
    if loop.kind in {LoopKind.NUMERIC_FOR, LoopKind.GENERIC_FOR}:
        return source == loop.latch_block
    if loop.kind == LoopKind.WHILE:
        return source == loop.header
    if loop.kind == LoopKind.REPEAT:
        return source == _continue_block(loop)
    return False


def _is_continue_edge(
    source: int,
    target: int,
    loop: LoopRegion,
    blocks: Mapping[int, object],
    successors: Mapping[int, tuple[int, ...]],
) -> bool:
    if source == loop.latch_block or target != _continue_block(loop):
        return False
    terminal = _terminal(blocks.get(source))
    if (
        terminal is None
        or terminal.op.name not in _CONDITIONAL_OPS
        or terminal.jump_target != target
    ):
        return False
    alternatives = [candidate for candidate in successors[source] if candidate != target]
    return len(alternatives) == 1 and alternatives[0] in loop.nodes


def _continue_block(loop: LoopRegion) -> int:
    return loop.latch_block if loop.continue_target == loop.latch else loop.continue_target


def _terminal(block: object) -> object | None:
    if block is None or not block.instructions:
        return None
    return block.instructions[-1]


def _frozen_mapping(values: Mapping[object, object]) -> Mapping:
    return MappingProxyType(dict(sorted(values.items())))
