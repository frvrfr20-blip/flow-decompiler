from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TypeVar, cast
import weakref

from .disasm import Instruction


_Item = TypeVar("_Item")


class _MutationAwareList(list[_Item]):
    def __init__(self, values: Iterable[_Item], changed: Callable[[], None]) -> None:
        super().__init__(values)
        self._changed = changed

    def _is_owned_by(self, changed: Callable[[], None]) -> bool:
        return self._changed == changed

    def _did_change(self) -> None:
        self._changed()

    def append(self, value: _Item) -> None:
        super().append(value)
        self._did_change()

    def extend(self, values: Iterable[_Item]) -> None:
        super().extend(values)
        self._did_change()

    def insert(self, index: int, value: _Item) -> None:
        super().insert(index, value)
        self._did_change()

    def pop(self, index: int = -1) -> _Item:
        value = super().pop(index)
        self._did_change()
        return value

    def remove(self, value: _Item) -> None:
        super().remove(value)
        self._did_change()

    def clear(self) -> None:
        super().clear()
        self._did_change()

    def reverse(self) -> None:
        super().reverse()
        self._did_change()

    def sort(self, *args: object, **kwargs: object) -> None:
        super().sort(*args, **kwargs)
        self._did_change()

    def __setitem__(self, index: int | slice, value: object) -> None:
        super().__setitem__(index, value)
        self._did_change()

    def __delitem__(self, index: int | slice) -> None:
        super().__delitem__(index)
        self._did_change()

    def __iadd__(self, values: Iterable[_Item]) -> _MutationAwareList[_Item]:
        result = super().__iadd__(values)
        self._did_change()
        return result

    def __imul__(self, count: int) -> _MutationAwareList[_Item]:
        result = super().__imul__(count)
        self._did_change()
        return result


@dataclass
class BasicBlock:
    start_pc: int
    end_pc: int
    instructions: list[Instruction]
    successors: list[int]
    _observers: list[weakref.ReferenceType[ControlFlowGraph]] = field(
        default_factory=list,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        self.instructions = self.instructions

    def __setattr__(self, name: str, value: object) -> None:
        previous = getattr(self, name, None)
        if (
            name == "instructions"
            and "_observers" in self.__dict__
        ):
            if not isinstance(value, _MutationAwareList) or not value._is_owned_by(
                self._instructions_changed
            ):
                value = _MutationAwareList(
                    cast(Iterable[Instruction], value),
                    self._instructions_changed,
                )
        object.__setattr__(self, name, value)
        if (
            name == "start_pc"
            and "_observers" in self.__dict__
            and previous != value
        ):
            self._notify_observers()
        elif (
            name == "instructions"
            and "_observers" in self.__dict__
            and previous is not value
        ):
            self._notify_observers()

    def _instructions_changed(self) -> None:
        self._notify_observers()

    def _notify_observers(self) -> None:
        observers: list[weakref.ReferenceType[ControlFlowGraph]] = []
        for observer in self._observers:
            graph = observer()
            if graph is not None:
                graph._mark_indexes_dirty()
                observers.append(observer)
        object.__setattr__(self, "_observers", observers)

    def _register_graph(self, graph: ControlFlowGraph) -> None:
        observers: list[weakref.ReferenceType[ControlFlowGraph]] = []
        registered = False
        for observer in self._observers:
            active_graph = observer()
            if active_graph is None:
                continue
            if active_graph is graph:
                if registered:
                    continue
                registered = True
            observers.append(observer)
        if not registered:
            observers.append(weakref.ref(graph))
        self._observers = observers

    def _unregister_graph(self, graph: ControlFlowGraph) -> None:
        self._observers = [
            observer
            for observer in self._observers
            if observer() is not None and observer() is not graph
        ]

@dataclass
class ControlFlowGraph:
    blocks: list[BasicBlock]
    _blocks_by_start_pc: dict[int, BasicBlock] = field(init=False, repr=False)
    _blocks_by_instruction_pc: dict[int, BasicBlock] = field(init=False, repr=False)
    _observed_blocks: list[BasicBlock] = field(init=False, repr=False, compare=False)
    _indexes_dirty: bool = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_blocks_by_start_pc", {})
        object.__setattr__(self, "_blocks_by_instruction_pc", {})
        object.__setattr__(self, "_observed_blocks", [])
        object.__setattr__(self, "_indexes_dirty", True)
        self.blocks = self.blocks
        self._refresh_indexes()

    def __setattr__(self, name: str, value: object) -> None:
        previous = getattr(self, name, None)
        if name == "blocks" and "_blocks_by_start_pc" in self.__dict__:
            if not isinstance(value, _MutationAwareList) or not value._is_owned_by(
                self._blocks_changed
            ):
                value = _MutationAwareList(
                    cast(Iterable[BasicBlock], value),
                    self._blocks_changed,
                )
        object.__setattr__(self, name, value)
        if (
            name == "blocks"
            and "_blocks_by_start_pc" in self.__dict__
            and previous is not value
        ):
            self._blocks_changed()

    def _blocks_changed(self) -> None:
        for block in self._observed_blocks:
            block._unregister_graph(self)
        self._observed_blocks = list(self.blocks)
        for block in self._observed_blocks:
            block._register_graph(self)
        self._mark_indexes_dirty()

    def _mark_indexes_dirty(self) -> None:
        self._indexes_dirty = True

    def _refresh_indexes(self) -> None:
        if not self._indexes_dirty:
            return

        blocks_by_start_pc: dict[int, BasicBlock] = {}
        blocks_by_instruction_pc: dict[int, BasicBlock] = {}
        for block in self.blocks:
            blocks_by_start_pc.setdefault(block.start_pc, block)
            for instruction in block.instructions:
                blocks_by_instruction_pc.setdefault(instruction.pc, block)
        self._blocks_by_start_pc = blocks_by_start_pc
        self._blocks_by_instruction_pc = blocks_by_instruction_pc
        self._indexes_dirty = False

    def block_at(self, pc: int) -> BasicBlock:
        self._refresh_indexes()
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
    predecessors: Mapping[int, tuple[int, ...]]
    reachable: frozenset[int]
    dominators: Mapping[int, frozenset[int]]
    post_dominators: Mapping[int, frozenset[int]]
    immediate_dominator: Mapping[int, int | None]
    immediate_post_dominator: Mapping[int, int | None]
    back_edges: tuple[tuple[int, int], ...]
    loops: tuple[LoopInfo, ...]
    components: tuple[StrongComponent, ...]


def analyze_cfg(graph: ControlFlowGraph) -> ControlFlowFacts:
    graph._refresh_indexes()
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
    components = _strong_components(successors, sorted_predecessors)
    cyclic_nodes = {
        node
        for component in components
        if len(component.nodes) > 1
        for node in component.nodes
    }
    cyclic_nodes.update(
        node
        for node in nodes
        if node in successors[node]
    )

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
    immediate_dominator = {node: None for node in nodes}
    if nodes:
        entry = nodes[0]
        reachable_successors = {
            node: tuple(successor for successor in successors[node] if successor in reachable)
            for node in reachable
        }
        idoms, reverse_postorder = _immediate_dominators(entry, reachable_successors)
        for node in reverse_postorder[1:]:
            parent = idoms[node]
            dominators[node] = dominators[parent] | {node}
            immediate_dominator[node] = parent

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
    immediate_post_dominator = {node: None for node in nodes}
    if can_exit:
        virtual_exit = object()
        blocked = {
            node
            for node in can_exit
            if any(successor not in can_exit for successor in successors[node])
        }
        reverse_successors: dict[object, tuple[object, ...]] = {
            virtual_exit: tuple(sorted(exits | blocked | (cyclic_nodes & can_exit))),
        }
        reverse_successors.update(
            {node: tuple(sorted_predecessors[node]) for node in can_exit}
        )
        post_idoms, reverse_postorder = _immediate_dominators(
            virtual_exit,
            reverse_successors,
        )
        for node in reverse_postorder[1:]:
            parent = post_idoms[node]
            if parent is virtual_exit:
                continue
            post_dominators[node] = post_dominators[parent] | {node}
            immediate_post_dominator[node] = parent

    return ControlFlowFacts(
        predecessors=_read_only_mapping(sorted_predecessors),
        reachable=frozenset(reachable),
        dominators=_read_only_mapping(dominators),
        post_dominators=_read_only_mapping(post_dominators),
        immediate_dominator=_read_only_mapping(immediate_dominator),
        immediate_post_dominator=_read_only_mapping(immediate_post_dominator),
        back_edges=_back_edges(successors, dominators),
        loops=_natural_loops(successors, sorted_predecessors, dominators),
        components=components,
    )


def _read_only_mapping(values: Mapping[int, object]) -> Mapping[int, object]:
    return MappingProxyType(dict(values))


def _reverse_postorder(
    entry: object,
    successors: Mapping[object, tuple[object, ...]],
) -> tuple[object, ...]:
    seen = {entry}
    postorder: list[object] = []
    frames: list[tuple[object, int]] = [(entry, 0)]

    while frames:
        node, successor_index = frames[-1]
        targets = successors[node]
        if successor_index == len(targets):
            postorder.append(node)
            frames.pop()
            continue
        successor = targets[successor_index]
        frames[-1] = (node, successor_index + 1)
        if successor not in seen:
            seen.add(successor)
            frames.append((successor, 0))

    return tuple(reversed(postorder))


def _immediate_dominators(
    entry: object,
    successors: Mapping[object, tuple[object, ...]],
) -> tuple[dict[object, object], tuple[object, ...]]:
    reverse_postorder = _reverse_postorder(entry, successors)
    order = {node: index for index, node in enumerate(reverse_postorder)}
    predecessors = {node: [] for node in reverse_postorder}
    for node in reverse_postorder:
        for successor in successors[node]:
            predecessors[successor].append(node)

    immediate = {entry: entry}
    changed = True
    while changed:
        changed = False
        for node in reverse_postorder[1:]:
            incoming = [
                predecessor
                for predecessor in predecessors[node]
                if predecessor in immediate
            ]
            if not incoming:
                continue
            candidate = incoming[0]
            for predecessor in incoming[1:]:
                candidate = _intersect_immediate_dominators(
                    candidate,
                    predecessor,
                    immediate,
                    order,
                )
            if immediate.get(node) != candidate:
                immediate[node] = candidate
                changed = True

    return immediate, reverse_postorder


def _intersect_immediate_dominators(
    left: object,
    right: object,
    immediate: Mapping[object, object],
    order: Mapping[object, int],
) -> object:
    while left != right:
        if order[left] > order[right]:
            left = immediate[left]
        else:
            right = immediate[right]
    return left


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

    for root in sorted(successors):
        if root in indices:
            continue

        indices[root] = next_index
        low_links[root] = next_index
        next_index += 1
        stack.append(root)
        on_stack.add(root)
        frames: list[tuple[int, int]] = [(root, 0)]

        while frames:
            node, successor_index = frames[-1]
            targets = successors[node]
            if successor_index < len(targets):
                successor = targets[successor_index]
                frames[-1] = (node, successor_index + 1)
                if successor not in indices:
                    indices[successor] = next_index
                    low_links[successor] = next_index
                    next_index += 1
                    stack.append(successor)
                    on_stack.add(successor)
                    frames.append((successor, 0))
                elif successor in on_stack:
                    low_links[node] = min(low_links[node], indices[successor])
                continue

            frames.pop()
            if low_links[node] == indices[node]:
                component: list[int] = []
                while True:
                    member = stack.pop()
                    on_stack.remove(member)
                    component.append(member)
                    if member == node:
                        break
                component_nodes = tuple(sorted(component))
                node_set = set(component_nodes)
                entries = tuple(
                    member
                    for member in component_nodes
                    if any(predecessor not in node_set for predecessor in predecessors[member])
                )
                components.append(
                    StrongComponent(component_nodes, entries, len(entries) > 1)
                )
            if frames:
                parent, _ = frames[-1]
                low_links[parent] = min(low_links[parent], low_links[node])

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
