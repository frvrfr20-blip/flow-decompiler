"""Immutable, source-independent values used during Luau reconstruction."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
from typing import Iterable


class Effect(Enum):
    PURE = "pure"
    READ = "read"
    WRITE = "write"
    CALL = "call"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Value:
    source_pc: int
    effect: Effect = Effect.PURE
    identity: str | None = None


@dataclass(frozen=True, init=False)
class LiteralValue(Value):
    literal: object

    def __init__(self, source_pc: int, literal: object) -> None:
        object.__setattr__(self, "source_pc", source_pc)
        object.__setattr__(self, "effect", Effect.PURE)
        object.__setattr__(self, "identity", None)
        object.__setattr__(self, "literal", _freeze_literal(literal))


@dataclass(frozen=True, init=False)
class ExpressionValue(Value):
    operator: str
    inputs: tuple[Value, ...]

    def __init__(
        self,
        source_pc: int,
        operator: str,
        inputs: Iterable[Value],
        effect: Effect = Effect.PURE,
    ) -> None:
        frozen_inputs = tuple(inputs)
        object.__setattr__(self, "source_pc", source_pc)
        object.__setattr__(self, "effect", _strongest_effect((effect, *(value.effect for value in frozen_inputs))))
        object.__setattr__(self, "identity", None)
        object.__setattr__(self, "operator", operator)
        object.__setattr__(self, "inputs", frozen_inputs)


@dataclass(frozen=True, init=False)
class CallValue(Value):
    callee: str
    arguments: tuple[Value, ...]

    def __init__(self, source_pc: int, callee: str, arguments: Iterable[Value]) -> None:
        object.__setattr__(self, "source_pc", source_pc)
        object.__setattr__(self, "effect", Effect.CALL)
        object.__setattr__(self, "identity", f"call@{source_pc}")
        object.__setattr__(self, "callee", callee)
        object.__setattr__(self, "arguments", tuple(arguments))


@dataclass(frozen=True, init=False)
class TableValue(Value):
    def __init__(self, source_pc: int, identity: str | None = None) -> None:
        object.__setattr__(self, "source_pc", source_pc)
        object.__setattr__(self, "effect", Effect.WRITE)
        object.__setattr__(self, "identity", identity or f"table@{source_pc}")


@dataclass(frozen=True, init=False)
class ClosureValue(Value):
    proto_id: int
    captures: tuple[Value, ...]

    def __init__(
        self,
        source_pc: int,
        proto_id: int,
        captures: Iterable[Value] = (),
        identity: str | None = None,
    ) -> None:
        object.__setattr__(self, "source_pc", source_pc)
        object.__setattr__(self, "effect", Effect.PURE)
        object.__setattr__(self, "identity", identity or f"closure@{source_pc}:{proto_id}")
        object.__setattr__(self, "proto_id", proto_id)
        object.__setattr__(self, "captures", tuple(captures))


@dataclass(frozen=True, init=False)
class UnknownValue(Value):
    proto_id: int | None
    opcode: str | None
    reason: str

    def __init__(
        self,
        source_pc: int,
        reason: str,
        proto_id: int | None = None,
        opcode: str | None = None,
    ) -> None:
        object.__setattr__(self, "source_pc", source_pc)
        object.__setattr__(self, "effect", Effect.UNKNOWN)
        object.__setattr__(self, "identity", f"unknown@{source_pc}:{reason}")
        object.__setattr__(self, "proto_id", proto_id)
        object.__setattr__(self, "opcode", opcode)
        object.__setattr__(self, "reason", reason)


@dataclass(frozen=True)
class RegisterVersion:
    register: int
    definition_pc: int
    value: Value

    @property
    def identity(self) -> tuple[int, int]:
        return self.register, self.definition_pc


@dataclass(frozen=True, init=False)
class PhiValue(Value):
    inputs: tuple[RegisterVersion, ...]

    def __init__(self, source_pc: int, inputs: Iterable[RegisterVersion]) -> None:
        ordered = tuple(sorted(inputs, key=_register_version_sort_key))
        effect = _strongest_effect(item.value.effect for item in ordered)
        object.__setattr__(self, "source_pc", source_pc)
        object.__setattr__(self, "effect", effect)
        object.__setattr__(self, "identity", f"phi@{source_pc}")
        object.__setattr__(self, "inputs", ordered)


@dataclass(frozen=True)
class CallResultGroup:
    source_pc: int
    base_register: int
    result_count: int | None
    identity: str | None = None

    def __post_init__(self) -> None:
        if self.base_register < 0:
            raise ValueError("base_register must be non-negative")
        if self.result_count is not None and self.result_count < 0:
            raise ValueError("result_count must be non-negative or None")
        if self.identity is None:
            object.__setattr__(self, "identity", f"call-results@{self.source_pc}:{self.base_register}")

    @property
    def is_open(self) -> bool:
        return self.result_count is None

    def result(self, result_index: int) -> "CallResultValue":
        if result_index < 0 or (self.result_count is not None and result_index >= self.result_count):
            raise IndexError("call result index is outside the fixed result group")
        return CallResultValue(self.source_pc, self, result_index)


@dataclass(frozen=True, init=False)
class CallResultValue(Value):
    group: CallResultGroup
    result_index: int

    def __init__(self, source_pc: int, group: CallResultGroup, result_index: int) -> None:
        object.__setattr__(self, "source_pc", source_pc)
        object.__setattr__(self, "effect", Effect.CALL)
        object.__setattr__(self, "identity", f"{group.identity}:{result_index}")
        object.__setattr__(self, "group", group)
        object.__setattr__(self, "result_index", result_index)


@dataclass(frozen=True)
class BlockState:
    registers: tuple[tuple[int, RegisterVersion], ...] = ()
    result_groups: tuple[CallResultGroup, ...] = ()

    def __post_init__(self) -> None:
        ordered = tuple(sorted(self.registers, key=lambda item: item[0]))
        if len({register for register, _ in ordered}) != len(ordered):
            raise ValueError("block state cannot contain duplicate registers")
        if any(register != version.register for register, version in ordered):
            raise ValueError("state register key must match its register version")
        object.__setattr__(self, "registers", ordered)
        object.__setattr__(self, "result_groups", tuple(sorted(self.result_groups, key=_call_group_sort_key)))

    def get(self, register: int) -> RegisterVersion | None:
        for candidate, version in self.registers:
            if candidate == register:
                return version
        for group in reversed(self.result_groups):
            if group.is_open and register >= group.base_register:
                return RegisterVersion(register, group.source_pc, group.result(register - group.base_register))
        return None

    def with_version(self, version: RegisterVersion) -> "BlockState":
        registers = tuple(
            (register, current)
            for register, current in self.registers
            if register != version.register
        ) + ((version.register, version),)
        return BlockState(registers, self.result_groups)

    def with_alias(self, target: int, source: int, definition_pc: int) -> "BlockState":
        source_version = self.get(source)
        value = (
            source_version.value
            if source_version is not None
            else UnknownValue(definition_pc, "MOVE source has no definition")
        )
        return self.with_version(RegisterVersion(target, definition_pc, value))

    def with_call_results(self, group: CallResultGroup) -> "BlockState":
        groups = tuple(
            candidate
            for candidate in self.result_groups
            if candidate.identity != group.identity and not _call_groups_overlap(candidate, group)
        ) + (group,)
        if group.is_open:
            registers = tuple(
                (register, version)
                for register, version in self.registers
                if register < group.base_register
            )
        else:
            end_register = group.base_register + (group.result_count or 0)
            registers = tuple(
                (register, version)
                for register, version in self.registers
                if not group.base_register <= register < end_register
            )
        state = BlockState(registers, groups)
        count = group.result_count if group.result_count is not None else 1
        for result_index in range(count):
            register = group.base_register + result_index
            state = state.with_version(RegisterVersion(register, group.source_pc, group.result(result_index)))
        return state

    def without_result_groups(self) -> "BlockState":
        return BlockState(self.registers)


def merge_states(block_pc: int, predecessors: Iterable[BlockState]) -> BlockState:
    states = tuple(predecessors)
    register_ids = sorted({register for state in states for register, _ in state.registers})
    merged: list[tuple[int, RegisterVersion]] = []
    for register in register_ids:
        definitions = [state.get(register) for state in states]
        if all(definition is not None and definition == definitions[0] for definition in definitions):
            merged.append((register, definitions[0]))
            continue
        inputs = [
            definition
            if definition is not None
            else RegisterVersion(
                register,
                block_pc,
                UnknownValue(block_pc, "missing predecessor definition"),
            )
            for definition in definitions
        ]
        merged.append((register, RegisterVersion(register, block_pc, PhiValue(block_pc, inputs))))
    common_groups = set(states[0].result_groups) if states else set()
    for state in states[1:]:
        common_groups.intersection_update(state.result_groups)
    return BlockState(tuple(merged), tuple(common_groups))


def requires_materialization(value: Value, use_count: int) -> bool:
    """Whether rendering a value at every use could duplicate observable work."""
    return use_count > 1 and (value.effect is not Effect.PURE or value.identity is not None)


def _freeze_literal(literal: object) -> object:
    if literal is None or isinstance(literal, (bool, int, float, str, bytes)):
        return literal
    if isinstance(literal, (list, tuple)):
        return tuple(_freeze_literal(item) for item in literal)
    if isinstance(literal, dict):
        items = ((_freeze_literal(key), _freeze_literal(value)) for key, value in literal.items())
        return tuple(sorted(items, key=lambda item: (_literal_sort_key(item[0]), _literal_sort_key(item[1]))))
    if isinstance(literal, (set, frozenset)):
        return frozenset(_freeze_literal(item) for item in literal)
    raise TypeError(f"unsupported mutable literal payload: {type(literal).__name__}")


def _literal_sort_key(literal: object) -> tuple[object, ...]:
    if literal is None:
        return ("none",)
    if isinstance(literal, bool):
        return ("bool", literal)
    if isinstance(literal, int):
        return ("int", literal)
    if isinstance(literal, float):
        if math.isnan(literal):
            return ("float", "nan")
        return ("float", literal.hex())
    if isinstance(literal, str):
        return ("str", literal)
    if isinstance(literal, bytes):
        return ("bytes", literal.hex())
    if isinstance(literal, tuple):
        return ("tuple", tuple(_literal_sort_key(item) for item in literal))
    if isinstance(literal, frozenset):
        return ("set", tuple(sorted(_literal_sort_key(item) for item in literal)))
    raise TypeError(f"unsupported frozen literal payload: {type(literal).__name__}")


def _register_version_sort_key(version: RegisterVersion) -> tuple[object, ...]:
    return version.definition_pc, version.register, _value_sort_key(version.value)


def _call_group_sort_key(group: CallResultGroup) -> tuple[object, ...]:
    return (
        group.source_pc,
        group.base_register,
        group.result_count if group.result_count is not None else -1,
        group.identity or "",
    )


def _call_groups_overlap(left: CallResultGroup, right: CallResultGroup) -> bool:
    if left.result_count == 0 or right.result_count == 0:
        return False
    left_end = None if left.is_open else left.base_register + (left.result_count or 0)
    right_end = None if right.is_open else right.base_register + (right.result_count or 0)
    if left_end is not None and left_end <= right.base_register:
        return False
    if right_end is not None and right_end <= left.base_register:
        return False
    return True


def _value_sort_key(value: Value) -> tuple[object, ...]:
    common = (value.__class__.__name__, value.source_pc, value.effect.value, value.identity or "")
    if isinstance(value, LiteralValue):
        return (*common, _literal_sort_key(value.literal))
    if isinstance(value, ExpressionValue):
        return (*common, value.operator, tuple(_value_sort_key(item) for item in value.inputs))
    if isinstance(value, CallValue):
        return (*common, value.callee, tuple(_value_sort_key(item) for item in value.arguments))
    if isinstance(value, ClosureValue):
        return (*common, value.proto_id, tuple(_value_sort_key(item) for item in value.captures))
    if isinstance(value, UnknownValue):
        return (*common, value.proto_id if value.proto_id is not None else -1, value.opcode or "", value.reason)
    if isinstance(value, PhiValue):
        return (*common, tuple(_register_version_sort_key(item) for item in value.inputs))
    if isinstance(value, CallResultValue):
        group = value.group
        return (
            *common,
            group.source_pc,
            group.base_register,
            group.result_count if group.result_count is not None else -1,
            group.identity or "",
            value.result_index,
        )
    return common


def _strongest_effect(effects: Iterable[Effect]) -> Effect:
    return max(effects, key=_effect_rank, default=Effect.UNKNOWN)


def _effect_rank(effect: Effect) -> int:
    return {
        Effect.PURE: 0,
        Effect.READ: 1,
        Effect.WRITE: 2,
        Effect.CALL: 3,
        Effect.UNKNOWN: 4,
    }[effect]
