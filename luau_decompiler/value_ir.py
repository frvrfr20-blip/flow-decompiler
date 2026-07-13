"""Immutable, source-independent values used during Luau reconstruction."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
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
        object.__setattr__(self, "literal", literal)


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
        object.__setattr__(self, "source_pc", source_pc)
        object.__setattr__(self, "effect", effect)
        object.__setattr__(self, "identity", None)
        object.__setattr__(self, "operator", operator)
        object.__setattr__(self, "inputs", tuple(inputs))


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
        ordered = tuple(sorted(inputs, key=lambda item: (item.definition_pc, item.register, item.value.identity or "")))
        effect = max((item.value.effect for item in ordered), key=_effect_rank, default=Effect.UNKNOWN)
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

    def __post_init__(self) -> None:
        ordered = tuple(sorted(self.registers, key=lambda item: item[0]))
        if len({register for register, _ in ordered}) != len(ordered):
            raise ValueError("block state cannot contain duplicate registers")
        if any(register != version.register for register, version in ordered):
            raise ValueError("state register key must match its register version")
        object.__setattr__(self, "registers", ordered)

    def get(self, register: int) -> RegisterVersion | None:
        for candidate, version in self.registers:
            if candidate == register:
                return version
        return None

    def with_version(self, version: RegisterVersion) -> "BlockState":
        return BlockState(tuple((register, current) for register, current in self.registers if register != version.register) + ((version.register, version),))


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
    return BlockState(tuple(merged))


def requires_materialization(value: Value, use_count: int) -> bool:
    """Whether rendering a value at every use could duplicate observable work."""
    return use_count > 1 and value.effect is not Effect.PURE


def _effect_rank(effect: Effect) -> int:
    return {
        Effect.PURE: 0,
        Effect.READ: 1,
        Effect.WRITE: 2,
        Effect.CALL: 3,
        Effect.UNKNOWN: 4,
    }[effect]
