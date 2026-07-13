from __future__ import annotations

import struct
from dataclasses import dataclass, field, fields
from typing import Any

from .binary import ChunkDecodeError, Reader
from .disasm import Instruction, decode_encoded_words, decode_roblox_words, decode_words
from .opcodes import CONSTANT_TAGS, TYPE_VERSION_MAX, TYPE_VERSION_MIN, VERSION_MAX, VERSION_MIN


LPF_INLINABLE = 1 << 3
LFT_CALLTARGET = 0


@dataclass(frozen=True)
class ParseLimits:
    max_chunk_bytes: int = 64 * 1024 * 1024
    max_strings: int = 1_000_000
    max_string_bytes: int = 16 * 1024 * 1024
    max_protos: int = 100_000
    max_instructions_per_proto: int = 2_000_000
    max_total_instructions: int = 5_000_000
    max_constants_per_proto: int = 1_000_000
    max_children_per_proto: int = 100_000
    max_debug_locals_per_proto: int = 1_000_000
    max_upvalues_per_proto: int = 1_000_000
    max_line_info_per_proto: int = 2_000_000
    max_feedback_per_proto: int = 1_000_000
    max_typeinfo_bytes: int = 16 * 1024 * 1024
    max_proto_nesting: int = 10_000

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"{item.name} must be a nonnegative integer")


@dataclass(frozen=True)
class Constant:
    kind: str
    value: Any = None


@dataclass(frozen=True)
class DebugLocal:
    name: str | None
    start_pc: int
    end_pc: int
    reg: int


@dataclass
class Proto:
    id: int
    maxstacksize: int
    numparams: int
    numupvalues: int
    is_vararg: bool
    flags: int
    typeinfo: bytes
    code_words: list[int]
    instructions: list[Instruction]
    constants: list[Constant]
    child_protos: list[int]
    linedefined: int
    debugname: str | None
    lineinfo: list[int] = field(default_factory=list)
    abslineinfo: list[int] = field(default_factory=list)
    debug_locals: list[DebugLocal] = field(default_factory=list)
    debug_upvalues: list[str | None] = field(default_factory=list)
    feedback: list[dict[str, int]] = field(default_factory=list)
    has_unknown_opcodes: bool = False
    serialized_size: int | None = None
    cost: int | None = None

    def constant(self, index: int) -> Constant | None:
        if 0 <= index < len(self.constants):
            return self.constants[index]
        return None

    def constant_text(self, index: int) -> str | None:
        const = self.constant(index)
        if const and const.kind == "string":
            return str(const.value)
        return None

    def import_path(self, import_id: int) -> str:
        parts = []
        for index in decompose_import_id(import_id):
            text = self.constant_text(index)
            parts.append(text if text is not None else f"K{index}")
        return ".".join(parts) if parts else f"import<{import_id}>"


@dataclass
class BytecodeChunk:
    version: int
    type_version: int
    strings: list[str]
    userdata_remaps: dict[int, str | None]
    protos: list[Proto]
    main_proto: int
    trailing: bytes = b""


@dataclass
class _ParseState:
    total_instructions: int = 0
    proto_offsets: dict[int, int] = field(default_factory=dict)


def decompose_import_id(value: int) -> tuple[int, ...]:
    count = value >> 30
    ids = []
    if count > 0:
        ids.append((value >> 20) & 1023)
    if count > 1:
        ids.append((value >> 10) & 1023)
    if count > 2:
        ids.append(value & 1023)
    return tuple(ids)


def _read_count(reader: Reader, section: str, limit: int, proto_id: int | None = None) -> int:
    reader.set_context(section, proto_id)
    value = reader.read_varint()
    if value > limit:
        raise ChunkDecodeError(f"{section} count {value} exceeds limit {limit}", reader.absolute_offset, section, proto_id)
    return value


def _read_u8(reader: Reader, section: str, proto_id: int | None = None) -> int:
    reader.set_context(section, proto_id)
    return reader.read_u8()


def _require_fixed_payload(reader: Reader, size: int, section: str, proto_id: int) -> None:
    reader.set_context(section, proto_id)
    if size > reader.remaining:
        raise ChunkDecodeError("unexpected end of bytecode", reader.absolute_offset, section, proto_id)


def _read_string_ref(reader: Reader, strings: list[str], proto_id: int | None = None) -> str | None:
    reader.set_context("string table index", proto_id)
    index = reader.read_varint()
    if index == 0:
        return None
    if index > len(strings):
        raise ChunkDecodeError(
            f"string table index {index} is out of range", reader.absolute_offset, "string table index", proto_id
        )
    return strings[index - 1]


def _read_constant(reader: Reader, strings: list[str], limits: ParseLimits, proto_id: int) -> Constant:
    tag = _read_u8(reader, "constant tag", proto_id)
    kind = CONSTANT_TAGS.get(tag)
    if kind is None:
        raise ChunkDecodeError(f"unknown constant tag {tag}", reader.absolute_offset, "constant tag", proto_id)

    if kind == "nil":
        return Constant(kind)
    if kind == "boolean":
        return Constant(kind, bool(_read_u8(reader, "constant boolean", proto_id)))
    if kind == "number":
        reader.set_context("constant number", proto_id)
        return Constant(kind, reader.read_f64())
    if kind == "string":
        return Constant(kind, _read_string_ref(reader, strings, proto_id))
    if kind == "import":
        reader.set_context("constant import", proto_id)
        return Constant(kind, reader.read_u32())
    if kind == "table":
        count = _read_count(reader, "table constant", limits.max_constants_per_proto, proto_id)
        reader.set_context("table constant", proto_id)
        return Constant(kind, [reader.read_varint() for _ in range(count)])
    if kind == "closure":
        reader.set_context("closure proto index", proto_id)
        return Constant(kind, reader.read_varint())
    if kind == "vector":
        reader.set_context("constant vector", proto_id)
        return Constant(kind, (reader.read_f32(), reader.read_f32(), reader.read_f32(), reader.read_f32()))
    if kind == "table_with_constants":
        count = _read_count(reader, "table_with_constants", limits.max_constants_per_proto, proto_id)
        reader.set_context("table_with_constants", proto_id)
        return Constant(kind, [(reader.read_varint(), reader.read_i32()) for _ in range(count)])
    if kind == "integer":
        negative = bool(_read_u8(reader, "constant integer", proto_id))
        reader.set_context("constant integer", proto_id)
        magnitude = reader.read_varint64()
        return Constant(kind, -magnitude if negative else magnitude)
    if kind == "class_shape":
        reader.set_context("class_shape", proto_id)
        class_name = reader.read_varint()
        property_count = _read_count(reader, "class_shape properties", limits.max_constants_per_proto, proto_id)
        method_count = _read_count(reader, "class_shape methods", limits.max_constants_per_proto, proto_id)
        reader.set_context("class_shape properties", proto_id)
        properties = [reader.read_varint() for _ in range(property_count)]
        reader.set_context("class_shape methods", proto_id)
        methods = [reader.read_varint() for _ in range(method_count)]
        return Constant(kind, {"class_name": class_name, "properties": properties, "methods": methods})
    raise AssertionError(kind)


def _decode_instructions(reader: Reader, code_words: list[int], proto_id: int) -> tuple[list[Instruction], bool]:
    try:
        instructions = decode_words(code_words, tolerate_unknown=True)
        has_unknown_opcodes = any(insn.op.name.startswith("UNKNOWN_") for insn in instructions)
        if has_unknown_opcodes:
            roblox_instructions = decode_roblox_words(code_words, tolerate_unknown=True)
            if not any(insn.op.name.startswith("UNKNOWN_") for insn in roblox_instructions):
                return roblox_instructions, False
            return decode_encoded_words(code_words), True
        return instructions, False
    except (IndexError, ValueError) as exc:
        raise ChunkDecodeError("failed to decode instructions", reader.absolute_offset, "instructions", proto_id) from exc


def _parse_proto(
    reader: Reader,
    version: int,
    strings: list[str],
    limits: ParseLimits,
    state: _ParseState,
    proto_id: int,
    serialized_size: int | None,
) -> Proto:
    state.proto_offsets[proto_id] = reader.absolute_offset
    maxstacksize = _read_u8(reader, "proto header", proto_id)
    numparams = _read_u8(reader, "proto header", proto_id)
    numupvalues = _read_u8(reader, "upvalues", proto_id)
    if numupvalues > limits.max_upvalues_per_proto:
        raise ChunkDecodeError(
            f"upvalues count {numupvalues} exceeds limit {limits.max_upvalues_per_proto}",
            reader.absolute_offset,
            "upvalues",
            proto_id,
        )
    is_vararg = bool(_read_u8(reader, "proto header", proto_id))
    flags = 0
    typeinfo = b""
    if version >= 4:
        flags = _read_u8(reader, "proto flags", proto_id)
        typeinfo_size = _read_count(reader, "typeinfo", limits.max_typeinfo_bytes, proto_id)
        reader.set_context("typeinfo", proto_id)
        typeinfo = reader.read_bytes(typeinfo_size)

    code_count = _read_count(reader, "instructions", limits.max_instructions_per_proto, proto_id)
    if state.total_instructions + code_count > limits.max_total_instructions:
        raise ChunkDecodeError(
            f"total instructions count {state.total_instructions + code_count} exceeds limit {limits.max_total_instructions}",
            reader.absolute_offset,
            "total instructions",
            proto_id,
        )
    state.total_instructions += code_count
    reader.set_context("instructions", proto_id)
    _require_fixed_payload(reader, code_count * 4, "instructions", proto_id)
    code_words = [reader.read_u32() for _ in range(code_count)]
    instructions, has_unknown_opcodes = _decode_instructions(reader, code_words, proto_id)

    constant_count = _read_count(reader, "constants", limits.max_constants_per_proto, proto_id)
    constants = [_read_constant(reader, strings, limits, proto_id) for _ in range(constant_count)]

    child_count = _read_count(reader, "child protos", limits.max_children_per_proto, proto_id)
    reader.set_context("child protos", proto_id)
    child_protos = [reader.read_varint() for _ in range(child_count)]
    linedefined = _read_count(reader, "line defined", (1 << 64) - 1, proto_id)
    debugname = _read_string_ref(reader, strings, proto_id)

    lineinfo: list[int] = []
    abslineinfo: list[int] = []
    if _read_u8(reader, "line info flag", proto_id):
        linegaplog2 = _read_u8(reader, "line info interval", proto_id)
        intervals = ((code_count - 1) >> linegaplog2) + 1 if code_count else 0
        if code_count > limits.max_line_info_per_proto or intervals > limits.max_line_info_per_proto:
            raise ChunkDecodeError(
                f"line info count {max(code_count, intervals)} exceeds limit {limits.max_line_info_per_proto}",
                reader.absolute_offset,
                "line info",
                proto_id,
            )
        _require_fixed_payload(reader, code_count + intervals * 4, "line info", proto_id)
        last = 0
        reader.set_context("line info", proto_id)
        for _ in range(code_count):
            last = (last + reader.read_u8()) & 0xFF
            lineinfo.append(last)
        last_line = 0
        reader.set_context("absolute line info", proto_id)
        for _ in range(intervals):
            last_line += reader.read_i32()
            abslineinfo.append(last_line)

    debug_locals: list[DebugLocal] = []
    debug_upvalues: list[str | None] = []
    if _read_u8(reader, "debug info flag", proto_id):
        local_count = _read_count(reader, "debug locals", limits.max_debug_locals_per_proto, proto_id)
        for _ in range(local_count):
            name = _read_string_ref(reader, strings, proto_id)
            start_pc = _read_count(reader, "debug local start pc", (1 << 64) - 1, proto_id)
            end_pc = _read_count(reader, "debug local end pc", (1 << 64) - 1, proto_id)
            if start_pc > end_pc or end_pc > code_count:
                raise ChunkDecodeError("debug local pc range is out of range", reader.absolute_offset, "debug local pc", proto_id)
            reg = _read_u8(reader, "debug local register", proto_id)
            if reg >= maxstacksize:
                raise ChunkDecodeError(
                    f"debug local register {reg} is out of range", reader.absolute_offset, "debug local register", proto_id
                )
            debug_locals.append(
                DebugLocal(name, start_pc, end_pc, reg)
            )
        upvalue_count = _read_count(reader, "debug upvalues", limits.max_upvalues_per_proto, proto_id)
        debug_upvalues = [_read_string_ref(reader, strings, proto_id) for _ in range(upvalue_count)]

    feedback: list[dict[str, int]] = []
    if version >= 11:
        feedback_count = _read_count(reader, "feedback", limits.max_feedback_per_proto, proto_id)
        instructions_by_pc = {instruction.pc: instruction for instruction in instructions}
        for _ in range(feedback_count):
            kind = _read_u8(reader, "feedback", proto_id)
            if kind != LFT_CALLTARGET:
                raise ChunkDecodeError(f"unknown feedback kind {kind}", reader.absolute_offset, "feedback kind", proto_id)
            reader.set_context("feedback pc", proto_id)
            pc = reader.read_varint()
            instruction = instructions_by_pc.get(pc)
            if instruction is None or instruction.op.name not in {"CALL", "CALLFB"}:
                raise ChunkDecodeError(
                    f"feedback pc {pc} does not reference a call instruction", reader.absolute_offset, "feedback pc", proto_id
                )
            feedback.append({"kind": kind, "pc": pc})

    cost = None
    if version >= 12 and flags & LPF_INLINABLE:
        reader.set_context("cost", proto_id)
        cost = reader.read_varint64()

    return Proto(
        proto_id,
        maxstacksize,
        numparams,
        numupvalues,
        is_vararg,
        flags,
        typeinfo,
        code_words,
        instructions,
        constants,
        child_protos,
        linedefined,
        debugname,
        lineinfo,
        abslineinfo,
        debug_locals,
        debug_upvalues,
        feedback,
        has_unknown_opcodes,
        serialized_size,
        cost,
    )


def _invalid_index(message: str, proto: Proto, state: _ParseState, section: str) -> ChunkDecodeError:
    return ChunkDecodeError(message, state.proto_offsets[proto.id], section, proto.id)


def _validate_indices(protos: list[Proto], state: _ParseState) -> None:
    proto_count = len(protos)
    for proto in protos:
        for child in proto.child_protos:
            if child >= proto_count:
                raise _invalid_index(f"child proto index {child} is out of range", proto, state, "child proto index")
        for constant in proto.constants:
            if constant.kind == "import":
                for index in decompose_import_id(constant.value):
                    if index >= len(proto.constants):
                        raise _invalid_index(
                            f"import constant index {index} is out of range", proto, state, "import constant index"
                        )
            if constant.kind == "closure" and constant.value >= proto_count:
                raise _invalid_index(
                    f"closure proto index {constant.value} is out of range", proto, state, "closure proto index"
                )
            if constant.kind == "table":
                for index in constant.value:
                    if index >= len(proto.constants):
                        raise _invalid_index(f"table constant index {index} is out of range", proto, state, "table constant index")
            if constant.kind == "table_with_constants":
                for key, value in constant.value:
                    if key >= len(proto.constants):
                        raise _invalid_index(
                            f"table_with_constants key index {key} is out of range", proto, state, "table_with_constants index"
                        )
                    if value >= len(proto.constants):
                        raise _invalid_index(
                            f"table_with_constants value index {value} is out of range", proto, state, "table_with_constants index"
                        )
            if constant.kind == "class_shape":
                references = [constant.value["class_name"], *constant.value["properties"], *constant.value["methods"]]
                for index in references:
                    if index >= len(proto.constants):
                        raise _invalid_index(f"class_shape index {index} is out of range", proto, state, "class_shape index")


def _validate_proto_graph(protos: list[Proto], limits: ParseLimits, state: _ParseState) -> None:
    incoming = [0] * len(protos)
    for proto in protos:
        for child in proto.child_protos:
            incoming[child] += 1

    queue = [proto_id for proto_id, count in enumerate(incoming) if count == 0]
    depths = [1] * len(protos)
    next_queue_index = 0
    visited = 0
    while next_queue_index < len(queue):
        proto_id = queue[next_queue_index]
        next_queue_index += 1
        visited += 1
        if depths[proto_id] > limits.max_proto_nesting:
            raise ChunkDecodeError(
                f"proto nesting depth {depths[proto_id]} exceeds limit {limits.max_proto_nesting}",
                state.proto_offsets[proto_id],
                "proto nesting",
                proto_id,
            )
        for child in protos[proto_id].child_protos:
            depths[child] = max(depths[child], depths[proto_id] + 1)
            incoming[child] -= 1
            if incoming[child] == 0:
                queue.append(child)

    if visited != len(protos):
        proto_id = next(index for index, count in enumerate(incoming) if count > 0)
        raise ChunkDecodeError(
            f"proto graph cycle includes proto {proto_id}",
            state.proto_offsets[proto_id],
            "proto graph cycle",
            proto_id,
        )


def parse_chunk(data: bytes, limits: ParseLimits | None = None) -> BytecodeChunk:
    limits = ParseLimits() if limits is None else limits
    if not isinstance(limits, ParseLimits):
        raise TypeError("limits must be a ParseLimits instance or None")
    if len(data) > limits.max_chunk_bytes:
        raise ChunkDecodeError(
            f"chunk size {len(data)} exceeds limit {limits.max_chunk_bytes}", 0, "chunk", None
        )

    reader = Reader(data)
    state = _ParseState()
    try:
        version = _read_u8(reader, "header")
        if version == 0:
            raise ChunkDecodeError("bytecode chunk contains compiler error marker", reader.absolute_offset, "header")
        if version < VERSION_MIN or version > VERSION_MAX:
            raise ChunkDecodeError(
                f"bytecode version mismatch: expected [{VERSION_MIN}..{VERSION_MAX}], got {version}",
                reader.absolute_offset,
                "header",
            )

        type_version = 0
        if version >= 4:
            type_version = _read_u8(reader, "type header")
            if type_version < TYPE_VERSION_MIN or type_version > TYPE_VERSION_MAX:
                raise ChunkDecodeError(
                    f"bytecode type version mismatch: expected [{TYPE_VERSION_MIN}..{TYPE_VERSION_MAX}], got {type_version}",
                    reader.absolute_offset,
                    "type header",
                )

        string_count = _read_count(reader, "strings", limits.max_strings)
        strings = []
        for _ in range(string_count):
            string_size = _read_count(reader, "string bytes", limits.max_string_bytes)
            reader.set_context("string bytes")
            raw = reader.read_bytes(string_size)
            strings.append(raw.decode("utf-8", errors="replace"))

        userdata_remaps: dict[int, str | None] = {}
        if type_version == 3:
            index = _read_u8(reader, "userdata remaps")
            seen_remap_indices: set[int] = set()
            while index:
                if index in seen_remap_indices:
                    raise ChunkDecodeError(
                        f"duplicate userdata remap index {index}", reader.absolute_offset, "userdata remaps"
                    )
                seen_remap_indices.add(index)
                userdata_remaps[index] = _read_string_ref(reader, strings)
                index = _read_u8(reader, "userdata remaps")

        proto_count = _read_count(reader, "protos", limits.max_protos)
        protos = []
        for proto_id in range(proto_count):
            serialized_size = None
            proto_reader = reader
            if version >= 12:
                reader.set_context("proto boundary", proto_id)
                declared_size = reader.read_varint()
                serialized_size = declared_size
                proto_reader = reader.subreader(declared_size, section="proto boundary", proto_id=proto_id)
            proto = _parse_proto(proto_reader, version, strings, limits, state, proto_id, serialized_size)
            if version >= 12 and proto_reader.remaining:
                proto_reader.set_context("proto tail", proto_id)
                proto_reader.skip(proto_reader.remaining)
            protos.append(proto)

        main_proto = _read_count(reader, "main proto", (1 << 64) - 1)
        if main_proto >= len(protos):
            raise ChunkDecodeError(f"main proto index {main_proto} is out of range", reader.absolute_offset, "main proto")
        _validate_indices(protos, state)
        _validate_proto_graph(protos, limits, state)
        trailing = reader.read_bytes(reader.remaining) if reader.remaining else b""
        return BytecodeChunk(version, type_version, strings, userdata_remaps, protos, main_proto, trailing)
    except ChunkDecodeError:
        raise
    except (IndexError, ValueError, struct.error) as exc:
        raise ChunkDecodeError("failed to decode bytecode", reader.absolute_offset, reader.section, reader.proto_id) from exc
