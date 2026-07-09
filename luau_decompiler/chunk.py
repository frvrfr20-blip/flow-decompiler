from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .binary import Reader
from .disasm import Instruction, decode_encoded_words, decode_roblox_words, decode_words
from .opcodes import CONSTANT_TAGS, TYPE_VERSION_MAX, TYPE_VERSION_MIN, VERSION_MAX, VERSION_MIN


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


def _read_string_ref(reader: Reader, strings: list[str]) -> str | None:
    index = reader.read_varint()
    if index == 0:
        return None
    try:
        return strings[index - 1]
    except IndexError as exc:
        raise ValueError(f"string table index {index} is out of range") from exc


def _read_constant(reader: Reader, strings: list[str]) -> Constant:
    tag = reader.read_u8()
    kind = CONSTANT_TAGS.get(tag)
    if kind is None:
        raise ValueError(f"unknown constant tag {tag}")

    if kind == "nil":
        return Constant(kind)
    if kind == "boolean":
        return Constant(kind, bool(reader.read_u8()))
    if kind == "number":
        return Constant(kind, reader.read_f64())
    if kind == "string":
        return Constant(kind, _read_string_ref(reader, strings))
    if kind == "import":
        return Constant(kind, reader.read_u32())
    if kind == "table":
        return Constant(kind, [reader.read_varint() for _ in range(reader.read_varint())])
    if kind == "closure":
        return Constant(kind, reader.read_varint())
    if kind == "vector":
        return Constant(kind, (reader.read_f32(), reader.read_f32(), reader.read_f32(), reader.read_f32()))
    if kind == "table_with_constants":
        count = reader.read_varint()
        return Constant(kind, [(reader.read_varint(), reader.read_i32()) for _ in range(count)])
    if kind == "integer":
        negative = bool(reader.read_u8())
        magnitude = reader.read_varint64()
        return Constant(kind, -magnitude if negative else magnitude)
    if kind == "class_shape":
        class_name = reader.read_varint()
        property_count = reader.read_varint()
        method_count = reader.read_varint()
        properties = [reader.read_varint() for _ in range(property_count)]
        methods = [reader.read_varint() for _ in range(method_count)]
        return Constant(kind, {"class_name": class_name, "properties": properties, "methods": methods})
    raise AssertionError(kind)


def parse_chunk(data: bytes) -> BytecodeChunk:
    reader = Reader(data)
    version = reader.read_u8()
    if version == 0:
        raise ValueError("bytecode chunk contains compiler error marker")
    if version < VERSION_MIN or version > VERSION_MAX:
        raise ValueError(f"bytecode version mismatch: expected [{VERSION_MIN}..{VERSION_MAX}], got {version}")

    type_version = 0
    if version >= 4:
        type_version = reader.read_u8()
        if type_version < TYPE_VERSION_MIN or type_version > TYPE_VERSION_MAX:
            raise ValueError(
                f"bytecode type version mismatch: expected [{TYPE_VERSION_MIN}..{TYPE_VERSION_MAX}], got {type_version}"
            )

    strings = []
    for _ in range(reader.read_varint()):
        raw = reader.read_bytes(reader.read_varint())
        strings.append(raw.decode("utf-8", errors="replace"))

    userdata_remaps: dict[int, str | None] = {}
    if type_version == 3:
        index = reader.read_u8()
        while index:
            userdata_remaps[index] = _read_string_ref(reader, strings)
            index = reader.read_u8()

    protos = []
    proto_count = reader.read_varint()
    for proto_id in range(proto_count):
        maxstacksize = reader.read_u8()
        numparams = reader.read_u8()
        numupvalues = reader.read_u8()
        is_vararg = bool(reader.read_u8())
        flags = 0
        typeinfo = b""
        if version >= 4:
            flags = reader.read_u8()
            typeinfo = reader.read_bytes(reader.read_varint())

        code_words = [reader.read_u32() for _ in range(reader.read_varint())]
        instructions = decode_words(code_words, tolerate_unknown=True)
        has_unknown_opcodes = any(insn.op.name.startswith("UNKNOWN_") for insn in instructions)
        if has_unknown_opcodes:
            roblox_instructions = decode_roblox_words(code_words, tolerate_unknown=True)
            if not any(insn.op.name.startswith("UNKNOWN_") for insn in roblox_instructions):
                instructions = roblox_instructions
                has_unknown_opcodes = False
            else:
                instructions = decode_encoded_words(code_words)

        constants = [_read_constant(reader, strings) for _ in range(reader.read_varint())]
        child_protos = [reader.read_varint() for _ in range(reader.read_varint())]
        linedefined = reader.read_varint()
        debugname = _read_string_ref(reader, strings)

        lineinfo = []
        abslineinfo = []
        if reader.read_u8():
            linegaplog2 = reader.read_u8()
            intervals = ((len(code_words) - 1) >> linegaplog2) + 1 if code_words else 0
            last = 0
            for _ in range(len(code_words)):
                last = (last + reader.read_u8()) & 0xFF
                lineinfo.append(last)
            last_line = 0
            for _ in range(intervals):
                last_line += reader.read_i32()
                abslineinfo.append(last_line)

        debug_locals = []
        debug_upvalues = []
        if reader.read_u8():
            for _ in range(reader.read_varint()):
                debug_locals.append(
                    DebugLocal(
                        _read_string_ref(reader, strings),
                        reader.read_varint(),
                        reader.read_varint(),
                        reader.read_u8(),
                    )
                )
            debug_upvalues = [_read_string_ref(reader, strings) for _ in range(reader.read_varint())]

        feedback = []
        if version >= 11:
            for _ in range(reader.read_varint()):
                feedback.append({"kind": reader.read_u8(), "pc": reader.read_varint()})

        protos.append(
            Proto(
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
            )
        )

    main_proto = reader.read_varint()
    trailing = reader.read_bytes(reader.remaining) if reader.remaining else b""
    return BytecodeChunk(version, type_version, strings, userdata_remaps, protos, main_proto, trailing)
