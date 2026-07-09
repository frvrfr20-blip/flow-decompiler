from __future__ import annotations

from dataclasses import dataclass


VERSION_MIN = 3
VERSION_MAX = 11
VERSION_TARGET = 7
TYPE_VERSION_MIN = 1
TYPE_VERSION_MAX = 3
TYPE_VERSION_TARGET = 3


OPCODE_NAMES = (
    "NOP",
    "BREAK",
    "LOADNIL",
    "LOADB",
    "LOADN",
    "LOADK",
    "MOVE",
    "GETGLOBAL",
    "SETGLOBAL",
    "GETUPVAL",
    "SETUPVAL",
    "CLOSEUPVALS",
    "GETIMPORT",
    "GETTABLE",
    "SETTABLE",
    "GETTABLEKS",
    "SETTABLEKS",
    "GETTABLEN",
    "SETTABLEN",
    "NEWCLOSURE",
    "NAMECALL",
    "CALL",
    "RETURN",
    "JUMP",
    "JUMPBACK",
    "JUMPIF",
    "JUMPIFNOT",
    "JUMPIFEQ",
    "JUMPIFLE",
    "JUMPIFLT",
    "JUMPIFNOTEQ",
    "JUMPIFNOTLE",
    "JUMPIFNOTLT",
    "ADD",
    "SUB",
    "MUL",
    "DIV",
    "MOD",
    "POW",
    "ADDK",
    "SUBK",
    "MULK",
    "DIVK",
    "MODK",
    "POWK",
    "AND",
    "OR",
    "ANDK",
    "ORK",
    "CONCAT",
    "NOT",
    "MINUS",
    "LENGTH",
    "NEWTABLE",
    "DUPTABLE",
    "SETLIST",
    "FORNPREP",
    "FORNLOOP",
    "FORGLOOP",
    "FORGPREP_INEXT",
    "FASTCALL3",
    "FORGPREP_NEXT",
    "NATIVECALL",
    "GETVARARGS",
    "DUPCLOSURE",
    "PREPVARARGS",
    "LOADKX",
    "JUMPX",
    "FASTCALL",
    "COVERAGE",
    "CAPTURE",
    "SUBRK",
    "DIVRK",
    "FASTCALL1",
    "FASTCALL2",
    "FASTCALL2K",
    "FORGPREP",
    "JUMPXEQKNIL",
    "JUMPXEQKB",
    "JUMPXEQKN",
    "JUMPXEQKS",
    "IDIV",
    "IDIVK",
    "GETUDATAKS",
    "SETUDATAKS",
    "NAMECALLUDATA",
    "NEWCLASSMEMBER",
    "CALLFB",
    "CMPPROTO",
)


AUX_OPS = {
    "GETGLOBAL",
    "SETGLOBAL",
    "GETIMPORT",
    "GETTABLEKS",
    "SETTABLEKS",
    "NAMECALL",
    "JUMPIFEQ",
    "JUMPIFLE",
    "JUMPIFLT",
    "JUMPIFNOTEQ",
    "JUMPIFNOTLE",
    "JUMPIFNOTLT",
    "NEWTABLE",
    "SETLIST",
    "FORGLOOP",
    "LOADKX",
    "FASTCALL2",
    "FASTCALL2K",
    "FASTCALL3",
    "JUMPXEQKNIL",
    "JUMPXEQKB",
    "JUMPXEQKN",
    "JUMPXEQKS",
    "GETUDATAKS",
    "SETUDATAKS",
    "NAMECALLUDATA",
    "NEWCLASSMEMBER",
    "CALLFB",
    "CMPPROTO",
}

FASTCALL_OPS = {"FASTCALL", "FASTCALL1", "FASTCALL2", "FASTCALL2K", "FASTCALL3"}

JUMP_D_OPS = {
    "JUMP",
    "JUMPIF",
    "JUMPIFNOT",
    "JUMPIFEQ",
    "JUMPIFLE",
    "JUMPIFLT",
    "JUMPIFNOTEQ",
    "JUMPIFNOTLE",
    "JUMPIFNOTLT",
    "FORNPREP",
    "FORNLOOP",
    "FORGPREP",
    "FORGLOOP",
    "FORGPREP_INEXT",
    "FORGPREP_NEXT",
    "JUMPBACK",
    "JUMPXEQKNIL",
    "JUMPXEQKB",
    "JUMPXEQKN",
    "JUMPXEQKS",
    "CMPPROTO",
}

NO_FALLTHROUGH_OPS = {"RETURN", "JUMP", "JUMPBACK", "JUMPX"}
SKIP_C_OPS = {"LOADB"}
LOOP_JUMP_OPS = {"JUMPBACK", "FORGLOOP", "FORNLOOP"}

CONSTANT_TAGS = {
    0: "nil",
    1: "boolean",
    2: "number",
    3: "string",
    4: "import",
    5: "table",
    6: "closure",
    7: "vector",
    8: "table_with_constants",
    9: "integer",
    10: "class_shape",
}


@dataclass(frozen=True)
class Opcode:
    code: int
    name: str
    length: int

    @property
    def has_aux(self) -> bool:
        return self.length == 2


OPCODES = tuple(Opcode(i, name, 2 if name in AUX_OPS else 1) for i, name in enumerate(OPCODE_NAMES))
OPCODE_BY_NAME = {op.name: op for op in OPCODES}


def opcode(code: int) -> Opcode:
    try:
        return OPCODES[code]
    except IndexError as exc:
        raise ValueError(f"unknown Luau opcode {code}") from exc


def unknown_opcode(code: int) -> Opcode:
    return Opcode(code, f"UNKNOWN_{code}", 1)


def encoded_opcode(code: int) -> Opcode:
    return Opcode(code, f"ENCODED_{code}", 1)


def op_index(name: str) -> int:
    try:
        return OPCODE_BY_NAME[name].code
    except KeyError as exc:
        raise ValueError(f"unknown Luau opcode {name!r}") from exc


def op_length(name_or_code: str | int) -> int:
    if isinstance(name_or_code, str):
        return OPCODE_BY_NAME[name_or_code].length
    return opcode(name_or_code).length
