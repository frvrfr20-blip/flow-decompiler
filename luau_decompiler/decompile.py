from __future__ import annotations

from dataclasses import dataclass, field
import json

from .chunk import BytecodeChunk, Proto, decompose_import_id
from .opcodes import FASTCALL_OPS


_KEYWORDS = {
    "and",
    "break",
    "do",
    "else",
    "elseif",
    "end",
    "false",
    "for",
    "function",
    "if",
    "in",
    "local",
    "nil",
    "not",
    "or",
    "repeat",
    "return",
    "then",
    "true",
    "until",
    "while",
}

_BINARY_OPS = {
    "ADD": "+",
    "SUB": "-",
    "MUL": "*",
    "DIV": "/",
    "MOD": "%",
    "POW": "^",
    "IDIV": "//",
    "AND": "and",
    "OR": "or",
}

_BINARY_K_OPS = {
    "ADDK": "+",
    "SUBK": "-",
    "MULK": "*",
    "DIVK": "/",
    "MODK": "%",
    "POWK": "^",
    "IDIVK": "//",
    "ANDK": "and",
    "ORK": "or",
}

_REVERSE_K_OPS = {
    "SUBRK": "-",
    "DIVRK": "/",
}

_UNARY_OPS = {
    "NOT": "not",
    "MINUS": "-",
    "LENGTH": "#",
}

_CONDITIONAL_JUMP_OPS = {
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

_REGISTER_COMPARE_FALLTHROUGH_OPS = {
    "JUMPIFEQ": "~=",
    "JUMPIFLE": ">",
    "JUMPIFLT": ">=",
    "JUMPIFNOTEQ": "==",
    "JUMPIFNOTLE": "<=",
    "JUMPIFNOTLT": "<",
}

_REGISTER_COMPARE_TAKEN_OPS = {
    "JUMPIFEQ": "==",
    "JUMPIFLE": "<=",
    "JUMPIFLT": "<",
    "JUMPIFNOTEQ": "~=",
    "JUMPIFNOTLE": ">",
    "JUMPIFNOTLT": ">=",
}

_CONSTANT_COMPARE_OPS = {"JUMPXEQKNIL", "JUMPXEQKB", "JUMPXEQKN", "JUMPXEQKS"}

_SOURCELESS_OPS = {"NOP", "BREAK", "PREPVARARGS", "CLOSEUPVALS", "COVERAGE", "NATIVECALL"}

_INFIX_TOKENS = (" + ", " - ", " * ", " / ", " % ", " ^ ", " // ", " and ", " or ", " .. ")

_NEGATED_COMPARISON_OPS = {
    " == ": " ~= ",
    " ~= ": " == ",
    " <= ": " > ",
    " >= ": " < ",
    " < ": " >= ",
    " > ": " <= ",
}

_ROBLOX_SERVICE_NAMES = {
    "CollectionService",
    "ContextActionService",
    "Debris",
    "GuiService",
    "HttpService",
    "Lighting",
    "Players",
    "ReplicatedFirst",
    "ReplicatedStorage",
    "RunService",
    "ServerStorage",
    "SoundService",
    "StarterGui",
    "StarterPack",
    "Teams",
    "TeleportService",
    "TweenService",
    "UserInputService",
    "Workspace",
}


def _quote_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _unquote_string_literal(value: str) -> str | None:
    if not value.startswith('"'):
        return None
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return None
    return decoded if isinstance(decoded, str) else None


def _is_identifier(value: str) -> bool:
    if not value or value in _KEYWORDS:
        return False
    first, rest = value[0], value[1:]
    return (first == "_" or first.isalpha()) and all(ch == "_" or ch.isalnum() for ch in rest)


def _is_if_expression(value: str) -> bool:
    return value.startswith("if ")


def _field_expr(receiver: str, key: str) -> str:
    receiver = _receiver_expr(receiver)
    if _is_identifier(key):
        return f"{receiver}.{key}"
    return f"{receiver}[{_quote_string(key)}]"


def _index_expr(receiver: str, key_expr: str) -> str:
    key_text = _unquote_string_literal(key_expr)
    if key_text is not None and _is_identifier(key_text):
        return _field_expr(receiver, key_text)
    return f"{_receiver_expr(receiver)}[{key_expr}]"


def _global_expr(key: str) -> str:
    if _is_identifier(key):
        return key
    return f"_G[{_quote_string(key)}]"


def _import_path_expr(proto: Proto, import_id: int) -> str:
    parts = []
    for index in decompose_import_id(import_id):
        parts.append(proto.constant_text(index) or f"K{index}")
    if not parts:
        return f"import<{import_id}>"

    value = _global_expr(parts[0])
    for key in parts[1:]:
        value = _field_expr(value, key)
    return value


def _is_dotted_identifier_path(value: str) -> bool:
    return all(_is_identifier(part) for part in value.split("."))


def _call_target_expr(function: str) -> str:
    if function.startswith("(") and function.endswith(")"):
        return function
    if function == "...":
        return "(...)"
    if _is_if_expression(function):
        return f"({function})"
    if function.startswith("function("):
        return f"({function})"
    if function.startswith(("not ", "-", "#")):
        return f"({function})"
    if any(token in function for token in _INFIX_TOKENS):
        return f"({function})"
    return function


def _call_args_source(args: list[str]) -> str:
    if not any("\n" in arg for arg in args):
        return f"({', '.join(args)})"

    lines = ["("]
    for index, arg in enumerate(args):
        arg_lines = arg.splitlines() or [""]
        if index < len(args) - 1:
            arg_lines[-1] = f"{arg_lines[-1]},"
        lines.extend(f"    {line}" if line else "" for line in arg_lines)
    lines.append(")")
    return "\n".join(lines)


def _call_expr(function: str, args: list[str]) -> str:
    return f"{_call_target_expr(function)}{_call_args_source(args)}"


def _namecall_expr(receiver: str, method: str, args: list[str]) -> str:
    receiver = _receiver_expr(receiver)
    if _is_identifier(method):
        return f"{receiver}:{method}{_call_args_source(args)}"
    all_args = [receiver, *args]
    return f"{receiver}[{_quote_string(method)}]{_call_args_source(all_args)}"


def _group_if_needed(value: str) -> str:
    if value.startswith("(") and value.endswith(")"):
        return value
    if _is_if_expression(value):
        return f"({value})"
    if value.startswith(("not ", "-", "#")):
        return f"({value})"
    if any(token in value for token in _INFIX_TOKENS):
        return f"({value})"
    return value


def _receiver_expr(value: str) -> str:
    grouped = _group_if_needed(value)
    if grouped != value:
        return grouped
    if value in {"nil", "true", "false"}:
        return f"({value})"
    if value.startswith("{") and value.endswith("}"):
        return f"({value})"
    if _unquote_string_literal(value) is not None:
        return f"({value})"
    return value


def _condition_expr(value: str) -> str:
    if _is_if_expression(value):
        return f"({value})"
    return value


def _has_comparison_expr(value: str) -> bool:
    return any(operator in value for operator in _NEGATED_COMPARISON_OPS)


def _negated_comparison_expr(value: str) -> str | None:
    if value.startswith("(") and value.endswith(")"):
        return None
    if " and " in value or " or " in value:
        return None
    for operator, negated in _NEGATED_COMPARISON_OPS.items():
        if operator not in value:
            continue
        left, right = value.split(operator, 1)
        if not left.strip() or not right.strip():
            return None
        return f"{_group_if_needed(left.strip())}{negated}{_group_if_needed(right.strip())}"
    return None


def _binary_expr(left: str, operator: str, right: str) -> str:
    return f"{_group_if_needed(left)} {operator} {_group_if_needed(right)}"


def _unary_expr(operator: str, value: str) -> str:
    if operator == "not":
        negated_comparison = _negated_comparison_expr(value)
        if negated_comparison is not None:
            return negated_comparison
        if _has_comparison_expr(value):
            return f"not ({value})"
        return f"not {_group_if_needed(value)}"
    return f"{operator}{_group_if_needed(value)}"


def _assignment_source(target: str, value: str) -> str:
    if _is_dotted_identifier_path(target) and value.startswith("function("):
        lines = value.splitlines()
        signature = lines[0][len("function") :]
        params_source = signature[1:-1] if signature.startswith("(") and signature.endswith(")") else ""
        params = [item.strip() for item in params_source.split(",") if item.strip()]
        if params[:1] == ["self"] and "." in target:
            receiver, method = target.rsplit(".", 1)
            if _is_dotted_identifier_path(receiver) and _is_identifier(method):
                colon_params = ", ".join(params[1:])
                return f"function {receiver}:{method}({colon_params})\n" + "\n".join(lines[1:])
        return f"function {target}{signature}\n" + "\n".join(lines[1:])
    return f"{target} = {value}"


def _may_have_constructor_side_effect(value: str) -> bool:
    source = value.strip()
    if source.startswith('"') or source.startswith("{"):
        return False
    if source.startswith("(") and source.endswith(")") and source.count("(") == 1 and source.count(")") == 1:
        return False
    return "(" in source and ")" in source


def _table_source(entries: list[str]) -> str:
    if not entries:
        return "{}"

    inline = "{" + ", ".join(entries) + "}"
    if len(entries) <= 6 and "\n" not in inline and len(inline) <= 120:
        return inline

    lines = ["{"]
    if not any("\n" in entry for entry in entries):
        row = ""
        for entry in entries:
            item = f"{entry},"
            candidate = item if not row else f"{row} {item}"
            if row and len(f"    {candidate}") > 120:
                lines.append(f"    {row}")
                row = item
            else:
                row = candidate
        if row:
            lines.append(f"    {row}")
        lines.append("}")
        return "\n".join(lines)

    for entry in entries:
        entry_lines = entry.splitlines() or [""]
        entry_lines[-1] = f"{entry_lines[-1]},"
        lines.extend(f"    {line}" if line else "    " for line in entry_lines)
    lines.append("}")
    return "\n".join(lines)


@dataclass
class TableLiteral:
    array: dict[int, str] = field(default_factory=dict)
    fields: list[tuple[str, str]] = field(default_factory=list)
    materialized: bool = False
    writes: list[tuple[str, int | str, str]] = field(default_factory=list)

    def set_array(self, index: int, value: str) -> None:
        self.array[index] = value
        for write_index, (kind, key, _) in enumerate(self.writes):
            if kind == "array" and key == index:
                self.writes[write_index] = (kind, key, value)
                return
        self.writes.append(("array", index, value))

    def set_field(self, key: str, value: str) -> None:
        for index, (existing_key, _) in enumerate(self.fields):
            if existing_key == key:
                self.fields[index] = (key, value)
                for write_index, (kind, existing_write_key, _) in enumerate(self.writes):
                    if kind == "field" and existing_write_key == key:
                        self.writes[write_index] = (kind, key, value)
                        return
                return
        self.fields.append((key, value))
        self.writes.append(("field", key, value))

    def render(self) -> str:
        if self.writes and any(_may_have_constructor_side_effect(value) for _, _, value in self.writes):
            entries = []
            next_index = 1
            for kind, key, value in self.writes:
                if kind == "array":
                    index = int(key)
                    if index == next_index:
                        entries.append(value)
                        next_index += 1
                    else:
                        entries.append(f"[{index}] = {value}")
                else:
                    entries.append(f"{key} = {value}")
            return _table_source(entries)

        entries = []
        next_index = 1
        for index in sorted(self.array):
            value = self.array[index]
            if index == next_index:
                entries.append(value)
            else:
                entries.append(f"[{index}] = {value}")
            next_index = index + 1
        entries.extend(f"{key} = {value}" for key, value in self.fields)
        return _table_source(entries)


def _table_field_key(key: str) -> str:
    if _is_identifier(key):
        return key
    return f"[{_quote_string(key)}]"


def _table_constant_key(proto: Proto, index: int) -> str:
    const = proto.constant(index)
    if const and const.kind == "string":
        return _table_field_key(str(const.value))
    return f"[{_literal(proto, index)}]"


def _duptable_literal(proto: Proto, index: int) -> TableLiteral:
    table = TableLiteral()
    const = proto.constant(index)
    if const is None:
        return table

    if const.kind == "table":
        for key_index in const.value:
            table.set_field(_table_constant_key(proto, int(key_index)), "0")
    elif const.kind == "table_with_constants":
        for key_index, value_index in const.value:
            value = _literal(proto, int(value_index)) if value_index >= 0 else "0"
            table.set_field(_table_constant_key(proto, int(key_index)), value)

    return table


def _literal(proto: Proto, index: int) -> str:
    const = proto.constant(index)
    if const is None:
        return f"K{index}"
    if const.kind == "nil":
        return "nil"
    if const.kind == "boolean":
        return "true" if const.value else "false"
    if const.kind in {"number", "integer"}:
        return str(const.value)
    if const.kind == "string":
        return _quote_string(str(const.value))
    if const.kind == "import":
        return _import_path_expr(proto, int(const.value))
    if const.kind == "vector":
        x, y, z, _w = const.value
        return f"vector.create({x}, {y}, {z})"
    return f"--[[{const.kind}:{const.value!r}]]"


def _debug_local(proto: Proto, reg_id: int, pc: int):
    for local in reversed(proto.debug_locals):
        if local.reg == reg_id and local.name and local.start_pc <= pc < local.end_pc and _is_identifier(local.name):
            return local
    return None


def _debug_local_name(proto: Proto, reg_id: int, pc: int) -> str | None:
    local = _debug_local(proto, reg_id, pc)
    if local is not None:
        return local.name
    return None


def _trim_trailing_nil(values: list[str]) -> list[str]:
    out = list(values)
    while len(out) > 1 and out[-1] == "nil":
        out.pop()
    return out


def _parameter_names(proto: Proto, reserved_names: set[str] | None = None) -> list[str]:
    used_names = set(reserved_names or ())
    used_names.update(name for name in proto.debug_upvalues if name and _is_identifier(name))
    params = []
    for reg_id in range(proto.numparams):
        base_name = _debug_local_name(proto, reg_id, 0) or f"p{reg_id}"
        name = base_name
        suffix = 2
        while name in used_names:
            name = f"{base_name}_{suffix}"
            suffix += 1
        params.append(name)
        used_names.add(name)
    if proto.is_vararg:
        params.append("...")
    return params


def _child_proto(parent: Proto, index: int, protos: list[Proto] | None) -> Proto | None:
    if protos is None:
        return None

    if 0 <= index < len(parent.child_protos):
        proto_id = parent.child_protos[index]
    else:
        proto_id = index

    if 0 <= proto_id < len(protos):
        return protos[proto_id]
    return None


def _closure_constant_proto(proto: Proto, index: int, protos: list[Proto] | None) -> Proto | None:
    if protos is None:
        return None
    const = proto.constant(index)
    if const is None or const.kind != "closure":
        return None
    proto_id = int(const.value)
    if 0 <= proto_id < len(protos):
        return protos[proto_id]
    return None


def _function_expr(proto: Proto, protos: list[Proto] | None, upvalue_names: dict[int, str] | None = None) -> str:
    params = ", ".join(_parameter_names(proto, set(upvalue_names.values()) if upvalue_names else None))
    body = decompile_proto(proto, protos, upvalue_names).rstrip()
    if not body:
        return f"function({params})\nend"

    body_lines = [f"    {line}" if line else "" for line in body.splitlines()]
    return f"function({params})\n" + "\n".join(body_lines) + "\nend"


def _function_body_lines(proto: Proto, protos: list[Proto] | None, upvalue_names: dict[int, str] | None = None) -> list[str]:
    body = decompile_proto(proto, protos, upvalue_names).rstrip()
    return body.splitlines() if body else []


def _upvalue_name(proto: Proto, index: int, upvalue_names: dict[int, str] | None = None) -> str:
    if upvalue_names is not None and index in upvalue_names:
        return upvalue_names[index]
    if 0 <= index < len(proto.debug_upvalues):
        name = proto.debug_upvalues[index]
        if name and _is_identifier(name):
            return name
    return f"upvalue{index}"


def _aux_key_index(opname: str, aux: int) -> int:
    if opname in {"GETUDATAKS", "SETUDATAKS", "NAMECALLUDATA"}:
        return aux & 0xFFFF
    return aux


def _needs_statement_separator(previous: str, indent: str, current: str) -> bool:
    if not current.startswith("("):
        return False
    previous_indent = previous[: len(previous) - len(previous.lstrip())]
    if previous_indent != indent:
        return False
    stripped = previous.strip()
    if not stripped or stripped.startswith("--"):
        return False
    return not stripped.endswith(("then", "do", "else", "{", "(", "[", ",", ";"))


def decompile_proto(
    proto: Proto,
    protos: list[Proto] | None = None,
    upvalue_names: dict[int, str] | None = None,
) -> str:
    lines = []
    parameter_names = _parameter_names(proto, set(upvalue_names.values()) if upvalue_names else None)
    regs: dict[int, str] = {
        reg_id: parameter_names[reg_id] for reg_id in range(proto.numparams)
    }
    table_literals: dict[int, TableLiteral] = {}
    pending_table_locals: dict[int, tuple[str, tuple[int, str, int, int]]] = {}
    pending_namecalls: dict[int, tuple[str, str]] = {}
    pending_iterator_calls: dict[int, str] = {}
    mutable_capture_locals: dict[int, str] = {}
    value_capture_locals: dict[int, tuple[str, str]] = {}
    next_capture_local = 0
    open_results: tuple[int, list[str]] | None = None
    declared_locals: set[tuple[int, str, int, int]] = set()
    inferred_locals: set[str] = set()
    reserved_local_names: set[str] = set()
    encoded_header_written = False

    def reg(reg_id: int) -> str:
        return regs.get(reg_id, f"r{reg_id}")

    def return_reg(reg_id: int, pc: int) -> str:
        current = reg(reg_id)
        if current == f"r{reg_id}":
            local_name = _debug_local_name(proto, reg_id, pc)
            if local_name is not None:
                return local_name
        return current

    def emit_line(indent: int, value: str) -> None:
        prefix = "    " * indent
        if value == "end" and lines and lines[-1] == f"{prefix}else":
            lines.pop()
        value_lines = value.splitlines() or [""]
        if lines and _needs_statement_separator(lines[-1], prefix, value_lines[0]):
            lines[-1] += ";"
        for line in value_lines:
            lines.append(f"{prefix}{line}")

    def emit_local_function(
        indent: int,
        name: str,
        child: Proto,
        child_upvalue_names: dict[int, str] | None = None,
        *,
        declare_local: bool = True,
    ) -> None:
        params = ", ".join(
            _parameter_names(
                child,
                set(child_upvalue_names.values()) if child_upvalue_names else None,
            )
        )
        keyword = "local function" if declare_local else "function"
        emit_line(indent, f"{keyword} {name}({params})")
        for line in _function_body_lines(child, protos, child_upvalue_names):
            emit_line(indent + 1, line)
        emit_line(indent, "end")

    def clone_tables() -> dict[int, TableLiteral]:
        return {
            reg_id: TableLiteral(dict(table.array), list(table.fields), table.materialized, list(table.writes))
            for reg_id, table in table_literals.items()
        }

    def set_reg(reg_id: int, value: str) -> None:
        nonlocal open_results
        value_capture_locals.pop(reg_id, None)
        regs[reg_id] = value
        table_literals.pop(reg_id, None)
        pending_table_locals.pop(reg_id, None)
        pending_iterator_calls.pop(reg_id, None)
        if open_results is not None and reg_id >= open_results[0]:
            open_results = None

    def local_key(reg_id: int, name: str, pc: int) -> tuple[int, str, int, int]:
        local = _debug_local(proto, reg_id, pc)
        if local is not None and local.name == name:
            return (reg_id, name, local.start_pc, local.end_pc)
        return (reg_id, name, -1, -1)

    def set_reg_or_declare_local(reg_id: int, value: str, pc: int, indent: int) -> None:
        mutable_name = mutable_capture_locals.get(reg_id)
        if mutable_name is not None:
            if value != mutable_name:
                emit_line(indent, f"{mutable_name} = {value}")
            set_reg(reg_id, mutable_name)
            return

        local_name = _debug_local_name(proto, reg_id, pc)
        if local_name is not None and reg_id >= proto.numparams:
            key = local_key(reg_id, local_name, pc)
            if key not in declared_locals:
                emit_line(indent, f"local {local_name} = {value}")
                declared_locals.add(key)
            elif value != local_name:
                emit_line(indent, f"{local_name} = {value}")
            set_reg(reg_id, local_name)
        else:
            set_reg(reg_id, value)

    def declare_multi_result_locals(reg_id: int, count: int, value: str, pc: int, indent: int) -> bool:
        names = []
        keys = []
        for offset in range(count):
            target = reg_id + offset
            local_name = _debug_local_name(proto, target, pc) or f"r{target}"
            key = local_key(target, local_name, pc)
            if target < proto.numparams or key in declared_locals:
                return False
            names.append(local_name)
            keys.append(key)

        emit_line(indent, f"local {', '.join(names)} = {value}")
        for offset, (local_name, key) in enumerate(zip(names, keys)):
            target = reg_id + offset
            declared_locals.add(key)
            set_reg(target, local_name)
        return True

    def assign_multi_result_locals(reg_id: int, count: int, value: str, pc: int, indent: int) -> bool:
        names = []
        for offset in range(count):
            target = reg_id + offset
            local_name = _debug_local_name(proto, target, pc)
            if local_name is None:
                current = reg(target)
                local_name = current if _is_identifier(current) else None
            if local_name is None:
                return False
            key = local_key(target, local_name, pc)
            if target >= proto.numparams and key not in declared_locals:
                return False
            names.append(local_name)

        emit_line(indent, f"{', '.join(names)} = {value}")
        for offset, local_name in enumerate(names):
            set_reg(reg_id + offset, local_name)
        return True

    def assign_mixed_multi_result_locals(reg_id: int, count: int, value: str, pc: int, indent: int) -> bool:
        names = []
        missing = []
        for offset in range(count):
            target = reg_id + offset
            if target < proto.numparams:
                return False

            local_name = _debug_local_name(proto, target, pc)
            if local_name is None:
                current = reg(target)
                key = local_key(target, current, pc) if _is_identifier(current) else None
                if key is not None and key in declared_locals:
                    local_name = current
            if local_name is None:
                local_name = f"r{target}"

            key = local_key(target, local_name, pc)
            names.append(local_name)
            if key not in declared_locals:
                missing.append((local_name, key))

        if missing:
            emit_line(indent, f"local {', '.join(name for name, _ in missing)} = nil")
            for _, key in missing:
                declared_locals.add(key)

        emit_line(indent, f"{', '.join(names)} = {value}")
        for offset, local_name in enumerate(names):
            set_reg(reg_id + offset, local_name)
        return True

    def allocate_capture_local_name() -> str:
        nonlocal next_capture_local
        used_names = set(inferred_locals)
        used_names.update(reserved_local_names)
        used_names.update(name for _, name, _, _ in declared_locals)
        used_names.update(value for value in regs.values() if _is_identifier(value))
        used_names.update(mutable_capture_locals.values())
        used_names.update(name for _, name in value_capture_locals.values())
        used_names.update(
            _upvalue_name(proto, index, upvalue_names)
            for index in range(proto.numupvalues)
        )

        while True:
            name = f"captured{next_capture_local}"
            next_capture_local += 1
            if name not in used_names:
                return name

    def capture_source_name(capture, indent: int | None = None, upvalue_index: int | None = None) -> str | None:
        nonlocal next_capture_local
        if capture.a in {0, 1}:
            local_name = _debug_local_name(proto, capture.b, capture.pc)
            value = local_name or reg(capture.b)
            if capture.a == 0 and capture.b in mutable_capture_locals:
                cached = value_capture_locals.get(capture.b)
                if cached is not None and cached[0] == value:
                    return cached[1]
                if indent is not None and upvalue_index is not None:
                    name = allocate_capture_local_name()
                    emit_line(indent, f"local {name} = {value}")
                    value_capture_locals[capture.b] = (value, name)
                    return name
                return None
            if _is_identifier(value):
                return value
            if capture.a == 0:
                cached = value_capture_locals.get(capture.b)
                if cached is not None and cached[0] == value:
                    return cached[1]
            if indent is not None and upvalue_index is not None:
                name = allocate_capture_local_name()
                emit_line(indent, f"local {name} = {value}")
                if capture.a == 1:
                    mutable_capture_locals[capture.b] = name
                    set_reg(capture.b, name)
                else:
                    value_capture_locals[capture.b] = (value, name)
                return name
            return None
        if capture.a == 2:
            value = _upvalue_name(proto, capture.b, upvalue_names)
            return value if _is_identifier(value) else None
        return None

    def closure_upvalue_names(closure_index: int, child: Proto | None = None, indent: int | None = None) -> dict[int, str]:
        names: dict[int, str] = {}
        upvalue_index = 0
        scan_index = closure_index + 1
        while scan_index < len(instructions):
            capture = instructions[scan_index]
            if capture.op.name != "CAPTURE":
                break
            if indent is not None and capture.a in {0, 1} and capture.b in pending_table_locals:
                emit_pending_table_local(capture.b, indent)
            name = None
            if child is not None and 0 <= upvalue_index < len(child.debug_upvalues):
                debug_name = child.debug_upvalues[upvalue_index]
                if debug_name and _is_identifier(debug_name):
                    name = debug_name
            if name is None:
                name = capture_source_name(capture, indent, upvalue_index)
            if name is not None:
                names[upvalue_index] = name
            upvalue_index += 1
            scan_index += 1
        return names

    def closure_captures_register(closure_index: int, reg_id: int) -> bool:
        scan_index = closure_index + 1
        while scan_index < len(instructions):
            capture = instructions[scan_index]
            if capture.op.name != "CAPTURE":
                break
            if capture.a in {0, 1} and capture.b == reg_id:
                return True
            scan_index += 1
        return False

    def set_table_reg(reg_id: int, table: TableLiteral, pc: int, indent: int) -> None:
        nonlocal open_results
        value_capture_locals.pop(reg_id, None)
        mutable_name = mutable_capture_locals.get(reg_id)
        if mutable_name is not None:
            rendered = table.render()
            if rendered != mutable_name:
                emit_line(indent, f"{mutable_name} = {rendered}")
            table.materialized = True
            table_literals[reg_id] = table
            regs[reg_id] = mutable_name
            if open_results is not None and reg_id >= open_results[0]:
                open_results = None
            return

        table_literals[reg_id] = table
        local_name = _debug_local_name(proto, reg_id, pc)
        if local_name is not None and reg_id >= proto.numparams and local_key(reg_id, local_name, pc) not in declared_locals:
            pending_table_locals[reg_id] = (local_name, local_key(reg_id, local_name, pc))
            regs[reg_id] = local_name
        else:
            pending_table_locals.pop(reg_id, None)
            regs[reg_id] = table.render()
        if open_results is not None and reg_id >= open_results[0]:
            open_results = None

    def alias_table_reg(target: int, source: int, pc: int, indent: int | None = None) -> bool:
        nonlocal open_results
        table = table_literals.get(source)
        if table is None:
            return False
        value_capture_locals.pop(target, None)

        if source in pending_table_locals:
            if indent is None:
                return False
            emit_pending_table_local(source, indent)

        mutable_name = mutable_capture_locals.get(target)
        if mutable_name is not None:
            if indent is None:
                return False
            source_name = regs.get(source, table.render())
            if source_name != mutable_name:
                emit_line(indent, f"{mutable_name} = {source_name}")
            table.materialized = True
            table_literals[target] = table
            regs[target] = mutable_name
            if open_results is not None and target >= open_results[0]:
                open_results = None
            return True

        local_name = _debug_local_name(proto, target, pc)
        source_name = regs.get(source, f"r{source}")
        if local_name is not None and target >= proto.numparams and local_key(target, local_name, pc) not in declared_locals:
            if indent is None:
                return False
            table.materialized = True
            emit_line(indent, f"local {local_name} = {source_name}")
            declared_locals.add(local_key(target, local_name, pc))
            table_literals[target] = table
            regs[target] = local_name
            if open_results is not None and target >= open_results[0]:
                open_results = None
            return True

        table_literals[target] = table
        regs[target] = source_name
        if open_results is not None and target >= open_results[0]:
            open_results = None
        return True

    def emit_pending_table_local(reg_id: int, indent: int) -> bool:
        pending = pending_table_locals.pop(reg_id, None)
        table = table_literals.get(reg_id)
        if pending is None or table is None:
            return False

        local_name, key = pending
        if key not in declared_locals:
            emit_line(indent, f"local {local_name} = {table.render()}")
            declared_locals.add(key)
        table.materialized = True
        regs[reg_id] = local_name
        return True

    def materialize_table_reg(reg_id: int, indent: int) -> bool:
        table = table_literals.get(reg_id)
        if table is None:
            return False
        if table.materialized:
            return True
        if emit_pending_table_local(reg_id, indent):
            return True

        rendered = table.render()
        local_name = regs.get(reg_id)
        if local_name is None or not _is_identifier(local_name) or local_name == rendered:
            local_name = f"r{reg_id}"
        emit_line(indent, f"local {local_name} = {rendered}")
        table.materialized = True
        regs[reg_id] = local_name
        for alias_id, candidate in table_literals.items():
            if alias_id != reg_id and candidate is table and regs.get(alias_id) == rendered:
                regs[alias_id] = local_name
        return True

    def refresh_table_aliases(table: TableLiteral) -> None:
        if table.materialized:
            return
        rendered = table.render()
        for reg_id, candidate in table_literals.items():
            if candidate is table:
                pending = pending_table_locals.get(reg_id)
                regs[reg_id] = pending[0] if pending is not None else rendered

    def fixed_args(start: int, count: int) -> list[str]:
        return [reg(start + i) for i in range(count)]

    def open_args(start: int) -> list[str]:
        if open_results is None:
            return []
        open_start, values = open_results
        if open_start < start:
            return []
        padding = [reg(index) for index in range(start, open_start)]
        return [*padding, *values]

    def jump_fallthrough_condition(insn) -> str | None:
        name = insn.op.name
        if name == "JUMPIF":
            return _unary_expr("not", reg(insn.a))
        if name == "JUMPIFNOT":
            return _condition_expr(reg(insn.a))
        if name in _REGISTER_COMPARE_FALLTHROUGH_OPS and insn.aux is not None:
            return _binary_expr(reg(insn.a), _REGISTER_COMPARE_FALLTHROUGH_OPS[name], reg(insn.aux & 0xFF))
        if name in _CONSTANT_COMPARE_OPS and insn.aux is not None:
            not_flag = bool(insn.aux & 0x80000000)
            operator = "==" if not_flag else "~="
            if name == "JUMPXEQKNIL":
                value = "nil"
            elif name == "JUMPXEQKB":
                value = "true" if insn.aux & 1 else "false"
            else:
                value = _literal(proto, insn.aux & 0xFFFFFF)
            return _binary_expr(reg(insn.a), operator, value)
        return None

    def jump_taken_condition(insn) -> str | None:
        name = insn.op.name
        if name == "JUMPIF":
            return _condition_expr(reg(insn.a))
        if name == "JUMPIFNOT":
            return _unary_expr("not", reg(insn.a))
        if name in _REGISTER_COMPARE_TAKEN_OPS and insn.aux is not None:
            return _binary_expr(reg(insn.a), _REGISTER_COMPARE_TAKEN_OPS[name], reg(insn.aux & 0xFF))
        if name in _CONSTANT_COMPARE_OPS and insn.aux is not None:
            not_flag = bool(insn.aux & 0x80000000)
            operator = "~=" if not_flag else "=="
            if name == "JUMPXEQKNIL":
                value = "nil"
            elif name == "JUMPXEQKB":
                value = "true" if insn.aux & 1 else "false"
            else:
                value = _literal(proto, insn.aux & 0xFFFFFF)
            return _binary_expr(reg(insn.a), operator, value)
        return None

    def folded_boolean_assignment_index(insn, indent: int) -> int | None:
        condition = jump_fallthrough_condition(insn)
        target = insn.jump_target
        fallthrough_index = pc_to_index.get(insn.next_pc)
        target_index = pc_to_index.get(target) if target is not None else None
        if condition is None or fallthrough_index is None or target_index is None:
            return None
        if target_index <= fallthrough_index or target_index >= len(instructions):
            return None

        true_load = instructions[fallthrough_index]
        false_load = instructions[target_index]
        if true_load.op.name != "LOADB" or false_load.op.name != "LOADB":
            return None
        if true_load.a != false_load.a or true_load.b == false_load.b:
            return None
        if true_load.jump_target != false_load.next_pc:
            return None

        expression = condition if true_load.b else _unary_expr("not", condition)
        set_reg_or_declare_local(true_load.a, expression, false_load.next_pc, indent)
        return target_index + 1

    instructions = proto.instructions
    pc_to_index = {insn.pc: index for index, insn in enumerate(instructions)}
    last_instruction = instructions[-1] if instructions else None

    def emit_range(
        start_index: int,
        stop_pc: int | None,
        indent: int,
        loop_continue_pc: int | None = None,
        loop_exit_pc: int | None = None,
        branch_exit_pc: int | None = None,
    ) -> int:
        nonlocal encoded_header_written, open_results, regs, table_literals

        def emit_elseif_chain(else_index: int, end_pc: int) -> bool:
            nonlocal open_results, regs, table_literals

            if else_index >= len(instructions):
                return False

            chain_regs = dict(regs)
            chain_tables = clone_tables()
            condition_index = else_index
            setup_index = apply_condition_setup(condition_index, end_pc)
            if setup_index is None or setup_index >= len(instructions):
                regs = chain_regs
                table_literals = chain_tables
                open_results = None
                return False
            condition_index = setup_index

            nested = instructions[condition_index]
            if nested.op.name not in _CONDITIONAL_JUMP_OPS:
                regs = chain_regs
                table_literals = chain_tables
                open_results = None
                return False

            condition = jump_fallthrough_condition(nested)
            target = nested.jump_target
            body_index = pc_to_index.get(nested.next_pc)
            target_index = pc_to_index.get(target) if target is not None else None
            if (
                condition is None
                or target is None
                or body_index is None
                or target_index is None
                or target <= nested.next_pc
                or target > end_pc
            ):
                regs = chain_regs
                table_literals = chain_tables
                open_results = None
                return False

            conditions = [condition]
            guard_index = body_index
            while guard_index < target_index:
                guard = instructions[guard_index]
                guard_condition = jump_fallthrough_condition(guard)
                next_guard_index = pc_to_index.get(guard.next_pc)
                if (
                    guard.op.name not in _CONDITIONAL_JUMP_OPS
                    or guard_condition is None
                    or guard.jump_target != target
                    or guard.next_pc >= target
                    or next_guard_index is None
                ):
                    break
                conditions.append(guard_condition)
                body_index = next_guard_index
                guard_index = next_guard_index

            condition = (
                condition_chain_source(conditions, "and")
                if len(conditions) > 1
                else condition
            )

            branch_stop_pc = target
            nested_else_index = target_index
            has_nested_else = False
            if target_index > body_index:
                maybe_jump = instructions[target_index - 1]
                jump_target = maybe_jump.jump_target
                if maybe_jump.op.name == "JUMP" and jump_target == end_pc:
                    has_nested_else = True
                    branch_stop_pc = maybe_jump.pc
                elif target != end_pc:
                    regs = chain_regs
                    table_literals = chain_tables
                    open_results = None
                    return False

            saved_regs = dict(regs)
            saved_tables = clone_tables()
            open_results = None
            emit_line(indent, f"elseif {condition} then")
            emit_range(body_index, branch_stop_pc, indent + 1, loop_continue_pc, loop_exit_pc)
            if has_nested_else:
                regs = dict(saved_regs)
                table_literals = {
                    reg_id: TableLiteral(dict(table.array), list(table.fields), table.materialized, list(table.writes))
                    for reg_id, table in saved_tables.items()
                }
                open_results = None
                if not emit_elseif_chain(nested_else_index, end_pc):
                    else_line_index = len(lines)
                    emit_line(indent, "else")
                    else_body_index = len(lines)
                    emit_range(nested_else_index, end_pc, indent + 1, loop_continue_pc, loop_exit_pc)
                    if len(lines) == else_body_index:
                        del lines[else_line_index:]
            regs = chain_regs
            table_literals = chain_tables
            open_results = None
            return True

        def snapshot_state() -> tuple[
            dict[int, str],
            dict[int, TableLiteral],
            dict[int, tuple[str, tuple[int, str, int, int]]],
            dict[int, str],
            dict[int, str],
            dict[int, tuple[str, str]],
            tuple[int, list[str]] | None,
        ]:
            return (
                dict(regs),
                clone_tables(),
                dict(pending_table_locals),
                dict(pending_iterator_calls),
                dict(mutable_capture_locals),
                dict(value_capture_locals),
                open_results,
            )

        def restore_state(
            saved: tuple[
                dict[int, str],
                dict[int, TableLiteral],
                dict[int, tuple[str, tuple[int, str, int, int]]],
                dict[int, str],
                dict[int, str],
                dict[int, tuple[str, str]],
                tuple[int, list[str]] | None,
            ],
        ) -> None:
            nonlocal mutable_capture_locals, open_results, pending_iterator_calls, pending_table_locals, regs, table_literals, value_capture_locals
            (
                regs,
                table_literals,
                pending_table_locals,
                pending_iterator_calls,
                mutable_capture_locals,
                value_capture_locals,
                open_results,
            ) = saved

        def apply_condition_setup(index: int, limit_pc: int) -> int | None:
            while index < len(instructions):
                setup = instructions[index]
                if setup.pc >= limit_pc:
                    return index
                if setup.op.name == "LOADB" and not setup.c:
                    set_reg(setup.a, "true" if setup.b else "false")
                elif setup.op.name == "LOADN":
                    set_reg(setup.a, str(setup.d))
                elif setup.op.name == "LOADK":
                    set_reg(setup.a, _literal(proto, setup.d))
                elif setup.op.name == "LOADKX" and setup.aux is not None:
                    set_reg(setup.a, _literal(proto, setup.aux))
                elif setup.op.name == "MOVE":
                    if not alias_table_reg(setup.a, setup.b, setup.next_pc):
                        set_reg(setup.a, reg(setup.b))
                elif setup.op.name == "GETUPVAL":
                    set_reg(setup.a, _upvalue_name(proto, setup.b, upvalue_names))
                elif setup.op.name in {"GETTABLEKS", "GETUDATAKS"} and setup.aux is not None:
                    key_index = _aux_key_index(setup.op.name, setup.aux)
                    key = proto.constant_text(key_index) or f"K{key_index}"
                    set_reg(setup.a, _field_expr(reg(setup.b), key))
                elif setup.op.name == "GETTABLE":
                    set_reg(setup.a, _index_expr(reg(setup.b), reg(setup.c)))
                elif setup.op.name == "GETTABLEN":
                    set_reg(setup.a, f"{reg(setup.b)}[{setup.c + 1}]")
                else:
                    return index
                index += 1
            return None

        def call_condition_prefix_any(index: int) -> tuple[int, str, int] | None:
            temp_regs = dict(regs)
            temp_namecalls: dict[int, tuple[str, str]] = {}

            def temp_reg(reg_id: int) -> str:
                return temp_regs.get(reg_id, reg(reg_id))

            def temp_condition(insn) -> str | None:
                name = insn.op.name
                if name == "JUMPIF":
                    return _unary_expr("not", temp_reg(insn.a))
                if name == "JUMPIFNOT":
                    return temp_reg(insn.a)
                if name in _REGISTER_COMPARE_FALLTHROUGH_OPS and insn.aux is not None:
                    return _binary_expr(
                        temp_reg(insn.a),
                        _REGISTER_COMPARE_FALLTHROUGH_OPS[name],
                        temp_reg(insn.aux & 0xFF),
                    )
                if name in _CONSTANT_COMPARE_OPS and insn.aux is not None:
                    not_flag = bool(insn.aux & 0x80000000)
                    operator = "==" if not_flag else "~="
                    if name == "JUMPXEQKNIL":
                        value = "nil"
                    elif name == "JUMPXEQKB":
                        value = "true" if insn.aux & 1 else "false"
                    else:
                        value = _literal(proto, insn.aux & 0xFFFFFF)
                    return _binary_expr(temp_reg(insn.a), operator, value)
                return None

            scan = index
            while scan < len(instructions):
                candidate = instructions[scan]
                name = candidate.op.name
                if name in _CONDITIONAL_JUMP_OPS:
                    condition = temp_condition(candidate)
                    next_index = pc_to_index.get(candidate.next_pc)
                    target = candidate.jump_target
                    if condition is None or next_index is None or target is None:
                        return None
                    return next_index, condition, target
                if name == "GETIMPORT" and candidate.aux is not None:
                    temp_regs[candidate.a] = _import_path_expr(proto, candidate.aux)
                elif name == "GETGLOBAL" and candidate.aux is not None:
                    key = proto.constant_text(candidate.aux) or f"K{candidate.aux}"
                    temp_regs[candidate.a] = _global_expr(key)
                elif name == "LOADK":
                    temp_regs[candidate.a] = _literal(proto, candidate.d)
                elif name == "LOADKX" and candidate.aux is not None:
                    temp_regs[candidate.a] = _literal(proto, candidate.aux)
                elif name == "LOADN":
                    temp_regs[candidate.a] = str(candidate.d)
                elif name == "LOADB" and not candidate.c:
                    temp_regs[candidate.a] = "true" if candidate.b else "false"
                elif name == "MOVE":
                    temp_regs[candidate.a] = temp_reg(candidate.b)
                elif name == "GETUPVAL":
                    temp_regs[candidate.a] = _upvalue_name(proto, candidate.b, upvalue_names)
                elif name in {"GETTABLEKS", "GETUDATAKS"} and candidate.aux is not None:
                    key_index = _aux_key_index(name, candidate.aux)
                    key = proto.constant_text(key_index) or f"K{key_index}"
                    temp_regs[candidate.a] = _field_expr(temp_reg(candidate.b), key)
                elif name == "GETTABLE":
                    temp_regs[candidate.a] = _index_expr(temp_reg(candidate.b), temp_reg(candidate.c))
                elif name == "GETTABLEN":
                    temp_regs[candidate.a] = f"{temp_reg(candidate.b)}[{candidate.c + 1}]"
                elif name in {"NAMECALL", "NAMECALLUDATA"} and candidate.aux is not None:
                    key_index = _aux_key_index(name, candidate.aux)
                    method = proto.constant_text(key_index) or f"K{key_index}"
                    temp_namecalls[candidate.a] = (temp_reg(candidate.b), method)
                elif name in {"CALL", "CALLFB"}:
                    pending = temp_namecalls.pop(candidate.a, None)
                    if pending:
                        receiver, method = pending
                        args = [temp_reg(candidate.a + 2 + offset) for offset in range(max(candidate.b - 2, 0))]
                        call = _namecall_expr(receiver, method, args)
                    else:
                        args = [temp_reg(candidate.a + 1 + offset) for offset in range(max(candidate.b - 1, 0))]
                        call = _call_expr(temp_reg(candidate.a), args)
                    result_count = candidate.c - 1 if candidate.c else 0
                    if result_count != 1:
                        return None
                    temp_regs[candidate.a] = call
                elif name in FASTCALL_OPS:
                    pass
                else:
                    return None
                scan += 1
            return None

        def call_condition_prefix(index: int, target_pc: int) -> tuple[int, str] | None:
            prefix = call_condition_prefix_any(index)
            if prefix is None:
                return None
            next_index, condition, target = prefix
            if target != target_pc:
                return None
            return next_index, condition

        def condition_chain_source(conditions: list[str], operator: str) -> str:
            return f" {operator} ".join(_group_if_needed(condition) for condition in conditions)

        def value_chain_source(terms: list[str], operator: str) -> str:
            flattened: list[str] = []
            token = f" {operator} "
            for term in terms:
                if token in term and "(" not in term and (operator != "and" or " or " not in term):
                    flattened.extend(term.split(token))
                else:
                    flattened.append(_group_if_needed(term))
            return token.join(flattened)

        def table_write_register(candidate) -> int | None:
            name = candidate.op.name
            if name in {"SETTABLEKS", "SETUDATAKS", "SETTABLE", "SETTABLEN"}:
                return candidate.b
            if name == "SETLIST":
                return candidate.a
            return None

        def materialize_table_writes(ranges: list[tuple[int, int]], indent: int) -> None:
            seen: set[int] = set()
            for start, end_pc in ranges:
                aliases: dict[int, int] = {}
                scan_regs = dict(regs)
                scan = start
                while scan < len(instructions):
                    candidate = instructions[scan]
                    if candidate.pc >= end_pc:
                        break
                    if candidate.op.name == "MOVE":
                        source = aliases.get(candidate.b, candidate.b)
                        scan_regs[candidate.a] = scan_regs.get(candidate.b, reg(candidate.b))
                        if source in table_literals:
                            aliases[candidate.a] = source
                        else:
                            aliases.pop(candidate.a, None)
                        scan += 1
                        continue
                    if candidate.op.name == "GETIMPORT" and candidate.aux is not None:
                        scan_regs[candidate.a] = _import_path_expr(proto, candidate.aux)
                        aliases.pop(candidate.a, None)
                        scan += 1
                        continue
                    if candidate.op.name == "GETGLOBAL" and candidate.aux is not None:
                        key = proto.constant_text(candidate.aux) or f"K{candidate.aux}"
                        scan_regs[candidate.a] = _global_expr(key)
                        aliases.pop(candidate.a, None)
                        scan += 1
                        continue
                    if candidate.op.name in {"CALL", "CALLFB"} and candidate.b >= 2:
                        function = scan_regs.get(candidate.a, reg(candidate.a))
                        if function == "table.insert":
                            arg_reg_id = candidate.a + 1
                            resolved_reg_id = aliases.get(arg_reg_id, arg_reg_id)
                            table = table_literals.get(resolved_reg_id)
                            if table is not None and not table.materialized and resolved_reg_id not in seen:
                                materialize_table_reg(resolved_reg_id, indent)
                                seen.add(resolved_reg_id)
                        aliases.pop(candidate.a, None)
                        scan += 1
                        continue
                    reg_id = table_write_register(candidate)
                    resolved_reg_id = aliases.get(reg_id, reg_id) if reg_id is not None else None
                    table = table_literals.get(resolved_reg_id) if resolved_reg_id is not None else None
                    if table is not None and not table.materialized and resolved_reg_id not in seen:
                        materialize_table_reg(resolved_reg_id, indent)
                        seen.add(resolved_reg_id)
                    scan += 1

        def materialize_table_reads(ranges: list[tuple[int, int]], indent: int) -> None:
            seen_tables: set[int] = set()
            for reg_id, table in list(table_literals.items()):
                table_id = id(table)
                if table.materialized or table_id in seen_tables:
                    continue
                seen_tables.add(table_id)
                aliases = [
                    alias_id
                    for alias_id, candidate in table_literals.items()
                    if candidate is table
                ]
                should_materialize = False
                for start, end_pc in ranges:
                    for candidate in instructions[start:]:
                        if candidate.pc >= end_pc:
                            break
                        if any(instruction_reads_register(candidate, alias_id) for alias_id in aliases):
                            should_materialize = True
                            break
                    if should_materialize:
                        break
                if should_materialize:
                    materialize_table_reg(reg_id, indent)

        def materialize_branch_liveout_registers(
            ranges: list[tuple[int, int]],
            end_index: int | None,
            indent: int,
        ) -> None:
            if end_index is None:
                return

            guard_scan_start = min((start for start, _end_pc in ranges), default=end_index)

            def next_register_read_index(start_index: int, reg_id: int) -> int | None:
                for scan_index in range(start_index, len(instructions)):
                    if instruction_reads_register(instructions[scan_index], reg_id):
                        return scan_index
                return None

            def instruction_can_be_skipped_before_read(instruction_index: int, read_index: int) -> bool:
                instruction_pc = instructions[instruction_index].pc
                read_pc = instructions[read_index].pc
                for guard_index in range(guard_scan_start, instruction_index):
                    guard = instructions[guard_index]
                    target = guard.jump_target
                    if (
                        guard.op.name in _CONDITIONAL_JUMP_OPS
                        and target is not None
                        and guard.next_pc <= instruction_pc < target
                        and target <= read_pc
                    ):
                        return True
                return False

            def has_future_read_before_guaranteed_write(reg_id: int) -> bool:
                for scan_index in range(end_index, len(instructions)):
                    candidate = instructions[scan_index]
                    if instruction_reads_register(candidate, reg_id):
                        return True
                    if candidate.op.name == "RETURN":
                        read_index = next_register_read_index(scan_index + 1, reg_id)
                        if read_index is not None and instruction_can_be_skipped_before_read(scan_index, read_index):
                            continue
                        return False
                    if instruction_writes_register(candidate, reg_id):
                        read_index = next_register_read_index(scan_index + 1, reg_id)
                        if read_index is not None and instruction_can_be_skipped_before_read(scan_index, read_index):
                            continue
                        return False
                return False

            def guarded_fallback_value(reg_id: int) -> str | None:
                for start, end_pc in ranges:
                    range_end_index = pc_to_index.get(end_pc)
                    if range_end_index is None or range_end_index <= start:
                        continue
                    fallback_index = range_end_index - 1
                    fallback = simple_assignment_source(instructions[fallback_index])
                    if fallback is None:
                        continue
                    fallback_reg, fallback_source = fallback
                    if fallback_reg != reg_id:
                        continue
                    fallback_pc = instructions[fallback_index].pc
                    for guard_index in range(start, fallback_index):
                        guard = instructions[guard_index]
                        target = guard.jump_target
                        if (
                            guard.op.name in _CONDITIONAL_JUMP_OPS
                            and target is not None
                            and guard.next_pc <= fallback_pc < target
                            and target >= end_pc
                        ):
                            return fallback_source
                return None

            liveout_regs: list[int] = []
            seen: set[int] = set()
            for reg_id in range(proto.maxstacksize):
                if not has_future_read_before_guaranteed_write(reg_id):
                    continue
                for start, end_pc in ranges:
                    scan = start
                    while scan < len(instructions):
                        candidate = instructions[scan]
                        if candidate.pc >= end_pc:
                            break
                        if instruction_writes_register(candidate, reg_id):
                            if reg_id not in seen:
                                liveout_regs.append(reg_id)
                                seen.add(reg_id)
                            break
                        scan += 1
                    if reg_id in seen:
                        break

            for reg_id in liveout_regs:
                debug_name = _debug_local_name(proto, reg_id, instructions[end_index].pc)
                local_name = debug_name or (reg(reg_id) if reg_id < proto.numparams else f"r{reg_id}")
                if not _is_identifier(local_name):
                    local_name = f"r{reg_id}"

                key = local_key(reg_id, local_name, instructions[end_index].pc)
                already_declared = reg_id < proto.numparams or key in declared_locals or local_name in inferred_locals
                current = reg(reg_id)
                if not already_declared:
                    initial = guarded_fallback_value(reg_id) if current == local_name else current
                    if initial is None:
                        initial = "nil"
                    emit_line(indent, f"local {local_name} = {initial}")
                    if debug_name is not None:
                        declared_locals.add(key)
                    else:
                        inferred_locals.add(local_name)
                elif current != local_name and reg_id >= proto.numparams:
                    emit_line(indent, f"{local_name} = {current}")

                mutable_capture_locals[reg_id] = local_name
                set_reg(reg_id, local_name)

        def terminating_range_end_pc(start_index: int, limit_pc: int | None) -> int | None:
            scan = start_index
            while scan < len(instructions):
                candidate = instructions[scan]
                if limit_pc is not None and candidate.pc >= limit_pc:
                    return None
                if candidate.op.name == "RETURN":
                    return candidate.next_pc
                if candidate.op.name in _CONDITIONAL_JUMP_OPS:
                    target = candidate.jump_target
                    body_index = pc_to_index.get(candidate.next_pc)
                    target_index = pc_to_index.get(target) if target is not None else None
                    if (
                        target is not None
                        and body_index is not None
                        and target_index is not None
                        and target > candidate.next_pc
                    ):
                        then_end_pc = terminating_range_end_pc(body_index, target)
                        else_end_pc = terminating_range_end_pc(target_index, limit_pc)
                        if then_end_pc == target and else_end_pc is not None:
                            return else_end_pc
                        scan = target_index
                        continue
                if candidate.op.name == "JUMP":
                    return None
                scan += 1
            return None

        def inferred_service_name(receiver: str, method: str, args: list[str]) -> str | None:
            if receiver != "game" or method != "GetService" or len(args) != 1:
                return None
            service_name = _unquote_string_literal(args[0])
            if service_name is None or not _is_identifier(service_name):
                return None
            return service_name

        def inferred_require_name(function: str, args: list[str]) -> str | None:
            if function != "require" or len(args) != 1:
                return None
            name = args[0].rsplit(".", 1)[-1]
            return name if _is_identifier(name) else None

        def inferred_field_local_name(receiver: str, key: str) -> str | None:
            if receiver == "game" and key in _ROBLOX_SERVICE_NAMES:
                return key
            if receiver == "Players" and key == "LocalPlayer":
                return "LocalPlayer"
            return None

        def inferred_namecall_local_name(receiver: str, method: str, args: list[str]) -> str | None:
            if method == "Wait" and receiver.endswith(".CharacterAdded"):
                return "Character"
            if method == "WaitForChild" and len(args) == 1:
                child_name = _unquote_string_literal(args[0])
                if child_name is not None and _is_identifier(child_name):
                    return child_name
            if method == "InvokeServer":
                base_name = receiver.rsplit(".", 1)[-1]
                if base_name.startswith("Get") and len(base_name) > 3 and base_name[3].isupper():
                    candidate = f"{base_name[3].lower()}{base_name[4:]}"
                    if _is_identifier(candidate):
                        return candidate
                if _is_identifier(base_name):
                    return f"{base_name}Result"
            return None

        def unique_inferred_local_name(local_name: str) -> str:
            used_names = set(inferred_locals)
            used_names.update(reserved_local_names)
            used_names.update(name for _, name, _, _ in declared_locals)
            used_names.update(value for value in regs.values() if _is_identifier(value))
            used_names.update(
                _upvalue_name(proto, index, upvalue_names)
                for index in range(proto.numupvalues)
            )
            if local_name not in used_names:
                return local_name

            suffix = 2
            while f"{local_name}_{suffix}" in used_names:
                suffix += 1
            return f"{local_name}_{suffix}"

        def declare_inferred_local(reg_id: int, local_name: str | None, value: str, indent: int) -> bool:
            mutable_name = mutable_capture_locals.get(reg_id)
            if mutable_name is not None:
                if value != mutable_name:
                    emit_line(indent, f"{mutable_name} = {value}")
                set_reg(reg_id, mutable_name)
                return True
            if local_name is None or not _is_identifier(local_name):
                return False
            local_name = unique_inferred_local_name(local_name)
            if local_name not in inferred_locals:
                emit_line(indent, f"local {local_name} = {value}")
                inferred_locals.add(local_name)
            set_reg(reg_id, local_name)
            return True

        def instruction_reads_register(candidate, reg_id: int) -> bool:
            name = candidate.op.name
            if name == "MOVE":
                return candidate.b == reg_id
            if name in {"CALL", "CALLFB"}:
                if candidate.b == 0:
                    return candidate.a <= reg_id
                return candidate.a <= reg_id < candidate.a + candidate.b
            if name == "RETURN" and candidate.b > 1:
                return candidate.a <= reg_id < candidate.a + candidate.b - 1
            if name in {"SETGLOBAL", "SETUPVAL"}:
                return candidate.a == reg_id
            if name == "NEWCLASSMEMBER":
                return candidate.a == reg_id or candidate.c == reg_id
            if name in {"GETTABLEKS", "GETUDATAKS", "NAMECALL", "NAMECALLUDATA", "GETTABLEN"}:
                return candidate.b == reg_id
            if name == "GETTABLE":
                return candidate.b == reg_id or candidate.c == reg_id
            if name in {"SETTABLEKS", "SETUDATAKS"}:
                return candidate.a == reg_id or candidate.b == reg_id
            if name == "SETTABLEN":
                return candidate.a == reg_id or candidate.b == reg_id
            if name == "SETTABLE":
                return candidate.a == reg_id or candidate.b == reg_id or candidate.c == reg_id
            if name == "SETLIST" and candidate.c:
                return candidate.b <= reg_id < candidate.b + max(candidate.c - 1, 0)
            if name == "CAPTURE" and candidate.a in {0, 1}:
                return candidate.b == reg_id
            if name in _BINARY_OPS:
                return candidate.b == reg_id or candidate.c == reg_id
            if name in _BINARY_K_OPS:
                return candidate.b == reg_id
            if name in _REVERSE_K_OPS:
                return candidate.c == reg_id
            if name in _UNARY_OPS:
                return candidate.b == reg_id
            if name == "CONCAT":
                return candidate.b <= reg_id <= candidate.c
            if name in _CONDITIONAL_JUMP_OPS:
                if candidate.a == reg_id:
                    return True
                return name in _REGISTER_COMPARE_FALLTHROUGH_OPS and candidate.aux is not None and (candidate.aux & 0xFF) == reg_id
            return False

        def instruction_writes_register(candidate, reg_id: int) -> bool:
            name = candidate.op.name
            if name in {"NAMECALL", "NAMECALLUDATA"}:
                return candidate.a == reg_id or candidate.a + 1 == reg_id
            if name in {"CALL", "CALLFB"}:
                if candidate.c == 0:
                    return candidate.a <= reg_id
                result_count = candidate.c - 1
                return result_count > 0 and candidate.a <= reg_id < candidate.a + result_count
            if name in {
                "GETIMPORT",
                "GETGLOBAL",
                "LOADK",
                "LOADKX",
                "LOADN",
                "LOADB",
                "LOADNIL",
                "MOVE",
                "GETUPVAL",
                "NEWCLOSURE",
                "DUPCLOSURE",
                "NEWTABLE",
                "DUPTABLE",
                "GETTABLEKS",
                "GETUDATAKS",
                "GETTABLE",
                "GETTABLEN",
                "GETVARARGS",
            }:
                return candidate.a == reg_id
            if name in _BINARY_OPS or name in _BINARY_K_OPS or name in _REVERSE_K_OPS or name in _UNARY_OPS or name == "CONCAT":
                return candidate.a == reg_id
            return False

        def future_register_read_count(start_index: int, reg_id: int) -> int:
            count = 0
            for scan_index in range(start_index, len(instructions)):
                candidate = instructions[scan_index]
                if instruction_reads_register(candidate, reg_id):
                    count += 1
                if instruction_writes_register(candidate, reg_id):
                    break
            return count

        def future_register_read_needs_snapshot(start_index: int, reg_id: int) -> bool:
            read_indexes: list[int] = []
            for scan_index in range(start_index, len(instructions)):
                candidate = instructions[scan_index]
                if instruction_reads_register(candidate, reg_id):
                    read_indexes.append(scan_index)
                if instruction_writes_register(candidate, reg_id):
                    break

            if len(read_indexes) > 1:
                return True
            if not read_indexes:
                return False

            first_read_index = read_indexes[0]
            barrier_ops = {
                "CALL",
                "CALLFB",
                "FORGLOOP",
                "FORGPREP",
                "FORGPREP_INEXT",
                "FORGPREP_NEXT",
                "FORNLOOP",
                "FORNPREP",
                "JUMP",
                "JUMPBACK",
                "JUMPX",
                "SETGLOBAL",
                "SETLIST",
                "SETTABLE",
                "SETTABLEKS",
                "SETTABLEN",
                "SETUDATAKS",
                "SETUPVAL",
            }
            for scan_index in range(start_index, first_read_index):
                name = instructions[scan_index].op.name
                if name in barrier_ops or name in _CONDITIONAL_JUMP_OPS:
                    return True

            definition_index = start_index - 1
            if definition_index < 0:
                return False
            definition_pc = instructions[definition_index].pc
            read_pc = instructions[first_read_index].pc
            for scan_index in range(first_read_index + 1, len(instructions)):
                candidate = instructions[scan_index]
                if instruction_writes_register(candidate, reg_id):
                    break
                if candidate.op.name not in {"FORGLOOP", "FORNLOOP", "JUMPBACK"}:
                    continue
                target = candidate.jump_target
                if target is not None and definition_pc < target <= read_pc <= candidate.pc:
                    return True
            return False

        def set_reg_or_materialize_expression(
            instruction_index: int,
            reg_id: int,
            value: str,
            pc: int,
            indent: int,
            inferred_name: str | None = None,
        ) -> None:
            if (
                reg_id >= proto.numparams
                and _debug_local_name(proto, reg_id, pc) is None
                and future_register_read_needs_snapshot(instruction_index + 1, reg_id)
                and declare_inferred_local(reg_id, inferred_name or f"r{reg_id}", value, indent)
            ):
                return
            set_reg_or_declare_local(reg_id, value, pc, indent)

        def materialize_upvalue_snapshots(
            instruction_index: int,
            upvalue_index: int,
            source_reg: int,
            indent: int,
        ) -> None:
            upvalue_name = _upvalue_name(proto, upvalue_index, upvalue_names)
            for reg_id, value in list(regs.items()):
                if (
                    reg_id == source_reg
                    or value != upvalue_name
                    or future_register_read_count(instruction_index + 1, reg_id) == 0
                ):
                    continue

                debug_name = _debug_local_name(proto, reg_id, instructions[instruction_index].pc)
                if debug_name is not None:
                    key = local_key(reg_id, debug_name, instructions[instruction_index].pc)
                    if key in declared_locals:
                        emit_line(indent, f"{debug_name} = {upvalue_name}")
                    else:
                        emit_line(indent, f"local {debug_name} = {upvalue_name}")
                        declared_locals.add(key)
                    set_reg(reg_id, debug_name)
                    continue

                local_name = unique_inferred_local_name(f"r{reg_id}")
                emit_line(indent, f"local {local_name} = {upvalue_name}")
                inferred_locals.add(local_name)
                set_reg(reg_id, local_name)

        def previous_register_write_count(stop_index: int, reg_id: int) -> int:
            return sum(
                1
                for scan_index in range(max(stop_index, 0))
                if instruction_writes_register(instructions[scan_index], reg_id)
            )

        def previous_single_result_call_source(condition_index: int, reg_id: int) -> str | None:
            call_index = condition_index - 1
            if call_index < 0:
                return None
            call_insn = instructions[call_index]
            if call_insn.op.name not in {"CALL", "CALLFB"} or call_insn.a != reg_id or call_insn.c != 2:
                return None

            namecall_index = call_index - 1
            if namecall_index >= 0:
                maybe_namecall = instructions[namecall_index]
                if (
                    maybe_namecall.op.name in {"NAMECALL", "NAMECALLUDATA"}
                    and maybe_namecall.a == call_insn.a
                    and maybe_namecall.aux is not None
                ):
                    key_index = _aux_key_index(maybe_namecall.op.name, maybe_namecall.aux)
                    method = proto.constant_text(key_index) or f"K{key_index}"
                    args = fixed_args(call_insn.a + 2, max(call_insn.b - 2, 0))
                    return _namecall_expr(reg(maybe_namecall.b), method, args)

            args = fixed_args(call_insn.a + 1, max(call_insn.b - 1, 0))
            return _call_expr(reg(call_insn.a), args)

        def recover_constant_condition_from_previous_call(condition_index: int, candidate) -> str | None:
            name = candidate.op.name
            if name not in {"JUMPIF", "JUMPIFNOT"}:
                return None
            call_source = previous_single_result_call_source(condition_index, candidate.a)
            if call_source is None:
                return None
            return _unary_expr("not", call_source) if name == "JUMPIF" else call_source

        def is_generic_for_nil_state_setup(instruction_index: int) -> bool:
            candidate = instructions[instruction_index]
            if candidate.op.name != "LOADNIL":
                return False
            scan_index = instruction_index + 1
            while scan_index < len(instructions) and instructions[scan_index].op.name == "LOADNIL":
                scan_index += 1
            if scan_index >= len(instructions):
                return False
            maybe_for = instructions[scan_index]
            return (
                maybe_for.op.name in {"FORGPREP", "FORGPREP_INEXT", "FORGPREP_NEXT"}
                and candidate.a in {maybe_for.a + 1, maybe_for.a + 2}
            )

        def future_table_read_count(start_index: int, table: TableLiteral) -> int:
            return sum(
                future_register_read_count(start_index, reg_id)
                for reg_id, candidate in table_literals.items()
                if candidate is table
            )

        def finalize_pending_table_reads(insn, indent: int) -> None:
            name = insn.op.name
            reads: set[int] = set()
            if name == "MOVE":
                reads.add(insn.b)
            elif name in {"CALL", "CALLFB"}:
                reads.add(insn.a)
                if insn.b:
                    reads.update(range(insn.a + 1, insn.a + insn.b))
            elif name == "RETURN" and insn.b > 1:
                reads.update(range(insn.a, insn.a + insn.b - 1))
            elif name in {"GETTABLEKS", "GETUDATAKS", "NAMECALL", "NAMECALLUDATA"}:
                reads.add(insn.b)
            elif name == "GETTABLE":
                reads.update({insn.b, insn.c})
            elif name in {"SETTABLEKS", "SETUDATAKS"}:
                reads.add(insn.a)
            elif name == "SETTABLEN":
                reads.add(insn.a)
            elif name == "SETTABLE":
                reads.update({insn.a, insn.c})
            elif name == "SETLIST" and insn.c:
                reads.update(range(insn.b, insn.b + max(insn.c - 1, 0)))
            elif name in _BINARY_OPS:
                reads.update({insn.b, insn.c})
            elif name in _BINARY_K_OPS:
                reads.add(insn.b)
            elif name in _REVERSE_K_OPS:
                reads.add(insn.c)
            elif name in _UNARY_OPS:
                reads.add(insn.b)
            elif name == "CONCAT":
                reads.update(range(insn.b, insn.c + 1))
            elif name in _CONDITIONAL_JUMP_OPS:
                reads.add(insn.a)
                if name in _REGISTER_COMPARE_FALLTHROUGH_OPS and insn.aux is not None:
                    reads.add(insn.aux & 0xFF)

            for reg_id in sorted(reads):
                table = table_literals.get(reg_id)
                current_index = pc_to_index.get(insn.pc)
                if (
                    table is not None
                    and not table.materialized
                    and reg_id not in pending_table_locals
                    and current_index is not None
                    and (name != "MOVE" or table.render() != "{}")
                    and future_table_read_count(current_index + 1, table) > 0
                ):
                    materialize_table_reg(reg_id, indent)
                    continue
                emit_pending_table_local(reg_id, indent)

        def simple_assignment_source(candidate) -> tuple[int, str] | None:
            name = candidate.op.name
            if name == "LOADK":
                return candidate.a, _literal(proto, candidate.d)
            if name == "LOADKX" and candidate.aux is not None:
                return candidate.a, _literal(proto, candidate.aux)
            if name == "LOADN":
                return candidate.a, str(candidate.d)
            if name == "LOADB" and not candidate.c:
                return candidate.a, "true" if candidate.b else "false"
            if name == "LOADNIL":
                return candidate.a, "nil"
            if name == "MOVE":
                return candidate.a, reg(candidate.b)
            if name == "GETIMPORT" and candidate.aux is not None:
                return candidate.a, _import_path_expr(proto, candidate.aux)
            if name == "GETGLOBAL" and candidate.aux is not None:
                key = proto.constant_text(candidate.aux) or f"K{candidate.aux}"
                return candidate.a, _global_expr(key)
            if name == "GETUPVAL":
                return candidate.a, _upvalue_name(proto, candidate.b, upvalue_names)
            if name in _BINARY_OPS:
                return candidate.a, _binary_expr(reg(candidate.b), _BINARY_OPS[name], reg(candidate.c))
            if name in _BINARY_K_OPS:
                return candidate.a, _binary_expr(reg(candidate.b), _BINARY_K_OPS[name], _literal(proto, candidate.c))
            if name in _REVERSE_K_OPS:
                return candidate.a, _binary_expr(_literal(proto, candidate.b), _REVERSE_K_OPS[name], reg(candidate.c))
            if name in _UNARY_OPS:
                return candidate.a, _unary_expr(_UNARY_OPS[name], reg(candidate.b))
            if name == "CONCAT":
                values = [reg(item) for item in range(candidate.b, candidate.c + 1)]
                return candidate.a, f" .. ".join(_group_if_needed(value) for value in values)
            if name in {"GETTABLEKS", "GETUDATAKS"} and candidate.aux is not None:
                key_index = _aux_key_index(name, candidate.aux)
                key = proto.constant_text(key_index) or f"K{key_index}"
                return candidate.a, _field_expr(reg(candidate.b), key)
            if name == "GETTABLE":
                return candidate.a, _index_expr(reg(candidate.b), reg(candidate.c))
            if name == "GETTABLEN":
                return candidate.a, f"{reg(candidate.b)}[{candidate.c + 1}]"
            return None

        def simple_span_assignment_source(candidate, span_regs: dict[int, str]) -> tuple[int, str] | None:
            name = candidate.op.name
            if name == "LOADK":
                return candidate.a, _literal(proto, candidate.d)
            if name == "LOADKX" and candidate.aux is not None:
                return candidate.a, _literal(proto, candidate.aux)
            if name == "LOADN":
                return candidate.a, str(candidate.d)
            if name == "LOADB" and not candidate.c:
                return candidate.a, "true" if candidate.b else "false"
            if name == "LOADNIL":
                return candidate.a, "nil"
            if name == "MOVE":
                return candidate.a, span_regs.get(candidate.b, reg(candidate.b))
            if name == "GETIMPORT" and candidate.aux is not None:
                return candidate.a, _import_path_expr(proto, candidate.aux)
            if name == "GETUPVAL":
                return candidate.a, _upvalue_name(proto, candidate.b, upvalue_names)
            if name in {"GETTABLEKS", "GETUDATAKS"} and candidate.aux is not None:
                key_index = _aux_key_index(name, candidate.aux)
                key = proto.constant_text(key_index) or f"K{key_index}"
                return candidate.a, _field_expr(span_regs.get(candidate.b, reg(candidate.b)), key)
            if name == "GETTABLE":
                return candidate.a, _index_expr(
                    span_regs.get(candidate.b, reg(candidate.b)),
                    span_regs.get(candidate.c, reg(candidate.c)),
                )
            if name == "GETTABLEN":
                return candidate.a, f"{span_regs.get(candidate.b, reg(candidate.b))}[{candidate.c + 1}]"
            return None

        def call_assignment_span_source(start_index: int, stop_pc: int) -> tuple[int, str] | None:
            span_regs = dict(regs)
            span_namecalls: dict[int, tuple[str, str]] = {}
            current_index = start_index
            while current_index < len(instructions):
                candidate = instructions[current_index]
                if candidate.pc >= stop_pc:
                    return None
                if candidate.op.name in {"CALL", "CALLFB"}:
                    if candidate.c != 2 or candidate.b == 0 or candidate.next_pc != stop_pc:
                        return None
                    pending = span_namecalls.pop(candidate.a, None)
                    if pending is not None:
                        receiver, method = pending
                        args = [
                            span_regs.get(candidate.a + 2 + offset, reg(candidate.a + 2 + offset))
                            for offset in range(max(candidate.b - 2, 0))
                        ]
                        return candidate.a, _namecall_expr(receiver, method, args)
                    else:
                        function = span_regs.get(candidate.a, reg(candidate.a))
                        args = [
                            span_regs.get(candidate.a + 1 + offset, reg(candidate.a + 1 + offset))
                            for offset in range(max(candidate.b - 1, 0))
                        ]
                        return candidate.a, _call_expr(function, args)

                if candidate.op.name in {"NAMECALL", "NAMECALLUDATA"} and candidate.aux is not None:
                    key_index = _aux_key_index(candidate.op.name, candidate.aux)
                    method = proto.constant_text(key_index) or f"K{key_index}"
                    span_namecalls[candidate.a] = (span_regs.get(candidate.b, reg(candidate.b)), method)
                    current_index += 1
                    continue

                value = simple_span_assignment_source(candidate, span_regs)
                if value is None:
                    return None
                target_reg, source = value
                span_regs[target_reg] = source
                current_index += 1
            return None

        def assignment_span_source(start_index: int, stop_pc: int) -> tuple[int, str] | None:
            if start_index >= len(instructions):
                return None
            candidate = instructions[start_index]
            value = simple_assignment_source(candidate)
            if value is not None and candidate.next_pc == stop_pc:
                return value
            return call_assignment_span_source(start_index, stop_pc)

        def table_assignment_span_source(start_index: int, stop_pc: int) -> tuple[int, str, str] | None:
            span_regs = dict(regs)
            current_index = start_index
            while current_index < len(instructions):
                candidate = instructions[current_index]
                if candidate.pc >= stop_pc:
                    return None

                name = candidate.op.name
                if name in {"SETTABLEKS", "SETUDATAKS"} and candidate.aux is not None:
                    if candidate.next_pc != stop_pc:
                        return None
                    key_index = _aux_key_index(name, candidate.aux)
                    key = proto.constant_text(key_index) or f"K{key_index}"
                    receiver = span_regs.get(candidate.b, reg(candidate.b))
                    value = span_regs.get(candidate.a, reg(candidate.a))
                    return candidate.b, _field_expr(receiver, key), value

                if name == "SETTABLE":
                    if candidate.next_pc != stop_pc:
                        return None
                    receiver = span_regs.get(candidate.b, reg(candidate.b))
                    key = span_regs.get(candidate.c, reg(candidate.c))
                    key_text = _unquote_string_literal(key)
                    target = _field_expr(receiver, key_text) if key_text is not None else f"{receiver}[{key}]"
                    value = span_regs.get(candidate.a, reg(candidate.a))
                    return candidate.b, target, value

                if name == "SETTABLEN":
                    if candidate.next_pc != stop_pc:
                        return None
                    receiver = span_regs.get(candidate.b, reg(candidate.b))
                    value = span_regs.get(candidate.a, reg(candidate.a))
                    return candidate.b, f"{receiver}[{candidate.c + 1}]", value

                value = simple_span_assignment_source(candidate, span_regs)
                if value is None:
                    return None
                target_reg, source = value
                span_regs[target_reg] = source
                current_index += 1
            return None

        def and_assignment_span_source(start_index: int, stop_pc: int) -> tuple[int, str] | None:
            guard_index = start_index + 1
            while guard_index < len(instructions):
                guard = instructions[guard_index]
                if guard.pc >= stop_pc:
                    return None
                if guard.op.name == "JUMPIFNOT" and guard.jump_target == stop_pc:
                    condition_value = assignment_span_source(start_index, guard.pc)
                    body_index = pc_to_index.get(guard.next_pc)
                    if condition_value is None or body_index is None:
                        return None
                    target_reg, condition_source = condition_value
                    if guard.a != target_reg:
                        return None
                    truthy_value = assignment_span_source(body_index, stop_pc)
                    if truthy_value is None:
                        truthy_value = and_assignment_span_source(body_index, stop_pc)
                    if truthy_value is None:
                        return None
                    truthy_reg, truthy_source = truthy_value
                    if truthy_reg != target_reg:
                        return None
                    return target_reg, value_chain_source([condition_source, truthy_source], "and")
                guard_index += 1
            return None

        def folded_if_expression_assignment_index(insn, indent: int) -> int | None:
            def value_expression_at(start_index: int, expected_join_pc: int | None = None) -> tuple[int, str, int, int] | None:
                branch = instructions[start_index]
                condition = jump_fallthrough_condition(branch)
                target = branch.jump_target
                body_index = pc_to_index.get(branch.next_pc)
                else_index = pc_to_index.get(target) if target is not None else None
                if (
                    condition is None
                    or target is None
                    or body_index is None
                    or else_index is None
                    or target <= branch.next_pc
                    or else_index <= body_index
                    or else_index >= len(instructions)
                ):
                    return None

                then_jump_index = else_index - 1
                then_jump = instructions[then_jump_index]
                join_pc = then_jump.jump_target
                join_index = pc_to_index.get(join_pc) if join_pc is not None else None
                if (
                    then_jump.op.name != "JUMP"
                    or join_pc is None
                    or join_index is None
                    or join_pc <= target
                    or (expected_join_pc is not None and join_pc != expected_join_pc)
                    or (stop_pc is not None and join_pc > stop_pc)
                    or instructions[else_index].pc != target
                ):
                    return None

                then_value = assignment_span_source(body_index, then_jump.pc)
                if then_value is None:
                    return None

                else_value = assignment_span_source(else_index, join_pc)
                if else_value is None and instructions[else_index].op.name.startswith("JUMP"):
                    nested_value = value_expression_at(else_index, join_pc)
                    if nested_value is not None:
                        else_reg, nested_source, _nested_join_pc, _nested_join_index = nested_value
                        else_value = (else_reg, nested_source)
                if else_value is None:
                    return None

                target_reg, true_source = then_value
                else_reg, false_source = else_value
                if target_reg != else_reg:
                    return None

                if false_source.startswith("if "):
                    expression = f"if {condition} then {true_source} elseif {false_source[len('if '):]}"
                else:
                    expression = f"if {condition} then {true_source} else {false_source}"
                return target_reg, expression, join_pc, join_index

            folded_value = value_expression_at(index)
            if folded_value is not None:
                target_reg, expression, join_pc, join_index = folded_value
                set_reg_or_declare_local(target_reg, expression, join_pc, indent)
                return join_index

            condition = jump_fallthrough_condition(insn)
            target = insn.jump_target
            body_index = pc_to_index.get(insn.next_pc)
            else_index = pc_to_index.get(target) if target is not None else None
            if condition is None or target is None or body_index is None or else_index is None:
                return None

            then_jump = instructions[else_index - 1]
            join_pc = then_jump.jump_target
            join_index = pc_to_index.get(join_pc) if join_pc is not None else None
            if (
                then_jump.op.name != "JUMP"
                or join_pc is None
                or join_index is None
                or join_pc <= target
                or (stop_pc is not None and join_pc > stop_pc)
                or instructions[else_index].pc != target
            ):
                return None

            then_value = assignment_span_source(pc_to_index[insn.next_pc], then_jump.pc)
            else_value = assignment_span_source(else_index, join_pc)
            if then_value is None or else_value is None:
                then_table_value = table_assignment_span_source(body_index, then_jump.pc)
                else_table_value = table_assignment_span_source(else_index, join_pc)
                if then_table_value is None or else_table_value is None:
                    return None
                table_reg, target, true_source = then_table_value
                else_table_reg, else_target, false_source = else_table_value
                if table_reg != else_table_reg or target != else_target:
                    return None

                table = table_literals.get(table_reg)
                if table is not None and not table.materialized:
                    materialize_table_reg(table_reg, indent)
                expression = f"if {condition} then {true_source} else {false_source}"
                emit_line(indent, _assignment_source(target, expression))
                return join_index

            target_reg, true_source = then_value
            else_reg, false_source = else_value
            if target_reg != else_reg:
                return None
            expression = f"if {condition} then {true_source} else {false_source}"
            set_reg_or_declare_local(target_reg, expression, join_pc, indent)
            return join_index

        def folded_or_call_value_index(insn, indent: int) -> int | None:
            if insn.op.name != "JUMPIF":
                return None

            target = insn.jump_target
            body_index = pc_to_index.get(insn.next_pc)
            target_index = pc_to_index.get(target) if target is not None else None
            if (
                target is None
                or body_index is None
                or target_index is None
                or target <= insn.next_pc
                or body_index + 1 >= len(instructions)
            ):
                return None

            fallback_value = assignment_span_source(body_index, target)
            if fallback_value is None:
                return None

            target_reg, fallback = fallback_value
            if target_reg != insn.a:
                return None

            set_reg_or_declare_local(insn.a, _binary_expr(reg(insn.a), "or", fallback), target, indent)
            return target_index

        def folded_or_value_chain_index(insn, indent: int) -> int | None:
            if insn.op.name != "JUMPIF":
                return None

            target = insn.jump_target
            current_index = pc_to_index.get(insn.next_pc)
            target_index = pc_to_index.get(target) if target is not None else None
            if (
                target is None
                or current_index is None
                or target_index is None
                or target <= insn.next_pc
                or (stop_pc is not None and target > stop_pc)
            ):
                return None

            target_reg = insn.a
            terms = [reg(target_reg)]
            while current_index < target_index:
                next_jump_index = None
                scan_index = current_index
                while scan_index < target_index:
                    candidate = instructions[scan_index]
                    if (
                        candidate.op.name == "JUMPIF"
                        and candidate.a == target_reg
                        and candidate.jump_target == target
                    ):
                        next_jump_index = scan_index
                        break
                    scan_index += 1

                if next_jump_index is None:
                    fallback_value = assignment_span_source(current_index, target)
                    if fallback_value is None:
                        return None
                    fallback_reg, fallback_source = fallback_value
                    if fallback_reg != target_reg:
                        return None
                    terms.append(fallback_source)
                    expression = " or ".join(_group_if_needed(term) for term in terms)
                    set_reg_or_declare_local(target_reg, expression, target, indent)
                    return target_index

                next_jump = instructions[next_jump_index]
                truthy_value = assignment_span_source(current_index, next_jump.pc)
                if truthy_value is None:
                    return None
                truthy_reg, truthy_source = truthy_value
                if truthy_reg != target_reg:
                    return None
                terms.append(truthy_source)

                following_index = pc_to_index.get(next_jump.next_pc)
                if following_index is None or following_index <= current_index:
                    return None
                current_index = following_index

            return None

        def folded_and_value_index(insn, indent: int) -> int | None:
            if insn.op.name != "JUMPIFNOT":
                return None

            target = insn.jump_target
            body_index = pc_to_index.get(insn.next_pc)
            target_index = pc_to_index.get(target) if target is not None else None
            if (
                target is None
                or body_index is None
                or target_index is None
                or target <= insn.next_pc
                or (stop_pc is not None and target > stop_pc)
            ):
                return None

            truthy_value = assignment_span_source(body_index, target)
            if truthy_value is None:
                truthy_value = and_assignment_span_source(body_index, target)
            if truthy_value is None:
                return None
            target_reg, truthy_source = truthy_value
            if target_reg != insn.a:
                return None

            expression = value_chain_source([reg(insn.a), truthy_source], "and")
            set_reg_or_declare_local(target_reg, expression, target, indent)
            return target_index

        def folded_while_grouped_or_loop_index(insn, indent: int) -> int | None:
            nonlocal open_results, regs, table_literals

            if insn.op.name != "JUMPIF":
                return None

            def parse_or_condition_chain(
                start_index: int,
                expected_end_pc: int | None = None,
            ) -> tuple[str, int, int] | None:
                if start_index >= len(instructions):
                    return None

                first = instructions[start_index]
                first_condition = jump_taken_condition(first)
                body_pc = first.jump_target
                body_index = pc_to_index.get(body_pc) if body_pc is not None else None
                next_index = pc_to_index.get(first.next_pc)
                if (
                    first.op.name not in _CONDITIONAL_JUMP_OPS
                    or first_condition is None
                    or body_pc is None
                    or body_index is None
                    or next_index is None
                    or body_pc <= first.next_pc
                ):
                    return None

                conditions = [first_condition]
                current_index = next_index
                while True:
                    current_index = apply_condition_setup(current_index, body_pc)
                    if current_index is None or current_index >= len(instructions):
                        return None

                    candidate = instructions[current_index]
                    next_condition = jump_taken_condition(candidate)
                    if (
                        candidate.op.name in _CONDITIONAL_JUMP_OPS
                        and next_condition is not None
                        and candidate.jump_target == body_pc
                        and candidate.next_pc < body_pc
                    ):
                        following_index = pc_to_index.get(candidate.next_pc)
                        if following_index is None:
                            return None
                        conditions.append(next_condition)
                        current_index = following_index
                        continue

                    prefix = call_condition_prefix_any(current_index)
                    if prefix is not None:
                        prefix_body_index, prefix_condition, prefix_end_pc = prefix
                        prefix_end_index = pc_to_index.get(prefix_end_pc)
                        if (
                            prefix_body_index == body_index
                            and prefix_end_index is not None
                            and prefix_end_pc > body_pc
                            and (expected_end_pc is None or prefix_end_pc == expected_end_pc)
                            and not (
                                prefix_end_index > body_index
                                and instructions[prefix_end_index - 1].op.name == "JUMPBACK"
                            )
                        ):
                            conditions.append(prefix_condition)
                            return condition_chain_source(conditions, "or"), body_index, prefix_end_index

                    final_condition = jump_fallthrough_condition(candidate)
                    end_pc = candidate.jump_target
                    end_index = pc_to_index.get(end_pc) if end_pc is not None else None
                    if (
                        candidate.op.name in _CONDITIONAL_JUMP_OPS
                        and final_condition is not None
                        and candidate.next_pc == body_pc
                        and end_pc is not None
                        and end_index is not None
                        and end_pc > body_pc
                        and (expected_end_pc is None or end_pc == expected_end_pc)
                    ):
                        conditions.append(final_condition)
                        return condition_chain_source(conditions, "or"), body_index, end_index

                    return None

            start_index = pc_to_index.get(insn.pc)
            if start_index is None:
                return None

            or_chain = parse_or_condition_chain(start_index)
            if or_chain is None:
                return None

            or_condition, body_index, end_index = or_chain
            end_pc = instructions[end_index].pc
            conditions = [or_condition]

            tail_or_chain = parse_or_condition_chain(body_index, end_pc)
            if tail_or_chain is not None:
                tail_condition, body_index, tail_end_index = tail_or_chain
                if tail_end_index != end_index:
                    return None
                conditions.append(tail_condition)
            elif body_index < len(instructions):
                tail_guard = instructions[body_index]
                tail_condition = jump_fallthrough_condition(tail_guard)
                tail_body_index = pc_to_index.get(tail_guard.next_pc)
                if (
                    tail_guard.op.name in _CONDITIONAL_JUMP_OPS
                    and tail_condition is not None
                    and tail_guard.jump_target == end_pc
                    and tail_body_index is not None
                    and tail_guard.next_pc < end_pc
                ):
                    conditions.append(tail_condition)
                    body_index = tail_body_index

            if len(conditions) < 2 and body_index == pc_to_index.get(insn.jump_target):
                return None

            maybe_backedge = instructions[end_index - 1]
            backedge_target = maybe_backedge.jump_target
            if (
                maybe_backedge.op.name != "JUMPBACK"
                or backedge_target is None
                or backedge_target > insn.pc
            ):
                return None

            saved = snapshot_state()
            open_results = None
            emit_line(indent, f"while {condition_chain_source(conditions, 'and')} do")
            emit_range(body_index, maybe_backedge.pc, indent + 1, backedge_target, end_pc)
            emit_line(indent, "end")
            restore_state(saved)
            return end_index

        def folded_while_or_loop_index(insn, indent: int) -> int | None:
            nonlocal open_results, regs, table_literals

            if insn.op.name != "JUMPIF":
                return None

            body_pc = insn.jump_target
            body_index = pc_to_index.get(body_pc) if body_pc is not None else None
            guard_index = pc_to_index.get(insn.pc)
            if body_pc is None or body_index is None or guard_index is None:
                return None

            conditions: list[str] = []
            while guard_index < len(instructions):
                guard = instructions[guard_index]
                if guard.op.name != "JUMPIF" or guard.jump_target != body_pc:
                    break
                condition = jump_taken_condition(guard)
                next_guard_index = pc_to_index.get(guard.next_pc)
                if condition is None or next_guard_index is None or next_guard_index <= guard_index:
                    return None
                conditions.append(condition)
                guard_index = next_guard_index

            if not conditions or guard_index >= len(instructions):
                return None

            exit_guard = instructions[guard_index]
            final_condition = jump_fallthrough_condition(exit_guard)
            exit_pc = exit_guard.jump_target
            exit_index = pc_to_index.get(exit_pc) if exit_pc is not None else None
            if (
                exit_guard.op.name not in _CONDITIONAL_JUMP_OPS
                or final_condition is None
                or exit_guard.next_pc != body_pc
                or exit_pc is None
                or exit_index is None
                or exit_pc > (stop_pc if stop_pc is not None else exit_pc)
                or exit_index <= body_index
            ):
                return None

            maybe_backedge = instructions[exit_index - 1]
            backedge_target = maybe_backedge.jump_target
            if (
                maybe_backedge.op.name != "JUMPBACK"
                or backedge_target is None
                or backedge_target > insn.pc
            ):
                return None

            saved_regs = dict(regs)
            saved_tables = clone_tables()
            open_results = None
            emit_line(indent, f"while {condition_chain_source([*conditions, final_condition], 'or')} do")
            emit_range(body_index, maybe_backedge.pc, indent + 1, backedge_target, exit_pc)
            emit_line(indent, "end")
            regs = saved_regs
            table_literals = saved_tables
            open_results = None
            return exit_index

        def folded_and_or_value_index(insn, indent: int) -> int | None:
            condition = jump_fallthrough_condition(insn)
            if condition is None:
                return None

            first_target = insn.jump_target
            then_index = pc_to_index.get(insn.next_pc)
            if (
                first_target is None
                or then_index is None
                or first_target <= insn.next_pc
            ):
                return None

            def fold_shape(or_jump_index: int, fallback_index: int) -> int | None:
                if or_jump_index >= len(instructions) or fallback_index >= len(instructions):
                    return None

                or_jump = instructions[or_jump_index]
                fallback_assign = instructions[fallback_index]
                join_pc = or_jump.jump_target
                join_index = pc_to_index.get(join_pc) if join_pc is not None else None
                if (
                    or_jump.op.name != "JUMPIF"
                    or join_pc is None
                    or join_index is None
                    or join_pc <= fallback_assign.pc
                    or or_jump.pc <= insn.next_pc
                    or (stop_pc is not None and join_pc > stop_pc)
                ):
                    return None

                then_value = assignment_span_source(then_index, or_jump.pc)
                fallback_value = assignment_span_source(fallback_index, join_pc)
                if fallback_value is None:
                    fallback_value = and_assignment_span_source(fallback_index, join_pc)
                if then_value is None or fallback_value is None:
                    return None

                target_reg, truthy_source = then_value
                fallback_reg, fallback_source = fallback_value
                if target_reg != or_jump.a or fallback_reg != or_jump.a:
                    return None

                expression = (
                    f"{_group_if_needed(condition)} and "
                    f"{_group_if_needed(truthy_source)} or "
                    f"{_group_if_needed(fallback_source)}"
                )
                set_reg_or_declare_local(target_reg, expression, join_pc, indent)
                return join_index

            target_index = pc_to_index.get(first_target)
            if insn.op.name == "JUMPIFNOT" and target_index is not None:
                folded_index = fold_shape(target_index, target_index + 1)
                if folded_index is not None:
                    return folded_index

            if target_index is not None and target_index > then_index:
                return fold_shape(target_index - 1, target_index)

            return None

        def folded_guarded_or_fallback_if_index(insn, indent: int) -> int | None:
            nonlocal open_results

            outer_condition = jump_fallthrough_condition(insn)
            fallback_pc = insn.jump_target
            body_index = pc_to_index.get(insn.next_pc)
            fallback_index = pc_to_index.get(fallback_pc) if fallback_pc is not None else None
            if (
                outer_condition is None
                or fallback_pc is None
                or body_index is None
                or fallback_index is None
                or fallback_pc <= insn.next_pc
            ):
                return None

            def temp_prefix_condition(
                start_index: int,
                limit_pc: int,
            ) -> tuple[int, int, str, str, int] | None:
                temp_regs = dict(regs)
                temp_namecalls: dict[int, tuple[str, str]] = {}
                scan = start_index

                def temp_reg(reg_id: int) -> str:
                    return temp_regs.get(reg_id, reg(reg_id))

                def temp_fallthrough_condition(candidate) -> str | None:
                    name = candidate.op.name
                    if name == "JUMPIF":
                        return _unary_expr("not", temp_reg(candidate.a))
                    if name == "JUMPIFNOT":
                        return temp_reg(candidate.a)
                    if name in _REGISTER_COMPARE_FALLTHROUGH_OPS and candidate.aux is not None:
                        return _binary_expr(
                            temp_reg(candidate.a),
                            _REGISTER_COMPARE_FALLTHROUGH_OPS[name],
                            temp_reg(candidate.aux & 0xFF),
                        )
                    if name in _CONSTANT_COMPARE_OPS and candidate.aux is not None:
                        not_flag = bool(candidate.aux & 0x80000000)
                        operator = "==" if not_flag else "~="
                        if name == "JUMPXEQKNIL":
                            value = "nil"
                        elif name == "JUMPXEQKB":
                            value = "true" if candidate.aux & 1 else "false"
                        else:
                            value = _literal(proto, candidate.aux & 0xFFFFFF)
                        return _binary_expr(temp_reg(candidate.a), operator, value)
                    return None

                def temp_taken_condition(candidate) -> str | None:
                    name = candidate.op.name
                    if name == "JUMPIF":
                        return temp_reg(candidate.a)
                    if name == "JUMPIFNOT":
                        return _unary_expr("not", temp_reg(candidate.a))
                    if name in _REGISTER_COMPARE_TAKEN_OPS and candidate.aux is not None:
                        return _binary_expr(
                            temp_reg(candidate.a),
                            _REGISTER_COMPARE_TAKEN_OPS[name],
                            temp_reg(candidate.aux & 0xFF),
                        )
                    if name in _CONSTANT_COMPARE_OPS and candidate.aux is not None:
                        not_flag = bool(candidate.aux & 0x80000000)
                        operator = "~=" if not_flag else "=="
                        if name == "JUMPXEQKNIL":
                            value = "nil"
                        elif name == "JUMPXEQKB":
                            value = "true" if candidate.aux & 1 else "false"
                        else:
                            value = _literal(proto, candidate.aux & 0xFFFFFF)
                        return _binary_expr(temp_reg(candidate.a), operator, value)
                    return None

                while scan < len(instructions):
                    candidate = instructions[scan]
                    name = candidate.op.name
                    if candidate.pc >= limit_pc:
                        return None
                    if name in _CONDITIONAL_JUMP_OPS:
                        next_index = pc_to_index.get(candidate.next_pc)
                        target = candidate.jump_target
                        taken = temp_taken_condition(candidate)
                        fallthrough = temp_fallthrough_condition(candidate)
                        if next_index is None or target is None or taken is None or fallthrough is None:
                            return None
                        return scan, next_index, taken, fallthrough, target
                    if name == "GETIMPORT" and candidate.aux is not None:
                        temp_regs[candidate.a] = _import_path_expr(proto, candidate.aux)
                    elif name == "GETGLOBAL" and candidate.aux is not None:
                        key = proto.constant_text(candidate.aux) or f"K{candidate.aux}"
                        temp_regs[candidate.a] = _global_expr(key)
                    elif name == "LOADK":
                        temp_regs[candidate.a] = _literal(proto, candidate.d)
                    elif name == "LOADKX" and candidate.aux is not None:
                        temp_regs[candidate.a] = _literal(proto, candidate.aux)
                    elif name == "LOADN":
                        temp_regs[candidate.a] = str(candidate.d)
                    elif name == "LOADB" and not candidate.c:
                        temp_regs[candidate.a] = "true" if candidate.b else "false"
                    elif name == "LOADNIL":
                        temp_regs[candidate.a] = "nil"
                    elif name == "MOVE":
                        temp_regs[candidate.a] = temp_reg(candidate.b)
                    elif name == "GETUPVAL":
                        temp_regs[candidate.a] = _upvalue_name(proto, candidate.b, upvalue_names)
                    elif name in {"GETTABLEKS", "GETUDATAKS"} and candidate.aux is not None:
                        key_index = _aux_key_index(name, candidate.aux)
                        key = proto.constant_text(key_index) or f"K{key_index}"
                        temp_regs[candidate.a] = _field_expr(temp_reg(candidate.b), key)
                    elif name == "GETTABLE":
                        temp_regs[candidate.a] = _index_expr(temp_reg(candidate.b), temp_reg(candidate.c))
                    elif name == "GETTABLEN":
                        temp_regs[candidate.a] = f"{temp_reg(candidate.b)}[{candidate.c + 1}]"
                    elif name in {"NAMECALL", "NAMECALLUDATA"} and candidate.aux is not None:
                        key_index = _aux_key_index(name, candidate.aux)
                        method = proto.constant_text(key_index) or f"K{key_index}"
                        temp_namecalls[candidate.a] = (temp_reg(candidate.b), method)
                    elif name in {"CALL", "CALLFB"}:
                        pending = temp_namecalls.pop(candidate.a, None)
                        if pending:
                            receiver, method = pending
                            args = [
                                temp_reg(candidate.a + 2 + offset)
                                for offset in range(max(candidate.b - 2, 0))
                            ]
                            call = _namecall_expr(receiver, method, args)
                        else:
                            args = [
                                temp_reg(candidate.a + 1 + offset)
                                for offset in range(max(candidate.b - 1, 0))
                            ]
                            call = _call_expr(temp_reg(candidate.a), args)
                        result_count = candidate.c - 1 if candidate.c else 0
                        if result_count != 1:
                            return None
                        temp_regs[candidate.a] = call
                    elif name in FASTCALL_OPS:
                        pass
                    else:
                        return None
                    scan += 1
                return None

            first = temp_prefix_condition(body_index, fallback_pc)
            if first is None:
                return None

            first_jump_index, current_index, first_taken, _first_fallthrough, normal_pc = first
            normal_index = pc_to_index.get(normal_pc)
            if (
                normal_index is None
                or normal_pc <= fallback_pc
                or first_jump_index >= fallback_index
            ):
                return None

            normal_conditions = [first_taken]
            while current_index != fallback_index:
                if current_index is None or current_index >= fallback_index:
                    return None
                next_condition = temp_prefix_condition(current_index, fallback_pc)
                if next_condition is None:
                    return None
                jump_index, current_index, taken, _fallthrough, target_pc = next_condition
                if jump_index >= fallback_index or target_pc != normal_pc:
                    return None
                normal_conditions.append(taken)
                if len(normal_conditions) > 4:
                    return None

            if len(normal_conditions) < 2:
                return None

            fallback_guard = instructions[fallback_index]
            fallback_condition = jump_fallthrough_condition(fallback_guard)
            end_pc = fallback_guard.jump_target
            end_index = pc_to_index.get(end_pc) if end_pc is not None else None
            fallback_body_index = pc_to_index.get(fallback_guard.next_pc)
            if (
                fallback_guard.op.name not in _CONDITIONAL_JUMP_OPS
                or fallback_condition is None
                or end_pc is None
                or end_index is None
                or fallback_body_index is None
                or end_pc <= fallback_guard.next_pc
                or normal_index >= end_index
                or (stop_pc is not None and end_pc > stop_pc)
            ):
                return None

            fallback_jump_index = None
            join_pc = None
            scan = fallback_body_index
            while scan < min(normal_index, end_index):
                candidate = instructions[scan]
                target = candidate.jump_target
                if (
                    candidate.op.name in {"JUMP", "JUMPX"}
                    and target is not None
                    and normal_pc <= target <= end_pc
                    and target in pc_to_index
                ):
                    fallback_jump_index = scan
                    join_pc = target
                    break
                scan += 1

            if fallback_jump_index is None or join_pc is None:
                return None

            join_index = pc_to_index[join_pc]
            normal_or_condition = value_chain_source(normal_conditions, "or")
            condition = condition_chain_source([outer_condition, normal_or_condition], "and")
            saved = snapshot_state()

            open_results = None
            emit_line(indent, f"if {condition} then")
            emit_range(normal_index, end_pc, indent + 1, loop_continue_pc, loop_exit_pc, end_pc)

            restore_state(saved)
            open_results = None
            emit_line(indent, f"elseif {fallback_condition} then")
            fallback_jump = instructions[fallback_jump_index]
            emit_range(fallback_body_index, fallback_jump.pc, indent + 1, loop_continue_pc, loop_exit_pc, join_pc)
            emit_range(join_index, end_pc, indent + 1, loop_continue_pc, loop_exit_pc, end_pc)
            emit_line(indent, "end")

            restore_state(saved)
            return end_index

        def folded_short_circuit_if_index(insn) -> int | None:
            nonlocal open_results, regs, table_literals

            if insn.op.name in {"JUMPIFLE", "JUMPIFLT", "JUMPIFNOTLE", "JUMPIFNOTLT"}:
                return None

            saved = snapshot_state()

            def parse_or_condition_chain(
                start_index: int,
                expected_end_pc: int | None = None,
            ) -> tuple[str, int, int] | None:
                if start_index >= len(instructions):
                    return None

                first = instructions[start_index]
                first_condition = jump_taken_condition(first)
                body_pc = first.jump_target
                body_index = pc_to_index.get(body_pc) if body_pc is not None else None
                next_index = pc_to_index.get(first.next_pc)
                if (
                    first.op.name not in _CONDITIONAL_JUMP_OPS
                    or first_condition is None
                    or body_pc is None
                    or body_index is None
                    or next_index is None
                    or body_pc <= first.next_pc
                ):
                    return None

                conditions = [first_condition]
                current_index = next_index
                while True:
                    current_index = apply_condition_setup(current_index, body_pc)
                    if current_index is None or current_index >= len(instructions):
                        return None

                    candidate = instructions[current_index]
                    next_condition = jump_taken_condition(candidate)
                    if (
                        candidate.op.name in _CONDITIONAL_JUMP_OPS
                        and next_condition is not None
                        and candidate.jump_target == body_pc
                        and candidate.next_pc < body_pc
                    ):
                        following_index = pc_to_index.get(candidate.next_pc)
                        if following_index is None:
                            return None
                        conditions.append(next_condition)
                        current_index = following_index
                        continue

                    prefix = call_condition_prefix_any(current_index)
                    if prefix is not None:
                        prefix_body_index, prefix_condition, prefix_end_pc = prefix
                        prefix_end_index = pc_to_index.get(prefix_end_pc)
                        if (
                            prefix_body_index == body_index
                            and prefix_end_index is not None
                            and prefix_end_pc > body_pc
                            and (expected_end_pc is None or prefix_end_pc == expected_end_pc)
                            and not (
                                prefix_end_index > body_index
                                and instructions[prefix_end_index - 1].op.name == "JUMPBACK"
                            )
                        ):
                            conditions.append(prefix_condition)
                            return condition_chain_source(conditions, "or"), body_index, prefix_end_index

                    final_condition = jump_fallthrough_condition(candidate)
                    end_pc = candidate.jump_target
                    end_index = pc_to_index.get(end_pc) if end_pc is not None else None
                    if (
                        candidate.op.name in _CONDITIONAL_JUMP_OPS
                        and final_condition is not None
                        and candidate.next_pc == body_pc
                        and end_pc is not None
                        and end_index is not None
                        and end_pc > body_pc
                        and (expected_end_pc is None or end_pc == expected_end_pc)
                        and not (end_index > body_index and instructions[end_index - 1].op.name == "JUMPBACK")
                    ):
                        conditions.append(final_condition)
                        return condition_chain_source(conditions, "or"), body_index, end_index

                    return None

            first_condition = jump_taken_condition(insn)
            start_index = pc_to_index.get(insn.pc)
            if start_index is not None:
                first = instructions[start_index]
                first_and_condition = jump_fallthrough_condition(first)
                fallback_pc = first.jump_target
                fallback_index = pc_to_index.get(fallback_pc) if fallback_pc is not None else None
                second_index = pc_to_index.get(first.next_pc)
                if (
                    first_and_condition is not None
                    and fallback_pc is not None
                    and fallback_index is not None
                    and second_index is not None
                    and fallback_pc > first.next_pc
                ):
                    second = instructions[second_index]
                    second_and_condition = jump_taken_condition(second)
                    body_pc = second.jump_target
                    body_index = pc_to_index.get(body_pc) if body_pc is not None else None
                    if (
                        second.op.name in _CONDITIONAL_JUMP_OPS
                        and second_and_condition is not None
                        and second.next_pc == fallback_pc
                        and body_pc is not None
                        and body_index is not None
                        and body_pc > fallback_pc
                    ):
                        fallback_guard = instructions[fallback_index]
                        fallback_condition = jump_fallthrough_condition(fallback_guard)
                        end_pc = fallback_guard.jump_target
                        end_index = pc_to_index.get(end_pc) if end_pc is not None else None
                        if (
                            fallback_guard.op.name in _CONDITIONAL_JUMP_OPS
                            and fallback_condition is not None
                            and fallback_guard.next_pc == body_pc
                            and end_pc is not None
                            and end_index is not None
                            and end_pc > body_pc
                            and not (end_index > body_index and instructions[end_index - 1].op.name == "JUMPBACK")
                        ):
                            branch_saved = snapshot_state()
                            open_results = None
                            and_condition = condition_chain_source([first_and_condition, second_and_condition], "and")
                            condition = f"{and_condition} or {_group_if_needed(fallback_condition)}"
                            emit_line(indent, f"if {condition} then")
                            emit_range(body_index, end_pc, indent + 1, loop_continue_pc, loop_exit_pc)
                            emit_line(indent, "end")
                            restore_state(branch_saved)
                            restore_state(saved)
                            return end_index

            if first_condition is not None and start_index is not None:
                or_chain = parse_or_condition_chain(start_index)
                if or_chain is not None:
                    or_condition, or_body_index, or_end_index = or_chain
                    or_end_pc = instructions[or_end_index].pc
                    if or_body_index < len(instructions):
                        tail_or_chain = parse_or_condition_chain(or_body_index, or_end_pc)
                        if tail_or_chain is not None:
                            tail_or_condition, tail_or_body_index, tail_or_end_index = tail_or_chain
                            if tail_or_end_index == or_end_index:
                                branch_saved = snapshot_state()
                                open_results = None
                                condition = condition_chain_source([or_condition, tail_or_condition], "and")
                                emit_line(indent, f"if {condition} then")
                                emit_range(tail_or_body_index, or_end_pc, indent + 1, loop_continue_pc, loop_exit_pc)
                                emit_line(indent, "end")
                                restore_state(branch_saved)
                                restore_state(saved)
                                return or_end_index

                        tail_guard = instructions[or_body_index]
                        tail_condition = jump_fallthrough_condition(tail_guard)
                        tail_body_index = pc_to_index.get(tail_guard.next_pc)
                        if (
                            tail_guard.op.name in _CONDITIONAL_JUMP_OPS
                            and tail_condition is not None
                            and tail_guard.jump_target == or_end_pc
                            and tail_body_index is not None
                            and tail_guard.next_pc < or_end_pc
                        ):
                            branch_saved = snapshot_state()
                            open_results = None
                            condition = condition_chain_source([or_condition, tail_condition], "and")
                            emit_line(indent, f"if {condition} then")
                            emit_range(tail_body_index, or_end_pc, indent + 1, loop_continue_pc, loop_exit_pc)
                            emit_line(indent, "end")
                            restore_state(branch_saved)
                            restore_state(saved)
                            return or_end_index

                    or_branch_stop_pc = or_end_pc
                    or_else_index = None
                    or_final_end_pc = or_end_pc
                    or_final_end_index = or_end_index
                    if or_end_index > or_body_index:
                        maybe_then_jump = instructions[or_end_index - 1]
                        maybe_then_end_pc = maybe_then_jump.jump_target
                        maybe_then_end_index = pc_to_index.get(maybe_then_end_pc) if maybe_then_end_pc is not None else None
                        if (
                            maybe_then_jump.op.name in {"JUMP", "JUMPX"}
                            and maybe_then_end_pc is not None
                            and maybe_then_end_index is not None
                            and maybe_then_end_pc > or_end_pc
                            and (stop_pc is None or maybe_then_end_pc <= stop_pc)
                        ):
                            or_branch_stop_pc = maybe_then_jump.pc
                            or_else_index = or_end_index
                            or_final_end_pc = maybe_then_end_pc
                            or_final_end_index = maybe_then_end_index

                    restore_state(saved)
                    ranges = [(or_body_index, or_branch_stop_pc)]
                    if or_else_index is not None:
                        ranges.append((or_else_index, or_final_end_pc))
                    materialize_branch_liveout_registers(ranges, or_final_end_index, indent)
                    saved = snapshot_state()
                    branch_saved = snapshot_state()
                    open_results = None
                    emit_line(indent, f"if {or_condition} then")
                    emit_range(or_body_index, or_branch_stop_pc, indent + 1, loop_continue_pc, loop_exit_pc, or_final_end_pc)
                    if or_else_index is not None:
                        restore_state(branch_saved)
                        open_results = None
                        if not emit_elseif_chain(or_else_index, or_final_end_pc):
                            else_line_index = len(lines)
                            emit_line(indent, "else")
                            else_body_index = len(lines)
                            emit_range(or_else_index, or_final_end_pc, indent + 1, loop_continue_pc, loop_exit_pc, or_final_end_pc)
                            if len(lines) == else_body_index:
                                del lines[else_line_index:]
                    emit_line(indent, "end")
                    restore_state(branch_saved)
                    restore_state(saved)
                    return or_final_end_index

            restore_state(saved)

            condition = jump_fallthrough_condition(insn)
            target = insn.jump_target
            body_index = pc_to_index.get(insn.next_pc)
            target_index = pc_to_index.get(target) if target is not None else None
            if (
                condition is not None
                and target is not None
                and body_index is not None
                and target_index is not None
                and target > insn.next_pc
                and not (target_index > body_index and instructions[target_index - 1].op.name == "JUMPBACK")
            ):
                conditions = [condition]
                current_index = body_index
                while True:
                    current_index = apply_condition_setup(current_index, target)
                    if current_index is None or current_index >= len(instructions):
                        break
                    candidate = instructions[current_index]
                    or_state = snapshot_state()
                    or_chain = parse_or_condition_chain(current_index, target)
                    if or_chain is None:
                        restore_state(or_state)
                    if or_chain is not None:
                        or_condition, or_body_index, or_end_index = or_chain
                        if or_end_index == target_index:
                            branch_saved = snapshot_state()
                            open_results = None
                            emit_line(indent, f"if {condition_chain_source([*conditions, or_condition], 'and')} then")
                            emit_range(or_body_index, target, indent + 1, loop_continue_pc, loop_exit_pc)
                            emit_line(indent, "end")
                            restore_state(branch_saved)
                            restore_state(saved)
                            return target_index

                    next_condition = jump_fallthrough_condition(candidate)
                    if (
                        candidate.op.name not in _CONDITIONAL_JUMP_OPS
                        or next_condition is None
                        or candidate.jump_target != target
                        or candidate.next_pc >= target
                    ):
                        break
                    next_index = pc_to_index.get(candidate.next_pc)
                    if next_index is None:
                        restore_state(saved)
                        return None
                    conditions.append(next_condition)
                    current_index = next_index

                if len(conditions) > 1 and current_index is not None and current_index < target_index:
                    branch_saved = snapshot_state()
                    end_pc = target
                    end_index = target_index
                    branch_stop_pc = target
                    else_index = None
                    maybe_then_jump = instructions[target_index - 1]
                    maybe_then_end_pc = maybe_then_jump.jump_target
                    maybe_then_end_index = pc_to_index.get(maybe_then_end_pc) if maybe_then_end_pc is not None else None
                    if (
                        maybe_then_jump.op.name == "JUMP"
                        and maybe_then_end_pc is not None
                        and maybe_then_end_index is not None
                        and maybe_then_end_pc > target
                        and (stop_pc is None or maybe_then_end_pc <= stop_pc)
                    ):
                        branch_stop_pc = maybe_then_jump.pc
                        else_index = target_index
                        end_pc = maybe_then_end_pc
                        end_index = maybe_then_end_index
                    maybe_else_jump = instructions[target_index]
                    maybe_end_pc = maybe_else_jump.jump_target
                    maybe_else_index = pc_to_index.get(maybe_else_jump.next_pc)
                    maybe_end_index = pc_to_index.get(maybe_end_pc) if maybe_end_pc is not None else None
                    if (
                        else_index is None
                        and
                        maybe_else_jump.op.name == "JUMP"
                        and maybe_end_pc is not None
                        and maybe_end_index is not None
                        and maybe_else_index is not None
                        and maybe_end_pc > maybe_else_jump.next_pc
                        and (stop_pc is None or maybe_end_pc <= stop_pc)
                    ):
                        else_index = maybe_else_index
                        end_pc = maybe_end_pc
                        end_index = maybe_end_index

                    open_results = None
                    emit_line(indent, f"if {condition_chain_source(conditions, 'and')} then")
                    emit_range(current_index, branch_stop_pc, indent + 1, loop_continue_pc, loop_exit_pc, end_pc)
                    if else_index is not None:
                        restore_state(branch_saved)
                        open_results = None
                        if not emit_elseif_chain(else_index, end_pc):
                            else_line_index = len(lines)
                            emit_line(indent, "else")
                            else_body_index = len(lines)
                            emit_range(else_index, end_pc, indent + 1, loop_continue_pc, loop_exit_pc, end_pc)
                            if len(lines) == else_body_index:
                                del lines[else_line_index:]
                    emit_line(indent, "end")
                    restore_state(branch_saved)
                    restore_state(saved)
                    return end_index

            restore_state(saved)

            first_condition = jump_taken_condition(insn)
            target = insn.jump_target
            body_index = pc_to_index.get(target) if target is not None else None
            fallthrough_index = pc_to_index.get(insn.next_pc)
            if first_condition is None or target is None or body_index is None or fallthrough_index is None:
                return None

            current_index = apply_condition_setup(fallthrough_index, target)
            if current_index is None or current_index >= len(instructions):
                restore_state(saved)
                return None

            candidate = instructions[current_index]
            next_condition = jump_fallthrough_condition(candidate)
            end_pc = candidate.jump_target
            end_index = pc_to_index.get(end_pc) if end_pc is not None else None
            if (
                candidate.op.name not in _CONDITIONAL_JUMP_OPS
                or next_condition is None
                or candidate.next_pc != target
                or end_pc is None
                or end_index is None
                or end_pc <= target
                or (end_index > body_index and instructions[end_index - 1].op.name == "JUMPBACK")
            ):
                restore_state(saved)
                return None

            branch_saved = snapshot_state()
            open_results = None
            emit_line(indent, f"if {condition_chain_source([first_condition, next_condition], 'or')} then")
            emit_range(body_index, end_pc, indent + 1, loop_continue_pc, loop_exit_pc)
            emit_line(indent, "end")
            restore_state(branch_saved)
            restore_state(saved)
            return end_index

        index = start_index
        while index < len(instructions):
            insn = instructions[index]
            if stop_pc is not None and insn.pc >= stop_pc:
                break

            name = insn.op.name
            finalize_pending_table_reads(insn, indent)
            if name in {"FORGPREP", "FORGPREP_INEXT", "FORGPREP_NEXT"}:
                target = insn.jump_target
                body_index = pc_to_index.get(insn.next_pc)
                loop_index = pc_to_index.get(target) if target is not None else None
                if (
                    target is not None
                    and body_index is not None
                    and loop_index is not None
                    and target > insn.next_pc
                    and (stop_pc is None or target <= stop_pc)
                ):
                    maybe_loop = instructions[loop_index]
                    if (
                        maybe_loop.op.name == "FORGLOOP"
                        and maybe_loop.a == insn.a
                        and maybe_loop.jump_target == insn.next_pc
                    ):
                        var_count = (maybe_loop.aux or 1) & 0xFF
                        if var_count <= 0:
                            var_count = 1
                        loop_vars = [
                            _debug_local_name(proto, insn.a + 3 + offset, insn.next_pc) or f"r{insn.a + 3 + offset}"
                            for offset in range(var_count)
                        ]
                        iterator_call = pending_iterator_calls.pop(insn.a, None)
                        if iterator_call is not None:
                            iterator_values = [iterator_call]
                        elif name == "FORGPREP_INEXT":
                            iterator_values = [_call_expr("ipairs", [reg(insn.a + 1)])]
                        elif name == "FORGPREP_NEXT":
                            iterator_values = [_call_expr("pairs", [reg(insn.a + 1)])]
                        else:
                            iterator_values = _trim_trailing_nil([reg(insn.a), reg(insn.a + 1), reg(insn.a + 2)])

                        loop_end_index = pc_to_index.get(maybe_loop.next_pc)
                        materialize_table_reads([(body_index, maybe_loop.pc)], indent)
                        materialize_table_writes([(body_index, maybe_loop.pc)], indent)
                        materialize_branch_liveout_registers([(body_index, maybe_loop.pc)], loop_end_index, indent)
                        saved_regs = dict(regs)
                        saved_tables = clone_tables()
                        saved_reserved_names = set(reserved_local_names)
                        open_results = None
                        for offset, loop_var in enumerate(loop_vars):
                            regs[insn.a + 3 + offset] = loop_var
                            table_literals.pop(insn.a + 3 + offset, None)
                            if _is_identifier(loop_var):
                                reserved_local_names.add(loop_var)
                        emit_line(indent, f"for {', '.join(loop_vars)} in {', '.join(iterator_values)} do")
                        emit_range(body_index, maybe_loop.pc, indent + 1, maybe_loop.pc, maybe_loop.next_pc)
                        emit_line(indent, "end")
                        regs = saved_regs
                        table_literals = saved_tables
                        reserved_local_names.clear()
                        reserved_local_names.update(saved_reserved_names)
                        open_results = None
                        index = loop_index + 1
                        continue

            if name == "FORNPREP":
                target = insn.jump_target
                body_index = pc_to_index.get(insn.next_pc)
                target_index = pc_to_index.get(target) if target is not None else None
                if (
                    target is not None
                    and body_index is not None
                    and target_index is not None
                    and target > insn.next_pc
                    and target_index > body_index
                    and (stop_pc is None or target <= stop_pc)
                ):
                    maybe_loop = instructions[target_index - 1]
                    if (
                        maybe_loop.op.name == "FORNLOOP"
                        and maybe_loop.a == insn.a
                        and maybe_loop.jump_target == insn.next_pc
                    ):
                        loop_var = _debug_local_name(proto, insn.a + 3, insn.next_pc) or f"r{insn.a + 3}"
                        start_value = reg(insn.a + 2)
                        limit_value = reg(insn.a)
                        step_value = reg(insn.a + 1)

                        loop_end_index = pc_to_index.get(maybe_loop.next_pc)
                        materialize_table_reads([(body_index, maybe_loop.pc)], indent)
                        materialize_table_writes([(body_index, maybe_loop.pc)], indent)
                        materialize_branch_liveout_registers([(body_index, maybe_loop.pc)], loop_end_index, indent)
                        saved_regs = dict(regs)
                        saved_tables = clone_tables()
                        saved_reserved_names = set(reserved_local_names)
                        open_results = None
                        regs[insn.a + 3] = loop_var
                        table_literals.pop(insn.a + 3, None)
                        if _is_identifier(loop_var):
                            reserved_local_names.add(loop_var)
                        emit_line(indent, f"for {loop_var} = {start_value}, {limit_value}, {step_value} do")
                        emit_range(body_index, maybe_loop.pc, indent + 1, maybe_loop.pc, target)
                        emit_line(indent, "end")
                        regs = saved_regs
                        table_literals = saved_tables
                        reserved_local_names.clear()
                        reserved_local_names.update(saved_reserved_names)
                        open_results = None
                        index = target_index
                        continue

            repeat_exit_guard_index = None
            repeat_backedge_index = None
            scan_index = index + 1
            while scan_index < len(instructions):
                candidate = instructions[scan_index]
                if stop_pc is not None and candidate.pc >= stop_pc:
                    break
                if candidate.op.name == "JUMPBACK" and candidate.jump_target == insn.pc and scan_index > index:
                    guard_index = scan_index - 1
                    guard = instructions[guard_index]
                    enclosed_by_forward_guard = any(
                        prior.op.name in _CONDITIONAL_JUMP_OPS
                        and prior.jump_target is not None
                        and prior.next_pc <= candidate.pc < prior.jump_target
                        and prior.jump_target > candidate.next_pc
                        for prior in instructions[index:guard_index]
                    )
                    if (
                        guard.op.name in _CONDITIONAL_JUMP_OPS
                        and guard.next_pc == candidate.pc
                        and guard.jump_target == candidate.next_pc
                        and jump_taken_condition(guard) is not None
                        and not enclosed_by_forward_guard
                    ):
                        repeat_exit_guard_index = guard_index
                        repeat_backedge_index = scan_index
                        break
                scan_index += 1

            if repeat_exit_guard_index is not None and repeat_backedge_index is not None:
                repeat_guard = instructions[repeat_exit_guard_index]
                repeat_backedge = instructions[repeat_backedge_index]
                saved = snapshot_state()
                open_results = None
                emit_line(indent, "repeat")
                emit_range(index, repeat_guard.pc, indent + 1, repeat_guard.pc, repeat_backedge.next_pc)
                condition = jump_taken_condition(repeat_guard) or reg(repeat_guard.a)
                emit_line(indent, f"until {condition}")
                restore_state(saved)
                index = pc_to_index.get(repeat_backedge.next_pc, repeat_backedge_index + 1)
                continue

            repeat_jump_index = None
            scan_index = index + 1
            while scan_index < len(instructions):
                candidate = instructions[scan_index]
                if stop_pc is not None and candidate.pc >= stop_pc:
                    break
                if (
                    candidate.op.name in _CONDITIONAL_JUMP_OPS
                    and candidate.jump_target == insn.pc
                    and candidate.pc > insn.pc
                ):
                    repeat_jump_index = scan_index
                    break
                scan_index += 1

            if repeat_jump_index is not None:
                repeat_jump = instructions[repeat_jump_index]
                repeat_body_stop_pc = repeat_jump.pc
                repeat_condition_jumps = []
                repeat_end_index = pc_to_index.get(repeat_jump.next_pc)
                scan_repeat_index = repeat_jump_index
                while scan_repeat_index < len(instructions):
                    candidate = instructions[scan_repeat_index]
                    next_repeat_index = pc_to_index.get(candidate.next_pc)
                    if (
                        candidate.op.name not in _CONDITIONAL_JUMP_OPS
                        or candidate.jump_target != insn.pc
                        or next_repeat_index is None
                    ):
                        break
                    repeat_condition_jumps.append(candidate)
                    repeat_jump = candidate
                    repeat_end_index = next_repeat_index
                    scan_repeat_index = next_repeat_index

                repeat_or_prefix_jumps = []
                repeat_exit_pc = repeat_jump.next_pc
                previous_index = repeat_jump_index - 1
                expected_next_pc = instructions[repeat_jump_index].pc
                while previous_index >= index:
                    candidate = instructions[previous_index]
                    if (
                        candidate.op.name not in _CONDITIONAL_JUMP_OPS
                        or candidate.next_pc != expected_next_pc
                        or candidate.jump_target != repeat_exit_pc
                        or jump_taken_condition(candidate) is None
                    ):
                        break
                    repeat_or_prefix_jumps.insert(0, candidate)
                    repeat_body_stop_pc = candidate.pc
                    expected_next_pc = candidate.pc
                    previous_index -= 1

                saved_regs = dict(regs)
                saved_tables = clone_tables()
                open_results = None
                emit_line(indent, "repeat")
                emit_range(index, repeat_body_stop_pc, indent + 1, repeat_body_stop_pc, repeat_jump.next_pc)
                repeat_or_conditions = [
                    condition
                    for guard in repeat_or_prefix_jumps
                    if (condition := jump_taken_condition(guard)) is not None
                ]
                repeat_conditions = [
                    condition
                    for guard in repeat_condition_jumps
                    if (condition := jump_fallthrough_condition(guard)) is not None
                ]
                if repeat_or_conditions and repeat_conditions:
                    condition = condition_chain_source([*repeat_or_conditions, repeat_conditions[0]], "or")
                else:
                    condition = (
                        condition_chain_source(repeat_conditions, "and")
                        if len(repeat_conditions) > 1
                        else (repeat_conditions[0] if repeat_conditions else reg(repeat_jump.a))
                    )
                emit_line(indent, f"until {condition}")
                regs = saved_regs
                table_literals = saved_tables
                open_results = None
                index = repeat_end_index if repeat_end_index is not None else repeat_jump_index + 1
                continue

            if name in _CONDITIONAL_JUMP_OPS:
                folded_index = folded_boolean_assignment_index(insn, indent)
                if folded_index is not None:
                    open_results = None
                    index = folded_index
                    continue

                folded_index = folded_if_expression_assignment_index(insn, indent)
                if folded_index is not None:
                    open_results = None
                    index = folded_index
                    continue

                folded_index = folded_or_value_chain_index(insn, indent)
                if folded_index is not None:
                    open_results = None
                    index = folded_index
                    continue

                folded_index = folded_or_call_value_index(insn, indent)
                if folded_index is not None:
                    open_results = None
                    index = folded_index
                    continue

                folded_index = folded_and_or_value_index(insn, indent)
                if folded_index is not None:
                    open_results = None
                    index = folded_index
                    continue

                folded_index = folded_and_value_index(insn, indent)
                if folded_index is not None:
                    open_results = None
                    index = folded_index
                    continue

                folded_state = snapshot_state()
                folded_index = folded_while_grouped_or_loop_index(insn, indent)
                if folded_index is not None:
                    open_results = None
                    index = folded_index
                    continue
                restore_state(folded_state)

                folded_index = folded_while_or_loop_index(insn, indent)
                if folded_index is not None:
                    open_results = None
                    index = folded_index
                    continue

                folded_index = folded_guarded_or_fallback_if_index(insn, indent)
                if folded_index is not None:
                    open_results = None
                    index = folded_index
                    continue

                folded_state = snapshot_state()
                folded_index = folded_short_circuit_if_index(insn)
                if folded_index is not None:
                    open_results = None
                    index = folded_index
                    continue
                restore_state(folded_state)

                target = insn.jump_target
                body_index = pc_to_index.get(insn.next_pc)
                target_index = pc_to_index.get(target) if target is not None else None
                break_condition = jump_taken_condition(insn)
                if (
                    break_condition in {"true", "false", "not true", "not false"}
                    and previous_register_write_count(index, insn.a) > 1
                ):
                    raw_register = _debug_local_name(proto, insn.a, insn.pc) or f"r{insn.a}"
                    if insn.op.name == "JUMPIF":
                        break_condition = raw_register
                    elif insn.op.name == "JUMPIFNOT":
                        break_condition = _unary_expr("not", raw_register)
                if (
                    break_condition is not None
                    and target is not None
                    and target == loop_exit_pc
                    and body_index is not None
                    and target > insn.next_pc
                    and stop_pc is not None
                    and target > stop_pc
                    and target != branch_exit_pc
                ):
                    open_results = None
                    emit_line(indent, f"if {break_condition} then")
                    emit_line(indent + 1, "break")
                    emit_line(indent, "end")
                    index = body_index
                    continue

                return_condition = jump_taken_condition(insn)
                if (
                    return_condition is not None
                    and target is not None
                    and target_index is not None
                    and target_index == len(instructions) - 1
                    and instructions[target_index].op.name == "RETURN"
                    and body_index is not None
                    and target > insn.next_pc
                    and stop_pc is not None
                    and target > stop_pc
                    and target != branch_exit_pc
                ):
                    open_results = None
                    emit_line(indent, f"if {return_condition} then")
                    emit_line(indent + 1, "return")
                    emit_line(indent, "end")
                    index = body_index
                    continue

                condition = jump_fallthrough_condition(insn)
                if condition in {"true", "false", "not true", "not false"}:
                    condition = recover_constant_condition_from_previous_call(index, insn) or condition
                direct_condition = condition
                if (
                    condition is not None
                    and target is not None
                    and body_index is not None
                    and target_index is not None
                    and target > insn.next_pc
                    and (
                        stop_pc is None
                        or target <= stop_pc
                        or target == branch_exit_pc
                        or (
                            stop_pc is not None
                            and target > stop_pc
                            and stop_pc in pc_to_index
                            and target_index > pc_to_index[stop_pc]
                            and (loop_continue_pc is None or target <= loop_continue_pc)
                            and target != loop_exit_pc
                        )
                    )
                ):
                    if stop_pc is not None and target > stop_pc and target != branch_exit_pc:
                        saved_regs = dict(regs)
                        saved_tables = clone_tables()
                        open_results = None
                        emit_line(indent, f"if {condition} then")
                        emit_range(body_index, stop_pc, indent + 1, loop_continue_pc, loop_exit_pc, target)
                        emit_line(indent, "end")
                        regs = saved_regs
                        table_literals = saved_tables
                        open_results = None
                        index = pc_to_index.get(stop_pc, target_index)
                        continue

                    if stop_pc is not None and target == branch_exit_pc and target > stop_pc:
                        branch_exit_jump = instructions[pc_to_index[stop_pc] - 1] if stop_pc in pc_to_index and pc_to_index[stop_pc] > body_index else None
                        body_stop_pc = (
                            branch_exit_jump.pc
                            if branch_exit_jump is not None
                            and branch_exit_jump.op.name in {"JUMP", "JUMPX"}
                            and branch_exit_jump.jump_target == branch_exit_pc
                            else stop_pc
                        )

                        saved_regs = dict(regs)
                        saved_tables = clone_tables()
                        open_results = None
                        emit_line(indent, f"if {condition} then")
                        emit_range(body_index, body_stop_pc, indent + 1, loop_continue_pc, loop_exit_pc, branch_exit_pc)
                        emit_line(indent, "end")
                        regs = saved_regs
                        table_literals = saved_tables
                        open_results = None
                        index = pc_to_index.get(stop_pc, target_index)
                        continue

                    if target_index > body_index:
                        loop_conditions = [condition]
                        loop_body_index = body_index
                        guard_index = body_index
                        while guard_index < target_index:
                            guard = instructions[guard_index]
                            guard_condition = jump_fallthrough_condition(guard)
                            next_guard_index = pc_to_index.get(guard.next_pc)
                            guard_is_condition = guard.op.name in _CONDITIONAL_JUMP_OPS
                            guard_target = guard.jump_target
                            guard_next_pc = guard.next_pc
                            if guard_condition is None:
                                prefix = call_condition_prefix(guard_index, target)
                                if prefix is not None:
                                    next_guard_index, guard_condition = prefix
                                    guard_is_condition = True
                                    guard_target = target
                                    guard_next_pc = instructions[next_guard_index].pc if next_guard_index < len(instructions) else target
                            if (
                                not guard_is_condition
                                or guard_condition is None
                                or guard_target != target
                                or guard_next_pc >= target
                                or next_guard_index is None
                            ):
                                break
                            loop_conditions.append(guard_condition)
                            loop_body_index = next_guard_index
                            guard_index = next_guard_index

                        if len(loop_conditions) > 1:
                            condition = condition_chain_source(loop_conditions, "and")
                            body_index = loop_body_index

                        maybe_backedge = instructions[target_index - 1]
                        backedge_target = maybe_backedge.jump_target
                        if (
                            maybe_backedge.op.name == "JUMPBACK"
                            and backedge_target is not None
                            and backedge_target <= insn.pc
                            and not (
                                loop_continue_pc is not None
                                and backedge_target <= loop_continue_pc
                            )
                        ):
                            loop_ranges = [(loop_body_index, maybe_backedge.pc)]
                            materialize_table_writes(loop_ranges, indent)
                            materialize_branch_liveout_registers(
                                loop_ranges,
                                pc_to_index.get(backedge_target),
                                indent,
                            )
                            condition_start_index = pc_to_index.get(backedge_target)
                            if condition_start_index is not None and backedge_target < insn.pc:
                                apply_condition_setup(condition_start_index, insn.pc)
                            saved_regs = dict(regs)
                            saved_tables = clone_tables()
                            open_results = None
                            loop_condition = (
                                condition_chain_source(loop_conditions, "and")
                                if len(loop_conditions) > 1
                                else (jump_fallthrough_condition(insn) or condition)
                            )
                            emit_line(indent, f"while {loop_condition} do")
                            emit_range(loop_body_index, maybe_backedge.pc, indent + 1, backedge_target, target)
                            emit_line(indent, "end")
                            regs = saved_regs
                            table_literals = saved_tables
                            open_results = None
                            index = target_index
                            continue

                    end_pc = target
                    branch_stop_pc = target
                    else_index = target_index
                    has_else = False
                    if target_index > body_index:
                        maybe_jump = instructions[target_index - 1]
                        jump_target = maybe_jump.jump_target
                        if (
                            maybe_jump.op.name == "JUMP"
                            and jump_target is not None
                            and jump_target > target
                            and (
                                stop_pc is None
                                or jump_target <= stop_pc
                                or jump_target == branch_exit_pc
                            )
                            and jump_target in pc_to_index
                        ):
                            has_else = True
                            branch_stop_pc = maybe_jump.pc
                            end_pc = jump_target
                        else:
                            then_end_pc = terminating_range_end_pc(body_index, target)
                            else_end_pc = terminating_range_end_pc(target_index, stop_pc)
                            if (
                                then_end_pc == target
                                and else_end_pc is not None
                                and (stop_pc is None or else_end_pc <= stop_pc)
                            ):
                                has_else = True
                                branch_stop_pc = target
                                end_pc = else_end_pc

                        if not has_else and target_index > body_index and target_index < len(instructions):
                            maybe_skip = instructions[target_index - 1]
                            fallback = simple_assignment_source(instructions[target_index])
                            fallback_end_pc = instructions[target_index].next_pc
                            if (
                                fallback is not None
                                and maybe_skip.op.name in {"JUMPIF", "JUMPIFNOT"}
                                and maybe_skip.a == fallback[0]
                                and maybe_skip.jump_target == fallback_end_pc
                            ):
                                branch_stop_pc = fallback_end_pc
                                end_pc = fallback_end_pc

                    ranges = [(body_index, branch_stop_pc)]
                    if has_else:
                        ranges.append((else_index, end_pc))
                    materialize_table_writes(ranges, indent)
                    materialize_branch_liveout_registers(ranges, pc_to_index.get(end_pc), indent)
                    if condition == direct_condition:
                        condition = jump_fallthrough_condition(insn) or condition

                    saved_regs = dict(regs)
                    saved_tables = clone_tables()
                    open_results = None
                    emit_line(indent, f"if {condition} then")
                    emit_range(body_index, branch_stop_pc, indent + 1, loop_continue_pc, loop_exit_pc, end_pc)
                    if has_else:
                        regs = dict(saved_regs)
                        table_literals = {
                            reg_id: TableLiteral(dict(table.array), list(table.fields), table.materialized, list(table.writes))
                            for reg_id, table in saved_tables.items()
                        }
                        open_results = None
                        if not emit_elseif_chain(else_index, end_pc):
                            emit_line(indent, "else")
                            emit_range(else_index, end_pc, indent + 1, loop_continue_pc, loop_exit_pc, end_pc)
                    emit_line(indent, "end")
                    regs = saved_regs
                    table_literals = saved_tables
                    open_results = None
                    index = pc_to_index.get(end_pc, len(instructions))
                    continue

            if name.startswith("UNKNOWN_") or name.startswith("ENCODED_"):
                if not encoded_header_written:
                    emit_line(indent, "-- encoded opcode stream: public Luau opcode bytes are not trusted for this proto")
                    encoded_header_written = True
                emit_line(indent, f"-- pc {insn.pc}: encoded or unsupported opcode {insn.op.code} raw=0x{insn.word:08x}")
            elif name == "GETIMPORT" and insn.aux is not None:
                set_reg(insn.a, _import_path_expr(proto, insn.aux))
            elif name == "GETGLOBAL" and insn.aux is not None:
                key = proto.constant_text(insn.aux) or f"K{insn.aux}"
                set_reg(insn.a, _global_expr(key))
            elif name == "SETGLOBAL" and insn.aux is not None:
                key = proto.constant_text(insn.aux) or f"K{insn.aux}"
                open_results = None
                emit_line(indent, _assignment_source(_global_expr(key), reg(insn.a)))
            elif name == "LOADK":
                set_reg_or_declare_local(insn.a, _literal(proto, insn.d), insn.next_pc, indent)
            elif name == "LOADKX" and insn.aux is not None:
                set_reg_or_declare_local(insn.a, _literal(proto, insn.aux), insn.next_pc, indent)
            elif name == "LOADN":
                set_reg_or_declare_local(insn.a, str(insn.d), insn.next_pc, indent)
            elif name == "LOADB":
                set_reg_or_declare_local(insn.a, "true" if insn.b else "false", insn.next_pc, indent)
                if insn.c:
                    target_index = pc_to_index.get(insn.jump_target)
                    if target_index is not None and (stop_pc is None or instructions[target_index].pc < stop_pc):
                        index = target_index
                        continue
            elif name == "LOADNIL":
                if is_generic_for_nil_state_setup(index):
                    set_reg(insn.a, "nil")
                    index += 1
                    continue
                set_reg_or_declare_local(insn.a, "nil", insn.next_pc, indent)
            elif name == "MOVE":
                if not alias_table_reg(insn.a, insn.b, insn.next_pc, indent):
                    value = reg(insn.b)
                    debug_name = _debug_local_name(proto, insn.a, insn.next_pc)
                    repeated_expression = value.startswith("function(") or value.rstrip().endswith(")")
                    if (
                        debug_name is None
                        and repeated_expression
                        and future_register_read_needs_snapshot(index + 1, insn.a)
                    ):
                        declare_inferred_local(insn.a, f"r{insn.a}", value, indent)
                    else:
                        set_reg_or_declare_local(insn.a, value, insn.next_pc, indent)
            elif name == "GETUPVAL":
                set_reg_or_declare_local(insn.a, _upvalue_name(proto, insn.b, upvalue_names), insn.next_pc, indent)
            elif name == "SETUPVAL":
                open_results = None
                materialize_upvalue_snapshots(index, insn.b, insn.a, indent)
                emit_line(indent, f"{_upvalue_name(proto, insn.b, upvalue_names)} = {reg(insn.a)}")
            elif name == "NEWCLOSURE":
                child = _child_proto(proto, insn.d, protos)
                if child is not None:
                    local_name = _debug_local_name(proto, insn.a, insn.next_pc)
                    inferred_name = None
                    if (
                        local_name is None
                        and child.debugname is not None
                        and _is_identifier(child.debugname)
                        and future_register_read_count(index + 1, insn.a) > 1
                        and not closure_captures_register(index, insn.a)
                    ):
                        inferred_name = unique_inferred_local_name(child.debugname)
                        local_name = inferred_name
                    child_upvalue_names = closure_upvalue_names(index, child, indent)
                    if local_name is not None:
                        key = local_key(insn.a, local_name, insn.next_pc) if inferred_name is None else None
                        emit_local_function(
                            indent,
                            local_name,
                            child,
                            child_upvalue_names,
                            declare_local=inferred_name is not None or key not in declared_locals,
                        )
                        if inferred_name is not None:
                            inferred_locals.add(inferred_name)
                        elif key is not None:
                            declared_locals.add(key)
                        set_reg(insn.a, local_name)
                    else:
                        set_reg(insn.a, _function_expr(child, protos, child_upvalue_names))
                else:
                    emit_line(indent, f"-- pc {insn.pc}: {insn.disassemble()}")
                    open_results = None
            elif name == "DUPCLOSURE":
                child = _closure_constant_proto(proto, insn.d, protos)
                if child is not None:
                    local_name = _debug_local_name(proto, insn.a, insn.next_pc)
                    inferred_name = None
                    if (
                        local_name is None
                        and child.debugname is not None
                        and _is_identifier(child.debugname)
                        and future_register_read_count(index + 1, insn.a) > 1
                        and not closure_captures_register(index, insn.a)
                    ):
                        inferred_name = unique_inferred_local_name(child.debugname)
                        local_name = inferred_name
                    child_upvalue_names = closure_upvalue_names(index, child, indent)
                    if local_name is not None:
                        key = local_key(insn.a, local_name, insn.next_pc) if inferred_name is None else None
                        emit_local_function(
                            indent,
                            local_name,
                            child,
                            child_upvalue_names,
                            declare_local=inferred_name is not None or key not in declared_locals,
                        )
                        if inferred_name is not None:
                            inferred_locals.add(inferred_name)
                        elif key is not None:
                            declared_locals.add(key)
                        set_reg(insn.a, local_name)
                    else:
                        set_reg(insn.a, _function_expr(child, protos, child_upvalue_names))
                else:
                    emit_line(indent, f"-- pc {insn.pc}: {insn.disassemble()}")
                    open_results = None
            elif name == "CAPTURE":
                open_results = None
            elif name == "NEWTABLE":
                set_table_reg(insn.a, TableLiteral(), insn.next_pc, indent)
            elif name == "DUPTABLE":
                set_table_reg(insn.a, _duptable_literal(proto, insn.d), insn.next_pc, indent)
            elif name in _BINARY_OPS:
                set_reg_or_materialize_expression(
                    index,
                    insn.a,
                    _binary_expr(reg(insn.b), _BINARY_OPS[name], reg(insn.c)),
                    insn.next_pc,
                    indent,
                )
            elif name in _BINARY_K_OPS:
                set_reg_or_materialize_expression(
                    index,
                    insn.a,
                    _binary_expr(reg(insn.b), _BINARY_K_OPS[name], _literal(proto, insn.c)),
                    insn.next_pc,
                    indent,
                )
            elif name in _REVERSE_K_OPS:
                set_reg_or_materialize_expression(
                    index,
                    insn.a,
                    _binary_expr(_literal(proto, insn.b), _REVERSE_K_OPS[name], reg(insn.c)),
                    insn.next_pc,
                    indent,
                )
            elif name in _UNARY_OPS:
                set_reg_or_materialize_expression(
                    index,
                    insn.a,
                    _unary_expr(_UNARY_OPS[name], reg(insn.b)),
                    insn.next_pc,
                    indent,
                )
            elif name == "CONCAT":
                values = [reg(item) for item in range(insn.b, insn.c + 1)]
                set_reg_or_materialize_expression(
                    index,
                    insn.a,
                    f" .. ".join(_group_if_needed(value) for value in values),
                    insn.next_pc,
                    indent,
                )
            elif name in {"GETTABLEKS", "GETUDATAKS"} and insn.aux is not None:
                key_index = _aux_key_index(name, insn.aux)
                key = proto.constant_text(key_index) or f"K{key_index}"
                receiver = reg(insn.b)
                field = _field_expr(receiver, key)
                debug_name = _debug_local_name(proto, insn.a, insn.next_pc)
                inferred_name = inferred_field_local_name(receiver, key)
                if debug_name is None and future_register_read_count(index + 1, insn.a) > 0:
                    if not declare_inferred_local(insn.a, inferred_name, field, indent):
                        if future_register_read_needs_snapshot(index + 1, insn.a):
                            declare_inferred_local(
                                insn.a,
                                key if _is_identifier(key) else f"r{insn.a}",
                                field,
                                indent,
                            )
                        else:
                            set_reg_or_declare_local(insn.a, field, insn.next_pc, indent)
                else:
                    set_reg_or_declare_local(insn.a, field, insn.next_pc, indent)
            elif name == "GETTABLE":
                set_reg_or_materialize_expression(
                    index,
                    insn.a,
                    _index_expr(reg(insn.b), reg(insn.c)),
                    insn.next_pc,
                    indent,
                )
            elif name == "GETTABLEN":
                set_reg_or_materialize_expression(
                    index,
                    insn.a,
                    f"{reg(insn.b)}[{insn.c + 1}]",
                    insn.next_pc,
                    indent,
                )
            elif name == "SETLIST" and insn.aux is not None:
                table = table_literals.get(insn.a)
                values = open_args(insn.b) if insn.c == 0 else [reg(insn.b + offset) for offset in range(max(insn.c - 1, 0))]
                if table is not None and table.materialized:
                    for offset, value in enumerate(values):
                        emit_line(indent, f"{reg(insn.a)}[{insn.aux + offset}] = {value}")
                elif table is not None:
                    for offset, value in enumerate(values):
                        table.set_array(insn.aux + offset, value)
                    refresh_table_aliases(table)
                else:
                    emit_line(indent, f"-- pc {insn.pc}: {insn.disassemble()}")
                open_results = None
            elif name in {"SETTABLEKS", "SETUDATAKS"} and insn.aux is not None:
                table = table_literals.get(insn.b)
                key_index = _aux_key_index(name, insn.aux)
                key = proto.constant_text(key_index) or f"K{key_index}"
                value = reg(insn.a)
                if table is not None and insn.b in pending_table_locals and value.startswith("function("):
                    emit_pending_table_local(insn.b, indent)
                    table = table_literals.get(insn.b)
                if table is not None and table.materialized:
                    emit_line(indent, _assignment_source(_field_expr(reg(insn.b), key), value))
                elif table is not None:
                    table.set_field(_table_field_key(key), value)
                    refresh_table_aliases(table)
                else:
                    emit_line(indent, _assignment_source(_field_expr(reg(insn.b), key), value))
                open_results = None
            elif name == "SETTABLE":
                table = table_literals.get(insn.b)
                value = reg(insn.a)
                key = reg(insn.c)
                key_text = _unquote_string_literal(key)
                target = (
                    _field_expr(reg(insn.b), key_text)
                    if key_text is not None
                    else f"{reg(insn.b)}[{key}]"
                )
                if table is not None and insn.b in pending_table_locals and value.startswith("function("):
                    emit_pending_table_local(insn.b, indent)
                    table = table_literals.get(insn.b)
                if table is not None and table.materialized:
                    emit_line(indent, _assignment_source(target, value))
                elif table is not None:
                    table.set_field(_table_field_key(key_text) if key_text is not None else f"[{key}]", value)
                    refresh_table_aliases(table)
                else:
                    emit_line(indent, _assignment_source(target, value))
                open_results = None
            elif name == "SETTABLEN":
                table = table_literals.get(insn.b)
                value = reg(insn.a)
                table_index = insn.c + 1
                if table is not None and table.materialized:
                    emit_line(indent, f"{reg(insn.b)}[{table_index}] = {value}")
                elif table is not None:
                    table.set_array(table_index, value)
                    refresh_table_aliases(table)
                else:
                    emit_line(indent, f"{reg(insn.b)}[{table_index}] = {value}")
                open_results = None
            elif name == "NEWCLASSMEMBER" and insn.aux is not None:
                key = proto.constant_text(insn.aux) or f"K{insn.aux}"
                target = _field_expr(reg(insn.a), key)
                open_results = None
                emit_line(indent, _assignment_source(target, reg(insn.c)))
            elif name in {"NAMECALL", "NAMECALLUDATA"} and insn.aux is not None:
                key_index = _aux_key_index(name, insn.aux)
                method = proto.constant_text(key_index) or f"K{key_index}"
                pending_namecalls[insn.a] = (reg(insn.b), method)
                open_results = None
            elif name == "GETVARARGS":
                if insn.b == 0:
                    table_literals.pop(insn.a, None)
                    regs[insn.a] = "..."
                    open_results = (insn.a, ["..."])
                elif insn.b >= 2:
                    count = insn.b - 1
                    if count > 1 and declare_multi_result_locals(insn.a, count, "...", insn.next_pc, indent):
                        pass
                    else:
                        for offset in range(count):
                            set_reg_or_declare_local(insn.a + offset, "...", insn.next_pc, indent)
                else:
                    open_results = None
                    emit_line(indent, f"-- pc {insn.pc}: {insn.disassemble()}")
            elif name in {"CALL", "CALLFB"}:
                pending = pending_namecalls.pop(insn.a, None)
                call_target = None
                if pending:
                    receiver, method = pending
                    args = open_args(insn.a + 2) if insn.b == 0 else fixed_args(insn.a + 2, max(insn.b - 2, 0))
                    call = _namecall_expr(receiver, method, args)
                else:
                    args = open_args(insn.a + 1) if insn.b == 0 else fixed_args(insn.a + 1, max(insn.b - 1, 0))
                    call_target = reg(insn.a)
                    call = _call_expr(call_target, args)

                result_count = insn.c - 1 if insn.c else 0
                open_results = None
                if insn.c == 0:
                    table_literals.pop(insn.a, None)
                    regs[insn.a] = call
                    open_results = (insn.a, [call])
                elif result_count > 0:
                    next_insn = instructions[index + 1] if index + 1 < len(instructions) else None
                    if (
                        result_count == 1
                        and _debug_local_name(proto, insn.a, insn.next_pc) is None
                        and future_register_read_count(index + 1, insn.a) == 0
                    ):
                        emit_line(indent, call)
                    elif (
                        result_count == 3
                        and next_insn is not None
                        and next_insn.op.name in {"FORGPREP", "FORGPREP_INEXT", "FORGPREP_NEXT"}
                        and next_insn.a == insn.a
                    ):
                        pending_iterator_calls[insn.a] = call
                        open_results = None
                    elif result_count > 1 and declare_multi_result_locals(insn.a, result_count, call, insn.next_pc, indent):
                        pass
                    elif result_count > 1 and assign_multi_result_locals(insn.a, result_count, call, insn.next_pc, indent):
                        pass
                    elif result_count > 1 and assign_mixed_multi_result_locals(
                        insn.a,
                        result_count,
                        call,
                        insn.next_pc,
                        indent,
                    ):
                        pass
                    elif pending and result_count == 1:
                        service_name = inferred_service_name(receiver, method, args)
                        debug_name = _debug_local_name(proto, insn.a, insn.next_pc)
                        if service_name is not None and debug_name is None:
                            if service_name not in inferred_locals:
                                emit_line(indent, f"local {service_name}: {service_name} = {call}")
                                inferred_locals.add(service_name)
                            set_reg(insn.a, service_name)
                        elif debug_name is None and future_register_read_count(index + 1, insn.a) > 0:
                            inferred_name = inferred_namecall_local_name(receiver, method, args)
                            if declare_inferred_local(insn.a, inferred_name, call, indent):
                                pass
                            elif future_register_read_needs_snapshot(index + 1, insn.a):
                                local_name = unique_inferred_local_name(f"r{insn.a}")
                                key = local_key(insn.a, local_name, insn.next_pc)
                                if key not in declared_locals:
                                    emit_line(indent, f"local {local_name} = {call}")
                                    declared_locals.add(key)
                                elif call != local_name:
                                    emit_line(indent, f"{local_name} = {call}")
                                set_reg(insn.a, local_name)
                            else:
                                set_reg_or_declare_local(insn.a, call, insn.next_pc, indent)
                        else:
                            set_reg_or_declare_local(insn.a, call, insn.next_pc, indent)
                    else:
                        module_name = inferred_require_name(call_target or "", args)
                        debug_name = _debug_local_name(proto, insn.a, insn.next_pc)
                        if module_name is not None and debug_name is None and future_register_read_needs_snapshot(index + 1, insn.a):
                            if module_name not in inferred_locals:
                                emit_line(indent, f"local {module_name} = {call}")
                                inferred_locals.add(module_name)
                            set_reg(insn.a, module_name)
                        elif debug_name is None and future_register_read_needs_snapshot(index + 1, insn.a):
                            if not declare_inferred_local(insn.a, f"r{insn.a}", call, indent):
                                set_reg_or_declare_local(insn.a, call, insn.next_pc, indent)
                        else:
                            set_reg_or_declare_local(insn.a, call, insn.next_pc, indent)
                else:
                    emit_line(indent, call)
            elif name == "RETURN":
                if insn.b == 0:
                    values = open_args(insn.a)
                    open_results = None
                    if values:
                        emit_line(indent, f"return {', '.join(values)}")
                    elif insn is not last_instruction:
                        emit_line(indent, "return")
                elif insn.b <= 1:
                    open_results = None
                    if insn is not last_instruction:
                        emit_line(indent, "return")
                else:
                    open_results = None
                    values = [return_reg(insn.a + offset, insn.pc) for offset in range(insn.b - 1)]
                    emit_line(indent, f"return {', '.join(values)}")
                break
            elif name in {"JUMP", "JUMPX"}:
                open_results = None
                target = insn.jump_target
                target_index = pc_to_index.get(target) if target is not None else None
                if target is not None and target == branch_exit_pc:
                    if target_index is not None:
                        index = target_index
                        continue
                    break
                if target is not None and target == loop_exit_pc:
                    emit_line(indent, "break")
                    if stop_pc is not None and stop_pc in pc_to_index:
                        index = pc_to_index[stop_pc]
                        continue
                if target is not None and (
                    target == loop_continue_pc or (stop_pc is not None and target == stop_pc)
                ):
                    emit_line(indent, "continue")
                    if stop_pc is not None and stop_pc in pc_to_index:
                        index = pc_to_index[stop_pc]
                        continue
                if target_index is not None and target > insn.next_pc and (stop_pc is None or target <= stop_pc):
                    index = target_index
                    continue
                emit_line(indent, f"-- pc {insn.pc}: {insn.disassemble()}")
            elif name == "JUMPBACK":
                open_results = None
                target = insn.jump_target
                if target is not None and loop_continue_pc is not None and target <= loop_continue_pc:
                    emit_line(indent, "continue")
                    if stop_pc is not None and stop_pc in pc_to_index:
                        index = pc_to_index[stop_pc]
                        continue
                emit_line(indent, f"-- pc {insn.pc}: {insn.disassemble()}")
            elif name in {"JUMPIF", "JUMPIFNOT"}:
                open_results = None
                emit_line(indent, f"-- pc {insn.pc}: {insn.disassemble()}")
            elif name == "CMPPROTO":
                open_results = None
                if insn.jump_target != insn.next_pc:
                    emit_line(indent, f"-- pc {insn.pc}: {insn.disassemble()}")
            elif name in FASTCALL_OPS:
                pass
            elif name not in _SOURCELESS_OPS:
                open_results = None
                emit_line(indent, f"-- pc {insn.pc}: {insn.disassemble()}")

            index += 1

        return index

    emit_range(0, None, 0)

    return "\n".join(lines) + ("\n" if lines else "")


def decompile_chunk(chunk: BytecodeChunk, proto_id: int | None = None) -> str:
    index = chunk.main_proto if proto_id is None else proto_id
    proto = chunk.protos[index]
    header = [
        "-- Flow Decompiler",
        f"-- bytecode version {chunk.version}, type version {chunk.type_version}, proto {index}",
    ]
    return "\n".join(header) + "\n" + decompile_proto(proto, chunk.protos)
