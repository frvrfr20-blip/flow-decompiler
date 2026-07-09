from __future__ import annotations

from dataclasses import dataclass, field

from .chunk import Proto


@dataclass(frozen=True)
class CallEvidence:
    pc: int
    receiver: str
    method: str
    args: list[str]


@dataclass(frozen=True)
class FunctionCallEvidence:
    pc: int
    function: str
    args: list[str]

    @property
    def receiver(self) -> str:
        return ""

    @property
    def method(self) -> str:
        return ""


@dataclass(frozen=True)
class ClosureEvidence:
    pc: int
    kind: str
    register: int
    child_proto: int | None
    debugname: str | None
    linedefined: int
    numparams: int
    is_vararg: bool
    numupvalues: int
    params: list[str]
    upvalues: list[str]


@dataclass
class ProtoSummary:
    imports: list[str] = field(default_factory=list)
    namecalls: list[str] = field(default_factory=list)
    calls: list[CallEvidence | FunctionCallEvidence] = field(default_factory=list)
    closures: list[ClosureEvidence] = field(default_factory=list)


def _const_literal(proto: Proto, index: int) -> str:
    const = proto.constant(index)
    if const is None:
        return f"K{index}"
    if const.kind == "string":
        return repr(const.value)
    if const.kind == "number" or const.kind == "integer":
        return str(const.value)
    if const.kind == "boolean":
        return "true" if const.value else "false"
    if const.kind == "nil":
        return "nil"
    if const.kind == "import":
        return proto.import_path(int(const.value))
    return f"{const.kind}<{const.value}>"


def _call_expr(function: str, args: list[str]) -> str:
    return f"{function}({', '.join(args)})"


def _namecall_expr(receiver: str, method: str, args: list[str]) -> str:
    return f"{receiver}:{method}({', '.join(args)})"


def _aux_key_index(opname: str, aux: int) -> int:
    if opname in {"GETUDATAKS", "SETUDATAKS", "NAMECALLUDATA"}:
        return aux & 0xFFFF
    return aux


def _debug_local_name(proto: Proto, reg_id: int, pc: int) -> str | None:
    for local in reversed(proto.debug_locals):
        if local.reg == reg_id and local.name and local.start_pc <= pc < local.end_pc:
            return local.name
    return None


def _parameter_names(proto: Proto) -> list[str]:
    return [_debug_local_name(proto, reg_id, 0) or f"p{reg_id}" for reg_id in range(proto.numparams)]


def _upvalue_names(proto: Proto) -> list[str]:
    return [
        proto.debug_upvalues[index] if index < len(proto.debug_upvalues) and proto.debug_upvalues[index] else f"upvalue{index}"
        for index in range(proto.numupvalues)
    ]


def _child_proto_id(parent: Proto, index: int) -> int | None:
    if index < 0:
        return None
    if index < len(parent.child_protos):
        return parent.child_protos[index]
    return index


def _closure_constant_proto_id(proto: Proto, index: int) -> int | None:
    const = proto.constant(index)
    if const is None or const.kind != "closure":
        return None
    return int(const.value)


def _proto_by_id(protos: list[Proto] | None, proto_id: int | None) -> Proto | None:
    if protos is None or proto_id is None:
        return None
    if 0 <= proto_id < len(protos):
        return protos[proto_id]
    return None


def _capture_count(instructions, start_index: int) -> int:
    count = 0
    for insn in instructions[start_index + 1 :]:
        if insn.op.name != "CAPTURE":
            break
        count += 1
    return count


def _closure_evidence(
    pc: int,
    kind: str,
    register: int,
    child_proto_id: int | None,
    child: Proto | None,
    fallback_numupvalues: int,
) -> ClosureEvidence:
    if child is None:
        return ClosureEvidence(
            pc,
            kind,
            register,
            child_proto_id,
            None,
            0,
            0,
            False,
            fallback_numupvalues,
            [],
            [f"upvalue{index}" for index in range(fallback_numupvalues)],
        )

    return ClosureEvidence(
        pc,
        kind,
        register,
        child_proto_id,
        child.debugname,
        child.linedefined,
        child.numparams,
        child.is_vararg,
        child.numupvalues,
        _parameter_names(child),
        _upvalue_names(child),
    )


def summarize_proto(proto: Proto, protos: list[Proto] | None = None) -> ProtoSummary:
    summary = ProtoSummary()
    regs: dict[int, str] = {}
    pending_namecalls: dict[int, tuple[str, str]] = {}

    for index, insn in enumerate(proto.instructions):
        name = insn.op.name
        if name == "GETIMPORT" and insn.aux is not None:
            path = proto.import_path(insn.aux)
            regs[insn.a] = path
            if path not in summary.imports:
                summary.imports.append(path)
        elif name == "GETGLOBAL" and insn.aux is not None:
            regs[insn.a] = proto.constant_text(insn.aux) or f"K{insn.aux}"
        elif name == "LOADK":
            regs[insn.a] = _const_literal(proto, insn.d)
        elif name == "LOADKX" and insn.aux is not None:
            regs[insn.a] = _const_literal(proto, insn.aux)
        elif name == "LOADN":
            regs[insn.a] = str(insn.d)
        elif name == "LOADB":
            regs[insn.a] = "true" if insn.b else "false"
        elif name == "LOADNIL":
            regs[insn.a] = "nil"
        elif name == "MOVE":
            regs[insn.a] = regs.get(insn.b, f"r{insn.b}")
        elif name in {"GETTABLEKS", "GETUDATAKS"} and insn.aux is not None:
            key_index = _aux_key_index(name, insn.aux)
            key = proto.constant_text(key_index) or f"K{key_index}"
            regs[insn.a] = f"{regs.get(insn.b, f'r{insn.b}')}.{key}"
        elif name in {"NAMECALL", "NAMECALLUDATA"} and insn.aux is not None:
            key_index = _aux_key_index(name, insn.aux)
            method = proto.constant_text(key_index) or f"K{key_index}"
            receiver = regs.get(insn.b, f"r{insn.b}")
            pending_namecalls[insn.a] = (receiver, method)
            if method not in summary.namecalls:
                summary.namecalls.append(method)
        elif name == "NEWCLOSURE":
            child_proto_id = _child_proto_id(proto, insn.d)
            summary.closures.append(
                _closure_evidence(
                    insn.pc,
                    name,
                    insn.a,
                    child_proto_id,
                    _proto_by_id(protos, child_proto_id),
                    _capture_count(proto.instructions, index),
                )
            )
        elif name == "DUPCLOSURE":
            child_proto_id = _closure_constant_proto_id(proto, insn.d)
            summary.closures.append(
                _closure_evidence(
                    insn.pc,
                    name,
                    insn.a,
                    child_proto_id,
                    _proto_by_id(protos, child_proto_id),
                    _capture_count(proto.instructions, index),
                )
            )
        elif name in {"CALL", "CALLFB"}:
            pending = pending_namecalls.pop(insn.a, None)
            result_count = insn.c - 1 if insn.c else 0
            if pending:
                receiver, method = pending
                arg_count = max(insn.b - 2, 0) if insn.b else 0
                args = [regs.get(insn.a + 2 + i, f"r{insn.a + 2 + i}") for i in range(arg_count)]
                summary.calls.append(CallEvidence(insn.pc, receiver, method, args))
                if result_count > 0:
                    regs[insn.a] = _namecall_expr(receiver, method, args)
            else:
                function = regs.get(insn.a, f"r{insn.a}")
                arg_count = max(insn.b - 1, 0) if insn.b else 0
                args = [regs.get(insn.a + 1 + i, f"r{insn.a + 1 + i}") for i in range(arg_count)]
                summary.calls.append(FunctionCallEvidence(insn.pc, function, args))
                if result_count > 0:
                    regs[insn.a] = _call_expr(function, args)

    return summary
