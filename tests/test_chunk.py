import struct
import sys
import unittest
import base64

from luau_decompiler.chunk import parse_chunk
from luau_decompiler.decompile import (
    TableLiteral,
    _binary_expr,
    _call_expr,
    _field_expr,
    _index_expr,
    _is_loop_continue_target,
    _namecall_expr,
    _needs_statement_separator,
    _quote_string,
    decompile_chunk,
)
from luau_decompiler.disasm import encode_abc, encode_ad, encode_e


def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def string_table(strings):
    out = bytearray(varint(len(strings)))
    for value in strings:
        raw = value.encode("utf-8")
        out += varint(len(raw))
        out += raw
    return bytes(out)


def import_id(*ids):
    value = len(ids) << 30
    for shift, item in zip((20, 10, 0), ids):
        value |= item << shift
    return value


def make_namecall_chunk():
    strings = ["game", "FireServer"]
    words = [
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_abc("NAMECALL", 1, 0, 0),
        2,
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_non_identifier_import_path_chunk():
    strings = ["game", "Folder-Name"]
    words = [
        encode_ad("GETIMPORT", 0, 2),
        import_id(0, 1),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out.append(4)
    out += struct.pack("<I", import_id(0, 1))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_identifier_string_key_field_chunk():
    strings = ["ReplicatedStorage", "Packages"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_ad("LOADK", 1, 1),
        encode_abc("GETTABLE", 2, 0, 1),
        encode_abc("RETURN", 2, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_vector_return_chunk():
    words = [
        encode_ad("LOADK", 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(5)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(1)
    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(7)
    out += struct.pack("<ffff", 1.0, 2.5, -3.0, 0.0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_class_shape_chunk():
    strings = ["Widget", "health", "mana", "spawn"]
    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    words = [encode_abc("RETURN", 0, 1, 0)]
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(5)
    for string_id in (1, 2, 3, 4):
        out.append(3)
        out += varint(string_id)
    out.append(10)
    out += varint(0)
    out += varint(2)
    out += varint(1)
    out += varint(1)
    out += varint(2)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_arithmetic_call_chunk():
    strings = ["print"]
    words = [
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_ad("LOADN", 1, 40),
        encode_abc("ADDK", 1, 1, 2),
        encode_abc("CALL", 0, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(9)
    out.append(0)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_local_reassignment_call_chunk():
    strings = ["print", "count"]
    words = [
        encode_ad("LOADN", 0, 1),
        encode_abc("ADDK", 0, 0, 2),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(9)
    out.append(0)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(2)
    out += varint(1)
    out += varint(6)
    out.append(0)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_shadowed_local_same_register_chunk():
    strings = ["print", "value", "outer", "inner"]
    words = [
        encode_ad("LOADK", 0, 0),
        encode_ad("GETIMPORT", 1, 3),
        import_id(2),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_ad("LOADK", 0, 1),
        encode_ad("GETIMPORT", 1, 3),
        import_id(2),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(3)
    out.append(3)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(2))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    out += varint(2)
    out += varint(1)
    out += varint(5)
    out.append(0)
    out += varint(2)
    out += varint(6)
    out += varint(10)
    out.append(0)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_fastcall_fallback_call_chunk():
    strings = ["assert", "ok"]
    words = [
        encode_ad("LOADK", 1, 2),
        encode_abc("FASTCALL1", 1, 1, 2),
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_abc("CALL", 0, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_unused_single_call_result_chunk():
    strings = ["initialize"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("CALL", 0, 1, 2),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_call_result_global_assignment_chunk():
    strings = ["compute", "result"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("CALL", 0, 1, 2),
        encode_abc("SETGLOBAL", 0, 0, 0),
        1,
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(len(strings))
    for string_id in range(1, len(strings) + 1):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_fastcall_open_argument_chunk():
    strings = ["first", "producer", "consume"]
    words = [
        encode_ad("LOADK", 2, 0),
        encode_abc("GETGLOBAL", 3, 0, 0),
        1,
        encode_abc("CALL", 3, 1, 0),
        encode_abc("FASTCALL", 52, 0, 2),
        encode_abc("GETGLOBAL", 1, 0, 0),
        2,
        encode_abc("CALL", 1, 0, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(len(strings))
    for string_id in range(1, len(strings) + 1):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_failed_loop_probe_preserves_call_condition_chunk():
    strings = ["IsDescendantOf"]
    words = [
        encode_abc("MOVE", 5, 2, 0),
        encode_abc("NAMECALL", 3, 0, 0),
        0,
        encode_abc("CALL", 3, 3, 2),
        encode_ad("JUMPIF", 3, 3),
        encode_abc("MOVE", 3, 1, 0),
        encode_abc("CALL", 3, 1, 1),
        encode_abc("RETURN", 0, 1, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(len(strings))
    for string_id in range(1, len(strings) + 1):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_closeupvals_call_chunk():
    strings = ["print", "ok"]
    words = [
        encode_ad("LOADK", 0, 2),
        encode_abc("CLOSEUPVALS", 0, 0, 0),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_coverage_call_chunk():
    strings = ["print", "ok"]
    words = [
        encode_ad("LOADK", 0, 2),
        encode_e("COVERAGE", 123),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_nativecall_call_chunk():
    strings = ["print", "ok"]
    words = [
        encode_abc("NATIVECALL", 0, 0, 0),
        encode_ad("LOADK", 0, 2),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_cmpproto_noop_call_chunk():
    strings = ["print", "ok"]
    words = [
        encode_ad("CMPPROTO", 0, 1),
        0,
        encode_ad("LOADK", 0, 2),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(11)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_global_call_chunk():
    strings = ["print", "hi"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_ad("LOADK", 1, 1),
        encode_abc("CALL", 0, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_debug_named_field_read_call_chunk():
    strings = ["print", "profile", "name", "item"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("GETTABLEKS", 1, 0, 0),
        1,
        encode_ad("GETIMPORT", 2, 3),
        import_id(2),
        encode_abc("MOVE", 3, 1, 0),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(2))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(4)
    out += varint(4)
    out += varint(8)
    out.append(1)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_global_assign_chunk():
    strings = ["maker", "nickname"]
    words = [
        encode_ad("LOADK", 0, 0),
        encode_abc("SETGLOBAL", 0, 0, 0),
        1,
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_return_then_dead_global_chunk():
    strings = ["deadValue"]
    words = [
        encode_ad("LOADN", 0, -1),
        encode_abc("RETURN", 0, 2, 0),
        encode_ad("LOADN", 0, 99),
        encode_abc("SETGLOBAL", 0, 0, 0),
        0,
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_nil_receiver_table_write_chunk():
    words = [
        encode_abc("LOADNIL", 0, 0, 0),
        encode_abc("LOADNIL", 1, 0, 0),
        encode_abc("LOADNIL", 2, 0, 0),
        encode_abc("SETTABLE", 0, 1, 2),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_udata_field_call_chunk():
    strings = ["print", "obj", "Name"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        1,
        encode_abc("GETUDATAKS", 1, 0, 0),
        2 | (17 << 16),
        encode_abc("GETGLOBAL", 2, 0, 0),
        0,
        encode_abc("MOVE", 3, 1, 0),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(9)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    for string_id in (1, 2, 3):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_udata_field_assign_chunk():
    strings = ["maker", "obj", "Name"]
    words = [
        encode_ad("LOADK", 0, 0),
        encode_abc("GETGLOBAL", 1, 0, 0),
        1,
        encode_abc("SETUDATAKS", 0, 1, 0),
        2 | (29 << 16),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(9)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    for string_id in (1, 2, 3):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_udata_namecall_chunk():
    strings = ["obj", "FireServer", "hi"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("NAMECALLUDATA", 1, 0, 0),
        1 | (11 << 16),
        encode_ad("LOADK", 3, 2),
        encode_abc("CALL", 1, 3, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(9)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    for string_id in (1, 2, 3):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_table_call_chunk():
    strings = ["print", "name", "maker"]
    words = [
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_abc("NEWTABLE", 1, 1, 0),
        2,
        encode_ad("LOADN", 2, 1),
        encode_ad("LOADN", 3, 2),
        encode_abc("SETLIST", 1, 2, 3),
        1,
        encode_ad("LOADK", 2, 3),
        encode_abc("SETTABLEKS", 2, 1, 0),
        2,
        encode_abc("CALL", 0, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_table_side_effect_array_order_chunk():
    strings = ["f", "g"]
    words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_abc("GETGLOBAL", 1, 0, 0),
        0,
        encode_abc("CALL", 1, 1, 2),
        encode_abc("SETTABLEN", 1, 0, 1),
        encode_abc("GETGLOBAL", 1, 0, 0),
        1,
        encode_abc("CALL", 1, 1, 2),
        encode_abc("SETTABLEN", 1, 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    for string_id in (1, 2):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_anonymous_table_read_twice_chunk():
    strings = ["print", "name", "maker"]
    words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_ad("LOADK", 1, 3),
        encode_abc("SETTABLEKS", 1, 0, 0),
        2,
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_duptable_call_chunk():
    strings = ["print", "enabled", "name", "maker"]
    words = [
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_ad("DUPTABLE", 1, 6),
        encode_abc("CALL", 0, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(7)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(1)
    out.append(1)
    out.append(3)
    out += varint(3)
    out.append(3)
    out += varint(4)
    out.append(8)
    out += varint(2)
    out += varint(2)
    out += struct.pack("<i", 3)
    out += varint(4)
    out += struct.pack("<i", 5)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_duptable_patch_chunk():
    strings = ["print", "name", "score"]
    words = [
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_ad("DUPTABLE", 1, 4),
        encode_ad("LOADN", 2, 99),
        encode_abc("SETTABLEKS", 2, 1, 0),
        3,
        encode_abc("CALL", 0, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(5)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out.append(5)
    out += varint(2)
    out += varint(2)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_table_alias_patch_chunk():
    strings = ["print", "name", "maker"]
    words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_abc("MOVE", 1, 0, 0),
        encode_ad("LOADK", 2, 3),
        encode_abc("SETTABLEKS", 2, 1, 0),
        2,
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_abc("MOVE", 3, 0, 0),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_stripped_table_alias_read_twice_chunk():
    strings = ["print", "name", "maker"]
    words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_abc("MOVE", 1, 0, 0),
        encode_ad("LOADK", 2, 3),
        encode_abc("SETTABLEKS", 2, 1, 0),
        2,
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_abc("MOVE", 3, 0, 0),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 1, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_debug_named_table_alias_patch_chunk():
    strings = ["print", "name", "maker", "t", "alias"]
    words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_abc("MOVE", 1, 0, 0),
        encode_ad("LOADK", 2, 3),
        encode_abc("SETTABLEKS", 2, 1, 0),
        2,
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_abc("MOVE", 3, 0, 0),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    out += varint(4)
    out += varint(2)
    out += varint(10)
    out.append(0)
    out += varint(5)
    out += varint(3)
    out += varint(10)
    out.append(1)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_debug_named_table_literal_return_chunk():
    strings = ["Config", "name", "maker"]
    words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_ad("LOADK", 1, 2),
        encode_abc("SETTABLEKS", 1, 0, 0),
        1,
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(1)
    out += varint(1)
    out += varint(5)
    out.append(0)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_pending_table_capture_closure_chunk():
    strings = ["Config", "name", "maker"]
    main_words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_ad("LOADK", 1, 2),
        encode_abc("SETTABLEKS", 1, 0, 0),
        1,
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("CAPTURE", 0, 0, 0),
        encode_abc("RETURN", 1, 2, 0),
    ]
    child_words = [
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(1)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(1)
    out += varint(1)
    out += varint(8)
    out.append(0)
    out += varint(0)

    out += bytes([1, 0, 1, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(0)
    out += varint(1)
    out += varint(1)

    out += varint(0)
    return bytes(out)


def make_branch_mutated_table_config_chunk():
    strings = ["retry", "endpoint", "dev", "prod", "Config", "flag"]
    words = [
        encode_abc("NEWTABLE", 1, 0, 0),
        0,
        encode_ad("LOADN", 2, 2),
        encode_abc("SETTABLEKS", 2, 1, 0),
        0,
        encode_ad("JUMPIFNOT", 0, 4),
        encode_ad("LOADK", 2, 2),
        encode_abc("SETTABLEKS", 2, 1, 0),
        1,
        encode_ad("JUMP", 0, 3),
        encode_ad("LOADK", 2, 3),
        encode_abc("SETTABLEKS", 2, 1, 0),
        1,
        encode_abc("RETURN", 1, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 1, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    for string_id in (1, 2, 3, 4):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    out += varint(6)
    out += varint(0)
    out += varint(14)
    out.append(0)
    out += varint(5)
    out += varint(2)
    out += varint(14)
    out.append(1)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_loop_mutated_table_dynamic_key_chunk():
    strings = ["items", "Name", "out", "_", "child"]
    words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_ad("LOADN", 3, 0),
        encode_ad("FORGPREP_INEXT", 1, 3),
        encode_abc("GETTABLEKS", 6, 5, 0),
        2,
        encode_abc("SETTABLE", 5, 0, 6),
        encode_ad("FORGLOOP", 1, -4),
        2,
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([7, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(3)
    out += varint(3)
    out += varint(2)
    out += varint(12)
    out.append(0)
    out += varint(4)
    out += varint(6)
    out += varint(9)
    out.append(4)
    out += varint(5)
    out += varint(6)
    out += varint(9)
    out.append(5)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_nested_table_read_inside_loop_chunk():
    strings = ["Particles", "next", "items"]
    words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_abc("NEWTABLE", 1, 0, 0),
        0,
        encode_abc("SETTABLEKS", 1, 0, 0),
        0,
        encode_abc("GETGLOBAL", 1, 0, 0),
        1,
        encode_abc("GETGLOBAL", 2, 0, 0),
        2,
        encode_abc("LOADNIL", 3, 0, 0),
        encode_ad("FORGPREP", 1, 3),
        encode_abc("GETTABLEKS", 5, 0, 0),
        0,
        encode_abc("SETTABLE", 4, 5, 4),
        encode_ad("FORGLOOP", 1, -4),
        2,
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(len(strings))
    for string_id in range(1, len(strings) + 1):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_loop_alias_mutated_table_dynamic_key_chunk():
    strings = ["items", "Name", "map", "_", "item", "alias"]
    words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_ad("LOADN", 3, 0),
        encode_ad("FORGPREP_INEXT", 1, 4),
        encode_abc("MOVE", 6, 0, 0),
        encode_abc("GETTABLEKS", 7, 5, 0),
        2,
        encode_abc("SETTABLE", 5, 6, 7),
        encode_ad("FORGLOOP", 1, -5),
        2,
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([8, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(4)
    out += varint(3)
    out += varint(2)
    out += varint(13)
    out.append(0)
    out += varint(4)
    out += varint(6)
    out += varint(10)
    out.append(4)
    out += varint(5)
    out += varint(6)
    out += varint(10)
    out.append(5)
    out += varint(6)
    out += varint(7)
    out += varint(10)
    out.append(6)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_numeric_loop_mutated_table_without_debug_locals_chunk():
    strings = ["last"]
    words = [
        encode_abc("NEWTABLE", 4, 0, 0),
        0,
        encode_ad("LOADN", 0, 3),
        encode_ad("LOADN", 1, 1),
        encode_ad("LOADN", 2, 1),
        encode_ad("FORNPREP", 0, 5),
        encode_abc("SETTABLE", 3, 4, 3),
        encode_abc("SETTABLEN", 3, 4, 0),
        encode_abc("SETTABLEKS", 3, 4, 0),
        0,
        encode_ad("FORNLOOP", 0, -5),
        encode_abc("RETURN", 4, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_numeric_loop_scalar_liveout_chunk():
    words = [
        encode_abc("LOADB", 0, 0, 0),
        encode_ad("LOADN", 1, 3),
        encode_ad("LOADN", 2, 1),
        encode_ad("LOADN", 3, 1),
        encode_ad("FORNPREP", 1, 2),
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("FORNLOOP", 1, -2),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_loop_table_insert_accumulator_chunk():
    strings = ["table", "insert", "print"]
    words = [
        encode_abc("NEWTABLE", 4, 0, 0),
        0,
        encode_ad("LOADN", 0, 3),
        encode_ad("LOADN", 1, 1),
        encode_ad("LOADN", 2, 1),
        encode_ad("FORNPREP", 0, 6),
        encode_ad("GETIMPORT", 5, 2),
        import_id(0, 1),
        encode_abc("MOVE", 6, 4, 0),
        encode_abc("MOVE", 7, 3, 0),
        encode_abc("CALL", 5, 3, 1),
        encode_ad("FORNLOOP", 0, -6),
        encode_abc("MOVE", 0, 4, 0),
        encode_abc("LOADNIL", 1, 0, 0),
        encode_abc("LOADNIL", 2, 0, 0),
        encode_ad("FORGPREP", 0, 4),
        encode_ad("GETIMPORT", 5, 3),
        import_id(2),
        encode_abc("MOVE", 6, 3, 0),
        encode_abc("CALL", 5, 2, 1),
        encode_ad("FORGLOOP", 0, -5),
        1,
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([8, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    for string_id in (1, 2, 3):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_generic_for_pairs_pending_table_literal_chunk():
    strings = ["a", "b", "c", "pairs", "print", "t", "k", "v"]
    words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_ad("LOADN", 1, 1),
        encode_abc("SETTABLEKS", 1, 0, 0),
        0,
        encode_ad("LOADN", 1, 2),
        encode_abc("SETTABLEKS", 1, 0, 0),
        1,
        encode_ad("LOADN", 1, 3),
        encode_abc("SETTABLEKS", 1, 0, 0),
        2,
        encode_ad("GETIMPORT", 1, 4),
        import_id(3),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 4),
        encode_ad("FORGPREP", 1, 5),
        encode_ad("GETIMPORT", 6, 6),
        import_id(5),
        encode_abc("MOVE", 7, 4, 0),
        encode_abc("MOVE", 8, 5, 0),
        encode_abc("CALL", 6, 3, 1),
        encode_ad("FORGLOOP", 1, -6),
        2,
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([9, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(7)
    for string_id in (1, 2, 3, 4):
        out.append(3)
        out += varint(string_id)
    out.append(4)
    out += struct.pack("<I", import_id(3))
    out.append(3)
    out += varint(5)
    out.append(4)
    out += struct.pack("<I", import_id(5))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(3)
    out += varint(6)
    out += varint(2)
    out += varint(24)
    out.append(0)
    out += varint(7)
    out += varint(16)
    out += varint(21)
    out.append(4)
    out += varint(8)
    out += varint(16)
    out += varint(21)
    out.append(5)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_inferred_require_module_local_chunk():
    strings = [
        "game",
        "ReplicatedStorage",
        "GetService",
        "require",
        "Packages",
        "GameAnalytics",
        "initClient",
        "setUserId",
        "maker",
    ]
    words = [
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_abc("NAMECALL", 1, 0, 0),
        3,
        encode_ad("LOADK", 3, 2),
        encode_abc("CALL", 1, 3, 2),
        encode_ad("GETIMPORT", 0, 10),
        import_id(4),
        encode_abc("GETTABLEKS", 1, 1, 0),
        5,
        encode_abc("GETTABLEKS", 1, 1, 0),
        6,
        encode_abc("CALL", 0, 2, 2),
        encode_abc("NAMECALL", 1, 0, 0),
        7,
        encode_abc("CALL", 1, 2, 1),
        encode_abc("NAMECALL", 1, 0, 0),
        8,
        encode_ad("LOADK", 3, 9),
        encode_abc("CALL", 1, 3, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(11)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    for string_id in range(2, 10):
        out.append(3)
        out += varint(string_id)
    out.append(4)
    out += struct.pack("<I", import_id(4))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_direct_service_property_require_module_local_chunk():
    strings = [
        "game",
        "ReplicatedStorage",
        "Packages",
        "GameAnalytics",
        "require",
        "initClient",
        "setUserId",
        "maker",
    ]
    words = [
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_abc("GETTABLEKS", 1, 0, 0),
        2,
        encode_abc("GETTABLEKS", 1, 1, 0),
        3,
        encode_abc("GETTABLEKS", 1, 1, 0),
        4,
        encode_ad("GETIMPORT", 0, 6),
        import_id(5),
        encode_abc("CALL", 0, 2, 2),
        encode_abc("NAMECALL", 1, 0, 0),
        7,
        encode_abc("CALL", 1, 2, 1),
        encode_abc("NAMECALL", 1, 0, 0),
        8,
        encode_ad("LOADK", 3, 9),
        encode_abc("CALL", 1, 3, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(10)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    for string_id in range(2, 6):
        out.append(3)
        out += varint(string_id)
    out.append(4)
    out += struct.pack("<I", import_id(4))
    for string_id in range(6, 9):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_inferred_roblox_character_locals_chunk():
    strings = [
        "game",
        "Players",
        "GetService",
        "LocalPlayer",
        "CharacterAdded",
        "Wait",
        "HumanoidRootPart",
        "WaitForChild",
    ]
    words = [
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_abc("NAMECALL", 1, 0, 0),
        3,
        encode_ad("LOADK", 3, 2),
        encode_abc("CALL", 1, 3, 2),
        encode_abc("GETTABLEKS", 2, 1, 0),
        4,
        encode_abc("GETTABLEKS", 3, 2, 0),
        5,
        encode_abc("NAMECALL", 3, 3, 0),
        6,
        encode_abc("CALL", 3, 2, 2),
        encode_abc("NAMECALL", 4, 3, 0),
        8,
        encode_ad("LOADK", 6, 7),
        encode_abc("CALL", 4, 3, 2),
        encode_abc("RETURN", 2, 4, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([7, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(9)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    for string_id in range(2, 9):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_return_or_call_value_chain_chunk():
    strings = ["compute", "cached"]
    words = [
        encode_ad("JUMPIF", 0, 3),
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_abc("CALL", 0, 1, 2),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([1, 1, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(2)
    out += varint(0)
    out += varint(5)
    out.append(0)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_return_or_call_with_arg_value_chain_chunk():
    strings = ["compute", "cached", "b"]
    words = [
        encode_ad("JUMPIF", 0, 3),
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_abc("CALL", 0, 2, 2),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([2, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    for name_id, reg_id in ((2, 0), (3, 1)):
        out += varint(name_id)
        out += varint(0)
        out += varint(5)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_or_or_value_chain_local_chunk():
    strings = ["a", "b", "c", "value"]
    words = [
        encode_abc("MOVE", 3, 0, 0),
        encode_ad("JUMPIF", 3, 3),
        encode_abc("MOVE", 3, 1, 0),
        encode_ad("JUMPIF", 3, 1),
        encode_abc("MOVE", 3, 2, 0),
        encode_abc("RETURN", 3, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(4)
    for name_id, reg_id in ((1, 0), (2, 1), (3, 2)):
        out += varint(name_id)
        out += varint(0)
        out += varint(6)
        out.append(reg_id)
    out += varint(4)
    out += varint(5)
    out += varint(6)
    out.append(3)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_or_call_middle_value_chain_local_chunk():
    strings = ["compute", "a", "b", "c", "value"]
    words = [
        encode_abc("MOVE", 3, 0, 0),
        encode_ad("JUMPIF", 3, 6),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_abc("MOVE", 4, 1, 0),
        encode_abc("CALL", 3, 2, 2),
        encode_ad("JUMPIF", 3, 1),
        encode_abc("MOVE", 3, 2, 0),
        encode_abc("RETURN", 3, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(4)
    for name_id, reg_id in ((2, 0), (3, 1), (4, 2)):
        out += varint(name_id)
        out += varint(0)
        out += varint(9)
        out.append(reg_id)
    out += varint(5)
    out += varint(8)
    out += varint(9)
    out.append(3)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_nested_or_value_join_branch_chunk():
    strings = ["flag", "other", "a", "b", "value"]
    words = [
        encode_ad("JUMPIFNOT", 0, 8),
        encode_ad("JUMPIFNOT", 1, 5),
        encode_abc("MOVE", 5, 2, 0),
        encode_ad("JUMPIF", 5, 1),
        encode_abc("MOVE", 5, 3, 0),
        encode_abc("MOVE", 4, 5, 0),
        encode_ad("JUMP", 0, 3),
        encode_abc("MOVE", 4, 2, 0),
        encode_ad("JUMP", 0, 1),
        encode_abc("MOVE", 4, 3, 0),
        encode_abc("RETURN", 4, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 4, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(5)
    for name_id, reg_id in ((1, 0), (2, 1), (3, 2), (4, 3)):
        out += varint(name_id)
        out += varint(0)
        out += varint(11)
        out.append(reg_id)
    out += varint(5)
    out += varint(5)
    out += varint(11)
    out.append(4)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_and_or_value_chain_local_chunk():
    strings = ["a", "b", "c", "value"]
    words = [
        encode_abc("MOVE", 3, 0, 0),
        encode_ad("JUMPIFNOT", 3, 1),
        encode_abc("MOVE", 3, 1, 0),
        encode_ad("JUMPIF", 3, 1),
        encode_abc("MOVE", 3, 2, 0),
        encode_abc("RETURN", 3, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(4)
    for name_id, reg_id in ((1, 0), (2, 1), (3, 2)):
        out += varint(name_id)
        out += varint(0)
        out += varint(6)
        out.append(reg_id)
    out += varint(4)
    out += varint(5)
    out += varint(6)
    out.append(3)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_and_value_chain_local_chunk():
    strings = ["a", "b", "value"]
    words = [
        encode_abc("MOVE", 2, 0, 0),
        encode_ad("JUMPIFNOT", 2, 1),
        encode_abc("MOVE", 2, 1, 0),
        encode_abc("RETURN", 2, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(3)
    for name_id, reg_id in ((1, 0), (2, 1)):
        out += varint(name_id)
        out += varint(0)
        out += varint(4)
        out.append(reg_id)
    out += varint(3)
    out += varint(3)
    out += varint(4)
    out.append(2)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_three_term_and_value_chain_local_chunk():
    strings = ["a", "b", "c", "value"]
    words = [
        encode_abc("MOVE", 3, 0, 0),
        encode_ad("JUMPIFNOT", 3, 3),
        encode_abc("MOVE", 3, 1, 0),
        encode_ad("JUMPIFNOT", 3, 1),
        encode_abc("MOVE", 3, 2, 0),
        encode_abc("RETURN", 3, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(4)
    for name_id, reg_id in ((1, 0), (2, 1), (3, 2)):
        out += varint(name_id)
        out += varint(0)
        out += varint(6)
        out.append(reg_id)
    out += varint(4)
    out += varint(3)
    out += varint(6)
    out.append(3)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_expression_receiver_field_chunk():
    strings = ["Name", "a", "b"]
    words = [
        encode_abc("MOVE", 2, 0, 0),
        encode_ad("JUMPIF", 2, 1),
        encode_abc("MOVE", 2, 1, 0),
        encode_abc("GETTABLEKS", 3, 2, 0),
        0,
        encode_abc("RETURN", 3, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    for name_id, reg_id in ((2, 0), (3, 1)):
        out += varint(name_id)
        out += varint(0)
        out += varint(6)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_expression_receiver_namecall_chunk():
    strings = ["FindFirstChild", "X", "a", "b"]
    words = [
        encode_abc("MOVE", 2, 0, 0),
        encode_ad("JUMPIF", 2, 1),
        encode_abc("MOVE", 2, 1, 0),
        encode_abc("NAMECALL", 3, 2, 0),
        0,
        encode_ad("LOADK", 5, 1),
        encode_abc("CALL", 3, 3, 2),
        encode_abc("RETURN", 3, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    for name_id, reg_id in ((3, 0), (4, 1)):
        out += varint(name_id)
        out += varint(0)
        out += varint(8)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_and_or_grouped_fallback_value_chain_local_chunk():
    strings = ["a", "b", "c", "d", "value"]
    words = [
        encode_abc("MOVE", 4, 0, 0),
        encode_ad("JUMPIFNOT", 4, 1),
        encode_abc("MOVE", 4, 1, 0),
        encode_ad("JUMPIF", 4, 3),
        encode_abc("MOVE", 4, 2, 0),
        encode_ad("JUMPIFNOT", 4, 1),
        encode_abc("MOVE", 4, 3, 0),
        encode_abc("RETURN", 4, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 4, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(5)
    for name_id, reg_id in ((1, 0), (2, 1), (3, 2), (4, 3)):
        out += varint(name_id)
        out += varint(0)
        out += varint(8)
        out.append(reg_id)
    out += varint(5)
    out += varint(7)
    out += varint(8)
    out.append(4)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_and_or_call_value_chain_local_chunk():
    strings = ["compute", "a", "b", "c", "value"]
    words = [
        encode_abc("MOVE", 3, 0, 0),
        encode_ad("JUMPIFNOT", 3, 4),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_abc("MOVE", 4, 1, 0),
        encode_abc("CALL", 3, 2, 2),
        encode_ad("JUMPIF", 3, 1),
        encode_abc("MOVE", 3, 2, 0),
        encode_abc("RETURN", 3, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(4)
    for name_id, reg_id in ((2, 0), (3, 1), (4, 2)):
        out += varint(name_id)
        out += varint(0)
        out += varint(9)
        out.append(reg_id)
    out += varint(5)
    out += varint(8)
    out += varint(9)
    out.append(3)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_and_or_fallback_call_value_chain_local_chunk():
    strings = ["compute", "a", "b", "c", "value"]
    words = [
        encode_abc("MOVE", 3, 0, 0),
        encode_ad("JUMPIFNOT", 3, 1),
        encode_abc("MOVE", 3, 1, 0),
        encode_ad("JUMPIF", 3, 4),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_abc("MOVE", 4, 2, 0),
        encode_abc("CALL", 3, 2, 2),
        encode_abc("RETURN", 3, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(4)
    for name_id, reg_id in ((2, 0), (3, 1), (4, 2)):
        out += varint(name_id)
        out += varint(0)
        out += varint(9)
        out.append(reg_id)
    out += varint(5)
    out += varint(8)
    out += varint(9)
    out.append(3)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_and_or_namecall_value_chain_local_chunk():
    strings = ["Compute", "a", "obj", "b", "c", "value"]
    words = [
        encode_abc("MOVE", 4, 0, 0),
        encode_ad("JUMPIFNOT", 4, 4),
        encode_abc("NAMECALL", 4, 1, 0),
        0,
        encode_abc("MOVE", 6, 2, 0),
        encode_abc("CALL", 4, 3, 2),
        encode_ad("JUMPIF", 4, 1),
        encode_abc("MOVE", 4, 3, 0),
        encode_abc("RETURN", 4, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([7, 4, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(5)
    for name_id, reg_id in ((2, 0), (3, 1), (4, 2), (5, 3)):
        out += varint(name_id)
        out += varint(0)
        out += varint(9)
        out.append(reg_id)
    out += varint(6)
    out += varint(8)
    out += varint(9)
    out.append(4)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_comparison_and_or_call_value_chain_local_chunk():
    strings = ["compute", "x", "y", "z", "c", "value"]
    words = [
        encode_ad("JUMPIFNOTLT", 0, 6),
        1,
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_abc("MOVE", 5, 2, 0),
        encode_abc("CALL", 4, 2, 2),
        encode_ad("JUMPIF", 4, 1),
        encode_abc("MOVE", 4, 3, 0),
        encode_abc("RETURN", 4, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 4, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(5)
    for name_id, reg_id in ((2, 0), (3, 1), (4, 2), (5, 3)):
        out += varint(name_id)
        out += varint(0)
        out += varint(9)
        out.append(reg_id)
    out += varint(6)
    out += varint(8)
    out += varint(9)
    out.append(4)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_if_call_chunk():
    strings = ["print", "yes"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIFNOT", 0, 4),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_ad("LOADK", 2, 2),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_if_else_call_chunk():
    strings = ["print", "yes", "no"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIFNOT", 0, 5),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_ad("LOADK", 2, 2),
        encode_abc("CALL", 1, 2, 1),
        encode_ad("JUMP", 0, 4),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_ad("LOADK", 2, 3),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_if_else_return_without_join_chunk():
    strings = ["yes", "no", "flag"]
    words = [
        encode_ad("JUMPIFNOT", 0, 2),
        encode_ad("LOADK", 1, 0),
        encode_abc("RETURN", 1, 2, 0),
        encode_ad("LOADK", 1, 1),
        encode_abc("RETURN", 1, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([2, 1, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    for string_id in (1, 2, 3):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(3)
    out += varint(0)
    out += varint(5)
    out.append(0)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_nested_if_else_return_chunk():
    strings = ["yes", "maybe", "no", "a", "b"]
    words = [
        encode_ad("JUMPIFNOT", 0, 5),
        encode_ad("JUMPIFNOT", 1, 2),
        encode_ad("LOADK", 2, 0),
        encode_abc("RETURN", 2, 2, 0),
        encode_ad("LOADK", 2, 1),
        encode_abc("RETURN", 2, 2, 0),
        encode_ad("LOADK", 2, 2),
        encode_abc("RETURN", 2, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(5)
    for string_id in (1, 2, 3, 4, 5):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    for name_id, reg_id in ((4, 0), (5, 1)):
        out += varint(name_id)
        out += varint(0)
        out += varint(8)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_table_literal_numeric_index_chunk():
    words = [
        encode_abc("NEWTABLE", 0, 1, 0),
        2,
        encode_ad("LOADN", 1, 1),
        encode_ad("LOADN", 2, 2),
        encode_abc("SETLIST", 0, 1, 3),
        1,
        encode_abc("GETTABLEN", 1, 0, 1),
        encode_abc("RETURN", 1, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_nonterminating_guard_ladder_chunk(depth=24):
    words = []
    for _ in range(depth):
        words.append(encode_ad("JUMPIFNOT", 0, 1))
        words.append(encode_abc("RETURN", 0, 1, 0))
    words.append(encode_ad("JUMP", 0, -((depth * 2) + 1)))

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(1)
    out += bytes([1, 1, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_long_straight_line_chunk(length=400):
    words = [encode_abc("NOP", 0, 0, 0) for _ in range(length)]
    words.append(encode_abc("RETURN", 0, 1, 0))

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(1)
    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_if_expression_local_chunk():
    strings = ["print", "result", "yes", "no"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIFNOT", 0, 2),
        encode_ad("LOADK", 1, 2),
        encode_ad("JUMP", 0, 1),
        encode_ad("LOADK", 1, 3),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_abc("MOVE", 3, 1, 0),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(3)
    out.append(3)
    out += varint(4)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(2)
    out += varint(5)
    out += varint(9)
    out.append(1)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_if_expression_condition_chunk():
    strings = ["print", "yes", "no"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIFNOT", 0, 2),
        encode_ad("LOADK", 1, 1),
        encode_ad("JUMP", 0, 1),
        encode_ad("LOADK", 1, 2),
        encode_ad("JUMPIFNOT", 1, 4),
        encode_ad("GETIMPORT", 2, 3),
        import_id(0),
        encode_abc("MOVE", 3, 1, 0),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_empty_else_branch_chunk():
    strings = ["print", "hit"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIFNOT", 0, 5),
        encode_ad("GETIMPORT", 1, 2),
        import_id(0),
        encode_ad("LOADK", 2, 1),
        encode_abc("CALL", 1, 2, 1),
        encode_ad("JUMP", 0, 1),
        encode_abc("NOP", 0, 0, 0),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_comparison_if_expression_local_chunk():
    strings = ["x", "y", "a", "b", "print", "result"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("GETGLOBAL", 1, 0, 0),
        1,
        encode_abc("GETGLOBAL", 2, 0, 0),
        2,
        encode_abc("GETGLOBAL", 3, 0, 0),
        3,
        encode_ad("JUMPIFNOTLT", 0, 3),
        1,
        encode_abc("MOVE", 4, 2, 0),
        encode_ad("JUMP", 0, 1),
        encode_abc("MOVE", 4, 3, 0),
        encode_ad("GETIMPORT", 5, 5),
        import_id(4),
        encode_abc("MOVE", 6, 4, 0),
        encode_abc("CALL", 5, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([7, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(6)
    for string_id in (1, 2, 3, 4, 5):
        out.append(3)
        out += varint(string_id)
    out.append(4)
    out += struct.pack("<I", import_id(4))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(6)
    out += varint(13)
    out += varint(18)
    out.append(4)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_if_expression_call_local_chunk():
    strings = ["compute", "fallback", "print", "flag", "a", "b", "result"]
    words = [
        encode_ad("JUMPIFNOT", 0, 5),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_abc("MOVE", 4, 1, 0),
        encode_abc("CALL", 3, 2, 2),
        encode_ad("JUMP", 0, 4),
        encode_ad("GETIMPORT", 3, 3),
        import_id(2),
        encode_abc("MOVE", 4, 2, 0),
        encode_abc("CALL", 3, 2, 2),
        encode_ad("GETIMPORT", 4, 5),
        import_id(4),
        encode_abc("MOVE", 5, 3, 0),
        encode_abc("CALL", 4, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(6)
    for string_id, import_constant in ((1, 0), (2, 2), (3, 4)):
        out.append(3)
        out += varint(string_id)
        out.append(4)
        out += struct.pack("<I", import_id(import_constant))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(4)
    for name_id, reg_id in ((4, 0), (5, 1), (6, 2)):
        out += varint(name_id)
        out += varint(0)
        out += varint(15)
        out.append(reg_id)
    out += varint(7)
    out += varint(10)
    out += varint(15)
    out.append(3)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_elseif_if_expression_local_chunk():
    strings = ["dead", "stunned", "active", "print", "result"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("GETGLOBAL", 1, 0, 0),
        1,
        encode_ad("JUMPIFNOT", 0, 2),
        encode_ad("LOADK", 2, 0),
        encode_ad("JUMP", 0, 4),
        encode_ad("JUMPIFNOT", 1, 2),
        encode_ad("LOADK", 2, 1),
        encode_ad("JUMP", 0, 1),
        encode_ad("LOADK", 2, 2),
        encode_ad("GETIMPORT", 3, 4),
        import_id(3),
        encode_abc("MOVE", 4, 2, 0),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(6)
    for string_id in range(1, 6):
        out.append(3)
        out += varint(string_id)
    out.append(4)
    out += struct.pack("<I", import_id(3))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(5)
    out += varint(11)
    out += varint(16)
    out.append(2)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_if_expression_return_chunk():
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIFNOT", 0, 2),
        encode_ad("LOADN", 1, 10),
        encode_ad("JUMP", 0, 1),
        encode_ad("LOADN", 1, 20),
        encode_abc("RETURN", 1, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(1)
    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_elseif_chain_chunk():
    strings = ["print", "first", "second", "third"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIFNOT", 0, 5),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_ad("LOADK", 2, 2),
        encode_abc("CALL", 1, 2, 1),
        encode_ad("JUMP", 0, 11),
        encode_abc("LOADB", 0, 0, 0),
        encode_ad("JUMPIFNOT", 0, 5),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_ad("LOADK", 2, 3),
        encode_abc("CALL", 1, 2, 1),
        encode_ad("JUMP", 0, 4),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_ad("LOADK", 2, 4),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(5)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    for string_id in (2, 3, 4):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_compound_elseif_and_chunk():
    strings = ["print", "first", "second", "third", "a", "b", "c"]
    words = [
        encode_ad("JUMPIFNOT", 0, 5),
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_ad("LOADK", 5, 2),
        encode_abc("CALL", 4, 2, 1),
        encode_ad("JUMP", 0, 11),
        encode_ad("JUMPIFNOT", 1, 6),
        encode_ad("JUMPIFNOT", 2, 5),
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_ad("LOADK", 5, 3),
        encode_abc("CALL", 4, 2, 1),
        encode_ad("JUMP", 0, 4),
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_ad("LOADK", 5, 4),
        encode_abc("CALL", 4, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(5)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    for string_id in (2, 3, 4):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(3)
    for name_id, reg_id in ((5, 0), (6, 1), (7, 2)):
        out += varint(name_id)
        out += varint(0)
        out += varint(18)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_short_circuit_and_if_chunk():
    strings = ["print", "hit"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIFNOT", 0, 6),
        encode_abc("LOADB", 1, 0, 0),
        encode_ad("JUMPIFNOT", 1, 4),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_ad("LOADK", 3, 2),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_short_circuit_and_if_else_chunk():
    strings = ["print", "yes", "no"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIFNOT", 0, 6),
        encode_abc("LOADB", 1, 0, 0),
        encode_ad("JUMPIFNOT", 1, 4),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_ad("LOADK", 3, 2),
        encode_abc("CALL", 2, 2, 1),
        encode_ad("JUMP", 0, 4),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_ad("LOADK", 3, 3),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_short_circuit_or_if_chunk():
    strings = ["print", "hit"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIF", 0, 2),
        encode_abc("LOADB", 1, 0, 0),
        encode_ad("JUMPIFNOT", 1, 4),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_ad("LOADK", 3, 2),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_short_circuit_or_branch_liveout_chunk():
    strings = ["initial", "changed", "print"]
    words = [
        encode_ad("LOADK", 2, 0),
        encode_ad("JUMPIF", 0, 1),
        encode_ad("JUMPIFNOT", 1, 1),
        encode_ad("LOADK", 2, 1),
        encode_ad("GETIMPORT", 3, 3),
        import_id(2),
        encode_abc("MOVE", 4, 2, 0),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out.append(4)
    out += struct.pack("<I", import_id(2))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_three_term_short_circuit_or_if_chunk():
    strings = ["print", "hit"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIF", 0, 4),
        encode_abc("LOADB", 1, 0, 0),
        encode_ad("JUMPIF", 1, 2),
        encode_abc("LOADB", 2, 1, 0),
        encode_ad("JUMPIFNOT", 2, 4),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_ad("LOADK", 4, 2),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_mixed_and_or_short_circuit_if_chunk():
    strings = ["print", "hit"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_abc("LOADB", 1, 0, 0),
        encode_abc("LOADB", 2, 1, 0),
        encode_ad("JUMPIFNOT", 0, 6),
        encode_ad("JUMPIF", 1, 1),
        encode_ad("JUMPIFNOT", 2, 4),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_ad("LOADK", 4, 2),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_mixed_or_and_short_circuit_if_chunk():
    strings = ["print", "hit"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_abc("LOADB", 1, 0, 0),
        encode_abc("LOADB", 2, 1, 0),
        encode_ad("JUMPIF", 0, 1),
        encode_ad("JUMPIFNOT", 1, 5),
        encode_ad("JUMPIFNOT", 2, 4),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_ad("LOADK", 4, 2),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_and_or_fallback_short_circuit_if_chunk():
    strings = ["print", "hit", "a", "b", "c"]
    words = [
        encode_ad("JUMPIFNOT", 0, 1),
        encode_ad("JUMPIF", 1, 1),
        encode_ad("JUMPIFNOT", 2, 4),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_ad("LOADK", 4, 2),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(3)
    for name_id, reg_id in ((3, 0), (4, 1), (5, 2)):
        out += varint(name_id)
        out += varint(0)
        out += varint(8)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_grouped_or_and_or_short_circuit_if_chunk():
    strings = ["print", "hit", "a", "b", "c", "d"]
    words = [
        encode_ad("JUMPIF", 0, 1),
        encode_ad("JUMPIFNOT", 1, 6),
        encode_ad("JUMPIF", 2, 1),
        encode_ad("JUMPIFNOT", 3, 4),
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_ad("LOADK", 5, 2),
        encode_abc("CALL", 4, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 4, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(4)
    for name_id, reg_id in ((3, 0), (4, 1), (5, 2), (6, 3)):
        out += varint(name_id)
        out += varint(0)
        out += varint(9)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_comparison_if_call_chunk():
    strings = ["print", "lt"]
    words = [
        encode_ad("LOADN", 0, 1),
        encode_ad("LOADN", 1, 2),
        encode_ad("JUMPIFNOTLT", 0, 5),
        1,
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_ad("LOADK", 3, 2),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_inner_compare_exits_parent_branch_chunk():
    strings = ["print", "inner", "else", "flag", "value", "limit"]
    words = [
        encode_ad("JUMPIFNOT", 0, 7),
        encode_ad("JUMPIFNOTLT", 1, 10),
        2,
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_ad("LOADK", 4, 2),
        encode_abc("CALL", 3, 2, 1),
        encode_ad("JUMP", 0, 4),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_ad("LOADK", 4, 3),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(3)
    for name_id, reg_id in ((4, 0), (5, 1), (6, 2)):
        out += varint(name_id)
        out += varint(0)
        out += varint(13)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_or_branch_inner_compare_exits_join_chunk():
    strings = ["print", "first", "else", "a", "b", "value", "limit"]
    words = [
        encode_ad("JUMPIF", 0, 1),
        encode_ad("JUMPIFNOT", 1, 7),
        encode_ad("JUMPIFNOTLT", 2, 10),
        3,
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_ad("LOADK", 5, 2),
        encode_abc("CALL", 4, 2, 1),
        encode_ad("JUMP", 0, 4),
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_ad("LOADK", 5, 3),
        encode_abc("CALL", 4, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 4, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(4)
    for name_id, reg_id in ((4, 0), (5, 1), (6, 2), (7, 3)):
        out += varint(name_id)
        out += varint(0)
        out += varint(14)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_call_guard_exits_parent_branch_chunk():
    strings = ["print", "FindFirstChild", "hit", "else", "flag", "target", "name"]
    words = [
        encode_ad("JUMPIFNOT", 0, 10),
        encode_abc("MOVE", 5, 2, 0),
        encode_abc("NAMECALL", 3, 1, 0),
        2,
        encode_abc("CALL", 3, 3, 2),
        encode_ad("JUMPIFNOT", 3, 9),
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_ad("LOADK", 5, 3),
        encode_abc("CALL", 4, 2, 1),
        encode_ad("JUMP", 0, 4),
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_ad("LOADK", 5, 4),
        encode_abc("CALL", 4, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(5)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out.append(3)
    out += varint(4)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(3)
    for name_id, reg_id in ((5, 0), (6, 1), (7, 2)):
        out += varint(name_id)
        out += varint(0)
        out += varint(16)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_and_call_guard_exits_parent_branch_chunk():
    strings = ["print", "FindFirstChild", "hit", "else", "flag", "ok", "target", "name"]
    words = [
        encode_ad("JUMPIFNOT", 0, 11),
        encode_ad("JUMPIFNOT", 1, 10),
        encode_abc("MOVE", 6, 3, 0),
        encode_abc("NAMECALL", 4, 2, 0),
        2,
        encode_abc("CALL", 4, 3, 2),
        encode_ad("JUMPIFNOT", 4, 9),
        encode_ad("GETIMPORT", 5, 1),
        import_id(0),
        encode_ad("LOADK", 6, 3),
        encode_abc("CALL", 5, 2, 1),
        encode_ad("JUMP", 0, 4),
        encode_ad("GETIMPORT", 5, 1),
        import_id(0),
        encode_ad("LOADK", 6, 4),
        encode_abc("CALL", 5, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([7, 4, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(5)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out.append(3)
    out += varint(4)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(4)
    for name_id, reg_id in ((5, 0), (6, 1), (7, 2), (8, 3)):
        out += varint(name_id)
        out += varint(0)
        out += varint(17)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_namecall_guard_reuses_result_chunk():
    strings = ["print", "FindFirstChild", "target", "name"]
    words = [
        encode_abc("MOVE", 4, 1, 0),
        encode_abc("NAMECALL", 2, 0, 0),
        2,
        encode_abc("CALL", 2, 3, 2),
        encode_ad("JUMPIFNOT", 2, 4),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_abc("MOVE", 4, 2, 0),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    for name_id, reg_id in ((3, 0), (4, 1)):
        out += varint(name_id)
        out += varint(0)
        out += varint(10)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_loop_exit_guard_chunk():
    strings = ["print", "body", "keep"]
    words = [
        encode_ad("LOADN", 0, 3),
        encode_ad("LOADN", 1, 1),
        encode_ad("LOADN", 2, 1),
        encode_ad("FORNPREP", 0, 6),
        encode_ad("JUMPIFNOT", 4, 5),
        encode_ad("GETIMPORT", 5, 1),
        import_id(0),
        encode_ad("LOADK", 6, 2),
        encode_abc("CALL", 5, 2, 1),
        encode_ad("FORNLOOP", 0, -6),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([7, 5, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(3)
    out += varint(0)
    out += varint(11)
    out.append(4)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_loop_exit_guard_merged_boolean_chunk():
    strings = ["print", "body", "keep", "use"]
    words = [
        encode_abc("LOADB", 4, 0, 0),
        encode_ad("JUMPIFNOT", 5, 2),
        encode_abc("LOADB", 4, 1, 0),
        encode_ad("LOADN", 0, 3),
        encode_ad("LOADN", 1, 1),
        encode_ad("LOADN", 2, 1),
        encode_ad("FORNPREP", 0, 6),
        encode_ad("JUMPIFNOT", 4, 5),
        encode_ad("GETIMPORT", 6, 1),
        import_id(0),
        encode_ad("LOADK", 7, 2),
        encode_abc("CALL", 6, 2, 1),
        encode_ad("FORNLOOP", 0, -6),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([8, 6, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    for name_id, reg_id in ((3, 4), (4, 5)):
        out += varint(name_id)
        out += varint(0)
        out += varint(14)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_return_guard_exits_parent_branch_chunk():
    strings = ["print", "run", "else", "mode", "done"]
    words = [
        encode_ad("JUMPIFNOT", 0, 6),
        encode_ad("JUMPIF", 1, 9),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_ad("LOADK", 3, 2),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_ad("LOADK", 3, 3),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    for name_id, reg_id in ((4, 0), (5, 1)):
        out += varint(name_id)
        out += varint(0)
        out += varint(12)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_contained_if_in_terminating_else_chunk():
    strings = ["print", "body", "after", "mode", "guard", "looped"]
    words = [
        encode_ad("JUMPIFNOT", 0, 1),
        encode_abc("RETURN", 0, 1, 0),
        encode_ad("JUMPIFNOT", 1, 6),
        encode_ad("JUMPIFNOT", 2, 1),
        encode_abc("RETURN", 0, 1, 0),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_ad("LOADK", 4, 2),
        encode_abc("CALL", 3, 2, 1),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_ad("LOADK", 4, 3),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(3)
    for name_id, reg_id in ((4, 0), (5, 1), (6, 2)):
        out += varint(name_id)
        out += varint(0)
        out += varint(14)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_short_circuit_before_contained_if_chunk():
    strings = ["print", "body", "after", "mode", "slot", "value", "guard", "looped", "idle"]
    words = [
        encode_ad("JUMPIFNOT", 0, 1),
        encode_abc("RETURN", 0, 1, 0),
        encode_ad("JUMPXEQKNIL", 1, 4),
        0,
        encode_ad("JUMPXEQKB", 1, 2),
        0x80000000,
        encode_ad("LOADK", 2, 9),
        encode_ad("JUMPIFNOT", 3, 7),
        encode_ad("JUMPIFNOT", 4, 1),
        encode_abc("RETURN", 0, 1, 0),
        encode_ad("LOADK", 2, 9),
        encode_ad("GETIMPORT", 5, 1),
        import_id(0),
        encode_ad("LOADK", 6, 2),
        encode_abc("CALL", 5, 2, 1),
        encode_ad("GETIMPORT", 5, 1),
        import_id(0),
        encode_ad("LOADK", 6, 3),
        encode_abc("CALL", 5, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([7, 5, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(6)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out.append(1)
    out.append(2)
    out.append(3)
    out += varint(9)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(5)
    for name_id, reg_id in ((4, 0), (5, 1), (6, 2), (7, 3), (8, 4)):
        out += varint(name_id)
        out += varint(0)
        out += varint(20)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_short_circuit_branch_assignment_used_after_chunk():
    strings = ["print", "idle"]
    words = [
        encode_abc("MOVE", 2, 0, 0),
        encode_ad("JUMPXEQKNIL", 1, 4),
        0,
        encode_ad("JUMPXEQKB", 1, 2),
        0x80000000,
        encode_ad("LOADK", 2, 2),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_abc("MOVE", 4, 2, 0),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_short_circuit_branch_assignment_before_conditional_overwrite_chunk():
    strings = ["print", "idle", "fallback"]
    words = [
        encode_abc("MOVE", 3, 0, 0),
        encode_ad("JUMPXEQKNIL", 1, 4),
        0,
        encode_ad("JUMPXEQKB", 1, 2),
        0x80000000,
        encode_ad("LOADK", 3, 2),
        encode_ad("JUMPIFNOT", 2, 1),
        encode_ad("LOADK", 3, 3),
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_abc("MOVE", 5, 3, 0),
        encode_abc("CALL", 4, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_conditional_value_with_guarded_fallback_chunk():
    strings = ["print"]
    words = [
        encode_ad("JUMPIFNOT", 0, 4),
        encode_abc("GETUPVAL", 4, 0, 0),
        encode_abc("DIV", 3, 4, 2),
        encode_ad("JUMPIF", 3, 1),
        encode_ad("LOADK", 3, 2),
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_abc("MOVE", 5, 3, 0),
        encode_abc("CALL", 4, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 3, 1, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(9)
    out.append(0)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_branch_table_literal_assignment_used_after_chunk():
    strings = ["print"]
    words = [
        encode_abc("MOVE", 2, 0, 0),
        encode_ad("JUMPIF", 2, 2),
        encode_abc("NEWTABLE", 2, 0, 0),
        0,
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_abc("MOVE", 4, 2, 0),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 1, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_branch_assignment_captured_by_closure_chunk():
    strings = ["outer"]
    main_words = [
        encode_abc("LOADNIL", 2, 0, 0),
        encode_ad("JUMPIFNOT", 0, 1),
        encode_ad("LOADK", 2, 0),
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("CAPTURE", 0, 2, 0),
        encode_abc("RETURN", 1, 2, 0),
    ]
    child_words = [
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([3, 1, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(1)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += bytes([1, 0, 1, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(0)
    out += varint(1)
    out += varint(1)

    out += varint(0)
    return bytes(out)


def make_or_fallback_import_assignment_chunk():
    strings = ["print", "Enum", "Fallback"]
    words = [
        encode_abc("MOVE", 1, 0, 0),
        encode_ad("JUMPIF", 1, 2),
        encode_ad("GETIMPORT", 1, 2),
        import_id(1, 2),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_abc("MOVE", 3, 1, 0),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 1, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_branch_table_alias_reassigns_parameter_chunk():
    strings = ["print"]
    words = [
        encode_ad("JUMPIFNOT", 1, 6),
        encode_abc("NEWTABLE", 2, 0, 0),
        1,
        encode_abc("MOVE", 3, 0, 0),
        encode_abc("SETLIST", 2, 3, 2),
        1,
        encode_abc("MOVE", 0, 2, 0),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_abc("MOVE", 3, 0, 0),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_guarded_or_with_truthy_fallback_chunk():
    strings = ["value", "default", "sentinel", "type", "boolean", "out"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("GETGLOBAL", 1, 0, 0),
        1,
        encode_abc("GETGLOBAL", 2, 0, 0),
        2,
        encode_ad("JUMPIFEQ", 0, 15),
        2,
        encode_abc("FASTCALL1", 40, 0, 3),
        encode_abc("MOVE", 4, 0, 0),
        encode_ad("GETIMPORT", 3, 4),
        import_id(3),
        encode_abc("CALL", 3, 2, 2),
        encode_ad("JUMPXEQKS", 3, 12),
        0x80000000 | 5,
        encode_abc("FASTCALL1", 40, 1, 3),
        encode_abc("MOVE", 4, 1, 0),
        encode_ad("GETIMPORT", 3, 4),
        import_id(3),
        encode_abc("CALL", 3, 2, 2),
        encode_ad("JUMPXEQKS", 3, 5),
        5,
        encode_ad("JUMPIFNOT", 0, 5),
        encode_abc("MOVE", 0, 2, 0),
        encode_ad("JUMP", 0, 1),
        encode_ad("JUMP", 0, 2),
        encode_abc("SETGLOBAL", 0, 0, 0),
        6,
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(7)
    for string_id in (1, 2, 3, 4):
        out.append(3)
        out += varint(string_id)
    out.append(4)
    out += struct.pack("<I", import_id(3))
    for string_id in (5, 6):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_constant_comparison_if_call_chunk():
    strings = ["print", "ready", "ok", "status"]
    words = [
        encode_ad("LOADK", 0, 2),
        encode_ad("JUMPXEQKS", 0, 5),
        0x80000000 | 2,
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_ad("LOADK", 2, 3),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(4)
    out += varint(1)
    out += varint(7)
    out.append(0)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_constant_comparison_or_if_call_chunk():
    strings = ["print", "ready", "queued", "ok", "status"]
    words = [
        encode_ad("LOADK", 0, 2),
        encode_ad("JUMPXEQKS", 0, 3),
        2,
        encode_ad("JUMPXEQKS", 0, 5),
        0x80000000 | 3,
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_ad("LOADK", 2, 4),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(5)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out.append(3)
    out += varint(4)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(5)
    out += varint(1)
    out += varint(10)
    out.append(0)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_constant_comparison_exits_bounded_branch_chunk():
    strings = ["boolean", "number", "out", "value", "default"]
    words = [
        encode_ad("JUMPIFEQ", 0, 7),
        1,
        encode_ad("LOADK", 2, 1),
        encode_ad("JUMPXEQKS", 2, 5),
        0x80000000 | 1,
        encode_ad("LOADK", 2, 2),
        encode_ad("JUMPXEQKS", 2, 2),
        1,
        encode_ad("LOADK", 0, 1),
        encode_abc("SETGLOBAL", 0, 0, 0),
        3,
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    for string_id in (1, 2, 3):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    for name_id, reg_id in ((4, 0), (5, 1)):
        out += varint(name_id)
        out += varint(0)
        out += varint(12)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_upvalue_setup_short_circuit_and_if_chunk():
    strings = ["print", "hit", "FreeFall"]
    words = [
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_ad("JUMPXEQKS", 0, 9),
        0x80000000 | 3,
        encode_abc("GETUPVAL", 1, 1, 0),
        encode_ad("LOADN", 2, 0),
        encode_ad("JUMPIFNOTLE", 1, 5),
        2,
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_ad("LOADK", 4, 2),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 2, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_upvalue_setup_short_circuit_and_elseif_chunk():
    strings = ["print", "fall", "FreeFall", "sit", "Seated"]
    words = [
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_ad("JUMPXEQKS", 0, 10),
        0x80000000 | 3,
        encode_abc("GETUPVAL", 1, 1, 0),
        encode_ad("LOADN", 2, 0),
        encode_ad("JUMPIFNOTLE", 1, 6),
        2,
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_ad("LOADK", 4, 2),
        encode_abc("CALL", 3, 2, 1),
        encode_ad("JUMP", 0, 7),
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_ad("JUMPXEQKS", 0, 5),
        0x80000000 | 5,
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_ad("LOADK", 4, 4),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 2, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(6)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    for string_id in (2, 3, 4, 5):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_register_compare_preserves_condition_setup_chunk():
    words = [
        encode_abc("GETUPVAL", 5, 0, 0),
        encode_ad("LOADN", 6, 0),
        encode_ad("JUMPIFNOTLT", 6, 4),
        5,
        encode_abc("GETUPVAL", 6, 0, 0),
        encode_abc("SUB", 5, 6, 0),
        encode_abc("SETUPVAL", 5, 0, 0),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(1)
    out += bytes([7, 1, 1, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_register_compare_or_return_guard_chunk():
    strings = ["now", "available", "cached"]
    words = [
        encode_ad("JUMPIFEQ", 2, 3),
        1,
        encode_ad("JUMPIFNOTLT", 1, 2),
        0,
        encode_abc("RETURN", 0, 1, 0),
        encode_abc("RETURN", 1, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(3)
    for name_id, reg_id in ((1, 0), (2, 1), (3, 2)):
        out += varint(name_id)
        out += varint(0)
        out += varint(6)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_comparison_boolean_value_chunk():
    strings = ["print", "flag"]
    words = [
        encode_ad("LOADN", 0, 1),
        encode_ad("LOADN", 1, 2),
        encode_ad("JUMPIFNOTLT", 0, 2),
        1,
        encode_abc("LOADB", 2, 1, 1),
        encode_abc("LOADB", 2, 0, 0),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_abc("MOVE", 4, 2, 0),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(2)
    out += varint(6)
    out += varint(10)
    out.append(2)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_negated_comparison_boolean_value_chunk():
    strings = ["print", "flag"]
    words = [
        encode_ad("LOADN", 0, 1),
        encode_ad("LOADN", 1, 2),
        encode_ad("JUMPIFNOTLT", 0, 2),
        1,
        encode_abc("LOADB", 2, 0, 1),
        encode_abc("LOADB", 2, 1, 0),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_abc("MOVE", 4, 2, 0),
        encode_abc("CALL", 3, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(2)
    out += varint(6)
    out += varint(10)
    out.append(2)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_loadb_skip_call_chunk():
    strings = ["print"]
    words = [
        encode_abc("LOADB", 0, 1, 1),
        encode_abc("LOADB", 0, 0, 0),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_jump_skip_call_chunk():
    strings = ["print", "live", "dead"]
    words = [
        encode_ad("LOADK", 0, 1),
        encode_ad("JUMP", 0, 1),
        encode_ad("LOADK", 0, 2),
        encode_ad("GETIMPORT", 1, 3),
        import_id(0),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_while_call_chunk():
    strings = ["print", "tick"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIFNOT", 0, 5),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_ad("LOADK", 2, 2),
        encode_abc("CALL", 1, 2, 1),
        encode_ad("JUMPBACK", 0, -6),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_while_stripped_loop_carried_value_chunk():
    words = [
        encode_ad("LOADN", 0, 1),
        encode_ad("LOADN", 1, 3),
        encode_ad("LOADN", 2, 1),
        encode_ad("JUMPIFNOTLT", 0, 3),
        1,
        encode_abc("ADD", 0, 0, 2),
        encode_ad("JUMPBACK", 0, -4),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_while_condition_setup_uses_loop_carried_value_chunk():
    words = [
        encode_ad("LOADN", 1, 1),
        encode_ad("LOADN", 4, 1),
        encode_abc("GETTABLE", 2, 0, 1),
        encode_ad("LOADN", 3, 10),
        encode_ad("JUMPIFNOTLT", 2, 3),
        3,
        encode_abc("ADD", 1, 1, 4),
        encode_ad("JUMPBACK", 0, -6),
        encode_abc("RETURN", 1, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(1)
    out += bytes([5, 1, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_while_compound_guard_chunk():
    strings = ["tick", "a", "b"]
    words = [
        encode_ad("JUMPIFNOT", 0, 5),
        encode_ad("JUMPIFNOT", 1, 4),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_abc("CALL", 2, 1, 1),
        encode_ad("JUMPBACK", 0, -6),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    for name_id, reg_id in ((2, 0), (3, 1)):
        out += varint(name_id)
        out += varint(0)
        out += varint(6)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_while_or_guard_chunk():
    strings = ["tick", "a", "b"]
    words = [
        encode_ad("JUMPIF", 0, 1),
        encode_ad("JUMPIFNOT", 1, 4),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_abc("CALL", 2, 1, 1),
        encode_ad("JUMPBACK", 0, -6),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    for name_id, reg_id in ((2, 0), (3, 1)):
        out += varint(name_id)
        out += varint(0)
        out += varint(7)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_while_three_term_or_guard_chunk():
    strings = ["tick", "a", "b", "c"]
    words = [
        encode_ad("JUMPIF", 0, 2),
        encode_ad("JUMPIF", 1, 1),
        encode_ad("JUMPIFNOT", 2, 4),
        encode_ad("GETIMPORT", 3, 1),
        import_id(0),
        encode_abc("CALL", 3, 1, 1),
        encode_ad("JUMPBACK", 0, -7),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 3, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(3)
    for name_id, reg_id in ((2, 0), (3, 1), (4, 2)):
        out += varint(name_id)
        out += varint(0)
        out += varint(8)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_while_grouped_or_and_or_guard_chunk():
    strings = ["tick", "a", "b", "c", "d"]
    words = [
        encode_ad("JUMPIF", 0, 1),
        encode_ad("JUMPIFNOT", 1, 6),
        encode_ad("JUMPIF", 2, 1),
        encode_ad("JUMPIFNOT", 3, 4),
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_abc("CALL", 4, 1, 1),
        encode_ad("JUMPBACK", 0, -8),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 4, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(4)
    for name_id, reg_id in ((2, 0), (3, 1), (4, 2), (5, 3)):
        out += varint(name_id)
        out += varint(0)
        out += varint(9)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_while_break_chunk():
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIFNOT", 0, 2),
        encode_ad("JUMP", 0, 1),
        encode_ad("JUMPBACK", 0, -3),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(1)
    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_while_continue_chunk():
    strings = ["print", "top"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIFNOT", 0, 6),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_ad("LOADK", 2, 2),
        encode_abc("CALL", 1, 2, 1),
        encode_ad("JUMPBACK", 0, -6),
        encode_ad("JUMPBACK", 0, -7),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_while_conditional_continue_chunk():
    strings = ["print", "tick", "skip"]
    words = [
        encode_abc("LOADB", 0, 1, 0),
        encode_ad("JUMPIFNOT", 0, 7),
        encode_ad("JUMPIFNOT", 1, 1),
        encode_ad("JUMPBACK", 0, -4),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_ad("LOADK", 3, 2),
        encode_abc("CALL", 2, 2, 1),
        encode_ad("JUMPBACK", 0, -9),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(3)
    out += varint(0)
    out += varint(10)
    out.append(1)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_repeat_call_chunk():
    strings = ["print", "tick"]
    words = [
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_ad("LOADK", 2, 2),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("LOADB", 0, 0, 0),
        encode_ad("JUMPIFNOT", 0, -6),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_repeat_forward_exit_call_chunk():
    strings = ["tick", "flag"]
    words = [
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_abc("CALL", 1, 1, 1),
        encode_ad("JUMPIF", 0, 1),
        encode_ad("JUMPBACK", 0, -5),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([2, 1, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(2)
    out += varint(0)
    out += varint(6)
    out.append(0)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_repeat_and_condition_chunk():
    strings = ["tick", "a", "b"]
    words = [
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_abc("CALL", 2, 1, 1),
        encode_ad("JUMPIFNOT", 0, -4),
        encode_ad("JUMPIFNOT", 1, -5),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    for name_id, reg_id in ((2, 0), (3, 1)):
        out += varint(name_id)
        out += varint(0)
        out += varint(6)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_repeat_or_condition_chunk():
    strings = ["tick", "a", "b"]
    words = [
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_abc("CALL", 2, 1, 1),
        encode_ad("JUMPIF", 0, 1),
        encode_ad("JUMPIFNOT", 1, -5),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    for name_id, reg_id in ((2, 0), (3, 1)):
        out += varint(name_id)
        out += varint(0)
        out += varint(6)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_repeat_break_preserves_body_order_chunk():
    strings = ["step", "x"]
    words = [
        encode_ad("LOADN", 0, 0),
        encode_abc("ADDK", 0, 0, 2),
        encode_ad("LOADN", 1, 5),
        encode_ad("JUMPIFNOTEQ", 0, 2),
        1,
        encode_ad("JUMP", 0, 7),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_ad("LOADN", 2, 10),
        encode_ad("JUMPIFLT", 0, -11),
        2,
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(9)
    out.append(0)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(2)
    out += varint(1)
    out += varint(14)
    out.append(0)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_numeric_for_call_chunk():
    strings = ["print"]
    words = [
        encode_ad("LOADN", 0, 3),
        encode_ad("LOADN", 1, 1),
        encode_ad("LOADN", 2, 1),
        encode_ad("FORNPREP", 0, 5),
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_abc("MOVE", 5, 3, 0),
        encode_abc("CALL", 4, 2, 1),
        encode_ad("FORNLOOP", 0, -5),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_numeric_for_named_call_chunk():
    strings = ["print", "i"]
    words = [
        encode_ad("LOADN", 0, 3),
        encode_ad("LOADN", 1, 1),
        encode_ad("LOADN", 2, 1),
        encode_ad("FORNPREP", 0, 5),
        encode_ad("GETIMPORT", 4, 1),
        import_id(0),
        encode_abc("MOVE", 5, 3, 0),
        encode_abc("CALL", 4, 2, 1),
        encode_ad("FORNLOOP", 0, -5),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(2)
    out += varint(4)
    out += varint(8)
    out.append(3)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_numeric_for_inferred_local_shadow_chunk():
    strings = ["make", "print"]
    words = [
        encode_ad("LOADN", 0, 2),
        encode_ad("LOADN", 1, 1),
        encode_ad("LOADN", 2, 1),
        encode_ad("FORNPREP", 0, 9),
        encode_ad("GETIMPORT", 3, 2),
        import_id(0),
        encode_abc("CALL", 3, 1, 2),
        encode_ad("GETIMPORT", 4, 3),
        import_id(1),
        encode_abc("MOVE", 5, 3, 0),
        encode_abc("MOVE", 6, 3, 0),
        encode_abc("CALL", 4, 3, 1),
        encode_ad("FORNLOOP", 0, -9),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([7, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(4)
    out += struct.pack("<I", import_id(1))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_generic_for_named_call_chunk():
    strings = ["next", "items", "print", "key", "value", "state"]
    words = [
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_ad("GETIMPORT", 1, 3),
        import_id(2),
        encode_abc("LOADNIL", 2, 0, 0),
        encode_ad("FORGPREP", 0, 5),
        encode_ad("GETIMPORT", 5, 5),
        import_id(4),
        encode_abc("MOVE", 6, 3, 0),
        encode_abc("MOVE", 7, 4, 0),
        encode_abc("CALL", 5, 3, 1),
        encode_ad("FORGLOOP", 0, -6),
        2,
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([8, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(6)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(4)
    out += struct.pack("<I", import_id(1))
    out.append(3)
    out += varint(3)
    out.append(4)
    out += struct.pack("<I", import_id(2))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(3)
    out += varint(6)
    out += varint(5)
    out += varint(11)
    out.append(2)
    out += varint(4)
    out += varint(6)
    out += varint(11)
    out.append(3)
    out += varint(5)
    out += varint(6)
    out += varint(11)
    out.append(4)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_generic_for_call_iterator_chunk():
    strings = ["ipairs", "items", "print", "_", "child"]
    words = [
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_ad("GETIMPORT", 1, 3),
        import_id(2),
        encode_abc("CALL", 0, 2, 4),
        encode_ad("FORGPREP", 0, 4),
        encode_ad("GETIMPORT", 5, 5),
        import_id(4),
        encode_abc("MOVE", 6, 4, 0),
        encode_abc("CALL", 5, 2, 1),
        encode_ad("FORGLOOP", 0, -5),
        2,
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([7, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(6)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(4)
    out += struct.pack("<I", import_id(2))
    out.append(3)
    out += varint(3)
    out.append(4)
    out += struct.pack("<I", import_id(4))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    out += varint(4)
    out += varint(6)
    out += varint(10)
    out.append(3)
    out += varint(5)
    out += varint(6)
    out += varint(10)
    out.append(4)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_generic_for_inext_fastpath_chunk():
    strings = ["items", "print", "_", "child"]
    words = [
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_ad("LOADN", 2, 0),
        encode_ad("FORGPREP_INEXT", 0, 4),
        encode_ad("GETIMPORT", 5, 3),
        import_id(2),
        encode_abc("MOVE", 6, 4, 0),
        encode_abc("CALL", 5, 2, 1),
        encode_ad("FORGLOOP", 0, -5),
        2,
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([7, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(4)
    out += struct.pack("<I", import_id(1))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    out += varint(3)
    out += varint(4)
    out += varint(8)
    out.append(3)
    out += varint(4)
    out += varint(4)
    out += varint(8)
    out.append(4)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_generic_for_next_fastpath_chunk():
    strings = ["items", "print", "key", "value"]
    words = [
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_abc("LOADNIL", 2, 0, 0),
        encode_ad("FORGPREP_NEXT", 0, 5),
        encode_ad("GETIMPORT", 5, 3),
        import_id(2),
        encode_abc("MOVE", 6, 3, 0),
        encode_abc("MOVE", 7, 4, 0),
        encode_abc("CALL", 5, 3, 1),
        encode_ad("FORGLOOP", 0, -6),
        2,
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([8, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(4)
    out += struct.pack("<I", import_id(1))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    out += varint(3)
    out += varint(4)
    out += varint(9)
    out.append(3)
    out += varint(4)
    out += varint(4)
    out += varint(9)
    out.append(4)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_child_closure_chunk():
    strings = ["value"]
    main_words = [
        encode_ad("NEWCLOSURE", 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]
    child_words = [
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += bytes([1, 1, 0, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(1)
    out.append(0)
    out += varint(0)

    out += varint(0)
    return bytes(out)


def make_captured_upvalue_closure_chunk():
    strings = ["outer", "x"]
    main_words = [
        encode_ad("LOADK", 0, 0),
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("CAPTURE", 0, 0, 0),
        encode_abc("RETURN", 1, 2, 0),
    ]
    child_words = [
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(1)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += bytes([1, 0, 1, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(0)
    out += varint(1)
    out += varint(2)

    out += varint(0)
    return bytes(out)


def make_inferred_captured_upvalue_name_chunk():
    strings = ["outer", "x"]
    main_words = [
        encode_ad("LOADK", 0, 0),
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("CAPTURE", 0, 0, 0),
        encode_abc("RETURN", 1, 2, 0),
    ]
    child_words = [
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(1)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(2)
    out += varint(1)
    out += varint(4)
    out.append(0)
    out += varint(0)

    out += bytes([1, 0, 1, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(0)
    out += varint(0)

    out += varint(0)
    return bytes(out)


def make_mutual_forward_recursive_closures_chunk():
    strings = ["even", "odd"]
    main_words = [
        encode_abc("LOADNIL", 0, 0, 0),
        encode_abc("LOADNIL", 1, 0, 0),
        encode_ad("NEWCLOSURE", 0, 0),
        encode_abc("CAPTURE", 1, 1, 0),
        encode_ad("NEWCLOSURE", 1, 1),
        encode_abc("CAPTURE", 1, 0, 0),
        encode_abc("RETURN", 0, 3, 0),
    ]
    child_words = [
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(3)

    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(2)
    out += varint(1)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    out += varint(1)
    out += varint(1)
    out += varint(7)
    out.append(0)
    out += varint(2)
    out += varint(2)
    out += varint(7)
    out.append(1)
    out += varint(0)

    for _ in range(2):
        out += bytes([1, 0, 1, 0, 0])
        out += varint(0)
        out += varint(len(child_words))
        for word in child_words:
            out += struct.pack("<I", word)
        out += varint(0)
        out += varint(0)
        out += varint(0)
        out += varint(0)
        out.append(0)
        out.append(0)

    out += varint(0)
    return bytes(out)


def make_dupclosure_captured_expression_chunk():
    strings = ["script", "Parent"]
    main_words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("GETTABLEKS", 0, 0, 0),
        1,
        encode_ad("DUPCLOSURE", 1, 2),
        encode_abc("CAPTURE", 0, 0, 0),
        encode_abc("RETURN", 1, 2, 0),
    ]
    child_words = [
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out.append(6)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += bytes([1, 0, 1, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += varint(0)
    return bytes(out)


def make_stripped_ref_capture_mutation_chunk():
    main_words = [
        encode_ad("LOADN", 0, 0),
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("CAPTURE", 1, 0, 0),
        encode_ad("LOADN", 0, 1),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("RETURN", 1, 3, 0),
    ]
    child_words = [
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(2)

    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += bytes([1, 0, 1, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += varint(0)
    return bytes(out)


def make_stripped_val_and_ref_capture_identity_chunk():
    main_words = [
        encode_ad("LOADN", 0, 0),
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("CAPTURE", 0, 0, 0),
        encode_ad("NEWCLOSURE", 2, 1),
        encode_abc("CAPTURE", 1, 0, 0),
        encode_ad("LOADN", 0, 1),
        encode_abc("RETURN", 1, 3, 0),
    ]
    child_words = [
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(3)

    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(2)
    out += varint(1)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    for _ in range(2):
        out += bytes([1, 0, 1, 0, 0])
        out += varint(0)
        out += varint(len(child_words))
        for word in child_words:
            out += struct.pack("<I", word)
        out += varint(0)
        out += varint(0)
        out += varint(0)
        out += varint(0)
        out.append(0)
        out.append(0)

    out += varint(0)
    return bytes(out)


def make_stripped_ref_and_val_capture_identity_chunk():
    main_words = [
        encode_ad("LOADN", 0, 0),
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("CAPTURE", 1, 0, 0),
        encode_ad("NEWCLOSURE", 2, 1),
        encode_abc("CAPTURE", 0, 0, 0),
        encode_ad("LOADN", 0, 1),
        encode_abc("RETURN", 1, 3, 0),
    ]
    child_words = [
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(3)

    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(2)
    out += varint(1)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    for _ in range(2):
        out += bytes([1, 0, 1, 0, 0])
        out += varint(0)
        out += varint(len(child_words))
        for word in child_words:
            out += struct.pack("<I", word)
        out += varint(0)
        out += varint(0)
        out += varint(0)
        out += varint(0)
        out.append(0)
        out.append(0)

    out += varint(0)
    return bytes(out)


def make_stripped_shared_val_capture_identity_chunk():
    main_words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("CAPTURE", 0, 0, 0),
        encode_ad("NEWCLOSURE", 2, 1),
        encode_abc("CAPTURE", 0, 0, 0),
        encode_abc("RETURN", 1, 3, 0),
    ]
    child_words = [
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(3)

    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(2)
    out += varint(1)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    for _ in range(2):
        out += bytes([1, 0, 1, 0, 0])
        out += varint(0)
        out += varint(len(child_words))
        for word in child_words:
            out += struct.pack("<I", word)
        out += varint(0)
        out += varint(0)
        out += varint(0)
        out += varint(0)
        out.append(0)
        out.append(0)

    out += varint(0)
    return bytes(out)


def make_nested_generated_capture_name_collision_chunk():
    main_words = [
        encode_ad("LOADN", 0, 1),
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("CAPTURE", 0, 0, 0),
        encode_abc("RETURN", 1, 2, 0),
    ]
    child_words = [
        encode_ad("LOADN", 0, 0),
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("CAPTURE", 0, 0, 0),
        encode_abc("GETUPVAL", 2, 0, 0),
        encode_abc("RETURN", 1, 3, 0),
    ]
    nested_words = [
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(3)

    protos = [
        (bytes([2, 0, 0, 0, 0]), main_words, [1]),
        (bytes([3, 0, 1, 0, 0]), child_words, [2]),
        (bytes([1, 0, 1, 0, 0]), nested_words, []),
    ]
    for header, words, children in protos:
        out += header
        out += varint(0)
        out += varint(len(words))
        for word in words:
            out += struct.pack("<I", word)
        out += varint(0)
        out += varint(len(children))
        for child_id in children:
            out += varint(child_id)
        out += varint(0)
        out += varint(0)
        out.append(0)
        out.append(0)

    out += varint(0)
    return bytes(out)


def make_setupvalue_chunk():
    strings = ["ready", "state"]
    words = [
        encode_ad("LOADK", 0, 0),
        encode_abc("SETUPVAL", 0, 0, 0),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([1, 0, 1, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(0)
    out += varint(1)
    out += varint(2)
    out += varint(0)
    return bytes(out)


def make_setupvalue_preserves_loaded_snapshot_chunk():
    strings = ["state"]
    words = [
        encode_abc("GETUPVAL", 0, 0, 0),
        encode_ad("LOADN", 1, 0),
        encode_abc("SETUPVAL", 1, 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([2, 0, 1, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(0)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    return bytes(out)


def make_named_local_function_call_chunk():
    strings = ["helper", "ok"]
    main_words = [
        encode_ad("NEWCLOSURE", 0, 0),
        encode_abc("CALL", 0, 1, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]
    child_words = [
        encode_ad("LOADK", 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(3)
    out.append(0)
    out += varint(0)

    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += varint(0)
    return bytes(out)


def make_child_debugname_reused_function_chunk():
    strings = ["helper", "ok"]
    main_words = [
        encode_ad("NEWCLOSURE", 0, 0),
        encode_abc("MOVE", 1, 0, 0),
        encode_abc("CALL", 1, 1, 1),
        encode_abc("MOVE", 1, 0, 0),
        encode_abc("CALL", 1, 1, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]
    child_words = [
        encode_ad("LOADK", 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(1)
    out.append(0)
    out.append(0)

    out += varint(0)
    return bytes(out)


def make_immediate_closure_call_chunk():
    strings = ["ok"]
    main_words = [
        encode_ad("NEWCLOSURE", 0, 0),
        encode_abc("CALL", 0, 1, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]
    child_words = [
        encode_ad("LOADK", 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += varint(0)
    return bytes(out)


def make_namecall_with_closure_and_value_args_chunk():
    strings = ["Remote", "FireServer", "ok", "tag"]
    main_words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("NAMECALL", 1, 0, 0),
        1,
        encode_ad("NEWCLOSURE", 3, 0),
        encode_ad("LOADK", 4, 3),
        encode_abc("CALL", 1, 4, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]
    child_words = [
        encode_ad("LOADK", 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([5, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(4)
    for string_id in range(1, 5):
        out.append(3)
        out += varint(string_id)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += varint(0)
    return bytes(out)


def make_reused_invokeserver_result_chunk():
    strings = ["GetInventory", "InvokeServer", "print"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("NAMECALL", 1, 0, 0),
        1,
        encode_abc("CALL", 1, 2, 2),
        encode_ad("GETIMPORT", 2, 3),
        import_id(2),
        encode_abc("MOVE", 3, 1, 0),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 1, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out.append(3)
    out += varint(3)
    out.append(4)
    out += struct.pack("<I", import_id(2))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_reused_call_result_chunk():
    strings = ["compute", "print"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("CALL", 0, 1, 2),
        encode_ad("GETIMPORT", 1, 2),
        import_id(1),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out.append(4)
    out += struct.pack("<I", import_id(1))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_reused_call_result_through_move_chunk():
    strings = ["compute", "print"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("CALL", 0, 1, 2),
        encode_abc("MOVE", 1, 0, 0),
        encode_ad("GETIMPORT", 2, 2),
        import_id(1),
        encode_abc("MOVE", 3, 1, 0),
        encode_abc("MOVE", 4, 1, 0),
        encode_abc("CALL", 2, 3, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out.append(4)
    out += struct.pack("<I", import_id(1))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_delayed_single_call_result_chunk():
    strings = ["clock", "wait"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("CALL", 0, 1, 2),
        encode_abc("GETGLOBAL", 1, 0, 0),
        1,
        encode_abc("CALL", 1, 1, 1),
        encode_abc("GETGLOBAL", 1, 0, 0),
        0,
        encode_abc("CALL", 1, 1, 2),
        encode_abc("SUB", 2, 1, 0),
        encode_abc("RETURN", 2, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    for string_id in range(1, 3):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_reused_binary_result_chunk():
    strings = ["print"]
    words = [
        encode_abc("SUB", 2, 0, 1),
        encode_abc("GETGLOBAL", 3, 0, 0),
        0,
        encode_abc("MOVE", 4, 2, 0),
        encode_abc("MOVE", 5, 2, 0),
        encode_abc("CALL", 3, 3, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_loop_property_snapshot_chunk():
    strings = ["workspace", "CurrentCamera", "Position", "next", "items", "print"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("GETTABLEKS", 1, 0, 0),
        1,
        encode_abc("GETTABLEKS", 1, 1, 0),
        2,
        encode_abc("GETGLOBAL", 2, 0, 0),
        3,
        encode_abc("GETGLOBAL", 3, 0, 0),
        4,
        encode_abc("LOADNIL", 4, 0, 0),
        encode_ad("FORGPREP", 2, 4),
        encode_abc("GETGLOBAL", 7, 0, 0),
        5,
        encode_abc("MOVE", 8, 1, 0),
        encode_abc("CALL", 7, 2, 1),
        encode_ad("FORGLOOP", 2, -5),
        2,
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([9, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(len(strings))
    for string_id in range(1, len(strings) + 1):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_branch_condition_reused_register_chunk():
    strings = ["Texture", "IsA", "Parent", "BasePart", "print"]
    words = [
        encode_ad("LOADK", 3, 0),
        encode_abc("NAMECALL", 1, 0, 0),
        1,
        encode_abc("CALL", 1, 3, 2),
        encode_ad("JUMPIF", 1, 1),
        encode_abc("RETURN", 0, 1, 0),
        encode_abc("GETTABLEKS", 1, 0, 0),
        2,
        encode_ad("JUMPIFNOT", 1, 5),
        encode_ad("LOADK", 4, 3),
        encode_abc("NAMECALL", 2, 1, 0),
        1,
        encode_abc("CALL", 2, 3, 2),
        encode_ad("JUMPIF", 2, 1),
        encode_abc("RETURN", 0, 1, 0),
        encode_abc("GETGLOBAL", 2, 0, 0),
        4,
        encode_abc("MOVE", 3, 1, 0),
        encode_abc("CALL", 2, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 1, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(len(strings))
    for string_id in range(1, len(strings) + 1):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_short_circuit_indexed_guard_chunk():
    strings = ["Particles", "print"]
    words = [
        encode_ad("JUMPIFNOT", 0, 9),
        encode_abc("GETTABLE", 2, 1, 0),
        encode_ad("JUMPIFNOT", 2, 7),
        encode_abc("GETTABLEKS", 2, 2, 0),
        0,
        encode_abc("GETTABLE", 2, 2, 0),
        encode_ad("JUMPIFNOT", 2, 3),
        encode_abc("GETGLOBAL", 3, 0, 0),
        1,
        encode_abc("CALL", 3, 1, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([4, 2, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(len(strings))
    for string_id in range(1, len(strings) + 1):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_child_parameter_capture_collision_chunk():
    main_words = [
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("CAPTURE", 0, 0, 0),
        encode_abc("RETURN", 1, 2, 0),
    ]
    child_words = [
        encode_abc("GETUPVAL", 1, 0, 0),
        encode_abc("GETTABLE", 1, 1, 0),
        encode_abc("RETURN", 1, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(2)

    out += bytes([2, 1, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += bytes([2, 1, 1, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += varint(0)
    return bytes(out)


def make_expression_callee_call_chunk():
    strings = ["f", "g"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_abc("GETGLOBAL", 1, 0, 0),
        1,
        encode_abc("OR", 2, 0, 1),
        encode_abc("CALL", 2, 1, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_class_member_method_chunk():
    strings = ["Widget", "render", "ok"]
    main_words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("NEWCLASSMEMBER", 0, 0, 1),
        1,
        encode_abc("RETURN", 0, 1, 0),
    ]
    child_words = [
        encode_ad("LOADK", 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += varint(0)
    return bytes(out)


def make_global_function_assignment_chunk():
    strings = ["helper", "ok"]
    main_words = [
        encode_ad("NEWCLOSURE", 0, 0),
        encode_abc("SETGLOBAL", 0, 0, 0),
        0,
        encode_abc("RETURN", 0, 1, 0),
    ]
    child_words = [
        encode_ad("LOADK", 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(1)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += varint(0)
    return bytes(out)


def make_table_method_assignment_chunk():
    strings = ["Widget", "render", "ok"]
    main_words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("SETTABLEKS", 1, 0, 0),
        0,
        encode_abc("RETURN", 0, 1, 0),
    ]
    child_words = [
        encode_ad("LOADK", 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(1)
    out += varint(2)
    out += varint(6)
    out.append(0)
    out += varint(0)

    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += varint(0)
    return bytes(out)


def make_table_literal_key_method_assignment_chunk():
    strings = ["Widget", "render", "ok"]
    main_words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_ad("LOADK", 2, 0),
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("SETTABLE", 1, 0, 2),
        encode_abc("RETURN", 0, 1, 0),
    ]
    child_words = [
        encode_ad("LOADK", 0, 0),
        encode_abc("RETURN", 0, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(1)
    out += varint(2)
    out += varint(6)
    out.append(0)
    out += varint(0)

    out += bytes([1, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)

    out += varint(0)
    return bytes(out)


def make_table_colon_method_assignment_chunk():
    strings = ["Widget", "render", "ok", "self"]
    main_words = [
        encode_abc("NEWTABLE", 0, 0, 0),
        0,
        encode_ad("NEWCLOSURE", 1, 0),
        encode_abc("SETTABLEKS", 1, 0, 0),
        0,
        encode_abc("RETURN", 0, 1, 0),
    ]
    child_words = [
        encode_ad("LOADK", 1, 0),
        encode_abc("RETURN", 1, 2, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(2)

    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(main_words))
    for word in main_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(2)
    out += varint(1)
    out += varint(1)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(1)
    out += varint(2)
    out += varint(6)
    out.append(0)
    out += varint(0)

    out += bytes([2, 1, 0, 0, 0])
    out += varint(0)
    out += varint(len(child_words))
    for word in child_words:
        out += struct.pack("<I", word)
    out += varint(1)
    out.append(3)
    out += varint(3)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(4)
    out += varint(0)
    out += varint(2)
    out.append(0)
    out += varint(0)

    out += varint(0)
    return bytes(out)


def make_named_local_value_call_chunk():
    strings = ["print", "hi", "message"]
    words = [
        encode_ad("LOADK", 0, 2),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(3)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(3)
    out += varint(1)
    out += varint(5)
    out.append(0)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_vararg_return_chunk():
    words = [
        encode_abc("PREPVARARGS", 0, 0, 0),
        encode_abc("GETVARARGS", 0, 0, 0),
        encode_abc("RETURN", 0, 0, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table([])
    out.append(0)
    out += varint(1)
    out += bytes([1, 0, 0, 1, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_named_fixed_vararg_call_chunk():
    strings = ["print", "first"]
    words = [
        encode_abc("PREPVARARGS", 0, 0, 0),
        encode_abc("GETVARARGS", 0, 2, 0),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 1, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(1)
    out += varint(2)
    out += varint(2)
    out += varint(7)
    out.append(0)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_named_multi_vararg_call_chunk():
    strings = ["print", "first", "second"]
    words = [
        encode_abc("PREPVARARGS", 0, 0, 0),
        encode_abc("GETVARARGS", 0, 3, 0),
        encode_ad("GETIMPORT", 2, 1),
        import_id(0),
        encode_abc("MOVE", 3, 0, 0),
        encode_abc("MOVE", 4, 1, 0),
        encode_abc("CALL", 2, 3, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 0, 1, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    out += varint(2)
    out += varint(2)
    out += varint(8)
    out.append(0)
    out += varint(3)
    out += varint(2)
    out += varint(8)
    out.append(1)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_named_multi_return_call_chunk():
    strings = ["provider", "print", "first", "second"]
    words = [
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_abc("CALL", 0, 1, 3),
        encode_ad("GETIMPORT", 2, 3),
        import_id(2),
        encode_abc("MOVE", 3, 0, 0),
        encode_abc("MOVE", 4, 1, 0),
        encode_abc("CALL", 2, 3, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(4)
    out += struct.pack("<I", import_id(2))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    out += varint(3)
    out += varint(3)
    out += varint(8)
    out.append(0)
    out += varint(4)
    out += varint(3)
    out += varint(8)
    out.append(1)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_existing_local_multi_return_reassign_chunk():
    strings = ["provider", "first", "second"]
    words = [
        encode_ad("LOADN", 0, 0),
        encode_ad("LOADN", 1, 0),
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_abc("CALL", 0, 1, 3),
        encode_abc("RETURN", 0, 3, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([2, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(2)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(1)
    out += varint(2)
    for name_id, reg_id in ((2, 0), (3, 1)):
        out += varint(name_id)
        out += varint(0)
        out += varint(6)
        out.append(reg_id)
    out += varint(0)
    out += varint(0)
    return bytes(out)


def make_anonymous_multi_return_call_chunk():
    strings = ["provider", "print"]
    words = [
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_abc("CALL", 0, 1, 3),
        encode_ad("GETIMPORT", 2, 3),
        import_id(2),
        encode_abc("MOVE", 3, 0, 0),
        encode_abc("MOVE", 4, 1, 0),
        encode_abc("CALL", 2, 3, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([5, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(4)
    out += struct.pack("<I", import_id(1))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_overlapping_multi_return_call_chunk():
    strings = ["provider", "print"]
    words = [
        encode_ad("GETIMPORT", 0, 1),
        import_id(0),
        encode_abc("CALL", 0, 1, 3),
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_abc("CALL", 1, 1, 3),
        encode_ad("GETIMPORT", 3, 3),
        import_id(2),
        encode_abc("MOVE", 4, 1, 0),
        encode_abc("MOVE", 5, 2, 0),
        encode_abc("CALL", 3, 3, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([6, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(4)
    out += struct.pack("<I", import_id(1))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_short_circuit_call_guard_else_chunk():
    strings = ["flag", "sound", "AudioPlayer", "IsA", "Play", "Playing"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_ad("JUMPIFNOT", 0, 13),
        encode_abc("GETGLOBAL", 0, 0, 0),
        1,
        encode_ad("LOADK", 2, 2),
        encode_abc("NAMECALL", 0, 0, 0),
        3,
        encode_abc("CALL", 0, 3, 2),
        encode_ad("JUMPIFNOT", 0, 6),
        encode_abc("GETGLOBAL", 0, 0, 0),
        1,
        encode_abc("NAMECALL", 0, 0, 0),
        4,
        encode_abc("CALL", 0, 2, 1),
        encode_ad("JUMP", 0, 5),
        encode_abc("GETGLOBAL", 0, 0, 0),
        1,
        encode_abc("LOADB", 1, 1, 0),
        encode_abc("SETTABLEKS", 1, 0, 0),
        5,
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(6)
    for string_id in range(1, 7):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_short_circuit_or_call_guard_chunk():
    strings = ["sound", "TextLabel", "TextButton", "IsA", "TextColor3"]
    words = [
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_ad("LOADK", 2, 1),
        encode_abc("NAMECALL", 0, 0, 0),
        3,
        encode_abc("CALL", 0, 3, 2),
        encode_ad("JUMPIF", 0, 7),
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_ad("LOADK", 2, 2),
        encode_abc("NAMECALL", 0, 0, 0),
        3,
        encode_abc("CALL", 0, 3, 2),
        encode_ad("JUMPIFNOT", 0, 5),
        encode_abc("GETGLOBAL", 0, 0, 0),
        0,
        encode_ad("LOADN", 1, 1),
        encode_abc("SETTABLEKS", 1, 0, 0),
        4,
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(5)
    for string_id in range(1, 6):
        out.append(3)
        out += varint(string_id)
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


def make_table_open_call_chunk():
    strings = ["provider", "print"]
    words = [
        encode_abc("NEWTABLE", 0, 1, 0),
        1,
        encode_ad("GETIMPORT", 1, 1),
        import_id(0),
        encode_abc("CALL", 1, 1, 0),
        encode_abc("SETLIST", 0, 1, 0),
        1,
        encode_ad("GETIMPORT", 1, 3),
        import_id(2),
        encode_abc("MOVE", 2, 0, 0),
        encode_abc("CALL", 1, 2, 1),
        encode_abc("RETURN", 0, 1, 0),
    ]

    out = bytearray()
    out.append(4)
    out.append(3)
    out += string_table(strings)
    out.append(0)
    out += varint(1)
    out += bytes([3, 0, 0, 0, 0])
    out += varint(0)
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(4)
    out.append(3)
    out += varint(1)
    out.append(4)
    out += struct.pack("<I", import_id(0))
    out.append(3)
    out += varint(2)
    out.append(4)
    out += struct.pack("<I", import_id(1))
    out += varint(0)
    out += varint(0)
    out += varint(0)
    out.append(0)
    out.append(0)
    out += varint(0)
    return bytes(out)


class ChunkTests(unittest.TestCase):
    def test_handcrafted_chunks_have_no_trailing_bytes(self):
        for name, value in sorted(globals().items()):
            if name.startswith("make_") and name.endswith("_chunk"):
                with self.subTest(name=name):
                    chunk = parse_chunk(value())
                    self.assertEqual(chunk.trailing, b"")

    def test_parse_serialized_luau_chunk(self):
        chunk = parse_chunk(make_namecall_chunk())

        self.assertEqual(chunk.version, 4)
        self.assertEqual(chunk.type_version, 3)
        self.assertEqual(chunk.main_proto, 0)
        self.assertEqual(chunk.strings, ["game", "FireServer"])
        self.assertEqual(chunk.protos[0].constants[0].value, "game")
        self.assertEqual(chunk.protos[0].constants[1].kind, "import")
        self.assertEqual(chunk.protos[0].instructions[0].op.name, "GETIMPORT")

    def test_decompile_loadk_vector_constant(self):
        chunk = parse_chunk(make_vector_return_chunk())

        self.assertEqual(chunk.protos[0].constants[0].kind, "vector")
        self.assertEqual(chunk.protos[0].constants[0].value, (1.0, 2.5, -3.0, 0.0))

        source = decompile_chunk(chunk)

        self.assertIn("return vector.create(1.0, 2.5, -3.0)", source)
        self.assertNotIn("--[[vector:", source)

    def test_decompile_namecall_skeleton(self):
        chunk = parse_chunk(make_namecall_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("game:FireServer()", source)
        self.assertEqual(source.splitlines()[-1], "game:FireServer()")

    def test_decompile_import_path_uses_brackets_for_non_identifier_segment(self):
        chunk = parse_chunk(make_non_identifier_import_path_chunk())

        source = decompile_chunk(chunk)

        self.assertEqual(source.splitlines()[-1], 'return game["Folder-Name"]')
        self.assertNotIn("game.Folder-Name", source)

    def test_decompile_identifier_string_key_uses_dotted_field(self):
        chunk = parse_chunk(make_identifier_string_key_field_chunk())

        source = decompile_chunk(chunk)

        self.assertEqual(source.splitlines()[-1], "return ReplicatedStorage.Packages")
        self.assertNotIn('ReplicatedStorage["Packages"]', source)

    def test_parse_class_shape_member_counts_before_member_ids(self):
        chunk = parse_chunk(make_class_shape_chunk())
        value = chunk.protos[0].constants[4].value

        self.assertEqual(value["class_name"], 0)
        self.assertEqual(value["properties"], [1, 2])
        self.assertEqual(value["methods"], [3])

    def test_decompile_arithmetic_argument_expression(self):
        chunk = parse_chunk(make_arithmetic_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("print(40 + 2)", source)
        self.assertNotIn("ADDK", source)

    def test_decompile_debug_named_local_reassignment(self):
        chunk = parse_chunk(make_local_reassignment_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local count = 1\ncount = count + 1\nprint(count)", source)
        self.assertNotIn("print(count + 1)", source)

    def test_decompile_shadowed_same_register_local_redeclares(self):
        chunk = parse_chunk(make_shadowed_local_same_register_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local value = "outer"\nprint(value)\nlocal value = "inner"\nprint(value)', source)
        self.assertEqual(source.count("local value ="), 2)
        self.assertNotIn('\nvalue = "inner"', source)

    def test_decompile_omits_fastcall_hint_before_fallback_call(self):
        chunk = parse_chunk(make_fastcall_fallback_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('assert("ok")', source)
        self.assertEqual(source.splitlines()[-1], 'assert("ok")')
        self.assertNotIn("FASTCALL", source)

    def test_decompile_emits_unused_single_call_result(self):
        chunk = parse_chunk(make_unused_single_call_result_chunk())

        source = decompile_chunk(chunk)

        self.assertEqual(source.splitlines()[-1], "initialize()")

    def test_decompile_call_result_written_to_global_is_not_dropped(self):
        chunk = parse_chunk(make_call_result_global_assignment_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("result = compute()", source)
        self.assertEqual(source.count("compute()"), 1)

    def test_decompile_fastcall_preserves_open_arguments(self):
        chunk = parse_chunk(make_fastcall_open_argument_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('consume("first", producer())', source)
        self.assertNotIn("consume()", source)

    def test_decompile_failed_loop_probe_preserves_call_condition(self):
        chunk = parse_chunk(make_failed_loop_probe_preserves_call_condition_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("if not p0:IsDescendantOf(p2) then", source)
        self.assertNotIn("if not p1 then", source)

    def test_decompile_omits_closeupvals_lifetime_marker(self):
        chunk = parse_chunk(make_closeupvals_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('print("ok")', source)
        self.assertNotIn("CLOSEUPVALS", source)

    def test_decompile_omits_coverage_instrumentation_marker(self):
        chunk = parse_chunk(make_coverage_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('print("ok")', source)
        self.assertNotIn("COVERAGE", source)

    def test_decompile_omits_nativecall_runtime_dispatch_marker(self):
        chunk = parse_chunk(make_nativecall_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('print("ok")', source)
        self.assertNotIn("NATIVECALL", source)

    def test_decompile_omits_noop_cmpproto_guard_marker(self):
        chunk = parse_chunk(make_cmpproto_noop_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('print("ok")', source)
        self.assertNotIn("CMPPROTO", source)

    def test_decompile_global_call(self):
        chunk = parse_chunk(make_global_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('print("hi")', source)
        self.assertNotIn("GETGLOBAL", source)

    def test_decompile_debug_named_field_read_local(self):
        chunk = parse_chunk(make_debug_named_field_read_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local item = profile.name\nprint(item)", source)
        self.assertNotIn("print(profile.name)", source)

    def test_decompile_global_assignment(self):
        chunk = parse_chunk(make_global_assign_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('nickname = "maker"', source)
        self.assertNotIn("SETGLOBAL", source)

    def test_decompile_udata_field_read(self):
        chunk = parse_chunk(make_udata_field_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("print(obj.Name)", source)
        self.assertNotIn("GETUDATAKS", source)

    def test_decompile_udata_field_assignment(self):
        chunk = parse_chunk(make_udata_field_assign_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('obj.Name = "maker"', source)
        self.assertNotIn("SETUDATAKS", source)

    def test_decompile_udata_namecall_uses_low_16_aux_key(self):
        chunk = parse_chunk(make_udata_namecall_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('obj:FireServer("hi")', source)
        self.assertNotIn("NAMECALLUDATA", source)
        self.assertNotIn("K720897", source)

    def test_decompile_expression_receiver_field_groups_target(self):
        chunk = parse_chunk(make_expression_receiver_field_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("return (a or b).Name", source)
        self.assertNotIn("return a or b.Name", source)

    def test_decompile_expression_receiver_namecall_groups_target(self):
        chunk = parse_chunk(make_expression_receiver_namecall_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('return (a or b):FindFirstChild("X")', source)
        self.assertNotIn('a or b:FindFirstChild("X")', source)

    def test_decompile_mixed_table_argument_expression(self):
        chunk = parse_chunk(make_table_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('print({1, 2, name = "maker"})', source)
        self.assertNotIn("NEWTABLE", source)
        self.assertNotIn("SETLIST", source)
        self.assertNotIn("SETTABLEKS", source)

    def test_decompile_groups_table_literal_numeric_index_receiver(self):
        chunk = parse_chunk(make_table_literal_numeric_index_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("return ({1, 2})[2]", source)
        self.assertNotIn("return {1, 2}[2]", source)

    def test_decompile_table_literal_preserves_side_effect_write_order(self):
        chunk = parse_chunk(make_table_side_effect_array_order_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("return {[2] = f(), g()}", source)
        self.assertLess(source.index("f()"), source.index("g()"))
        self.assertNotIn("return {g(), [2] = f()}", source)

    def test_decompile_anonymous_table_read_twice_materializes_identity(self):
        chunk = parse_chunk(make_anonymous_table_read_twice_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local r0 = {name = "maker"}\nprint(r0)\nreturn r0', source)
        self.assertNotIn('print({name = "maker"})', source)
        self.assertNotIn('return {name = "maker"}', source)

    def test_decompile_duptable_template_constants(self):
        chunk = parse_chunk(make_duptable_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('print({enabled = true, name = "maker"})', source)
        self.assertNotIn("DUPTABLE", source)

    def test_decompile_duptable_template_patch_replaces_default(self):
        chunk = parse_chunk(make_duptable_patch_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("print({name = 0, score = 99})", source)
        self.assertNotIn("score = 0, score = 99", source)

    def test_decompile_table_alias_patch_updates_original_literal(self):
        chunk = parse_chunk(make_table_alias_patch_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('print({name = "maker"})', source)
        self.assertNotIn("{}.name", source)
        self.assertNotIn("print({})", source)

    def test_decompile_stripped_table_alias_read_twice_materializes_identity(self):
        chunk = parse_chunk(make_stripped_table_alias_read_twice_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local r0 = {name = "maker"}\nprint(r0)\nreturn r0', source)
        self.assertNotIn('print({name = "maker"})', source)
        self.assertNotIn('return {name = "maker"}', source)

    def test_decompile_debug_named_table_alias_preserves_identity(self):
        chunk = parse_chunk(make_debug_named_table_alias_patch_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local t = {}\nlocal alias = t\nalias.name = "maker"\nprint(t)', source)
        self.assertNotIn("local alias = {}", source)
        self.assertNotIn("print({})", source)

    def test_decompile_debug_named_table_literal_waits_for_constructor_fields(self):
        chunk = parse_chunk(make_debug_named_table_literal_return_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local Config = {name = "maker"}\nreturn Config', source)
        self.assertNotIn("local Config = {}\nConfig.name", source)

    def test_decompile_branch_mutated_table_config_materializes_before_if(self):
        chunk = parse_chunk(make_branch_mutated_table_config_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'local Config = {retry = 2}\n'
            'Config.endpoint = if flag then "dev" else "prod"\n'
            "return Config",
            source,
        )
        self.assertNotIn("if flag then\n", source)
        self.assertNotIn('return {retry = 2}', source)

    def test_decompile_loop_mutated_table_materializes_before_loop(self):
        chunk = parse_chunk(make_loop_mutated_table_dynamic_key_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local out = {}\n"
            "for _, child in ipairs(items) do\n"
            "    out[child.Name] = child\n"
            "end\n"
            "return out",
            source,
        )
        self.assertNotIn("return {}", source)

    def test_decompile_loop_alias_mutated_table_materializes_before_loop(self):
        chunk = parse_chunk(make_loop_alias_mutated_table_dynamic_key_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local map = {}\n"
            "for _, item in ipairs(items) do\n"
            "    local alias = map\n"
            "    alias[item.Name] = item\n"
            "end\n"
            "return map",
            source,
        )
        self.assertNotIn("return {}", source)

    def test_decompile_nested_table_read_materializes_before_loop(self):
        chunk = parse_chunk(make_nested_table_read_inside_loop_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local r0 = {Particles = {}}", source)
        self.assertIn("r0.Particles[r4] = r4", source)
        self.assertLess(source.index("local r0 ="), source.index("for r4"))
        self.assertEqual(source.count("{Particles = {}}"), 1)

    def test_decompile_no_debug_loop_mutated_table_materializes_fallback_local(self):
        chunk = parse_chunk(make_numeric_loop_mutated_table_without_debug_locals_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local r4 = {}\n"
            "for r3 = 1, 3, 1 do\n"
            "    r4[r3] = r3\n"
            "    r4[1] = r3\n"
            "    r4.last = r3\n"
            "end\n"
            "return r4",
            source,
        )
        self.assertNotIn("return {}", source)

    def test_decompile_loop_scalar_liveout_materializes_before_loop(self):
        chunk = parse_chunk(make_numeric_loop_scalar_liveout_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local r0 = false\n"
            "for r4 = 1, 3, 1 do\n"
            "    r0 = true\n"
            "end\n"
            "return r0",
            source,
        )
        self.assertNotIn("return true", source)

    def test_decompile_loop_table_insert_accumulator_materializes_before_loop(self):
        chunk = parse_chunk(make_loop_table_insert_accumulator_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local r4 = {}\n"
            "for r3 = 1, 3, 1 do\n"
            "    table.insert(r4, r3)\n"
            "end\n"
            "for r3 in r4 do\n"
            "    print(r3)\n"
            "end",
            source,
        )
        self.assertNotIn("for r3 in {} do", source)

    def test_decompile_infers_require_module_local_from_terminal_path(self):
        chunk = parse_chunk(make_inferred_require_module_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'local GameAnalytics = require(ReplicatedStorage.Packages.GameAnalytics)\n'
            "GameAnalytics:initClient()\n"
            'GameAnalytics:setUserId("maker")',
            source,
        )
        self.assertIn('local ReplicatedStorage: ReplicatedStorage = game:GetService("ReplicatedStorage")', source)
        self.assertNotIn("require(ReplicatedStorage.Packages.GameAnalytics):", source)

    def test_decompile_direct_service_property_gets_service_local(self):
        chunk = parse_chunk(make_direct_service_property_require_module_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local ReplicatedStorage = game.ReplicatedStorage\n"
            "local GameAnalytics = require(ReplicatedStorage.Packages.GameAnalytics)\n"
            "GameAnalytics:initClient()\n"
            'GameAnalytics:setUserId("maker")',
            source,
        )
        self.assertNotIn("require(game.ReplicatedStorage", source)

    def test_decompile_infers_roblox_character_locals(self):
        chunk = parse_chunk(make_inferred_roblox_character_locals_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'local Players: Players = game:GetService("Players")\n'
            "local LocalPlayer = Players.LocalPlayer\n"
            "local Character = LocalPlayer.CharacterAdded:Wait()\n"
            'local HumanoidRootPart = Character:WaitForChild("HumanoidRootPart")\n'
            "return LocalPlayer, Character, HumanoidRootPart",
            source,
        )
        self.assertNotIn("Players.LocalPlayer.CharacterAdded:Wait():WaitForChild", source)

    def test_decompile_return_or_call_value_chain(self):
        chunk = parse_chunk(make_return_or_call_value_chain_chunk())

        source = decompile_chunk(chunk)

        self.assertEqual(source.splitlines()[-1], "return cached or compute()")
        self.assertNotIn("if not cached then", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_return_or_call_with_arg_value_chain(self):
        chunk = parse_chunk(make_return_or_call_with_arg_value_chain_chunk())

        source = decompile_chunk(chunk)

        self.assertEqual(source.splitlines()[-1], "return cached or compute(b)")
        self.assertNotIn("if not cached then", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_or_or_value_chain_local(self):
        chunk = parse_chunk(make_or_or_value_chain_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local value = a or b or c\nreturn value", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_or_call_middle_value_chain_local(self):
        chunk = parse_chunk(make_or_call_middle_value_chain_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local value = a or compute(b) or c\nreturn value", source)
        self.assertNotIn("if not a then", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_nested_or_value_join_branch(self):
        chunk = parse_chunk(make_nested_or_value_join_branch_chunk())

        source = decompile_chunk(chunk)

        self.assertNotIn("-- pc 6: 0006 JUMP", source)
        self.assertIn("return value", source)

    def test_decompile_and_or_value_chain_local(self):
        chunk = parse_chunk(make_and_or_value_chain_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local value = a and b or c\nreturn value", source)
        self.assertNotIn("if a then", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_and_value_chain_local(self):
        chunk = parse_chunk(make_and_value_chain_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local value = a and b\nreturn value", source)
        self.assertNotIn("if a then", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_three_term_and_value_chain(self):
        chunk = parse_chunk(make_three_term_and_value_chain_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local value = a and b and c\nreturn value", source)
        self.assertNotIn("if a then", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_and_or_grouped_fallback_value_chain_local(self):
        chunk = parse_chunk(make_and_or_grouped_fallback_value_chain_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local value = a and b or (c and d)\nreturn value", source)
        self.assertNotIn("if a then", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_and_or_call_value_chain_local(self):
        chunk = parse_chunk(make_and_or_call_value_chain_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local value = a and compute(b) or c\nreturn value", source)
        self.assertNotIn("if a then", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_and_or_fallback_call_value_chain_local(self):
        chunk = parse_chunk(make_and_or_fallback_call_value_chain_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local value = a and b or compute(c)\nreturn value", source)
        self.assertNotIn("if a then", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_and_or_namecall_value_chain_local(self):
        chunk = parse_chunk(make_and_or_namecall_value_chain_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local value = a and obj:Compute(b) or c\nreturn value", source)
        self.assertNotIn("NAMECALL", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_comparison_and_or_call_value_chain_local(self):
        chunk = parse_chunk(make_comparison_and_or_call_value_chain_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local value = x < y and compute(z) or c\nreturn value", source)
        self.assertNotIn("if x < y then", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_simple_if_block(self):
        chunk = parse_chunk(make_if_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('if true then\n    print("yes")\nend', source)
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_if_else_block(self):
        chunk = parse_chunk(make_if_else_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('if true then\n    print("yes")\nelse\n    print("no")\nend', source)
        self.assertNotIn("JUMPIFNOT", source)
        self.assertNotIn("-- pc 6: 0006 JUMP", source)

    def test_decompile_if_else_return_without_join(self):
        chunk = parse_chunk(make_if_else_return_without_join_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('if flag then\n    return "yes"\nelse\n    return "no"\nend', source)
        self.assertNotIn('if flag then\n    return "yes"\nend\nreturn "no"', source)
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_nested_if_else_returns(self):
        chunk = parse_chunk(make_nested_if_else_return_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'if a then\n'
            '    if b then\n'
            '        return "yes"\n'
            '    else\n'
            '        return "maybe"\n'
            '    end\n'
            'else\n'
            '    return "no"\n'
            'end',
            source,
        )
        self.assertNotIn('if b then\n        return "yes"\n    end\n    return "maybe"', source)
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_guard_ladder_memoizes_termination_analysis(self):
        chunk = parse_chunk(make_nonterminating_guard_ladder_chunk(24))
        analysis_calls = 0

        class AnalysisBudgetExceeded(Exception):
            pass

        def count_analysis_calls(frame, event, _arg):
            nonlocal analysis_calls
            if event != "call" or frame.f_code.co_name != "terminating_range_end_pc":
                return
            analysis_calls += 1
            if analysis_calls > 10_000:
                raise AnalysisBudgetExceeded

        sys.setprofile(count_analysis_calls)
        try:
            try:
                source = decompile_chunk(chunk)
            except AnalysisBudgetExceeded:
                self.fail("termination analysis exceeded its deterministic work budget")
        finally:
            sys.setprofile(None)

        self.assertLess(analysis_calls, 1_000)
        self.assertIn("return", source)

    def test_decompile_straight_line_has_bounded_loop_detection_reads(self):
        chunk = parse_chunk(make_long_straight_line_chunk(400))

        class InstructionReadBudget(list):
            def __init__(self, values):
                super().__init__(values)
                self.reads = 0

            def __getitem__(self, key):
                amount = len(range(*key.indices(len(self)))) if isinstance(key, slice) else 1
                self.reads += amount
                if self.reads > 20_000:
                    raise AssertionError("loop detection exceeded its instruction-read budget")
                return super().__getitem__(key)

        instructions = InstructionReadBudget(chunk.protos[0].instructions)
        chunk.protos[0].instructions = instructions

        source = decompile_chunk(chunk)

        self.assertLess(instructions.reads, 20_000)
        self.assertIn("-- Flow Decompiler", source)

    def test_decompile_if_expression_local_assignment(self):
        chunk = parse_chunk(make_if_expression_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local result = if true then "yes" else "no"\nprint(result)', source)
        self.assertNotIn("if true then\n", source)
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_if_expression_condition_is_parenthesized(self):
        chunk = parse_chunk(make_if_expression_condition_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'if (if true then "yes" else "no") then\n'
            '    print(if true then "yes" else "no")\n'
            "end",
            source,
        )
        self.assertNotIn('if if true then "yes" else "no" then', source)

    def test_decompile_skips_empty_else_branch(self):
        chunk = parse_chunk(make_empty_else_branch_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('if true then\n    print("hit")\nend', source)
        self.assertNotIn("else\nend", source)

    def test_decompile_comparison_if_expression_local_assignment(self):
        chunk = parse_chunk(make_comparison_if_expression_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local result = if x < y then a else b\nprint(result)", source)
        self.assertNotIn("if x < y then\n", source)
        self.assertNotIn("-- pc", source)
        self.assertNotIn("JUMPIFNOTLT", source)

    def test_decompile_if_expression_call_local_assignment(self):
        chunk = parse_chunk(make_if_expression_call_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local result = if flag then compute(a) else fallback(b)\nprint(result)", source)
        self.assertNotIn("if flag then\n", source)
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_elseif_if_expression_local_assignment(self):
        chunk = parse_chunk(make_elseif_if_expression_local_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local result = if dead then "dead" elseif stunned then "stunned" else "active"\nprint(result)', source)
        self.assertNotIn("if dead then\n", source)
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_if_expression_return(self):
        chunk = parse_chunk(make_if_expression_return_chunk())

        source = decompile_chunk(chunk)

        self.assertEqual(source.splitlines()[-1], "return if true then 10 else 20")
        self.assertNotIn("if true then\n", source)
        self.assertNotIn("JUMPIFNOT", source)

    def test_if_expression_is_grouped_when_nested_inside_other_expressions(self):
        receiver = 'if Humanoid then Humanoid:FindFirstChildOfClass("Animator") else nil'
        speed = "if captured8 then captured14(r4, p2) else p2.Magnitude"
        callback = "if ready then handler else fallback"

        self.assertEqual(
            _namecall_expr(receiver, "GetPlayingAnimationTracks", []),
            '(if Humanoid then Humanoid:FindFirstChildOfClass("Animator") else nil):GetPlayingAnimationTracks()',
        )
        self.assertEqual(_binary_expr("0.1", "<", speed), "0.1 < (if captured8 then captured14(r4, p2) else p2.Magnitude)")
        self.assertEqual(_call_expr(callback, []), "(if ready then handler else fallback)()")

    def test_namecall_helper_groups_string_literal_receiver(self):
        self.assertEqual(_namecall_expr('"value"', "format", []), '("value"):format()')

    def test_decompile_elseif_chain(self):
        chunk = parse_chunk(make_elseif_chain_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'if true then\n    print("first")\nelseif false then\n    print("second")\nelse\n    print("third")\nend',
            source,
        )
        self.assertNotIn("else\n    if false then", source)

    def test_decompile_compound_elseif_and_chain(self):
        chunk = parse_chunk(make_compound_elseif_and_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'if a then\n    print("first")\nelseif b and c then\n    print("second")\nelse\n    print("third")\nend',
            source,
        )
        self.assertNotIn("elseif b then\n    if c then", source)
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_short_circuit_and_if(self):
        chunk = parse_chunk(make_short_circuit_and_if_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('if true and false then\n    print("hit")\nend', source)
        self.assertNotIn("if true then\n    if false then", source)

    def test_decompile_short_circuit_and_if_else(self):
        chunk = parse_chunk(make_short_circuit_and_if_else_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('if true and false then\n    print("yes")\nelse\n    print("no")\nend', source)
        self.assertNotIn("if true then\n    if false then", source)
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_short_circuit_or_if(self):
        chunk = parse_chunk(make_short_circuit_or_if_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('if true or false then\n    print("hit")\nend', source)
        self.assertNotIn("if not true then", source)

    def test_decompile_three_term_short_circuit_or_if(self):
        chunk = parse_chunk(make_three_term_short_circuit_or_if_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('if true or false or true then\n    print("hit")\nend', source)
        self.assertNotIn("if true then\n    if false then", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_mixed_and_or_short_circuit_if(self):
        chunk = parse_chunk(make_mixed_and_or_short_circuit_if_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('if true and (false or true) then\n    print("hit")\nend', source)
        self.assertNotIn("if true then\n    if", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_mixed_or_and_short_circuit_if(self):
        chunk = parse_chunk(make_mixed_or_and_short_circuit_if_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('if (true or false) and true then\n    print("hit")\nend', source)
        self.assertNotIn("if true or false then\n    if", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_and_or_fallback_short_circuit_if(self):
        chunk = parse_chunk(make_and_or_fallback_short_circuit_if_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('if a and b or c then\n    print("hit")\nend', source)
        self.assertNotIn("if (not a) or (not b) then", source)
        self.assertNotIn("-- pc 2:", source)

    def test_decompile_grouped_or_and_or_short_circuit_if(self):
        chunk = parse_chunk(make_grouped_or_and_or_short_circuit_if_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('if (a or b) and (c or d) then\n    print("hit")\nend', source)
        self.assertNotIn("if a or b then\n    if c or d then", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_comparison_if_block(self):
        chunk = parse_chunk(make_comparison_if_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('if 1 < 2 then\n    print("lt")\nend', source)
        self.assertNotIn("JUMPIFNOTLT", source)

    def test_decompile_inner_compare_exits_parent_branch(self):
        chunk = parse_chunk(make_inner_compare_exits_parent_branch_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'if flag then\n'
            '    if value < limit then\n'
            '        print("inner")\n'
            '    end\n'
            'else\n'
            '    print("else")\n'
            "end",
            source,
        )
        self.assertNotIn("JUMPIFNOTLT", source)
        self.assertNotIn("JUMP R0", source)

    def test_decompile_or_branch_inner_compare_exits_join(self):
        chunk = parse_chunk(make_or_branch_inner_compare_exits_join_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("if a or b then", source)
        self.assertIn('if value < limit then\n        print("first")\n    end', source)
        self.assertNotIn("JUMPIFNOTLT", source)
        self.assertNotIn("JUMP R0", source)

    def test_decompile_call_guard_exits_parent_branch(self):
        chunk = parse_chunk(make_call_guard_exits_parent_branch_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("if flag then", source)
        self.assertIn('if target:FindFirstChild(name) then\n        print("hit")\n    end', source)
        self.assertIn('else\n    print("else")\nend', source)
        self.assertNotIn("JUMPIFNOT", source)
        self.assertNotIn("JUMP R0", source)

    def test_decompile_and_call_guard_exits_parent_branch(self):
        chunk = parse_chunk(make_and_call_guard_exits_parent_branch_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("if flag and ok then", source)
        self.assertIn('if target:FindFirstChild(name) then\n        print("hit")\n    end', source)
        self.assertIn('else\n    print("else")\nend', source)
        self.assertNotIn("JUMPIFNOT", source)
        self.assertNotIn("JUMP R0", source)

    def test_decompile_namecall_guard_reuses_result_local(self):
        chunk = parse_chunk(make_namecall_guard_reuses_result_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local r2 = target:FindFirstChild(name)", source)
        self.assertIn("if r2 then\n    print(r2)\nend", source)
        self.assertNotIn("print(target:FindFirstChild(name))", source)

    def test_decompile_loop_exit_guard_as_break(self):
        chunk = parse_chunk(make_loop_exit_guard_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("if not keep then\n        break\n    end", source)
        self.assertIn('print("body")', source)
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_loop_exit_guard_uses_merged_boolean_register(self):
        chunk = parse_chunk(make_loop_exit_guard_merged_boolean_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("if not keep then\n        break\n    end", source)
        self.assertNotIn("if not false", source)
        self.assertNotIn("if not true", source)

    def test_decompile_return_guard_exits_parent_branch(self):
        chunk = parse_chunk(make_return_guard_exits_parent_branch_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("if mode then", source)
        self.assertIn("if done then\n        return\n    end", source)
        self.assertIn('print("run")', source)
        self.assertIn('print("else")', source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_contained_if_in_terminating_else(self):
        chunk = parse_chunk(make_contained_if_in_terminating_else_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("if guard then", source)
        self.assertIn("if looped then\n            return\n        end", source)
        self.assertIn('print("body")', source)
        self.assertIn('print("after")', source)
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_short_circuit_before_contained_if_keeps_range_open(self):
        chunk = parse_chunk(make_short_circuit_before_contained_if_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("if guard then", source)
        self.assertIn("if looped then\n            return\n        end", source)
        self.assertIn('print("body")', source)
        self.assertIn('print("after")', source)
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_short_circuit_branch_assignment_used_after(self):
        chunk = parse_chunk(make_short_circuit_branch_assignment_used_after_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'local r2 = p0\n'
            'if p1 ~= nil and p1 == false then\n'
            '    r2 = "idle"\n'
            'end\n'
            "print(r2)",
            source,
        )
        self.assertNotIn("\nif p1 ~= nil and p1 == false then\nend", source)
        self.assertNotIn("JUMPXEQ", source)

    def test_decompile_short_circuit_branch_assignment_before_conditional_overwrite(self):
        chunk = parse_chunk(make_short_circuit_branch_assignment_before_conditional_overwrite_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'local r3 = p0\n'
            'if p1 ~= nil and p1 == false then\n'
            '    r3 = "idle"\n'
            'end\n'
            'if p2 then\n'
            '    r3 = "fallback"\n'
            'end\n'
            "print(r3)",
            source,
        )
        self.assertNotIn("\nif p1 ~= nil and p1 == false then\nend", source)
        self.assertNotIn("JUMPXEQ", source)

    def test_decompile_conditional_value_with_guarded_fallback(self):
        chunk = parse_chunk(make_conditional_value_with_guarded_fallback_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local r3 = 1\n"
            "if p0 then\n"
            "    r3 = upvalue0 / p2\n"
            "    r3 = r3 or 1\n"
            "end\n"
            "print(r3)",
            source,
        )
        self.assertNotIn("\nif p0 then\nend", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_branch_table_literal_assignment_used_after(self):
        chunk = parse_chunk(make_branch_table_literal_assignment_used_after_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local r2 = p0\nif not r2 then\n    r2 = {}\nend\nprint(r2)", source)
        self.assertNotIn("\nif not p0 then\nend", source)

    def test_decompile_branch_assignment_captured_by_closure(self):
        chunk = parse_chunk(make_branch_assignment_captured_by_closure_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('if p0 then\n    r2 = "outer"\nend', source)
        self.assertNotIn("\nif p0 then\nend", source)

    def test_decompile_or_fallback_import_assignment(self):
        chunk = parse_chunk(make_or_fallback_import_assignment_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("print(p0 or Enum.Fallback)", source)
        self.assertNotIn("\nif p0 then\nend", source)

    def test_decompile_branch_table_alias_reassigns_parameter(self):
        chunk = parse_chunk(make_branch_table_alias_reassigns_parameter_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("if p1 then\n    p0 = {p0}\nend\nprint(p0)", source)
        self.assertNotIn("\nif p1 then\nend", source)

    def test_decompile_guarded_or_with_truthy_fallback(self):
        chunk = parse_chunk(make_guarded_or_with_truthy_fallback_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'if value ~= sentinel and (type(value) ~= "boolean" or type(default) == "boolean") then\n'
            "    out = value\n"
            "elseif value then\n"
            "    out = sentinel\n"
            "end",
            source,
        )
        self.assertNotIn('if type(default) ~= "boolean" then\n    end', source)
        self.assertNotIn("JUMPXEQKS", source)

    def test_decompile_constant_comparison_if_block(self):
        chunk = parse_chunk(make_constant_comparison_if_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local status = "ready"\nif status == "ready" then\n    print("ok")\nend', source)
        self.assertNotIn("JUMPXEQKS", source)

    def test_decompile_constant_comparison_short_circuit_or_if(self):
        chunk = parse_chunk(make_constant_comparison_or_if_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'local status = "ready"\nif status == "ready" or status == "queued" then\n    print("ok")\nend',
            source,
        )
        self.assertNotIn("JUMPXEQKS", source)

    def test_decompile_short_circuit_or_preserves_branch_liveout(self):
        chunk = parse_chunk(make_short_circuit_or_branch_liveout_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'local r2 = "initial"\n'
            "if p0 or p1 then\n"
            '    r2 = "changed"\n'
            "end\n"
            "print(r2)",
            source,
        )
        self.assertNotIn("if p0 or p1 then\nend", source)

    def test_decompile_constant_comparison_exits_bounded_branch(self):
        chunk = parse_chunk(make_constant_comparison_exits_bounded_branch_chunk())

        source = decompile_chunk(chunk)

        self.assertNotIn("JUMPXEQKS", source)

    def test_decompile_upvalue_setup_short_circuit_and_if(self):
        chunk = parse_chunk(make_upvalue_setup_short_circuit_and_if_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'if upvalue0 == "FreeFall" and upvalue1 <= 0 then\n    print("hit")\nend',
            source,
        )
        self.assertNotIn("JUMPIFNOTLE", source)

    def test_decompile_upvalue_setup_short_circuit_and_elseif(self):
        chunk = parse_chunk(make_upvalue_setup_short_circuit_and_elseif_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'if upvalue0 == "FreeFall" and upvalue1 <= 0 then\n'
            '    print("fall")\n'
            'elseif upvalue0 == "Seated" then\n'
            '    print("sit")\n'
            "end",
            source,
        )
        self.assertNotIn("JUMP R0", source)

    def test_register_compare_keeps_original_condition_registers(self):
        chunk = parse_chunk(make_register_compare_preserves_condition_setup_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("if 0 < upvalue0 then", source)
        self.assertNotIn("if upvalue0 < upvalue0 then", source)

    def test_decompile_register_compare_or_return_guard(self):
        chunk = parse_chunk(make_register_compare_or_return_guard_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "if cached == available or available < now then\n    return\nend",
            source,
        )
        self.assertNotIn("JUMPIFNOTLT", source)

    def test_decompile_comparison_boolean_value(self):
        chunk = parse_chunk(make_comparison_boolean_value_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local flag = 1 < 2\nprint(flag)", source)
        self.assertNotIn("JUMPIFNOTLT", source)
        self.assertNotIn("LOADB", source)

    def test_decompile_negated_comparison_boolean_value(self):
        chunk = parse_chunk(make_negated_comparison_boolean_value_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local flag = 1 >= 2\nprint(flag)", source)
        self.assertNotIn("not 1 < 2", source)
        self.assertNotIn("JUMPIFNOTLT", source)

    def test_decompile_loadb_skip_does_not_process_skipped_assignment(self):
        chunk = parse_chunk(make_loadb_skip_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("print(true)", source)
        self.assertNotIn("print(false)", source)

    def test_decompile_forward_jump_skips_unreachable_register_write(self):
        chunk = parse_chunk(make_jump_skip_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('print("live")', source)
        self.assertNotIn('print("dead")', source)
        self.assertNotIn("JUMP", source)

    def test_decompile_while_block(self):
        chunk = parse_chunk(make_while_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('while true do\n    print("tick")\nend', source)
        self.assertNotIn("JUMPIFNOT", source)
        self.assertNotIn("JUMPBACK", source)

    def test_decompile_while_preserves_stripped_loop_carried_value(self):
        chunk = parse_chunk(make_while_stripped_loop_carried_value_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local r0 = 1\n"
            "while r0 < 3 do\n"
            "    r0 = r0 + 1\n"
            "end\n"
            "return r0",
            source,
        )
        self.assertNotIn("while 1 < 3 do\nend", source)

    def test_decompile_while_rebuilds_condition_setup_with_loop_carried_value(self):
        chunk = parse_chunk(make_while_condition_setup_uses_loop_carried_value_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local r1 = 1\n"
            "while p0[r1] < 10 do\n"
            "    r1 = r1 + 1\n"
            "end\n"
            "return r1",
            source,
        )
        self.assertNotIn("while p0[1] < 10", source)

    def test_decompile_while_compound_guard(self):
        chunk = parse_chunk(make_while_compound_guard_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("while a and b do\n    tick()\nend", source)
        self.assertNotIn("JUMPIFNOT", source)
        self.assertNotIn("JUMPBACK", source)

    def test_decompile_while_or_guard(self):
        chunk = parse_chunk(make_while_or_guard_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("while a or b do\n    tick()\nend", source)
        self.assertNotIn("JUMPIF", source)
        self.assertNotIn("JUMPBACK", source)

    def test_decompile_while_three_term_or_guard(self):
        chunk = parse_chunk(make_while_three_term_or_guard_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("while a or b or c do\n    tick()\nend", source)
        self.assertNotIn("JUMPIF", source)
        self.assertNotIn("JUMPBACK", source)

    def test_decompile_while_grouped_or_and_or_guard(self):
        chunk = parse_chunk(make_while_grouped_or_and_or_guard_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("while (a or b) and (c or d) do\n    tick()\nend", source)
        self.assertNotIn("JUMPIF", source)
        self.assertNotIn("JUMPBACK", source)

    def test_decompile_while_break(self):
        chunk = parse_chunk(make_while_break_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("while true do\n    break\nend", source)
        self.assertNotIn("0002 JUMP", source)

    def test_decompile_while_continue(self):
        chunk = parse_chunk(make_while_continue_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('while true do\n    print("top")\n    continue\nend', source)
        self.assertNotIn("0006 JUMPBACK", source)

    def test_decompile_while_conditional_continue(self):
        chunk = parse_chunk(make_while_conditional_continue_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('while true do\n    if skip then\n        continue\n    end\n    print("tick")\nend', source)
        self.assertNotIn("JUMPIFNOT", source)
        self.assertNotIn("JUMPBACK", source)

    def test_decompile_repeat_until_block(self):
        chunk = parse_chunk(make_repeat_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('repeat\n    print("tick")\nuntil false', source)
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_repeat_until_forward_exit_guard(self):
        chunk = parse_chunk(make_repeat_forward_exit_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("repeat\n    tick()\nuntil flag", source)
        self.assertNotIn("while not flag do", source)
        self.assertNotIn("JUMPBACK", source)

    def test_decompile_repeat_until_and_condition(self):
        chunk = parse_chunk(make_repeat_and_condition_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("repeat\n    tick()\nuntil a and b", source)
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_repeat_until_or_condition(self):
        chunk = parse_chunk(make_repeat_or_condition_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("repeat\n    tick()\nuntil a or b", source)
        self.assertNotIn("JUMPIF", source)

    def test_decompile_repeat_break_preserves_body_order(self):
        chunk = parse_chunk(make_repeat_break_preserves_body_order_chunk())

        source = decompile_chunk(chunk)

        expected = (
            "local x = 0\n"
            "repeat\n"
            "    x = x + 1\n"
            "    if x == 5 then\n"
            "        break\n"
            "    end\n"
            "    step(x)\n"
            "until x >= 10\n"
            "return x"
        )
        self.assertIn(expected, source)
        self.assertEqual(source.count("step(x)"), 1)
        self.assertLess(source.index("if x == 5 then"), source.index("step(x)"))
        self.assertNotIn("-- pc", source)

    def test_decompile_numeric_for_block(self):
        chunk = parse_chunk(make_numeric_for_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("for r3 = 1, 3, 1 do\n    print(r3)\nend", source)
        self.assertNotIn("FORNPREP", source)
        self.assertNotIn("FORNLOOP", source)

    def test_decompile_numeric_for_uses_debug_local_name(self):
        chunk = parse_chunk(make_numeric_for_named_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("for i = 1, 3, 1 do\n    print(i)\nend", source)
        self.assertNotIn("for r3", source)

    def test_decompile_numeric_for_inferred_local_does_not_shadow_loop_var(self):
        chunk = parse_chunk(make_numeric_for_inferred_local_shadow_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "for r3 = 1, 2, 1 do\n"
            "    local r3_2 = make()\n"
            "    print(r3_2, r3_2)\n"
            "end",
            source,
        )
        self.assertNotIn("for r3 = 1, 2, 1 do\n    local r3 = make()", source)

    def test_decompile_generic_for_uses_debug_local_names(self):
        chunk = parse_chunk(make_generic_for_named_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("for key, value in next, items do\n    print(key, value)\nend", source)
        self.assertNotIn("state = nil", source)
        self.assertNotIn("FORGPREP", source)
        self.assertNotIn("FORGLOOP", source)

    def test_decompile_generic_for_uses_call_iterator_expression(self):
        chunk = parse_chunk(make_generic_for_call_iterator_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("for _, child in ipairs(items) do\n    print(child)\nend", source)
        self.assertNotIn("local r0, r1, r2 = ipairs(items)", source)
        self.assertNotIn("FORGPREP", source)

    def test_decompile_generic_for_inext_fastpath_uses_ipairs_expression(self):
        chunk = parse_chunk(make_generic_for_inext_fastpath_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("for _, child in ipairs(items) do\n    print(child)\nend", source)
        self.assertNotIn("r0, items, 0", source)
        self.assertNotIn("FORGPREP_INEXT", source)

    def test_decompile_generic_for_next_fastpath_uses_pairs_expression(self):
        chunk = parse_chunk(make_generic_for_next_fastpath_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("for key, value in pairs(items) do\n    print(key, value)\nend", source)
        self.assertNotIn("r0, items, nil", source)
        self.assertNotIn("FORGPREP_NEXT", source)

    def test_decompile_generic_for_pairs_preserves_pending_table_literal(self):
        chunk = parse_chunk(make_generic_for_pairs_pending_table_literal_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local t = {a = 1, b = 2, c = 3}\n"
            "for k, v in pairs(t) do\n"
            "    print(k, v)\n"
            "end\n"
            "return t",
            source,
        )
        self.assertNotIn("pairs({})", source)
        self.assertNotIn("local t = {}\nfor", source)

    def test_decompile_child_closure_expression_with_parameter_name(self):
        chunk = parse_chunk(make_child_closure_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("return function(value)\n    return value\nend", source)
        self.assertNotIn("NEWCLOSURE", source)

    def test_decompile_child_closure_uses_debug_upvalue_name(self):
        chunk = parse_chunk(make_captured_upvalue_closure_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("return function()\n    return x\nend", source)
        self.assertNotIn("GETUPVAL", source)
        self.assertNotIn("CAPTURE", source)

    def test_decompile_closure_capture_materializes_pending_table_local(self):
        chunk = parse_chunk(make_pending_table_capture_closure_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'local Config = {name = "maker"}\nreturn function()\n    return Config\nend',
            source,
        )
        self.assertLess(source.index("local Config"), source.index("return function()"))
        self.assertNotIn("CAPTURE", source)

    def test_decompile_child_closure_infers_captured_upvalue_name(self):
        chunk = parse_chunk(make_inferred_captured_upvalue_name_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local x = "outer"\nreturn function()\n    return x\nend', source)
        self.assertNotIn("upvalue0", source)
        self.assertNotIn("CAPTURE", source)

    def test_decompile_forward_recursive_closures_assign_existing_locals(self):
        chunk = parse_chunk(make_mutual_forward_recursive_closures_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local even = nil\n"
            "local odd = nil\n"
            "function even()\n"
            "    return odd\n"
            "end\n"
            "function odd()\n"
            "    return even\n"
            "end\n"
            "return even, odd",
            source,
        )
        self.assertNotIn("local function even()", source)
        self.assertNotIn("local function odd()", source)
        self.assertNotIn("upvalue", source)
        self.assertNotIn("CAPTURE", source)

    def test_decompile_dupclosure_hoists_captured_expression(self):
        chunk = parse_chunk(make_dupclosure_captured_expression_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local captured0 = script.Parent\n"
            "return function()\n"
            "    return captured0\n"
            "end",
            source,
        )
        self.assertNotIn("upvalue0", source)
        self.assertNotIn("CAPTURE", source)
        self.assertNotIn("GETUPVAL", source)

    def test_decompile_stripped_ref_capture_materializes_mutable_local(self):
        chunk = parse_chunk(make_stripped_ref_capture_mutation_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local captured0 = 0", source)
        self.assertIn("return function()\n    return captured0\nend", source)
        self.assertIn("captured0 = 1", source)
        self.assertIn("return function()", source)
        self.assertIn("captured0", source.splitlines()[-1])
        self.assertNotIn("return 0", source)
        self.assertNotIn("upvalue0", source)
        self.assertNotIn("CAPTURE", source)

    def test_decompile_stripped_val_and_ref_captures_keep_separate_identity(self):
        chunk = parse_chunk(make_stripped_val_and_ref_capture_identity_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local captured0 = 0\n"
            "local captured1 = 0\n"
            "captured1 = 1\n"
            "return function()\n"
            "    return captured0\n"
            "end, function()\n"
            "    return captured1\n"
            "end",
            source,
        )
        self.assertNotIn("local captured0 = 0\nlocal captured0 = 0", source)
        self.assertNotIn("CAPTURE", source)
        self.assertNotIn("GETUPVAL", source)

    def test_decompile_stripped_ref_then_val_captures_keep_separate_identity(self):
        chunk = parse_chunk(make_stripped_ref_and_val_capture_identity_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local captured0 = 0\n"
            "local captured1 = captured0\n"
            "captured0 = 1\n"
            "return function()\n"
            "    return captured0\n"
            "end, function()\n"
            "    return captured1\n"
            "end",
            source,
        )
        self.assertNotIn("CAPTURE", source)
        self.assertNotIn("GETUPVAL", source)

    def test_decompile_stripped_sibling_value_captures_share_identity(self):
        chunk = parse_chunk(make_stripped_shared_val_capture_identity_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local captured0 = {}\n"
            "return function()\n"
            "    return captured0\n"
            "end, function()\n"
            "    return captured0\n"
            "end",
            source,
        )
        self.assertNotIn("captured1", source)
        self.assertNotIn("CAPTURE", source)
        self.assertNotIn("GETUPVAL", source)

    def test_decompile_generated_capture_name_avoids_inherited_upvalue(self):
        chunk = parse_chunk(make_nested_generated_capture_name_collision_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local captured0 = 1\n"
            "return function()\n"
            "    local captured1 = 0\n"
            "    return function()\n"
            "        return captured1\n"
            "    end, captured0\n"
            "end",
            source,
        )
        self.assertNotIn("local captured0 = 0", source)

    def test_decompile_setupvalue_uses_debug_upvalue_name(self):
        chunk = parse_chunk(make_setupvalue_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('state = "ready"', source)
        self.assertNotIn("SETUPVAL", source)

    def test_decompile_setupvalue_preserves_loaded_upvalue_snapshot(self):
        chunk = parse_chunk(make_setupvalue_preserves_loaded_snapshot_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local r0 = state\nstate = 0\nreturn r0", source)
        self.assertNotIn("state = 0\nreturn state", source)
        self.assertNotIn("SETUPVAL", source)

    def test_decompile_named_local_function_call(self):
        chunk = parse_chunk(make_named_local_function_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local function helper()\n    return "ok"\nend\nhelper()', source)
        self.assertNotIn("function()\nend()", source)

    def test_decompile_reused_child_debugname_preserves_closure_identity(self):
        chunk = parse_chunk(make_child_debugname_reused_function_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'local function helper()\n'
            '    return "ok"\n'
            "end\n"
            "helper()\n"
            "helper()",
            source,
        )
        self.assertEqual(source.count('return "ok"'), 1)

    def test_decompile_immediate_closure_call_uses_parenthesized_iife(self):
        chunk = parse_chunk(make_immediate_closure_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('(function()\n    return "ok"\nend)()', source)
        self.assertNotIn('function()\n    return "ok"\nend()', source)
        self.assertNotIn("CALL", source)

    def test_decompile_namecall_multiline_function_arg_formats_argument_list(self):
        chunk = parse_chunk(make_namecall_with_closure_and_value_args_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'Remote:FireServer(\n'
            "    function()\n"
            '        return "ok"\n'
            "    end,\n"
            '    "tag"\n'
            ")",
            source,
        )
        self.assertNotIn('end, "tag")', source)
        self.assertNotIn("NEWCLOSURE", source)

    def test_decompile_reused_invokeserver_result_materializes_local(self):
        chunk = parse_chunk(make_reused_invokeserver_result_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local inventory = GetInventory:InvokeServer()\n"
            "print(inventory)\n"
            "return inventory",
            source,
        )
        self.assertEqual(source.count("GetInventory:InvokeServer()"), 1)

    def test_decompile_reused_plain_call_result_materializes_local(self):
        chunk = parse_chunk(make_reused_call_result_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            "local r0 = compute()\n"
            "print(r0)\n"
            "return r0",
            source,
        )
        self.assertEqual(source.count("compute()"), 1)

    def test_decompile_reused_moved_call_result_materializes_alias(self):
        chunk = parse_chunk(make_reused_call_result_through_move_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local r1 = compute()\nprint(r1, r1)", source)
        self.assertEqual(source.count("compute()"), 1)

    def test_decompile_delayed_single_call_result_preserves_snapshot(self):
        chunk = parse_chunk(make_delayed_single_call_result_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local r0 = clock()\nwait()\nreturn clock() - r0", source)
        self.assertNotIn("clock() - clock()", source)

    def test_decompile_reused_binary_result_materializes_once(self):
        chunk = parse_chunk(make_reused_binary_result_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local r2 = p0 - p1\nprint(r2, r2)", source)
        self.assertEqual(source.count("p0 - p1"), 1)

    def test_decompile_property_read_before_loop_preserves_snapshot(self):
        chunk = parse_chunk(make_loop_property_snapshot_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local Position = workspace.CurrentCamera.Position", source)
        self.assertIn("print(Position)", source)
        self.assertEqual(source.count("workspace.CurrentCamera.Position"), 1)

    def test_decompile_branch_condition_uses_materialized_register(self):
        chunk = parse_chunk(make_branch_condition_reused_register_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local r1 = p0:IsA("Texture")\nif not r1 then', source)
        self.assertIn("r1 = p0.Parent", source)
        self.assertIn("print(r1)", source)
        self.assertNotIn("local Parent", source)
        self.assertEqual(source.count('p0:IsA("Texture")'), 1)

    def test_decompile_short_circuit_guard_keeps_each_indexed_value(self):
        chunk = parse_chunk(make_short_circuit_indexed_guard_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("if p0 and p1[p0] and p1[p0].Particles[p0] then", source)
        self.assertNotIn("p1[p0].Particles and p1[p0].Particles", source)

    def test_decompile_child_parameter_avoids_captured_upvalue_name(self):
        chunk = parse_chunk(make_child_parameter_capture_collision_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("function(p0_2)", source)
        self.assertIn("return p0[p0_2]", source)
        self.assertNotIn("return p0[p0]", source)

    def test_decompile_expression_callee_call_uses_grouped_target(self):
        chunk = parse_chunk(make_expression_callee_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("(f or g)()", source)
        self.assertNotIn("f or g()", source)
        self.assertNotIn("CALL", source)

    def test_decompile_class_member_method_assignment(self):
        chunk = parse_chunk(make_class_member_method_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('function Widget.render()\n    return "ok"\nend', source)
        self.assertNotIn("Widget.render = function()", source)
        self.assertNotIn("NEWCLASSMEMBER", source)

    def test_decompile_global_function_assignment(self):
        chunk = parse_chunk(make_global_function_assignment_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('function helper()\n    return "ok"\nend', source)
        self.assertNotIn("helper = function()", source)
        self.assertNotIn("SETGLOBAL", source)

    def test_decompile_table_method_assignment(self):
        chunk = parse_chunk(make_table_method_assignment_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local Widget = {}\nfunction Widget.render()\n    return "ok"\nend', source)
        self.assertNotIn("Widget.render = function()", source)
        self.assertNotIn("SETTABLEKS", source)

    def test_decompile_table_literal_key_method_assignment(self):
        chunk = parse_chunk(make_table_literal_key_method_assignment_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local Widget = {}\nfunction Widget.render()\n    return "ok"\nend', source)
        self.assertNotIn('Widget["render"] = function()', source)
        self.assertNotIn('["render"] = function()', source)
        self.assertNotIn("SETTABLE", source)

    def test_decompile_table_colon_method_assignment(self):
        chunk = parse_chunk(make_table_colon_method_assignment_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local Widget = {}\nfunction Widget:render()\n    return "ok"\nend', source)
        self.assertNotIn("function Widget.render(self)", source)
        self.assertNotIn("SETTABLEKS", source)

    def test_decompile_named_local_value_call(self):
        chunk = parse_chunk(make_named_local_value_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn('local message = "hi"\nprint(message)', source)
        self.assertNotIn('print("hi")', source)

    def test_decompile_vararg_open_return(self):
        chunk = parse_chunk(make_vararg_return_chunk())

        source = decompile_chunk(chunk)

        self.assertEqual(source.splitlines()[-1], "return ...")
        self.assertNotIn("GETVARARGS", source)

    def test_decompile_named_fixed_vararg_value_call(self):
        chunk = parse_chunk(make_named_fixed_vararg_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local first = ...\nprint(first)", source)
        self.assertNotIn("GETVARARGS", source)

    def test_decompile_named_multi_vararg_value_call(self):
        chunk = parse_chunk(make_named_multi_vararg_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local first, second = ...\nprint(first, second)", source)
        self.assertNotIn("GETVARARGS", source)

    def test_decompile_named_multi_return_call(self):
        chunk = parse_chunk(make_named_multi_return_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local first, second = provider()\nprint(first, second)", source)
        self.assertNotIn("r1", source)

    def test_decompile_multi_return_reassigns_existing_locals(self):
        chunk = parse_chunk(make_existing_local_multi_return_reassign_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local first = 0\nlocal second = 0\nfirst, second = provider()\nreturn first, second", source)
        self.assertNotIn("local first, second = provider()", source)
        self.assertNotIn("first = first()", source)

    def test_decompile_anonymous_multi_return_call_uses_fallback_locals(self):
        chunk = parse_chunk(make_anonymous_multi_return_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local r0, r1 = provider()\nprint(r0, r1)", source)
        self.assertNotIn("print(provider(), r1)", source)

    def test_decompile_overlapping_multi_return_call_declares_missing_result(self):
        chunk = parse_chunk(make_overlapping_multi_return_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("local r0, r1 = provider()", source)
        self.assertIn("local r2 = nil\nr1, r2 = provider()\nprint(r1, r2)", source)
        self.assertNotIn("print(provider(), r2)", source)
        self.assertNotIn("print(r1, provider)", source)

    def test_decompile_short_circuit_call_guard_else(self):
        chunk = parse_chunk(make_short_circuit_call_guard_else_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'if flag and sound:IsA("AudioPlayer") then\n'
            "    sound:Play()\n"
            "else\n"
            "    sound.Playing = true\n"
            "end",
            source,
        )
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_short_circuit_or_call_guard(self):
        chunk = parse_chunk(make_short_circuit_or_call_guard_chunk())

        source = decompile_chunk(chunk)

        self.assertIn(
            'if sound:IsA("TextLabel") or sound:IsA("TextButton") then\n'
            "    sound.TextColor3 = 1\n"
            "end",
            source,
        )
        self.assertNotIn("JUMPIFNOT", source)

    def test_decompile_table_literal_preserves_open_call_setlist(self):
        chunk = parse_chunk(make_table_open_call_chunk())

        source = decompile_chunk(chunk)

        self.assertIn("print({provider()})", source)
        self.assertNotIn("print({})", source)

    def test_large_table_literal_renders_multiline(self):
        table = TableLiteral()
        for index in range(1, 8):
            table.set_array(index, str(index))

        source = table.render()

        self.assertEqual(
            source,
            "{\n"
            "    1, 2, 3, 4, 5, 6, 7,\n"
            "}",
        )

    def test_table_literal_receiver_is_grouped_for_index(self):
        self.assertEqual(_index_expr("{value = 1}", "key"), "({value = 1})[key]")

    def test_multiline_table_literal_receiver_is_grouped_for_index(self):
        table = "{\n    value = 1,\n}"

        self.assertEqual(_index_expr(table, "key"), f"({table})[key]")

    def test_nil_receiver_is_grouped_for_namecall(self):
        self.assertEqual(_namecall_expr("nil", "GetFullName", []), "(nil):GetFullName()")

    def test_boolean_receiver_is_grouped_for_field(self):
        self.assertEqual(_field_expr("true", "value"), "(true).value")

    def test_vararg_call_target_is_grouped(self):
        self.assertEqual(_call_expr("...", []), "(...)()")

    def test_parenthesized_assignment_after_call_needs_separator(self):
        self.assertTrue(_needs_statement_separator("    r9:Add()", "    ", "(state or fallback).active = true"))

    def test_parenthesized_call_after_call_needs_separator(self):
        self.assertTrue(_needs_statement_separator("    r9:Add()", "    ", "((state or fallback).Leaving):Fire()"))

    def test_parenthesized_statement_at_new_indent_does_not_modify_parent(self):
        self.assertFalse(_needs_statement_separator("if ready then", "    ", "(state).active = true"))

    def test_non_parenthesized_statement_needs_no_separator(self):
        self.assertFalse(_needs_statement_separator("    r9:Add()", "    ", "state.active = true"))

    def test_decompile_stops_current_range_after_return(self):
        source = decompile_chunk(parse_chunk(make_return_then_dead_global_chunk()))

        self.assertIn("return -1", source)
        self.assertNotIn("deadValue", source)
        self.assertNotIn("99", source)

    def test_branch_join_is_not_continue_without_loop_context(self):
        self.assertFalse(_is_loop_continue_target(20, 20, None))

    def test_loop_range_stop_can_be_continue_with_loop_context(self):
        self.assertTrue(_is_loop_continue_target(20, 20, 10))

    def test_settable_groups_literal_receiver(self):
        source = decompile_chunk(parse_chunk(make_nil_receiver_table_write_chunk()))

        self.assertIn("(nil)[nil] = nil", source)

    def test_vararg_receiver_is_grouped_for_index(self):
        self.assertEqual(_index_expr("...", "..."), "(...)[...]")

    def test_control_bytes_use_luau_hex_escapes(self):
        self.assertEqual(_quote_string("\x15\x00"), '"\\x15\\x00"')

    def test_live_roblox_encoded_opcode_chunk_is_preserved(self):
        raw = base64.b64decode("CQMAAAEAAAABAgACowAAAIIAAQAAAAEAARgAAAEAAAAAAA==")

        chunk = parse_chunk(raw)
        source = decompile_chunk(chunk)

        self.assertEqual(chunk.version, 9)
        self.assertEqual(chunk.protos[0].instructions[0].op.name, "PREPVARARGS")
        self.assertFalse(chunk.protos[0].has_unknown_opcodes)
        self.assertNotIn("encoded or unsupported opcode 163", source)

    def test_live_player_scripts_loader_decompiles_cleanly(self):
        raw = base64.b64decode(
            "CQMFB3JlcXVpcmUGc2NyaXB0BlBhcmVudAxQbGF5ZXJNb2R1bGUMV2FpdEZvckNoaWxkAAEEAAABAgANowAAAKQAAQAAAABApAEDAAAAIEBNAQEkBAAAAG8DBQC8AQHTBgAAAJ8BAwCfAAABggABAAcDAQQAAABAAwIEAAAgQAMDAwQDBQABAAEYAAYAAAAAAAAAAAAAAQEAAAAAAA=="
        )

        chunk = parse_chunk(raw)
        source = decompile_chunk(chunk)

        self.assertFalse(chunk.protos[0].has_unknown_opcodes)
        self.assertEqual(chunk.protos[0].instructions[0].op.name, "PREPVARARGS")
        self.assertEqual(chunk.protos[0].instructions[1].op.name, "GETIMPORT")
        self.assertIn('require(script.Parent:WaitForChild("PlayerModule"))', source)
        self.assertEqual(source.splitlines()[-1], 'require(script.Parent:WaitForChild("PlayerModule"))')
        self.assertNotIn("encoded opcode stream", source)

    def test_live_gameanalytics_infers_service_local(self):
        raw = base64.b64decode(
            "CQMHBGdhbWURUmVwbGljYXRlZFN0b3JhZ2UKR2V0U2VydmljZQdyZXF1aXJlCFBhY2thZ2VzDUdhbWVBbmFseXRpY3MKaW5pdENsaWVudAABBAAAAQIAEqMAAACkAAEAAAAAQG8CAgC8AAAWAwAAAJ8AAwKkAQUAAABAQE0CAOYGAAAATQICHQcAAACfAQICvAIBKggAAACfAgIBggABAAkDAQQAAABAAwIDAwMEBAAAQEADBQMGAwcAAQABGAACAAAAAAADAAAAAAAAAgAAAAEAAAAAAA=="
        )

        chunk = parse_chunk(raw)
        source = decompile_chunk(chunk)

        self.assertIn(
            'local ReplicatedStorage: ReplicatedStorage = game:GetService("ReplicatedStorage")\nrequire(ReplicatedStorage.Packages.GameAnalytics):initClient()',
            source,
        )
        self.assertNotIn('require(game:GetService("ReplicatedStorage")', source)


if __name__ == "__main__":
    unittest.main()
