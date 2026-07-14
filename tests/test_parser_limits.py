import base64
import struct
import unittest

from luau_decompiler.chunk import ChunkDecodeError, ParseLimits, parse_chunk
from luau_decompiler.decompile import decompile_chunk
from luau_decompiler.disasm import encode_abc, encode_ad


OFFICIAL_LUAU_0729_V12 = base64.b64decode(
    "DAMDA2FkZAR3cmFwBXByaW50AAMeAwIAAAgAAiECAAEWAgIAAAABAQEYAAABAAAAAAABLAQBAQAAAAUJAQAABgIAAAQDAgAVAQMAFgEAAAAAAgIBGAAAAAAAAgAAAAAAWAUAAAEKAAtBAAAAQAAAAEABAQBGAAAADAIDAAAAIEAGAwEABAQoABUDAgAVAgABFgABAAQGAAYBAwMEAAAgQAIAAQEAARgAAAEAAQAAAAAAAQEAAAAAABwC"
)


def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | 0x80 if value else byte)
        if not value:
            return bytes(out)


def string_table(strings):
    out = bytearray(varint(len(strings)))
    for value in strings:
        raw = value.encode("utf-8")
        out += varint(len(raw))
        out += raw
    return bytes(out)


def proto_body(
    *,
    maxstacksize=2,
    flags=0,
    numupvalues=0,
    typeinfo=b"",
    words=(),
    constants=b"",
    constant_count=0,
    children=(),
    debug_name=0,
    lineinfo=False,
    debug_locals=(),
    debug_upvalues=(),
    feedback=(),
    cost=None,
    tail=b"",
):
    out = bytearray([maxstacksize, 0, numupvalues, 0, flags])
    out += varint(len(typeinfo))
    out += typeinfo
    out += varint(len(words))
    for word in words:
        out += struct.pack("<I", word)
    out += varint(constant_count)
    out += constants
    out += varint(len(children))
    for child in children:
        out += varint(child)
    out += varint(0)
    out += varint(debug_name)
    if lineinfo:
        out += bytes([1, 0])
        out += bytes([0] * len(words))
        out += struct.pack("<i", 0) * len(words)
    else:
        out += b"\0"
    if debug_locals or debug_upvalues:
        out += b"\1" + varint(len(debug_locals))
        for name, start, end, reg in debug_locals:
            out += varint(name) + varint(start) + varint(end) + bytes([reg])
        out += varint(len(debug_upvalues))
        for name in debug_upvalues:
            out += varint(name)
    else:
        out += b"\0"
    out += varint(len(feedback))
    for kind, pc in feedback:
        out += bytes([kind]) + varint(pc)
    if cost is not None:
        out += varint(cost)
    out += tail
    return bytes(out)


def make_chunk(*, version=11, strings=(), bodies=None, main_proto=0, userdata_remaps=b"\0"):
    if bodies is None:
        bodies = [proto_body(words=[encode_abc("RETURN", 0, 1, 0)])]
    out = bytearray([version, 3])
    out += string_table(strings)
    out += userdata_remaps
    out += varint(len(bodies))
    for body in bodies:
        if version >= 12:
            out += varint(len(body))
        out += body
    out += varint(main_proto)
    return bytes(out)


def constant(tag, payload=b""):
    return bytes([tag]) + payload


class ParserLimitTests(unittest.TestCase):
    def assert_decode_error(self, data, *, section, limits=None, proto_id=None):
        with self.assertRaises(ChunkDecodeError) as raised:
            parse_chunk(data, limits)
        error = raised.exception
        self.assertEqual(error.section, section)
        self.assertIsInstance(error.offset, int)
        self.assertIn("offset", str(error))
        self.assertIn(section, str(error))
        if proto_id is not None:
            self.assertEqual(error.proto_id, proto_id)
            self.assertIn(f"proto {proto_id}", str(error))
        return error

    def test_parse_limits_reject_negative_values(self):
        with self.assertRaises(ValueError):
            ParseLimits(max_protos=-1)

    def test_limit_boundaries_for_chunk_strings_and_protos(self):
        data = make_chunk(strings=["x"])
        self.assertEqual(parse_chunk(data, ParseLimits(max_chunk_bytes=len(data))).strings, ["x"])
        self.assert_decode_error(data, section="chunk", limits=ParseLimits(max_chunk_bytes=len(data) - 1))
        self.assertEqual(parse_chunk(data, ParseLimits(max_strings=1)).strings, ["x"])
        self.assert_decode_error(data, section="strings", limits=ParseLimits(max_strings=0))
        self.assertEqual(parse_chunk(data, ParseLimits(max_string_bytes=1)).strings, ["x"])
        self.assert_decode_error(data, section="string bytes", limits=ParseLimits(max_string_bytes=0))
        self.assertEqual(len(parse_chunk(data, ParseLimits(max_protos=1)).protos), 1)
        self.assert_decode_error(data, section="protos", limits=ParseLimits(max_protos=0))

    def test_instruction_limits_are_checked_before_word_reads(self):
        body = proto_body(words=[encode_abc("RETURN", 0, 1, 0)])
        data = make_chunk(bodies=[body, body])
        self.assertEqual(len(parse_chunk(data, ParseLimits(max_instructions_per_proto=1)).protos[0].code_words), 1)
        self.assert_decode_error(data, section="instructions", limits=ParseLimits(max_instructions_per_proto=0), proto_id=0)
        self.assertEqual(len(parse_chunk(data, ParseLimits(max_total_instructions=2)).protos), 2)
        self.assert_decode_error(data, section="total instructions", limits=ParseLimits(max_total_instructions=1), proto_id=1)

    def test_nested_count_limits_are_checked_before_reads(self):
        one_constant = proto_body(constants=constant(0), constant_count=1)
        self.assertEqual(len(parse_chunk(make_chunk(bodies=[one_constant]), ParseLimits(max_constants_per_proto=1)).protos[0].constants), 1)
        self.assert_decode_error(make_chunk(bodies=[one_constant]), section="constants", limits=ParseLimits(max_constants_per_proto=0), proto_id=0)

        children = [proto_body(children=[1]), proto_body()]
        self.assertEqual(parse_chunk(make_chunk(bodies=children), ParseLimits(max_children_per_proto=1)).protos[0].child_protos, [1])
        self.assert_decode_error(make_chunk(bodies=children), section="child protos", limits=ParseLimits(max_children_per_proto=0), proto_id=0)

        locals_body = proto_body(debug_locals=[(0, 0, 0, 0)])
        self.assertEqual(len(parse_chunk(make_chunk(bodies=[locals_body]), ParseLimits(max_debug_locals_per_proto=1)).protos[0].debug_locals), 1)
        self.assert_decode_error(make_chunk(bodies=[locals_body]), section="debug locals", limits=ParseLimits(max_debug_locals_per_proto=0), proto_id=0)

        header_upvalue_body = proto_body(numupvalues=1)
        self.assertEqual(parse_chunk(make_chunk(bodies=[header_upvalue_body]), ParseLimits(max_upvalues_per_proto=1)).protos[0].numupvalues, 1)
        self.assert_decode_error(make_chunk(bodies=[header_upvalue_body]), section="upvalues", limits=ParseLimits(max_upvalues_per_proto=0), proto_id=0)

        debug_upvalues_body = proto_body(debug_upvalues=[0])
        self.assertEqual(len(parse_chunk(make_chunk(bodies=[debug_upvalues_body]), ParseLimits(max_upvalues_per_proto=1)).protos[0].debug_upvalues), 1)
        self.assert_decode_error(make_chunk(bodies=[debug_upvalues_body]), section="debug upvalues", limits=ParseLimits(max_upvalues_per_proto=0), proto_id=0)

        lines_body = proto_body(words=[encode_abc("RETURN", 0, 1, 0)], lineinfo=True)
        self.assertEqual(len(parse_chunk(make_chunk(bodies=[lines_body]), ParseLimits(max_line_info_per_proto=1)).protos[0].lineinfo), 1)
        self.assert_decode_error(make_chunk(bodies=[lines_body]), section="line info", limits=ParseLimits(max_line_info_per_proto=0), proto_id=0)

        feedback_body = proto_body(words=[encode_abc("CALL", 0, 1, 1)], feedback=[(0, 0)])
        self.assertEqual(len(parse_chunk(make_chunk(bodies=[feedback_body]), ParseLimits(max_feedback_per_proto=1)).protos[0].feedback), 1)
        self.assert_decode_error(make_chunk(bodies=[feedback_body]), section="feedback", limits=ParseLimits(max_feedback_per_proto=0), proto_id=0)

        typeinfo_body = proto_body(typeinfo=b"x")
        self.assertEqual(parse_chunk(make_chunk(bodies=[typeinfo_body]), ParseLimits(max_typeinfo_bytes=1)).protos[0].typeinfo, b"x")
        self.assert_decode_error(make_chunk(bodies=[typeinfo_body]), section="typeinfo", limits=ParseLimits(max_typeinfo_bytes=0), proto_id=0)

    def test_nested_constant_payloads_are_bounded(self):
        table = proto_body(constants=constant(5, varint(2) + varint(0) + varint(0)), constant_count=1)
        self.assert_decode_error(make_chunk(bodies=[table]), section="table constant", limits=ParseLimits(max_constants_per_proto=1), proto_id=0)
        table_with_constants = proto_body(
            constants=constant(8, varint(2) + varint(0) + struct.pack("<i", -1) + varint(0) + struct.pack("<i", -1)), constant_count=1
        )
        self.assert_decode_error(make_chunk(bodies=[table_with_constants]), section="table_with_constants", limits=ParseLimits(max_constants_per_proto=1), proto_id=0)
        class_shape = proto_body(constants=constant(10, varint(0) + varint(2) + varint(0) + varint(0) + varint(0)), constant_count=1)
        self.assert_decode_error(make_chunk(bodies=[class_shape]), section="class_shape properties", limits=ParseLimits(max_constants_per_proto=1), proto_id=0)
        class_shape_methods = proto_body(constants=constant(10, varint(0) + varint(0) + varint(2) + varint(0) + varint(0)), constant_count=1)
        self.assert_decode_error(make_chunk(bodies=[class_shape_methods]), section="class_shape methods", limits=ParseLimits(max_constants_per_proto=1), proto_id=0)

    def test_serialized_indices_and_proto_graph_are_validated_iteratively(self):
        valid = make_chunk(strings=["x"], bodies=[proto_body(children=[1], constants=constant(6, varint(1)), constant_count=1), proto_body()])
        self.assertEqual(len(parse_chunk(valid, ParseLimits(max_proto_nesting=2)).protos), 2)
        self.assert_decode_error(valid, section="proto nesting", limits=ParseLimits(max_proto_nesting=1))

        self.assert_decode_error(make_chunk(bodies=[proto_body(children=[1])]), section="child proto index", proto_id=0)
        self.assert_decode_error(make_chunk(bodies=[proto_body(constants=constant(6, varint(1)), constant_count=1)]), section="closure proto index", proto_id=0)
        self.assert_decode_error(make_chunk(strings=["x"], bodies=[proto_body(constants=constant(3, varint(2)), constant_count=1)]), section="string table index", proto_id=0)
        self.assert_decode_error(make_chunk(strings=["x"], bodies=[proto_body(debug_name=2)]), section="string table index", proto_id=0)
        self.assert_decode_error(make_chunk(bodies=[proto_body()], main_proto=1), section="main proto")
        self.assert_decode_error(make_chunk(bodies=[proto_body(children=[0])]), section="proto graph cycle")

    def test_import_constant_indices_are_validated(self):
        invalid_import_id = (1 << 30) | (1 << 20)
        body = proto_body(constants=constant(4, struct.pack("<I", invalid_import_id)), constant_count=1)

        self.assert_decode_error(make_chunk(bodies=[body]), section="import constant index", proto_id=0)

    def test_userdata_remap_indices_cannot_repeat(self):
        remaps = b"\x01\0\x01\0\0"

        self.assert_decode_error(make_chunk(strings=["x"], userdata_remaps=remaps), section="userdata remaps")

    def test_proto_nesting_uses_the_deepest_path_through_shared_children(self):
        bodies = [
            proto_body(children=[2]),
            proto_body(children=[3]),
            proto_body(children=[4]),
            proto_body(children=[2]),
            proto_body(),
        ]

        self.assert_decode_error(make_chunk(bodies=bodies), section="proto nesting", limits=ParseLimits(max_proto_nesting=3))

    def test_truncation_and_malformed_varints_are_contextual(self):
        error = self.assert_decode_error(make_chunk()[:-1], section="main proto")
        self.assertIsNone(error.proto_id)
        self.assert_decode_error(bytes([11, 3]) + b"\x80" * 11, section="strings")

    def test_feedback_pcs_must_reference_instruction_words(self):
        body = proto_body(words=[encode_ad("GETIMPORT", 0, 0), 0, encode_abc("CALL", 0, 1, 1)], feedback=[(0, 1)])
        self.assert_decode_error(make_chunk(bodies=[body]), section="feedback pc", proto_id=0)

    def test_feedback_kind_must_be_calltarget(self):
        body = proto_body(words=[encode_abc("CALL", 0, 1, 1)], feedback=[(1, 0)])

        self.assert_decode_error(make_chunk(bodies=[body]), section="feedback kind", proto_id=0)

    def test_fixed_width_payloads_are_preflighted_before_list_materialization(self):
        truncated_code = bytearray(make_chunk(bodies=[proto_body()]))
        truncated_code[11] = 100
        self.assert_decode_error(bytes(truncated_code), section="instructions", proto_id=0)

        lines = make_chunk(bodies=[proto_body(words=[encode_abc("RETURN", 0, 1, 0)], lineinfo=True)])
        self.assert_decode_error(lines[:-5], section="line info", proto_id=0)

    def test_debug_local_ranges_and_registers_are_bounded_by_the_proto(self):
        words = [encode_abc("RETURN", 0, 1, 0)]
        bad_range = proto_body(words=words, debug_locals=[(0, 1, 0, 0)])
        self.assert_decode_error(make_chunk(bodies=[bad_range]), section="debug local pc", proto_id=0)
        bad_register = proto_body(maxstacksize=1, words=words, debug_locals=[(0, 0, 1, 1)])
        self.assert_decode_error(make_chunk(bodies=[bad_register]), section="debug local register", proto_id=0)

    def test_v12_uses_declared_proto_boundaries_and_cost_metadata(self):
        chunk = parse_chunk(OFFICIAL_LUAU_0729_V12)

        self.assertEqual(chunk.version, 12)
        self.assertEqual([proto.serialized_size for proto in chunk.protos], [30, 44, 88])
        self.assertEqual([proto.flags for proto in chunk.protos], [8, 0, 10])
        self.assertIsInstance(chunk.protos[0].cost, int)
        self.assertIsNone(chunk.protos[1].cost)
        self.assertIsInstance(chunk.protos[2].cost, int)
        self.assertEqual(chunk.main_proto, 2)
        self.assertEqual(chunk.trailing, b"")
        self.assertIn("return p0 + p1", decompile_chunk(chunk))

    def test_v12_rejects_bad_boundaries_and_accepts_declared_future_tail(self):
        body = proto_body(flags=8, feedback=[], cost=1 << 40)
        valid = make_chunk(version=12, bodies=[body])
        chunk = parse_chunk(valid)
        self.assertEqual(chunk.protos[0].serialized_size, len(body))
        self.assertEqual(chunk.protos[0].cost, 1 << 40)

        with_tail = make_chunk(version=12, bodies=[body + b"\xaa\xbb"])
        self.assertEqual(parse_chunk(with_tail).protos[0].cost, 1 << 40)

        too_small = bytearray(valid)
        too_small[5] = len(body) - 1
        self.assert_decode_error(bytes(too_small), section="cost", proto_id=0)
        too_large = bytearray(valid)
        too_large[5] = len(body) + 2
        self.assert_decode_error(bytes(too_large), section="proto boundary", proto_id=0)
        self.assert_decode_error(valid[:-2], section="proto boundary", proto_id=0)
        self.assert_decode_error(valid[:-1], section="main proto")


if __name__ == "__main__":
    unittest.main()
