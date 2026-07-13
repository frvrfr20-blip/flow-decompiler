from __future__ import annotations

import base64
import struct


class ChunkDecodeError(ValueError):
    def __init__(self, message: str, offset: int, section: str, proto_id: int | None = None):
        super().__init__(message)
        self.message = message
        self.offset = offset
        self.section = section
        self.proto_id = proto_id

    def __str__(self) -> str:
        proto = f", proto {self.proto_id}" if self.proto_id is not None else ""
        return f"{self.message} (offset {self.offset}, section {self.section}{proto})"


class Reader:
    def __init__(self, data: bytes, *, base_offset: int = 0, section: str = "chunk", proto_id: int | None = None):
        self.data = data
        self.offset = 0
        self.base_offset = base_offset
        self.section = section
        self.proto_id = proto_id

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    @property
    def absolute_offset(self) -> int:
        return self.base_offset + self.offset

    def set_context(self, section: str, proto_id: int | None = None) -> None:
        self.section = section
        self.proto_id = proto_id

    def _take(self, size: int) -> bytes:
        if size < 0 or size > self.remaining:
            raise ChunkDecodeError("unexpected end of bytecode", self.absolute_offset, self.section, self.proto_id)
        out = self.data[self.offset : self.offset + size]
        self.offset += size
        return out

    def subreader(self, size: int, *, section: str, proto_id: int | None = None) -> Reader:
        self.set_context(section, proto_id)
        if size < 0 or size > self.remaining:
            raise ChunkDecodeError("declared proto body exceeds remaining chunk", self.absolute_offset, "proto boundary", proto_id)
        start = self.absolute_offset
        return Reader(self._take(size), base_offset=start, section=section, proto_id=proto_id)

    def skip(self, size: int) -> None:
        self._take(size)

    def read_u8(self) -> int:
        return self._take(1)[0]

    def read_u32(self) -> int:
        return struct.unpack("<I", self._take(4))[0]

    def read_i32(self) -> int:
        return struct.unpack("<i", self._take(4))[0]

    def read_f32(self) -> float:
        return struct.unpack("<f", self._take(4))[0]

    def read_f64(self) -> float:
        return struct.unpack("<d", self._take(8))[0]

    def read_bytes(self, size: int) -> bytes:
        return self._take(size)

    def read_varint(self) -> int:
        return self.read_varint64()

    def read_varint64(self) -> int:
        result = 0
        for index in range(10):
            byte = self.read_u8()
            if index == 9 and (byte & 0xFE):
                raise ChunkDecodeError("varint is too large", self.absolute_offset, self.section, self.proto_id)
            result |= (byte & 0x7F) << (index * 7)
            if not byte & 0x80:
                return result
        raise ChunkDecodeError("varint is too large", self.absolute_offset, self.section, self.proto_id)


def maybe_base64_decode(data: bytes) -> bytes:
    stripped = b"".join(data.split())
    if not stripped:
        return data
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except Exception:
        return data
    return decoded if decoded else data
