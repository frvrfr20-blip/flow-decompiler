from __future__ import annotations

import base64
import struct


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def _take(self, size: int) -> bytes:
        if self.offset + size > len(self.data):
            raise ValueError(f"unexpected end of bytecode at offset {self.offset}")
        out = self.data[self.offset : self.offset + size]
        self.offset += size
        return out

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
        shift = 0
        while True:
            byte = self.read_u8()
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7
            if shift > 70:
                raise ValueError("varint is too large")


def maybe_base64_decode(data: bytes) -> bytes:
    stripped = b"".join(data.split())
    if not stripped:
        return data
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except Exception:
        return data
    return decoded if decoded else data
