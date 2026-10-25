"""JY FE FC framing used on GATT 0x33F3 / 0x33F4."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional


HEADER_LEN = 10
MAGIC = b"\xfe\xfc"


@dataclass(frozen=True)
class JyFrame:
    cmd: int
    total: int
    idx: int
    payload: bytes

    @property
    def length(self) -> int:
        return len(self.payload)

    def pack(self) -> bytes:
        return pack_jy(self.cmd, self.payload, total=self.total, idx=self.idx)


def pack_jy(
    cmd: int,
    payload: bytes = b"",
    *,
    total: int = 1,
    idx: int = 1,
) -> bytes:
    """Build FE FC | cmd|total|idx|len (all u16le) | payload."""
    if not (0 <= cmd <= 0xFFFF):
        raise ValueError(f"cmd out of range: {cmd}")
    if len(payload) > 0xFFFF:
        raise ValueError("payload too large")
    return MAGIC + struct.pack("<HHHH", cmd, total, idx, len(payload)) + payload


def parse_jy(data: bytes | bytearray) -> Optional[JyFrame]:
    """Parse one JY PDU. Returns None if not FE FC or truncated."""
    if len(data) < HEADER_LEN or bytes(data[:2]) != MAGIC:
        return None
    cmd, total, idx, ln = struct.unpack_from("<HHHH", data, 2)
    if len(data) < HEADER_LEN + ln:
        return None
    return JyFrame(cmd=cmd, total=total, idx=idx, payload=bytes(data[HEADER_LEN : HEADER_LEN + ln]))
