#!/usr/bin/env python3
"""Extract FE FC 0x34 bulk payloads from tshark ATT export into a binary blob."""

from __future__ import annotations

import struct
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    raw = (root / "reports" / "att_fefc_raw.txt").read_text(encoding="ascii", errors="replace")
    chunks: list[bytes] = []
    meta: list[str] = []
    for line in raw.splitlines():
        parts = line.strip().split("|")
        if len(parts) < 5 or parts[3].lower() != "0x0019":
            continue
        v = bytes.fromhex(parts[4].replace(":", ""))
        if len(v) < 12 or v[:3] != b"\xfe\xfc\x34":
            continue
        mode, seq = struct.unpack(">HH", v[3:7])
        length = struct.unpack("<H", v[8:10])[0]
        payload = v[10 : 10 + length]
        if len(payload) < 8:
            continue
        ts = struct.unpack_from("<I", payload, 0)[0]
        # Observed: ts(4) + 00 00 + body
        body = payload[6:]
        chunks.append(body)
        meta.append(f"seq={seq} ts={ts} body_len={len(body)}")

    out = root / "reports" / "transfer_0x34_bodies.bin"
    out.write_bytes(b"".join(chunks))
    (root / "reports" / "transfer_0x34_meta.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
    print(f"chunks={len(chunks)} bytes={out.stat().st_size} -> {out}")


if __name__ == "__main__":
    main()
