#!/usr/bin/env python3
"""Parse FE FC protocol frames extracted from ring-hack-capture.pcapng via tshark."""

from __future__ import annotations

import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def parse_fefc(b: bytes) -> dict | None:
    if len(b) < 3 or b[0:2] != b"\xfe\xfc":
        return None
    cmd = b[2]
    if len(b) < 9:
        return {"cmd": cmd, "short": True, "raw": b}
    a = struct.unpack_from("<H", b, 3)[0]
    bb = struct.unpack_from("<H", b, 5)[0]
    c = struct.unpack_from("<H", b, 7)[0]
    return {
        "cmd": cmd,
        "a": a,
        "b": bb,
        "c": c,
        "payload": b[9:],
        "len": len(b),
        "short": False,
        "raw": b,
    }


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    raw_path = root / "reports" / "att_fefc_raw.txt"
    lines = raw_path.read_text(encoding="ascii", errors="replace").splitlines()
    frames = []
    for line in lines:
        parts = line.strip().split("|")
        if len(parts) < 5:
            continue
        handle_s = parts[3].strip()
        # Skip multi-handle discovery rows accidentally exported
        if "," in handle_s or not handle_s.startswith("0x"):
            continue
        if handle_s.lower() not in ("0x0017", "0x0019"):
            continue
        val = parts[4].replace(":", "")
        if not val:
            continue
        frames.append(
            {
                "n": int(parts[0]),
                "t": float(parts[1]),
                "op": parts[2],
                "handle": int(handle_s, 16),
                "val": bytes.fromhex(val),
            }
        )
    print(f"frames={len(frames)}")

    by_cmd: dict[int, list] = defaultdict(list)
    non = []
    for f in frames:
        p = parse_fefc(f["val"])
        if p is None:
            non.append(f)
            continue
        if p.get("short"):
            continue
        by_cmd[p["cmd"]].append((f, p))

    print("\nnon-FEFC / odd:")
    for f in non[:10]:
        print(f"  n={f['n']} h=0x{f['handle']:04X} {f['val'].hex()}")

    print("\nCMD histogram:")
    for cmd in sorted(by_cmd):
        dirs = Counter(("W" if f["handle"] == 0x17 else "N") for f, _ in by_cmd[cmd])
        lens = [p["len"] for _, p in by_cmd[cmd]]
        print(
            f"  0x{cmd:02X}: n={len(by_cmd[cmd]):3d} dirs={dict(dirs)} "
            f"len={min(lens)}..{max(lens)}"
        )

    bulk = by_cmd.get(0x34, [])
    print(f"\n=== Bulk cmd 0x34: {len(bulk)} PDUs ===")
    payloads = []
    seq = []
    for f, p in bulk:
        seq.append(p["b"])
        payloads.append(p["payload"])
        print(
            f"  t={f['t']:8.3f} a={p['a']:#06x} b={p['b']:#06x} c={p['c']:#06x} "
            f"plen={len(p['payload']):3d} head={p['payload'][:20].hex()}"
        )
    if seq:
        expected = list(range(seq[0], seq[0] + len(seq)))
        print(f"seq contiguous: {seq == expected} ({seq[0]}..{seq[-1]})")
    total = sum(len(p) for p in payloads)
    print(f"total 0x34 payload bytes: {total}")

    if payloads:
        blob = b"".join(payloads)
        Path(root / "reports" / "bulk_0x34.bin").write_bytes(blob)
        print(f"wrote reports/bulk_0x34.bin ({len(blob)} bytes)")
        # entropy-ish
        counts = Counter(blob)
        import math

        ent = -sum((c / len(blob)) * math.log2(c / len(blob)) for c in counts.values())
        print(f"shannon entropy: {ent:.3f} bits/byte (8.0 = random)")
        print(f"first 64 bytes: {blob[:64].hex()}")
        print(f"ascii-ish: {blob[:64]!r}")
        for off in range(0, 12):
            if off + 4 <= len(payloads[0]):
                ts = struct.unpack_from("<I", payloads[0], off)[0]
                if 1_600_000_000 < ts < 2_100_000_000:
                    print(
                        f"  unix@+{off}: {ts} = "
                        f"{datetime.fromtimestamp(ts, timezone.utc).isoformat()}"
                    )

    print("\n=== cmd 0x21 (candidate file list) ===")
    for f, p in by_cmd.get(0x21, []):
        print(
            f"  t={f['t']:.3f} h=0x{f['handle']:04X} a={p['a']} b={p['b']} c={p['c']} "
            f"plen={len(p['payload'])}"
        )
        pl = p["payload"]
        print(f"    head={pl[:48].hex()}")
        # Try records of 16 bytes after optional lead byte
        for lead in (0, 1):
            data = pl[lead:]
            if len(data) < 16:
                continue
            print(f"    try lead={lead}:")
            for i in range(0, min(len(data), 64), 16):
                chunk = data[i : i + 16]
                if len(chunk) < 8:
                    break
                ts = struct.unpack_from("<I", chunk, 0)[0]
                rest = chunk[4:]
                ts_s = ""
                if 1_600_000_000 < ts < 2_100_000_000:
                    ts_s = datetime.fromtimestamp(ts, timezone.utc).isoformat()
                print(f"      [{i:02d}] ts={ts:#x}/{ts_s} rest={rest.hex()}")

    print("\n=== notable control cmds ===")
    for cmd in (0x01, 0x1A, 0x1D, 0x22, 0x2F, 0x36, 0x3D, 0x3E, 0x40, 0x43, 0x25, 0x37, 0x44):
        items = by_cmd.get(cmd, [])
        if not items:
            continue
        print(f"cmd 0x{cmd:02X} ({len(items)}):")
        for f, p in items[:6]:
            print(
                f"  t={f['t']:8.3f} h=0x{f['handle']:04X} a={p['a']:#06x} "
                f"b={p['b']:#06x} c={p['c']:#06x} pl={p['payload'].hex()}"
            )
        if len(items) > 6:
            print(f"  ... +{len(items)-6} more")

    # Transfer window summary
    if bulk:
        t0, t1 = bulk[0][0]["t"], bulk[-1][0]["t"]
        print(f"\nTransfer window: {t0:.3f}s .. {t1:.3f}s ({t1-t0:.3f}s)")
        # surrounding host cmds
        print("Host writes in [t0-2, t1+2]:")
        for f in frames:
            if f["handle"] != 0x17:
                continue
            if t0 - 2 <= f["t"] <= t1 + 2:
                p = parse_fefc(f["val"])
                if p and not p.get("short"):
                    print(
                        f"  t={f['t']:.3f} cmd=0x{p['cmd']:02X} "
                        f"a={p['a']:#06x} b={p['b']:#06x} c={p['c']:#06x} "
                        f"pl={p['payload'].hex()}"
                    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
