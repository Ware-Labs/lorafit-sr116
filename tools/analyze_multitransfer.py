#!/usr/bin/env python3
"""Analyze multi-file offline audio transfer pattern from sniffer ATT export."""

from __future__ import annotations

import struct
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def parse_jy(b: bytes) -> dict | None:
    """JY frame: FE FC | cmd u16le | total u16le | idx u16le | len u16le | payload."""
    if len(b) < 10 or b[0:2] != b"\xfe\xfc":
        return None
    cmd, total, idx, ln = struct.unpack_from("<HHHH", b, 2)
    return {
        "cmd": cmd,
        "total": total,
        "idx": idx,
        "len": ln,
        "payload": b[10 : 10 + ln],
        "raw": b,
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    raw_path = root / "reports" / "att_fefc_multitransfer_raw.txt"
    lines = raw_path.read_text(encoding="ascii", errors="replace").splitlines()

    frames = []
    for line in lines:
        parts = line.strip().split("|")
        if len(parts) < 5:
            continue
        h = parts[3].strip().lower()
        if h not in ("0x0017", "0x0019"):
            continue
        val = parts[4].replace(":", "")
        if not val:
            continue
        blob = bytes.fromhex(val)
        jy = parse_jy(blob)
        frames.append(
            {
                "n": int(parts[0]),
                "t": float(parts[1]),
                "op": parts[2],
                "handle": int(h, 16),
                "dir": "H->R" if h == "0x0017" else "R->H",
                "jy": jy,
                "blob": blob,
            }
        )

    print(f"ATT 0x17/0x19 PDUs: {len(frames)}")
    print(f"time span: {frames[0]['t']:.3f} .. {frames[-1]['t']:.3f} s")

    # Command histogram by direction
    print("\n=== CMD histogram ===")
    by = Counter()
    for f in frames:
        j = f["jy"]
        if not j:
            by[("non-JY", f["dir"])] += 1
            continue
        by[(f"0x{j['cmd']:02X}", f["dir"])] += 1
    for (cmd, d), c in sorted(by.items(), key=lambda x: (-x[1], x[0])):
        print(f"  {cmd:8} {d}: {c}")

    # Compact timeline: skip keepalive floods, highlight key cmds
    KEY = {0x01, 0x1A, 0x1D, 0x21, 0x22, 0x2F, 0x34, 0x36, 0x3D, 0x40, 0x43, 0x25, 0x37, 0x44, 0x3D, 0x61}
    KEEP_SHOW = {0x3E}  # show first/last only

    print("\n=== Compact timeline (key cmds) ===")
    keepalive_streak = 0
    transfers = []  # list of dicts
    current = None

    def flush():
        nonlocal current
        if current:
            transfers.append(current)
            current = None

    for f in frames:
        j = f["jy"]
        if not j:
            if f["blob"][:1] != b"\xfe":
                print(f"  t={f['t']:8.3f} {f['dir']} NON-JY {f['blob'][:16].hex()}")
            continue
        cmd = j["cmd"]

        # Track transfer state machine
        if cmd == 0x40 and f["dir"] == "H->R":
            flush()
            current = {
                "prep_t": f["t"],
                "start_t": None,
                "end_t": None,
                "n_data": 0,
                "first_seq": None,
                "last_seq": None,
                "total_field": None,
                "start_ts": None,
                "end_ts": None,
                "bytes": 0,
                "select_before": None,
            }
        elif cmd == 0x34 and f["dir"] == "H->R" and j["len"] == 0:
            if current is None:
                current = {
                    "prep_t": None,
                    "start_t": f["t"],
                    "end_t": None,
                    "n_data": 0,
                    "first_seq": None,
                    "last_seq": None,
                    "total_field": None,
                    "start_ts": None,
                    "end_ts": None,
                    "bytes": 0,
                    "select_before": None,
                }
            else:
                current["start_t"] = f["t"]
        elif cmd == 0x34 and f["dir"] == "R->H" and j["len"] >= 6:
            if current is None:
                current = {
                    "prep_t": None,
                    "start_t": f["t"],
                    "end_t": None,
                    "n_data": 0,
                    "first_seq": None,
                    "last_seq": None,
                    "total_field": None,
                    "start_ts": None,
                    "end_ts": None,
                    "bytes": 0,
                    "select_before": None,
                }
            pl = j["payload"]
            ts = struct.unpack_from("<I", pl, 0)[0]
            current["n_data"] += 1
            current["bytes"] += max(0, len(pl) - 6)
            current["total_field"] = j["total"]
            if current["first_seq"] is None:
                current["first_seq"] = j["idx"]
                current["start_ts"] = ts
            current["last_seq"] = j["idx"]
            current["end_ts"] = ts
        elif cmd == 0x36:
            if current:
                current["end_t"] = f["t"]
                current["complete_dir"] = f["dir"]
                current["complete_payload"] = j["payload"].hex()
                if f["dir"] == "H->R":
                    flush()

        # Printing
        if cmd in (0x3E, 0x2F) and f["dir"] == "H->R" and j["len"] <= 1:
            keepalive_streak += 1
            continue
        if keepalive_streak:
            print(f"  ... ({keepalive_streak} host keepalives 0x3E/0x2F omitted) ...")
            keepalive_streak = 0

        interesting = cmd in KEY or (cmd == 0x34) or (j["len"] > 2)
        if not interesting and cmd not in (0x3D,):
            continue

        pl = j["payload"]
        extra = ""
        if cmd == 0x34 and f["dir"] == "R→H" and len(pl) >= 6:
            ts = struct.unpack_from("<I", pl, 0)[0]
            try:
                ts_s = datetime.fromtimestamp(ts, timezone.utc).isoformat()
            except Exception:
                ts_s = "?"
            # Only print first/last few of a run — mark mid
            extra = f" total={j['total']} idx={j['idx']} ts={ts}({ts_s}) opus_body={len(pl)-6}"
        elif cmd in (0x21, 0x22) and pl:
            extra = f" list_bytes={len(pl)} head={pl[:32].hex()}"
        elif cmd == 0x01:
            extra = f" select={pl.hex()}"
        elif cmd == 0x3D:
            extra = f" pl={pl.hex()}"
        elif cmd == 0x36:
            extra = f" pl={pl.hex()}"
        elif pl:
            extra = f" pl={pl.hex()[:40]}"

        # Suppress middle 0x34 data spam: print first 2 and every time idx==1 or idx==total
        if cmd == 0x34 and f["dir"] == "R->H":
            if j["idx"] not in (1, 2) and j["idx"] != j["total"] and j["idx"] % 50 != 0:
                continue

        print(
            f"  t={f['t']:8.3f} {f['dir']} cmd=0x{cmd:02X} "
            f"tot={j['total']} idx={j['idx']} len={j['len']}{extra}"
        )

    flush()
    if keepalive_streak:
        print(f"  ... ({keepalive_streak} trailing keepalives) ...")

    print("\n=== Detected transfer sessions ===")
    for i, tr in enumerate(transfers, 1):
        dur = None
        if tr.get("start_t") and tr.get("end_t"):
            dur = tr["end_t"] - tr["start_t"]
        audio_s = tr["n_data"] * 0.24 if tr["n_data"] else 0
        start_iso = end_iso = "?"
        if tr.get("start_ts"):
            try:
                start_iso = datetime.fromtimestamp(tr["start_ts"], timezone.utc).isoformat()
            except Exception:
                pass
        if tr.get("end_ts"):
            try:
                end_iso = datetime.fromtimestamp(tr["end_ts"], timezone.utc).isoformat()
            except Exception:
                pass
        line = (
            f"  #{i}: prep={tr.get('prep_t')} start={tr.get('start_t')} "
            f"end={tr.get('end_t')}"
        )
        if dur is not None:
            line += f" wall={dur:.3f}s"
        print(line)
        print(
            f"       packets idx {tr.get('first_seq')}..{tr.get('last_seq')} "
            f"/ total_field={tr.get('total_field')} n_data={tr['n_data']} "
            f"opus_bytes={tr['bytes']} audio~{audio_s:.2f}s"
        )
        print(
            f"       ts counter {tr.get('start_ts')}..{tr.get('end_ts')} "
            f"({start_iso} .. {end_iso})"
        )
        print(f"       complete_payload={tr.get('complete_payload')}")

    # File list parsing
    print("\n=== File listing payloads (0x21/0x22) ===")
    for f in frames:
        j = f["jy"]
        if not j or j["cmd"] not in (0x21, 0x22):
            continue
        pl = j["payload"]
        print(
            f"  t={f['t']:.3f} {f['dir']} cmd=0x{j['cmd']:02X} "
            f"tot={j['total']} idx={j['idx']} len={j['len']} raw={pl.hex()}"
        )
        # Try parse records after optional lead 0x00
        data = pl[1:] if pl[:1] == b"\x00" else pl
        # From prior: 16-byte records starting with u32le ts
        if j["cmd"] == 0x21:
            rec_size = 16
        else:
            rec_size = 8  # 0x22 looked like ts6-ish + flags in prior capture
        print(f"    trying rec_size={rec_size}:")
        for off in range(0, len(data) - rec_size + 1, rec_size):
            rec = data[off : off + rec_size]
            ts = struct.unpack_from("<I", rec, 0)[0]
            try:
                iso = datetime.fromtimestamp(ts, timezone.utc).isoformat()
            except Exception:
                iso = "?"
            print(f"      [{off:03d}] ts={ts} {iso} rest={rec[4:].hex()}")

    # 0x3D file count around transfers
    print("\n=== 0x3D (file count / audio state-ish) ===")
    for f in frames:
        j = f["jy"]
        if not j or j["cmd"] != 0x3D:
            continue
        print(
            f"  t={f['t']:8.3f} {f['dir']} tot={j['total']} idx={j['idx']} "
            f"pl={j['payload'].hex()}"
        )

    # 0x01 select commands
    print("\n=== 0x01 select / setTime-like ===")
    for f in frames:
        j = f["jy"]
        if not j or j["cmd"] != 0x01:
            continue
        print(
            f"  t={f['t']:8.3f} {f['dir']} pl={j['payload'].hex()}"
        )

    # Sequence between transfers: what host sends between 0x36 and next 0x40
    print("\n=== Inter-transfer host commands (between completes) ===")
    host_cmds = [
        (f["t"], f["jy"])
        for f in frames
        if f["dir"] == "H->R" and f["jy"]
    ]
    # Find 0x36 host echoes and following until 0x40
    for i, (t, j) in enumerate(host_cmds):
        if j["cmd"] != 0x36:
            continue
        print(f"  after host 0x36 @ {t:.3f} (pl={j['payload'].hex()}):")
        for t2, j2 in host_cmds:
            if t2 <= t:
                continue
            if j2["cmd"] == 0x40:
                print(f"    ... then 0x40 @ {t2:.3f}")
                break
            if j2["cmd"] in (0x3E, 0x2F) and j2["len"] <= 1:
                continue
            print(
                f"    t={t2:.3f} cmd=0x{j2['cmd']:02X} "
                f"tot={j2['total']} idx={j2['idx']} pl={j2['payload'].hex()}"
            )

    # Write markdown report path hint
    out = root / "reports" / "multitransfer_pattern.md"
    print(f"\n(analysis printed; writing {out.name} via companion)")


if __name__ == "__main__":
    main()
