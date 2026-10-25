#!/usr/bin/env python3
"""Analyze SR116 steps / daily health sync from sniffer ATT export."""

from __future__ import annotations

import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

CMD = {
    0x01: "setTime",
    0x04: "vibrateLED",
    0x06: "getBattery",
    0x07: "openHR",
    0x08: "closeHR",
    0x0B: "liveHR",
    0x1A: "setAppInfo",
    0x1D: "status",
    0x1E: "autoHR",
    0x15: "tempSample",  # 21
    0x14: "openTemp",  # 20
    0x17: "spo2Ctrl",
    0x18: "spo2Sample",
    0x1B: "multiSport?",  # 27
    0x1D: "status",
    0x1C: "appRunning?",  # 28
    0x1D: "status",
    0x1F: "?",
    0x21: "list21",
    0x22: "list22",
    0x24: "?",
    0x25: "deviceInfo",
    0x29: "getStepInfo",  # 41? wait 29=0x1D conflict
    # Fix numeric:
    # 29 decimal = 0x1D — but 0x1D used as status in our captures. APK getStepInfo is cmd 29.
    # 33 = 0x21 getStepCountInfo — but 0x21 is list in audio path. Same cmd space!
    # Actually ALL are one cmd namespace. So 0x21 might be step history OR file list depending on context?
    # From lord-the-ring: 33 getStepCountInfo, 21 is openCloseTemperature reply path...
    # Recheck ledger:
    # 20 openCloseTemperature
    # 21 temperature sample
    # 23/24 spo2
    # 29 getStepInfo
    # 33 getStepCountInfo(day)
    # 34 getSleepData
    # 36 getHealthRecord
    # 42/43/45 terminators
}


def parse_jy(b: bytes):
    if len(b) < 10 or b[:2] != b"\xfe\xfc":
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


def ts_iso(ts: int) -> str:
    try:
        if 1_600_000_000 < ts < 2_100_000_000:
            return datetime.fromtimestamp(ts, timezone.utc).isoformat()
    except Exception:
        pass
    return "?"


def main() -> None:
    frames = []
    for line in Path("reports/att_fefc_steps_raw.txt").read_text().splitlines():
        p = line.strip().split("|")
        if len(p) < 5:
            continue
        h = p[3].lower()
        if h not in ("0x0017", "0x0019"):
            continue
        val = p[4].replace(":", "")
        if not val:
            continue
        blob = bytes.fromhex(val)
        t = float(p[1])
        frames.append(
            {
                "n": int(p[0]),
                "t": t,
                "dir": "H->R" if h == "0x0017" else "R->H",
                "jy": parse_jy(blob),
                "blob": blob,
            }
        )
    if not frames:
        print("no frames")
        return
    t0 = frames[0]["t"]
    print(f"PDUs={len(frames)} t={frames[0]['t']:.3f}..{frames[-1]['t']:.3f} span={frames[-1]['t']-t0:.3f}s")

    hist = Counter()
    for f in frames:
        j = f["jy"]
        if not j:
            hist[("nonJY", f["dir"])] += 1
        else:
            hist[(f"0x{j['cmd']:02X}", f["dir"])] += 1
    print("\n=== CMD histogram ===")
    for (c, d), n in sorted(hist.items(), key=lambda x: (-x[1], x[0])):
        print(f"  {c:8} {d}: {n}")

    NAMES = {
        0x01: "setTime",
        0x04: "vibrateLED",
        0x06: "battery",
        0x08: "closeHR",
        0x1A: "appInfo",
        0x1D: "getStepInfo/status",  # ambiguous historically; decode payload
        0x1E: "autoHR",
        0x21: "stepBuckets/list",  # 33d
        0x22: "sleep/list",  # 34d
        0x24: "healthRec/?",  # 36d = 0x24
        0x25: "deviceInfo",
        0x2A: "syncDone?",  # 42
        0x2B: "syncDone?",  # 43
        0x2D: "syncDone?",  # 45
        0x2F: "audioState",
        0x37: "features",
        0x3D: "offlineAudioCount",
        0x3E: "heartbeat",
        0x43: "teardown",
        0x44: "name",
    }

    print("\n=== Full timeline ===")
    streak = 0
    for f in frames:
        j = f["jy"]
        rel = f["t"] - t0
        if j and j["cmd"] == 0x3E and f["dir"] == "H->R" and j["len"] <= 1:
            streak += 1
            continue
        if streak:
            print(f"  ... ({streak}x host 0x3E) ...")
            streak = 0
        if not j:
            print(f"  rel={rel:6.3f} {f['dir']} NON-JY {f['blob'][:20].hex()}")
            continue
        name = NAMES.get(j["cmd"], "")
        pl = j["payload"]
        extra = decode_payload(j["cmd"], pl, f["dir"])
        print(
            f"  rel={rel:6.3f} abs={f['t']:8.3f} {f['dir']} "
            f"cmd=0x{j['cmd']:02X}({name:18}) tot={j['total']} idx={j['idx']} "
            f"len={j['len']}{extra}"
        )
    if streak:
        print(f"  ... ({streak}x trailing 0x3E) ...")


def decode_payload(cmd: int, pl: bytes, direction: str) -> str:
    if not pl:
        return " pl=(empty)"
    # getStepInfo reply (cmd 29 = 0x1D): ts6 + steps u32 + cal u16 + dist u16 — OR our status 14 bytes
    if cmd == 0x1D and len(pl) >= 14:
        ts = struct.unpack_from("<I", pl, 0)[0]
        # try step info layout at offset 6: steps u32
        if len(pl) >= 14:
            steps = struct.unpack_from("<I", pl, 6)[0]
            cal = struct.unpack_from("<H", pl, 10)[0]
            dist = struct.unpack_from("<H", pl, 12)[0]
            # also try status-like mid fields
            return (
                f" pl={pl.hex()} ts={ts}({ts_iso(ts)}) "
                f"asStepInfo: steps={steps} cal={cal} dist={dist}"
            )
    if cmd == 0x21 and pl:
        # step buckets: items 16B: ts6, duration u16, steps u32, cal u16, dist u16
        return decode_items(pl, 16, "stepBucket")
    if cmd == 0x22 and pl:
        # sleep 8B: ts6, quality u8, move u8 — or our list format
        return decode_items(pl, 8, "sleep/list")
    if cmd == 0x24 and pl:
        # health 14B: ts6, hr u8, spo2 u8, temp i16, u32
        return decode_health(pl)
    if cmd == 0x04:
        return f" pl={pl.hex()} (LED/vibrate mode?)"
    if cmd in (0x2A, 0x2B, 0x2D):
        ts = struct.unpack_from("<I", pl, 0)[0] if len(pl) >= 4 else None
        return f" pl={pl.hex()} ts={ts}({ts_iso(ts) if ts else '?'}) TERMINATOR?"
    if cmd == 0x06 and len(pl) >= 2:
        return f" battery={pl[0]}% charging={pl[1]}"
    if cmd == 0x25 and len(pl) >= 12:
        fw = struct.unpack_from("<H", pl, 0)[0]
        mac = pl[2:8].hex(":")
        return f" fw={fw} mac={mac} rest={pl[8:].hex()}"
    if cmd == 0x01 and len(pl) >= 6 and direction == "R->H":
        y = struct.unpack_from("<H", pl, 0)[0]
        return f" calendar={y}-{pl[2]:02d}-{pl[3]:02d} {pl[4]:02d}:{pl[5]:02d}:{pl[6] if len(pl)>6 else 0:02d}"
    return f" pl={pl.hex()[:64]}"


def decode_items(pl: bytes, size: int, label: str) -> str:
    data = pl[1:] if pl[:1] == b"\x00" and len(pl) > size else pl
    lines = [f" {label} bytes={len(pl)}"]
    # try with and without lead byte
    for lead, blob in ((0, pl), (1, pl[1:] if len(pl) > 1 else b"")):
        if len(blob) < 4:
            continue
        n = len(blob) // size
        if n == 0:
            continue
        lines.append(f"  try lead={lead} n={n} size={size}:")
        for i in range(min(n, 8)):
            rec = blob[i * size : (i + 1) * size]
            ts = struct.unpack_from("<I", rec, 0)[0]
            rest = rec[4:].hex()
            lines.append(f"    [{i}] ts={ts}({ts_iso(ts)}) rest={rest}")
        if n > 8:
            lines.append(f"    ... +{n-8} more")
        break
    return "\n" + "\n".join(lines)


def decode_health(pl: bytes) -> str:
    lines = [f" health-ish pl={pl.hex()}"]
    # single record or multiple 14-byte
    data = pl
    if len(data) >= 14:
        for i in range(0, len(data) - 13, 14):
            rec = data[i : i + 14]
            ts = struct.unpack_from("<I", rec, 0)[0]
            # layouts to try:
            # A: ts4 + pad2 + hr + spo2 + temp_i16 + u32
            hr_a, spo2_a = rec[6], rec[7]
            temp_a = struct.unpack_from("<h", rec, 8)[0]
            # B: ts6 + hr + spo2 + temp + u32 at 6
            hr_b, spo2_b = rec[6], rec[7] if len(rec) > 7 else 0
            lines.append(
                f"  rec@{i} ts={ts}({ts_iso(ts)}) "
                f"hr={hr_a} spo2={spo2_a} temp_raw={temp_a} rest={rec[8:].hex()}"
            )
    elif len(data) >= 7:
        ts = struct.unpack_from("<I", data, 0)[0]
        lines.append(f"  short ts={ts} rest={data[4:].hex()}")
    return "\n" + "\n".join(lines)


if __name__ == "__main__":
    main()
