#!/usr/bin/env python3
"""Analyze SR116 heart-rate session from sniffer ATT export."""

from __future__ import annotations

import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

CMD_NAMES = {
    0x01: "setTime",
    0x06: "getBattery",
    0x07: "openHeartRate",
    0x08: "closeHeartRate",
    0x0B: "liveHeartRate",  # 11
    0x1A: "setAppInfo",
    0x1D: "status?",
    0x1E: "setAutoHR?",  # 30 decimal in some docs is auto-HR; 0x1E=30
    0x21: "list21",
    0x22: "list22",
    0x25: "deviceInfo",
    0x2D: "event?",
    0x2F: "audioState",
    0x34: "offlineAudio",
    0x36: "audioDone",
    0x37: "features?",
    0x3D: "offlineCount",
    0x3E: "heartbeat",
    0x40: "audioPrep",
    0x44: "name",
}


def parse_jy(b: bytes) -> dict | None:
    if len(b) < 10 or b[:2] != b"\xfe\xfc":
        return None
    cmd, total, idx, ln = struct.unpack_from("<HHHH", b, 2)
    return {
        "cmd": cmd,
        "total": total,
        "idx": idx,
        "len": ln,
        "payload": b[10 : 10 + ln],
    }


def main() -> None:
    raw = Path("reports/att_fefc_heartrate_raw.txt").read_text(encoding="ascii", errors="replace")
    frames = []
    t0 = None
    for line in raw.splitlines():
        parts = line.strip().split("|")
        if len(parts) < 5:
            continue
        h = parts[3].lower()
        if h not in ("0x0017", "0x0019"):
            continue
        val = parts[4].replace(":", "")
        if not val:
            continue
        t = float(parts[1])
        if t0 is None:
            t0 = t
        blob = bytes.fromhex(val)
        frames.append(
            {
                "n": int(parts[0]),
                "t": t,
                "rel": t - t0,
                "dir": "H->R" if h == "0x0017" else "R->H",
                "jy": parse_jy(blob),
                "blob": blob,
            }
        )

    print(f"PDUs={len(frames)} absolute_t={frames[0]['t']:.3f}..{frames[-1]['t']:.3f}")
    print(f"session_rel=0..{frames[-1]['rel']:.3f}s (t0={t0:.3f})")

    print("\n=== CMD histogram ===")
    c = Counter()
    for f in frames:
        j = f["jy"]
        if not j:
            c[("nonJY", f["dir"])] += 1
        else:
            c[(f"0x{j['cmd']:02X}", f["dir"])] += 1
    for (cmd, d), n in sorted(c.items(), key=lambda x: (-x[1], x[0])):
        name = CMD_NAMES.get(int(cmd, 16), "") if cmd.startswith("0x") else ""
        print(f"  {cmd:8} {d}: {n:3}  {name}")

    print("\n=== Full timeline (keepalives collapsed) ===")
    streak = 0
    hr_samples = []
    for f in frames:
        j = f["jy"]
        if j and j["cmd"] == 0x3E and f["dir"] == "H->R" and j["len"] <= 1:
            streak += 1
            continue
        if streak:
            print(f"  ... ({streak}x host 0x3E keepalive) ...")
            streak = 0
        if not j:
            print(f"  rel={f['rel']:7.3f} {f['dir']} NON-JY {f['blob'][:20].hex()}")
            continue
        name = CMD_NAMES.get(j["cmd"], "")
        pl = j["payload"]
        extra = ""
        if j["cmd"] == 0x0B and len(pl) >= 7:
            # APK: ts6 + heart_rate u8 — often ts as 4 or 6 bytes LE
            # Prior vector: FEFC 0B00 0100 0100 0700 29FA656900 00 5F = ts then 00? then bpm 0x5F=95
            if len(pl) >= 7:
                ts4 = struct.unpack_from("<I", pl, 0)[0]
                # try layouts
                bpm_candidates = []
                if len(pl) == 7:
                    bpm_candidates.append(("ts4+pad2+bpm?", pl[6], pl.hex()))
                if len(pl) >= 8:
                    bpm_candidates.append(("ts4+u16+bpm", pl[6] if len(pl) == 7 else pl[-1], pl.hex()))
                # common: 6-byte ts + bpm
                if len(pl) >= 7:
                    bpm = pl[-1]
                    prefix = pl[:-1]
                    extra = f" bpm={bpm} prefix={prefix.hex()} ts4={ts4}"
                    try:
                        iso = datetime.fromtimestamp(ts4, timezone.utc).isoformat()
                        extra += f" ts4_iso={iso}"
                    except Exception:
                        pass
                    hr_samples.append((f["rel"], f["t"], bpm, pl.hex(), ts4))
        elif j["cmd"] in (0x07, 0x08):
            extra = f" pl={pl.hex() or '(empty)'}"
        elif pl:
            extra = f" pl={pl.hex()[:48]}"
        print(
            f"  rel={f['rel']:7.3f} abs={f['t']:10.3f} {f['dir']} "
            f"cmd=0x{j['cmd']:02X}({name:14}) len={j['len']}{extra}"
        )
    if streak:
        print(f"  ... ({streak}x trailing 0x3E) ...")

    print("\n=== Heart-rate sample table (cmd 0x0B) ===")
    if not hr_samples:
        print("  (none)")
    else:
        print(f"  n={len(hr_samples)}")
        for rel, abs_t, bpm, hx, ts4 in hr_samples:
            print(f"  rel={rel:7.3f} bpm={bpm:3} ts4={ts4} hex={hx}")
        bpms = [b for _, _, b, _, _ in hr_samples]
        print(f"  bpm range={min(bpms)}..{max(bpms)} mean={sum(bpms)/len(bpms):.1f}")
        if len(hr_samples) >= 2:
            dts = [hr_samples[i][0] - hr_samples[i - 1][0] for i in range(1, len(hr_samples))]
            print(
                f"  interval_s min={min(dts):.3f} med={sorted(dts)[len(dts)//2]:.3f} "
                f"max={max(dts):.3f}"
            )

    # Open/close bracketing
    print("\n=== Open/stream/close brackets ===")
    for f in frames:
        j = f["jy"]
        if not j:
            continue
        if j["cmd"] in (0x07, 0x08, 0x0B) or (
            j["cmd"] == 0x1E
        ):
            print(
                f"  rel={f['rel']:7.3f} {f['dir']} 0x{j['cmd']:02X} "
                f"{CMD_NAMES.get(j['cmd'],'')} pl={j['payload'].hex()}"
            )


if __name__ == "__main__":
    main()
