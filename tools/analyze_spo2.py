#!/usr/bin/env python3
"""Analyze SR116 SpO2 session from sniffer ATT export."""

from __future__ import annotations

import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

CMD_NAMES = {
    0x01: "setTime",
    0x06: "getBattery",
    0x07: "openHR",
    0x08: "closeHR",
    0x0B: "liveHR",
    0x11: "hrEnd",
    0x14: "openTemp?",  # 20
    0x15: "tempSample?",  # 21
    0x17: "openCloseSpo2",  # 23
    0x18: "spo2Sample",  # 24
    0x1A: "setAppInfo",
    0x1D: "status",
    0x1E: "autoHR",
    0x21: "list21",
    0x22: "list22",
    0x25: "deviceInfo",
    0x2F: "audioState",
    0x37: "features",
    0x3D: "offlineCount",
    0x3E: "heartbeat",
    0x43: "teardown",
    0x44: "name",
}


def parse_jy(b: bytes) -> dict | None:
    if len(b) < 10 or b[:2] != b"\xfe\xfc":
        return None
    cmd, total, idx, ln = struct.unpack_from("<HHHH", b, 2)
    return {"cmd": cmd, "total": total, "idx": idx, "len": ln, "payload": b[10 : 10 + ln]}


def main() -> None:
    raw = Path("reports/att_fefc_spo2_raw.txt").read_text(encoding="ascii", errors="replace")
    frames = []
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
        blob = bytes.fromhex(val)
        frames.append(
            {
                "n": int(parts[0]),
                "t": t,
                "dir": "H->R" if h == "0x0017" else "R->H",
                "jy": parse_jy(blob),
                "blob": blob,
            }
        )
    if not frames:
        print("no frames")
        return

    # Use first connected-session cluster: prefer times near LE connect if multimodal
    # Sort and find largest contiguous cluster by gap > 30s
    frames.sort(key=lambda f: f["t"])
    clusters = [[frames[0]]]
    for f in frames[1:]:
        if f["t"] - clusters[-1][-1]["t"] > 30:
            clusters.append([f])
        else:
            clusters[-1].append(f)
    print(f"total_PDUs={len(frames)} clusters={len(clusters)}")
    for i, cl in enumerate(clusters):
        print(f"  cluster{i}: n={len(cl)} t={cl[0]['t']:.3f}..{cl[-1]['t']:.3f} span={cl[-1]['t']-cl[0]['t']:.3f}s")

    # Analyze each cluster, highlight SpO2 cmds
    for ci, cl in enumerate(clusters):
        t0 = cl[0]["t"]
        print(f"\n======== CLUSTER {ci} (t0={t0:.3f}) ========")
        hist = Counter()
        for f in cl:
            j = f["jy"]
            if not j:
                hist[("nonJY", f["dir"])] += 1
            else:
                hist[(f"0x{j['cmd']:02X}", f["dir"])] += 1
        print("CMD histogram:")
        for (cmd, d), n in sorted(hist.items(), key=lambda x: (-x[1], x[0])):
            name = ""
            if cmd.startswith("0x"):
                name = CMD_NAMES.get(int(cmd, 16), "")
            print(f"  {cmd:8} {d}: {n:3}  {name}")

        print("\nTimeline (0x3E collapsed):")
        streak = 0
        samples = []
        for f in cl:
            j = f["jy"]
            rel = f["t"] - t0
            if j and j["cmd"] == 0x3E and f["dir"] == "H->R" and j["len"] <= 1:
                streak += 1
                continue
            if streak:
                print(f"  ... ({streak}x host 0x3E) ...")
                streak = 0
            if not j:
                print(f"  rel={rel:7.3f} {f['dir']} NON-JY {f['blob'][:16].hex()}")
                continue
            name = CMD_NAMES.get(j["cmd"], "")
            pl = j["payload"]
            extra = ""
            if j["cmd"] == 0x17:
                extra = f" pl={pl.hex() or '(empty)'}"
            elif j["cmd"] == 0x18 and pl:
                # Expected: ts6 + spo2 u8 (APK). Try layouts.
                ts4 = struct.unpack_from("<I", pl, 0)[0] if len(pl) >= 4 else None
                spo2 = pl[-1]
                extra = f" spo2?={spo2} pl={pl.hex()} ts4={ts4}"
                try:
                    if ts4 and 1_600_000_000 < ts4 < 2_100_000_000:
                        extra += f" iso={datetime.fromtimestamp(ts4, timezone.utc).isoformat()}"
                except Exception:
                    pass
                samples.append((rel, spo2, pl.hex(), ts4))
            elif j["cmd"] in (0x07, 0x08, 0x14, 0x15, 0x11) or j["cmd"] in (0x17, 0x18):
                extra = f" pl={pl.hex() or '(empty)'}"
            elif pl:
                extra = f" pl={pl.hex()[:48]}"
            # Always print SpO2-related; print others unless boring list spam mid
            interesting = j["cmd"] in (
                0x17, 0x18, 0x07, 0x08, 0x0B, 0x11, 0x14, 0x15, 0x01, 0x1A, 0x1E, 0x06, 0x25, 0x44, 0x37, 0x3D, 0x43, 0x2F
            ) or (j["len"] > 0 and j["cmd"] not in (0x21, 0x22, 0x1D))
            if j["cmd"] in (0x21, 0x22) and j["len"] > 8:
                print(f"  rel={rel:7.3f} {f['dir']} cmd=0x{j['cmd']:02X}({name}) len={j['len']} (list chunk)")
                continue
            if j["cmd"] == 0x1D and f["dir"] == "R->H":
                print(f"  rel={rel:7.3f} {f['dir']} cmd=0x{j['cmd']:02X}(status) len={j['len']} pl={pl.hex()}")
                continue
            if interesting or j["cmd"] in (0x21, 0x22, 0x1D, 0x24, 0x2D):
                print(
                    f"  rel={rel:7.3f} abs={f['t']:10.3f} {f['dir']} "
                    f"cmd=0x{j['cmd']:02X}({name:14}) len={j['len']}{extra}"
                )
        if streak:
            print(f"  ... ({streak}x trailing 0x3E) ...")

        print("\nSpO2 sample table (0x18):")
        if not samples:
            print("  (none)")
        else:
            for rel, spo2, hx, ts4 in samples:
                print(f"  rel={rel:7.3f} val={spo2} ts4={ts4} hex={hx}")
            vals = [s[1] for s in samples]
            print(f"  n={len(vals)} range={min(vals)}..{max(vals)}")

        print("\nSpO2 open/close brackets (0x17/0x18 and neighbors):")
        for f in cl:
            j = f["jy"]
            if not j:
                continue
            if j["cmd"] in (0x17, 0x18, 0x14, 0x15, 0x07, 0x08, 0x11):
                print(
                    f"  rel={f['t']-t0:7.3f} {f['dir']} 0x{j['cmd']:02X} "
                    f"{CMD_NAMES.get(j['cmd'],'')} pl={j['payload'].hex()}"
                )


if __name__ == "__main__":
    main()
