#!/usr/bin/env python3
"""Analyze SR116 scroll/tap HID digitizer reports (Report ID 2 on handle 0x003d)."""

from __future__ import annotations

from pathlib import Path


def unpack(b: bytes) -> dict:
    """4-byte Input Report ID 2 (Report ID not included in ATT value)."""
    assert len(b) == 4
    tip = b[0] & 1
    in_range = (b[0] >> 1) & 1
    confidence = (b[0] >> 2) & 1
    contact_id = (b[0] >> 3) & 0x1F
    packed = b[1] | (b[2] << 8) | (b[3] << 16)
    x = packed & 0xFFF
    y = (packed >> 12) & 0xFFF
    return {
        "tip": tip,
        "in_range": in_range,
        "confidence": confidence,
        "contact_id": contact_id,
        "x": x,
        "y": y,
        "raw": b.hex(),
    }


def main() -> None:
    rows = []
    for line in Path("reports/hid_scroll_reports_raw.txt").read_text().splitlines():
        parts = line.strip().split("|")
        if len(parts) < 3:
            continue
        t = float(parts[1])
        b = bytes.fromhex(parts[2].replace(":", ""))
        if len(b) == 4:
            rows.append((t, unpack(b)))

    print(f"reports={len(rows)}")
    print(f"{'t':>8} raw      tip rng conf  X    Y   dy")
    prev_y = None
    for t, r in rows:
        dy = "" if prev_y is None else f"{r['y']-prev_y:+d}"
        print(
            f"{t:8.3f} {r['raw']}   {r['tip']}   {r['in_range']}   {r['confidence']}  "
            f"{r['x']:4d} {r['y']:4d}  {dy}"
        )
        prev_y = r["y"]

    print("\n=== Gestures (gap > 0.4s) ===")
    gest: list[list] = []
    cur: list = []
    for item in rows:
        if cur and item[0] - cur[-1][0] > 0.4:
            gest.append(cur)
            cur = []
        cur.append(item)
    if cur:
        gest.append(cur)

    for i, g in enumerate(gest, 1):
        ys = [r["y"] for _, r in g if r["tip"] or r["in_range"]]
        # include all Y for path
        ys_all = [r["y"] for _, r in g]
        y0, y1 = ys_all[0], ys_all[-1]
        dy = y1 - y0
        # Touch Y typically increases downward → dy>0 = finger down = scroll content up
        if dy > 20:
            meaning = "finger DOWN => scroll content UP"
        elif dy < -20:
            meaning = "finger UP => scroll content DOWN"
        else:
            meaning = "small/ambiguous"
        print(
            f"\nGesture {i}: n={len(g)} dur={g[-1][0]-g[0][0]:.3f}s "
            f"Y {y0}->{y1} (dy={dy:+d})  {meaning}"
        )
        for t, r in g:
            print(
                f"  {t:8.3f} {r['raw']} tip={r['tip']} X={r['x']} Y={r['y']}"
            )


if __name__ == "__main__":
    main()
