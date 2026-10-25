#!/usr/bin/env python3
"""
LoraFit SR116 BLE exploration client (local-only, read-only by default).

Safe defaults:
  - scan / inspect / read (standard READ props only) / listen (explicit CCCD write)
  - No vendor command writes unless a future verified `replay` path is enabled
  - No network upload, analytics, or cloud dependency
  - Never deletes recordings

Windows: Bleak may show device IDs that are not classic MAC strings; pass the
address exactly as printed by `scan`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from bleak import BleakClient, BleakScanner
    from bleak.backends.characteristic import BleakGATTCharacteristic
except ImportError:
    print(
        "Missing dependency: bleak. Install with: pip install -r requirements.txt",
        file=sys.stderr,
    )
    raise SystemExit(1)


def _utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _props(char: BleakGATTCharacteristic) -> list[str]:
    # bleak exposes .properties as a list[str] on recent versions
    props = getattr(char, "properties", None)
    if props is None:
        return []
    if isinstance(props, (list, tuple, set)):
        return sorted(str(p) for p in props)
    return sorted(str(p) for p in props)


async def cmd_scan(args: argparse.Namespace) -> int:
    timeout = args.timeout
    print(f"Scanning for {timeout:.1f}s …")
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    rows = []
    for addr, (dev, adv) in devices.items():
        name = dev.name or adv.local_name or ""
        uuids = list(adv.service_uuids or [])
        rows.append(
            {
                "address": addr,
                "name": name,
                "rssi": adv.rssi,
                "service_uuids": uuids,
            }
        )
    rows.sort(key=lambda r: (r["name"] == "", r["name"], r["address"]))
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            uu = ",".join(r["service_uuids"][:6])
            if len(r["service_uuids"]) > 6:
                uu += ",…"
            marker = "  << SR116?" if "SR116" in (r["name"] or "").upper() else ""
            print(
                f"{r['address']:40}  RSSI={r['rssi']!s:>4}  "
                f"name={r['name']!r}  adv_services=[{uu}]{marker}"
            )
        print(f"\n{len(rows)} device(s). Use the Address column with `inspect`.")
    return 0


async def cmd_inspect(args: argparse.Namespace) -> int:
    address = args.address
    out: dict[str, Any] = {
        "address": address,
        "inspected_at": _utc_ts(),
        "services": [],
    }
    print(f"Connecting to {address} …")
    async with BleakClient(address, timeout=args.timeout) as client:
        out["is_connected"] = client.is_connected
        # Pairing/bonding state is platform-specific; do not claim security level.
        services = client.services
        for svc in services:
            svc_entry: dict[str, Any] = {
                "uuid": str(svc.uuid),
                "handle": getattr(svc, "handle", None),
                "description": getattr(svc, "description", None),
                "characteristics": [],
            }
            for char in svc.characteristics:
                char_entry: dict[str, Any] = {
                    "uuid": str(char.uuid),
                    "handle": getattr(char, "handle", None),
                    "properties": _props(char),
                    "descriptors": [],
                }
                for desc in char.descriptors:
                    char_entry["descriptors"].append(
                        {
                            "uuid": str(desc.uuid),
                            "handle": getattr(desc, "handle", None),
                        }
                    )
                svc_entry["characteristics"].append(char_entry)
            out["services"].append(svc_entry)

    text = json.dumps(out, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Wrote GATT map to {args.output}")
    else:
        print(text)

    # Human hints for known 16-bit services from nRF observations
    print("\n--- proprietary service hints (from prior nRF Connect, not semantic proof) ---")
    for svc in out["services"]:
        u = svc["uuid"].lower()
        if any(x in u for x in ("56ff", "ff12", "fef5")):
            print(f"Service {svc['uuid']}:")
            for c in svc["characteristics"]:
                print(f"  {c['uuid']}  handle={c['handle']}  props={c['properties']}")
    return 0


async def cmd_read(args: argparse.Namespace) -> int:
    print(
        "WARNING: Vendor-specific characteristic reads can have side effects on "
        "buggy firmware. Prefer standard Battery / Device Information UUIDs first.",
        file=sys.stderr,
    )
    address = args.address
    uuid = args.uuid
    async with BleakClient(address, timeout=args.timeout) as client:
        char = client.services.get_characteristic(uuid)
        if char is None:
            print(f"Characteristic {uuid} not found.", file=sys.stderr)
            return 1
        props = _props(char)
        if "read" not in [p.lower() for p in props]:
            print(
                f"Characteristic does not advertise READ (properties={props}). Aborting.",
                file=sys.stderr,
            )
            return 1
        data = await client.read_gatt_char(uuid)
        print(f"handle={getattr(char, 'handle', None)} uuid={uuid}")
        print(f"len={len(data)} hex={data.hex()} utf8={data!r}")
    return 0


async def cmd_listen(args: argparse.Namespace) -> int:
    print(
        "NOTE: Enabling notifications writes the CCCD (Client Characteristic "
        "Configuration Descriptor). This is not a strictly passive operation.",
        file=sys.stderr,
    )
    address = args.address
    uuid = args.uuid
    duration = args.duration
    count = 0

    def handler(_: BleakGATTCharacteristic, data: bytearray) -> None:
        nonlocal count
        count += 1
        print(f"{_utc_ts()}  n={count}  len={len(data)}  hex={data.hex()}")

    async with BleakClient(address, timeout=args.timeout) as client:
        char = client.services.get_characteristic(uuid)
        if char is None:
            print(f"Characteristic {uuid} not found.", file=sys.stderr)
            return 1
        props = {p.lower() for p in _props(char)}
        if "notify" not in props and "indicate" not in props:
            print(
                f"Characteristic does not advertise notify/indicate (properties={sorted(props)}).",
                file=sys.stderr,
            )
            return 1
        await client.start_notify(uuid, handler)
        print(f"Listening on {uuid} for {duration:.1f}s (Ctrl+C to stop early) …")
        try:
            await asyncio.sleep(duration)
        except asyncio.CancelledError:
            pass
        await client.stop_notify(uuid)
    print(f"Done. Received {count} notification(s).")
    return 0


async def cmd_replay(args: argparse.Namespace) -> int:
    """
    Intentionally not implemented until a specific command is verified from
    complete (non-truncated) capture payloads.
    """
    print(
        "replay is disabled: no vendor write commands have been fully verified "
        "from complete capture payloads yet.\n"
        "When enabled, this command will require:\n"
        "  --uuid <characteristic UUID>\n"
        "  --payload <hex>\n"
        "  --allow-write\n"
        "  interactive confirmation showing exact outgoing bytes and risk\n"
        "  no automatic retries\n"
        "\n"
        "Observed-but-incomplete candidates (NOT safe to invent or pad):\n"
        "  - ATT Write_Cmd on handle 0x0042 / likely UUID 0x33F3 (truncated bodies)\n"
        "  - ATT Write_Req on handle 0x0017 with FE FC prefix (truncated bodies)\n"
        "Capture a full (non-btsnooz-truncated) HCI snoop or sniffer trace before enabling replay.",
        file=sys.stderr,
    )
    return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sr116_cli",
        description="Safe, local-only BLE explorer for LoraFit SR116 (read-only by default).",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="BLE scan/connect timeout seconds (default 20)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Discover nearby BLE devices")
    scan.add_argument("--json", action="store_true", help="Emit JSON")
    scan.set_defaults(func=cmd_scan)

    inspect = sub.add_parser(
        "inspect", help="Connect and enumerate GATT; export JSON"
    )
    inspect.add_argument("address", help="Device address / ID from scan")
    inspect.add_argument(
        "-o",
        "--output",
        help="Write JSON to file (recommended: keep out of git if personal)",
    )
    inspect.set_defaults(func=cmd_inspect)

    read = sub.add_parser(
        "read",
        help="Read a user-specified characteristic (READ property required)",
    )
    read.add_argument("address")
    read.add_argument("uuid", help="Characteristic UUID")
    read.set_defaults(func=cmd_read)

    listen = sub.add_parser(
        "listen",
        help="Subscribe to notifications for a bounded duration (writes CCCD)",
    )
    listen.add_argument("address")
    listen.add_argument("uuid", help="NOTIFY/INDICATE characteristic UUID")
    listen.add_argument(
        "--duration",
        type=float,
        default=15.0,
        help="Seconds to listen (default 15)",
    )
    listen.set_defaults(func=cmd_listen)

    replay = sub.add_parser(
        "replay",
        help="Opt-in write of a verified command (NOT IMPLEMENTED until verified)",
    )
    replay.add_argument("address", nargs="?")
    replay.add_argument("--uuid")
    replay.add_argument("--payload", help="Exact hex payload")
    replay.add_argument(
        "--allow-write",
        action="store_true",
        help="Required flag once replay is implemented",
    )
    replay.set_defaults(func=cmd_replay)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(args.func(args))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
