"""Payload decoders for capture-verified layouts."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


def ts_iso(ts: int) -> str:
    try:
        if 1_600_000_000 < ts < 2_100_000_000:
            return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass
    return "?"


@dataclass
class StepStatus:
    timestamp: int
    steps: int
    calories: int
    distance: int

    @property
    def ts_iso(self) -> str:
        return ts_iso(self.timestamp)


def parse_step_status(pl: bytes) -> Optional[StepStatus]:
    """0x1D: u32le ts, u16 pad, u32le steps, u16le cal, u16le dist."""
    if len(pl) < 14:
        return None
    ts = struct.unpack_from("<I", pl, 0)[0]
    steps = struct.unpack_from("<I", pl, 6)[0]
    cal = struct.unpack_from("<H", pl, 10)[0]
    dist = struct.unpack_from("<H", pl, 12)[0]
    return StepStatus(timestamp=ts, steps=steps, calories=cal, distance=dist)


@dataclass
class StepBucket:
    timestamp: int
    field: int
    steps: int
    calories: int
    distance: int

    @property
    def ts_iso(self) -> str:
        return ts_iso(self.timestamp)


def parse_step_buckets(pl: bytes) -> list[StepBucket]:
    """0x21 assembled: 16-byte records."""
    out: list[StepBucket] = []
    for i in range(0, len(pl) - 15, 16):
        rec = pl[i : i + 16]
        ts = struct.unpack_from("<I", rec, 0)[0]
        # pad u16 at 4, field u16 at 6
        field = struct.unpack_from("<H", rec, 6)[0]
        steps = struct.unpack_from("<I", rec, 8)[0]
        cal = struct.unpack_from("<H", rec, 12)[0]
        dist = struct.unpack_from("<H", rec, 14)[0]
        out.append(
            StepBucket(
                timestamp=ts, field=field, steps=steps, calories=cal, distance=dist
            )
        )
    return out


@dataclass
class SleepRow:
    timestamp: int
    flags: bytes

    @property
    def ts_iso(self) -> str:
        return ts_iso(self.timestamp)

    @property
    def flags_hex(self) -> str:
        return self.flags.hex()


def parse_sleep_rows(pl: bytes) -> list[SleepRow]:
    """0x22 assembled: 8-byte rows ts4 + 4 flag bytes."""
    out: list[SleepRow] = []
    for i in range(0, len(pl) - 7, 8):
        rec = pl[i : i + 8]
        ts = struct.unpack_from("<I", rec, 0)[0]
        out.append(SleepRow(timestamp=ts, flags=rec[4:8]))
    return out


@dataclass
class HealthSample:
    timestamp: int
    hr: int
    spo2: int
    temp_raw: int
    rest: bytes

    @property
    def ts_iso(self) -> str:
        return ts_iso(self.timestamp)

    @property
    def temp_c(self) -> float:
        return self.temp_raw / 10.0


def parse_health_samples(pl: bytes) -> list[HealthSample]:
    """0x24: 14-byte records ts4 + pad2 + hr + spo2 + temp_i16 + rest."""
    out: list[HealthSample] = []
    for i in range(0, len(pl) - 13, 14):
        rec = pl[i : i + 14]
        ts = struct.unpack_from("<I", rec, 0)[0]
        hr, spo2 = rec[6], rec[7]
        temp = struct.unpack_from("<h", rec, 8)[0]
        out.append(
            HealthSample(
                timestamp=ts, hr=hr, spo2=spo2, temp_raw=temp, rest=rec[10:]
            )
        )
    return out


@dataclass
class DeviceInfo:
    firmware: int
    mac: str
    rest: bytes


def parse_device_info(pl: bytes) -> Optional[DeviceInfo]:
    if len(pl) < 8:
        return None
    fw = struct.unpack_from("<H", pl, 0)[0]
    mac = pl[2:8].hex(":")
    return DeviceInfo(firmware=fw, mac=mac, rest=pl[8:])


def parse_battery(pl: bytes) -> Optional[tuple[int, int]]:
    if len(pl) < 2:
        return None
    return pl[0], pl[1]


def parse_name(pl: bytes) -> str:
    # often length-prefixed ascii
    if not pl:
        return ""
    if pl[0] == len(pl) - 1:
        return pl[1:].decode("utf-8", errors="replace")
    return pl.decode("utf-8", errors="replace")


def parse_audio_count(pl: bytes) -> int:
    if len(pl) >= 2:
        return struct.unpack_from("<H", pl, 0)[0]
    if len(pl) == 1:
        return pl[0]
    return 0


def parse_live_value(pl: bytes) -> Optional[tuple[int, int]]:
    """0x0B / 0x18: u32le ts + 00 00 + u8 value."""
    if len(pl) < 7:
        return None
    ts = struct.unpack_from("<I", pl, 0)[0]
    return ts, pl[6]


def extract_opus_chunk_body(payload_486: bytes) -> bytes:
    """0x34 data payload: ts4 + pad2 + 480 opus bytes."""
    if len(payload_486) >= 486:
        return payload_486[6:486]
    if len(payload_486) > 6:
        return payload_486[6:]
    return b""
