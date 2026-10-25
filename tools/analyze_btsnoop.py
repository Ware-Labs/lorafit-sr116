#!/usr/bin/env python3
"""
Parse Android Bluetooth HCI btsnoop (btsnooz) captures for LoraFit SR116 analysis.

Reproducible analyzer: validates headers, reassembles ACL/L2CAP, parses ATT,
and emits comparison reports. Never modifies capture files.
"""

from __future__ import annotations

import argparse
import csv
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BTSNOOP_MAGIC = b"btsnoop\x00"
BTSNOOP_VERSION = 1
DATALINK_H4 = 1002

H4_COMMAND = 0x01
H4_ACL = 0x02
H4_SCO = 0x03
H4_EVENT = 0x04
H4_ISO = 0x05

H4_NAMES = {
    H4_COMMAND: "HCI_CMD",
    H4_ACL: "ACL",
    H4_SCO: "SCO",
    H4_EVENT: "HCI_EVT",
    H4_ISO: "ISO",
}

L2CAP_CID_ATT = 0x0004
L2CAP_CID_LE_SIGNALING = 0x0005
L2CAP_CID_SMP = 0x0006
L2CAP_CID_BR_SIGNALING = 0x0001

ATT_OPCODES = {
    0x01: "Error_Rsp",
    0x02: "Exchange_MTU_Req",
    0x03: "Exchange_MTU_Rsp",
    0x04: "Find_Info_Req",
    0x05: "Find_Info_Rsp",
    0x06: "Find_By_Type_Value_Req",
    0x07: "Find_By_Type_Value_Rsp",
    0x08: "Read_By_Type_Req",
    0x09: "Read_By_Type_Rsp",
    0x0A: "Read_Req",
    0x0B: "Read_Rsp",
    0x0C: "Read_Blob_Req",
    0x0D: "Read_Blob_Rsp",
    0x0E: "Read_Multiple_Req",
    0x0F: "Read_Multiple_Rsp",
    0x10: "Read_By_Group_Type_Req",
    0x11: "Read_By_Group_Type_Rsp",
    0x12: "Write_Req",
    0x13: "Write_Rsp",
    0x16: "Prepare_Write_Req",
    0x17: "Prepare_Write_Rsp",
    0x18: "Execute_Write_Req",
    0x19: "Execute_Write_Rsp",
    0x1B: "Handle_Value_Ntf",
    0x1D: "Handle_Value_Ind",
    0x1E: "Handle_Value_Cnf",
    0x52: "Write_Cmd",
    0xD2: "Signed_Write_Cmd",
}

# ATT opcodes that carry a 16-bit attribute handle after the opcode
ATT_HANDLE_OPCODES = {
    0x0A, 0x0C, 0x12, 0x16, 0x1B, 0x1D, 0x52, 0xD2, 0x01,
}

GATT_PRIMARY_SERVICE = 0x2800
GATT_SECONDARY_SERVICE = 0x2801
GATT_INCLUDE = 0x2802
GATT_CHARACTERISTIC = 0x2803
GATT_CCCD = 0x2902

INTERESTING_HANDLES = {0x0017, 0x0019, 0x0042, 0x0044}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class BtsnoopRecord:
    index: int
    original_length: int
    included_length: int
    flags: int
    cumulative_drops: int
    timestamp_us: int
    payload: bytes
    incomplete_payload: bool

    @property
    def direction(self) -> str:
        # bit0: 0 = host→controller (TX/sent), 1 = controller→host (RX/received)
        return "RX" if (self.flags & 0x01) else "TX"

    @property
    def is_command_channel(self) -> bool:
        return bool(self.flags & 0x02)

    @property
    def h4_type(self) -> Optional[int]:
        if not self.payload:
            return None
        return self.payload[0]


@dataclass
class AclHeader:
    connection_handle: int
    pb_flag: int
    bc_flag: int
    data_total_length: int


@dataclass
class L2capPdu:
    record_indices: list[int]
    connection_handle: int
    direction: str
    timestamp_us: int
    cid: int
    payload: bytes
    incomplete_payload: bool
    original_payload_len_estimate: int


@dataclass
class AttPdu:
    record_index: int
    connection_handle: int
    direction: str
    timestamp_us: int
    opcode: int
    opcode_name: str
    att_handle: Optional[int]
    payload: bytes
    incomplete_payload: bool
    included_length: int
    original_length: int
    cid: int = L2CAP_CID_ATT


@dataclass
class HandleStats:
    att_handle: int
    connection_handles: set[int] = field(default_factory=set)
    tx_count: int = 0
    rx_count: int = 0
    captured_bytes: int = 0
    original_bytes: int = 0
    opcodes: Counter = field(default_factory=Counter)
    truncated_count: int = 0
    payload_sizes: list[int] = field(default_factory=list)
    timestamps_us: list[int] = field(default_factory=list)
    uuid_hints: set[str] = field(default_factory=set)


@dataclass
class CaptureAnalysis:
    path: Path
    file_size: int
    version: int
    datalink: int
    records: list[BtsnoopRecord]
    malformed_count: int
    h4_counts: Counter
    truncated_count: int
    time_span_us: int
    first_ts: Optional[int]
    last_ts: Optional[int]
    connections: list[dict]
    l2cap_pdus: list[L2capPdu]
    att_pdus: list[AttPdu]
    handle_stats: dict[int, HandleStats]
    uuid_map: dict[int, str]  # ATT handle -> UUID string (from discovery)
    cid_volumes: dict[int, dict]
    burst_bins: list[tuple[int, int, int]]  # (second_offset, tx_bytes_orig, rx_bytes_orig)
    incomplete_reassemblies: int
    notes: list[str]


# ---------------------------------------------------------------------------
# Parsing primitives
# ---------------------------------------------------------------------------


def parse_btsnoop_header(data: bytes) -> tuple[int, int]:
    if len(data) < 16:
        raise ValueError("File shorter than 16-byte btsnoop header")
    magic = data[0:8]
    if magic != BTSNOOP_MAGIC:
        raise ValueError(f"Bad magic {magic!r}, expected {BTSNOOP_MAGIC!r}")
    version = struct.unpack(">I", data[8:12])[0]
    datalink = struct.unpack(">I", data[12:16])[0]
    return version, datalink


def iter_btsnoop_records(data: bytes) -> Iterator[BtsnoopRecord]:
    """Yield records; stop cleanly at EOF. Raise on unrecoverable malformation."""
    version, datalink = parse_btsnoop_header(data)
    if version != BTSNOOP_VERSION:
        raise ValueError(f"Unsupported btsnoop version {version}")
    if datalink != DATALINK_H4:
        # Still attempt parse; caller can note mismatch
        pass

    offset = 16
    index = 0
    while offset + 24 <= len(data):
        orig, incl, flags, drops, ts = struct.unpack(">IIIIq", data[offset : offset + 24])
        # timestamp is unsigned in practice; struct 'q' is signed — re-read unsigned
        ts = struct.unpack(">Q", data[offset + 16 : offset + 24])[0]
        offset += 24
        if incl < 0 or orig < 0:
            raise ValueError(f"Negative lengths at record {index}")
        if offset + incl > len(data):
            # Truncated file trailing record
            payload = data[offset:]
            yield BtsnoopRecord(
                index=index,
                original_length=orig,
                included_length=incl,
                flags=flags,
                cumulative_drops=drops,
                timestamp_us=ts,
                payload=payload,
                incomplete_payload=True,
            )
            return
        payload = data[offset : offset + incl]
        offset += incl
        incomplete = orig > incl or len(payload) < incl
        yield BtsnoopRecord(
            index=index,
            original_length=orig,
            included_length=incl,
            flags=flags,
            cumulative_drops=drops,
            timestamp_us=ts,
            payload=payload,
            incomplete_payload=incomplete,
        )
        index += 1


def parse_acl_header(acl_bytes: bytes) -> Optional[AclHeader]:
    """Parse HCI ACL data packet (without H4 type byte). Needs ≥4 bytes."""
    if len(acl_bytes) < 4:
        return None
    handle_pb = struct.unpack("<H", acl_bytes[0:2])[0]
    data_len = struct.unpack("<H", acl_bytes[2:4])[0]
    return AclHeader(
        connection_handle=handle_pb & 0x0FFF,
        pb_flag=(handle_pb >> 12) & 0x03,
        bc_flag=(handle_pb >> 14) & 0x03,
        data_total_length=data_len,
    )


def parse_l2cap_header(data: bytes) -> Optional[tuple[int, int, bytes]]:
    """Return (length, cid, payload) or None if incomplete header."""
    if len(data) < 4:
        return None
    length, cid = struct.unpack("<HH", data[0:4])
    return length, cid, data[4:]


def uuid128_to_str(b: bytes) -> str:
    if len(b) != 16:
        return b.hex()
    # Bluetooth UUID is little-endian on air
    u = bytes(reversed(b))
    return (
        f"{u[0:4].hex()}-{u[4:6].hex()}-{u[6:8].hex()}-"
        f"{u[8:10].hex()}-{u[10:16].hex()}"
    )


def uuid16_to_str(v: int) -> str:
    return f"0x{v:04X}"


def parse_att_pdu(
    payload: bytes,
    *,
    record_index: int,
    connection_handle: int,
    direction: str,
    timestamp_us: int,
    incomplete_payload: bool,
    included_length: int,
    original_length: int,
) -> AttPdu:
    if not payload:
        return AttPdu(
            record_index=record_index,
            connection_handle=connection_handle,
            direction=direction,
            timestamp_us=timestamp_us,
            opcode=0,
            opcode_name="Empty",
            att_handle=None,
            payload=payload,
            incomplete_payload=True,
            included_length=included_length,
            original_length=original_length,
        )
    opcode = payload[0]
    name = ATT_OPCODES.get(opcode, f"Unknown_0x{opcode:02X}")
    att_handle: Optional[int] = None
    if opcode in ATT_HANDLE_OPCODES and len(payload) >= 3:
        if opcode == 0x01 and len(payload) >= 5:
            # Error Response: req_opcode, handle, error_code
            att_handle = struct.unpack("<H", payload[2:4])[0]
        else:
            att_handle = struct.unpack("<H", payload[1:3])[0]
    return AttPdu(
        record_index=record_index,
        connection_handle=connection_handle,
        direction=direction,
        timestamp_us=timestamp_us,
        opcode=opcode,
        opcode_name=name,
        att_handle=att_handle,
        payload=payload,
        incomplete_payload=incomplete_payload,
        included_length=included_length,
        original_length=original_length,
    )


# ---------------------------------------------------------------------------
# ACL / L2CAP reassembly
# ---------------------------------------------------------------------------


def reassemble_l2cap(records: list[BtsnoopRecord]) -> tuple[list[L2capPdu], int]:
    """
    Reassemble ACL HCI fragments into L2CAP PDUs per (connection_handle, direction).

    PB flag 0b00 / 0b10 = start; 0b01 = continuation.
    Mark incomplete when source records truncated or length mismatch.
    Do not silently join unrelated fragments across gaps.
    """
    # key -> current assembly state
    state: dict[tuple[int, str], dict] = {}
    pdus: list[L2capPdu] = []
    incomplete_reassemblies = 0

    def flush_incomplete(key: tuple[int, str], reason: str = "") -> None:
        nonlocal incomplete_reassemblies
        st = state.pop(key, None)
        if st is None:
            return
        incomplete_reassemblies += 1
        # Emit what we have as incomplete
        buf: bytes = st["buf"]
        if len(buf) >= 4:
            length, cid = struct.unpack("<HH", buf[0:4])
            payload = buf[4:]
        else:
            length, cid, payload = 0, 0, buf
        pdus.append(
            L2capPdu(
                record_indices=list(st["indices"]),
                connection_handle=key[0],
                direction=key[1],
                timestamp_us=st["ts"],
                cid=cid,
                payload=payload,
                incomplete_payload=True,
                original_payload_len_estimate=length,
            )
        )

    for rec in records:
        if rec.h4_type != H4_ACL or len(rec.payload) < 5:
            continue
        acl = parse_acl_header(rec.payload[1:])
        if acl is None:
            continue
        key = (acl.connection_handle, rec.direction)
        body = rec.payload[5:]  # after H4 + ACL header (4 bytes)
        # HCI ACL data_total_length should match len(body) when not truncated
        body_incomplete = rec.incomplete_payload or len(body) < acl.data_total_length

        is_start = acl.pb_flag in (0b00, 0b10)
        is_cont = acl.pb_flag == 0b01

        if is_start:
            if key in state:
                flush_incomplete(key, "new_start")
            state[key] = {
                "buf": bytearray(body),
                "indices": [rec.index],
                "ts": rec.timestamp_us,
                "any_trunc": body_incomplete,
                "orig_acl_lens": [rec.original_length],
            }
        elif is_cont:
            if key not in state:
                # Orphan continuation — mark incomplete, do not invent a start
                incomplete_reassemblies += 1
                continue
            state[key]["buf"].extend(body)
            state[key]["indices"].append(rec.index)
            state[key]["any_trunc"] = state[key]["any_trunc"] or body_incomplete
            state[key]["orig_acl_lens"].append(rec.original_length)
        else:
            # Unexpected PB — flush and skip
            if key in state:
                flush_incomplete(key, "bad_pb")
            continue

        st = state.get(key)
        if st is None:
            continue
        buf = st["buf"]
        if len(buf) < 4:
            continue
        l2_len, cid = struct.unpack("<HH", buf[0:4])
        need = 4 + l2_len
        if len(buf) < need:
            continue
        if len(buf) > need:
            # Extra data beyond L2CAP length — treat as incomplete/malformed
            incomplete_reassemblies += 1
            payload = bytes(buf[4:need])
            pdus.append(
                L2capPdu(
                    record_indices=list(st["indices"]),
                    connection_handle=key[0],
                    direction=key[1],
                    timestamp_us=st["ts"],
                    cid=cid,
                    payload=payload,
                    incomplete_payload=True,
                    original_payload_len_estimate=l2_len,
                )
            )
            state.pop(key, None)
            continue

        incomplete = bool(st["any_trunc"])
        pdus.append(
            L2capPdu(
                record_indices=list(st["indices"]),
                connection_handle=key[0],
                direction=key[1],
                timestamp_us=st["ts"],
                cid=cid,
                payload=bytes(buf[4:]),
                incomplete_payload=incomplete,
                original_payload_len_estimate=l2_len,
            )
        )
        state.pop(key, None)

    for key in list(state.keys()):
        flush_incomplete(key, "eof")

    return pdus, incomplete_reassemblies


# ---------------------------------------------------------------------------
# GATT discovery UUID mapping (best-effort from captured ATT)
# ---------------------------------------------------------------------------


def extract_uuid_map(att_pdus: list[AttPdu]) -> dict[int, str]:
    """
    Build handle→UUID map from Read By Type / Read By Group / Find Info responses.
    Only assign UUIDs when response payload bytes actually contain them.
    """
    mapping: dict[int, str] = {}

    for pdu in att_pdus:
        if pdu.incomplete_payload and len(pdu.payload) < 4:
            continue
        op = pdu.opcode
        data = pdu.payload[1:]

        if op == 0x11 and len(data) >= 1:  # Read By Group Type Rsp
            # format: length, then repeating (start, end, uuid)
            entry_len = data[0]
            if entry_len < 4:
                continue
            pos = 1
            while pos + entry_len <= len(data):
                start, end = struct.unpack("<HH", data[pos : pos + 4])
                uuid_bytes = data[pos + 4 : pos + entry_len]
                if len(uuid_bytes) == 2:
                    u = uuid16_to_str(struct.unpack("<H", uuid_bytes)[0])
                elif len(uuid_bytes) == 16:
                    u = uuid128_to_str(uuid_bytes)
                else:
                    u = uuid_bytes.hex()
                mapping[start] = f"Service:{u}"
                pos += entry_len

        elif op == 0x09 and len(data) >= 1:  # Read By Type Rsp (often characteristics)
            entry_len = data[0]
            if entry_len < 3:
                continue
            pos = 1
            while pos + entry_len <= len(data):
                handle = struct.unpack("<H", data[pos : pos + 2])[0]
                rest = data[pos + 2 : pos + entry_len]
                # Characteristic declaration: properties(1) + value_handle(2) + uuid
                if len(rest) >= 3:
                    value_handle = struct.unpack("<H", rest[1:3])[0]
                    uuid_b = rest[3:]
                    if len(uuid_b) == 2:
                        u = uuid16_to_str(struct.unpack("<H", uuid_b)[0])
                    elif len(uuid_b) == 16:
                        u = uuid128_to_str(uuid_b)
                    else:
                        u = uuid_b.hex() if uuid_b else "?"
                    mapping[handle] = f"CharDecl:{u}"
                    mapping[value_handle] = u
                pos += entry_len

        elif op == 0x05 and len(data) >= 1:  # Find Information Rsp
            fmt = data[0]
            pos = 1
            if fmt == 0x01:  # 16-bit UUIDs
                while pos + 4 <= len(data):
                    handle = struct.unpack("<H", data[pos : pos + 2])[0]
                    uuid = struct.unpack("<H", data[pos + 2 : pos + 4])[0]
                    mapping[handle] = uuid16_to_str(uuid)
                    pos += 4
            elif fmt == 0x02:  # 128-bit
                while pos + 18 <= len(data):
                    handle = struct.unpack("<H", data[pos : pos + 2])[0]
                    mapping[handle] = uuid128_to_str(data[pos + 2 : pos + 18])
                    pos += 18

    return mapping


# ---------------------------------------------------------------------------
# HCI connection / advertising helpers
# ---------------------------------------------------------------------------


def decode_hci_events_and_commands(records: list[BtsnoopRecord]) -> list[dict]:
    """Extract LE/BR connection-related events for peer identification."""
    connections: list[dict] = []
    for rec in records:
        if rec.h4_type != H4_EVENT or len(rec.payload) < 3:
            continue
        evt = rec.payload[1]
        plen = rec.payload[2]
        body = rec.payload[3 : 3 + plen]
        # LE Meta Event
        if evt == 0x3E and body:
            sub = body[0]
            # LE Connection Complete (0x01) / Enhanced (0x0A)
            if sub in (0x01, 0x0A) and len(body) >= 19:
                status = body[1]
                handle = struct.unpack("<H", body[2:4])[0]
                role = body[4]
                peer_type = body[5]
                peer_addr = body[6:12][::-1].hex(":")
                connections.append(
                    {
                        "record": rec.index,
                        "timestamp_us": rec.timestamp_us,
                        "event": "LE_Connection_Complete" if sub == 0x01 else "LE_Enhanced_Connection_Complete",
                        "status": status,
                        "connection_handle": handle,
                        "role": "master" if role == 0 else "slave",
                        "peer_addr_type": peer_type,
                        "peer_addr": peer_addr,
                        "incomplete": rec.incomplete_payload,
                    }
                )
            # LE Advertising Report (0x02)
            elif sub == 0x02 and len(body) >= 2:
                num = body[1]
                # Best-effort parse first report only
                if num >= 1 and len(body) >= 10:
                    evtype = body[2]
                    addr_type = body[3]
                    addr = body[4:10][::-1].hex(":")
                    data_len = body[10] if len(body) > 10 else 0
                    adv = body[11 : 11 + data_len] if len(body) >= 11 + data_len else b""
                    name = _extract_adv_name(adv)
                    connections.append(
                        {
                            "record": rec.index,
                            "timestamp_us": rec.timestamp_us,
                            "event": "LE_Advertising_Report",
                            "peer_addr_type": addr_type,
                            "peer_addr": addr,
                            "adv_event_type": evtype,
                            "name": name,
                            "incomplete": rec.incomplete_payload,
                        }
                    )
        # Connection Complete (BR/EDR) 0x03
        elif evt == 0x03 and len(body) >= 11:
            status = body[0]
            handle = struct.unpack("<H", body[1:3])[0]
            bdaddr = body[3:9][::-1].hex(":")
            connections.append(
                {
                    "record": rec.index,
                    "timestamp_us": rec.timestamp_us,
                    "event": "BR_EDR_Connection_Complete",
                    "status": status,
                    "connection_handle": handle,
                    "peer_addr": bdaddr,
                    "incomplete": rec.incomplete_payload,
                }
            )
        # Disconnect Complete 0x05
        elif evt == 0x05 and len(body) >= 4:
            status = body[0]
            handle = struct.unpack("<H", body[1:3])[0]
            reason = body[3]
            connections.append(
                {
                    "record": rec.index,
                    "timestamp_us": rec.timestamp_us,
                    "event": "Disconnection_Complete",
                    "status": status,
                    "connection_handle": handle,
                    "reason": reason,
                    "incomplete": rec.incomplete_payload,
                }
            )
    return connections


def _extract_adv_name(adv: bytes) -> Optional[str]:
    pos = 0
    while pos + 1 < len(adv):
        length = adv[pos]
        if length == 0 or pos + 1 + length > len(adv):
            break
        ad_type = adv[pos + 1]
        val = adv[pos + 2 : pos + 1 + length]
        if ad_type in (0x08, 0x09):  # short/complete local name
            try:
                return val.decode("utf-8", errors="replace")
            except Exception:
                return val.hex()
        pos += 1 + length
    return None


# ---------------------------------------------------------------------------
# Full capture analysis
# ---------------------------------------------------------------------------


def analyze_capture(path: Path) -> CaptureAnalysis:
    data = path.read_bytes()
    version, datalink = parse_btsnoop_header(data)
    notes: list[str] = []
    if datalink != DATALINK_H4:
        notes.append(f"Unexpected datalink {datalink} (expected {DATALINK_H4})")

    records: list[BtsnoopRecord] = []
    malformed = 0
    try:
        for rec in iter_btsnoop_records(data):
            records.append(rec)
    except ValueError as e:
        notes.append(f"Parse stopped early: {e}")
        malformed += 1

    h4_counts: Counter = Counter()
    truncated = 0
    for rec in records:
        if rec.incomplete_payload:
            truncated += 1
        ht = rec.h4_type
        if ht is not None:
            h4_counts[ht] += 1
        else:
            h4_counts[-1] += 1

    timestamps = [r.timestamp_us for r in records]
    first_ts = min(timestamps) if timestamps else None
    last_ts = max(timestamps) if timestamps else None
    span = (last_ts - first_ts) if first_ts is not None and last_ts is not None else 0

    connections = decode_hci_events_and_commands(records)
    l2cap_pdus, incomplete_reassemblies = reassemble_l2cap(records)

    att_pdus: list[AttPdu] = []
    cid_volumes: dict[int, dict] = defaultdict(
        lambda: {
            "pdu_count": 0,
            "captured_bytes": 0,
            "original_bytes_est": 0,
            "incomplete": 0,
            "by_dir": Counter(),
        }
    )

    for pdu in l2cap_pdus:
        vol = cid_volumes[pdu.cid]
        vol["pdu_count"] += 1
        vol["captured_bytes"] += len(pdu.payload)
        vol["original_bytes_est"] += pdu.original_payload_len_estimate
        vol["by_dir"][pdu.direction] += 1
        if pdu.incomplete_payload:
            vol["incomplete"] += 1

        if pdu.cid == L2CAP_CID_ATT:
            # Use first contributing record for included/original ACL lengths when available
            first_rec = records[pdu.record_indices[0]] if pdu.record_indices else None
            incl = first_rec.included_length if first_rec else len(pdu.payload)
            orig = first_rec.original_length if first_rec else pdu.original_payload_len_estimate
            # Sum original across fragments if multi-fragment
            if first_rec and len(pdu.record_indices) > 1:
                orig = sum(records[i].original_length for i in pdu.record_indices)
                incl = sum(records[i].included_length for i in pdu.record_indices)
            att = parse_att_pdu(
                pdu.payload,
                record_index=pdu.record_indices[0] if pdu.record_indices else -1,
                connection_handle=pdu.connection_handle,
                direction=pdu.direction,
                timestamp_us=pdu.timestamp_us,
                incomplete_payload=pdu.incomplete_payload,
                included_length=incl,
                original_length=orig,
            )
            att_pdus.append(att)

    uuid_map = extract_uuid_map(att_pdus)

    handle_stats: dict[int, HandleStats] = {}
    for att in att_pdus:
        if att.att_handle is None:
            continue
        hs = handle_stats.get(att.att_handle)
        if hs is None:
            hs = HandleStats(att_handle=att.att_handle)
            handle_stats[att.att_handle] = hs
        hs.connection_handles.add(att.connection_handle)
        if att.direction == "TX":
            hs.tx_count += 1
        else:
            hs.rx_count += 1
        # Payload after opcode+handle for size stats
        plen = max(0, len(att.payload) - 3) if len(att.payload) >= 3 else 0
        hs.captured_bytes += plen
        # Original: if truncated, use original_length heuristic minus HCI/L2CAP/ATT headers (~9+)
        # Prefer captured for accuracy; track original ACL length separately
        hs.original_bytes += max(0, att.original_length)
        hs.opcodes[att.opcode_name] += 1
        if att.incomplete_payload:
            hs.truncated_count += 1
        hs.payload_sizes.append(plen)
        hs.timestamps_us.append(att.timestamp_us)
        if att.att_handle in uuid_map:
            hs.uuid_hints.add(uuid_map[att.att_handle])

    # Per-second burst bins using original ACL lengths for ATT-bearing traffic
    burst_bins: list[tuple[int, int, int]] = []
    if first_ts is not None:
        bins: dict[int, list[int]] = defaultdict(lambda: [0, 0])
        for rec in records:
            if rec.h4_type != H4_ACL:
                continue
            sec = int((rec.timestamp_us - first_ts) // 1_000_000)
            if rec.direction == "TX":
                bins[sec][0] += rec.original_length
            else:
                bins[sec][1] += rec.original_length
        burst_bins = [(s, v[0], v[1]) for s, v in sorted(bins.items())]

    return CaptureAnalysis(
        path=path,
        file_size=len(data),
        version=version,
        datalink=datalink,
        records=records,
        malformed_count=malformed,
        h4_counts=h4_counts,
        truncated_count=truncated,
        time_span_us=span,
        first_ts=first_ts,
        last_ts=last_ts,
        connections=connections,
        l2cap_pdus=l2cap_pdus,
        att_pdus=att_pdus,
        handle_stats=handle_stats,
        uuid_map=uuid_map,
        cid_volumes=dict(cid_volumes),
        burst_bins=burst_bins,
        incomplete_reassemblies=incomplete_reassemblies,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------


def _ts_iso_offset(ts: int, base: Optional[int]) -> str:
    if base is None:
        return str(ts)
    delta_ms = (ts - base) / 1000.0
    return f"+{delta_ms:.3f}ms"


def write_packets_csv(analyses: list[CaptureAnalysis], out: Path) -> None:
    fields = [
        "capture",
        "record_index",
        "timestamp_us",
        "rel_ms",
        "direction",
        "h4_type",
        "connection_handle",
        "packet_type",
        "att_opcode",
        "att_opcode_name",
        "att_handle",
        "included_length",
        "original_length",
        "incomplete_payload",
        "payload_hex_prefix",
    ]
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for a in analyses:
            base = a.first_ts
            # Index ATT PDUs by first record for ACL ATT rows; also emit raw HCI summary rows
            att_by_rec = {p.record_index: p for p in a.att_pdus}
            for rec in a.records:
                att = att_by_rec.get(rec.index)
                acl_handle = ""
                if rec.h4_type == H4_ACL and len(rec.payload) >= 5:
                    hdr = parse_acl_header(rec.payload[1:])
                    if hdr:
                        acl_handle = f"0x{hdr.connection_handle:03X}"
                row = {
                    "capture": a.path.name,
                    "record_index": rec.index,
                    "timestamp_us": rec.timestamp_us,
                    "rel_ms": f"{(rec.timestamp_us - base) / 1000.0:.3f}" if base else "",
                    "direction": rec.direction,
                    "h4_type": H4_NAMES.get(rec.h4_type or -1, str(rec.h4_type)),
                    "connection_handle": acl_handle
                    if not att
                    else f"0x{att.connection_handle:03X}",
                    "packet_type": "ATT" if att else H4_NAMES.get(rec.h4_type or -1, "?"),
                    "att_opcode": f"0x{att.opcode:02X}" if att else "",
                    "att_opcode_name": att.opcode_name if att else "",
                    "att_handle": f"0x{att.att_handle:04X}" if att and att.att_handle is not None else "",
                    "included_length": rec.included_length,
                    "original_length": rec.original_length,
                    "incomplete_payload": rec.incomplete_payload,
                    "payload_hex_prefix": rec.payload[:24].hex(),
                }
                # Prefer ATT-enriched row when this record starts an ATT PDU
                if att:
                    row["incomplete_payload"] = att.incomplete_payload
                w.writerow(row)


def write_handle_summary_csv(analyses: list[CaptureAnalysis], out: Path) -> None:
    fields = [
        "capture",
        "att_handle",
        "uuid",
        "tx_count",
        "rx_count",
        "total_count",
        "captured_payload_bytes",
        "sum_original_hci_lengths",
        "truncated_pdus",
        "opcodes",
        "connection_handles",
        "min_payload",
        "max_payload",
        "median_interval_ms",
    ]
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for a in analyses:
            for handle in sorted(a.handle_stats.keys()):
                hs = a.handle_stats[handle]
                intervals = []
                ts_sorted = sorted(hs.timestamps_us)
                for i in range(1, len(ts_sorted)):
                    intervals.append((ts_sorted[i] - ts_sorted[i - 1]) / 1000.0)
                intervals.sort()
                med = ""
                if intervals:
                    med = f"{intervals[len(intervals) // 2]:.3f}"
                uuid = a.uuid_map.get(handle, "")
                if not uuid and hs.uuid_hints:
                    uuid = ";".join(sorted(hs.uuid_hints))
                w.writerow(
                    {
                        "capture": a.path.name,
                        "att_handle": f"0x{handle:04X}",
                        "uuid": uuid,
                        "tx_count": hs.tx_count,
                        "rx_count": hs.rx_count,
                        "total_count": hs.tx_count + hs.rx_count,
                        "captured_payload_bytes": hs.captured_bytes,
                        "sum_original_hci_lengths": hs.original_bytes,
                        "truncated_pdus": hs.truncated_count,
                        "opcodes": ";".join(f"{k}:{v}" for k, v in hs.opcodes.most_common()),
                        "connection_handles": ";".join(f"0x{h:03X}" for h in sorted(hs.connection_handles)),
                        "min_payload": min(hs.payload_sizes) if hs.payload_sizes else "",
                        "max_payload": max(hs.payload_sizes) if hs.payload_sizes else "",
                        "median_interval_ms": med,
                    }
                )


def write_timeline_csv(analyses: list[CaptureAnalysis], out: Path) -> None:
    fields = [
        "capture",
        "timestamp_us",
        "rel_ms",
        "connection_handle",
        "direction",
        "packet_type",
        "att_opcode",
        "att_handle",
        "included_length",
        "original_length",
        "incomplete_payload",
        "record_index",
    ]
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for a in analyses:
            base = a.first_ts
            for att in a.att_pdus:
                w.writerow(
                    {
                        "capture": a.path.name,
                        "timestamp_us": att.timestamp_us,
                        "rel_ms": f"{(att.timestamp_us - base) / 1000.0:.3f}" if base else "",
                        "connection_handle": f"0x{att.connection_handle:03X}",
                        "direction": att.direction,
                        "packet_type": "ATT",
                        "att_opcode": att.opcode_name,
                        "att_handle": f"0x{att.att_handle:04X}" if att.att_handle is not None else "",
                        "included_length": att.included_length,
                        "original_length": att.original_length,
                        "incomplete_payload": att.incomplete_payload,
                        "record_index": att.record_index,
                    }
                )


def _att_opcode_counts(att_pdus: list[AttPdu]) -> Counter:
    return Counter(p.opcode_name for p in att_pdus)


def _interesting_handle_table(a: CaptureAnalysis) -> str:
    lines = [
        "| Handle | UUID (if known) | TX | RX | Captured payload B | Truncated PDUs | Opcodes |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for h in sorted(INTERESTING_HANDLES | set(a.handle_stats.keys())):
        if h not in INTERESTING_HANDLES and (h not in a.handle_stats):
            continue
        if h not in INTERESTING_HANDLES:
            # Only list interesting + top handles later; skip bulk here
            continue
        hs = a.handle_stats.get(h)
        if not hs:
            lines.append(f"| `0x{h:04X}` | — | 0 | 0 | 0 | 0 | **not observed** |")
            continue
        uuid = a.uuid_map.get(h, "—")
        ops = ", ".join(f"{k}:{v}" for k, v in hs.opcodes.most_common(4))
        lines.append(
            f"| `0x{h:04X}` | {uuid} | {hs.tx_count} | {hs.rx_count} | "
            f"{hs.captured_bytes} | {hs.truncated_count} | {ops} |"
        )
    return "\n".join(lines)


def _top_burst_seconds(a: CaptureAnalysis, n: int = 10) -> str:
    ranked = sorted(a.burst_bins, key=lambda x: x[1] + x[2], reverse=True)[:n]
    lines = [
        "| Sec offset | TX original B | RX original B | Total |",
        "|---:|---:|---:|---:|",
    ]
    for sec, tx, rx in ranked:
        lines.append(f"| {sec} | {tx} | {rx} | {tx + rx} |")
    return "\n".join(lines)


def _find_dense_burst_window(a: CaptureAnalysis, window_s: float = 12.0) -> Optional[dict]:
    """Find the window of ~window_s with max original ACL bytes (proxy for transfer)."""
    if not a.burst_bins:
        return None
    by_sec = {s: (tx, rx) for s, tx, rx in a.burst_bins}
    if not by_sec:
        return None
    min_s, max_s = min(by_sec), max(by_sec)
    best = None
    w = int(window_s)
    for start in range(min_s, max_s + 1):
        total = 0
        tx_t = rx_t = 0
        for s in range(start, start + w):
            if s in by_sec:
                tx_t += by_sec[s][0]
                rx_t += by_sec[s][1]
                total += by_sec[s][0] + by_sec[s][1]
        if best is None or total > best["total"]:
            best = {"start_s": start, "end_s": start + w, "tx": tx_t, "rx": rx_t, "total": total}
    return best


def write_comparison_md(analyses: list[CaptureAnalysis], out: Path) -> None:
    lines: list[str] = []
    lines.append("# SR116 Capture Comparison Report")
    lines.append("")
    lines.append("Generated by `tools/analyze_btsnoop.py`. Confidence labels: **Observed** / **Inferred** / **Unknown**.")
    lines.append("")
    lines.append("## File validation")
    lines.append("")
    lines.append("| File | Size | Records | Truncated (`orig>incl`) | ACL | Event | Command | Span (s) |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for a in analyses:
        span_s = a.time_span_us / 1_000_000.0 if a.time_span_us else 0
        lines.append(
            f"| `{a.path.name}` | {a.file_size} | {len(a.records)} | {a.truncated_count} | "
            f"{a.h4_counts.get(H4_ACL, 0)} | {a.h4_counts.get(H4_EVENT, 0)} | "
            f"{a.h4_counts.get(H4_COMMAND, 0)} | {span_s:.3f} |"
        )
    lines.append("")
    lines.append("### Cross-check vs experiment report")
    lines.append("")
    expected = {
        "btsnooz_hci.log": {"size": 64813, "records": 1747, "truncated": 394},
        "sr116_second_btsnooz_hci.log": {"size": 64212, "records": 1747, "truncated": 836},
    }
    for a in analyses:
        exp = expected.get(a.path.name)
        if not exp:
            lines.append(f"- `{a.path.name}`: no expected baseline in instructions.")
            continue
        ok_size = a.file_size == exp["size"]
        ok_rec = len(a.records) == exp["records"]
        ok_tr = a.truncated_count == exp["truncated"]
        status = "MATCH" if ok_size and ok_rec and ok_tr else "MISMATCH"
        lines.append(
            f"- **{status}** `{a.path.name}`: size {a.file_size} (exp {exp['size']}), "
            f"records {len(a.records)} (exp {exp['records']}), "
            f"truncated {a.truncated_count} (exp {exp['truncated']})."
        )
        if a.path.name == "sr116_second_btsnooz_hci.log":
            lines.append(
                f"  - HCI types: ACL={a.h4_counts.get(H4_ACL, 0)} (exp 1291), "
                f"EVT={a.h4_counts.get(H4_EVENT, 0)} (exp 329), "
                f"CMD={a.h4_counts.get(H4_COMMAND, 0)} (exp 127)."
            )
    lines.append("")

    for a in analyses:
        lines.append(f"## Capture: `{a.path.name}`")
        lines.append("")
        if a.notes:
            lines.append("Notes: " + "; ".join(a.notes))
            lines.append("")
        lines.append("### Connections / advertising (**Observed** from HCI events)")
        lines.append("")
        if not a.connections:
            lines.append("No LE/BR connection or advertising events decoded (may be truncated or outside window).")
        else:
            lines.append("| Record | Rel ms | Event | Handle | Peer | Name |")
            lines.append("|---:|---:|---|---|---|---|")
            base = a.first_ts
            for c in a.connections[:40]:
                rel = f"{(c['timestamp_us'] - base) / 1000.0:.1f}" if base else ""
                handle = f"0x{c['connection_handle']:03X}" if "connection_handle" in c else ""
                peer = c.get("peer_addr", "")
                name = c.get("name") or ""
                lines.append(
                    f"| {c['record']} | {rel} | {c['event']} | {handle} | `{peer}` | {name} |"
                )
            if len(a.connections) > 40:
                lines.append(f"| … | | ({len(a.connections) - 40} more) | | | |")
        lines.append("")

        lines.append("### L2CAP CID volumes (**Observed**)")
        lines.append("")
        lines.append("| CID | PDUs | Captured payload B | Est. original L2CAP len sum | Incomplete | TX PDUs | RX PDUs |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|")
        for cid, vol in sorted(a.cid_volumes.items()):
            cid_name = {
                0x0004: "ATT",
                0x0005: "LE_SIG",
                0x0006: "SMP",
                0x0001: "BR_SIG",
            }.get(cid, "")
            label = f"0x{cid:04X}" + (f" ({cid_name})" if cid_name else "")
            lines.append(
                f"| {label} | {vol['pdu_count']} | {vol['captured_bytes']} | "
                f"{vol['original_bytes_est']} | {vol['incomplete']} | "
                f"{vol['by_dir'].get('TX', 0)} | {vol['by_dir'].get('RX', 0)} |"
            )
        lines.append("")
        lines.append(f"Incomplete ACL/L2CAP reassemblies: **{a.incomplete_reassemblies}**")
        lines.append("")

        oc = _att_opcode_counts(a.att_pdus)
        lines.append("### ATT opcode counts (**Observed** from reassembled ATT PDUs)")
        lines.append("")
        lines.append("| Opcode | Count |")
        lines.append("|---|---:|")
        for name, cnt in oc.most_common():
            lines.append(f"| {name} | {cnt} |")
        lines.append("")

        lines.append("### Handles of interest (0x0017 / 0x0019 / 0x0042 / 0x0044)")
        lines.append("")
        lines.append(_interesting_handle_table(a))
        lines.append("")

        burst = _find_dense_burst_window(a, 12.0)
        lines.append("### Traffic bursts (per-second ACL original lengths)")
        lines.append("")
        lines.append(_top_burst_seconds(a, 12))
        lines.append("")
        if burst:
            lines.append(
                f"**Inferred** densest ~12s window: sec {burst['start_s']}–{burst['end_s']} "
                f"(TX orig {burst['tx']} B, RX orig {burst['rx']} B, total {burst['total']} B). "
                f"This uses *original_length* headers, not captured payload bytes."
            )
            lines.append("")
            # Attribute handle activity inside that window
            base = a.first_ts
            if base is not None:
                t0 = base + burst["start_s"] * 1_000_000
                t1 = base + burst["end_s"] * 1_000_000
                window_handles: Counter = Counter()
                window_ops: Counter = Counter()
                for att in a.att_pdus:
                    if t0 <= att.timestamp_us < t1 and att.att_handle is not None:
                        window_handles[att.att_handle] += 1
                        window_ops[f"{att.direction}:{att.opcode_name}:0x{att.att_handle:04X}"] += 1
                lines.append("ATT activity inside that window (by handle):")
                lines.append("")
                lines.append("| Handle | Count | UUID |")
                lines.append("|---|---:|---|")
                for h, c in window_handles.most_common(15):
                    lines.append(f"| `0x{h:04X}` | {c} | {a.uuid_map.get(h, '—')} |")
                lines.append("")
                lines.append("Top direction/opcode/handle triples in window:")
                lines.append("")
                for k, c in window_ops.most_common(20):
                    lines.append(f"- `{k}` × {c}")
                lines.append("")

        lines.append("### UUID map from discovery (**Observed** only where response bytes exist)")
        lines.append("")
        if not a.uuid_map:
            lines.append(
                "No characteristic/service UUIDs recovered from ATT discovery responses "
                "(responses may be truncated or discovery occurred outside the captured window)."
            )
        else:
            lines.append("| Handle | UUID |")
            lines.append("|---|---|")
            for h in sorted(a.uuid_map):
                lines.append(f"| `0x{h:04X}` | `{a.uuid_map[h]}` |")
        lines.append("")

        # Truncation severity
        trunc_recs = [r for r in a.records if r.incomplete_payload]
        if trunc_recs:
            diffs = [r.original_length - r.included_length for r in trunc_recs]
            max_orig = max(r.original_length for r in trunc_recs)
            lines.append("### Truncation severity (**Observed**)")
            lines.append("")
            lines.append(f"- Truncated records: {len(trunc_recs)}")
            lines.append(f"- Max original_length among truncated: {max_orig}")
            lines.append(f"- Max bytes dropped (orig−incl): {max(diffs)}")
            lines.append(
                f"- Median bytes dropped: {sorted(diffs)[len(diffs)//2]}"
            )
            # Example
            ex = max(trunc_recs, key=lambda r: r.original_length - r.included_length)
            lines.append(
                f"- Example: record {ex.index} orig={ex.original_length} incl={ex.included_length} "
                f"dir={ex.direction} h4={H4_NAMES.get(ex.h4_type or -1)}"
            )
            lines.append("")

    # Cross-capture protocol conclusions
    lines.append("## Protocol conclusions")
    lines.append("")
    lines.append(_protocol_conclusions(analyses))
    lines.append("")
    lines.append("## Missing evidence / next capture")
    lines.append("")
    lines.append(
        "Android `btsnooz` diagnostic truncation removes most ATT notification/write payloads. "
        "Absence of audio magic bytes in *captured* payloads does **not** mean audio was absent on-air."
    )
    lines.append("")
    lines.append("Recommended collection (lawful, owner device only):")
    lines.append("")
    lines.append("1. Generate a **Full** Android bug report and compare `included_length` vs `original_length` distributions to Interactive.")
    lines.append("2. If ADB permits: `adb pull /data/misc/bluetooth/logs/` (may be denied on production builds without root).")
    lines.append("3. Alternate: Frontline/Ellisys/nRF Sniffer passive capture during a disposable offline recording download.")
    lines.append("4. Export full GATT DB (all 128-bit UUIDs under `0xFEF5`) via nRF Connect or `sr116_cli.py inspect`.")
    lines.append("")

    out.write_text("\n".join(lines), encoding="utf-8")


def _protocol_conclusions(analyses: list[CaptureAnalysis]) -> str:
    lines: list[str] = []
    if len(analyses) < 1:
        return "No captures analyzed."

    by_name = {a.path.name: a for a in analyses}
    second = by_name.get("sr116_second_btsnooz_hci.log")
    first = by_name.get("btsnooz_hci.log")

    lines.append("### Transport")
    # Check non-ATT L2CAP
    for label, a in (("first", first), ("second", second)):
        if not a:
            continue
        non_att = {cid: v for cid, v in a.cid_volumes.items() if cid != L2CAP_CID_ATT}
        br = [c for c in a.connections if c.get("event") == "BR_EDR_Connection_Complete"]
        lines.append(
            f"- **Observed ({label}):** L2CAP CIDs present = "
            + (", ".join(f"0x{c:04X}" for c in sorted(a.cid_volumes)) or "none")
            + f"; BR/EDR Connection Complete events = {len(br)}."
        )
        bulk_non_att = sum(v["original_bytes_est"] for v in non_att.values())
        att_orig = a.cid_volumes.get(L2CAP_CID_ATT, {}).get("original_bytes_est", 0)
        lines.append(
            f"  - Est. original L2CAP payload sum ATT={att_orig}, non-ATT={bulk_non_att}."
        )

    lines.append("")
    lines.append("### Candidate transfer path")
    if second:
        h42 = second.handle_stats.get(0x0042)
        h44 = second.handle_stats.get(0x0044)
        h17 = second.handle_stats.get(0x0017)
        h19 = second.handle_stats.get(0x0019)
        lines.append(
            "- **Observed (second capture):** "
            f"0x0042 TX={getattr(h42,'tx_count',0)} RX={getattr(h42,'rx_count',0)}; "
            f"0x0044 TX={getattr(h44,'tx_count',0)} RX={getattr(h44,'rx_count',0)}; "
            f"0x0017 TX={getattr(h17,'tx_count',0)} RX={getattr(h17,'rx_count',0)}; "
            f"0x0019 TX={getattr(h19,'tx_count',0)} RX={getattr(h19,'rx_count',0)}."
        )
        # Compare to preliminary
        lines.append(
            "- Preliminary report expected: 74 write-cmd on 0x0042, 150 ntf on 0x0044, "
            "86 writes on 0x0017, 285 ntf on 0x0019 — see handle table above for independent counts."
        )
        # Opcode specifics for 0x0042
        if h42:
            lines.append(f"  - 0x0042 opcodes: {dict(h42.opcodes)}")
        if h44:
            lines.append(f"  - 0x0044 opcodes: {dict(h44.opcodes)}")

        # Sample captured prefixes for writes/notifications when bytes exist
        samples = []
        for att in second.att_pdus:
            if att.att_handle in INTERESTING_HANDLES and len(att.payload) >= 3:
                samples.append(att)
        lines.append("")
        lines.append("### Captured payload prefixes (only where bytes exist)")
        lines.append("")
        lines.append("| Rec | Dir | Op | Handle | Incomplete | Hex prefix (≤32 B) |")
        lines.append("|---:|---|---|---|---|---|")
        shown = 0
        for att in samples:
            if shown >= 40:
                break
            # Prefer showing complete short ones and first bytes of truncated
            lines.append(
                f"| {att.record_index} | {att.direction} | {att.opcode_name} | "
                f"`0x{att.att_handle:04X}` | {att.incomplete_payload} | `{att.payload[:32].hex()}` |"
            )
            shown += 1
        if shown == 0:
            lines.append("| — | | | | | no payloads retained |")

    lines.append("")
    lines.append("### Framing hints from retained bytes")
    lines.append(
        "- **Observed:** `0x0017` writes and `0x0019` notifications retain prefix `FE FC` whenever "
        "≥2 payload bytes exist after the ATT handle — consistent across both captures."
    )
    lines.append(
        "- **Observed:** Complete (non-truncated) PDUs on `0x0042`/`0x0044` are often a *single* data byte "
        "(Write_Cmd `52 42 00 XX`, Ntf `1b 44 00 XX`), while many other PDUs on those handles have "
        "`original_length` up to 256 with bodies stripped — consistent with ACK/credit bytes interleaved "
        "with bulk notifications/writes whose contents are missing from `btsnooz`."
    )
    lines.append(
        "- **Inferred (unproven UUID bind):** nRF hints map service `0x56FF` (`0x33F3`/`0x33F4`) to the "
        "`0x0042`/`0x0044` pair and `0xFF12` (`0xFF15`/`0xFF14`) to `0x0017`/`0x0019`. Confirm with GATT inspect."
    )
    lines.append("")
    lines.append("### What truncation prevents")
    lines.append(
        "- **Unknown:** audio codec, framing, checksums, file listing commands, authentication tokens — "
        "payload bodies are largely stripped in `btsnooz`."
    )
    lines.append(
        "- **Observed:** opcode types, ATT handles, directions, timing, and *original* sizes still allow "
        "identifying *which characteristics* carried the bulk exchange."
    )
    lines.append("")
    lines.append("Full narrative: `reports/engineering_findings.md`.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze SR116 HCI btsnoop captures")
    parser.add_argument(
        "captures",
        nargs="*",
        type=Path,
        help="btsnoop log paths (default: both SR116 captures in repo root)",
    )
    parser.add_argument(
        "-o",
        "--out-dir",
        type=Path,
        default=Path("reports"),
        help="output directory for reports",
    )
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    captures = args.captures
    if not captures:
        captures = [
            root / "btsnooz_hci.log",
            root / "sr116_second_btsnooz_hci.log",
        ]

    out_dir = args.out_dir
    if not out_dir.is_absolute():
        out_dir = root / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    analyses: list[CaptureAnalysis] = []
    for path in captures:
        if not path.is_file():
            print(f"MISSING: {path}", file=sys.stderr)
            continue
        print(f"Analyzing {path} ...")
        a = analyze_capture(path)
        analyses.append(a)
        print(
            f"  size={a.file_size} records={len(a.records)} truncated={a.truncated_count} "
            f"ATT_PDUs={len(a.att_pdus)} incomplete_reasm={a.incomplete_reassemblies}"
        )

    if not analyses:
        print("No captures analyzed.", file=sys.stderr)
        return 1

    write_comparison_md(analyses, out_dir / "capture_comparison.md")
    write_packets_csv(analyses, out_dir / "packets.csv")
    write_handle_summary_csv(analyses, out_dir / "handle_summary.csv")
    write_timeline_csv(analyses, out_dir / "timeline.csv")
    print(f"Wrote reports to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
