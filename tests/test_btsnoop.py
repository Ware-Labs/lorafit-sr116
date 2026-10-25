"""Unit tests for btsnoop record parsing and ACL/L2CAP reassembly."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from analyze_btsnoop import (  # noqa: E402
    BTSNOOP_MAGIC,
    DATALINK_H4,
    H4_ACL,
    analyze_capture,
    iter_btsnoop_records,
    parse_acl_header,
    parse_btsnoop_header,
    reassemble_l2cap,
    BtsnoopRecord,
)


def _make_file(records: list[tuple[int, int, int, bytes]]) -> bytes:
    """Build a minimal btsnoop file. records: (orig, incl, flags, payload)."""
    header = BTSNOOP_MAGIC + struct.pack(">II", 1, DATALINK_H4)
    body = bytearray()
    ts = 1_000_000
    for orig, incl, flags, payload in records:
        assert len(payload) == incl
        body += struct.pack(">IIIIQ", orig, incl, flags, 0, ts)
        body += payload
        ts += 10_000
    return header + bytes(body)


class TestBtsnoopHeader(unittest.TestCase):
    def test_header_ok(self):
        data = BTSNOOP_MAGIC + struct.pack(">II", 1, DATALINK_H4)
        ver, dl = parse_btsnoop_header(data)
        self.assertEqual(ver, 1)
        self.assertEqual(dl, DATALINK_H4)

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            parse_btsnoop_header(b"notsnoop" + b"\x00" * 8)


class TestRecordIteration(unittest.TestCase):
    def test_single_complete_record(self):
        payload = bytes([H4_ACL, 0x00, 0x20, 0x01, 0x00, 0xAA])
        data = _make_file([(6, 6, 0x01, payload)])  # RX data
        recs = list(iter_btsnoop_records(data))
        self.assertEqual(len(recs), 1)
        self.assertFalse(recs[0].incomplete_payload)
        self.assertEqual(recs[0].direction, "RX")
        self.assertEqual(recs[0].payload, payload)

    def test_truncated_flag_when_orig_gt_incl(self):
        payload = bytes([0x02, 0x00, 0x20, 0x01, 0x00])  # 5 bytes included
        data = _make_file([(256, 5, 0x01, payload)])
        recs = list(iter_btsnoop_records(data))
        self.assertEqual(len(recs), 1)
        self.assertTrue(recs[0].incomplete_payload)
        self.assertEqual(recs[0].original_length, 256)
        self.assertEqual(recs[0].included_length, 5)


class TestAclHeader(unittest.TestCase):
    def test_parse(self):
        # handle 0x0040, PB=0 (start), BC=0, len=10
        raw = struct.pack("<HH", 0x0040, 10) + b"\x00" * 10
        hdr = parse_acl_header(raw)
        assert hdr is not None
        self.assertEqual(hdr.connection_handle, 0x040)
        self.assertEqual(hdr.pb_flag, 0)
        self.assertEqual(hdr.data_total_length, 10)


class TestL2capReassembly(unittest.TestCase):
    def _acl_rec(
        self,
        index: int,
        handle: int,
        pb: int,
        body: bytes,
        direction_rx: bool = True,
        incomplete: bool = False,
        orig: int | None = None,
    ) -> BtsnoopRecord:
        handle_pb = (handle & 0x0FFF) | ((pb & 3) << 12)
        acl = struct.pack("<HH", handle_pb, len(body)) + body
        payload = bytes([H4_ACL]) + acl
        incl = len(payload)
        original = orig if orig is not None else incl
        return BtsnoopRecord(
            index=index,
            original_length=original,
            included_length=incl,
            flags=0x01 if direction_rx else 0x00,
            cumulative_drops=0,
            timestamp_us=1_000_000 + index * 1000,
            payload=payload,
            incomplete_payload=incomplete or original > incl,
        )

    def test_single_start_complete(self):
        # L2CAP: length=4, CID=0x0004, payload=aabbccdd
        l2 = struct.pack("<HH", 4, 0x0004) + bytes.fromhex("aabbccdd")
        rec = self._acl_rec(0, 0x40, pb=0b00, body=l2)
        pdus, incomplete = reassemble_l2cap([rec])
        self.assertEqual(incomplete, 0)
        self.assertEqual(len(pdus), 1)
        self.assertEqual(pdus[0].cid, 0x0004)
        self.assertEqual(pdus[0].payload, bytes.fromhex("aabbccdd"))
        self.assertFalse(pdus[0].incomplete_payload)

    def test_fragmented_reassembly(self):
        full_payload = bytes(range(20))
        l2 = struct.pack("<HH", 20, 0x0004) + full_payload
        # split after 8 bytes of ACL body
        part1 = l2[:8]
        part2 = l2[8:]
        r0 = self._acl_rec(0, 0x40, pb=0b00, body=part1)
        r1 = self._acl_rec(1, 0x40, pb=0b01, body=part2)
        pdus, incomplete = reassemble_l2cap([r0, r1])
        self.assertEqual(incomplete, 0)
        self.assertEqual(len(pdus), 1)
        self.assertEqual(pdus[0].payload, full_payload)
        self.assertEqual(pdus[0].record_indices, [0, 1])

    def test_truncated_source_marks_incomplete(self):
        l2 = struct.pack("<HH", 4, 0x0004) + bytes.fromhex("aabbccdd")
        rec = self._acl_rec(0, 0x40, pb=0b00, body=l2, incomplete=True, orig=100)
        pdus, _ = reassemble_l2cap([rec])
        self.assertEqual(len(pdus), 1)
        self.assertTrue(pdus[0].incomplete_payload)

    def test_orphan_continuation_not_joined(self):
        body = b"\x00" * 8
        rec = self._acl_rec(0, 0x40, pb=0b01, body=body)
        pdus, incomplete = reassemble_l2cap([rec])
        self.assertEqual(len(pdus), 0)
        self.assertGreaterEqual(incomplete, 1)

    def test_new_start_flushes_previous_incomplete(self):
        # First start never completes
        incomplete_l2 = struct.pack("<HH", 100, 0x0004) + b"\x11\x22"
        r0 = self._acl_rec(0, 0x40, pb=0b00, body=incomplete_l2)
        # New start that completes
        ok = struct.pack("<HH", 2, 0x0004) + b"\xaa\xbb"
        r1 = self._acl_rec(1, 0x40, pb=0b00, body=ok)
        pdus, incomplete = reassemble_l2cap([r0, r1])
        self.assertGreaterEqual(incomplete, 1)
        self.assertTrue(any(p.payload == b"\xaa\xbb" and not p.incomplete_payload for p in pdus))


class TestRealCapturesSmoke(unittest.TestCase):
    def test_first_capture_counts(self):
        path = ROOT / "btsnooz_hci.log"
        if not path.is_file():
            self.skipTest("capture missing")
        a = analyze_capture(path)
        self.assertEqual(a.file_size, 64813)
        self.assertEqual(len(a.records), 1747)
        self.assertEqual(a.truncated_count, 394)

    def test_second_capture_counts(self):
        path = ROOT / "sr116_second_btsnooz_hci.log"
        if not path.is_file():
            self.skipTest("capture missing")
        a = analyze_capture(path)
        self.assertEqual(a.file_size, 64212)
        self.assertEqual(len(a.records), 1747)
        self.assertEqual(a.truncated_count, 836)
        self.assertEqual(a.h4_counts.get(H4_ACL, 0), 1291)


if __name__ == "__main__":
    unittest.main()
