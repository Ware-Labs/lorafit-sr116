"""Unit tests for JY framing and payload decoders (no BLE)."""

from __future__ import annotations

import struct
import unittest
from pathlib import Path

from sr116.audio.opus import extract_opus_frames
from sr116.features.decode import (
    parse_audio_count,
    parse_health_samples,
    parse_live_value,
    parse_step_buckets,
    parse_step_status,
    parse_sleep_rows,
)
from sr116.protocol.commands import ALLOWED_TX, CMD
from sr116.protocol.jy import pack_jy, parse_jy


class TestJyFraming(unittest.TestCase):
    def test_roundtrip_empty(self) -> None:
        # Captured prep: fefc4000010001000000
        raw = pack_jy(0x40, b"")
        self.assertEqual(raw, bytes.fromhex("fefc4000010001000000"))
        fr = parse_jy(raw)
        assert fr is not None
        self.assertEqual(fr.cmd, 0x40)
        self.assertEqual(fr.total, 1)
        self.assertEqual(fr.idx, 1)
        self.assertEqual(fr.payload, b"")

    def test_roundtrip_payload(self) -> None:
        raw = pack_jy(0x17, b"\x01")
        self.assertEqual(raw, bytes.fromhex("fefc170001000100010001"))
        fr = parse_jy(raw)
        assert fr is not None
        self.assertEqual(fr.payload, b"\x01")

    def test_reject_non_jy(self) -> None:
        self.assertIsNone(parse_jy(b"\x00\x01\x02"))

    def test_allowlist_has_core(self) -> None:
        for c in (CMD.OPEN_HR, CMD.AUDIO_PREP, CMD.AUDIO_DATA, CMD.STEP_STATUS):
            self.assertIn(c, ALLOWED_TX)
        self.assertIn(CMD.AUDIO_DONE, ALLOWED_TX)  # gated at session layer


class TestDecoders(unittest.TestCase):
    def test_step_status_5397(self) -> None:
        # From steps capture: steps=5397 cal=146 dist=4182
        pl = bytes.fromhex("013fde6a00001515000092005610")
        st = parse_step_status(pl)
        assert st is not None
        self.assertEqual(st.steps, 5397)
        self.assertEqual(st.calories, 146)
        self.assertEqual(st.distance, 4182)

    def test_health_samples(self) -> None:
        pl = bytes.fromhex(
            "7f27de6a00004c63360100361013"
            "6b3bde6a00005062360100303514"
            "c33dde6a000048003601002d3512"
            "ef3ede6a00006f6236010056351b"
        )
        samples = parse_health_samples(pl)
        self.assertEqual(len(samples), 4)
        self.assertEqual(samples[0].hr, 76)
        self.assertEqual(samples[0].spo2, 99)
        self.assertEqual(samples[3].hr, 111)
        self.assertEqual(samples[3].spo2, 98)

    def test_live_hr(self) -> None:
        # bpm=75 from heartrate capture
        pl = bytes.fromhex("be3cde6a00004b")
        parsed = parse_live_value(pl)
        assert parsed is not None
        ts, bpm = parsed
        self.assertEqual(bpm, 75)

    def test_spo2_sample(self) -> None:
        pl = bytes.fromhex("f13ade6a000062")
        parsed = parse_live_value(pl)
        assert parsed is not None
        self.assertEqual(parsed[1], 98)

    def test_audio_count(self) -> None:
        self.assertEqual(parse_audio_count(bytes.fromhex("0300")), 3)

    def test_step_bucket_one(self) -> None:
        # First bucket from steps analysis
        rec = bytes.fromhex("73f7dd6a00002c01e00100000d007401")
        buckets = parse_step_buckets(rec)
        self.assertEqual(len(buckets), 1)
        self.assertEqual(buckets[0].steps, 480)
        self.assertEqual(buckets[0].field, 300)

    def test_sleep_row(self) -> None:
        rec = bytes.fromhex("3ef6dd6a00000002")
        rows = parse_sleep_rows(rec)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].flags, b"\x00\x00\x00\x02")


class TestOpusExtract(unittest.TestCase):
    def test_chunk_body_frames(self) -> None:
        body = bytes([0xB8] + [0] * 39) * 12
        frames = extract_opus_frames(body)
        self.assertEqual(len(frames), 12)
        self.assertEqual(frames[0][0], 0xB8)

    def test_fixture_bin_if_present(self) -> None:
        p = Path("reports/transfer_0x34_bodies.bin")
        if not p.is_file():
            self.skipTest("no transfer fixture")
        frames = extract_opus_frames(p.read_bytes())
        self.assertGreater(len(frames), 0)
        self.assertEqual(frames[0][0], 0xB8)


class TestStoreStats(unittest.TestCase):
    def test_stats_today(self) -> None:
        import tempfile
        from sr116.store import Store

        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "t.db")
            # fixed day
            base = 1792949400  # within 2026-10-25-ish from captures
            store.add_vital(base, "hr", 75, source="live")
            store.add_vital(base + 1, "hr", 64, source="live")
            store.add_vital(base + 2, "hr", 111, source="health")
            st = store.stats_today("hr", now=base)
            self.assertEqual(st.count, 3)
            self.assertEqual(st.min_v, 64)
            self.assertEqual(st.max_v, 111)
            self.assertEqual(st.latest, 111)
            self.assertAlmostEqual(st.avg or 0, (75 + 64 + 111) / 3)
            store.close()


if __name__ == "__main__":
    unittest.main()
