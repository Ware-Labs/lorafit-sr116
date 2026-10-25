#!/usr/bin/env python3
"""
Convert SR116 offline-transfer body blobs to Ogg Opus and/or WAV.

Input formats accepted:
  - transfer_0x34_bodies.bin  — concatenated 480-byte chunk bodies
    (each body = 12 × 40-byte Opus packets; TOC 0xB8)
  - raw stream of 40-byte Opus frames
  - full ATT payloads (486 B = u32le ts + u16 0 + 480 B opus)

Audio parameters (from JY/LoraFit reverse engineering + this capture):
  Opus CELT, TOC 0xB8, 20 ms, mono, 48 kHz nominal (Opus fullband);
  ring documents also treat stream as 16 kHz — we decode at 48 kHz by default
  (Opus always decodes to the rate you request from libopus; 48 kHz is safest).

Usage:
  python tools/opus_bin_to_audio.py reports/transfer_0x34_bodies.bin
  python tools/opus_bin_to_audio.py reports/transfer_0x34_bodies.bin --wav
"""

from __future__ import annotations

import argparse
import struct
import sys
import wave
from pathlib import Path


FRAME_BYTES = 40
FRAMES_PER_CHUNK = 12
CHUNK_BODY = FRAME_BYTES * FRAMES_PER_CHUNK  # 480
SAMPLE_RATE = 48000
FRAME_SAMPLES = SAMPLE_RATE // 50  # 20 ms


def crc32_ogg(data: bytes) -> int:
    """Ogg CRC-32 (poly 0x04C11DB7, init 0, reflected differently from ZIP)."""
    # Standard Ogg CRC table
    crc = 0
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc


def extract_opus_frames(blob: bytes) -> list[bytes]:
    """Pull 40-byte Opus packets from known SR116 layouts."""
    if not blob:
        return []

    # Full 486-byte ATT payloads concatenated
    if len(blob) % 486 == 0 and len(blob) >= 486:
        frames: list[bytes] = []
        for i in range(0, len(blob), 486):
            payload = blob[i : i + 486]
            body = payload[6:486]
            if len(body) == CHUNK_BODY and body[0] == 0xB8:
                for j in range(0, CHUNK_BODY, FRAME_BYTES):
                    frames.append(body[j : j + FRAME_BYTES])
        if frames:
            return frames

    # Chunk bodies only (480 × N)
    if len(blob) % CHUNK_BODY == 0 and blob[0] == 0xB8:
        return [blob[i : i + FRAME_BYTES] for i in range(0, len(blob), FRAME_BYTES)]

    # Raw 40-byte frames
    if len(blob) % FRAME_BYTES == 0 and blob[0] == 0xB8:
        return [blob[i : i + FRAME_BYTES] for i in range(0, len(blob), FRAME_BYTES)]

    # Fallback: scan for 0xB8-aligned 40-byte runs
    frames = []
    i = 0
    while i + FRAME_BYTES <= len(blob):
        if blob[i] == 0xB8:
            frames.append(blob[i : i + FRAME_BYTES])
            i += FRAME_BYTES
        else:
            i += 1
    return frames


def build_opus_head(channels: int = 1, input_sample_rate: int = 48000) -> bytes:
    # https://wiki.xiph.org/OggOpus
    return b"".join(
        [
            b"OpusHead",
            b"\x01",  # version
            bytes([channels]),
            struct.pack("<H", 0),  # pre-skip
            struct.pack("<I", input_sample_rate),
            struct.pack("<h", 0),  # output gain
            b"\x00",  # channel mapping family 0
        ]
    )


def build_opus_tags() -> bytes:
    vendor = b"sr116-ring-hack"
    parts = [b"OpusTags", struct.pack("<I", len(vendor)), vendor, struct.pack("<I", 0)]
    return b"".join(parts)


def ogg_page(
    data: bytes,
    *,
    granule: int,
    serial: int,
    seq: int,
    header_type: int,
    segments: list[int] | None = None,
) -> bytes:
    if segments is None:
        # Split into ≤255-byte lacing values
        segments = []
        remaining = len(data)
        off = 0
        while remaining >= 255:
            segments.append(255)
            remaining -= 255
            off += 255
        segments.append(remaining)
    assert sum(segments) == len(data)
    header = bytearray()
    header += b"OggS"
    header += b"\x00"  # version
    header += bytes([header_type])
    header += struct.pack("<Q", granule)
    header += struct.pack("<I", serial)
    header += struct.pack("<I", seq)
    header += b"\x00\x00\x00\x00"  # CRC placeholder
    header += bytes([len(segments)])
    header += bytes(segments)
    page = bytes(header) + data
    crc = crc32_ogg(page)
    return page[:22] + struct.pack("<I", crc) + page[26:]


def write_ogg_opus(frames: list[bytes], out: Path) -> None:
    serial = 0x53313136  # 'S116'
    pages = []
    # BOS OpusHead
    pages.append(
        ogg_page(
            build_opus_head(1, SAMPLE_RATE),
            granule=0,
            serial=serial,
            seq=0,
            header_type=0x02,  # BOS
        )
    )
    # OpusTags
    pages.append(
        ogg_page(
            build_opus_tags(),
            granule=0,
            serial=serial,
            seq=1,
            header_type=0x00,
        )
    )
    granule = 0
    seq = 2
    for i, frame in enumerate(frames):
        granule += FRAME_SAMPLES
        ht = 0x04 if i == len(frames) - 1 else 0x00  # EOS on last
        pages.append(
            ogg_page(frame, granule=granule, serial=serial, seq=seq, header_type=ht)
        )
        seq += 1
    out.write_bytes(b"".join(pages))


def try_decode_wav(frames: list[bytes], out: Path, rate: int = SAMPLE_RATE) -> bool:
    decoder = None
    try:
        from opuslib_next import Decoder  # type: ignore

        decoder = Decoder(rate, 1)
    except Exception:
        try:
            from opuslib import Decoder  # type: ignore

            decoder = Decoder(rate, 1)
        except Exception as e:
            print(f"WAV decode skipped (no libopus): {e}", file=sys.stderr)
            return False

    frame_samples = rate // 50
    pcm = bytearray()
    for fr in frames:
        try:
            pcm.extend(decoder.decode(bytes(fr), frame_samples))
        except Exception as e:
            print(f"decode error on frame: {e}", file=sys.stderr)
            # insert silence
            pcm.extend(b"\x00\x00" * frame_samples)

    with wave.open(str(out), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(pcm))
    return True


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SR116 Opus body → Ogg/WAV")
    ap.add_argument("input", type=Path, help="transfer_0x34_bodies.bin or similar")
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        help="output .ogg path (default: alongside input)",
    )
    ap.add_argument(
        "--wav",
        action="store_true",
        help="also decode to WAV (libopus or bundled ffmpeg)",
    )
    ap.add_argument(
        "--play",
        action="store_true",
        help="decode to WAV and play it (Windows winsound)",
    )
    ap.add_argument(
        "--rate",
        type=int,
        default=SAMPLE_RATE,
        help="PCM sample rate for WAV (default 48000)",
    )
    args = ap.parse_args(argv)

    blob = args.input.read_bytes()
    frames = extract_opus_frames(blob)
    if not frames:
        print("No Opus frames found.", file=sys.stderr)
        return 1
    toc = frames[0][0]
    duration_s = len(frames) * 0.02
    print(
        f"frames={len(frames)} toc=0x{toc:02X} duration~{duration_s:.2f}s "
        f"({len(frames)/FRAMES_PER_CHUNK:.0f} BLE chunks)"
    )

    ogg_path = args.output or args.input.with_suffix(".ogg")
    write_ogg_opus(frames, ogg_path)
    print(f"wrote {ogg_path} ({ogg_path.stat().st_size} bytes)")

    want_wav = args.wav or args.play
    wav_path = ogg_path.with_suffix(".wav")
    if want_wav:
        ok = try_decode_wav(frames, wav_path, rate=args.rate)
        if not ok:
            ok = _ffmpeg_ogg_to_wav(ogg_path, wav_path)
        if ok:
            print(f"wrote {wav_path} ({wav_path.stat().st_size} bytes)")
        else:
            print(
                "Could not decode WAV. Play the .ogg in VLC, or: "
                "pip install imageio-ffmpeg",
                file=sys.stderr,
            )
            return 2

    if args.play:
        _play_wav(wav_path)
    return 0


def _ffmpeg_ogg_to_wav(ogg: Path, wav: Path) -> bool:
    try:
        import imageio_ffmpeg
        import subprocess

        ff = imageio_ffmpeg.get_ffmpeg_exe()
        r = subprocess.run(
            [ff, "-y", "-i", str(ogg), str(wav)],
            capture_output=True,
            text=True,
        )
        return r.returncode == 0 and wav.is_file()
    except Exception as e:
        print(f"ffmpeg fallback failed: {e}", file=sys.stderr)
        return False


def _play_wav(path: Path) -> None:
    try:
        import winsound

        print(f"Playing {path} ...")
        winsound.PlaySound(str(path), winsound.SND_FILENAME)
        print("done")
    except Exception as e:
        print(f"Play failed: {e}. Open {path} manually.", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
