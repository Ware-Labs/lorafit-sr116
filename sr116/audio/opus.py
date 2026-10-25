"""Opus frame extract / Ogg / WAV helpers for SR116 offline chunks."""

from __future__ import annotations

import struct
import subprocess
import wave
from pathlib import Path

FRAME_BYTES = 40
FRAMES_PER_CHUNK = 12
CHUNK_BODY = FRAME_BYTES * FRAMES_PER_CHUNK  # 480
SAMPLE_RATE = 48000
FRAME_SAMPLES = SAMPLE_RATE // 50  # 20 ms


def crc32_ogg(data: bytes) -> int:
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
    if not blob:
        return []
    if len(blob) % 486 == 0 and len(blob) >= 486:
        frames: list[bytes] = []
        for i in range(0, len(blob), 486):
            body = blob[i + 6 : i + 486]
            if len(body) == CHUNK_BODY and body[0] == 0xB8:
                for j in range(0, CHUNK_BODY, FRAME_BYTES):
                    frames.append(body[j : j + FRAME_BYTES])
        if frames:
            return frames
    if len(blob) % CHUNK_BODY == 0 and blob[0] == 0xB8:
        return [blob[i : i + FRAME_BYTES] for i in range(0, len(blob), FRAME_BYTES)]
    if len(blob) % FRAME_BYTES == 0 and blob[0] == 0xB8:
        return [blob[i : i + FRAME_BYTES] for i in range(0, len(blob), FRAME_BYTES)]
    frames = []
    i = 0
    while i + FRAME_BYTES <= len(blob):
        if blob[i] == 0xB8:
            frames.append(blob[i : i + FRAME_BYTES])
            i += FRAME_BYTES
        else:
            i += 1
    return frames


def _build_opus_head(channels: int = 1, input_sample_rate: int = 48000) -> bytes:
    return b"".join(
        [
            b"OpusHead",
            b"\x01",
            bytes([channels]),
            struct.pack("<H", 0),
            struct.pack("<I", input_sample_rate),
            struct.pack("<h", 0),
            b"\x00",
        ]
    )


def _build_opus_tags() -> bytes:
    vendor = b"sr116-local"
    return b"".join(
        [b"OpusTags", struct.pack("<I", len(vendor)), vendor, struct.pack("<I", 0)]
    )


def _ogg_page(
    data: bytes,
    *,
    granule: int,
    serial: int,
    seq: int,
    header_type: int,
) -> bytes:
    segments: list[int] = []
    remaining = len(data)
    while remaining >= 255:
        segments.append(255)
        remaining -= 255
    segments.append(remaining)
    header = bytearray()
    header += b"OggS\x00"
    header += bytes([header_type])
    header += struct.pack("<Q", granule)
    header += struct.pack("<I", serial)
    header += struct.pack("<I", seq)
    header += b"\x00\x00\x00\x00"
    header += bytes([len(segments)])
    header += bytes(segments)
    page = bytes(header) + data
    crc = crc32_ogg(page)
    return page[:22] + struct.pack("<I", crc) + page[26:]


def write_ogg_opus(frames: list[bytes], out: Path) -> None:
    serial = 0x53313136
    pages = [
        _ogg_page(_build_opus_head(1, SAMPLE_RATE), granule=0, serial=serial, seq=0, header_type=0x02),
        _ogg_page(_build_opus_tags(), granule=0, serial=serial, seq=1, header_type=0x00),
    ]
    granule = 0
    seq = 2
    for i, frame in enumerate(frames):
        granule += FRAME_SAMPLES
        ht = 0x04 if i == len(frames) - 1 else 0x00
        pages.append(_ogg_page(frame, granule=granule, serial=serial, seq=seq, header_type=ht))
        seq += 1
    out.write_bytes(b"".join(pages))


def bodies_to_ogg(bodies: bytes, out: Path) -> tuple[Path, int, float]:
    """Write Ogg from concatenated 480-byte chunk bodies. Returns path, frames, duration_s."""
    frames = extract_opus_frames(bodies)
    if not frames:
        raise ValueError("no Opus frames in body blob")
    write_ogg_opus(frames, out)
    return out, len(frames), len(frames) * 0.02


def _ffmpeg_ogg_to_wav(ogg: Path, wav: Path) -> bool:
    try:
        import imageio_ffmpeg

        ff = imageio_ffmpeg.get_ffmpeg_exe()
        r = subprocess.run(
            [ff, "-y", "-i", str(ogg), str(wav)],
            capture_output=True,
            text=True,
        )
        return r.returncode == 0 and wav.is_file()
    except Exception:
        return False


def bodies_to_wav(bodies: bytes, wav: Path, *, ogg: Path | None = None) -> Path:
    frames = extract_opus_frames(bodies)
    if not frames:
        raise ValueError("no Opus frames")
    ogg_path = ogg or wav.with_suffix(".ogg")
    if not ogg_path.is_file():
        write_ogg_opus(frames, ogg_path)
    if not _ffmpeg_ogg_to_wav(ogg_path, wav):
        raise RuntimeError("WAV decode failed (install imageio-ffmpeg)")
    return wav


def play_wav(path: Path) -> None:
    import winsound

    winsound.PlaySound(str(path), winsound.SND_FILENAME)
