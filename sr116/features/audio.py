"""Offline audio count / FIFO download (optional delete via 0x36)."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from sr116.audio.opus import bodies_to_ogg, bodies_to_wav
from sr116.features.decode import extract_opus_chunk_body, parse_audio_count
from sr116.protocol.commands import CMD
from sr116.protocol.jy import JyFrame
from sr116.protocol.session import JySession
from sr116.store import Store

ProgressCb = Callable[[str], None]


@dataclass
class DownloadedFile:
    bin_path: Path
    ogg_path: Path
    wav_path: Optional[Path]
    chunks: int
    duration_s: float
    remaining_after: Optional[int]
    deleted_on_ring: bool


@dataclass
class _TransferState:
    collecting: bool = False
    chunks: list[bytes] = field(default_factory=list)
    total: int = 0
    done_event: Optional[asyncio.Event] = None
    empty_event: Optional[asyncio.Event] = None
    complete_frame: Optional[JyFrame] = None
    error: Optional[str] = None


class AudioService:
    def __init__(
        self,
        session: JySession,
        *,
        out_dir: Path,
        store: Optional[Store] = None,
    ) -> None:
        self.s = session
        self.out_dir = out_dir
        self.store = store
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.count: Optional[int] = None
        self._xfer = _TransferState()
        self._lock = asyncio.Lock()
        session.add_listener(self._on_frame)

    def _on_frame(self, frame: JyFrame) -> None:
        x = self._xfer
        if frame.cmd == CMD.AUDIO_EMPTY and x.empty_event is not None:
            x.empty_event.set()
            return
        if frame.cmd == CMD.AUDIO_DONE:
            x.complete_frame = frame
            if x.done_event is not None:
                x.done_event.set()
            return
        if frame.cmd == CMD.AUDIO_DATA and x.collecting and frame.payload:
            body = extract_opus_chunk_body(frame.payload)
            if body:
                x.chunks.append(body)
                x.total = frame.total
            if frame.idx >= frame.total and frame.total > 0:
                # wait for 0x36 rather than finishing early
                pass

    async def query_count(self) -> int:
        fr = await self.s.write(
            CMD.AUDIO_COUNT, b"", expect_reply=True, reply_timeout=5.0
        )
        n = parse_audio_count(fr.payload) if fr else 0
        self.count = n
        return n

    async def download_next(
        self,
        *,
        delete_after: bool = False,
        make_wav: bool = True,
        on_progress: Optional[ProgressCb] = None,
        prepared: bool = False,
    ) -> Optional[DownloadedFile]:
        """
        Pull next FIFO file.
        delete_after=False: do not echo 0x36 (keep on ring).
        prepared=True: skip 0x40 (already sent for this batch).
        Returns None if queue empty (0x35).
        """
        async with self._lock:
            log = on_progress or (lambda _m: None)
            if not prepared:
                await self.s.write(
                    CMD.AUDIO_PREP, b"", expect_reply=True, reply_timeout=5.0
                )
                log("sent audio prep 0x40")

            x = self._xfer
            x.collecting = True
            x.chunks = []
            x.total = 0
            x.complete_frame = None
            x.done_event = asyncio.Event()
            x.empty_event = asyncio.Event()
            x.error = None

            await self.s.write(CMD.AUDIO_DATA, b"", expect_reply=False)
            log("sent empty 0x34 (start next)")

            # Wait for either empty queue or transfer complete
            try:
                done, pending = await asyncio.wait(
                    [
                        asyncio.create_task(x.done_event.wait()),
                        asyncio.create_task(x.empty_event.wait()),
                    ],
                    timeout=60.0,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for t in pending:
                    t.cancel()
            except Exception as e:
                x.collecting = False
                raise RuntimeError(f"download wait failed: {e}") from e

            if x.empty_event.is_set() and not x.chunks:
                x.collecting = False
                log("queue empty (0x35)")
                return None

            # If we got chunks but 0x36 timed out, still save
            if not x.done_event.is_set() and x.chunks:
                log(f"timeout on 0x36; saving {len(x.chunks)} chunks anyway")
            elif not x.chunks and x.empty_event.is_set():
                x.collecting = False
                return None
            elif not x.chunks:
                x.collecting = False
                raise RuntimeError("no audio chunks received")

            x.collecting = False
            bodies = b"".join(x.chunks)
            n_chunks = len(x.chunks)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            base = self.out_dir / f"recording_{stamp}_{n_chunks}ch"
            bin_path = base.with_suffix(".bin")
            bin_path.write_bytes(bodies)
            log(f"wrote {bin_path.name} ({len(bodies)} bytes, {n_chunks} chunks)")

            ogg_path = base.with_suffix(".ogg")
            _, n_frames, dur = bodies_to_ogg(bodies, ogg_path)
            wav_path: Optional[Path] = None
            if make_wav:
                try:
                    wav_path = bodies_to_wav(bodies, base.with_suffix(".wav"), ogg=ogg_path)
                except Exception as e:
                    log(f"wav skipped: {e}")

            remaining = None
            deleted = False
            if x.complete_frame and len(x.complete_frame.payload) >= 2:
                remaining = parse_audio_count(x.complete_frame.payload)

            if delete_after and x.complete_frame is not None:
                echo_pl = x.complete_frame.payload
                await self.s.write(
                    CMD.AUDIO_DONE,
                    echo_pl,
                    expect_reply=False,
                    allow_delete=True,
                )
                deleted = True
                log(f"echoed 0x36 (DELETE on ring); rem payload={echo_pl.hex()}")
            elif delete_after:
                log("delete requested but no 0x36 from ring — skipped echo")
            else:
                log("kept on ring (did not echo 0x36)")

            if self.store:
                self.store.add_recording(
                    str(bin_path),
                    ogg_path=str(ogg_path),
                    wav_path=str(wav_path) if wav_path else None,
                    chunks=n_chunks,
                    duration_s=dur,
                    deleted_on_ring=deleted,
                )

            return DownloadedFile(
                bin_path=bin_path,
                ogg_path=ogg_path,
                wav_path=wav_path,
                chunks=n_chunks,
                duration_s=dur,
                remaining_after=remaining,
                deleted_on_ring=deleted,
            )

    async def download_all(
        self,
        *,
        delete_after: bool = False,
        make_wav: bool = True,
        on_progress: Optional[ProgressCb] = None,
    ) -> list[DownloadedFile]:
        log = on_progress or (lambda _m: None)
        n = await self.query_count()
        log(f"offline count={n}")
        if n <= 0:
            return []
        await self.s.write(CMD.AUDIO_PREP, b"", expect_reply=True, reply_timeout=5.0)
        out: list[DownloadedFile] = []
        for i in range(n + 1):  # +1 probe for 0x35
            log(f"download slot {i + 1}/{n}")
            f = await self.download_next(
                delete_after=delete_after,
                make_wav=make_wav,
                on_progress=on_progress,
                prepared=True,
            )
            if f is None:
                break
            out.append(f)
        return out
