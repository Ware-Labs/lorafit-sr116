"""Live heart-rate measurement."""

from __future__ import annotations

from typing import Callable, Optional

from sr116.features.decode import parse_live_value
from sr116.protocol.commands import AUTO_HR_DISABLE, AUTO_HR_ENABLE, CMD
from sr116.protocol.jy import JyFrame
from sr116.protocol.session import JySession
from sr116.store import Store

SampleCb = Callable[[int, int], None]  # ts, bpm


class HeartRateService:
    def __init__(self, session: JySession, store: Optional[Store] = None) -> None:
        self.s = session
        self.store = store
        self.running = False
        self.last_bpm: Optional[int] = None
        self.last_ts: Optional[int] = None
        self._cb: Optional[SampleCb] = None
        session.add_listener(self._on_frame)

    def on_sample(self, cb: Optional[SampleCb]) -> None:
        self._cb = cb

    def _on_frame(self, frame: JyFrame) -> None:
        if frame.cmd == CMD.LIVE_HR:
            parsed = parse_live_value(frame.payload)
            if not parsed:
                return
            ts, bpm = parsed
            self.last_ts, self.last_bpm = ts, bpm
            if self.store:
                self.store.add_vital(ts, "hr", float(bpm), source="live")
            if self._cb:
                self._cb(ts, bpm)
        elif frame.cmd == CMD.HR_END:
            self.running = False

    async def start(self) -> None:
        await self.s.write(CMD.OPEN_HR, b"", expect_reply=True, reply_timeout=3.0)
        await self.s.write(
            CMD.AUTO_HR, AUTO_HR_ENABLE, expect_reply=True, reply_timeout=3.0
        )
        self.running = True

    async def stop(self) -> None:
        try:
            await self.s.write(
                CMD.AUTO_HR, AUTO_HR_DISABLE, expect_reply=False, reply_timeout=2.0
            )
        except Exception:
            pass
        await self.s.write(CMD.CLOSE_HR, b"", expect_reply=True, reply_timeout=3.0)
        self.running = False
