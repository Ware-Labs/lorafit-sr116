"""SpO₂ measurement."""

from __future__ import annotations

from typing import Callable, Optional

from sr116.features.decode import parse_live_value
from sr116.protocol.commands import CMD
from sr116.protocol.jy import JyFrame
from sr116.protocol.session import JySession
from sr116.store import Store

SampleCb = Callable[[int, int], None]


class Spo2Service:
    def __init__(self, session: JySession, store: Optional[Store] = None) -> None:
        self.s = session
        self.store = store
        self.running = False
        self.last_spo2: Optional[int] = None
        self.last_ts: Optional[int] = None
        self._cb: Optional[SampleCb] = None
        session.add_listener(self._on_frame)

    def on_sample(self, cb: Optional[SampleCb]) -> None:
        self._cb = cb

    def _on_frame(self, frame: JyFrame) -> None:
        if frame.cmd == CMD.SPO2_SAMPLE:
            parsed = parse_live_value(frame.payload)
            if not parsed:
                return
            ts, val = parsed
            self.last_ts, self.last_spo2 = ts, val
            if self.store:
                self.store.add_vital(ts, "spo2", float(val), source="live")
            if self._cb:
                self._cb(ts, val)
        elif frame.cmd == CMD.SPO2_END:
            self.running = False

    async def start(self) -> None:
        await self.s.write(CMD.SPO2_CTRL, b"\x01", expect_reply=True, reply_timeout=3.0)
        self.running = True

    async def stop(self) -> None:
        await self.s.write(CMD.SPO2_CTRL, b"\x00", expect_reply=True, reply_timeout=5.0)
        self.running = False
