"""Steps, sleep list, and health sample sync."""

from __future__ import annotations

from typing import Optional

from sr116.features.decode import (
    HealthSample,
    SleepRow,
    StepBucket,
    StepStatus,
    parse_health_samples,
    parse_sleep_rows,
    parse_step_buckets,
    parse_step_status,
)
from sr116.protocol.commands import CMD
from sr116.protocol.jy import JyFrame
from sr116.protocol.session import JySession
from sr116.store import Store


class StepsService:
    def __init__(self, session: JySession, store: Optional[Store] = None) -> None:
        self.s = session
        self.store = store
        self.status: Optional[StepStatus] = None
        self.buckets: list[StepBucket] = []
        self.sleep_rows: list[SleepRow] = []
        self.health: list[HealthSample] = []
        session.add_listener(self._on_frame)

    def _on_frame(self, frame: JyFrame) -> None:
        if frame.cmd == CMD.STEP_STATUS and frame.payload:
            st = parse_step_status(frame.payload)
            if st:
                self.status = st

    async def pull_status(self) -> Optional[StepStatus]:
        fr = await self.s.write(
            CMD.STEP_STATUS, b"", expect_reply=True, reply_timeout=4.0
        )
        if fr and fr.payload:
            self.status = parse_step_status(fr.payload)
        return self.status

    async def pull_buckets(self, day_offset: int = 0) -> list[StepBucket]:
        pl = bytes([day_offset & 0xFF])
        raw = await self.s.write_and_reassemble(CMD.LIST_21, pl, reply_timeout=12.0)
        self.buckets = parse_step_buckets(raw)
        return self.buckets

    async def pull_sleep(self, day_offset: int = 0) -> list[SleepRow]:
        pl = bytes([day_offset & 0xFF])
        raw = await self.s.write_and_reassemble(CMD.LIST_22, pl, reply_timeout=12.0)
        self.sleep_rows = parse_sleep_rows(raw)
        return self.sleep_rows

    async def pull_health(self, day_offset: int = 0) -> list[HealthSample]:
        pl = bytes([day_offset & 0xFF])
        raw = await self.s.write_and_reassemble(CMD.HEALTH, pl, reply_timeout=12.0)
        self.health = parse_health_samples(raw)
        if self.store:
            for h in self.health:
                if h.hr > 0:
                    self.store.add_vital(h.timestamp, "hr", float(h.hr), source="health")
                if h.spo2 > 0:
                    self.store.add_vital(
                        h.timestamp, "spo2", float(h.spo2), source="health"
                    )
                if h.temp_raw:
                    self.store.add_vital(
                        h.timestamp, "temp", h.temp_c, source="health"
                    )
        return self.health

    async def sync_day(self) -> dict:
        status = await self.pull_status()
        buckets = await self.pull_buckets(0)
        health = await self.pull_health(0)
        return {
            "status": status,
            "buckets": buckets,
            "health": health,
        }
