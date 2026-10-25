"""Shared runtime state for the Textual app."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from sr116.features.audio import AudioService
from sr116.features.device import DeviceService
from sr116.features.hr import HeartRateService
from sr116.features.spo2 import Spo2Service
from sr116.features.steps import StepsService
from sr116.protocol.session import JySession
from sr116.store import Store


class AppState:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.data_dir = root / "data"
        self.recordings_dir = root / "recordings"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.recordings_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(self.data_dir / "sr116.db")
        self.session: Optional[JySession] = None
        self.device: Optional[DeviceService] = None
        self.steps: Optional[StepsService] = None
        self.hr: Optional[HeartRateService] = None
        self.spo2: Optional[Spo2Service] = None
        self.audio: Optional[AudioService] = None
        self.log_lines: list[str] = []

    def log(self, msg: str) -> None:
        self.log_lines.append(msg)
        if len(self.log_lines) > 500:
            self.log_lines = self.log_lines[-400:]

    def bind_session(self, session: JySession) -> None:
        self.session = session
        self.device = DeviceService(session)
        self.steps = StepsService(session, self.store)
        self.hr = HeartRateService(session, self.store)
        self.spo2 = Spo2Service(session, self.store)
        self.audio = AudioService(
            session, out_dir=self.recordings_dir, store=self.store
        )

    async def clear_session(self) -> None:
        if self.session:
            try:
                await self.session.disconnect()
            except Exception:
                pass
        self.session = None
        self.device = None
        self.steps = None
        self.hr = None
        self.spo2 = None
        self.audio = None
