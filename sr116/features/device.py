"""Device info / battery / handshake helpers."""

from __future__ import annotations

from typing import Any, Optional

from sr116.features.decode import (
    DeviceInfo,
    parse_battery,
    parse_device_info,
    parse_name,
)
from sr116.protocol.commands import CMD
from sr116.protocol.jy import JyFrame
from sr116.protocol.session import JySession


class DeviceService:
    def __init__(self, session: JySession) -> None:
        self.s = session
        self.info: Optional[DeviceInfo] = None
        self.name: str = ""
        self.battery_pct: Optional[int] = None
        self.charging: Optional[int] = None
        session.add_listener(self._on_frame)

    def _on_frame(self, frame: JyFrame) -> None:
        if frame.cmd == CMD.DEVICE_INFO:
            self.info = parse_device_info(frame.payload)
        elif frame.cmd == CMD.NAME:
            self.name = parse_name(frame.payload)
        elif frame.cmd == CMD.BATTERY:
            b = parse_battery(frame.payload)
            if b:
                self.battery_pct, self.charging = b

    async def refresh(self) -> dict[str, Any]:
        # Battery / info often unsolicited; empty step status poke wakes device
        await self.s.write(CMD.STEP_STATUS, b"", expect_reply=True, reply_timeout=3.0)
        return {
            "name": self.name,
            "firmware": self.info.firmware if self.info else None,
            "mac": self.info.mac if self.info else None,
            "battery": self.battery_pct,
            "charging": self.charging,
        }
