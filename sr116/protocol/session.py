"""Bleak JY session: allowlisted writes, notify demux, multi-idx reassembly."""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

from sr116.protocol.commands import (
    ALLOWED_TX,
    CMD,
    NOTIFY_UUID,
    WRITE_UUID,
    cmd_name,
)
from sr116.protocol.jy import JyFrame, pack_jy, parse_jy

log = logging.getLogger(__name__)

LogFn = Callable[[str], None]
FrameHandler = Callable[[JyFrame], None]


@dataclass
class PendingMulti:
    cmd: int
    total: int
    parts: dict[int, bytes] = field(default_factory=dict)
    created: float = field(default_factory=time.monotonic)

    def add(self, frame: JyFrame) -> Optional[bytes]:
        self.parts[frame.idx] = frame.payload
        if len(self.parts) >= self.total and all(i in self.parts for i in range(1, self.total + 1)):
            return b"".join(self.parts[i] for i in range(1, self.total + 1))
        return None


class JySession:
    """One BLE connection to the SR116 proprietary channel."""

    def __init__(
        self,
        address: str,
        *,
        timeout: float = 20.0,
        on_log: Optional[LogFn] = None,
    ) -> None:
        self.address = address
        self.timeout = timeout
        self._on_log = on_log or (lambda _m: None)
        self.client: Optional[BleakClient] = None
        self._waiters: dict[int, list[asyncio.Future[JyFrame]]] = defaultdict(list)
        self._multi: dict[int, PendingMulti] = {}
        self._multi_waiters: dict[int, list[asyncio.Future[bytes]]] = defaultdict(list)
        self._listeners: list[FrameHandler] = []
        self._keepalive_task: Optional[asyncio.Task[None]] = None
        self.connected = False

    def _log(self, msg: str) -> None:
        self._on_log(msg)
        log.debug(msg)

    def add_listener(self, handler: FrameHandler) -> None:
        self._listeners.append(handler)

    def remove_listener(self, handler: FrameHandler) -> None:
        try:
            self._listeners.remove(handler)
        except ValueError:
            pass

    async def connect(self) -> None:
        self.client = BleakClient(self.address, timeout=self.timeout)
        await self.client.connect()
        self.connected = True
        await self.client.start_notify(NOTIFY_UUID, self._on_notify)
        self._log(f"connected {self.address}; notify {NOTIFY_UUID}")
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())

    async def disconnect(self) -> None:
        if self._keepalive_task:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
            self._keepalive_task = None
        if self.client and self.client.is_connected:
            try:
                await self.write(CMD.TEARDOWN, b"", expect_reply=False)
            except Exception:
                pass
            try:
                await self.client.stop_notify(NOTIFY_UUID)
            except Exception:
                pass
            await self.client.disconnect()
        self.connected = False
        self._log("disconnected")

    async def _keepalive_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(2.0)
                if not self.connected:
                    return
                try:
                    await self.write(CMD.KEEPALIVE, b"", expect_reply=False)
                except Exception as e:
                    self._log(f"keepalive err: {e}")
        except asyncio.CancelledError:
            return

    def _on_notify(self, _char: BleakGATTCharacteristic, data: bytearray) -> None:
        frame = parse_jy(data)
        if frame is None:
            self._log(f"rx non-JY len={len(data)} hex={bytes(data)[:24].hex()}")
            return
        self._log(
            f"rx {cmd_name(frame.cmd)} tot={frame.total} idx={frame.idx} "
            f"len={frame.length}"
        )
        for h in list(self._listeners):
            try:
                h(frame)
            except Exception as e:
                self._log(f"listener error: {e}")

        # Multi-packet reassembly (total > 1)
        if frame.total > 1:
            pending = self._multi.get(frame.cmd)
            if pending is None or pending.total != frame.total:
                pending = PendingMulti(cmd=frame.cmd, total=frame.total)
                self._multi[frame.cmd] = pending
            assembled = pending.add(frame)
            if assembled is not None:
                del self._multi[frame.cmd]
                waiters = self._multi_waiters.pop(frame.cmd, [])
                for fut in waiters:
                    if not fut.done():
                        fut.set_result(assembled)
            # Also wake single-frame waiters with each part (for streaming 0x34)
        waiters = self._waiters.get(frame.cmd, [])
        # Deliver to first waiter matching this cmd
        delivered = False
        still: list[asyncio.Future[JyFrame]] = []
        for fut in waiters:
            if not delivered and not fut.done():
                fut.set_result(frame)
                delivered = True
            elif not fut.done():
                still.append(fut)
        self._waiters[frame.cmd] = still

    async def write(
        self,
        cmd: int,
        payload: bytes = b"",
        *,
        expect_reply: bool = True,
        reply_timeout: float = 8.0,
        allow_delete: bool = False,
    ) -> Optional[JyFrame]:
        if cmd not in ALLOWED_TX:
            raise PermissionError(f"command 0x{cmd:02X} not in allowlist")
        if cmd == CMD.AUDIO_DONE and not allow_delete:
            raise PermissionError("0x36 delete echo blocked (allow_delete=False)")
        if not self.client or not self.client.is_connected:
            raise RuntimeError("not connected")

        fut: Optional[asyncio.Future[JyFrame]] = None
        if expect_reply:
            fut = asyncio.get_running_loop().create_future()
            self._waiters[cmd].append(fut)

        blob = pack_jy(cmd, payload)
        self._log(f"tx {cmd_name(cmd)} len={len(payload)}")
        await self.client.write_gatt_char(WRITE_UUID, blob, response=False)

        if not expect_reply or fut is None:
            return None
        try:
            return await asyncio.wait_for(fut, timeout=reply_timeout)
        except asyncio.TimeoutError:
            # remove waiter
            self._waiters[cmd] = [f for f in self._waiters[cmd] if f is not fut]
            self._log(f"timeout waiting reply 0x{cmd:02X}")
            return None

    async def write_and_reassemble(
        self,
        cmd: int,
        payload: bytes = b"",
        *,
        reply_timeout: float = 10.0,
    ) -> bytes:
        """Send cmd and wait for full multi-idx payload (or single)."""
        loop = asyncio.get_running_loop()
        multi_fut: asyncio.Future[bytes] = loop.create_future()
        single_fut: asyncio.Future[JyFrame] = loop.create_future()
        self._multi_waiters[cmd].append(multi_fut)
        self._waiters[cmd].append(single_fut)

        blob = pack_jy(cmd, payload)
        if cmd not in ALLOWED_TX:
            raise PermissionError(f"command 0x{cmd:02X} not in allowlist")
        if not self.client or not self.client.is_connected:
            raise RuntimeError("not connected")
        self._log(f"tx {cmd_name(cmd)} len={len(payload)} (reassemble)")
        await self.client.write_gatt_char(WRITE_UUID, blob, response=False)

        try:
            done, _pending = await asyncio.wait(
                {multi_fut, single_fut},
                timeout=reply_timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
        except Exception:
            done = set()

        # Prefer completed multi assembly
        if multi_fut.done() and not multi_fut.cancelled():
            try:
                result = multi_fut.result()
                self._cleanup_waiter(cmd, single_fut, multi_fut)
                return result
            except Exception:
                pass

        if single_fut.done() and not single_fut.cancelled():
            fr = single_fut.result()
            if fr.total <= 1:
                if not multi_fut.done():
                    multi_fut.cancel()
                self._cleanup_waiter(cmd, single_fut, multi_fut)
                return fr.payload
            # Multi in progress — keep multi_fut alive until complete
            try:
                result = await asyncio.wait_for(multi_fut, timeout=reply_timeout)
                self._cleanup_waiter(cmd, single_fut, multi_fut)
                return result
            except asyncio.TimeoutError:
                pending_m = self._multi.pop(cmd, None)
                self._cleanup_waiter(cmd, single_fut, multi_fut)
                if pending_m and pending_m.parts:
                    return b"".join(
                        pending_m.parts[i] for i in sorted(pending_m.parts)
                    )
                return fr.payload

        self._cleanup_waiter(cmd, single_fut, multi_fut)
        return b""

    def _cleanup_waiter(
        self,
        cmd: int,
        single_fut: asyncio.Future[JyFrame],
        multi_fut: asyncio.Future[bytes],
    ) -> None:
        self._waiters[cmd] = [f for f in self._waiters[cmd] if f is not single_fut and not f.done()]
        self._multi_waiters[cmd] = [
            f for f in self._multi_waiters[cmd] if f is not multi_fut and not f.done()
        ]
        for f in (single_fut, multi_fut):
            if not f.done():
                f.cancel()

    async def wait_frame(
        self,
        cmd: int,
        *,
        timeout: float = 15.0,
        predicate: Optional[Callable[[JyFrame], bool]] = None,
    ) -> Optional[JyFrame]:
        """Wait for next notify of cmd (optionally filtered)."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            fut: asyncio.Future[JyFrame] = asyncio.get_running_loop().create_future()
            self._waiters[cmd].append(fut)
            try:
                fr = await asyncio.wait_for(fut, timeout=remaining)
            except asyncio.TimeoutError:
                self._waiters[cmd] = [f for f in self._waiters[cmd] if f is not fut]
                return None
            if predicate is None or predicate(fr):
                return fr

    async def handshake(self) -> dict[str, Any]:
        """Light post-connect housekeeping matching captures."""
        from sr116.protocol.commands import DEFAULT_APP_INFO

        info: dict[str, Any] = {}
        # Unsolicited device info / battery often arrive on connect; also poll.
        now = int(datetime.now(timezone.utc).timestamp())
        set_pl = struct.pack("<I", now) + b"\x00\x00\x00"
        await self.write(CMD.SET_TIME, set_pl, expect_reply=True, reply_timeout=3.0)
        await self.write(CMD.APP_INFO, DEFAULT_APP_INFO, expect_reply=True, reply_timeout=3.0)
        # Collect recent unsolicited by querying status
        st = await self.write(CMD.STEP_STATUS, b"", expect_reply=True, reply_timeout=3.0)
        if st and len(st.payload) >= 14:
            info["step_status_raw"] = st.payload.hex()
        return info
