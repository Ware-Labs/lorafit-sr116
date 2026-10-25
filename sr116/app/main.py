"""Textual SR116 local client."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from sr116.app.state import AppState
from sr116.audio.opus import play_wav
from sr116.protocol.session import JySession


ROOT = Path(__file__).resolve().parents[2]


class SR116App(App[None]):
    """Local-only SR116 workbench."""

    TITLE = "SR116 Local"
    SUB_TITLE = "high/medium confidence retrieval"
    CSS = """
    Screen {
        layout: vertical;
    }
    #status {
        dock: top;
        height: 3;
        padding: 0 1;
        background: $surface;
        border: solid $primary;
    }
    #main {
        height: 1fr;
    }
    #event_log {
        dock: bottom;
        height: 10;
        border: solid $accent;
    }
    .row {
        height: auto;
        margin: 1 0;
    }
    .big {
        text-style: bold;
        color: $text;
    }
    ListView {
        height: 12;
        border: solid $primary;
    }
    DataTable {
        height: 14;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "scan", "Scan"),
        Binding("d", "disconnect", "Disconnect"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.state = AppState(ROOT)

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Disconnected — press Scan or enter address", id="status")
        with TabbedContent(id="main"):
            with TabPane("Connect", id="tab-connect"):
                yield Label("Scan for SR116, or paste a Bleak address:")
                yield Input(placeholder="Bleak address / device id", id="addr_input")
                with Horizontal(classes="row"):
                    yield Button("Scan", id="btn_scan", variant="primary")
                    yield Button("Connect", id="btn_connect", variant="success")
                    yield Button("Disconnect", id="btn_disconnect", variant="error")
                yield ListView(id="device_list")
            with TabPane("Dashboard", id="tab-dash"):
                with Horizontal(classes="row"):
                    yield Button("Sync day", id="btn_sync", variant="primary")
                yield Static("Steps: —", id="dash_steps", classes="big")
                yield Static("HR today: —", id="dash_hr")
                yield Static("SpO₂ today: —", id="dash_spo2")
                yield Static("Health samples: —", id="dash_health")
                yield Static("Buckets: —", id="dash_buckets")
            with TabPane("Recordings", id="tab-rec"):
                with Horizontal(classes="row"):
                    yield Button("Refresh count", id="btn_rec_count")
                    yield Button("Download next", id="btn_rec_next", variant="primary")
                    yield Button("Download all", id="btn_rec_all", variant="warning")
                    yield Button("Play last WAV", id="btn_rec_play")
                yield Checkbox(
                    "Delete after download (echo 0x36 — erases on ring)",
                    id="chk_delete",
                    value=False,
                )
                yield Static("Offline count: —", id="rec_count")
                yield Static("Last download: —", id="rec_last")
            with TabPane("Heart rate", id="tab-hr"):
                with Horizontal(classes="row"):
                    yield Button("Start HR", id="btn_hr_start", variant="success")
                    yield Button("Stop HR", id="btn_hr_stop", variant="error")
                yield Static("BPM: —", id="hr_live", classes="big")
            with TabPane("SpO₂", id="tab-spo2"):
                with Horizontal(classes="row"):
                    yield Button("Start SpO₂", id="btn_spo2_start", variant="success")
                    yield Button("Stop SpO₂", id="btn_spo2_stop", variant="error")
                yield Static(
                    "SpO₂: —  (first sample often ~20s after start)",
                    id="spo2_live",
                    classes="big",
                )
            with TabPane("Sleep", id="tab-sleep"):
                with Horizontal(classes="row"):
                    yield Button("Pull sleep list", id="btn_sleep", variant="primary")
                yield Label("Raw rows (flags not interpreted as stages):")
                yield DataTable(id="sleep_table")
        yield RichLog(id="event_log", markup=True, highlight=True, max_lines=400)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#sleep_table", DataTable)
        table.add_columns("UTC", "unix", "flags_hex")
        self._elog("Ready. Scan or connect to an SR116.")

    def _elog(self, msg: str) -> None:
        self.state.log(msg)
        try:
            self.query_one("#event_log", RichLog).write(msg)
        except Exception:
            pass

    def _set_status(self, text: str) -> None:
        self.query_one("#status", Static).update(text)

    def _require_session(self) -> Optional[JySession]:
        if not self.state.session or not self.state.session.connected:
            self._elog("[red]Not connected[/]")
            self.notify("Connect first", severity="warning")
            return None
        return self.state.session

    def action_scan(self) -> None:
        self.scan_devices()

    def action_disconnect(self) -> None:
        self.do_disconnect()

    @on(Button.Pressed, "#btn_scan")
    def _btn_scan(self) -> None:
        self.scan_devices()

    @on(Button.Pressed, "#btn_connect")
    def _btn_connect(self) -> None:
        addr = self.query_one("#addr_input", Input).value.strip()
        if not addr:
            # selected list item?
            lv = self.query_one("#device_list", ListView)
            if lv.highlighted_child and isinstance(lv.highlighted_child, DeviceItem):
                addr = lv.highlighted_child.address
        if not addr:
            self.notify("No address", severity="error")
            return
        self.do_connect(addr)

    @on(Button.Pressed, "#btn_disconnect")
    def _btn_disc(self) -> None:
        self.do_disconnect()

    @on(ListView.Selected, "#device_list")
    def _list_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, DeviceItem):
            self.query_one("#addr_input", Input).value = event.item.address

    @work(exclusive=True)
    async def scan_devices(self) -> None:
        self._elog("Scanning 6s…")
        try:
            from bleak import BleakScanner

            found = await BleakScanner.discover(timeout=6.0, return_adv=True)
        except Exception as e:
            self._elog(f"[red]scan error: {e}[/]")
            return
        lv = self.query_one("#device_list", ListView)
        lv.clear()
        rows = []
        for addr, (dev, adv) in found.items():
            name = dev.name or adv.local_name or ""
            rows.append((addr, name, adv.rssi))
        rows.sort(key=lambda r: ("SR116" not in (r[1] or "").upper(), r[1] or "", r[0]))
        for addr, name, rssi in rows:
            lv.append(DeviceItem(addr, name, rssi))
        self._elog(f"Found {len(rows)} device(s)")

    @work(exclusive=True)
    async def do_connect(self, address: str) -> None:
        await self.state.clear_session()
        self._set_status(f"Connecting {address}…")
        session = JySession(address, on_log=lambda m: self.call_from_thread(self._elog, m))
        try:
            await session.connect()
            self.state.bind_session(session)

            def _log_from_ble(m: str) -> None:
                self.call_from_thread(self._elog, m)

            session._on_log = _log_from_ble
            await session.handshake()
            if self.state.device:
                await self.state.device.refresh()
            d = self.state.device
            bat = f"{d.battery_pct}%" if d and d.battery_pct is not None else "?"
            name = (d.name if d and d.name else "") or "SR116"
            fw = d.info.firmware if d and d.info else "?"
            self._set_status(f"Connected: {name}  fw={fw}  battery={bat}  [{address}]")
            self._elog(f"[green]Connected {address}[/]")
            if self.state.hr:
                self.state.hr.on_sample(
                    lambda ts, bpm: self.call_from_thread(self._on_hr, ts, bpm)
                )
            if self.state.spo2:
                self.state.spo2.on_sample(
                    lambda ts, v: self.call_from_thread(self._on_spo2, ts, v)
                )
        except Exception as e:
            self._set_status(f"Connect failed: {e}")
            self._elog(f"[red]connect failed: {e}[/]")
            await self.state.clear_session()

    def _on_hr(self, ts: int, bpm: int) -> None:
        self.query_one("#hr_live", Static).update(f"BPM: {bpm}  (ts={ts})")
        self._refresh_dash_stats()

    def _on_spo2(self, ts: int, val: int) -> None:
        self.query_one("#spo2_live", Static).update(f"SpO₂: {val}%  (ts={ts})")
        self._refresh_dash_stats()

    @work(exclusive=True)
    async def do_disconnect(self) -> None:
        await self.state.clear_session()
        self._set_status("Disconnected")
        self._elog("Disconnected")

    @on(Button.Pressed, "#btn_sync")
    def _btn_sync(self) -> None:
        self.sync_day()

    @work(exclusive=True)
    async def sync_day(self) -> None:
        if not self._require_session() or not self.state.steps:
            return
        self._elog("Syncing day (status / buckets / health)…")
        try:
            data = await self.state.steps.sync_day()
            st = data["status"]
            if st:
                self.query_one("#dash_steps", Static).update(
                    f"Steps: {st.steps}   cal={st.calories}   dist={st.distance}   ({st.ts_iso})"
                )
            buckets = data["buckets"]
            self.query_one("#dash_buckets", Static).update(
                f"Buckets: {len(buckets)} records"
                + (
                    f"  last cumulative steps={buckets[-1].steps}"
                    if buckets
                    else ""
                )
            )
            health = data["health"]
            if health:
                last = health[-1]
                lines = ", ".join(
                    f"{h.ts_iso[11:16]} HR={h.hr} SpO2={h.spo2}" for h in health
                )
                self.query_one("#dash_health", Static).update(
                    f"Health ({len(health)}): {lines}"
                )
            else:
                self.query_one("#dash_health", Static).update("Health samples: none")
            self._refresh_dash_stats()
            self._elog("[green]Day sync done[/]")
        except Exception as e:
            self._elog(f"[red]sync error: {e}[/]")

    def _refresh_dash_stats(self) -> None:
        hr = self.state.store.stats_today("hr")
        spo2 = self.state.store.stats_today("spo2")

        def fmt(st) -> str:
            if st.count == 0:
                return f"{st.kind}: no local samples today"
            return (
                f"{st.kind}: n={st.count}  latest={st.latest:.0f}  "
                f"min={st.min_v:.0f}  max={st.max_v:.0f}  avg={st.avg:.0f}"
            )

        self.query_one("#dash_hr", Static).update(fmt(hr))
        self.query_one("#dash_spo2", Static).update(fmt(spo2))

    @on(Button.Pressed, "#btn_rec_count")
    def _btn_rc(self) -> None:
        self.rec_count()

    @work(exclusive=True)
    async def rec_count(self) -> None:
        if not self._require_session() or not self.state.audio:
            return
        try:
            n = await self.state.audio.query_count()
            self.query_one("#rec_count", Static).update(f"Offline count: {n}")
            self._elog(f"offline audio count={n}")
        except Exception as e:
            self._elog(f"[red]count error: {e}[/]")

    def _delete_flag(self) -> bool:
        return self.query_one("#chk_delete", Checkbox).value

    @on(Button.Pressed, "#btn_rec_next")
    def _btn_rn(self) -> None:
        self.rec_download_next()

    @work(exclusive=True)
    async def rec_download_next(self) -> None:
        if not self._require_session() or not self.state.audio:
            return
        delete = self._delete_flag()
        if delete:
            self._elog("[yellow]Delete-after-download ENABLED[/]")
        try:
            f = await self.state.audio.download_next(
                delete_after=delete,
                on_progress=lambda m: self.call_from_thread(self._elog, m),
            )
            if f is None:
                self.query_one("#rec_last", Static).update("Last download: queue empty")
                return
            self.query_one("#rec_last", Static).update(
                f"Last: {f.ogg_path.name}  {f.duration_s:.1f}s  "
                f"chunks={f.chunks}  deleted={f.deleted_on_ring}"
            )
        except Exception as e:
            self._elog(f"[red]download error: {e}[/]")

    @on(Button.Pressed, "#btn_rec_all")
    def _btn_ra(self) -> None:
        self.rec_download_all()

    @work(exclusive=True)
    async def rec_download_all(self) -> None:
        if not self._require_session() or not self.state.audio:
            return
        delete = self._delete_flag()
        try:
            files = await self.state.audio.download_all(
                delete_after=delete,
                on_progress=lambda m: self.call_from_thread(self._elog, m),
            )
            self.query_one("#rec_last", Static).update(
                f"Downloaded {len(files)} file(s)"
            )
        except Exception as e:
            self._elog(f"[red]download-all error: {e}[/]")

    @on(Button.Pressed, "#btn_rec_play")
    def _btn_play(self) -> None:
        recs = self.state.store.list_recordings(1)
        if not recs or not recs[0].get("wav_path"):
            self.notify("No WAV yet — download first", severity="warning")
            return
        path = Path(recs[0]["wav_path"])
        if not path.is_file():
            self.notify("WAV missing on disk", severity="error")
            return
        try:
            play_wav(path)
            self._elog(f"played {path.name}")
        except Exception as e:
            self._elog(f"[red]play error: {e}[/]")

    @on(Button.Pressed, "#btn_hr_start")
    def _btn_hrs(self) -> None:
        self.hr_start()

    @on(Button.Pressed, "#btn_hr_stop")
    def _btn_hre(self) -> None:
        self.hr_stop()

    @work(exclusive=True)
    async def hr_start(self) -> None:
        if not self._require_session() or not self.state.hr:
            return
        try:
            await self.state.hr.start()
            self._elog("HR started (PPG LEDs may flash)")
        except Exception as e:
            self._elog(f"[red]HR start: {e}[/]")

    @work(exclusive=True)
    async def hr_stop(self) -> None:
        if not self._require_session() or not self.state.hr:
            return
        try:
            await self.state.hr.stop()
            self._elog("HR stopped")
        except Exception as e:
            self._elog(f"[red]HR stop: {e}[/]")

    @on(Button.Pressed, "#btn_spo2_start")
    def _btn_ss(self) -> None:
        self.spo2_start()

    @on(Button.Pressed, "#btn_spo2_stop")
    def _btn_se(self) -> None:
        self.spo2_stop()

    @work(exclusive=True)
    async def spo2_start(self) -> None:
        if not self._require_session() or not self.state.spo2:
            return
        try:
            await self.state.spo2.start()
            self._elog("SpO₂ started — wait for sample")
        except Exception as e:
            self._elog(f"[red]SpO₂ start: {e}[/]")

    @work(exclusive=True)
    async def spo2_stop(self) -> None:
        if not self._require_session() or not self.state.spo2:
            return
        try:
            await self.state.spo2.stop()
            self._elog("SpO₂ stopped")
        except Exception as e:
            self._elog(f"[red]SpO₂ stop: {e}[/]")

    @on(Button.Pressed, "#btn_sleep")
    def _btn_sleep(self) -> None:
        self.pull_sleep()

    @work(exclusive=True)
    async def pull_sleep(self) -> None:
        if not self._require_session() or not self.state.steps:
            return
        try:
            rows = await self.state.steps.pull_sleep(0)
            table = self.query_one("#sleep_table", DataTable)
            table.clear()
            for r in rows:
                table.add_row(r.ts_iso, str(r.timestamp), r.flags_hex)
            self._elog(f"sleep rows={len(rows)}")
        except Exception as e:
            self._elog(f"[red]sleep pull: {e}[/]")

    async def on_unmount(self) -> None:
        await self.state.clear_session()
        self.state.store.close()


class DeviceItem(ListItem):
    def __init__(self, address: str, name: str, rssi: int) -> None:
        label = f"{name or '(no name)'}  RSSI={rssi}  {address}"
        super().__init__(Label(label))
        self.address = address


def run() -> None:
    SR116App().run()


if __name__ == "__main__":
    run()
