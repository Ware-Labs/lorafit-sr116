# LoraFit SR116 — local BLE protocol workbench

Personal reverse-engineering workspace for a **personally owned** LoraFit SR116 voice-recording ring. Goal: understand recording transfer over Bluetooth so a local-only client can replace the manufacturer app. **No evidence of cloud exfiltration has been established** from BLE analysis alone.

## Textual app (recommended)

Local TUI covering high/medium-confidence retrieval: connect, day steps/health sync, live HR & SpO₂, offline audio download/play, sleep row list. Day HR/SpO₂ min/max/avg are computed from a **local SQLite** store (same approach as the vendor app).

```powershell
pip install -r requirements.txt
python -m sr116
```

| Tab | What it does |
|---|---|
| Connect | Bleak scan / connect; enables `0x33F4` notify |
| Dashboard | Sync `0x1D` / `0x21` / `0x24`; show local vitals stats |
| Recordings | `0x3D` count; FIFO download (`0x40`/`0x34`); Opus→ogg/wav |
| Heart rate | Live BPM (`0x07` / `0x0B` / `0x08`) |
| SpO₂ | Spot reading (`0x17` / `0x18`) |
| Sleep | Raw `0x22` rows (timestamps + flags; no stage labels) |

**Safety**

- Only **allowlisted** JY commands are written (see `sr116/protocol/commands.py`).
- **Delete after download is off by default.** Checking the box echoes `0x36`, which **erases** the file on the ring.
- Downloads land in `recordings/`; vitals DB in `data/sr116.db`.
- HID scroll / DFU / free-form replay are **not** implemented.

## Contents

| Path | Purpose |
|---|---|
| `sr116/` | Textual app + protocol/feature library |
| `sr116_cli.py` | Low-level bleak explorer (scan/inspect/read/listen) |
| [`docs/howto-nrf-sniffer.md`](docs/howto-nrf-sniffer.md) | Flash an nRF52840 Dongle, capture in Wireshark, repeat the six scenarios |
| `tools/` | HCI analyzer, per-capture scripts, Opus converter |
| `reports/` | Pattern docs. Start at `sniffer_capture_findings.md`; HCI-era notes are historical |
| `btsnooz_hci.log` / `sr116_second_btsnooz_hci.log` | Truncated Android HCI captures (do not modify) |
| `ring-hack-capture*.pcapng` | Nordic sniffer captures (gitignored; full ATT bodies) |

## Analyze HCI / sniffer captures

```powershell
pip install -r requirements.txt
python tools/analyze_btsnoop.py
python -m unittest discover -s tests -v
```

Sniffer captures (full payloads) supersede the HCI handle guess. Read `reports/sniffer_capture_findings.md`, then:

| Capture | Doc |
|---|---|
| One recording download | `reports/sniffer_capture_findings.md` |
| Three recordings, 1/3…3/3 | `reports/multitransfer_pattern.md` |
| Live heart rate | `reports/heartrate_pattern.md` |
| SpO₂ | `reports/spo2_pattern.md` |
| Tap / scroll (HID, not JY) | `reports/scroll_pattern.md` |
| Desk sync: steps, LEDs, HR/SpO₂ cards | `reports/steps_pattern.md` |

`reports/engineering_findings.md` and `reports/capture_comparison.md` describe the truncated `btsnooz` logs. `SR116_Reverse_Engineering_Experiment_Report.md` and `Cursor_Instructions_SR116_Protocol_Analysis.md` are the original brief; both now point at the results above.

To take a new capture: [`docs/howto-nrf-sniffer.md`](docs/howto-nrf-sniffer.md).

## Low-level BLE CLI (read-oriented)

```powershell
python sr116_cli.py scan
python sr116_cli.py inspect <address> -o gatt_map.json
python sr116_cli.py read <address> 00002a19-0000-1000-8000-00805f9b34fb
python sr116_cli.py listen <address> 000033f4-0000-1000-8000-00805f9b34fb --duration 20
```

`replay` remains disabled in this CLI; use `python -m sr116` for verified writes.

## Protocol summary

- Service **`0x56FF`**: write **`0x33F3`**, notify **`0x33F4`**, framing **`FE FC`**.
- Offline audio: `0x3D` → `0x40` → empty `0x34` chunks (12×40 B Opus) → `0x36` (delete if echoed) / `0x35` empty.
- Live HR: `0x07` / samples `0x0B` / stop `0x08`.
- SpO₂: `0x17` on/off / sample `0x18`.
- Steps: `0x1D` totals, `0x21` buckets, `0x24` health samples.

### Play a captured transfer body

```powershell
python tools/opus_bin_to_audio.py reports/transfer_0x34_bodies.bin --play
```

## Manual ring checklist

1. Connect via Connect tab; battery/name appear in status.
2. Dashboard → Sync day; steps total should match vendor app when possible.
3. Heart rate → Start; BPM updates; Dashboard HR min/max/avg move.
4. SpO₂ → Start; wait ~20s for a `%`; Stop.
5. Recordings → Refresh count → Download next **without** delete; Play last WAV.
6. Sleep → Pull list; rows show without claiming stages.
