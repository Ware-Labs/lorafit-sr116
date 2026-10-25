# LoraFit SR116 — local BLE protocol workbench

Personal reverse-engineering workspace for a **personally owned** LoraFit SR116 voice-recording ring. Goal: understand recording transfer over Bluetooth so a local-only client can replace the manufacturer app. **No evidence of cloud exfiltration has been established** from BLE analysis alone.

## Contents

| Path | Purpose |
|---|---|
| `btsnooz_hci.log` | First Android HCI capture (do not modify) |
| `sr116_second_btsnooz_hci.log` | Second capture during offline recording download (do not modify) |
| `SR116_Reverse_Engineering_Experiment_Report.md` | Experiment history |
| `tools/analyze_btsnoop.py` | Reproducible btsnoop → ATT/L2CAP analyzer |
| `reports/` | Generated capture comparison + CSV timelines |
| `sr116_cli.py` | Safe bleak-based BLE explorer (Windows-friendly) |
| `reports/engineering_findings.md` | Verified facts, gaps, safe next steps |

## Analyze HCI captures

```powershell
pip install -r requirements.txt   # bleak only needed for the CLI
python tools/analyze_btsnoop.py
python tests/test_btsnoop.py -v
```

Outputs: `reports/capture_comparison.md`, `packets.csv`, `handle_summary.csv`, `timeline.csv`.

## BLE client (read-only by default)

```powershell
pip install -r requirements.txt
python sr116_cli.py scan
python sr116_cli.py inspect <address> -o gatt_map.json
python sr116_cli.py read <address> 00002a19-0000-1000-8000-00805f9b34fb   # Battery Level example
python sr116_cli.py listen <address> <notify-uuid> --duration 20
```

**Safety rules**

- Default paths never write vendor commands.
- `listen` writes a CCCD (not strictly passive); you choose the characteristic.
- `replay` is **disabled** until a command is verified from complete (non-truncated) payloads. Do not brute-force custom characteristics — risk of erase / DFU / factory reset.
- Do not commit personal recordings or full bug-report ZIPs.

## What the captures show (summary)

**Authoritative:** Nordic sniffer `ring-hack-capture.pcapng` (full payloads). See `reports/sniffer_capture_findings.md`.

- Recording protocol is **`FE FC` on service `0x56FF`**: write `0x33F3` (handle `0x0017`), notify `0x33F4` (handle `0x0019`).
- Download = host `0x40` then empty `0x34`; ring sends sequenced `0x34` chunks (**12×40 B Opus / 240 ms** each); ends with `0x36` (**deletes** file if echoed).
- Codec: **Opus** TOC `0xB8`, mono, 20 ms frames — playback works.
- Handles `0x0042`/`0x0044` are **HID**, not the recording pipe.

### Play a captured transfer body

```powershell
pip install -r requirements.txt
python tools/opus_bin_to_audio.py reports/transfer_0x34_bodies.bin --play
# also writes reports/transfer_0x34.ogg and .wav
```

Also: `reports/engineering_findings.md` (HCI era), `reports/capture_comparison.md`.
