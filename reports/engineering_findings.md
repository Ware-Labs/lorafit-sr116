# SR116 Engineering Findings

**HCI analysis date:** 2026-10-25  
**Updated:** 2026-10-26 after Nordic sniffer captures and the Textual client  
**Inputs:** `btsnooz_hci.log`, `sr116_second_btsnooz_hci.log`, `ring-hack-capture*.pcapng`  
**Analyzer:** `tools/analyze_btsnoop.py` (unit tests: `tests/test_btsnoop.py`)  
**Client:** `python -m sr116` (allowlisted JY writes). `sr116_cli.py replay` stays disabled.

---

## 1. Verified protocol facts (**Observed**)

### Capture integrity

| File | Size | Records | Truncated | ACL / EVT / CMD |
|---|---:|---:|---:|---|
| `btsnooz_hci.log` | 64813 | 1747 | 394 | 726 / 671 / 350 |
| `sr116_second_btsnooz_hci.log` | 64212 | 1747 | 836 | 1291 / 329 / 127 |

All counts **MATCH** the experiment report baselines (including second-capture HCI type counts 1291 / 329 / 127).

### Transport

- Reassembled L2CAP traffic is overwhelmingly **ATT (CID `0x0004`)**.
- LE Signaling (`0x0005`) and SMP (`0x0006`, first capture only) volumes are negligible vs ATT.
- BR/EDR `Connection Complete` events appear (peer `b8:db:38:21:60:af` — likely phone/accessory unrelated or classic link), but **estimated original L2CAP payload mass is on ATT**, not a separate classic bulk channel in these windows.
- Second-capture LE connection: handle `0x041`, peer RPA `c1:90:ba:6b:a4:2c`.
- First-capture LE connection: handle `0x042`, peer `73:01:06:00:10:a2` (consistent with advertisement name `SR116-10A2`).

### ATT opcode totals (second capture — matches preliminary report)

| Opcode | Count |
|---|---:|
| Handle Value Notification | 441 |
| Write Request | 93 |
| Write Response | 93 |
| Write Command | 74 |

### Handles during confirmed download (second capture)

| Handle | Direction | Ops | Notes |
|---|---|---|---|
| `0x0042` | Phone → ring | Write_Cmd × **74** | Exact match to preliminary |
| `0x0044` | Ring → phone | Ntf × **150** | Exact match |
| `0x0017` | Phone → ring | Write_Req × **86** | Exact match |
| `0x0019` | Ring → phone | Ntf × **285** | Exact match |

First capture (sync/playback session) used the same handle pairs but with different mix: heavy `0x0017`/`0x0019`, light `0x0042`/`0x0044`.

### Timing / volume (**Observed** headers; payloads mostly missing)

- Second capture densest ~12 s ACL window: **sec 1–13**, ~135 KB of *original_length* ACL bytes (RX-dominated). Aligns with user-observed multi-second transfer and the preliminary ~11.7 s bidirectional exchange.
- Truncation: max `original_length` 256 with `included_length` 15 common; second capture median drop = **241** bytes. Large notification bodies are not present in the diagnostic files.

### Surviving payload structure (**Observed** where `incomplete_payload=false` or prefix retained)

1. **`0x0017` / `0x0019`:** Every retained body after the ATT header begins with `FE FC` (183/183 writes first capture; 86/86 and 285/285 second). This is a dedicated framed command/status channel, not raw PCM.
2. **`0x0042` / `0x0044` short complete PDUs:** single-byte values, e.g. Write_Cmd `52 42 00 XX` and Ntf `1b 44 00 XX`. Consistent with **flow-control / ACK / credit** interleaved with truncated large PDUs on the same handles (large PDUs show `original_length` up to 256).
3. **MTU (second):** phone requests 517, ring responds **247** → ATT payloads up to 244 bytes fit the 256-byte HCI original lengths seen when truncated.

### UUID mapping (**Observed** on sniffer; HCI logs did not contain it)

The truncated HCI logs did not recover characteristic UUIDs. An early nRF Connect hint that bound `0x56FF` to `0x0042`/`0x0044` was **wrong**. `ring-hack-capture.pcapng` GATT discovery shows:

| Handle | UUID | Role |
|---|---|---|
| `0x0017` | `0x33F3` | JY write (`FE FC` commands) |
| `0x0019` | `0x33F4` | JY notify (responses and audio chunks) |
| `0x001A` | `0x2902` | CCCD for `0x33F4` |
| `0x0042` / nearby | HID | Digitizer / scroll, not audio |

---

## 2. Candidate transfer path

### Updated from sniffer `ring-hack-capture.pcapng` (**Observed** — prefer this)

See `reports/sniffer_capture_findings.md`. Recording transfer is entirely on **`0x33F3`/`0x33F4`** (`0x0017`/`0x0019`) with `FE FC` opcode **`0x34`** data chunks. Handles `0x0042`/`0x0044` are HID CCCD/decls, not audio.

### Prior HCI-only inference (superseded for bulk path)

HCI `btsnooz` suggested bulk on `0x0042`/`0x0044` from opcode counts; that traffic was real but is **HID-related**. The truncated `FE FC` traffic on `0x0019` was the actual recording channel all along.

---

## 3. Evidence status

HCI `btsnooz` still cannot show payload bodies. The sniffer captures closed the items below.

| Topic | Status |
|---|---|
| Download start | **Observed:** empty `0x40` then empty `0x34` |
| Multi-file queue | **Observed:** FIFO; `0x36` remaining count; `0x35` when empty. Echoing `0x36` deletes the file |
| Audio codec | **Observed:** Opus TOC `0xB8`, 12×40 B per chunk; playback verified |
| Live HR / SpO₂ | **Observed:** `0x0B` / `0x18` (`reports/heartrate_pattern.md`, `reports/spo2_pattern.md`) |
| Day steps / health samples | **Observed:** `0x1D`, `0x21`, `0x24` (`reports/steps_pattern.md`) |
| Day HR min/max/avg | **App-side** over live samples + `0x24`, not a ring aggregate command |
| Scroll | **Observed:** HID report ID 2 on `0x003D` (`reports/scroll_pattern.md`) |
| `0xFEF5` 128-bit UUIDs | Still not required for retrieval |
| App cloud upload | Still unknown; BLE cannot answer it |

---

## 4. Commands safe to run now (on the physical ring)

| Action | Safe? | Notes |
|---|---|---|
| `python -m sr116` | Yes, allowlisted | Connect, day sync, live HR/SpO₂, audio download, sleep list |
| Download with delete checkbox off | Yes | Does not echo `0x36` |
| Download with delete checkbox on | Destructive | Echoes `0x36` and erases that file on the ring |
| `sr116_cli.py scan` / `inspect` | Yes | Passive discovery / GATT map |
| `read` of Battery / Device Info | Mostly yes | Avoid random vendor reads |
| `listen` on `0x33F4` | Cautious | Writes the CCCD |
| `sr116_cli.py replay` | **Still blocked** | Use the Textual app instead of free-form hex |
| Brute-force / sweep / DFU | **Forbidden** | |

---

## 5. Local client

`python -m sr116` implements the verified FSM: audio FIFO (`0x3D` → `0x40` → `0x34` → optional `0x36` / `0x35`), live HR, SpO₂, and day steps/health. Day min/max/avg live in `data/sr116.db`. Setup for new captures is `docs/howto-nrf-sniffer.md`.

---

## 6. Security / privacy note

BLE metadata shows *how* the phone talks to the ring, not whether LoraFit uploads audio. Separate HTTPS/DNS inspection with a **non-sensitive** test recording is required for that question. Do not bypass accounts or other people’s devices.
