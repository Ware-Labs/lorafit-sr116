# Nordic Sniffer Capture Analysis — `ring-hack-capture.pcapng`

**Capture type:** Nordic BLE sniffer (Wireshark/`nordic_ble`)  
**How to repeat:** `docs/howto-nrf-sniffer.md` (scenario A)  
**Size / span:** 414,312 bytes file; **6,031 frames** over **~60.6 s** (on-air bytes ~208 KB)  
**Device:** `SR116-10A2` @ `73:01:06:00:10:a2`  
**Central:** `52:c0:91:bf:69:07` (phone/app that requested pairing)

This capture is **not truncated** like Android `btsnooz`. Full ATT payloads are present (and remain dissectable after bonding because pairing fell back to **Legacy**).

---

## Timeline (**Observed**)

| t (s) | Event |
|---:|---|
| ~0–13 | Scan environment (Thinkpad, Fitbit, etc.); `SR116-10A2` advertisements |
| **13.05** | LE connection to ring |
| 13.1–15 | GATT discovery; CCCD enable on `0x001A` |
| 14.97–17.8 | `FE FC` control: identity (`SR116-10A2`), status `0x1D`, **file list `0x21`/`0x22`**, select `0x01` |
| **19.3–23.8** | **SMP pairing + bonding** → link encryption |
| 24–37 | More discovery / keepalives (`0x2F`, `0x3D`, `0x3E`) |
| **37.17** | Host `FE FC 0x40` (prep) |
| **37.55** | Host `FE FC 0x34` empty — **start transfer** |
| **37.77–39.32** | Ring **33×** `FE FC 0x34` data notifications (~486 B each) |
| **39.32 / 39.44** | Ring `0x36` complete; host echoes `0x36` |
| 40–53 | Idle polls `0x3E`; final `0x43` |

Yes: there was a real offline-recording download. Chunk timestamps span **33 consecutive seconds** (`2026-10-25 14:58:52Z` … `14:59:24Z`), transferred in **~1.8 s** wall time (~16 KB ATT payload).

---

## GATT map correction (**Observed** — overrides prior handle guess)

From Read-by-type / Find-info in this sniffer capture:

| Handle | UUID | Role |
|---|---|---|
| `0x0015`–`0x001A` | Service **`0x56FF`** | Proprietary |
| **`0x0017`** | **`0x33F3`** | Write (command channel) |
| **`0x0019`** | **`0x33F4`** | Notify (response / bulk) |
| `0x001A` | `0x2902` | CCCD for `0x33F4` |
| `0x001B`… | Service **`0xFF12`** | `0xFF15` / `0xFF14` (separate) |
| `0x0041` / `0x0045`… | HID Report values | **Not** the recording pipe |
| **`0x0042`** | **`0x2902` CCCD** | HID notify enable — **not** bulk audio |

**Correction vs Android-HCI preliminary guess:** bulk recording traffic is on **`0x0017`/`0x0019` (`0x33F3`/`0x33F4`)**, not `0x0042`/`0x0044`. Those HID handles were busy in the phone HCI logs but are a different path. Truncated `btsnooz` only showed `FE FC` prefixes on `0x0019`; this sniffer shows the full `0x34` bodies.

---

## `FE FC` framing (**Observed**)

```
FE FC | cmd | mode_be:u16 | seq_be:u16 | pad:u8 | len_le:u16 | payload
```

Verified on `0x34` data PDUs: total length 496 = 10-byte header + 486-byte payload; `len=0x01E6`.

### Commands seen (high confidence labels)

| Cmd | Dir | Meaning (inferred from correlation) |
|---|---|---|
| `0x44` | Ring | Device name: `SR116-10A2` |
| `0x25` | Ring | Identity blob (contains `73:01:06:00:10:a2`) |
| `0x21` / `0x22` | Both | Recording **listing** (records with Unix timestamps) |
| `0x01` | Host→Ring | Select recording by timestamp |
| `0x1A` | Both | Challenge/response-looking 13-byte blob (echoed) |
| `0x1D` | Both | Status (includes ts + counters) |
| `0x2F` / `0x3D` / `0x3E` | Mostly host | Keepalive / poll / ACK |
| **`0x40`** | Host | Pre-transfer probe |
| **`0x34`** | Host empty / Ring data | **Download start + data chunks** |
| **`0x36`** | Both | Transfer complete |
| `0x43` | Both | Session teardown-ish |

### Exact host bytes that started the download (**Observed**)

```
FE FC 40 00 01 00 01 00 00 00          # prep (0x40), len=0
FE FC 34 00 01 00 01 00 00 00          # start (0x34), len=0
```

Complete: `fefc4000010001000000` then `fefc3400010001000000` written to UUID `0x33F3` / handle `0x0017`.

**Not sent to the ring from this repo.** Opt-in replay still requires your approval.

### Data chunk body (**Observed** + decoded)

Each ring `0x34` payload (486 B):

| Offset | Field |
|---|---|
| 0–3 | `u32le` counter seeded with device-local start time (+1 per packet, **not** 1 s of audio) |
| 4–5 | `00 00` |
| 6–485 | **12 × 40-byte Opus packets** (TOC `0xB8` = CELT fullband, 20 ms, mono) |

So each BLE packet = **240 ms** of audio. This capture: 33 packets → **7.92 s** → `reports/transfer_0x34.wav` (plays via `tools/opus_bin_to_audio.py --play`).

**Warning (from JY/LoraFit behavior):** echoing cmd `0x36` after transfer **deletes** the on-ring file. Do not send `0x36` unless deletion is intended.

---

## Pairing / security (**Observed**)

- Phone Pairing Request: **Secure Connections + MITM + Bonding**, IO Keyboard/Display.
- Ring Pairing Response: **Secure Connections = false**, No Input/No Output, MITM+Bonding.
- Result: **Legacy pairing** with Confirm/Random; distribution of LTK/IRK visible to sniffer after `LL_ENC_*`.
- Practical impact: a passive sniffer that witnesses pairing can decrypt later ATT (as Wireshark did here). Bonded re-connections without re-pairing would need a stored LTK.

---

## Compared to Android `btsnooz`

| | `btsnooz` | This `pcapng` |
|---|---|---|
| Payload bodies | Mostly stripped | **Intact** |
| Prove audio on ATT | Only via `original_length` | **Direct `0x34` payloads** |
| Handle map | Incomplete UUIDs | Full `0x56FF` / HID map |
| Pairing | Partial | Full SMP trace |

---

## Follow-on (2026-10-26)

Local client: `python -m sr116`. Allowlisted writes cover the verified download and vitals commands. Echoing `0x36` still deletes the on-ring file and stays behind an explicit checkbox.

Later captures in this repo:

| File | Pattern doc |
|---|---|
| `ring-hack-capture_multitransfer.pcapng` | `reports/multitransfer_pattern.md` |
| `ring-hack-capture_heartrate.pcapng` | `reports/heartrate_pattern.md` |
| `ring-hack-capture_spO2.pcapng` | `reports/spo2_pattern.md` |
| `ring-hack-capture_scroll.pcapng` | `reports/scroll_pattern.md` |
| `ring-hack-capture_steps.pcapng` | `reports/steps_pattern.md` |

How to repeat them: `docs/howto-nrf-sniffer.md`. Opus playback of this transfer: `python tools/opus_bin_to_audio.py reports/transfer_0x34_bodies.bin --play`.
