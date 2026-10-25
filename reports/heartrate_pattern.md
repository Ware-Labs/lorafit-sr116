# Heart-rate transfer pattern

**Capture:** `ring-hack-capture_heartrate.pcapng` (overwritten 2026-10-25 17:31; 781 640 bytes, 11 560 frames, ~162 s)  
**Scenario:** connect → start HR (app showed updating BPM) → end → disconnect  
**JY session:** t ≈ **12.5–74.3 s** (~62 s)

Same proprietary path as SpO₂/audio: service **`0x56FF`**, write **`0x33F3`**, notify **`0x33F4`**. Not SIG HR (`0x2A37`).

---

## Verdict

| Role | Cmd | Payload |
|---|---|---|
| **Start** | `0x07` (7) | empty |
| **Auto-HR enable** (app also writes) | `0x1E` (30) | `00 00 17 3B 01 05` |
| **Live sample** | `0x0B` (11) notify | `u32le ts` + `00 00` + **`u8 BPM`** |
| **Stream end** (ring) | `0x11` (17) | empty |
| **Stop** (when sent) | `0x08` (8) | empty |

Live samples are confirmed in this capture (**8× `0x0B`**, BPM 75→64).

---

## Observed sequence

Relative to first JY PDU (`t0 = 12.544`).

| rel (s) | Dir | Cmd | Notes |
|---:|---|---|---|
| ~2.7 | H/R | `0x08` | handshake “close HR” default |
| **11.670** | **H→R** | **`0x07`** | **start measurement** (empty) |
| 12.000 | H→R | `0x1E` | auto-HR window **enable=1** |
| 12.12 / 12.17 | R→H | `0x07` / `0x1E` | echoes |
| 12–22 | H→R | `0x3E` | keepalives (~10 s settle before first BPM) |
| **22.89–34.25** | **R→H** | **`0x0B` ×8** | live BPM stream (~1 Hz) |
| **34.246** | **R→H** | **`0x11`** | **session end** (empty) |
| later | R→H | `0x28` | `01` then `02` (unclassified; after HR) |
| 61.7 | H/R | `0x43` | teardown |

Exact frames:

```
open:    FE FC 07 00 01 00 01 00 00 00
auto on: FE FC 1E 00 01 00 01 00 06 00  00 00 17 3B 01 05
sample:  FE FC 0B 00 01 00 01 00 07 00  be 3c de 6a 00 00 4b   # BPM=75
end:     FE FC 11 00 01 00 01 00 00 00
close:   FE FC 08 00 01 00 01 00 00 00   # seen at handshake; not repeated at end in this file
```

### Sample payload (`0x0B`) — **Observed**

Same shape as SpO₂ `0x18`:

| Offset | Field |
|---|---|
| 0–3 | `u32le` device timestamp |
| 4–5 | `00 00` |
| 6 | **BPM** (uint8) |

| rel (s) | BPM | ts |
|---:|---:|---|
| 22.890 | 75 | 1792949438 |
| 23.910 | 74 | 1792949438 |
| 24.945 | 70 | 1792949440 |
| 25.980 | 66 | 1792949440 |
| 27.000 | 64 | 1792949442 |
| 28.005 | 64 | 1792949442 |
| 29.040 | 64 | 1792949444 |
| 34.245 | 64 | 1792949449 |

- Interval ≈ **1.0–1.05 s** (one gap ~5.2 s before last sample)  
- Range **64–75**, mean **67.6**  
- First sample ~**11 s** after open (sensor settle)

In this run the ring emitted **`0x11` end** without a captured host `0x08`/`0x1E` disable at stop (unlike the earlier no-sample capture). CLI should still support explicit `0x08` stop; treat `0x11` as “stream finished.”

---

## FSM for CLI

```
subscribe 0x33F4
on start:
  write empty 0x07
  optional: write 0x1E enable=1 (vendor does)
  on notify 0x0B: bpm = payload[6], ts = u32le payload[0:4]
on stop:
  write empty 0x08
  optional: 0x1E enable=0
  expect possible empty 0x11 from ring
```

---

## vs prior HR capture / SpO₂

| | Old HR pcap | This HR pcap | SpO₂ |
|---|---|---|---|
| Open | `0x07` empty | `0x07` empty | `0x17` + `01` |
| Samples | none | **`0x0B` stream ~1 Hz** | single `0x18` |
| Value byte | — | BPM | SpO₂% |
| End | `0x11` + host `0x08` | **`0x11`** (host close not seen) | `0x19` + `0x17=00` |

---

## Confidence

| Claim | Level |
|---|---|
| Start = empty `0x07` | **Observed** |
| Live BPM = `0x0B`, last byte rate | **Observed** |
| Framing `ts4 + 0000 + u8` | **Observed** |
| End = empty `0x11` | **Observed** |
| `0x28` after HR | **Unknown** |
