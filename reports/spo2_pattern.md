# SpO₂ transfer pattern

**Capture:** `ring-hack-capture_spO2.pcapng` (599 728 bytes, 8 842 frames, ~105 s file)  
**Scenario:** connect → start SpO₂ → end SpO₂ → disconnect  
**Ring session (JY on `0x0017`/`0x0019`):** t ≈ **12.7–60.0 s** (~47 s)

Same proprietary path as HR/audio: GATT service **`0x56FF`**, write **`0x33F3`**, notify **`0x33F4`**. No Bluetooth SIG pulse-ox / HR UUIDs carrying the measurement.

---

## Verdict

| Role | Cmd | Payload |
|---|---|---|
| **Start** | `0x17` (23) | **`01`** (enable) |
| **Sample** | `0x18` (24) notify | `u32le ts` + `00 00` + **`u8 SpO₂%%`** |
| **Stop** | `0x17` | **`00`** (disable); ring echoes |

Unlike the HR capture (open/close only, no samples), this trace includes a real reading: **SpO₂ = 98%**.

---

## Observed sequence

Relative to first JY PDU (`t0 = 12.745`).

| rel (s) | Dir | Cmd | Notes |
|---:|---|---|---|
| 0–7 | both | handshake | info, lists, setTime, appInfo, closeHR, keepalives |
| **7.770** | **H→R** | **`0x17`** | **`pl=01`** start measurement |
| 7.8–30.1 | H→R | `0x3E` ×51 | keepalives while measuring (~22 s) |
| **30.180** | **R→H** | **`0x18`** | **one sample** (see below) |
| 30–38 | H→R | `0x3E` | more keepalives |
| **38.071** | **H→R** | **`0x17`** | **`pl=00`** stop |
| 38.462 | R→H | **`0x19`** | empty — likely **session end** (cf. HR `0x11`) |
| 38.462 | R→H | `0x17` | echo `00` |
| 38.8 / 39.2 / 43.7 | H/R | `0x17` | stop retried / echoed again |
| 47.2 | H/R | `0x43` | teardown |

Exact frames:

```
start:  FE FC 17 00 01 00 01 00 01 00  01
stop:   FE FC 17 00 01 00 01 00 01 00  00
sample: FE FC 18 00 01 00 01 00 07 00  f1 3a de 6a 00 00 62
```

### Sample payload (`0x18`) — **Observed**

| Offset | Bytes | Field |
|---|---|---|
| 0–3 | `f1 3a de 6a` | `u32le` device time `1792948977` ≈ 2026-10-25 17:22:57Z |
| 4–5 | `00 00` | pad / flags |
| 6 | `62` | **SpO₂ = 98** |

So: **7-byte** payload, same `ts + 0000 + value` shape as other JY telemetry.

Only **one** `0x18` appeared in this run (spot reading after ~22 s acquisition, not a continuous stream like live HR ticks).

Ring also emitted empty **`0x19`** immediately on stop (same instant as first `0x17` echo) — analogous to HR’s empty **`0x11`** end marker.

---

## FSM for CLI

```
subscribe 0x33F4
handshake ...
on start SpO2:
  write 0x17 with payload 01
  wait for 0x18 notify(s) → spo2 = payload[6], ts = u32le payload[0:4]
on stop:
  write 0x17 with payload 00
  expect echo 0x17 / 00  (may retry like the app)
```

---

## vs heart-rate capture

| | HR (`0x07`/`0x08`) | SpO₂ (`0x17`/`0x18`) |
|---|---|---|
| Enable payload | empty open cmd | **`01` / `00` on same cmd** |
| Live data cmd | expected `0x0B` (absent in HR pcap) | **`0x18` present** |
| End marker | ring `0x11` | ring **`0x19`** empty + `0x17` echo `00` |
| Sample rate | (unknown here) | single result after ~22 s settle |

---

## Confidence

| Claim | Level |
|---|---|
| Start/stop = `0x17` with `01`/`00` | **Observed** |
| Result = `0x18` notify, last byte SpO₂% | **Observed** (98) |
| Timestamp = first 4 bytes LE | **Observed** |
| Continuous SpO₂ streaming | **Not seen** (one sample only) |
| SIG Pulse Ox service used | **Not observed** |
