# Heart-rate transfer pattern

**Capture:** `ring-hack-capture_heartrate.pcapng` (373 816 bytes, 5 540 frames)  
**Scenario:** connect/pair → start HR measurement → stop HR → disconnect  
**Ring:** `SR116-10A2` @ `73:01:06:00:10:a2` (LE connect ~4307.35 s absolute)

JY traffic on this session spans **~52 s** relative (`4309.21` … `4361.01`).

---

## Verdict

Heart rate is **not** the Bluetooth SIG Heart Rate Service (`0x180D` / `0x2A37`).  
It rides the same proprietary JY channel as audio: service **`0x56FF`**, notify **`0x33F4`** / handle **`0x0019`**.

This capture shows a complete **control** sequence (open → close → end marker) but **zero live BPM samples**. During the ~29 s measurement window the ring sent only ACKs/config, while the phone mostly sent `0x3E` keepalives.

---

## Observed control sequence

Relative times are from first JY PDU (`t0 = 4309.210`).

| rel (s) | Dir | Cmd | Meaning | Payload |
|---:|---|---|---|---|
| 2.445 | H→R | `0x08` | close HR (handshake default) | empty |
| 2.490 | R→H | `0x08` | echo | empty |
| **13.125** | **H→R** | **`0x07`** | **open / start HR measurement** | empty |
| 13.590 | R→H | `0x07` | ack/echo | empty |
| 13.620 | R→H | `0x1E` | auto-HR window pushed, **enabled** | `00 00 17 3B 01 05` |
| 13.6–41.9 | H→R | `0x3E` ×36 | app heartbeat only | empty/keepalive |
| *(no `0x0B` notifications in this window)* | | | | |
| **41.941** | **H→R** | **`0x08`** | **stop HR measurement** | empty |
| 42.016 | R→H | **`0x11`** | **HR stream end marker** | empty |
| 42.016 | H→R | `0x1E` | auto-HR **disabled** | `00 00 17 3B 00 05` |
| 42.016 | R→H | `0x08` | close echo | empty |
| 42.391 | R→H | `0x1E` | echo disable | `00 00 17 3B 00 05` |
| 51.436 | H→R | `0x43` | teardown-ish | empty |
| 51.796 | R→H | `0x43` | ack | `01` |

Exact wire frames (10-byte JY header, little-endian):

```
open:   FE FC 07 00 01 00 01 00 00 00
close:  FE FC 08 00 01 00 01 00 00 00
end:    FE FC 11 00 01 00 01 00 00 00     # ring → host
auto on:  FE FC 1E 00 01 00 01 00 06 00  00 00 17 3B 01 05
auto off: FE FC 1E 00 01 00 01 00 06 00  00 00 17 3B 00 05
```

### `0x1E` payload layout (**Observed**)

| Byte | Value | Meaning |
|---|---|---|
| 0–1 | `00 00` | window hour/min |
| 2–3 | `17 3B` | end 23:59 |
| 4 | `01` / `00` | enable / disable |
| 5 | `05` | interval minutes (5) |

Matches LoraFit’s `setAutoHeartRateSetting` shape. Here the **ring** emits enable=`1` right after `0x07`; the **host** writes enable=`0` when stopping.

---

## What did *not* appear (important)

| Expected (from JY/APK notes) | In this capture |
|---|---|
| Live samples as cmd **`0x0B` (11)** on `0x0019`: typically `ts` + BPM | **None** |
| SIG HR notifications `0x2A37` | **None** (only Battery `0x2A19` reads) |
| Any other notify handle carrying BPM | **None** — all 40 notifications were on `0x0019`, and none were `0x0B` |

So this experiment proves **how measurement is started/stopped**, not the on-air BPM framing. Prior independent RE describes cmd `0x0B` payloads as device-time + BPM (example bpm `0x5F` = 95). Re-run with finger firmly on the sensor (and preferably not only on charger) to capture samples.

Ring also emitted empty **`0x11`** immediately when stopping — consistent with “HR session end” (APK path: open `7` → ticks `11` → end `17`).

---

## FSM for a future CLI

```
subscribe 0x33F4
handshake (setTime, appInfo, optional closeHR 0x08)
on user start:
  write empty 0x07
  expect echo 0x07; may see 0x1E enable=1
  listen for 0x0B notifications → parse BPM  # not seen in this pcap
on user stop:
  write empty 0x08
  expect 0x11 (end) and/or echo 0x08
  optional: write 0x1E with enable=0 (vendor does this)
```

Keepalives (`0x3E` every ~2 s) continued during measurement; they are not HR data.

---

## Confidence

| Claim | Level |
|---|---|
| Start = empty `0x07` on `0x33F3` | **Observed** |
| Stop = empty `0x08`; ring may send `0x11` end | **Observed** |
| Auto-HR config `0x1E` 6-byte window toggled with session | **Observed** |
| Live BPM = `0x0B` notify payloads | **Inferred** from protocol family / APK (not present in this pcap) |
| Why no samples here | **Unknown** (sensor contact, settling time, firmware gate, …) |

---

## Not related to HR (also in session)

Standard connect noise: device info `0x25`, name `0x44`, features `0x37`, offline count `0x3D=0`, lists `0x21`/`0x22`, battery JY `0x06` → `50 00` (80%, not charging), BAS handle `0x002C` reads, HID CCCD enables, SMP pairing ~4310–4313.
