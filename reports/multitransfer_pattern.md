# Multi-file offline transfer pattern

**Capture:** `ring-hack-capture_multitransfer.pcapng` (~122 s, 12 303 frames)  
**Scenario:** 3 offline recordings on ring → open LoraFit → recordings UI shows 1/3, 2/3, 3/3 → force-close  
**Channel:** GATT `0x56FF` / write `0x33F3` (`0x0017`) / notify `0x33F4` (`0x0019`), JY framing `FE FC`

---

## Headline result

Multi-download is **not** “select file by id, then pull” in a loop with different selectors.  
It is a **FIFO queue pull**:

1. Ask how many files (`0x3D`)
2. Prep once (`0x40`)
3. Repeatedly request “next file” with **empty `0x34`**
4. Each file ends with ring `0x36` carrying **remaining count**; host echoes `0x36` (**deletes that file**)
5. When none left, empty `0x34` → ring answers **`0x35`** (no payload)

That maps cleanly to UI `1/3 … 3/3`.

---

## Observed batch (t ≈ 104–110 s)

| Step | Who | Cmd | Payload / notes |
|---|---|---|---|
| Count | H→R / R→H | `0x3D` | empty query → **`03 00`** (u16le **3**) |
| List (metadata) | H / R | `0x21` | optional; multi-idx list blobs |
| Prep | H / R | `0x40` | empty; **once per batch** |
| List (alt) | H / R | `0x22` | optional |
| setTime / appId | H / R | `0x01`, `0x1A` | session housekeeping, not per-file select |
| **File 1** | H | `0x34` empty | start next |
| | R | `0x34` × **18** | `total=18`, idx 1..18, 240 ms audio each (~4.3 s) |
| | R | `0x36` | **`03 00`** remaining=3 |
| | H | `0x36` | echo `03 00` → delete just-fetched file |
| | R | `0x3D` (polled) | soon **`02 00`** |
| **File 2** | H | `0x34` empty | **no second `0x40`** |
| | R | `0x34` × **18** | ~4.3 s |
| | R / H | `0x36` | **`02 00`** (host retried echo many times) |
| | R | `0x3D` | **`01 00`** |
| **File 3** | H | `0x34` empty | |
| | R | `0x34` × **19** | ~4.6 s |
| | R / H | `0x36` | **`01 00`** |
| Drain | H | `0x34` empty | probe after last delete |
| | R | **`0x35`** empty | **queue empty / no more offline audio** |

Wall time for all three transfers: ~**4.2 s** of radio (106.1→110.3).

---

## State machine for CLI

```
subscribe 0x33F4
handshake (setTime 0x01, appInfo 0x1A, …)   # as needed
N = query_count_0x3D()                      # u16le in reply payload
optional: list_0x21() / list_0x22()         # UI inventory only

send 0x40 (empty) once
i = 0
loop:
  send 0x34 (empty)
  wait:
    - series of 0x34 data (header total/idx; body = ts_u32 + 0000 + 12*40B Opus)
      until idx == total
    - OR single 0x35 empty  => DONE (no more files)
  if 0x35: break
  i += 1
  # UI progress: i / N   (or N - rem + 1 after seeing 0x36)
  wait ring 0x36 with rem = u16le
  # VENDOR BEHAVIOR: echoing 0x36 DELETES that file on the ring
  send 0x36 echo(rem)     # ONLY if user opted into delete-after-download
  optional: verify query_0x3D() == rem - 1
```

### Progress counter (`1/3`, `2/3`, `3/3`)

**Observed:**

- Initial `0x3D` = N = 3  
- After each completed file, ring `0x36.rem` = 3, then 2, then 1  
- Mid-transfer `0x3D` still shows pre-delete count; after `0x36` echo, `0x3D` drops by 1  

So UI progress is: **file_index = N - rem + 1** at `0x36` time, or simply increment on each finished `0x34` run.

### What is *not* required per file

- No extra `0x40` between files  
- No per-file timestamp select on the download path (the `0x01` seen nearby is **setTime**, ring echoes calendar `Y/M/D/h/m/s`)  
- Packet `total` in data `0x34` headers is **packets in this file**, not “file k of N”

---

## Early connect note (t ≈ 24–31 s)

Before the recordings-page batch, the phone already connected/paired. At that moment `0x3D` returned **0** (no pending offline files yet, or not the same queue). Later `0x2F` state bytes (`0x10`/`0x40`/`0x50`) appear while recordings were likely finishing on-ring. The **3-file pull only starts after `0x3D=3`** around t=104.

---

## CLI design implications

| Concern | Guidance |
|---|---|
| `list` | Use `0x3D` for count; `0x21`/`0x22` for richer metadata if needed |
| `pull-all` | One `0x40`, then loop empty `0x34` until `0x35` |
| `pull-one` | Same as one loop iteration; still appears to fetch queue head (not random access in this capture) |
| Delete | Treat `0x36` echo as **destructive**; default off or require `--delete-after-download` |
| Decode | Same as single-file: strip 6-byte prefix per data PDU → 40-byte Opus frames → Ogg/WAV |
| Stop | `0x35` is the clean end marker; don’t require a fourth `0x36` |

---

## Confidence

| Claim | Level |
|---|---|
| Batch = repeated empty `0x34` after one `0x40` | **Observed** |
| `0x3D` u16le = offline file count | **Observed** |
| `0x36` u16le tracks remaining; echo deletes | **Observed** + matches prior JY notes |
| `0x35` = no more data after empty `0x34` | **Observed** (this capture) |
| Random access by timestamp for offline pull | **Not seen** here (Unknown / unsupported by this trace) |
