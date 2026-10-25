# SR116 Engineering Findings

**Date:** 2026-10-25  
**Inputs:** `btsnooz_hci.log`, `sr116_second_btsnooz_hci.log`, experiment report, nRF Connect hints  
**Analyzer:** `tools/analyze_btsnoop.py` (unit tests: `tests/test_btsnoop.py`)  
**Policy:** No unverified writes sent to the ring.

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

### UUID mapping limits (**Observed**)

Discovery responses in-window mostly yield CCCD UUID `0x2902` at descriptor handles. **Characteristic value UUIDs for `0x0017`/`0x0019`/`0x0042`/`0x0044` were not recovered** from these truncated captures. nRF Connect hints remain the best external map:

| Service (hint) | Char (hint) | Props (hint) | Candidate handle (inferred, unproven) |
|---|---|---|---|
| `0x56FF` | `0x33F3` | write / write-cmd | `0x0042` |
| `0x56FF` | `0x33F4` | notify | `0x0044` |
| `0xFF12` | `0xFF15` | read / write-cmd | `0x0017` |
| `0xFF12` | `0xFF14` | notify | `0x0019` |

Handle↔UUID must be confirmed with `sr116_cli.py inspect` or nRF export before any write tooling keys off UUIDs.

---

## 2. Candidate transfer path

### Updated from sniffer `ring-hack-capture.pcapng` (**Observed** — prefer this)

See `reports/sniffer_capture_findings.md`. Recording transfer is entirely on **`0x33F3`/`0x33F4`** (`0x0017`/`0x0019`) with `FE FC` opcode **`0x34`** data chunks. Handles `0x0042`/`0x0044` are HID CCCD/decls, not audio.

### Prior HCI-only inference (superseded for bulk path)

HCI `btsnooz` suggested bulk on `0x0042`/`0x0044` from opcode counts; that traffic was real but is **HID-related**. The truncated `FE FC` traffic on `0x0019` was the actual recording channel all along.

---

## 3. Missing evidence (**Unknown**)

| Topic | Status |
|---|---|
| Full command bytes for download start / file select | Truncated — cannot verify |
| Chunk headers, sequence, CRC | Truncated |
| Audio codec / container magic | Not present in retained bytes; absence ≠ proof audio offline |
| `0xFEF5` 128-bit UUIDs | Need GATT inspect export |
| App cloud upload behavior | Out of scope for HCI; needs network capture of test data |
| Authentication beyond “connected, not bonded” | Unknown at app layer |

---

## 4. Commands safe to run now (on the physical ring)

| Action | Safe? | Notes |
|---|---|---|
| `sr116_cli.py scan` | Yes | Passive discovery |
| `inspect` | Yes | GATT enumeration only |
| `read` of standard Battery / Device Info | Mostly yes | Still a read; avoid random vendor reads |
| `listen` on a user-chosen notify UUID | Cautious | Writes CCCD; bounded duration |
| `replay` / any vendor write | **No — blocked** | No complete verified command payloads |
| Brute-force / sweep / DFU / erase | **Forbidden** | Per instructions |

**Stop condition honored:** no unverified commands will be sent without explicit approval and exact hex review.

---

## 5. Path to a disposable recording download

1. **Full GATT map** via `inspect` → bind handles `0x0017`/`0x0019`/`0x0042`/`0x0044` to UUIDs.
2. **Non-truncated capture** during one disposable download:
   - Prefer nRF Sniffer / Ellisys / Frontline, or
   - Full bug report + compare truncation, or
   - `adb pull` of snoop if the build allows.
3. From complete PDUs, document FSM: connect → (auth?) → list → start → chunk/ACK → end.
4. Implement opt-in `download` only after byte-exact command verification, checksum policy, and local decode check.
5. Only then consider an Android Kotlin client.

---

## 6. Security / privacy note

BLE metadata shows *how* the phone talks to the ring, not whether LoraFit uploads audio. Separate HTTPS/DNS inspection with a **non-sensitive** test recording is required for that question. Do not bypass accounts or other people’s devices.
