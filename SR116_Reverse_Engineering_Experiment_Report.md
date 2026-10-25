# LoraFit SR116 Voice Recorder Ring — Reverse-Engineering Experiment Report

**Date:** 2026-10-25  
**Device:** LoraFit voice recorder ring, BLE advertisement `SR116-10A2`  
**Phone:** Google Pixel 10 Pro (Android)  
**Objective:** Determine how the manufacturer's Android app discovers the ring, retrieves offline recordings, and decodes audio, so a local-only replacement client can be built.

## 1. Motivation and scope

The owner is concerned that the LoraFit app might access or upload private recordings. The goal is a self-controlled app that connects to the purchased ring, downloads audio locally, and avoids manufacturer cloud dependencies. **No evidence of exfiltration has been established.** BLE protocol inspection alone cannot establish the manufacturer's network behavior.

## 2. Experiments performed

### A. GATT enumeration with Nordic nRF Connect

- Scanned for and connected to `SR116-10A2`.
- Android/nRF Connect displayed **connected, not bonded**. This does *not* prove the ring lacks application-layer authentication or security on individual characteristics.
- Observed standard GATT services including Battery (`0x180F`), Device Information (`0x180A`), and HID (`0x1812`), plus proprietary services `0xFEF5`, `0x56FF`, and `0xFF12`.
- `0x56FF`: characteristic `0x33F3` supports write / write-without-response; `0x33F4` supports notify.
- `0xFF12`: characteristic `0xFF15` supports read / write-without-response; `0xFF14` supports notify.
- `0xFEF5`: multiple 128-bit custom characteristics, including a notify-only characteristic beginning `5f78df94`, several read/write characteristics, and a read/write/write-without-response characteristic beginning `457871e8`. **Full 128-bit UUIDs need exporting from GATT discovery.**
- Service purpose remains **unidentified**. Avoid inferring recording-transfer semantics from characteristic properties alone.

### B. First Bluetooth HCI capture

1. Enabled **Bluetooth HCI snoop log** in Android Developer Options.
2. Connected/synchronized the ring with LoraFit and played a successfully transferred recording.
3. Generated an Android bug report; extracted `FS/data/misc/bluetooth/logs/btsnooz_hci.log`.
4. The extracted file begins with the standard `btsnoop` magic and is directly parseable as btsnoop (despite its `btsnooz` filename).

**Local file:** `btsnooz_hci.log` (64,813 bytes).  
**Independently verified from btsnoop record headers:** 1,747 HCI records; 394 records have `original_length > included_length` (truncated).

An earlier preliminary analysis reported 192 ATT Write Requests, 104 ATT Notifications, 6 ATT Write Commands, and repeated short `FE FC`-prefixed exchanges around handles `0x0017` and `0x0019`. Treat these opcode/handle counts as **preliminary**, requiring independent reproduction by the analysis script; record counts and truncation counts above were independently checked.

### C. Second controlled offline recording and capture

1. Bluetooth HCI snoop setting remained **Enabled**, not Filtered.
2. Made a **30+ second offline recording** on the ring.
3. Opened LoraFit and watched the recording transfer over approximately **5–6 seconds or longer**.
4. Verified the transferred audio played successfully in the app.
5. Generated an **Interactive** Android bug report and extracted the new `btsnooz_hci.log`.

**Local file:** `sr116_second_btsnooz_hci.log` (64,212 bytes).  
**Independently verified from btsnoop record headers:** 1,747 HCI records; **836 truncated**; HCI packet type counts: 1,291 ACL (`0x02`), 329 event (`0x04`), 127 command (`0x01`).

**Preliminary packet-level findings from prior analysis (reproduce before relying on them):**

| Metric | Preliminary second-capture result |
|---|---:|
| ATT notifications | 441 |
| ATT Write Requests | 93 |
| ATT Write Commands | 74 |
| Concentrated bidirectional exchange | ~11.7 seconds |
| Phone → ring, handle `0x0042` | 74 write-without-response operations |
| Ring → phone, handle `0x0044` | 150 notifications |
| Phone → ring, handle `0x0017` | 86 writes |
| Ring → phone, handle `0x0019` | 285 notifications |

Some prior counts were described with unresolved direction/handle assignments; do not assume they are final until the parser confirms ATT direction, connection handle, and characteristic mappings.

**Crucial confirmed limitation:** btsnoop record headers show many truncated packets. One observed example was an original packet length of 256 bytes with only 15 bytes retained. This means absence of a visible audio payload **does not establish** that audio did not travel over BLE. The small size of the diagnostic file cannot be used to infer on-air throughput.

## 3. Conclusions, with confidence levels

- **Confirmed:** The SR116 exposes BLE GATT services with writable and notifying characteristics.
- **Confirmed by user observation:** LoraFit downloaded and played a 30+ second offline recording during the second experiment.
- **Confirmed from file headers:** The second btsnoop log has substantially more truncated records (836 vs. 394) and different HCI packet-type distribution from the first.
- **Plausible, not proven:** A burst involving handles `0x0042`/`0x0044` corresponds to recording transfer. Correlate timestamps and full packets before assigning meaning.
- **Unknown:** Whether audio is carried entirely over BLE ATT, another L2CAP channel, Bluetooth Classic, or an alternate transport.
- **Unknown:** Audio codec, framing, file listing, transfer acknowledgment, authentication, and storage format.
- **Unknown:** Whether LoraFit uploads recordings or metadata to remote servers. Separate network inspection is required.

## 4. Immediate next steps

1. **Reparse both HCI logs reproducibly** with a script. Validate btsnoop headers, record lengths, ACL fragmentation/reassembly, L2CAP CIDs, ATT opcodes, directions, handle mapping, and per-second traffic volume. Flag truncated packets; never treat a truncated payload as complete.
2. **Export the full GATT database**, especially all 128-bit UUIDs under `0xFEF5`, and map ATT handles to services and characteristics via discovery exchanges.
3. **Attempt a Full bug report** (instead of Interactive) without replaying a transfer, then compare included/original packet lengths. A Full report might still only contain reduced `btsnooz` data.
4. If necessary, **try ADB retrieval** of the full snoop log on the owner's device (production Android may deny access). Do not root the phone as a first step.
5. **Build a read-only BLE diagnostic client first** (scan, connect, discover, read safe standard characteristics, subscribe to notifications with explicit approval). Any unknown writes must be separately authorized.
6. Once transfer commands are actually identified, reproduce one controlled download of a disposable recording and verify checksum/codec locally before building the Android app.

## 5. Files to provide Cursor

- `btsnooz_hci.log` — first capture.
- `sr116_second_btsnooz_hci.log` — second capture.
- Optionally, the original Android bug-report ZIPs for comparing embedded snoop representations; these can contain extensive sensitive diagnostic information.
- Screenshots or exported text of GATT services and characteristics.

**Engineering caution:** Do not brute-force unknown BLE commands or write arbitrary bytes to custom characteristics. Some commands may erase recordings, factory-reset the ring, or enter firmware-update mode. Prefer passive capture and explicit confirmation for all device-changing actions.
