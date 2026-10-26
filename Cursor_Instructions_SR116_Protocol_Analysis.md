# Cursor Task: Reverse Engineer LoraFit SR116 Recording Transfer

**Status (2026-10-26):** this brief has been carried out. Do not treat the early handle guess (`0x0042`/`0x0044` as the recording pipe) as current. Authoritative results are `README.md`, `reports/sniffer_capture_findings.md`, `reports/*_pattern.md`, and the Textual client under `sr116/`. New sniffer runs: `docs/howto-nrf-sniffer.md`. The safety rule still holds: no writes outside the allowlist, and do not echo `0x36` unless deletion is intended.

You are an embedded/Bluetooth protocol engineer. Work in this repository to analyze two Android Bluetooth HCI logs and build a cautious, local-only BLE client for a personally owned LoraFit SR116 voice-recording ring. **Do the actual analysis and implement runnable tooling; do not stop at a plan.**

## Inputs

- `SR116_Reverse_Engineering_Experiment_Report.md` — experiment history and confidence levels.
- `btsnooz_hci.log` — first HCI capture.
- `sr116_second_btsnooz_hci.log` — second HCI capture with a confirmed 30+ second offline audio download (observed transfer ≥5–6 seconds).
- Optional original bug report ZIPs and Nordic nRF Connect screenshots.

If any input is absent, identify the missing filename and continue with available inputs. Never fabricate packets, UUIDs, or inferred commands. Keep raw capture files unchanged.

## Goal and acceptance criteria

1. Produce a reproducible, automated report describing both captures and identifying the most likely recording-transfer path.
2. Resolve which transport(s) and ATT handles/characteristics are involved, to the extent the data supports.
3. Determine exactly what information is missing due to truncated diagnostic captures.
4. Implement a **safe, read-only by default** Python BLE exploration utility using `bleak` (Windows-friendly), with scan/connect/discovery and optionally safe standard-characteristic reads.
5. Implement a separate **explicitly opt-in** experimental interface for known, captured commands, only after validating their meaning and showing exact outgoing bytes. Never automatically send unknown commands.
6. Document a concrete path to downloading and decoding a disposable recording, and implement transfer/download only if supported by verified evidence.

## Phase 1 — Parse and validate btsnoop

Create `tools/analyze_btsnoop.py` using Python standard library wherever practical. Treat btsnoop as big-endian: 16-byte file header, then per-record `original_length`, `included_length`, `flags`, `cumulative_drops` (4 bytes each) and 64-bit timestamp. Parse H4 packet types (`0x01` command, `0x02` ACL, `0x04` event). Be rigorous about direction flags and avoid assuming connection handles map to the same peer across sessions.

Required checks:

- Verify file header, datalink type, record count, malformed/truncated records, time span, packet types, and original-vs-included length distributions.
- Cross-check these known counts: first file 64,813 bytes / 1,747 records / 394 truncated; second 64,212 bytes / 1,747 records / 836 truncated. If different, explain why.
- Decode HCI connection events and identify ring connection(s) using advertising/device address and timing where possible; do not conflate BR/EDR and LE handles.
- Reassemble ACL HCI fragmentation by connection handle and PB flags, then parse L2CAP headers/CIDs. Mark reassembly incomplete when source records are truncated; do not silently join unrelated fragments.
- Parse ATT (CID `0x0004`) requests, responses, writes, write commands, notifications, indications, MTU exchanges, discovery, and CCCD writes. For any non-ATT L2CAP channels, enumerate channel setup and data volumes.
- Summarize per-handle packet count, bytes **captured**, original length, direction, payload-size distributions, and timestamp intervals.
- Map handles to characteristic UUIDs using discovery exchanges, supplemented by provided nRF Connect GATT observations; never infer UUID solely from numeric handle.
- Find traffic bursts with per-second time bins, especially the reported ~11.7-second exchange. Check whether handles `0x0042`, `0x0044`, `0x0017`, and `0x0019` occur and whether they correspond to the previously reported packet counts.
- Distinguish bytes actually captured from bytes merely reported in original-length headers. Use an explicit `incomplete_payload` field for any truncated record or fragment.

Outputs: `reports/capture_comparison.md`, `reports/packets.csv`, `reports/handle_summary.csv`, and `reports/timeline.csv` (include timestamps, connection IDs, direction, packet type, ATT opcode, ATT handle, included/original lengths, and truncation flags where available). Add unit tests for btsnoop record parsing and ACL/L2CAP reassembly.

## Phase 2 — Identify the protocol

Use this observed GATT information as *hints*, not confirmed semantic assignments:

- Service `0x56FF`: `0x33F3` writable; `0x33F4` notifying.
- Service `0xFF12`: `0xFF15` readable / write-without-response; `0xFF14` notifying.
- Service `0xFEF5`: multiple 128-bit custom UUIDs; complete UUIDs not yet captured.
- Prior preliminary analysis suggested writes on ATT handle `0x0042` and notifications on `0x0044` during a candidate transfer burst. Verify this from raw packets.

Analyze command/response correlations, packet headers, sequence numbers, counters, checksums, transfer start/end markers, and likely audio/container signatures **only where payload bytes actually exist**. Compare the two captures and separate baseline status/polling from transfer-specific traffic. Test whether the bulk transfer could be on another L2CAP CID or BR/EDR ACL rather than ATT.

If the captures cannot reveal audio payloads due to Android btsnooz truncation, state that decisively and provide targeted collection instructions: Full vs Interactive bug report comparison, direct full snoop extraction if ADB permits, and alternate lawful passive capture approaches. Do not claim the absence of audio based solely on truncated packets.

## Phase 3 — Build safe Python exploration client

Create `sr116_cli.py`, `requirements.txt`, and `README.md` using `bleak`.

Commands:

- `scan` — discover nearby BLE devices and display name/address/advertised services.
- `inspect` — connect to a user-selected device and enumerate all services/characteristics/properties/descriptors; export JSON. Handle Windows BLE address/device ID behavior.
- `read` — read a **user-specified** characteristic only when READ is advertised; warn that vendor-specific reads can have side effects on buggy devices.
- `listen` — subscribe to a **user-specified** NOTIFY characteristic for a bounded duration and log timestamped hex payloads. Explain that enabling notifications writes a CCCD and is not strictly passive.
- `replay` — **do not implement until a specific command is verified**. When implemented, require a literal characteristic UUID and exact hex payload, an explicit `--allow-write` flag, interactive confirmation showing bytes and potential risk, and no retries by default. No generic brute-force, command sweeping, firmware update, reset, or erase functionality.

Default behavior must never write vendor commands. No network upload, analytics, or cloud dependency. Never delete recordings. Avoid storing personal recordings in Git.

## Phase 4 — Controlled reproduction, if evidence permits

Once transfer commands are verified against captured traffic:

1. Define a finite-state-machine specification for connection, optional authentication, file enumeration, download initiation, data reception, acknowledgments, and transfer completion.
2. Add a **separate opt-in download command** for a disposable test recording, with timeouts, chunk sequence verification, CRC/checksum if known, resume/retry policy only if understood, and local binary output.
3. Identify codec/container via magic bytes, entropy, packet structure, and reference files; never guess that arbitrary bytes are PCM/WAV.
4. Verify output with a known test recording and independent playback/decoding.
5. Propose an Android Kotlin implementation only after the Python transfer is repeatable.

## Security and privacy workstream

Document what BLE analysis can and cannot establish about the app's network behavior. Optionally analyze the legitimate Android APK using JADX for BLE UUIDs, protocol framing, codec routines, network endpoints, and bundled OEM SDKs. Any app network testing should use non-sensitive test recordings. Do not bypass third-party accounts, access other people's devices, or exploit vulnerabilities beyond this personally owned ring.

## Working style and deliverables

- Make incremental commits or logically separated changes; do not modify original capture files.
- At each stage state **Observed / Inferred / Unknown** and cite packet numbers, timestamps, and offsets for claims.
- Prefer runnable code and tests over speculative explanations.
- Run the analyzer on both inputs and include its actual outputs and any exceptions.
- End with a concise engineering report: verified protocol facts, candidate transfer channel, missing evidence, commands safe to run now, and exact next capture needed.
- **Stop before issuing any unknown write or other potentially destructive command to the physical ring; ask for explicit user approval.**
