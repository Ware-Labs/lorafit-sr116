# How to sniff the SR116 with an nRF52840 Dongle and Wireshark

This is the capture method that produced the `ring-hack-capture*.pcapng` files in this repo. Android `btsnooz` logs drop most ATT payload bytes, so they cannot show audio or vitals. A Nordic sniffer sitting on the air sees the full packets, including encrypted ATT, **if it watches the pairing**.

Use this only on a ring and phone you own.

Official Nordic walkthrough (screenshots, current `nrfutil` commands): [Setting up nRF Sniffer for Bluetooth LE](https://academy.nordicsemi.com/courses/bluetooth-low-energy-fundamentals/lessons/lesson-6-bluetooth-le-sniffer/topic/nrf-sniffer-for-bluetooth-le/).

## What you need

- [nRF52840 Dongle](https://www.nordicsemi.com/Products/Development-hardware/nRF52840-Dongle) (PCA10059). This how-to is for that dongle, not an nRF52840 DK.
- A Windows PC with a free USB port. A short USB extension cable helps you park the dongle between the phone and the ring.
- The phone that runs the LoraFit app, and the ring.
- [Wireshark](https://www.wireshark.org/download.html) 4.x (3.4.7 or newer is the Nordic minimum).
- [nRF Util](https://www.nordicsemi.com/Products/Development-tools/nRF-Util) (`nrfutil.exe`).

## 1. Install Wireshark and nrfutil

1. Install Wireshark. The default options are fine. You do not need Npcap for this sniffer; the dongle is a COM-port extcap, not an Ethernet capture.
2. Download `nrfutil.exe` and put it on your `PATH` (for example `C:\nordic_tools\`).
3. In a terminal:

```powershell
nrfutil install ble-sniffer device
```

`ble-sniffer` includes the Wireshark plugin and the dongle firmware. `device` is what programs the dongle.

Firmware lands under:

```text
%USERPROFILE%\.nrfutil\share\nrfutil-ble-sniffer\firmware\
```

The dongle file is a **zip**, named like `sniffer_nrf52840dongle_nrf52840_<version>.zip`. DK boards use a `.hex` instead. Do not flash a DK hex onto the dongle.

## 2. Register the sniffer with Wireshark

Close Wireshark. Open **PowerShell as Administrator** (bootstrap writes into Wireshark's extcap folder) and run:

```powershell
nrfutil ble-sniffer bootstrap
```

If Wireshark was installed for the current user only, the extcap path is under `%APPDATA%\Wireshark\extcap`. Check it in Wireshark: **Help → About Wireshark → Folders → Personal Extcap path**.

## 3. Flash the dongle

The dongle has no debugger. It only accepts new firmware in DFU mode.

1. Plug the dongle into USB.
2. Press the **side button** (the small button on the narrow edge, not a software reset). The red LED starts pulsing. That is DFU mode.
3. Confirm the PC sees it:

```powershell
nrfutil device list
```

4. Program the zip from step 1 (adjust the version in the filename):

```powershell
nrfutil device program --firmware "$env:USERPROFILE\.nrfutil\share\nrfutil-ble-sniffer\firmware\sniffer_nrf52840dongle_nrf52840_<version>.zip"
```

If more than one Nordic device is listed, pass `--serial-number` from `nrfutil device list`.

When programming finishes, unplug and replug the dongle. It should enumerate as a COM port, not stay in the pulsing-red DFU state.

Alternate flasher: nRF Connect for Desktop → **Programmer**, select the dongle while the red LED is pulsing, add the same zip, and write it.

## 4. Start a capture

1. Plug the dongle in. Put it physically between the phone and the ring, within about a metre of both. Walls and a laptop lid between them drop packets.
2. Open Wireshark. **Capture → Refresh Interfaces**.
3. Double-click the interface named **nRF Sniffer for Bluetooth LE** on a COM port.
4. You should see a stream of advertising packets (`LE LL`) from whatever is nearby, plus an nRF Sniffer toolbar.

If the interface is missing: refresh again, rerun `nrfutil ble-sniffer bootstrap` from an admin shell, and confirm the COM port appears in Device Manager. Only one program can hold the COM port.

### Follow the ring

Leave the toolbar on **All advertising devices** until you see `SR116-10A2`. This ring's public address in our captures is `73:01:06:00:10:a2`. Then pick that device in the sniffer **Device** dropdown so the dongle follows its connection (channel hopping). If you stay on "all devices", you will miss most of the connection.

Useful display filter once ATT is visible:

```text
btatt
```

### Decrypting the link

The LoraFit phone bonds. If that bond already exists, the phone encrypts ATT with a key the sniffer never saw, and Wireshark shows encrypted link-layer data instead of `FE FC`.

Before a capture you care about:

1. Start the sniffer and follow the ring **before** you open the app.
2. In Android **Settings → Bluetooth**, forget `SR116-10A2`.
3. Open LoraFit and connect, so pairing happens while the sniffer is listening.

On this ring the phone asks for LE Secure Connections, and the ring answers **No Input, No Output**, so the exchange falls back to **Legacy Just Works**. The sniffer can derive the key from that exchange. You should then see SMP pairing followed by clear ATT writes whose value starts with `fe fc`.

If you only see encrypted packets, the bond was already stored. Forget the device and pair again under an already-running capture. Do not try to extract the phone's bonding keys.

## 5. Save the file

**File → Save As**, type **pcapng**, into the repo root. `*.pcapng` is gitignored on purpose (it can contain a pairing transcript). The durable record of a capture is the matching `reports/*_pattern.md`, which you can commit.

Suggested names, matching files already analyzed here:

| File | What you did |
|---|---|
| `ring-hack-capture.pcapng` | Pair, then one offline recording download |
| `ring-hack-capture_multitransfer.pcapng` | Three recordings, UI shows 1/3 … 3/3 |
| `ring-hack-capture_heartrate.pcapng` | Start heart rate, wait for a live BPM, stop |
| `ring-hack-capture_spO2.pcapng` | Start SpO₂, wait for a percent, stop |
| `ring-hack-capture_scroll.pcapng` | Single tap and double tap (phone scrolls) |
| `ring-hack-capture_steps.pcapng` | Ring on the desk; day steps and vitals populate |

Write the app's on-screen numbers next to the filename (steps, HR min/max/avg/latest, SpO₂ latest/high/low/avg). Those notes are what made the `0x24` vs live-sample question decidable.

## 6. Scenarios

Do one scenario per file. Close the app and stop the capture between them so the trace has one session.

### A. One recording

1. Record a few seconds on the ring while it is **not** connected.
2. Forget the bond if this capture must be decrypted (see above).
3. Start Wireshark, follow the ring, then open LoraFit and let it pair and download.
4. Confirm the app plays the clip, then stop the capture.

In Wireshark, ATT writes to handle `0x0017` / UUID `0x33F3` should include:

- `fe fc 40 …` — prep
- `fe fc 34 …` with an empty payload — start
- many notifications on `0x0019` of `fe fc 34` with ~486-byte payloads (Opus)
- `fe fc 36 …` — complete

The vendor app echoes `0x36`, which **deletes** that file on the ring. Expect the recording to be gone afterward.

### B. Three recordings

Leave three clips on the ring. Open the recordings screen and wait until the app shows 1/3, 2/3, and 3/3. Force-close the app.

You should see one `0x40`, then three `0x34` transfers. Each ends with `0x36` whose payload is a remaining count (`03 00`, then `02 00`, then `01 00`). A later empty `0x34` gets `0x35` (queue empty). There is no per-file select command. Details: `reports/multitransfer_pattern.md`.

### C. Heart rate

Connect, start a heart-rate measurement, wait until the app shows a changing BPM, then stop and disconnect.

Look for host `fe fc 07` (open), notifications `fe fc 0b` whose last payload byte is the BPM, then empty `fe fc 11` when the ring ends the stream. Details: `reports/heartrate_pattern.md`.

### D. SpO₂

Start SpO₂, wait until a percent appears (often ~20 seconds), then stop.

Look for `fe fc 17` payload `01` to start and `00` to stop, and `fe fc 18` with the percent in the last byte (98 is `0x62`). Details: `reports/spo2_pattern.md`.

### E. Scroll

Connect, then single-tap and double-tap the ring so the phone scrolls. This traffic is **not** `FE FC`. It is HID input on report handle `0x003D` (Report ID 2, a fake touch swipe). Details: `reports/scroll_pattern.md`.

### F. Steps and the dashboard

Leave the ring on the desk (so you are not adding steps during the capture). Forget/pair as needed, open the app, and wait until:

- the day's step count fills in
- the green LEDs flash briefly
- min / max / latest heart rate and SpO₂ are on screen

Write those UI numbers down. Stop the capture.

Expect `0x1D` (step total), `0x21` (step buckets), `0x22` (sleep-style rows), `0x24` (a few HR/SpO₂/temp samples), and a `0x07` around the LED flash. The day's HR min/max/avg are **not** a separate ring field; the app averages samples it already stored plus `0x24`. Details: `reports/steps_pattern.md`.

## 7. Check the file before you analyze it

A useful capture has all of these:

- Advertising from `SR116-10A2` before the connection.
- An LE connection, then (if you forgot the bond) SMP pairing.
- ATT **Write Request** or **Write Command** to `0x0017` and **Handle Value Notification** from `0x0019`, with values starting `fe fc`, not a wall of encrypted PDUs.
- For an audio test, `0x34` notifications whose ATT value is hundreds of bytes, not a 10-byte header only.

If the bytes pane shows `fe fc` you can stop. The pattern docs were written from that view.

## 8. What this repo does with a capture

`*.pcapng` stays local. Analysis notes go in `reports/`. Existing helpers:

```powershell
python tools/analyze_btsnoop.py
python tools/opus_bin_to_audio.py reports/transfer_0x34_bodies.bin --play
python -m unittest discover -s tests -v
```

`analyze_btsnoop.py` only reads the Android HCI logs. Sniffer pcaps were pulled apart with the one-off scripts under `tools/analyze_*.py` (heart rate, SpO₂, steps, scroll, multi-transfer). To re-check a new pcap, open it in Wireshark and filter `btatt`, or adapt those scripts.

The local client that speaks the same commands is:

```powershell
pip install -r requirements.txt
python -m sr116
```

It will not echo `0x36` unless you check **Delete after download**.
