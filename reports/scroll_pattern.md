# Scroll / tap gesture pattern

**Capture:** `ring-hack-capture_scroll.pcapng` (481 424 bytes, 7 116 frames, ~85 s)  
**Scenario:** connect/pair → single tap → double tap → repeat → disconnect; phone scrolled down and up  

Scrolling is **not** on the JY `0x33F3`/`0x33F4` channel. It is **BLE HID** digitizer input.

---

## Verdict

| Item | Value |
|---|---|
| Service | HID `0x1812` |
| Characteristic | Report `0x2A4D`, value handle **`0x003D`** |
| CCCD | `0x003E` (enabled `01 00`) |
| Report Reference `0x003F` | **Report ID `0x02`**, Input |
| Mechanism | Synthetic **touch-screen swipe** (not mouse wheel) |

JY traffic during gestures is only keepalives (`0x3E`); taps do not use `FE FC` commands.

---

## Report map (Report ID 2)

From Report Map read at handle `0x0037`: Digitizer / Touch Screen / Finger, with:

- Tip Switch, In Range, Confidence, Contact ID (packed into **1 byte**)
- **X** 12-bit, **Y** 12-bit (logical 0…1000)

ATT notify payload is **4 bytes** (Report ID omitted; implied by Report Reference):

```
byte0: tip:1 | in_range:1 | confidence:1 | contact_id:5
bytes1-3: little-endian packed (X 12b | Y 12b)
```

Decode:

```python
tip = b[0] & 1
packed = b[1] | (b[2] << 8) | (b[3] << 16)
x = packed & 0xFFF
y = (packed >> 12) & 0xFFF
```

X is fixed at **500** in this capture; motion is almost pure **vertical Y**.

---

## Observed gestures (5 bursts)

| # | t (s) | Pattern | Y path | Interpretation |
|---:|---|---|---|---|
| 1 | 21.58 | short (~6 reports, 0.20 s) | 620 → 120 | finger **UP** → scroll content **DOWN** |
| 2 | 25.02 | short | 620 → 120 | same (DOWN) |
| 3 | 28.11 | longer (~8 reports, 0.23 s) | 350 → 920 | finger **DOWN** → scroll content **UP** |
| 4 | 31.05 | short | 620 → 120 | DOWN |
| 5 | 34.12 | longer | 350 → 920 | UP |

So **two canned swipe macros**:

1. **Scroll down:** tip-down at (500, ~620), Y decreases toward ~120, tip-up  
   Example start/end: `00f4c126` → … → `00f48107`
2. **Scroll up:** tip-down at (500, ~350), Y increases toward ~920, tip-up  
   Example: `00f4e115` → … → `00f48139`

Button/tip byte toggles `00` (release) ↔ `07` (tip+range+confidence, contact 0) during the stroke.

User’s single vs double tap map onto these two opposite swipes (exact tap→macro binding is firmware-side; both directions appear as distinct HID sequences).

---

## FSM / CLI notes

To *observe* scroll from a Python client:

1. Connect + (typically) bond — HID often triggers pairing  
2. Discover HID Report `0x003D` (or match Report Ref ID 2)  
3. Enable CCCD `0x003E`  
4. On notify: decode tip/X/Y; classify swipe by ΔY sign/magnitude  

Emitting scroll ourselves would mean **writing/forging HID input** (not JY writes). That is a different, more sensitive path than JY telemetry; keep it opt-in and separate from audio/HR commands.

Mouse Report ID **`0x03`** exists in the map but was **not** the notify path used here.

---

## Confidence

| Claim | Level |
|---|---|
| Scroll = HID Report ID 2 on `0x003D` | **Observed** |
| 4-byte tip + 12-bit X/Y packing | **Observed** (matches map + values) |
| Two opposite vertical swipes = up/down scroll | **Observed** / **Inferred** OS mapping |
| Single tap vs double tap ↔ which swipe | **Inferred** from experiment description + two sequence families |
| JY involved in scroll | **Not observed** |
