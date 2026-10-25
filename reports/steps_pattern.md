# Steps / daily health sync pattern

**Capture:** `ring-hack-capture_steps.pcapng` (223 540 bytes, 3 196 frames, ~29.5 s)  
**Scenario:** ring on desk → connect → wait for steps to populate → green LEDs flash briefly → UI shows day steps + HR/SpO₂ min/max/current  
**JY session:** t ≈ **11.56–24.07 s** (~12.5 s of protocol)

All on GATT `0x56FF` / `0x33F3`–`0x33F4` (handles `0x0017`/`0x0019`).

---

## Verdict

The app does a **bulk history sync** right after connect—not a special “steps only” pipe:

| Cmd | Role | What arrived here |
|---|---|---|
| **`0x1D` (29)** | Live day totals | **5397 steps**, 146 kcal, 4182 dist |
| **`0x21` (33)** | Step **time buckets** (today, day offset `00`) | **30 × ~5 min records**, cumulative steps |
| **`0x22` (34)** | Sleep-style buckets | many 8-byte rows (mostly quality/`02`) |
| **`0x24` (36)** | Health samples | **4 records** with HR + SpO₂ (+ temp) |

Green LEDs: **no `0x04` vibrate/LED cmd**. The flash lines up with host **`0x07` openHeartRate** (+ `0x1E` auto-HR enable)—i.e. the **PPG sensor LEDs**, not a separate status blink.

**App ground truth (same day, user-reported):** HR min **64** / max **111** / avg **73** / latest **111**; SpO₂ latest **98** / high **99** / low **98** / avg **98**.

Those HR stats are **not** explainable from this session’s `0x24` alone (only 72/76/80/111 → would be min 72, avg ~85). They **do** match if the app merges earlier live `0x0B` samples from the HR capture (75→64) with these `0x24` records: combined min **64**, max **111**, mean **73.3 → 73**. SpO₂ matches `0x24` (ignore SpO₂=0). So min/max/avg are **app-side over accumulated samples**, not a ring-precomputed aggregate in this sync.

---

## Sequence (relative to first JY PDU)

| rel | Dir | Cmd | Notes |
|---:|---|---|---|
| 0.00 | R | `0x25` | device info (fw 152) |
| 0.09 | R | **`0x1D`** | unsolicited snapshot: **steps=5397** |
| 0.87 | H/R | `0x3D` | offline audio count = 0 |
| **1.25** | **H** | **`0x21`** | query day `00` |
| 1.47–1.62 | R | **`0x21`** | **5 packets**, idx 1..5, 16-byte buckets |
| 1.62+ | H/R | `0x1D` | empty query → same 5397 snapshot (retries) |
| **2.22** | **H** | **`0x22`** | query `00` |
| 2.28–2.34 | R | **`0x22`** | 3 packets sleep/history rows |
| 2.37 | H/R | `0x01` | setTime |
| 2.54 | H/R | `0x1A` | appInfo |
| **2.69** | **H** | **`0x07`** | open HR → **green LEDs** |
| 2.84 | H/R | `0x1E` | auto-HR enable |
| **2.99** | **H** | **`0x24`** | query `00` |
| 3.26 | R | **`0x24`** | **56 bytes = 4×14-byte health records** |
| … | | `0x3E` | keepalives |
| 12.4 | H/R | `0x43` | teardown |

---

## Payload layouts (**Observed**)

### `0x1D` — day step summary (14 bytes)

```
u32le timestamp
u16   0x0000
u32le steps
u16le calories
u16le distance
```

Example: `…00001515000092005610` → steps **5397**, cal **146**, dist **4182**.

Host may send empty `0x1D` to refresh; ring also pushes one on connect.

### `0x21` — step buckets (16 bytes each; multi-idx)

Host request payload: `00` (day offset 0 = today).

```
u32le timestamp   # bucket time (here often :xx:59)
u16   0x0000
u16le field       # often 300 (5 min); later rows vary—may be active-seconds, not fixed period
u32le steps       # **cumulative** through the day in this capture
u16le calories    # cumulative
u16le distance    # cumulative
```

This session: **30 buckets** from ~12:35Z through ~17:40Z; last cumulative steps **5397** (matches `0x1D`).

### `0x22` — sleep / activity list (8 bytes each)

Request `00`; replies multi-packet. Records look like `ts4 + 00 00 + flags` (here often `…000002`). Used for sleep UI; not required to explain the step total.

### `0x24` — health samples (14 bytes each)

Host request: `00`. One notify held **4 records**:

| Time (UTC) | HR | SpO₂ | Temp (/10 °C) |
|---|---:|---:|---:|
| 15:59:59 | 76 | 99 | 31.0 |
| 17:24:59 | 80 | 98 | 31.0 |
| 17:34:59 | 72 | **0** (invalid?) | 31.0 |
| 17:39:59 | **111** | 98 | 31.0 |

Trailing 4 bytes per record still partly unknown (`3601…` pattern).

**UI mapping (ground-truthed vs app):**

| Stat | App | From this `0x24` only | From `0x0B` (earlier HR run) + `0x24` |
|---|---|---|---|
| HR latest | 111 | 111 | 111 |
| HR min / max / avg | 64 / 111 / 73 | 72 / 111 / ~85 | **64 / 111 / 73** |
| SpO₂ latest / min / max / avg | 98 / 98 / 99 / 98 | 98 / 98 / 99 / ~98 | same (`0x24`) |

- Steps / day curve ≈ `0x1D` + `0x21` buckets  
- Day HR/SpO₂ cards ≈ **phone DB** of prior live streams + sparse `0x24` health records (ring does not push day min/max/avg as its own fields here)

---

## Green LEDs

| Hypothesis | Evidence |
|---|---|
| PPG LEDs from `0x07` open HR | **Best fit** — present in timeline; user saw brief green flash |
| Dedicated LED cmd `0x04` | **Not in this capture** |

App enables HR sensing during dashboard sync even on the desk; LEDs can flash without a full live `0x0B` stream (none here).

---

## FSM for CLI

```
subscribe 0x33F4
# connect pushes: 0x25, 0x44, 0x37, 0x1D(steps), 0x06, …
query 0x21 with day_offset=0   -> reassemble idx/total -> buckets
query 0x22 with 0              -> sleep rows (optional)
setTime / appInfo
optional: 0x07 / 0x1E          # may light PPG LEDs
query 0x24 with 0              -> health samples -> derive min/max/current
refresh 0x1D empty             -> totals
```

---

## Confidence

| Claim | Level |
|---|---|
| Steps total via `0x1D` | **Observed** (5397) |
| Day buckets via `0x21` | **Observed** |
| Health HR/SpO₂ samples via `0x24` | **Observed** |
| UI SpO₂ min/max/avg from `0x24` | **Observed** (matches app) |
| UI HR min/avg need prior `0x0B` history | **Observed** (64 + avg 73 only with earlier live stream) |
| Green LEDs = `0x07` PPG | **Inferred** (strong timing correlation) |
| Precomputed day min/max/avg on ring | **Unlikely** for this UI — app aggregates locally |
