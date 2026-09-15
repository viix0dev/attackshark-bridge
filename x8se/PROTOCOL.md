# Attack Shark X8SE — USB HID Protocol

Status: **verified against capture + the device's own HID report descriptor.**

Everything below was derived from two captures — `x8se/800to1600to800.pcapng`
(the vendor software changing DPI 800 -> 1600 -> 800) and
`X8SE_20260905_131001.pcap` (which turned out to contain no DPI change, but did
capture the battery event) — and cross-checked against the
[X11 driver docs](https://github.com/HarukaYamamoto0/attack-shark-x11-driver).
Where a field is still a guess it is marked **UNVERIFIED**.

---

## 1. Device identity

From the DEVICE descriptor in the capture (`1201100100000040571d2021060101020301`):

| Field | Value |
|---|---|
| idVendor | `0x1D57` |
| idProduct | `0x2120` (2.4 GHz dongle) |
| bcdDevice | `0x0106` |
| iManufacturer | `"Beken"` |
| iProduct | `"X8SE Mouse"` |
| iSerial | `"X8SE Mouse-001"` |
| Configurations | 1, with **4 interfaces** |

`Beken` matches the X11's BK3630 SoC vendor, which is why the two mice share so
much protocol.

### Config interface

**Interface 2** is the configuration interface. Every vendor request in the
capture uses `wIndex = 2` — identical to the X11.

---

## 2. Feature reports declared by interface 2

Parsed from the interface-2 HID report descriptor (`GET_DESCRIPTOR HID_REPORT
wIndex=2`, 206 bytes). Sizes include the leading report-ID byte:

| Report ID | Wire size | Purpose |
|---|---|---|
| `0x04` | 52 | **Main profile** (DPI stages, active stage, LOD, RGB) |
| `0x05` | 13 | unknown |
| `0x06` | 9 | **Polling rate** |
| `0x07` | 8 | unknown |
| `0x08` | 59 | unknown (button mapping? **UNVERIFIED**) |
| `0x09` | 64 | unknown (macro? **UNVERIFIED**) |
| `0x0a` | 8 declared | **State readback blob** (over-read to 128, see §4) |
| `0x0b` | 8 | device info |
| `0x0c` | 6 | unknown |
| `0x0d` | 8 | unknown |
| `0x10` | 8 | unknown |
| `0xa0` | 8 | **Command / readback-request channel** |

The declared 51 data bytes + 1 report ID for `0x04` is exactly the 52-byte
`SET_REPORT` seen on the wire, which confirms the descriptor parse.

---

## 3. Report `0x04` — main profile (write)

```
bmRequestType = 0x21   (Host-to-Device, Class, Interface)
bRequest      = 0x09   (SET_REPORT)
wValue        = 0x0304 (Feature, Report ID 4)
wIndex        = 2
wLength       = 52
```

Layout is **identical to the X11**, confirmed byte-for-byte:

| Offset | Field | Notes |
|---|---|---|
| 0 | `0x04` | report ID |
| 1 | `0x38` | fixed |
| 2 | `0x01` | fixed |
| 3 | Angle snap | 0/1 |
| 4 | Ripple control | 0/1 |
| 5 | `0x3F` | fixed |
| 6 | Stage mask A | bit N set = stage N+1 uses the 2x multiplier (>12000 DPI) |
| 7 | Stage mask B | duplicate of A |
| 8–13 | Stage 1–6 DPI | encoded `xByte`, see §7 |
| 14–15 | `0x01 0x01` | **X8SE differs here** — the X11 has `0x00 0x00` |
| 16–21 | Stage 1–6 high flag | the `yByte` of the DPI codec |
| 22–23 | `0x00 0x00` | fixed |
| 24 | **Active stage** | 1–6 |
| 25–49 | RGB / reserved | preserve as-is on read-modify-write |
| 50 | Checksum high | |
| 51 | Checksum low | |

### Checksum — confirmed

```python
s = sum(buf[3:50]) & 0xFFFF
buf[50] = (s >> 8) & 0xFF
buf[51] = s & 0xFF
```

Verified against both captured packets:

| Packet | Computed | Stored |
|---|---|---|
| 1 | `0x0E4B` | `0x0E4B` OK |
| 2 | `0x0E4A` | `0x0E4A` OK |

### The captured DPI change, decoded

The only two bytes that differ between the two captured packets are offset 24
and the checksum:

```
offset 24: 0x03 -> 0x02
offset 51: 0x4b -> 0x4a   (checksum follows)
```

Decoding the stage table (`09 12 25 2a 2f 38`) with the PAW3311 codec:

| Stage | Byte | DPI |
|---|---|---|
| 1 | `0x09` | 400 |
| 2 | `0x12` | **800** |
| 3 | `0x25` | **1600** |
| 4 | `0x2A` | 1800 |
| 5 | `0x2F` | 2000 |
| 6 | `0x38` | 2400 |

Packet 1 sets active stage **3 = 1600 DPI**, packet 2 sets active stage
**2 = 800 DPI** — exactly the `800 -> 1600 -> 800` the capture was named for.
This confirms the whole layout end to end.

Note the vendor software **does not send a DPI value** for a stage switch — it
rewrites the entire profile and only changes the active-stage index.

---

## 4. Readback: the `0xa0` command channel

This is the part the X11 driver does **not** have (its README lists "settings
reading" and "battery status" as missing). The X8SE exposes a generic
request/poll/fetch mechanism on report `0xa0`.

### Sequence (observed verbatim in the capture)

```
t=1.521  SET 0xa0  <- a0 0b 08 00 00 00 00 00   request report 0x0b, 8 bytes
t=2.041  GET 0xa0  -> a0 01 00 00 00 00 00 00   byte[1]=1 => ready
t=2.150  GET 0x0b  -> 0b 08 01 06 00 00 00 00   the payload

t=2.260  SET 0xa0  <- a0 0a 80 00 01 00 00 00   request report 0x0a, 0x80=128 bytes
t=2.571  GET 0xa0  -> a0 01 00 00 00 00 00 00   ready
t=2.681  GET 0x0a  -> <128-byte state dump>
```

### Request format

| Offset | Meaning |
|---|---|
| 0 | `0xA0` |
| 1 | report ID to fetch |
| 2 | number of bytes to fetch |
| 3 | `0x00` |
| 4 | profile index (**UNVERIFIED** — was `0x01`) |
| 5–7 | `0x00` |

`GET 0xa0` returns `a0 00 ...` while busy and `a0 01 ...` when the requested
report is ready. Poll it, then `GET_REPORT` the target ID.

Note report `0x0a` **declares only 7 data bytes** in the descriptor but is read
back with `wLength=128`. The device honours the over-read. On Windows,
`HidD_GetFeature` caps the buffer at the collection's largest feature report
(64 bytes, from report `0x09`), so a 128-byte read will fail there — read 64
instead, which still covers every field identified below.

### The 128-byte state dump (report `0x0a`)

The dump embeds the whole `0x04` profile body at a **+2 offset**:

```
GET[i+2] == SET04[i]   for i in 3..49    (verified, all 47 bytes match)
```

| Offset | Value seen | Meaning |
|---|---|---|
| 0 | `0x0A` | report ID |
| 1 | `0x80` | echo of requested length |
| 2 | `0x01` | profile index (**UNVERIFIED**) |
| 3 | `0x01` | **polling rate** — same encoding as report `0x06` => 1000 Hz |
| 4 | `0xFE` | `0xFF - byte[3]`, the polling-rate complement checksum |
| 5–51 | | profile body, `== SET04[3..49]` |
| 52 | `0x00` | padding |
| 53–54 | `4A 0E` | profile checksum, **little-endian** here (`0x0E4A`) |
| 63 | `0x5E` = 94 | **battery percent?** (**UNVERIFIED** — prefer the event message in §5) |
| 71–74 | `11 0A 16 0D` | unknown (LOD / debounce / sleep? **UNVERIFIED**) |
| 83 | `0x3C` = 60 | unknown, plausibly a sleep timer (**UNVERIFIED**) |
| 119 | `0xA6` | unknown |

Byte 3 reading `0x01` with its complement `0xFE` at byte 4 is the exact shape of
the X11 polling-rate payload, which is strong evidence for that identification.

---

## 5. Asynchronous event messages (battery) — VERIFIED

The mouse pushes unsolicited 5-byte reports **into the host** on interface 2's
interrupt IN endpoint (`0x83`, declared in the descriptor as Report ID 3, Input,
4 data bytes). No request, no vendor software, no `0xa0` handshake — they just
arrive.

This is the same messaging protocol the X11 uses
([docs/messages](https://github.com/HarukaYamamoto0/attack-shark-x11-driver/tree/main/docs/messages)):

| Byte | Meaning |
|---|---|
| 0 | opcode, always `0x03` |
| 1 | **device ID — `0x02` on the X8SE** (the X11 uses `0x55`) |
| 2 | event code |
| 3 | parameter 1 |
| 4 | parameter 2 |

### Battery — event `0x40` ("Device Connection Message")

Captured in `X8SE_20260905_131001.pcap`, three times, identical:

```
03 02 40 01 64

03  event message
02  device ID (X8SE)
40  device connection / battery message
01  charge state
64  battery = 100%
```

| Parameter 1 | Meaning |
|---|---|
| `0x01` | charging complete |
| `0x02` | fully charged |
| `0x03` | charging in progress (also means wired mode) |

Parameter 2 is the battery percentage as a plain uint8. In wired mode (`0x03`)
it holds the last processed reading rather than a live one.

Event code `0x41` is reported on the X11 as an equivalent of `0x40`; not seen on
the X8SE.

Two caveats carried over from the X11 research, both worth respecting:

- the first report after a connection is established may read `0x64` (100%)
  regardless of the real level — the firmware appears to seed the value before
  the ADC takes its first measurement. Wait for a second report.
- the percentage is approximate and can read above or below the true level.

**This supersedes the offset-63 guess in §4.** It is a decoded, cross-confirmed
field rather than a plausible-looking byte, and it is what `--battery` reads.

### DPI cycle — event `0x10` (X11 only so far)

The X11 emits `03 <id> 10 <stage> 00` when the DPI cycle is triggered from a
button. **No such event appears anywhere in the X8SE capture**, so it is
unconfirmed here — see §8.

---

## 6. Report `0x06` — polling rate

The descriptor declares report `0x06` as 9 bytes on the wire — exactly the X11's
polling-rate report. **Not yet captured on the X8SE**, so this is carried over
from the X11 and should be confirmed before trusting it.

```
wValue = 0x0306, wIndex = 2, wLength = 9

06 09 01 <rate> <0xFF-rate> 00 00 00 00
```

| Rate | Byte |
|---|---|
| 1000 Hz | `0x01` |
| 500 Hz | `0x02` |
| 250 Hz | `0x04` |
| 125 Hz | `0x08` |

The X8SE advertises 4000 Hz in wireless mode, which this table does not cover —
the encoding for it is unknown. Capture it before assuming.

---

## 7. DPI encoding (PAW3311)

DPI is **not** stored as a literal number. It is an index into the sensor's step
table (`DPI_3311`, 220 entries), split across three places in the report:
`xByte` (offsets 8–13), `yByte` (offsets 16–21) and a `double` bit (offsets 6/7).

```python
def dpi_to_bytes(dpi):
    dpi = max(50, min(dpi, 26000))
    if dpi == 20100:
        return 0xEB, 1, True
    double = False
    target = dpi
    if dpi > 10000:
        target = round(dpi / 2)
        double = True
    if target > 10000:
        combined = 199 + (target - 10100) // 100
        return combined & 0xFF, (combined >> 8) & 0xFF, double
    if target > 5000 and target % 100 == 0:
        return DPI_3311[target // 100 - 1], 1, double
    return DPI_3311[(target - 50) // 50], 0, double
```

Range 50–26000, usually in steps of 50. The X8SE's captured stage bytes decode
correctly with this, which is why it is treated as verified.

---

## 8. What is still unknown

- **~~Battery~~** — solved, see §5. The remaining loose end is offset 63 of the
  `0x0a` dump, which read 94 while the event message said 100. Those disagree,
  so offset 63 is probably not battery percent at all.
- **The DPI cycle event (`0x10`).** `X8SE_20260905_131001.pcap` was taken while
  changing DPI with the button on the mouse, and contains **no** event message
  other than battery, and no control transfers at all. So either the X8SE does
  not emit the X11's DPI-cycle event, or it only fires when the button is bound
  to the "DPI Cycle" macro specifically. Worth one more capture: run
  `x8se_dpi.py --watch` and press the DPI button.
- **Polling rate on the X8SE** (report `0x06`) — inherited from the X11, never
  captured here. The 4000 Hz encoding is entirely unknown.
- **Reports `0x05`, `0x07`, `0x08`, `0x09`, `0x0c`, `0x0d`, `0x10`** — sizes are
  known, meanings are not. `0x08` (59 B) and `0x09` (64 B) are the right size for
  button mapping and macros respectively, by analogy with the X11.
- **Profile switching** — the `0x01` at request offset 4 and dump offset 2 looks
  like a profile index but was never observed changing.
- **Offsets 25–49** of report `0x04` — RGB on the X11; not exercised in this
  capture, so preserve them rather than synthesising them.
