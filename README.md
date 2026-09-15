# AttackShark Bridge 🦈

> Reverse-engineering AttackShark gaming mice to bring native driver support to the **OpenMouse** project—freeing hardware from bloated proprietary software.

---

## Overview

Many budget-friendly AttackShark mice feature impressive hardware specifications, but rely on closed-source, OS-restricted, and bloatware-heavy configuration software. **AttackShark Bridge** aims to map out the underlying USB HID communications, packet layouts, and hardware registers to provide clean, native, open-source support across Linux, macOS, and Windows.

This repository includes:
* **Protocol Specifications:** Reverse-engineered USB/2.4GHz HID report maps (DPI, polling rates, RGB lighting, key remapping, and battery status).
* **Wireshark Analysis Tools:** Custom scripts, dissectors, and filters to parse and decode USB packet captures (`.pcapng`) automatically.
* **OpenMouse Drivers:** Integration code to connect reverse-engineered protocols directly to the OpenMouse Project.

---

## Supported Devices

| Model | Connection | Status | Notes |
| :--- | :--- | :--- | :--- |
| **AttackShark X11** | Wired / 2.4G / BT | 🟢 Partily Supported | https://github.com/viix0dev/OpenMouse-Bridge |
| **AttackShark X8se** | Wired / 2.4G | 🟢 Protocol mapped | DPI + active stage verified — see [x8se/PROTOCOL.md](x8se/PROTOCOL.md) |
| **AttackShark X3** | Wired / 2.4G / BT | 🔴 Planned | Captures needed |

---

## Included Analysis Tools
Take a look on the [Helpers.md](https://github.com/viix0dev/attackshark-bridge/blob/main/Helpers.md)

---

## AttackShark X8SE

The X8SE protocol is documented in **[x8se/PROTOCOL.md](x8se/PROTOCOL.md)** and
implemented in **`x8se_dpi.py`**. DPI stages, the active stage, the checksum and
the settings-readback channel are verified against a real capture and against
the mouse's own HID report descriptor.

```bash
pip install hidapi

python x8se_dpi.py --list                 # find the device
python x8se_dpi.py --get                  # read the current configuration
python x8se_dpi.py --set-active-stage 3   # switch DPI stage
python x8se_dpi.py --set-stage 2 1600     # set stage 2 to 1600 DPI
python x8se_dpi.py --battery              # battery level and charge state
python x8se_dpi.py --watch --timeout 20   # log events live, to map what's left
python x8se_dpi.py --dump 0x0b 8          # dump any feature report
```

Add `--dry-run` to any write to print the exact bytes without sending them.

Battery needs no request at all: the mouse pushes `03 02 40 <state> <percent>`
onto an interrupt endpoint by itself, which is how `--battery` reads it. Device
ID `0x02` identifies an X8SE (the X11 uses `0x55`).

Unlike the X11 driver, the X8SE can also be **read back**: report `0xa0` is a
request/poll/fetch channel that returns the mouse's live configuration, so the
tool never has to guess at the current state — every write is a
read-modify-write that preserves the settings it doesn't understand.

The protocol logic is tested offline against the captured packets, with no mouse
required:

```bash
python x8se/test_protocol.py
```

Its main test regenerates, byte for byte, the packet the vendor software sent to
change DPI — starting from the profile the mouse reported.

### Got an X8SE? Help test

The protocol is decoded but has **not yet been run against real hardware**. If
you own one, **[x8se/TESTING.md](x8se/TESTING.md)** is a step-by-step guide —
read-only checks first, then writes, then captures. Every step says what to send
back.

The most useful things right now: does the DPI button emit an event (`--watch`),
and a capture of a **polling rate** change, which is the one setting still
carried over unverified from the X11.
