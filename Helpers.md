# DPI capture toolkit

Two small, dependency-free Python scripts that sit on top of your existing
Wireshark + USBPcap workflow, so you stop having to eyeball hex bytes by hand.

No changes to how you capture — you still use Wireshark/USBPcap exactly like
before. These scripts just (1) stamp the *exact* moment you change a setting,
and (2) automatically pull out and diff the relevant USB packets afterward.

## Why this works

USBPcap timestamps in the `.pcapng` are real UTC epoch times (down to the
microsecond), not some internal counter. That means a timestamp recorded by
a normal Python script on the same machine lines up *directly* with packet
timestamps in the capture — no manual correlation needed.

## Workflow

1. **Start your Wireshark/USBPcap capture** as usual (select your USBPcap
   interface, hit start).

2. **In a separate terminal, run the marker tool:**
   ```
   python dpi_marker.py
   ```
   For each DPI change you're about to make:
   - Type a short label (e.g. `800to1600`) and press Enter, or just press
     Enter for an auto label.
   - You'll see `3... 2... 1... CHANGE!` — change the DPI at that moment.
   - Repeat for each change (e.g. do it again for `1600to800`).
   - Type `q` + Enter when done. This writes `markers.json`.

3. **Stop the Wireshark capture and save it** (e.g. `capture.pcapng`).

4. **Run the analyzer:**
   ```
   python analyze_capture.py capture.pcapng markers.json
   ```
   This prints:
   - The full timeline of every HID `GET_REPORT`/`SET_REPORT` transaction
     in the capture, decoded (report type, report ID, direction, hex data).
   - For each marker, every HID control transaction within a time window
     of the marked moment (default ±2s, adjust with `--window 1.5`).
   - A before/after diff per report ID across each marker, showing exactly
     which byte offsets changed and their old/new values.

You can also run the analyzer without a markers file to just see the full
decoded timeline:
```
python analyze_capture.py capture.pcapng
```

## Requirements

- Python 3.6+, no external packages (pure stdlib — works even offline).
- Tested against Windows USBPcap captures (linktype 249). It will warn if
  the capture uses a different link type.

## Known limitation (already fixed here, worth knowing)

USBPcap's `irpId` field looks like a transaction ID but is actually a raw
Windows kernel pointer, which gets reused across many unrelated transfers.
Do not use it to correlate SETUP/completion pairs — this toolkit instead
relies on the fact that USBPcap always emits the completion as the very
next control-transfer packet on the same device, which held up against
manual verification on a real X8 SE capture.

## Extending it

If your device's DPI/config data lives somewhere this doesn't already
decode (e.g. a vendor report ID this script doesn't know the name of), the
raw hex is printed either way — you can extend `REQ_NAMES` or add your own
per-report decoders in `analyze_capture.py` as you map out more fields.
