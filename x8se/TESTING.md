# X8SE — what to run and what to send back

Thanks for helping test this. The goal is an open-source way to change DPI,
polling rate and read battery on the Attack Shark X8SE without the vendor
software.

The protocol was reverse-engineered from USB captures, but **it has never been
run against a real mouse yet** — you're the first. So this is ordered
deliberately: everything in Part A only *reads* from the mouse and cannot change
anything. Do Part A first and send the output back before going near Part B.

Please copy-paste the **full terminal output** of each step, even when it errors
or looks boring. An error message is useful data.

---

## Setup (once, ~5 minutes)

1. Install Python 3 from <https://python.org> — **tick "Add Python to PATH"** in
   the installer.
2. Open a terminal (Windows: press Start, type `cmd`, Enter) and run:

   ```
   pip install hidapi
   ```

3. Download this project (green **Code** button > **Download ZIP** on the repo
   page), unzip it, and `cd` into the folder. For example:

   ```
   cd Downloads\WireMouse-main
   ```

Close the Attack Shark vendor software completely before testing — if it's
holding the device open, nothing here can talk to it.

---

## Part A — read-only (nothing can be changed)

### A1. Find the mouse

```
python x8se_dpi.py --list
```

Please run this **twice**: once with the mouse on the 2.4 GHz dongle, and once
plugged in with the USB cable. Send both outputs and say which is which — the
device may appear under a different PID in each mode, and we only have the
wireless one confirmed so far.

If it prints "No devices for VID 0x1d57", say so — that alone is worth knowing.

### A2. Read the current configuration

```
python x8se_dpi.py --get
```

This should print your six DPI stages, which one is active, and the polling
rate.

**Please also open the vendor software and screenshot its DPI page**, then tell
us whether the numbers match. That cross-check is the single most valuable thing
in this whole document — it confirms the decoder is right on hardware other than
the one it was built from.

Also: **save this output somewhere.** The `Raw profile:` hex line is your
rollback if anything later goes wrong.

### A3. Battery

```
python x8se_dpi.py --battery
```

Run it twice in a row. The first reading after connecting can falsely say 100%,
so the second one matters more. Tell us what the vendor software reports at the
same moment.

### A4. The open question — does the DPI button emit an event?

```
python x8se_dpi.py --watch --timeout 30
```

While that's running, **press the DPI button on the mouse a few times**, and
move the mouse around. Then send everything it printed.

We're looking for a line like `03 02 10 02 00` (a DPI-cycle event). The X11
sends one; we don't know whether the X8SE does. **If nothing appears at all,
that is a real answer too** — please still send the output.

---

## Part B — writing settings

Only after Part A's output has been checked. These change settings on your
mouse. They're all reversible, but read this bit first:

- Every command below takes `--dry-run`, which prints the exact bytes and sends
  **nothing**. Run it with `--dry-run` first and send that output.
- The tool never writes a setting blindly: it reads your current profile, edits
  only the field you asked for, and preserves everything else.
- If anything goes wrong, restore the profile from the hex you saved in A2:

  ```
  python x8se_dpi.py --restore-hex 04380100013f...
  ```

  The vendor software can also reset the mouse.

### B1. Switch DPI stage (the safest write)

```
python x8se_dpi.py --set-active-stage 3 --dry-run
python x8se_dpi.py --set-active-stage 3
```

Then move the mouse — did the sensitivity actually change? Does the vendor
software show stage 3 selected? Run `--get` again to confirm it stuck.

### B2. Change a stage's DPI value

```
python x8se_dpi.py --set-stage 2 1600 --dry-run
python x8se_dpi.py --set-stage 2 1600
```

Then `--get` again, and check the vendor software shows stage 2 at 1600.

### B3. Polling rate — least certain, do this last

This report was carried over from the X11 driver and has **never been captured
on an X8SE**. It's the most likely thing to misbehave.

```
python x8se_dpi.py --set-polling 500 --dry-run
python x8se_dpi.py --set-polling 500
```

Check the vendor software, or a polling-rate test site like
<https://www.mouse-sensor.com/polling-rate> — did it take effect?

The X8SE advertises 4000 Hz, which we have no encoding for. `--set-polling 4000`
will refuse rather than guess.

---

## Part C — captures (only if you're up for it)

This is where the biggest remaining gaps get closed. It needs Wireshark, and
takes longer.

1. Install Wireshark from <https://www.wireshark.org/download.html>. **Make sure
   "USBPcap" is ticked** during installation. Reboot afterwards.
2. Open Wireshark. In the interface list you'll see `USBPcap1`, `USBPcap2`, etc.
   Each one is a different USB controller. **Expand each one and find the one
   that actually lists your mouse** — this is the step everyone gets wrong, and
   picking the wrong one produces a capture with no mouse traffic in it.
3. Double-click that interface to start capturing.
4. Open the vendor software and change **one setting only**.
5. Stop the capture and save it as a `.pcapng`.

Please do one capture per setting, and **name the file after what you changed**,
e.g. `polling_1000_to_500.pcapng`. In a text file alongside it, note the exact
before and after values the vendor software showed.

In priority order:

| # | What to change in the vendor software | Why it matters |
|---|---|---|
| 1 | Polling rate, e.g. 1000 → 500 Hz | Confirms the one setting we're guessing at |
| 2 | Polling rate → 4000 Hz (if offered) | Completely unknown encoding |
| 3 | One DPI stage's value, e.g. stage 1 → 1200 | Confirms the DPI codec on a second mouse |
| 4 | A button remap | Report `0x08` is unidentified |
| 5 | RGB colour or effect | Profile bytes 25–49 are unmapped |

**Important:** change the setting *in the vendor software*, not with the button
on the mouse. The button is handled inside the mouse and puts nothing on the USB
bus — we already have one capture that came back empty for exactly that reason.

---

## Sending results back

Most useful, in order:

1. Terminal output from every Part A step (paste as text, not screenshots)
2. Whether the numbers in `--get` matched the vendor software
3. Whether the Part B writes actually took effect
4. Any `.pcapng` files, with a note of what changed from what to what
5. Your mouse's exact model/variant and firmware version if the vendor software
   shows one

If something crashes, the full error text including the `Traceback` lines is
exactly what's needed — don't trim it.
