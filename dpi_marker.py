#!/usr/bin/env python3
"""
dpi_marker.py — run this in a terminal WHILE your Wireshark/USBPcap capture
is running. Each time you're about to change the DPI, hit Enter, watch the
countdown, and change it exactly when it says CHANGE. The exact epoch
timestamp gets logged to markers.json so the analyzer can find it later.

Usage:
    python dpi_marker.py                 # writes to markers.json
    python dpi_marker.py my_markers.json # custom output file

Workflow:
    1. Start your Wireshark/USBPcap capture.
    2. Run this script in a separate terminal.
    3. For each DPI change you're about to make:
         - Type a short label (e.g. "800to1600") and press Enter, or just
           press Enter to auto-label it change_1, change_2, ...
         - Wait for "3... 2... 1... CHANGE!"
         - Change the DPI at the moment "CHANGE!" prints.
    4. Type 'q' + Enter when done.
    5. Stop the capture, save the .pcapng.
    6. Run analyze_capture.py your_capture.pcapng markers.json
"""

import json
import os
import sys
import time

try:
    import winsound
    def beep():
        winsound.Beep(1000, 150)
except ImportError:
    def beep():
        # Terminal bell fallback on non-Windows
        sys.stdout.write("\a")
        sys.stdout.flush()


def countdown_and_mark(label):
    print(f"\n[{label}] Get ready...")
    time.sleep(0.7)
    for n in (3, 2, 1):
        print(f"  {n}...")
        beep()
        time.sleep(1.0)
    mark_time = time.time()
    print("  >>> CHANGE NOW <<<")
    beep()
    beep()
    return mark_time


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "markers.json"

    markers = []
    if os.path.exists(out_path):
        try:
            with open(out_path) as f:
                markers = json.load(f)
            print(f"Loaded {len(markers)} existing marker(s) from {out_path}")
        except Exception:
            pass

    print("=" * 60)
    print("DPI change marker tool")
    print("Make sure your Wireshark/USBPcap capture is ALREADY running.")
    print("Press Enter (optionally typing a label first) to start a")
    print("countdown for the next DPI change. Type 'q' to quit and save.")
    print("=" * 60)

    idx = len(markers) + 1
    while True:
        raw = input(f"\n[{idx}] Label (or blank, or 'q' to quit): ").strip()
        if raw.lower() == "q":
            break
        label = raw if raw else f"change_{idx}"
        mark_time = countdown_and_mark(label)
        markers.append({
            "label": label,
            "epoch_time": mark_time,
            "readable_time": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(mark_time)
            ) + f".{int((mark_time % 1) * 1e6):06d}",
        })
        with open(out_path, "w") as f:
            json.dump(markers, f, indent=2)
        print(f"  Marked '{label}' at {markers[-1]['readable_time']} "
              f"(saved to {out_path})")
        idx += 1

    print(f"\nDone. {len(markers)} marker(s) saved to {out_path}.")
    print("Now stop your capture, save the .pcapng, and run:")
    print(f"  python analyze_capture.py your_capture.pcapng {out_path}")


if __name__ == "__main__":
    main()
