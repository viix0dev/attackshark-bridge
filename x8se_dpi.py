#!/usr/bin/env python3
"""
x8se_dpi.py — set the Attack Shark X8 SE's DPI stages via raw USB HID
Feature Report 0x04, using the protocol reverse-engineered from your
Wireshark capture + cross-referenced against the open-source X11 driver.

Requires: pip install hidapi

IMPORTANT SAFETY NOTE
----------------------
This tool uses READ-MODIFY-WRITE: it reads the mouse's *current* profile
first, only edits the DPI-related fields, recomputes the checksum, and
writes it back. This avoids stomping on lighting/other settings whose
byte offsets we haven't fully mapped yet (offsets 25-49 in the buffer).

Known-verified fields (cross-checked against x11 driver + your capture):
    offset 0-2   header (0x04 0x38 0x01)          - fixed
    offset 3     angle snap                       - 0/1
    offset 4     ripple control                   - 0/1
    offset 5     fixed constant (0x3f)            - fixed
    offset 6-7   stage mask (dup, 1 if any stage >12000 dpi)
    offset 8-13  6x DPI stage bytes, via DPI_STEP_MAP lookup
    offset 16-21 "high" flags per stage (10100-12000 or 20100-22000 range)
    offset 24    active stage index (1-6)
    offset 50-51 checksum: 16-bit big-endian sum of bytes[3:50]

DPI_STEP_MAP is only verified for 800/1600/2400 so far (matched exactly
against the public X11 driver's table + your capture). Other values will
raise an error until you verify them — see --learn below.

Usage:
    python x8se_dpi.py --list
    python x8se_dpi.py --get
    python x8se_dpi.py --set-stage 2 1600
    python x8se_dpi.py --set-active-stage 2
    python x8se_dpi.py --set-stage 2 1600 --dry-run
"""

import argparse
import sys

try:
    import hid
except ImportError:
    print("Missing dependency. Install with:  pip install hidapi")
    sys.exit(1)


VID = 0x1D57
PID_DEFAULT = 0x2120  # X8 SE via 2.4GHz wireless dongle, from your original capture
KNOWN_PIDS = [0x2120, 0xFA60, 0xFA55]  # wireless dongle, X11-shared wired PIDs
INTERFACE_NUMBER = 2  # "Interface 2: Generic HID" — the config interface
REPORT_ID_PROFILE = 0x04
PROFILE_LEN = 52  # matches your capture (wired-mode-length buffer)

# Verified against the public X11 driver's DPI_STEP_MAP + your capture.
# Extend this ONLY after verifying with the marker/analyze toolkit.
DPI_STEP_MAP = {
    800: 0x12,
    1600: 0x25,
    2400: 0x38,
}
DPI_STEP_MAP_REVERSE = {v: k for k, v in DPI_STEP_MAP.items()}


def find_device_path(pid):
    matches = [d for d in hid.enumerate(VID, pid)
               if d.get("interface_number") == INTERFACE_NUMBER]
    if not matches:
        # fall back: some platforms don't report interface_number reliably
        matches = [d for d in hid.enumerate(VID, pid)]
    return matches


def open_device(pid, path=None):
    dev = hid.device()
    if path:
        dev.open_path(path)
        return dev

    pids_to_try = [pid] if pid else KNOWN_PIDS
    for candidate_pid in pids_to_try:
        matches = find_device_path(candidate_pid)
        if matches:
            print(f"Found device at PID={candidate_pid:#06x}, opening "
                  f"{matches[0]['path']}")
            dev.open_path(matches[0]["path"])
            return dev

    tried = ", ".join(f"{p:#06x}" for p in pids_to_try)
    print(f"No HID device found for VID={VID:#06x}, tried PID(s): {tried}. "
          f"Try --list to see what's actually connected, then --pid to "
          f"target it explicitly.")
    sys.exit(1)


def encode_dpi(dpi):
    if dpi not in DPI_STEP_MAP:
        raise ValueError(
            f"DPI {dpi} is not in the verified table yet. "
            f"Known-good values: {sorted(DPI_STEP_MAP)}. "
            f"Capture a real change to this value first (see --learn)."
        )
    return DPI_STEP_MAP[dpi]


def decode_dpi(byte_val):
    return DPI_STEP_MAP_REVERSE.get(byte_val, f"unknown(0x{byte_val:02x})")


def checksum(buf):
    s = sum(buf[3:50]) & 0xFFFF
    return (s >> 8) & 0xFF, s & 0xFF


def read_profile(dev):
    # hidapi's get_feature_report needs the report id as the first byte
    # of the buffer you pass in, and returns it prefixed in the result too.
    raw = dev.get_feature_report(REPORT_ID_PROFILE, PROFILE_LEN)
    return bytearray(raw)


def print_profile(buf):
    print(f"Raw ({len(buf)} bytes): {bytes(buf).hex()}")
    print(f"  Angle snap:      {buf[3]}")
    print(f"  Ripple control:  {buf[4]}")
    print(f"  Stage mask:      {buf[6]:#04x} / {buf[7]:#04x}")
    print(f"  Stages 1-6:      " + ", ".join(
        f"#{i+1}=0x{b:02x}({decode_dpi(b)})" for i, b in enumerate(buf[8:14])
    ))
    print(f"  High flags:      {buf[16:22].hex()}")
    print(f"  Active stage:    {buf[24]}")
    hi, lo = checksum(buf)
    ok = (hi, lo) == (buf[50], buf[51])
    print(f"  Checksum stored: {buf[50]:02x}{buf[51]:02x}  "
          f"computed: {hi:02x}{lo:02x}  {'OK' if ok else 'MISMATCH!'}")


def write_profile(dev, buf, dry_run):
    hi, lo = checksum(buf)
    buf[50], buf[51] = hi, lo
    print(f"About to send: {bytes(buf).hex()}")
    if dry_run:
        print("(--dry-run: not actually sending. Compare this hex against "
              "a real Wireshark capture of the same change before trusting it.)")
        return
    dev.send_feature_report(bytes(buf))
    print("Sent.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=lambda x: int(x, 0), default=None,
                     help=f"USB PID override. If omitted, tries known PIDs "
                          f"in order: {', '.join(f'{p:#06x}' for p in KNOWN_PIDS)}")
    ap.add_argument("--path", help="Exact hidapi device path (bypasses auto-detect)")
    ap.add_argument("--list", action="store_true", help="List matching HID interfaces and exit")
    ap.add_argument("--get", action="store_true", help="Read and print the current profile")
    ap.add_argument("--set-stage", nargs=2, metavar=("STAGE", "DPI"),
                     help="Set one stage's DPI, e.g. --set-stage 2 1600")
    ap.add_argument("--set-active-stage", type=int, metavar="STAGE",
                     help="Change which stage is active (1-6), leaving DPI values untouched")
    ap.add_argument("--restore-hex", metavar="HEXSTRING",
                     help="Rollback/safety escape hatch: write back an exact known-good "
                          "52-byte profile (as hex, e.g. saved from --get output or a "
                          "known-good capture), unchanged. No read-modify-write, no "
                          "reinterpretation of fields — sent byte-for-byte as given.")
    ap.add_argument("--dry-run", action="store_true",
                     help="Print the bytes that would be sent, but don't send them")
    args = ap.parse_args()

    if args.list:
        matches = hid.enumerate(VID, 0)
        if not matches:
            print(f"No devices found for VID {VID:#06x}. Is the dongle/mouse plugged in?")
            return
        for d in matches:
            print(f"  PID={d['product_id']:#06x} iface={d.get('interface_number')} "
                  f"usage_page={d.get('usage_page')} usage={d.get('usage')} "
                  f"path={d['path']}")
        return

    if not (args.get or args.set_stage or args.set_active_stage is not None
            or args.restore_hex):
        ap.print_help()
        return

    dev = open_device(args.pid, args.path)
    try:
        if args.restore_hex:
            hex_str = args.restore_hex.replace(" ", "").replace(":", "")
            try:
                buf = bytearray.fromhex(hex_str)
            except ValueError:
                print("That doesn't look like valid hex."); sys.exit(1)
            if len(buf) != PROFILE_LEN:
                print(f"Expected {PROFILE_LEN} bytes, got {len(buf)}. "
                      f"Refusing to send a buffer of the wrong length.")
                sys.exit(1)
            if buf[0] != REPORT_ID_PROFILE:
                print(f"First byte is {buf[0]:#04x}, expected report ID "
                      f"{REPORT_ID_PROFILE:#04x}. Refusing to send — this "
                      f"doesn't look like a report 0x04 profile buffer.")
                sys.exit(1)
            hi, lo = checksum(buf)
            if (hi, lo) != (buf[50], buf[51]):
                print(f"WARNING: checksum in the given hex ({buf[50]:02x}{buf[51]:02x}) "
                      f"doesn't match what this buffer's contents compute to "
                      f"({hi:02x}{lo:02x}). Sending it exactly as given anyway, since "
                      f"--restore-hex never reinterprets bytes — but double-check this "
                      f"is really the hex you meant to restore.")
            print("Restoring exact known-good profile (byte-for-byte, unmodified):")
            print(f"  {bytes(buf).hex()}")
            if args.dry_run:
                print("(--dry-run: not actually sending.)")
            else:
                dev.send_feature_report(bytes(buf))
                print("Sent.")

        if args.get:
            buf = read_profile(dev)
            print_profile(buf)

        if args.set_stage:
            stage_num, dpi = int(args.set_stage[0]), int(args.set_stage[1])
            if not (1 <= stage_num <= 6):
                print("Stage must be 1-6"); sys.exit(1)
            buf = read_profile(dev)
            print("Before:")
            print_profile(buf)
            buf[8 + (stage_num - 1)] = encode_dpi(dpi)
            all_dpis = [decode_dpi(b) for b in buf[8:14]]
            high = any(isinstance(v, int) and v > 12000 for v in
                       [dpi if i == stage_num - 1 else buf[8 + i] for i in range(6)])
            buf[6] = 1 if high else 0
            buf[7] = buf[6]
            buf[16 + (stage_num - 1)] = (
                0x01 if (10100 <= dpi <= 12000 or 20100 <= dpi <= 22000) else 0x00
            )
            write_profile(dev, buf, args.dry_run)

        if args.set_active_stage is not None:
            n = args.set_active_stage
            if not (1 <= n <= 6):
                print("Stage must be 1-6"); sys.exit(1)
            buf = read_profile(dev)
            print("Before:")
            print_profile(buf)
            buf[24] = n
            write_profile(dev, buf, args.dry_run)
    finally:
        dev.close()


if __name__ == "__main__":
    main()