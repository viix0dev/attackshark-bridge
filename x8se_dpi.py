#!/usr/bin/env python3
"""
x8se_dpi.py - configure the Attack Shark X8SE without the vendor software.

Reads and writes DPI stages, the active stage, and polling rate over raw USB
HID feature reports. Also exposes a generic report dumper so the remaining
unknown reports can be mapped without going back to Wireshark every time.

The protocol is documented in x8se/PROTOCOL.md. Everything this script relies
on was verified against x8se/800to1600to800.pcapng and the mouse's own HID
report descriptor, except where noted below.

Requires: pip install hidapi

VERIFIED
    - VID 0x1D57 / PID 0x2120, config interface 2 ("X8SE Mouse", Beken)
    - Report 0x04, 52 bytes: profile layout + checksum sum(buf[3:50]) BE @50,51
    - DPI codec (PAW3311 step table) - decodes the captured stages exactly
    - The 0xa0 request/poll/fetch readback channel
    - Report 0x0a dump: GET[i+2] == SET04[i] for i in 3..49
    - Battery, from the asynchronous event message 03 02 40 <state> <percent>
      (device ID 0x02 identifies the X8SE; the X11 uses 0x55)

NOT VERIFIED (will say so at runtime)
    - Polling rate (report 0x06) - carried over from the X11 driver, never
      captured on an X8SE. 4000 Hz encoding is unknown entirely.
    - Whether the X8SE emits the X11's DPI-cycle event (0x10) when the DPI
      button is pressed. A capture of exactly that contained no such event.
      Use --watch to check.

Safety: every write is read-modify-write. The profile is read back from the
device, only the requested fields are edited, the checksum is recomputed, and
the rest (RGB and friends, offsets 25-49) is preserved untouched. Use
--dry-run to see the exact bytes first, and --restore-hex to roll back.

Usage:
    python x8se_dpi.py --list
    python x8se_dpi.py --get
    python x8se_dpi.py --battery
    python x8se_dpi.py --watch --timeout 20
    python x8se_dpi.py --set-stage 2 1600
    python x8se_dpi.py --set-active-stage 3
    python x8se_dpi.py --set-polling 1000
    python x8se_dpi.py --dump 0x0b 8
    python x8se_dpi.py --set-stage 2 1600 --dry-run
"""

import argparse
import sys
import time

try:
    import hid
except ImportError:
    print("Missing dependency. Install with:  pip install hidapi")
    sys.exit(1)


VID = 0x1D57
PID_DEFAULT = 0x2120                 # X8SE 2.4GHz dongle, from the device descriptor
KNOWN_PIDS = [0x2120, 0xFA60, 0xFA55]
INTERFACE_NUMBER = 2                 # config interface, wIndex=2 in every capture

REPORT_PROFILE = 0x04                # 52 bytes on the wire
REPORT_STATE = 0x0A                  # readback blob
REPORT_POLLING = 0x06                # 9 bytes on the wire
REPORT_CMD = 0xA0                    # 8 bytes, request/poll channel

PROFILE_LEN = 52
CMD_LEN = 8
POLLING_LEN = 9
STATE_LEN = 128                      # what the vendor software asks for
STATE_LEN_WINDOWS = 64               # HidD_GetFeature caps at the collection max

# Offsets into the report 0x04 profile buffer (see PROTOCOL.md section 3).
OFF_ANGLE_SNAP = 3
OFF_RIPPLE = 4
OFF_STAGE_MASK_A = 6
OFF_STAGE_MASK_B = 7
OFF_STAGES = 8                       # 8..13, six stages
OFF_HIGH_FLAGS = 16                  # 16..21, the yByte per stage
OFF_ACTIVE_STAGE = 24
OFF_CHECKSUM = 50                    # 50 = high, 51 = low

# The 0x0a dump carries the profile body at a +2 offset: dump[i+2] == profile[i].
STATE_TO_PROFILE_SHIFT = 2
OFF_STATE_POLLING = 3
OFF_STATE_POLLING_COMPLEMENT = 4
OFF_STATE_BATTERY = 63               # UNVERIFIED - read 94 during the capture

POLLING_RATES = {1000: 0x01, 500: 0x02, 250: 0x04, 125: 0x08}
POLLING_RATES_REVERSE = {v: k for k, v in POLLING_RATES.items()}

# Asynchronous 5-byte event messages the mouse pushes on interface 2's
# interrupt IN endpoint. See PROTOCOL.md section 5.
EVENT_OPCODE = 0x03
DEVICE_ID_X8SE = 0x02             # the X11 uses 0x55
EVENT_LEN = 5
EVENT_BATTERY = (0x40, 0x41)      # "Device Connection Message"
EVENT_DPI_CYCLE = 0x10            # seen on the X11; not yet on the X8SE

BATTERY_STATES = {
    0x01: "charging complete",
    0x02: "fully charged",
    0x03: "charging (or wired mode)",
}

MIN_DPI = 50
MAX_ROUNDTRIP_DPI = 20000   # highest value that encodes and decodes consistently
MAX_DPI = 20100             # 20100 has its own special-case encoding (0xEB, 1, 2x)

# PAW3311 DPI step table, from the X11 driver's src/tables/dpi-map.ts.
# The tail deliberately repeats earlier values; that is how the vendor table is.
DPI_3311 = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1b, 0x1c,
    0x1d, 0x1e, 0x1f, 0x20, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x29, 0x2a,
    0x2b, 0x2c, 0x2d, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x43, 0x44, 0x45, 0x46,
    0x47, 0x48, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x51, 0x52, 0x53, 0x54,
    0x55, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5e, 0x5f, 0x60, 0x61, 0x62,
    0x63, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8d,
    0x8e, 0x8f, 0x90, 0x91, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x9a, 0x9b,
    0x9c, 0x9d, 0x9e, 0x9f, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa7, 0xa8, 0xa9,
    0xaa, 0xab, 0xac, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc2, 0xc3, 0xc4, 0xc5,
    0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3,
    0xd4, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdd, 0xde, 0xdf, 0xe0, 0xe1,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xea, 0xeb, 0x76, 0x77, 0x79, 0x7a,
    0x7b, 0x7c, 0x7d, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x86, 0x87, 0x88,
    0x89, 0x8a, 0x8b, 0x8d,
]

# The X8SE's config MCU drops back-to-back HID transactions; a short pause
# between them was needed to make reads reliable.
IO_DELAY = 0.15


# ---------------------------------------------------------------------------
# DPI codec (PROTOCOL.md section 6)
# ---------------------------------------------------------------------------

def dpi_to_bytes(dpi):
    """Encode a DPI value into (xByte, yByte, double) for the profile buffer.

    Capped at MAX_DPI. The X11 reference codec has a branch for targets above
    10000 that computes `combined = 199 + (target - 10100) // 100` and stores
    `yByte = combined >> 8`. Since `combined` never exceeds 228 for any input in
    range, that yByte is always 0, which is indistinguishable from single-byte
    mode - so the value decodes back as a much lower DPI (26000 came back as
    19400). Rather than write a byte that means something else to the mouse, we
    refuse to go above what round-trips correctly. If you capture the vendor
    software setting >20000 DPI on an X8SE, that branch can be fixed properly.
    """
    dpi = max(MIN_DPI, min(int(dpi), MAX_DPI))
    if dpi == 20100:
        return 0xEB, 1, True
    if dpi > MAX_ROUNDTRIP_DPI:
        dpi = MAX_ROUNDTRIP_DPI

    double = False
    target = dpi
    if dpi > 10000:
        # Above 10000 the sensor stores half the value and doubles it, so the
        # effective step size becomes 100 rather than 50.
        target = round(dpi / 2)
        double = True

    if target > 5000 and target % 100 == 0:
        return DPI_3311[target // 100 - 1], 1, double
    return DPI_3311[(target - 50) // 50], 0, double


def bytes_to_dpi(x_byte, y_byte, double):
    """Decode (xByte, yByte, double) back into a DPI value."""
    if x_byte == 0 and y_byte == 0:
        return 0

    if y_byte == 0:
        i = DPI_3311.index(x_byte) if x_byte in DPI_3311 else -1
        dpi = i * 50 + 50 if i != -1 else 50
    elif y_byte == 1:
        i = DPI_3311.index(x_byte) if x_byte in DPI_3311 else -1
        dpi = i * 100 + 100 if i != -1 else 100
    else:
        dpi = 10100 + (((y_byte << 8) | x_byte) - 199) * 100

    if double:
        if x_byte == 0xEB:
            return 20100
        dpi *= 2
    return min(dpi, 26000)


def nearest_supported_dpi(dpi):
    """The sensor only has discrete steps. Report what a request rounds to, so
    the caller can be told rather than silently getting something else."""
    x, y, double = dpi_to_bytes(dpi)
    return bytes_to_dpi(x, y, double)


# ---------------------------------------------------------------------------
# Device discovery
# ---------------------------------------------------------------------------

def candidate_paths(pid_arg):
    """Every HID path worth trying. Windows splits one USB interface into
    several paths (one per top-level collection) and only one of them actually
    carries our feature reports, so we cannot just take the first match."""
    pids = [pid_arg] if pid_arg else KNOWN_PIDS
    out = []
    for pid in pids:
        matches = [d for d in hid.enumerate(VID, pid)
                   if d.get("interface_number") == INTERFACE_NUMBER]
        if not matches:
            matches = list(hid.enumerate(VID, pid))
        for info in matches:
            out.append((pid, info["path"]))
    return out


def open_working_device(pid_arg, path_arg):
    """Open a handle that actually answers on the command channel."""
    if path_arg:
        dev = hid.device()
        dev.open_path(path_arg if isinstance(path_arg, bytes) else path_arg.encode())
        return dev

    candidates = candidate_paths(pid_arg)
    if not candidates:
        tried = ", ".join(f"{p:#06x}" for p in ([pid_arg] if pid_arg else KNOWN_PIDS))
        print(f"No HID device found for VID={VID:#06x}, tried PID(s): {tried}.")
        print("Is the dongle plugged in / the mouse switched on? Try --list.")
        sys.exit(1)

    last_err = None
    for pid, path in candidates:
        dev = hid.device()
        try:
            dev.open_path(path)
            time.sleep(IO_DELAY)
            dev.get_feature_report(REPORT_CMD, CMD_LEN)
        except OSError as e:
            last_err = e
            try:
                dev.close()
            except Exception:
                pass
            continue
        return dev

    print(f"None of the candidate collections answered GET_FEATURE on the "
          f"command channel (report {REPORT_CMD:#04x}).")
    print(f"Last error: {last_err}")
    print("Run --list, then pass the right one with --path '<path>'.")
    print("Also check the vendor software or Wireshark isn't holding the device.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Transport (PROTOCOL.md section 4)
# ---------------------------------------------------------------------------

def request_report(dev, report_id, length, profile=0x01, timeout=1.0):
    """Ask the mouse to stage `report_id` for reading, then wait until it says
    it's ready. This is the 0xa0 channel the vendor software uses."""
    cmd = bytearray(CMD_LEN)
    cmd[0] = REPORT_CMD
    cmd[1] = report_id
    cmd[2] = length & 0xFF
    cmd[3] = 0x00
    cmd[4] = profile

    time.sleep(IO_DELAY)
    dev.send_feature_report(bytes(cmd))

    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(IO_DELAY)
        status = bytes(dev.get_feature_report(REPORT_CMD, CMD_LEN))
        if len(status) > 1 and status[1] == 0x01:
            return True
    return False


def fetch_report(dev, report_id, length, profile=0x01):
    """Full request/poll/fetch cycle. Returns the raw bytes."""
    if not request_report(dev, report_id, length, profile):
        print(f"Warning: the mouse never reported report {report_id:#04x} as "
              f"ready; reading anyway.", file=sys.stderr)
    time.sleep(IO_DELAY)
    return bytes(dev.get_feature_report(report_id, length))


def read_state(dev):
    """Read the 0x0a state dump. Windows' HidD_GetFeature caps the buffer at the
    collection's largest feature report (64), so fall back to that."""
    for length in (STATE_LEN, STATE_LEN_WINDOWS):
        try:
            data = fetch_report(dev, REPORT_STATE, length)
            if data:
                return data
        except OSError:
            continue
    raise OSError(f"Could not read the state report ({REPORT_STATE:#04x}) at "
                  f"either {STATE_LEN} or {STATE_LEN_WINDOWS} bytes.")


def parse_event(data):
    """Decode a 5-byte asynchronous event message, or None if it isn't one."""
    if len(data) < EVENT_LEN or data[0] != EVENT_OPCODE:
        return None
    device_id, code, p1, p2 = data[1], data[2], data[3], data[4]
    event = {"device_id": device_id, "code": code, "param1": p1, "param2": p2,
             "raw": bytes(data[:EVENT_LEN])}

    if code in EVENT_BATTERY:
        event["kind"] = "battery"
        event["percent"] = p2
        event["state"] = BATTERY_STATES.get(p1, f"unknown (0x{p1:02x})")
    elif code == EVENT_DPI_CYCLE:
        event["kind"] = "dpi_cycle"
        event["stage"] = p1
    else:
        event["kind"] = "unknown"
    return event


def read_events(dev, timeout=6.0, want=None):
    """Collect event messages arriving on the interrupt IN endpoint.

    These are unsolicited, so this just listens. `want` is an optional set of
    event codes to stop on; otherwise it listens for the whole timeout.
    """
    events = []
    deadline = time.time() + timeout
    dev.set_nonblocking(0)
    while time.time() < deadline:
        remaining = max(0, deadline - time.time())
        try:
            data = dev.read(EVENT_LEN * 4, timeout_ms=int(remaining * 1000))
        except (OSError, ValueError):
            break
        if not data:
            continue
        event = parse_event(bytes(data))
        if event:
            events.append(event)
            if want and event["code"] in want:
                break
    return events


def profile_from_state(state):
    """Rebuild the 52-byte report 0x04 buffer out of the 0x0a dump. Verified:
    dump[i+2] == profile[i] for i in 3..49."""
    if len(state) < OFF_CHECKSUM + STATE_TO_PROFILE_SHIFT:
        raise ValueError(f"State dump too short ({len(state)} bytes) to rebuild "
                         f"the profile.")
    buf = bytearray(PROFILE_LEN)
    buf[0], buf[1], buf[2] = 0x04, 0x38, 0x01
    body_start = OFF_ANGLE_SNAP + STATE_TO_PROFILE_SHIFT
    body_end = OFF_CHECKSUM + STATE_TO_PROFILE_SHIFT
    buf[OFF_ANGLE_SNAP:OFF_CHECKSUM] = state[body_start:body_end]
    apply_checksum(buf)
    return buf


def read_profile(dev):
    """Prefer a direct read of report 0x04; fall back to rebuilding it from the
    state dump if the device won't serve 0x04 over GET_FEATURE."""
    try:
        time.sleep(IO_DELAY)
        raw = bytes(dev.get_feature_report(REPORT_PROFILE, PROFILE_LEN))
        if len(raw) == PROFILE_LEN and raw[0] == REPORT_PROFILE and raw[1] == 0x38:
            return bytearray(raw)
    except OSError:
        pass
    return profile_from_state(read_state(dev))


# ---------------------------------------------------------------------------
# Profile encode/decode
# ---------------------------------------------------------------------------

def compute_checksum(buf):
    return sum(buf[OFF_ANGLE_SNAP:OFF_CHECKSUM]) & 0xFFFF


def apply_checksum(buf):
    s = compute_checksum(buf)
    buf[OFF_CHECKSUM] = (s >> 8) & 0xFF
    buf[OFF_CHECKSUM + 1] = s & 0xFF
    return s


def decode_stages(buf):
    """Return [(stage_number, dpi, x_byte, y_byte, double), ...]."""
    mask = buf[OFF_STAGE_MASK_A]
    out = []
    for i in range(6):
        x = buf[OFF_STAGES + i]
        y = buf[OFF_HIGH_FLAGS + i]
        double = bool(mask & (1 << i))
        out.append((i + 1, bytes_to_dpi(x, y, double), x, y, double))
    return out


def set_stage_dpi(buf, stage, dpi):
    """Write one stage's DPI, keeping the mask/high-flag bookkeeping coherent."""
    x, y, double = dpi_to_bytes(dpi)
    idx = stage - 1
    buf[OFF_STAGES + idx] = x
    buf[OFF_HIGH_FLAGS + idx] = y

    mask = buf[OFF_STAGE_MASK_A]
    if double:
        mask |= (1 << idx)
    else:
        mask &= ~(1 << idx) & 0xFF
    buf[OFF_STAGE_MASK_A] = mask
    buf[OFF_STAGE_MASK_B] = mask
    return bytes_to_dpi(x, y, double)


def print_profile(buf, state=None):
    print(f"Raw profile ({len(buf)} bytes): {bytes(buf).hex()}")
    print()
    active = buf[OFF_ACTIVE_STAGE]
    for stage, dpi, x, y, double in decode_stages(buf):
        mark = "  <== active" if stage == active else ""
        extra = " (2x)" if double else ""
        print(f"  Stage {stage}: {dpi:>6} DPI   "
              f"[x=0x{x:02x} y={y}{extra}]{mark}")
    print()
    print(f"  Active stage:    {active}")
    print(f"  Angle snap:      {buf[OFF_ANGLE_SNAP]}")
    print(f"  Ripple control:  {buf[OFF_RIPPLE]}")
    print(f"  Stage mask:      0x{buf[OFF_STAGE_MASK_A]:02x} / "
          f"0x{buf[OFF_STAGE_MASK_B]:02x}")

    stored = (buf[OFF_CHECKSUM] << 8) | buf[OFF_CHECKSUM + 1]
    computed = compute_checksum(buf)
    status = "OK" if stored == computed else "MISMATCH"
    print(f"  Checksum:        stored=0x{stored:04x} computed=0x{computed:04x} "
          f"{status}")

    if state is not None and len(state) > OFF_STATE_POLLING_COMPLEMENT:
        rate_byte = state[OFF_STATE_POLLING]
        rate = POLLING_RATES_REVERSE.get(rate_byte)
        comp = state[OFF_STATE_POLLING_COMPLEMENT]
        comp_ok = (comp == (0xFF - rate_byte))
        shown = f"{rate} Hz" if rate else f"unknown (0x{rate_byte:02x})"
        print(f"  Polling rate:    {shown}"
              f"{'' if comp_ok else '  [complement byte does not match!]'}")
    if state is not None and len(state) > OFF_STATE_BATTERY:
        print(f"  Battery:         {state[OFF_STATE_BATTERY]}%  "
              f"(UNVERIFIED - see --battery)")


def write_profile(dev, buf, dry_run):
    apply_checksum(buf)
    print(f"About to send: {bytes(buf).hex()}")
    if dry_run:
        print("(--dry-run: nothing sent.)")
        return
    time.sleep(IO_DELAY)
    dev.send_feature_report(bytes(buf))
    print("Sent.")


def write_polling_rate(dev, hz, dry_run):
    if hz not in POLLING_RATES:
        print(f"Polling rate {hz} Hz is not in the known table. "
              f"Known: {sorted(POLLING_RATES)}.")
        if hz == 4000:
            print("4000 Hz is advertised by the X8SE but its encoding has not "
                  "been captured yet - see PROTOCOL.md section 5.")
        sys.exit(1)

    buf = bytearray(POLLING_LEN)
    buf[0] = REPORT_POLLING
    buf[1] = 0x09
    buf[2] = 0x01
    buf[3] = POLLING_RATES[hz]
    buf[4] = 0xFF - buf[3]

    print("NOTE: the polling-rate report is inherited from the X11 driver and "
          "has not been captured on an X8SE yet. Verify it took effect.")
    print(f"About to send: {bytes(buf).hex()}")
    if dry_run:
        print("(--dry-run: nothing sent.)")
        return
    time.sleep(IO_DELAY)
    dev.send_feature_report(bytes(buf))
    print("Sent.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_list():
    matches = hid.enumerate(VID, 0)
    if not matches:
        print(f"No devices for VID {VID:#06x}. Is the dongle plugged in?")
        print("(If your X8SE enumerates under a different VID, pass --pid or "
              "check --list output of a tool like USBDeview.)")
        return
    for d in matches:
        print(f"  PID={d['product_id']:#06x} iface={d.get('interface_number')} "
              f"usage_page={d.get('usage_page')} usage={d.get('usage')} "
              f"product={d.get('product_string')!r} path={d['path']}")


def cmd_battery(dev, timeout):
    """Battery comes from the unsolicited event message, not a polled field."""
    print(f"Listening up to {timeout:.0f}s for a battery event "
          f"(the mouse sends these on its own)...")
    events = read_events(dev, timeout=timeout, want=set(EVENT_BATTERY))

    battery = [e for e in events if e["kind"] == "battery"]
    for event in events:
        if event["kind"] != "battery":
            print(f"  (also saw: {event['raw'].hex()} - "
                  f"{event['kind']} event, code 0x{event['code']:02x})")

    if battery:
        last = battery[-1]
        print()
        print(f"  Battery: {last['percent']}%   ({last['state']})")
        print(f"  Raw:     {last['raw'].hex()}")
        if last["device_id"] != DEVICE_ID_X8SE:
            print(f"  Note: device ID 0x{last['device_id']:02x}, expected "
                  f"0x{DEVICE_ID_X8SE:02x} for an X8SE.")
        if last["percent"] == 100 and len(battery) == 1:
            print()
            print("  Heads up: the first report after connecting can read 100% "
                  "regardless of the true level. Run again for a second "
                  "reading before trusting it.")
        return

    print()
    print("No battery event arrived. That endpoint only emits periodically, so")
    print("try again, move the mouse first, or raise --timeout.")
    print()
    try:
        state = read_state(dev)
    except OSError as e:
        print(f"(Also couldn't read the state dump: {e})")
        return
    if len(state) > OFF_STATE_BATTERY:
        print(f"For reference, byte {OFF_STATE_BATTERY} of the 0x0a dump is "
              f"{state[OFF_STATE_BATTERY]}, but that byte read 94 while the "
              f"event message said 100, so it is probably NOT the battery.")


def cmd_watch(dev, timeout):
    """Print every event message as it arrives. Useful for mapping the events
    that are still unidentified - press buttons and see what shows up."""
    print(f"Watching the interrupt endpoint for {timeout:.0f}s. Press the DPI "
          f"button, toggle settings, let the battery report fire...")
    print("(Ctrl+C to stop early.)")
    print()
    start = time.time()
    seen = 0
    try:
        while time.time() - start < timeout:
            for event in read_events(dev, timeout=1.0):
                seen += 1
                rel = time.time() - start
                detail = ""
                if event["kind"] == "battery":
                    detail = f"battery {event['percent']}% ({event['state']})"
                elif event["kind"] == "dpi_cycle":
                    detail = f"DPI cycle -> stage {event['stage']}"
                else:
                    detail = (f"UNKNOWN event code 0x{event['code']:02x} "
                              f"params 0x{event['param1']:02x} "
                              f"0x{event['param2']:02x}")
                print(f"  [{rel:6.2f}s] {event['raw'].hex()}  {detail}")
    except KeyboardInterrupt:
        print("\n  (stopped)")
    print()
    print(f"{seen} event(s) seen.")
    if seen == 0:
        print("Nothing arrived. If pressing the DPI button produced no event, "
              "that is itself a result worth recording - see PROTOCOL.md "
              "section 8.")


def cmd_dump(dev, report_id, length):
    data = fetch_report(dev, report_id, length)
    print(f"Report {report_id:#04x} ({len(data)} bytes):")
    print(f"  {data.hex()}")
    print()
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        print(f"  [{off:3d}] {hexpart}")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=lambda x: int(x, 0), default=None,
                    help=f"USB PID override. Default tries: "
                         f"{', '.join(f'{p:#06x}' for p in KNOWN_PIDS)}")
    ap.add_argument("--path", help="Exact hidapi device path (skips auto-detect)")
    ap.add_argument("--list", action="store_true",
                    help="List matching HID interfaces and exit")
    ap.add_argument("--get", action="store_true",
                    help="Read and pretty-print the current configuration")
    ap.add_argument("--battery", action="store_true",
                    help="Read battery level from the mouse's event message")
    ap.add_argument("--watch", action="store_true",
                    help="Print asynchronous event messages as they arrive. "
                         "Use it to map events that are still unidentified - "
                         "press the DPI button and see whether anything fires.")
    ap.add_argument("--timeout", type=float, default=6.0, metavar="SECONDS",
                    help="How long --battery / --watch listen (default 6)")
    ap.add_argument("--dump", nargs="+", metavar="REPORT_ID [LEN]",
                    help="Read any feature report via the 0xa0 channel, e.g. "
                         "--dump 0x0b 8. Use this to map the reports that are "
                         "still unknown (0x05, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0x10).")
    ap.add_argument("--set-stage", nargs=2, metavar=("STAGE", "DPI"),
                    help="Set one stage's DPI, e.g. --set-stage 2 1600")
    ap.add_argument("--set-active-stage", type=int, metavar="STAGE",
                    help="Switch the active DPI stage (1-6), leaving values alone")
    ap.add_argument("--set-polling", type=int, metavar="HZ",
                    help="Set polling rate: 125, 250, 500 or 1000 (UNVERIFIED)")
    ap.add_argument("--restore-hex", metavar="HEXSTRING",
                    help="Rollback: write back an exact 52-byte profile as hex, "
                         "byte for byte, with no reinterpretation")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print the bytes that would be sent, but send nothing")
    args = ap.parse_args()

    if args.list:
        cmd_list()
        return

    wants_action = (args.get or args.battery or args.watch or args.dump
                    or args.set_stage
                    or args.set_active_stage is not None
                    or args.set_polling is not None or args.restore_hex)
    if not wants_action:
        ap.print_help()
        return

    dev = open_working_device(args.pid, args.path)
    try:
        if args.restore_hex:
            hex_str = args.restore_hex.replace(" ", "").replace(":", "")
            try:
                buf = bytearray.fromhex(hex_str)
            except ValueError:
                print("That doesn't look like valid hex.")
                sys.exit(1)
            if len(buf) != PROFILE_LEN:
                print(f"Expected {PROFILE_LEN} bytes, got {len(buf)}. Refusing.")
                sys.exit(1)
            if buf[0] != REPORT_PROFILE:
                print(f"First byte is {buf[0]:#04x}, expected "
                      f"{REPORT_PROFILE:#04x}. Refusing - this isn't a profile.")
                sys.exit(1)
            stored = (buf[OFF_CHECKSUM] << 8) | buf[OFF_CHECKSUM + 1]
            computed = compute_checksum(buf)
            if stored != computed:
                print(f"WARNING: the checksum in this hex (0x{stored:04x}) "
                      f"doesn't match its contents (0x{computed:04x}). Sending "
                      f"exactly as given anyway, since --restore-hex never "
                      f"rewrites bytes - but double-check it's what you meant.")
            print("Restoring profile byte-for-byte:")
            print(f"  {bytes(buf).hex()}")
            if args.dry_run:
                print("(--dry-run: nothing sent.)")
            else:
                time.sleep(IO_DELAY)
                dev.send_feature_report(bytes(buf))
                print("Sent.")

        if args.get:
            state = None
            try:
                state = read_state(dev)
            except OSError as e:
                print(f"(Couldn't read the state dump: {e})", file=sys.stderr)
            buf = profile_from_state(state) if state else read_profile(dev)
            print_profile(buf, state)

        if args.battery:
            cmd_battery(dev, args.timeout)

        if args.watch:
            cmd_watch(dev, args.timeout)

        if args.dump:
            rid = int(args.dump[0], 0)
            length = int(args.dump[1], 0) if len(args.dump) > 1 else 8
            cmd_dump(dev, rid, length)

        if args.set_stage:
            stage, dpi = int(args.set_stage[0]), int(args.set_stage[1])
            if not 1 <= stage <= 6:
                print("Stage must be 1-6.")
                sys.exit(1)
            if dpi > MAX_DPI:
                print(f"Note: {dpi} DPI is above the highest value this codec "
                      f"encodes reliably ({MAX_DPI}); capping. See the comment "
                      f"on dpi_to_bytes().")
            rounded = nearest_supported_dpi(dpi)
            if rounded != dpi:
                print(f"Note: {dpi} DPI isn't a sensor step; using {rounded}.")
            buf = read_profile(dev)
            print("Before:")
            print_profile(buf)
            print()
            set_stage_dpi(buf, stage, dpi)
            write_profile(dev, buf, args.dry_run)

        if args.set_active_stage is not None:
            stage = args.set_active_stage
            if not 1 <= stage <= 6:
                print("Stage must be 1-6.")
                sys.exit(1)
            buf = read_profile(dev)
            print("Before:")
            print_profile(buf)
            print()
            buf[OFF_ACTIVE_STAGE] = stage
            write_profile(dev, buf, args.dry_run)

        if args.set_polling is not None:
            write_polling_rate(dev, args.set_polling, args.dry_run)
    finally:
        dev.close()


if __name__ == "__main__":
    main()
