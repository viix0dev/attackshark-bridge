#!/usr/bin/env python3
"""
Offline tests for the X8SE protocol implementation in x8se_dpi.py.

These run against bytes captured from a real X8SE - the profile writes in
x8se/800to1600to800.pcapng and the battery event in X8SE_20260905_131001.pcap -
so they need no mouse, no dongle and no hidapi, just Python. The headline test is
`test_regenerates_captured_packet`: it takes the profile the mouse actually had
and regenerates, byte for byte, the packet the vendor software sent to switch
DPI. If that passes, the layout and checksum are right.

Run:
    python x8se/test_protocol.py
"""

import os
import sys
import types

# x8se_dpi imports hidapi at module level for talking to the device; stub it so
# these pure-logic tests run anywhere.
sys.modules.setdefault("hid", types.ModuleType("hid"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import x8se_dpi as X  # noqa: E402


# Captured from x8se/800to1600to800.pcapng.
# Two SET_REPORT 0x04 packets: the vendor software switching 800 -> 1600 -> 800.
SET_1600 = bytearray.fromhex(
    "04380100013f00000912252a2f38010100000000000000000"
    "3ff000000ff000000ffffff0000ffffff00ffff4000ffffff020e4b")
SET_800 = bytearray.fromhex(
    "04380100013f00000912252a2f38010100000000000000000"
    "2ff000000ff000000ffffff0000ffffff00ffff4000ffffff020e4a")
# The GET_REPORT 0x0a state dump read just before those writes.
STATE = bytes.fromhex(
    "0a800101fe00013f00000912252a2f380101000000000000000002ff000000ff0000"
    "00ffffff0000ffffff00ffff4000ffffff02004a0e0003580000ff02025e01020000"
    "030000110a160d00000500000600003c000001000001000001000001000001000001"
    "0000010000010000010000 0a0000090000a60000000000000000".replace(" ", ""))

FAILURES = []


def check(name, got, want):
    if got == want:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}\n         got  {got!r}\n         want {want!r}")


def test_checksum():
    print("checksum matches both captured packets")
    check("1600 packet", X.compute_checksum(SET_1600), 0x0E4B)
    check("800 packet", X.compute_checksum(SET_800), 0x0E4A)


def test_stage_decode():
    print("DPI stages decode to the values the vendor UI showed")
    check("stages", [d for _, d, _, _, _ in X.decode_stages(SET_1600)],
          [400, 800, 1600, 1800, 2000, 2400])
    check("active stage of the 1600 packet", SET_1600[X.OFF_ACTIVE_STAGE], 3)
    check("active stage of the 800 packet", SET_800[X.OFF_ACTIVE_STAGE], 2)


def test_dpi_roundtrip():
    print("DPI codec round-trips every representable step")
    for dpi in (50, 100, 400, 800, 1600, 2400, 3200, 6400, 10000,
                12000, 16000, 20000, 20100):
        x, y, double = X.dpi_to_bytes(dpi)
        check(f"{dpi} DPI", X.bytes_to_dpi(x, y, double), dpi)


def test_dpi_encoder_invariants():
    print("encoder never emits an ambiguous yByte or an out-of-range result")
    ok = True
    for dpi in range(X.MIN_DPI, X.MAX_DPI + 1, 50):
        x, y, double = X.dpi_to_bytes(dpi)
        if y not in (0, 1) or X.bytes_to_dpi(x, y, double) > X.MAX_DPI:
            ok = False
    check("all encodings well-formed", ok, True)

    print("requests above the cap clamp rather than wrapping to a low DPI")
    for dpi in (22000, 26000, 99999):
        check(f"{dpi} clamps into range",
              20000 <= X.nearest_supported_dpi(dpi) <= X.MAX_DPI, True)

    print("a higher request never yields a lower DPI")
    prev, mono = 0, True
    for dpi in range(X.MIN_DPI, 20001, 50):
        value = X.nearest_supported_dpi(dpi)
        mono = mono and value >= prev
        prev = value
    check("monotonic", mono, True)


def test_state_dump_rebuild():
    print("the 0x0a state dump rebuilds the 0x04 profile exactly")
    check("full 128-byte dump", bytes(X.profile_from_state(STATE)),
          bytes(SET_800))
    # Windows' HidD_GetFeature caps the buffer at the collection's largest
    # feature report (64), so the short read has to work too.
    check("truncated 64-byte dump", bytes(X.profile_from_state(STATE[:64])),
          bytes(SET_800))


def test_polling_rate_in_dump():
    print("polling rate reads out of the state dump")
    rate_byte = STATE[X.OFF_STATE_POLLING]
    check("rate byte", rate_byte, 0x01)
    check("decodes to 1000 Hz", X.POLLING_RATES_REVERSE[rate_byte], 1000)
    check("complement byte", STATE[X.OFF_STATE_POLLING_COMPLEMENT],
          0xFF - rate_byte)


def test_regenerates_captured_packet():
    """The end-to-end proof: start from the profile the mouse actually had,
    switch the active stage the way the vendor software did, and check we
    produce the exact bytes it put on the wire."""
    print("regenerating the captured 800 -> 1600 switch")
    buf = X.profile_from_state(STATE)          # what the mouse reported
    check("rebuilt profile == captured 800 packet", bytes(buf), bytes(SET_800))
    buf[X.OFF_ACTIVE_STAGE] = 3                # switch to stage 3 (1600 DPI)
    X.apply_checksum(buf)
    check("regenerated == captured 1600 packet", bytes(buf), bytes(SET_1600))


# Captured three times in X8SE_20260905_131001.pcap, on the interrupt IN
# endpoint, with no request of any kind sent first.
BATTERY_EVENT = bytes.fromhex("0302400164")


def test_battery_event():
    print("the captured event message decodes as a battery report")
    event = X.parse_event(BATTERY_EVENT)
    check("recognised as an event", event is not None, True)
    check("kind", event["kind"], "battery")
    check("device id is the X8SE's", event["device_id"], X.DEVICE_ID_X8SE)
    check("event code", event["code"], 0x40)
    check("battery percent", event["percent"], 100)
    check("charge state", event["state"], "charging complete")


def test_event_parser_rejects_non_events():
    print("the parser doesn't mistake other traffic for an event")
    # A 7-byte mouse movement report from the same capture.
    check("movement report rejected",
          X.parse_event(bytes.fromhex("00ffff00000000")), None)
    check("too short rejected", X.parse_event(bytes.fromhex("0302")), None)
    check("wrong opcode rejected",
          X.parse_event(bytes.fromhex("0102400164")), None)


def test_dpi_cycle_event_shape():
    print("a DPI-cycle event would decode, if the X8SE ever sends one")
    # Not observed on the X8SE - this is the X11's documented shape with the
    # X8SE device id substituted, to prove the parser would handle it.
    event = X.parse_event(bytes.fromhex("0302100200"))
    check("kind", event["kind"], "dpi_cycle")
    check("stage", event["stage"], 2)


def test_stage_mask_bookkeeping():
    print("the >12000 DPI multiplier bit is maintained on both mask bytes")
    buf = bytearray(SET_800)
    X.set_stage_dpi(buf, 1, 16000)
    check("double bit set for stage 1", buf[X.OFF_STAGE_MASK_A] & 0x01, 1)
    check("mask A mirrors mask B", buf[X.OFF_STAGE_MASK_A],
          buf[X.OFF_STAGE_MASK_B])
    check("stage 1 reads back as 16000", X.decode_stages(buf)[0][1], 16000)
    X.set_stage_dpi(buf, 1, 800)
    check("double bit cleared again", buf[X.OFF_STAGE_MASK_A] & 0x01, 0)
    check("stage 1 reads back as 800", X.decode_stages(buf)[0][1], 800)


def main():
    for test in (test_checksum, test_stage_decode, test_dpi_roundtrip,
                 test_dpi_encoder_invariants, test_state_dump_rebuild,
                 test_polling_rate_in_dump, test_regenerates_captured_packet,
                 test_battery_event, test_event_parser_rejects_non_events,
                 test_dpi_cycle_event_shape, test_stage_mask_bookkeeping):
        test()
        print()

    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {FAILURES}")
        return 1
    print("All tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
