#!/usr/bin/env python3
"""
analyze_capture.py — parses a USBPcap .pcapng capture (no tshark/scapy
required) and:

  1. Reconstructs every HID class GET_REPORT / SET_REPORT transaction
     (matching SETUP + completion by IRP id), with real timestamps.
  2. If given a markers.json (from dpi_marker.py), shows exactly what
     happened in a window around each marked "CHANGE" moment, and diffs
     the report state before vs. after each marker.

Usage:
    python analyze_capture.py capture.pcapng
    python analyze_capture.py capture.pcapng markers.json
    python analyze_capture.py capture.pcapng markers.json --window 1.5

Notes:
    - Only tested against USBPcap (Windows) captures, linktype 249.
    - Timestamps in the pcapng are real UTC epoch times (verified against
      wall clock), so markers.json timestamps line up directly.
"""

import json
import struct
import sys


# ---------------------------------------------------------------------------
# pcapng + USBPcap parsing (pure python, no dependencies)
# ---------------------------------------------------------------------------

def parse_pcapng(path):
    with open(path, "rb") as f:
        data = f.read()

    pos = 0
    n = len(data)
    endian = "<"
    interfaces = []
    packets = []

    while pos < n:
        if pos + 8 > n:
            break
        block_type = struct.unpack_from("<I", data, pos)[0]
        block_total_len = struct.unpack_from("<I", data, pos + 4)[0]

        if block_type == 0x0A0D0D0A:
            bom = struct.unpack_from("<I", data, pos + 8)[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
        elif block_type == 0x00000001:
            linktype, _reserved, snaplen = struct.unpack_from(
                endian + "HHI", data, pos + 8
            )
            interfaces.append({"linktype": linktype, "snaplen": snaplen})
        elif block_type == 0x00000006:
            iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack_from(
                endian + "IIIII", data, pos + 8
            )
            start = pos + 8 + 20
            pkt_data = data[start:start + cap_len]
            ts = (ts_high << 32) | ts_low
            packets.append({
                "iface_id": iface_id,
                "ts": ts,
                "cap_len": cap_len,
                "orig_len": orig_len,
                "data": pkt_data,
            })

        if block_total_len == 0 or block_total_len % 4 != 0:
            break
        pos += block_total_len

    if interfaces and interfaces[0]["linktype"] != 249:
        print(f"WARNING: linktype {interfaces[0]['linktype']} is not "
              f"USBPcap (249). This tool assumes Windows USBPcap captures; "
              f"results may be wrong.", file=sys.stderr)

    return interfaces, packets


TRANSFER_TYPES = {0: "ISOCH", 1: "INTERRUPT", 2: "CONTROL", 3: "BULK"}


def parse_usbpcap_header(pkt, num):
    d = pkt["data"]
    if len(d) < 27:
        return None
    headerLen = struct.unpack_from("<H", d, 0)[0]
    irpId = struct.unpack_from("<Q", d, 2)[0]
    status = struct.unpack_from("<I", d, 10)[0]
    function = struct.unpack_from("<H", d, 14)[0]
    info = d[16]
    bus = struct.unpack_from("<H", d, 17)[0]
    device = struct.unpack_from("<H", d, 19)[0]
    endpoint_raw = d[21]
    transfer = d[22]
    dataLength = struct.unpack_from("<I", d, 23)[0]

    direction_in = bool(endpoint_raw & 0x80)
    endpoint = endpoint_raw & 0x7F
    payload = d[headerLen:headerLen + dataLength]

    return {
        "num": num, "ts": pkt["ts"], "irpId": irpId, "status": status,
        "function": function, "bus": bus, "device": device,
        "endpoint": endpoint, "direction_in": direction_in,
        "transfer": TRANSFER_TYPES.get(transfer, transfer),
        "dataLength": dataLength, "payload": payload,
    }


REQ_NAMES = {0x01: "GET_REPORT", 0x09: "SET_REPORT", 0x0a: "SET_IDLE", 0x02: "GET_IDLE"}


def build_hid_transactions(parsed, t0):
    """Match HID class control SETUP packets with their completion to
    reconstruct full request/response pairs, including GET_REPORT data
    that arrives in a separate completion packet.

    NOTE: USBPcap's irpId field is a raw kernel pointer that Windows
    reuses across unrelated I/O requests, so it is NOT a reliable
    transaction identifier here (verified empirically on real captures:
    the same irpId value showed up for hundreds of unrelated URBs).
    Instead we rely on the fact that USBPcap emits the SETUP packet and
    its completion back-to-back on the wire for control transfers, so we
    just look at the next control-transfer packet(s) on the same device.
    """
    ctrl = sorted([h for h in parsed if h["transfer"] == "CONTROL"],
                  key=lambda h: h["num"])

    transactions = []
    i = 0
    while i < len(ctrl):
        h = ctrl[i]
        p = h["payload"]
        if len(p) >= 8 and p[0] in (0x21, 0xA1):
            bmReqType, bReq = p[0], p[1]
            wValue = p[2] | (p[3] << 8)
            wIndex = p[4] | (p[5] << 8)
            wLength = p[6] | (p[7] << 8)
            reportType = wValue >> 8
            reportId = wValue & 0xFF
            is_read = bool(bmReqType & 0x80)

            data = b""
            if not is_read and len(p) > 8:
                # write: data already appended after the 8-byte setup
                data = p[8:]
            elif is_read and wLength > 0:
                # USBPcap emits the completion as the very next
                # control-transfer packet on the same device
                for j in range(i + 1, min(i + 4, len(ctrl))):
                    cand = ctrl[j]
                    if cand["device"] == h["device"] and cand["dataLength"] > 0:
                        data = cand["payload"]
                        break

            transactions.append({
                "num": h["num"],
                "t": (h["ts"] - t0) / 1e6,
                "epoch": h["ts"] / 1e6,
                "direction": "IN" if is_read else "OUT",
                "request": REQ_NAMES.get(bReq, hex(bReq)),
                "reportType": reportType,
                "reportId": reportId,
                "wIndex": wIndex,
                "wLength": wLength,
                "data": data,
            })
        i += 1

    transactions.sort(key=lambda t: t["num"])
    return transactions


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def fmt_txn(t):
    return (f"pkt={t['num']:6d} t={t['t']:9.3f}s {t['direction']:3s} "
            f"{t['request']:11s} reportType={t['reportType']} "
            f"reportId=0x{t['reportId']:02x} wLen={t['wLength']:3d} "
            f"data={t['data'].hex()}")


def print_full_timeline(transactions):
    print("\n=== Full HID GET/SET_REPORT timeline ===")
    for t in transactions:
        print(fmt_txn(t))


def print_marker_windows(transactions, markers, window):
    print(f"\n=== Marker windows (+/- {window}s) ===")
    for m in markers:
        mark_epoch = m["epoch_time"]
        print(f"\n--- Marker '{m['label']}' at {m.get('readable_time', mark_epoch)} ---")
        nearby = [t for t in transactions if abs(t["epoch"] - mark_epoch) <= window]
        if not nearby:
            print(f"  (no HID control transactions within {window}s — try a larger --window)")
            continue
        for t in nearby:
            rel = t["epoch"] - mark_epoch
            marker_flag = "  <== near marker" if abs(rel) < 0.05 else ""
            print(f"  rel={rel:+7.3f}s  {fmt_txn(t)}{marker_flag}")

    # Diff each report id's data across marker boundaries
    print("\n=== State before/after each marker, per report ID ===")
    report_ids = sorted(set(t["reportId"] for t in transactions if t["data"]))
    for rid in report_ids:
        rows = [t for t in transactions if t["reportId"] == rid and t["data"]]
        print(f"\nReportID 0x{rid:02x}:")
        last_data = None
        for m in markers:
            mark_epoch = m["epoch_time"]
            before = [t for t in rows if t["epoch"] < mark_epoch]
            after = [t for t in rows if t["epoch"] >= mark_epoch]
            b = before[-1]["data"] if before else None
            a = after[0]["data"] if after else None
            print(f"  [{m['label']}] before={b.hex() if b else '(none)'}")
            print(f"  [{m['label']}] after ={a.hex() if a else '(none)'}")
            if b and a and b != a:
                diffs = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
                print(f"    -> differing byte offsets: {diffs}")
                for i in diffs:
                    print(f"       offset {i}: {b[i]:#04x} -> {a[i]:#04x} "
                          f"({b[i]} -> {a[i]})")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    pcap_path = sys.argv[1]
    markers_path = None
    window = 2.0
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--window":
            window = float(args[i + 1])
            i += 2
        else:
            markers_path = args[i]
            i += 1

    interfaces, packets = parse_pcapng(pcap_path)
    parsed = []
    for idx, p in enumerate(packets):
        h = parse_usbpcap_header(p, idx + 1)
        if h:
            parsed.append(h)

    if not parsed:
        print("No USB packets parsed — check the file/format.")
        sys.exit(1)

    t0 = parsed[0]["ts"]
    transactions = build_hid_transactions(parsed, t0)

    print(f"Loaded {len(packets)} packets, {len(transactions)} HID "
          f"GET/SET_REPORT transactions.")
    print(f"Capture span: {(parsed[-1]['ts'] - t0) / 1e6:.3f}s")

    print_full_timeline(transactions)

    if markers_path:
        with open(markers_path) as f:
            markers = json.load(f)
        print_marker_windows(transactions, markers, window)
    else:
        print("\n(No markers.json given — showing full timeline only. "
              "Pass a markers file from dpi_marker.py to get windowed "
              "before/after diffs.)")


if __name__ == "__main__":
    main()
