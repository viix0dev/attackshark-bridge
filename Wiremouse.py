import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import json
import shutil
import subprocess
import threading
import time
import signal
import struct


CONFIG_PATH = "recorder_config.json"
CAPTURES_DIR = "captures"

DEFAULT_ARGS_TEMPLATE = "-d {device} -o {output} -A"


# =============================================================
# USBPCAP / PCAP ANALYZER
# =============================================================

TRANSFER_TYPES = {
    0: "ISOCH",
    1: "INTERRUPT",
    2: "CONTROL",
    3: "BULK",
}

REQ_NAMES = {
    0x01: "GET_REPORT",
    0x09: "SET_REPORT",
    0x0A: "SET_IDLE",
    0x02: "GET_IDLE",
}


def parse_pcap_classic(path):
    """
    Parse classic libpcap format.

    Returns:
        interfaces, packets

    packets:
        [(timestamp_seconds, raw_packet_bytes), ...]
    """

    packets = []

    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 24:
        raise ValueError("PCAP file is too small.")

    magic = data[:4]

    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
        nano = False

    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
        nano = False

    elif magic == b"\x4d\x3c\xb2\xa1":
        endian = "<"
        nano = True

    elif magic == b"\xa1\xb2\x3c\x4d":
        endian = ">"
        nano = True

    else:
        raise ValueError(
            f"Unknown PCAP magic: {magic.hex()}"
        )

    header = struct.unpack(
        endian + "IHHIIII",
        data[:24]
    )

    snaplen = header[5]
    offset = 24

    while offset + 16 <= len(data):

        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
            endian + "IIII",
            data[offset:offset + 16]
        )

        offset += 16

        if offset + incl_len > len(data):
            break

        packet = data[
            offset:offset + incl_len
        ]

        offset += incl_len

        if nano:
            timestamp = ts_sec + (
                ts_frac / 1_000_000_000
            )
        else:
            timestamp = ts_sec + (
                ts_frac / 1_000_000
            )

        packets.append(
            (timestamp, packet)
        )

    return [snaplen], packets


def parse_pcapng(path):
    """
    Basic pcapng parser.

    Returns:
        interfaces, packets
    """

    packets = []
    interfaces = []

    with open(path, "rb") as f:
        data = f.read()

    offset = 0

    while offset + 12 <= len(data):

        block_type, block_length = struct.unpack(
            "<II",
            data[offset:offset + 8]
        )

        if block_length < 12:
            break

        if offset + block_length > len(data):
            break

        block = data[
            offset:offset + block_length
        ]

        # -----------------------------------------------------
        # Interface Description Block
        # -----------------------------------------------------

        if block_type == 0x00000001:

            if len(block) >= 20:

                link_type, reserved, snaplen = struct.unpack(
                    "<HHI",
                    block[8:16]
                )

                interfaces.append(
                    {
                        "link_type": link_type,
                        "snaplen": snaplen,
                    }
                )

        # -----------------------------------------------------
        # Enhanced Packet Block
        # -----------------------------------------------------

        elif block_type == 0x00000006:

            if len(block) >= 32:

                interface_id = struct.unpack(
                    "<I",
                    block[8:12]
                )[0]

                ts_high = struct.unpack(
                    "<I",
                    block[12:16]
                )[0]

                ts_low = struct.unpack(
                    "<I",
                    block[16:20]
                )[0]

                captured_len = struct.unpack(
                    "<I",
                    block[20:24]
                )[0]

                timestamp_raw = (
                    (ts_high << 32)
                    | ts_low
                )

                # USBPcap normally uses microsecond timestamps.
                timestamp = timestamp_raw / 1_000_000.0

                packet_start = 28
                packet_end = (
                    packet_start
                    + captured_len
                )

                if packet_end <= len(block):

                    packet = block[
                        packet_start:packet_end
                    ]

                    packets.append(
                        (timestamp, packet)
                    )

        # -----------------------------------------------------
        # Simple Packet Block
        # -----------------------------------------------------

        elif block_type == 0x00000003:

            if len(block) >= 16:

                packet = block[12:-4]

                packets.append(
                    (0, packet)
                )

        offset += block_length

    return interfaces, packets


def parse_capture_file(path):
    """
    Automatically detect classic PCAP or PCAPNG.
    """

    with open(path, "rb") as f:
        magic = f.read(4)

    if magic == b"\x0a\x0d\x0d\x0a":
        return parse_pcapng(path)

    return parse_pcap_classic(path)


def parse_usbpcap_header(packet, num):
    """
    Parse USBPcap packet header.

    USBPcap header is normally 27 bytes.
    """

    if len(packet) < 27:
        return None

    try:

        header_len = packet[0]

        if header_len < 27:
            return None

        irp_id = struct.unpack(
            "<Q",
            packet[1:9]
        )[0]

        status = struct.unpack(
            "<I",
            packet[9:13]
        )[0]

        function = struct.unpack(
            "<H",
            packet[13:15]
        )[0]

        info = packet[15]

        bus = struct.unpack(
            "<H",
            packet[16:18]
        )[0]

        device = struct.unpack(
            "<H",
            packet[18:20]
        )[0]

        endpoint = packet[20]

        transfer_type = packet[21]

        data_length = struct.unpack(
            "<I",
            packet[22:26]
        )[0]

        stage = packet[26]

        payload = packet[
            header_len:
        ]

        return {
            "num": num,
            "header_len": header_len,
            "irpId": irp_id,
            "status": status,
            "function": function,
            "info": info,
            "bus": bus,
            "device": device,
            "endpoint": endpoint,
            "transfer": transfer_type,
            "stage": stage,
            "dataLength": data_length,
            "data": payload,
        }

    except Exception:
        return None


def build_hid_transactions(parsed, t0):
    """
    Reconstruct HID GET_REPORT / SET_REPORT transactions.

    IMPORTANT:
    transaction["epoch"] is stored in SECONDS.

    This matches time.time() used by the DPI marker.
    """

    transactions = []

    for i, packet in enumerate(parsed):

        data = packet.get(
            "data",
            b""
        )

        if not data:
            continue

        transfer = packet.get(
            "transfer"
        )

        if transfer != 2:
            continue

        stage = packet.get(
            "stage"
        )

        if stage != 0:
            continue

        if len(data) < 8:
            continue

        bm_request = data[0]
        b_request = data[1]

        w_value = struct.unpack(
            "<H",
            data[2:4]
        )[0]

        w_index = struct.unpack(
            "<H",
            data[4:6]
        )[0]

        w_length = struct.unpack(
            "<H",
            data[6:8]
        )[0]

        request_name = REQ_NAMES.get(
            b_request,
            f"0x{b_request:02X}"
        )

        report_type = (
            (w_value >> 8)
            & 0xFF
        )

        report_id = (
            w_value
            & 0xFF
        )

        direction_in = (
            bm_request & 0x80
        ) != 0

        # -----------------------------------------------------
        # Search following packets for completion/data.
        # -----------------------------------------------------

        completion = None

        for j in range(
            i + 1,
            min(i + 5, len(parsed))
        ):

            candidate = parsed[j]

            if (
                candidate.get("irpId")
                == packet.get("irpId")
            ):

                completion = candidate
                break

        payload = b""

        if completion:

            payload = completion.get(
                "data",
                b""
            )

        # Sometimes data follows without same IRP metadata.

        if not payload:

            for j in range(
                i + 1,
                min(i + 5, len(parsed))
            ):

                candidate = parsed[j]

                if (
                    candidate.get("transfer")
                    == 2
                    and candidate.get("data")
                ):

                    payload = candidate[
                        "data"
                    ]

                    break

        # -----------------------------------------------------
        # IMPORTANT TIMESTAMP FIX
        #
        # packet["ts"] is microseconds.
        # Convert it to seconds here.
        # -----------------------------------------------------

        packet_epoch = (
            packet.get("ts", 0)
            / 1_000_000.0
        )

        transactions.append(
            {
                "packet": packet.get("num"),
                "epoch": packet_epoch,

                # Relative capture time in seconds.
                "time": (
                    packet.get("ts", 0)
                    - t0
                ) / 1_000_000.0,

                "request": request_name,
                "request_code": b_request,
                "reportType": report_type,
                "reportId": report_id,

                "direction": (
                    "IN"
                    if direction_in
                    else "OUT"
                ),

                "wIndex": w_index,
                "length": w_length,
                "data": payload,
            }
        )

    return transactions


def fmt_txn(t):
    """
    Format one HID transaction for the report.
    """

    data = t.get(
        "data",
        b""
    )

    hex_data = (
        data.hex(" ")
        if data
        else "-"
    )

    return (
        f"{t['time']:10.6f}s  "
        f"pkt={t['packet']:5}  "
        f"{t['direction']:>3}  "
        f"{t['request']:<12}  "
        f"reportType=0x{t['reportType']:02X}  "
        f"reportId=0x{t['reportId']:02X}  "
        f"len={len(data):3}  "
        f"{hex_data}"
    )


def fmt_relative_txn(
    transaction,
    relative_time
):
    """
    Format a transaction relative to the DPI marker.

    Example:

        -0.421000s  pkt=123 ...
        +0.034000s  pkt=145 ...
    """

    return (
        f"{relative_time:+.6f}s  "
        f"pkt={transaction['packet']:5}  "
        f"{transaction['direction']:>3}  "
        f"{transaction['request']:<12}  "
        f"reportType=0x{transaction['reportType']:02X}  "
        f"reportId=0x{transaction['reportId']:02X}  "
        f"len={len(transaction.get('data', b'')):3}  "
        f"{transaction.get('data', b'').hex(' ') if transaction.get('data') else '-'}"
    )


def analyze_file(
    pcap_path,
    markers_path=None,
    before_window=0.5,
    after_window=0.5
):
    """
    Analyze a USBPcap capture around the human-triggered
    DPI change.

    Example:

        -0.500s -------- DPI CHANGE -------- +0.500s

    before_window:
        Number of seconds to inspect BEFORE the marker.

    after_window:
        Number of seconds to inspect AFTER the marker.

    The exact marker timestamp is retained internally.
    """

    report = []

    def out(text=""):
        report.append(
            str(text)
        )

    # ---------------------------------------------------------
    # Parse capture
    # ---------------------------------------------------------

    interfaces, packets = parse_capture_file(
        pcap_path
    )

    if not packets:
        raise ValueError(
            "No packets found in capture."
        )

    parsed = []

    for idx, packet_info in enumerate(
        packets
    ):

        timestamp, raw_packet = packet_info

        header = parse_usbpcap_header(
            raw_packet,
            idx + 1
        )

        if header:

            # Keep timestamp in MICROSECONDS here.
            header["ts"] = (
                timestamp * 1_000_000.0
            )

            parsed.append(
                header
            )

    if not parsed:
        raise ValueError(
            "No USB packets parsed — "
            "check the capture file/format."
        )

    t0 = parsed[0]["ts"]

    transactions = build_hid_transactions(
        parsed,
        t0
    )

    capture_span = (
        parsed[-1]["ts"]
        - t0
    ) / 1_000_000.0

    # ---------------------------------------------------------
    # Report header
    # ---------------------------------------------------------

    out("=" * 80)
    out("WIREMOUSE ANALYSIS REPORT")
    out("=" * 80)
    out()

    out(
        f"Capture: {pcap_path}"
    )

    out(
        f"Packets: {len(packets)}"
    )

    out(
        f"USB packets parsed: {len(parsed)}"
    )

    out(
        f"HID transactions: {len(transactions)}"
    )

    out(
        f"Capture span: {capture_span:.6f} seconds"
    )

    out(
        f"Human analysis window: "
        f"-{before_window:.3f}s "
        f"-> DPI CHANGE -> "
        f"+{after_window:.3f}s"
    )

    out()

    # ---------------------------------------------------------
    # Full timeline
    # ---------------------------------------------------------

    out("=" * 80)
    out("HID TRANSACTION TIMELINE")
    out("=" * 80)
    out()

    if not transactions:

        out(
            "No HID control transactions were reconstructed."
        )

    else:

        for transaction in transactions:

            out(
                fmt_txn(
                    transaction
                )
            )

    out()

    # ---------------------------------------------------------
    # Marker analysis
    # ---------------------------------------------------------

    if not markers_path:

        out(
            "No marker file supplied."
        )

        out("=" * 80)
        out("END OF REPORT")
        out("=" * 80)

        return "\n".join(report)

    if not os.path.exists(
        markers_path
    ):

        out(
            f"Marker file not found: {markers_path}"
        )

        out("=" * 80)
        out("END OF REPORT")
        out("=" * 80)

        return "\n".join(report)

    try:

        with open(
            markers_path,
            "r",
            encoding="utf-8"
        ) as f:

            markers = json.load(f)

    except Exception as e:

        raise ValueError(
            f"Could not read marker file: {e}"
        )

    out("=" * 80)
    out("DPI CHANGE MARKER WINDOWS")
    out("=" * 80)
    out()

    if not markers:

        out(
            "No markers found."
        )

    # ---------------------------------------------------------
    # Analyze each DPI marker
    # ---------------------------------------------------------

    for marker_index, marker in enumerate(
        markers,
        start=1
    ):

        mark_epoch = marker.get(
            "epoch_time"
        )

        label = marker.get(
            "label",
            "marker"
        )

        if mark_epoch is None:
            continue

        readable = marker.get(
            "readable_time",
            ""
        )

        # -----------------------------------------------------
        # Calculate actual human window.
        # -----------------------------------------------------

        start_epoch = (
            mark_epoch
            - before_window
        )

        end_epoch = (
            mark_epoch
            + after_window
        )

        before_transactions = [
            t
            for t in transactions
            if (
                start_epoch
                <= t["epoch"]
                < mark_epoch
            )
        ]

        after_transactions = [
            t
            for t in transactions
            if (
                mark_epoch
                <= t["epoch"]
                <= end_epoch
            )
        ]

        # -----------------------------------------------------
        # Marker header
        # -----------------------------------------------------

        out("")
        out("")
        out("=" * 80)
        out(
            f"DPI CHANGE #{marker_index}"
        )
        out("=" * 80)

        out(
            f"Label: {label}"
        )

        out(
            f"Exact marker epoch: {mark_epoch:.6f}"
        )

        if readable:

            out(
                f"Human time: {readable}"
            )

        out(
            f"Analysis window: "
            f"-{before_window:.3f}s "
            f"-> DPI CHANGE -> "
            f"+{after_window:.3f}s"
        )

        out()

        # -----------------------------------------------------
        # BEFORE
        # -----------------------------------------------------

        out("-" * 80)
        out(
            f"BEFORE DPI CHANGE "
            f"(-{before_window:.3f}s)"
        )
        out("-" * 80)

        if not before_transactions:

            out(
                "No HID transactions found before "
                "the DPI change inside the configured window."
            )

        else:

            for transaction in before_transactions:

                relative = (
                    transaction["epoch"]
                    - mark_epoch
                )

                out(
                    fmt_relative_txn(
                        transaction,
                        relative
                    )
                )

        # -----------------------------------------------------
        # DPI MARKER
        # -----------------------------------------------------

        out()
        out()

        out(
            "================== TIME OF DPI CHANGE =================="
        )

        if readable:

            out(
                f"                    {readable}"
            )

        out(
            f"                    epoch={mark_epoch:.6f}"
        )

        out(
            "=========================================================="
        )

        out()
        out()

        # -----------------------------------------------------
        # AFTER
        # -----------------------------------------------------

        out("-" * 80)
        out(
            f"AFTER DPI CHANGE "
            f"(+{after_window:.3f}s)"
        )
        out("-" * 80)

        if not after_transactions:

            out(
                "No HID transactions found after "
                "the DPI change inside the configured window."
            )

        else:

            for transaction in after_transactions:

                relative = (
                    transaction["epoch"]
                    - mark_epoch
                )

                out(
                    fmt_relative_txn(
                        transaction,
                        relative
                    )
                )

        out()

        # -----------------------------------------------------
        # BEFORE / AFTER STATE
        # -----------------------------------------------------

        out("=" * 80)
        out("BEFORE / AFTER REPORT STATE")
        out("=" * 80)

        report_ids = sorted(
            set(
                t["reportId"]
                for t in (
                    before_transactions
                    + after_transactions
                )
                if t.get("data")
                and t.get("reportId") is not None
            )
        )

        if not report_ids:

            out(
                "No data-bearing HID reports found "
                "inside the configured window."
            )

        for report_id in report_ids:

            before_rows = [
                t
                for t in before_transactions
                if (
                    t["reportId"]
                    == report_id
                    and t.get("data")
                )
            ]

            after_rows = [
                t
                for t in after_transactions
                if (
                    t["reportId"]
                    == report_id
                    and t.get("data")
                )
            ]

            out()
            out(
                f"Report ID: 0x{report_id:02X}"
            )
            out("-" * 60)

            # -------------------------------------------------
            # Last report BEFORE DPI change
            # -------------------------------------------------

            if before_rows:

                before_transaction = (
                    before_rows[-1]
                )

                before_data = (
                    before_transaction["data"]
                )

                before_relative = (
                    before_transaction["epoch"]
                    - mark_epoch
                )

                out(
                    f"  Before "
                    f"({before_relative:+.6f}s): "
                    f"{before_data.hex(' ')}"
                )

            else:

                before_transaction = None
                before_data = None

                out(
                    "  Before: no data-bearing report "
                    "inside configured window."
                )

            # -------------------------------------------------
            # First report AFTER DPI change
            # -------------------------------------------------

            if after_rows:

                after_transaction = (
                    after_rows[0]
                )

                after_data = (
                    after_transaction["data"]
                )

                after_relative = (
                    after_transaction["epoch"]
                    - mark_epoch
                )

                out(
                    f"  After  "
                    f"({after_relative:+.6f}s): "
                    f"{after_data.hex(' ')}"
                )

            else:

                after_transaction = None
                after_data = None

                out(
                    "  After: no data-bearing report "
                    "inside configured window."
                )

            # -------------------------------------------------
            # Diff
            # -------------------------------------------------

            if (
                before_data is None
                or after_data is None
            ):

                out(
                    "  Diff: INSUFFICIENT DATA"
                )

                continue

            max_len = max(
                len(before_data),
                len(after_data)
            )

            differences = []

            for i in range(
                max_len
            ):

                old = (
                    before_data[i]
                    if i < len(before_data)
                    else None
                )

                new = (
                    after_data[i]
                    if i < len(after_data)
                    else None
                )

                if old != new:

                    differences.append(
                        (
                            i,
                            old,
                            new
                        )
                    )

            if not differences:

                out(
                    "  Diff: NO CHANGE"
                )

            else:

                out(
                    f"  Diff: {len(differences)} "
                    f"byte(s) changed."
                )

                for offset, old, new in differences:

                    old_text = (
                        f"0x{old:02X}"
                        if old is not None
                        else "--"
                    )

                    new_text = (
                        f"0x{new:02X}"
                        if new is not None
                        else "--"
                    )

                    out(
                        f"    offset {offset:3}: "
                        f"{old_text} -> {new_text}"
                    )

        out()

    out("=" * 80)
    out("END OF REPORT")
    out("=" * 80)

    return "\n".join(report)


# =============================================================
# GUI
# =============================================================

class WireMouseApp:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "WireMouse - Built for Reverse Engineering"
        )

        self.root.geometry(
            "800x650"
        )

        self.process = None
        self.capturing = False
        self.mark_time = None
        self.output_path = None

        self.build_gui()
        self.load_config()

    # =========================================================
    # GUI
    # =========================================================

    def build_gui(self):

        main = ttk.Frame(
            self.root,
            padding=15
        )

        main.pack(
            fill="both",
            expand=True
        )

        # -----------------------------------------------------
        # Header
        # -----------------------------------------------------

        ttk.Label(
            main,
            text="WireMouse",
            font=("Segoe UI", 24, "bold")
        ).pack(
            anchor="w"
        )

        ttk.Label(
            main,
            text="USB capture • DPI change detection • analysis"
        ).pack(
            anchor="w",
            pady=(0, 15)
        )

        # -----------------------------------------------------
        # Configuration
        # -----------------------------------------------------

        config = ttk.LabelFrame(
            main,
            text="Capture Configuration",
            padding=10
        )

        config.pack(
            fill="x"
        )

        # USBPcap

        ttk.Label(
            config,
            text="USBPcapCMD:"
        ).grid(
            row=0,
            column=0,
            sticky="w",
            pady=5
        )

        self.usbpcap_var = tk.StringVar()

        ttk.Entry(
            config,
            textvariable=self.usbpcap_var
        ).grid(
            row=0,
            column=1,
            sticky="ew",
            padx=5
        )

        ttk.Button(
            config,
            text="Browse",
            command=self.browse_usbpcap
        ).grid(
            row=0,
            column=2
        )

        # Interface

        ttk.Label(
            config,
            text="USB Interface:"
        ).grid(
            row=1,
            column=0,
            sticky="w",
            pady=5
        )

        self.interface_var = tk.StringVar()

        self.interface_menu = ttk.Combobox(
            config,
            textvariable=self.interface_var,
            values=[
                "USBPcap1",
                "USBPcap2",
                "USBPcap3",
                "USBPcap4",
                "USBPcap5",
                "USBPcap6",
                "USBPcap7",
                "USBPcap8",
            ],
            state="readonly",
            width=20
        )

        self.interface_menu.grid(
            row=1,
            column=1,
            sticky="w",
            padx=5
        )

        # Capture name

        ttk.Label(
            config,
            text="Capture Name:"
        ).grid(
            row=2,
            column=0,
            sticky="w",
            pady=5
        )

        self.name_var = tk.StringVar()

        ttk.Entry(
            config,
            textvariable=self.name_var
        ).grid(
            row=2,
            column=1,
            sticky="ew",
            padx=5
        )

        # Wait after DPI change

        ttk.Label(
            config,
            text="Wait after DPI change:"
        ).grid(
            row=3,
            column=0,
            sticky="w",
            pady=5
        )

        self.wait_var = tk.StringVar(
            value="2.0"
        )

        ttk.Spinbox(
            config,
            from_=0,
            to=30,
            increment=0.5,
            textvariable=self.wait_var,
            width=10
        ).grid(
            row=3,
            column=1,
            sticky="w",
            padx=5
        )

        # -----------------------------------------------------
        # NEW: Analysis BEFORE
        # -----------------------------------------------------

        ttk.Label(
            config,
            text="Analysis before DPI:"
        ).grid(
            row=4,
            column=0,
            sticky="w",
            pady=5
        )

        self.analysis_before_var = tk.StringVar(
            value="0.5"
        )

        ttk.Spinbox(
            config,
            from_=0.1,
            to=10.0,
            increment=0.1,
            textvariable=self.analysis_before_var,
            width=10
        ).grid(
            row=4,
            column=1,
            sticky="w",
            padx=5
        )

        ttk.Label(
            config,
            text="seconds"
        ).grid(
            row=4,
            column=2,
            sticky="w"
        )

        # -----------------------------------------------------
        # NEW: Analysis AFTER
        # -----------------------------------------------------

        ttk.Label(
            config,
            text="Analysis after DPI:"
        ).grid(
            row=5,
            column=0,
            sticky="w",
            pady=5
        )

        self.analysis_after_var = tk.StringVar(
            value="0.5"
        )

        ttk.Spinbox(
            config,
            from_=0.1,
            to=10.0,
            increment=0.1,
            textvariable=self.analysis_after_var,
            width=10
        ).grid(
            row=5,
            column=1,
            sticky="w",
            padx=5
        )

        ttk.Label(
            config,
            text="seconds"
        ).grid(
            row=5,
            column=2,
            sticky="w"
        )

        config.columnconfigure(
            1,
            weight=1
        )

        # -----------------------------------------------------
        # Countdown
        # -----------------------------------------------------

        countdown_frame = ttk.LabelFrame(
            main,
            text="DPI Change Capture",
            padding=15
        )

        countdown_frame.pack(
            fill="x",
            pady=15
        )

        self.status_var = tk.StringVar(
            value="READY"
        )

        ttk.Label(
            countdown_frame,
            textvariable=self.status_var,
            font=("Segoe UI", 14, "bold")
        ).pack()

        self.counter_var = tk.StringVar(
            value="—"
        )

        ttk.Label(
            countdown_frame,
            textvariable=self.counter_var,
            font=("Segoe UI", 48, "bold")
        ).pack(
            pady=10
        )

        self.instruction_var = tk.StringVar(
            value="Press Start when the mouse software is ready."
        )

        ttk.Label(
            countdown_frame,
            textvariable=self.instruction_var,
            font=("Segoe UI", 11)
        ).pack()

        # -----------------------------------------------------
        # Buttons
        # -----------------------------------------------------

        button_frame = ttk.Frame(
            main
        )

        button_frame.pack(
            fill="x",
            pady=5
        )

        self.start_button = ttk.Button(
            button_frame,
            text="▶  START CAPTURE",
            command=self.start_capture
        )

        self.start_button.pack(
            side="left"
        )

        self.stop_button = ttk.Button(
            button_frame,
            text="■  STOP",
            command=self.stop_capture,
            state="disabled"
        )

        self.stop_button.pack(
            side="left",
            padx=5
        )

        # -----------------------------------------------------
        # Log
        # -----------------------------------------------------

        log_frame = ttk.LabelFrame(
            main,
            text="Capture / Analysis Report",
            padding=5
        )

        log_frame.pack(
            fill="both",
            expand=True,
            pady=(10, 0)
        )

        self.log = tk.Text(
            log_frame,
            wrap="none",
            state="disabled",
            font=("Consolas", 9)
        )

        scrollbar_y = ttk.Scrollbar(
            log_frame,
            orient="vertical",
            command=self.log.yview
        )

        scrollbar_x = ttk.Scrollbar(
            log_frame,
            orient="horizontal",
            command=self.log.xview
        )

        self.log.configure(
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set
        )

        self.log.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar_y.pack(
            side="right",
            fill="y"
        )

        scrollbar_x.pack(
            side="bottom",
            fill="x"
        )

    # =========================================================
    # LOGGING
    # =========================================================

    def write_log(self, text):

        self.log.configure(
            state="normal"
        )

        self.log.insert(
            "end",
            str(text) + "\n"
        )

        self.log.see(
            "end"
        )

        self.log.configure(
            state="disabled"
        )

    # =========================================================
    # CONFIG
    # =========================================================

    def load_config(self):

        if os.path.exists(
            CONFIG_PATH
        ):

            try:

                with open(
                    CONFIG_PATH,
                    "r",
                    encoding="utf-8"
                ) as f:

                    cfg = json.load(f)

                interface = cfg.get(
                    "interface_number"
                )

                if interface:

                    self.interface_var.set(
                        f"USBPcap{interface}"
                    )

                usbpcap = cfg.get(
                    "usbpcapcmd"
                )

                if usbpcap:

                    self.usbpcap_var.set(
                        usbpcap
                    )

            except Exception:
                pass

        else:

            path = shutil.which(
                "USBPcapCMD.exe"
            )

            if path:

                self.usbpcap_var.set(
                    path
                )

    def save_config(self):

        interface = self.interface_var.get()

        number = interface.replace(
            "USBPcap",
            ""
        )

        cfg = {
            "interface_number": number,
            "usbpcapcmd": self.usbpcap_var.get()
        }

        with open(
            CONFIG_PATH,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                cfg,
                f,
                indent=2
            )

    # =========================================================
    # BROWSE
    # =========================================================

    def browse_usbpcap(self):

        path = filedialog.askopenfilename(
            title="Select USBPcapCMD.exe",
            filetypes=[
                ("Executable", "*.exe"),
                ("All files", "*.*")
            ]
        )

        if path:

            self.usbpcap_var.set(
                path
            )

    # =========================================================
    # START CAPTURE
    # =========================================================

    def start_capture(self):

        if self.capturing:
            return

        usbpcap = self.usbpcap_var.get()
        interface = self.interface_var.get()
        name = self.name_var.get().strip()

        if not usbpcap:

            messagebox.showerror(
                "USBPcap",
                "Select USBPcapCMD.exe."
            )

            return

        if not os.path.isfile(
            usbpcap
        ):

            messagebox.showerror(
                "USBPcap",
                "USBPcapCMD.exe was not found."
            )

            return

        if not interface:

            messagebox.showerror(
                "Interface",
                "Select a USBPcap interface."
            )

            return

        if not name:

            messagebox.showerror(
                "Capture name",
                "Enter a capture name."
            )

            return

        try:

            wait_after = float(
                self.wait_var.get()
            )

            if wait_after < 0:
                raise ValueError

        except ValueError:

            messagebox.showerror(
                "Wait time",
                "Enter a valid non-negative number."
            )

            return

        # -----------------------------------------------------
        # NEW: Validate analysis windows
        # -----------------------------------------------------

        try:

            analysis_before = float(
                self.analysis_before_var.get()
            )

            analysis_after = float(
                self.analysis_after_var.get()
            )

            if analysis_before <= 0:
                raise ValueError

            if analysis_after <= 0:
                raise ValueError

        except ValueError:

            messagebox.showerror(
                "Analysis window",
                "Analysis before/after must be positive numbers."
            )

            return

        self.save_config()

        os.makedirs(
            CAPTURES_DIR,
            exist_ok=True
        )

        safe_name = "".join(
            c if c.isalnum() or c in "-_"
            else "_"
            for c in name
        )

        timestamp = time.strftime(
            "%Y%m%d_%H%M%S"
        )

        self.output_path = os.path.join(
            CAPTURES_DIR,
            f"{safe_name}_{timestamp}.pcap"
        )

        interface_number = interface.replace(
            "USBPcap",
            ""
        )

        device = (
            rf"\\.\USBPcap{interface_number}"
        )

        cmd = [
            usbpcap,
            "-d",
            device,
            "-o",
            self.output_path,
            "-A",
        ]

        self.write_log("")
        self.write_log("=" * 80)
        self.write_log("STARTING USBPCAP")
        self.write_log("=" * 80)

        self.write_log(
            f"Interface: {interface}"
        )

        self.write_log(
            f"Output: {self.output_path}"
        )

        self.write_log(
            f"Analysis window: "
            f"-{analysis_before:.3f}s "
            f"-> DPI CHANGE -> "
            f"+{analysis_after:.3f}s"
        )

        self.write_log(
            f"Command: {subprocess.list2cmdline(cmd)}"
        )

        self.capturing = True

        self.start_button.configure(
            state="disabled"
        )

        self.stop_button.configure(
            state="normal"
        )

        self.status_var.set(
            "CAPTURE STARTING..."
        )

        self.counter_var.set(
            "—"
        )

        self.instruction_var.set(
            "Starting USBPcap..."
        )

        thread = threading.Thread(
            target=self.capture_thread,
            args=(cmd, wait_after),
            daemon=True
        )

        thread.start()

    # =========================================================
    # CAPTURE THREAD
    # =========================================================

    def capture_thread(
        self,
        cmd,
        wait_after
    ):

        try:

            creationflags = 0

            if os.name == "nt":

                creationflags = getattr(
                    subprocess,
                    "CREATE_NEW_PROCESS_GROUP",
                    0
                )

            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=creationflags
            )

            self.root.after(
                0,
                self.write_log,
                "USBPcap process started."
            )

            threading.Thread(
                target=self.read_process_output,
                daemon=True
            ).start()

            time.sleep(1)

            if (
                self.process
                and self.process.poll() is not None
            ):

                self.root.after(
                    0,
                    self.capture_error,
                    "USBPcap exited immediately."
                )

                return

            self.root.after(
                0,
                self.begin_countdown,
                wait_after
            )

        except Exception as e:

            self.root.after(
                0,
                self.capture_error,
                str(e)
            )

    # =========================================================
    # READ USBPCAP OUTPUT
    # =========================================================

    def read_process_output(self):

        process = self.process

        if not process:
            return

        try:

            if process.stdout:

                for line in process.stdout:

                    line = line.rstrip()

                    if line:

                        self.root.after(
                            0,
                            self.write_log,
                            "[USBPcap] " + line
                        )

        except Exception:
            pass

    # =========================================================
    # COUNTDOWN
    # =========================================================

    def begin_countdown(
        self,
        wait_after
    ):

        if not self.capturing:
            return

        self.status_var.set(
            "GET READY"
        )

        self.instruction_var.set(
            "Prepare to change the DPI."
        )

        self.counter_var.set(
            "3"
        )

        self.root.after(
            1000,
            lambda: self.countdown_step(
                2,
                wait_after
            )
        )

    def countdown_step(
        self,
        number,
        wait_after
    ):

        if not self.capturing:
            return

        if number > 0:

            self.counter_var.set(
                str(number)
            )

            self.status_var.set(
                "GET READY"
            )

            self.root.after(
                1000,
                lambda: self.countdown_step(
                    number - 1,
                    wait_after
                )
            )

        else:

            self.counter_var.set(
                "CHANGE DPI!"
            )

            self.status_var.set(
                "CHANGE NOW"
            )

            self.instruction_var.set(
                "Change the mouse DPI NOW."
            )

            # -------------------------------------------------
            # EXACT HUMAN MARKER
            # -------------------------------------------------

            self.mark_time = time.time()

            self.write_log(
                ">>> DPI CHANGE MARKER <<<"
            )

            self.write_log(
                time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.localtime(
                        self.mark_time
                    )
                )
            )

            self.root.after(
                int(wait_after * 1000),
                self.finish_capture
            )

    # =========================================================
    # FINISH CAPTURE
    # =========================================================

    def finish_capture(self):

        if not self.capturing:
            return

        self.status_var.set(
            "STOPPING..."
        )

        self.counter_var.set(
            "✓"
        )

        self.instruction_var.set(
            "Stopping USBPcap and saving capture..."
        )

        self.stop_process()

        self.root.after(
            1000,
            self.save_marker
        )

    # =========================================================
    # STOP PROCESS
    # =========================================================

    def stop_process(self):

        process = self.process

        if not process:
            return

        try:

            if process.poll() is None:

                if (
                    os.name == "nt"
                    and hasattr(
                        signal,
                        "CTRL_BREAK_EVENT"
                    )
                ):

                    try:

                        process.send_signal(
                            signal.CTRL_BREAK_EVENT
                        )

                        self.write_log(
                            "Sent CTRL_BREAK_EVENT to USBPcap."
                        )

                    except Exception:

                        process.terminate()

                else:

                    process.terminate()

            try:

                process.wait(
                    timeout=3
                )

            except subprocess.TimeoutExpired:

                process.kill()

                self.write_log(
                    "USBPcap did not exit gracefully; process killed."
                )

            else:

                self.write_log(
                    "USBPcap process stopped."
                )

        except Exception as e:

            self.write_log(
                f"Stop error: {e}"
            )

        finally:

            self.process = None

    # =========================================================
    # SAVE MARKER
    # =========================================================

    def save_marker(self):

        if not self.output_path:
            return

        if not os.path.exists(
            self.output_path
        ):

            self.capture_error(
                "Capture file was not created."
            )

            return

        size = os.path.getsize(
            self.output_path
        )

        if size < 32:

            self.capture_error(
                f"Capture file is too small ({size} bytes)."
            )

            return

        base_path = os.path.splitext(
            self.output_path
        )[0]

        markers_path = (
            base_path
            + ".markers.json"
        )

        markers = [
            {
                "label": "change",
                "epoch_time": self.mark_time,
                "readable_time": time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.localtime(
                        self.mark_time
                    )
                )
            }
        ]

        try:

            with open(
                markers_path,
                "w",
                encoding="utf-8"
            ) as f:

                json.dump(
                    markers,
                    f,
                    indent=2
                )

        except Exception as e:

            self.capture_error(
                f"Could not save marker:\n{e}"
            )

            return

        self.write_log("")
        self.write_log("=" * 80)
        self.write_log("CAPTURE COMPLETE")
        self.write_log("=" * 80)

        self.write_log(
            f"PCAP: {self.output_path}"
        )

        self.write_log(
            f"Size: {size} bytes"
        )

        self.write_log(
            f"Marker: {markers_path}"
        )

        self.status_var.set(
            "CAPTURE COMPLETE"
        )

        self.counter_var.set(
            "✓"
        )

        self.instruction_var.set(
            "Capture saved. Starting analysis..."
        )

        self.capturing = False

        self.start_button.configure(
            state="disabled"
        )

        self.stop_button.configure(
            state="disabled"
        )

        # -----------------------------------------------------
        # AUTOMATIC ANALYSIS
        # -----------------------------------------------------

        self.run_analysis(
            self.output_path,
            markers_path
        )

    # =========================================================
    # ANALYSIS
    # =========================================================

    def run_analysis(
        self,
        pcap_path,
        markers_path
    ):

        # -----------------------------------------------------
        # Read analysis window from GUI.
        # -----------------------------------------------------

        try:

            before_window = float(
                self.analysis_before_var.get()
            )

            after_window = float(
                self.analysis_after_var.get()
            )

            if before_window <= 0:
                raise ValueError

            if after_window <= 0:
                raise ValueError

        except ValueError:

            self.analysis_error(
                "Invalid analysis window."
            )

            return

        self.status_var.set(
            "ANALYZING..."
        )

        self.counter_var.set(
            "⌛"
        )

        self.instruction_var.set(
            "Parsing USB packets and reconstructing HID reports..."
        )

        self.write_log("")
        self.write_log("=" * 80)
        self.write_log("RUNNING WIREMOUSE ANALYZER")
        self.write_log("=" * 80)

        self.write_log(
            f"Analysis window: "
            f"-{before_window:.3f}s "
            f"-> DPI CHANGE -> "
            f"+{after_window:.3f}s"
        )

        # Analysis runs in background.

        thread = threading.Thread(
            target=self.analysis_thread,
            args=(
                pcap_path,
                markers_path,
                before_window,
                after_window
            ),
            daemon=True
        )

        thread.start()

    def analysis_thread(
        self,
        pcap_path,
        markers_path,
        before_window,
        after_window
    ):

        try:

            report = analyze_file(
                pcap_path,
                markers_path,
                before_window=before_window,
                after_window=after_window
            )

            base_path = os.path.splitext(
                pcap_path
            )[0]

            report_path = (
                base_path
                + ".report.txt"
            )

            with open(
                report_path,
                "w",
                encoding="utf-8"
            ) as f:

                f.write(
                    report
                )

            self.root.after(
                0,
                self.analysis_complete,
                report,
                report_path
            )

        except Exception as e:

            self.root.after(
                0,
                self.analysis_error,
                str(e)
            )

    def analysis_complete(
        self,
        report,
        report_path
    ):

        # Replace capture log with report.

        self.log.configure(
            state="normal"
        )

        self.log.delete(
            "1.0",
            "end"
        )

        self.log.insert(
            "end",
            report
        )

        self.log.see(
            "1.0"
        )

        self.log.configure(
            state="disabled"
        )

        self.status_var.set(
            "ANALYSIS COMPLETE"
        )

        self.counter_var.set(
            "✓"
        )

        self.instruction_var.set(
            "Capture analyzed successfully."
        )

        self.start_button.configure(
            state="normal"
        )

        self.stop_button.configure(
            state="disabled"
        )

        self.write_log(
            ""
        )

        self.write_log(
            f"Report saved: {report_path}"
        )

    def analysis_error(
        self,
        error
    ):

        self.status_var.set(
            "ANALYSIS ERROR"
        )

        self.counter_var.set(
            "!"
        )

        self.instruction_var.set(
            "Capture completed, but analysis failed."
        )

        self.start_button.configure(
            state="normal"
        )

        self.stop_button.configure(
            state="disabled"
        )

        self.write_log("")
        self.write_log("=" * 80)
        self.write_log("ANALYSIS ERROR")
        self.write_log("=" * 80)
        self.write_log(
            str(error)
        )

        messagebox.showerror(
            "Analysis Error",
            str(error)
        )

    # =========================================================
    # MANUAL STOP
    # =========================================================

    def stop_capture(self):

        if not self.capturing:
            return

        self.capturing = False

        self.stop_process()

        self.status_var.set(
            "STOPPED"
        )

        self.counter_var.set(
            "■"
        )

        self.instruction_var.set(
            "Capture stopped manually."
        )

        self.start_button.configure(
            state="normal"
        )

        self.stop_button.configure(
            state="disabled"
        )

        self.write_log(
            "Capture manually stopped."
        )

    # =========================================================
    # ERROR
    # =========================================================

    def capture_error(
        self,
        error
    ):

        self.capturing = False

        self.stop_process()

        self.status_var.set(
            "ERROR"
        )

        self.counter_var.set(
            "!"
        )

        self.instruction_var.set(
            "Capture failed."
        )

        self.start_button.configure(
            state="normal"
        )

        self.stop_button.configure(
            state="disabled"
        )

        self.write_log(
            "ERROR:"
        )

        self.write_log(
            str(error)
        )

        messagebox.showerror(
            "Capture Error",
            str(error)
        )


# =============================================================
# MAIN
# =============================================================

def main():

    root = tk.Tk()

    app = WireMouseApp(
        root
    )

    root.mainloop()


if __name__ == "__main__":
    main()