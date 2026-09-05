#!/usr/bin/env python3
"""
record_dpi_change.py — one-command capture for a single DPI change.

Starts a USBPcap capture, walks you through the change with a countdown,
stops the capture automatically 2 seconds after the change, and (if
analyze_capture.py is in the same folder) immediately shows you what
happened.

HONESTY NOTE: I don't have a Windows machine with USBPcap installed to
test this against directly, so the USBPcapCMD.exe invocation below is
built from USBPcap's documented command-line flags, not verified against
real hardware. The script prints the exact command it's running and
surfaces USBPcapCMD's own output if it exits early, so you can see
immediately if a flag is wrong and adjust via --capture-args (see --help).
If USBPcapCMD.exe rejects a flag, run `USBPcapCMD.exe -h` yourself to see
its real options and pass the working set with --capture-args.

Setup (one-time):
    You need to know which USBPcap interface number corresponds to your
    mouse's USB port (e.g. USBPcap1, USBPcap2...). Open Wireshark once,
    look at the interface list, and note the number you'd normally pick
    for your mouse captures (same one you've been using all along). The
    first time you run this script it'll ask and remember your answer in
    recorder_config.json.

Usage:
    python record_dpi_change.py
    python record_dpi_change.py --reselect-interface
    python record_dpi_change.py --usbpcapcmd "C:\\Program Files\\USBPcap\\USBPcapCMD.exe"
    python record_dpi_change.py --capture-args "-d {device} -o {output} -A"
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

try:
    import winsound
    def beep():
        winsound.Beep(1000, 150)
except ImportError:
    def beep():
        sys.stdout.write("\a")
        sys.stdout.flush()

CONFIG_PATH = "recorder_config.json"
CAPTURES_DIR = "captures"

DEFAULT_CANDIDATE_PATHS = [
    r"C:\Program Files\USBPcap\USBPcapCMD.exe",
    r"C:\Program Files (x86)\USBPcap\USBPcapCMD.exe",
]

# Based on USBPcap's documented CLI flags: -d device, -o output file,
# -A capture all (not just control transfers). NOT verified against real
# hardware in this environment — override with --capture-args if wrong.
DEFAULT_ARGS_TEMPLATE = "-d {device} -o {output} -A"


def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def find_usbpcapcmd(explicit):
    if explicit:
        if os.path.isfile(explicit):
            return explicit
        print(f"--usbpcapcmd path doesn't exist: {explicit}")
        sys.exit(1)
    which = shutil.which("USBPcapCMD.exe") or shutil.which("USBPcapCMD")
    if which:
        return which
    for p in DEFAULT_CANDIDATE_PATHS:
        if os.path.isfile(p):
            return p
    print("Couldn't find USBPcapCMD.exe automatically. It's normally "
          "installed alongside USBPcap (which Wireshark's installer can "
          "set up). Pass its path explicitly with --usbpcapcmd \"<path>\".")
    sys.exit(1)


def get_interface_number(cfg, force_reselect):
    if not force_reselect and "interface_number" in cfg:
        return cfg["interface_number"]
    print("\nWhich USBPcap interface is your mouse on?")
    print("(Open Wireshark, check the interface list — it's the same "
          "USBPcapN you've used for previous captures.)")
    while True:
        raw = input("Enter the number (e.g. 1 for USBPcap1): ").strip()
        if raw.isdigit():
            n = int(raw)
            cfg["interface_number"] = n
            save_config(cfg)
            return n
        print("Please enter a plain number.")


def sanitize_filename(name):
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name.strip())
    return safe or "capture"


def countdown_and_mark():
    print("\nGet ready...")
    time.sleep(0.7)
    for n in (3, 2, 1):
        print(f"  {n}...")
        beep()
        time.sleep(1.0)
    mark_time = time.time()
    print("  >>> CHANGE THE DPI NOW <<<")
    beep()
    beep()
    return mark_time


def start_capture(usbpcapcmd, interface_num, output_path, args_template):
    device = rf"\\.\USBPcap{interface_num}"
    args_str = args_template.format(device=device, output=output_path)
    cmd = [usbpcapcmd] + args_str.split()
    print(f"Running: {' '.join(cmd)}")

    creationflags = 0
    if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

    proc = subprocess.Popen(
        cmd, creationflags=creationflags,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    # give it a moment to start; if it dies immediately, that's a real
    # problem (bad flag, permissions, wrong interface) worth surfacing
    time.sleep(0.7)
    if proc.poll() is not None:
        out = proc.stdout.read() if proc.stdout else ""
        print(f"\nUSBPcapCMD exited immediately (code {proc.returncode}). "
              f"Its output:\n{out}")
        print("This usually means a wrong flag or wrong interface number. "
              "Try running the printed command by hand, or run "
              "'USBPcapCMD.exe -h' to see real flags and pass a working "
              "set via --capture-args.")
        sys.exit(1)
    return proc


def stop_capture(proc, timeout=5):
    print("Stopping capture...")
    try:
        if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            import signal
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.terminate()
    except Exception as e:
        print(f"(graceful stop signal failed: {e}, will force-terminate)")

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        print("Didn't stop gracefully in time, forcing it...")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--usbpcapcmd", help="Explicit path to USBPcapCMD.exe")
    ap.add_argument("--reselect-interface", action="store_true",
                     help="Re-ask which USBPcap interface number to use")
    ap.add_argument("--capture-args", default=DEFAULT_ARGS_TEMPLATE,
                     help="Override the USBPcapCMD argument template. Use "
                          "{device} and {output} as placeholders.")
    ap.add_argument("--wait-after", type=float, default=2.0,
                     help="Seconds to keep capturing after the change (default 2.0)")
    ap.add_argument("--no-analyze", action="store_true",
                     help="Skip auto-running analyze_capture.py on the result")
    args = ap.parse_args()

    usbpcapcmd = find_usbpcapcmd(args.usbpcapcmd)
    cfg = load_config()
    interface_num = get_interface_number(cfg, args.reselect_interface)

    os.makedirs(CAPTURES_DIR, exist_ok=True)

    name = input("\nCapture name: ").strip()
    safe_name = sanitize_filename(name)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(CAPTURES_DIR, f"{safe_name}_{timestamp}.pcap")

    print(f"\nOpen the vendor software now (Attack Shark HUB or similar).")
    input("Press Enter when it's open and ready...")

    proc = start_capture(usbpcapcmd, interface_num, output_path, args.capture_args)
    print(f"Capturing to {output_path}")

    mark_time = countdown_and_mark()

    print(f"Waiting {args.wait_after}s to make sure the change's traffic "
          f"lands in the capture...")
    time.sleep(args.wait_after)

    stop_capture(proc)

    if not os.path.exists(output_path) or os.path.getsize(output_path) < 32:
        print(f"\nSomething's off: {output_path} is missing or tiny. "
              f"Check the USBPcapCMD output above for errors.")
        sys.exit(1)

    print(f"\nSaved: {output_path} ({os.path.getsize(output_path)} bytes)")

    markers_path = output_path.replace(".pcap", ".markers.json")
    markers = [{
        "label": "change",
        "epoch_time": mark_time,
        "readable_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mark_time)),
    }]
    with open(markers_path, "w") as f:
        json.dump(markers, f, indent=2)
    print(f"Saved marker: {markers_path}")

    if not args.no_analyze:
        try:
            import analyze_capture as ac
        except ImportError:
            print("\n(analyze_capture.py not found alongside this script — "
                  "skipping auto-analysis. Run it manually:)")
            print(f"  python analyze_capture.py {output_path} {markers_path}")
            return

        print("\n" + "=" * 60)
        print("AUTO-ANALYSIS")
        print("=" * 60)
        interfaces, packets = ac.parse_capture_file(output_path)
        parsed = []
        for idx, p in enumerate(packets):
            h = ac.parse_usbpcap_header(p, idx + 1)
            if h:
                parsed.append(h)
        if not parsed:
            print("No USB packets parsed from this capture.")
            return
        t0 = parsed[0]["ts"]
        transactions = ac.build_hid_transactions(parsed, t0)
        print(f"Loaded {len(packets)} packets, {len(transactions)} HID "
              f"GET/SET_REPORT transactions.")
        ac.print_full_timeline(transactions)
        ac.print_marker_windows(transactions, markers, window=2.0)


if __name__ == "__main__":
    main()
