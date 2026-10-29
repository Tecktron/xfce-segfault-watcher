#!/usr/bin/env python3
"""Watches the systemd journal for kernel Oopses and userspace crashes, and
fires an XFCE desktop notification (via notify-send) explaining what crashed
and why, as soon as it happens.

Built to help track down an ongoing hardware/firmware instability issue on
this machine (segfaults + kernel general protection faults hitting unrelated
processes). See README.md alongside this script; install.sh sets up the
autostart entry, which runs this with the bundled .venv's Python.
"""

import glob
import logging
import os
import re
import subprocess
import threading
import time

# Installed into this folder's .venv by install.sh. Run with a Python that
# lacks it, the journal watching still works; only Chrome dump decoding is off.
try:
    from minidump.minidumpfile import MinidumpFile
except ImportError:
    MinidumpFile = None

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

CHROME_CRASH_DIR = os.path.expanduser("~/.config/google-chrome/Crash Reports/completed")

# Durable record of every detection, independent of the ephemeral notify-send
# popup. Always appended (never truncated), so it survives both the script's
# own restarts and the crash-induced reboot that's often the whole reason
# you're checking it after the fact.
EVENTS_LOG = os.path.join(SCRIPT_DIR, "events.log")

# Confirmed against Crashpad's own source (chromium/crashpad):
# MinidumpExceptionWriter::InitializeFromSnapshot ->
#   SetExceptionFlags(exception_snapshot->ExceptionInfo())
# ExceptionSnapshotLinux::ExceptionInfo() returns signal_code_,
# which is set from siginfo.code. So ExceptionFlags *is* si_code verbatim.
SI_CODE_NAMES = {
    1: "SEGV_MAPERR",
    2: "SEGV_ACCERR",
    3: "SEGV_BNDERR",
    4: "SEGV_PKUERR",
    128: "SI_KERNEL",
}
SI_KERNEL = 128

CHROME_POLL_SECONDS = 5

OOPS_RE = re.compile(
    r"Oops: (?P<kind>[^,]+), probably for non-canonical address (?P<addr>0x[0-9a-fA-F]+)"
)
OOPS_COMM_RE = re.compile(r"PID:\s*(?P<pid>\d+)\s+Comm:\s*(?P<comm>\S+)")
COREDUMP_RE = re.compile(
    r"Process (?P<pid>\d+) \((?P<comm>[^)]+)\) of user \d+ dumped core"
)
SEGFAULT_RE = re.compile(
    r"(?P<comm>.+)\[(?P<pid>\d+)\]: segfault at (?P<addr>[0-9a-f]+) "
    r"ip (?P<ip>[0-9a-f]+) sp (?P<sp>[0-9a-f]+) error (?P<err>\d+)"
    r"(?: in (?P<lib>\S+))?"
)

# How many lines to keep looking for the Comm: follow-up after an Oops line,
# before giving up and notifying without a process name.
OOPS_COMM_LOOKAHEAD = 5

# How long (seconds) to suppress a duplicate notification for the same PID,
# since a single crash typically logs both a kernel "segfault at" line and a
# systemd-coredump "dumped core" line.
DEDUP_WINDOW_SECONDS = 5


def notify(summary, body, urgency="normal", persistent=False):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(EVENTS_LOG, "a") as f:
            f.write(f"[{timestamp}] ({urgency}) {summary}\n")
            for line in body.splitlines():
                f.write(f"    {line}\n")
    except OSError as e:
        print(f"Failed to write to events log: {e}")

    args = ["notify-send", "-u", urgency, "-a", "Segfault Watcher"]
    args += ["-i", "dialog-error" if urgency == "critical" else "dialog-warning"]
    if persistent:
        args += ["-t", "0"]
    args += [summary, body]
    subprocess.run(args, check=False)


def coredump_details(pid):
    """Best-effort enrichment via coredumpctl: signal + first backtrace frame."""
    try:
        result = subprocess.run(
            ["coredumpctl", "info", str(pid), "--no-pager"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if result.returncode != 0:
        return None

    signal_line = None
    first_frame = None
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Signal:"):
            signal_line = stripped
        elif stripped.startswith("#0") and first_frame is None:
            first_frame = stripped
    details = [l for l in (signal_line, first_frame) if l]
    return "\n".join(details) if details else None


def describe_chrome_dump(path):
    """Parse a Crashpad minidump and return (signal_name, si_code, addr, verdict)."""
    prev_level = logging.getLogger().level
    logging.getLogger().setLevel(logging.CRITICAL)  # silence the benign PEB-parse warning
    try:
        mf = MinidumpFile.parse(path)
    finally:
        logging.getLogger().setLevel(prev_level)

    if mf.exception is None or not mf.exception.exception_records:
        return None

    record = mf.exception.exception_records[0].ExceptionRecord
    signal_name = str(record.ExceptionCode).replace("ExceptionCode.EXCEPTION_", "")
    si_code = record.ExceptionFlags
    si_code_name = SI_CODE_NAMES.get(si_code, str(si_code))
    addr = record.ExceptionAddress

    if signal_name == "SIGTRAP" and si_code == SI_KERNEL and addr == 0:
        verdict = (
            "Likely Chrome's own intentional diagnostic trap, not memory "
            "corruption (SIGTRAP + SI_KERNEL + null address is how Chrome "
            "self-triggers a debug dump)."
        )
    elif si_code == SI_KERNEL:
        verdict = (
            "MATCHES the hardware-fault pattern (SI_KERNEL) — treat this "
            "seriously, not as a routine Chrome bug."
        )
    else:
        verdict = f"Ordinary software fault (si_code={si_code_name}) — not the hardware pattern."

    return signal_name, si_code_name, addr, verdict


def watch_chrome_crashes():
    if MinidumpFile is None:
        print("minidump package unavailable — Chrome crash decoding disabled.")
        return
    if not os.path.isdir(CHROME_CRASH_DIR):
        print(f"Chrome crash dir not found ({CHROME_CRASH_DIR}) — skipping.")
        return

    start_time = time.time()
    seen = set()

    while True:
        for path in glob.glob(os.path.join(CHROME_CRASH_DIR, "*.dmp")):
            name = os.path.basename(path)
            if name in seen:
                continue
            seen.add(name)
            try:
                if os.path.getmtime(path) <= start_time or os.path.getsize(path) == 0:
                    continue
                result = describe_chrome_dump(path)
            except Exception as e:
                print(f"Failed to parse Chrome dump {name}: {e}")
                continue
            if result is None:
                continue

            signal_name, si_code_name, addr, verdict = result
            urgency = "critical" if si_code_name == "SI_KERNEL" else "normal"
            notify(
                f"Chrome crash: {signal_name}",
                f"si_code={si_code_name}  addr=0x{addr:x}\n{verdict}",
                urgency=urgency,
                persistent=(urgency == "critical"),
            )
        time.sleep(CHROME_POLL_SECONDS)


def main():
    threading.Thread(target=watch_chrome_crashes, daemon=True).start()

    proc = subprocess.Popen(
        ["journalctl", "-f", "-n", "0", "-o", "cat"],
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    pending_oops = None  # (kind, addr, lines_waited)
    recently_notified = {}  # pid -> timestamp

    def already_notified(pid):
        now = time.monotonic()
        last = recently_notified.get(pid)
        if last is not None and now - last < DEDUP_WINDOW_SECONDS:
            return True
        recently_notified[pid] = now
        return False

    for line in proc.stdout:
        line = line.rstrip("\n")

        if pending_oops is not None:
            kind, addr, lines_waited = pending_oops
            m = OOPS_COMM_RE.search(line)
            if m:
                notify(
                    f"Kernel Oops: {kind}",
                    f"Process: {m.group('comm')} (PID {m.group('pid')})\n"
                    f"Fault address: {addr}\n"
                    "This is a kernel-level fault, not just an app crash — "
                    "check `cat /proc/sys/kernel/tainted` and "
                    "`journalctl -k -b0 | grep Oops`.",
                    urgency="critical",
                    persistent=True,
                )
                pending_oops = None
            elif lines_waited + 1 >= OOPS_COMM_LOOKAHEAD:
                notify(
                    f"Kernel Oops: {kind}",
                    f"Fault address: {addr}\n"
                    "Process could not be identified — see "
                    "`journalctl -k -b0 | grep -A5 Oops` for details.",
                    urgency="critical",
                    persistent=True,
                )
                pending_oops = None
            else:
                pending_oops = (kind, addr, lines_waited + 1)
            continue

        m = OOPS_RE.search(line)
        if m:
            pending_oops = (m.group("kind"), m.group("addr"), 0)
            continue

        m = COREDUMP_RE.search(line)
        if m:
            pid, comm = m.group("pid"), m.group("comm")
            if already_notified(pid):
                continue
            details = coredump_details(pid)
            body = f"PID {pid} crashed and dumped core."
            if details:
                body += f"\n{details}"
            notify(f"Crash: {comm}", body, urgency="normal")
            continue

        m = SEGFAULT_RE.search(line)
        if m:
            pid = m.group("pid")
            if already_notified(pid):
                continue
            lib = m.group("lib") or "unknown location"
            notify(
                f"Segfault: {m.group('comm')}",
                f"PID {pid} crashed in {lib}\n"
                f"addr={m.group('addr')} error={m.group('err')}",
                urgency="normal",
            )
            continue


if __name__ == "__main__":
    main()
