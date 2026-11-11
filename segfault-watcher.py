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
# which is set from siginfo.code. So ExceptionFlags *is* si_code verbatim,
# though stored as a uint32 (see describe_chrome_dump).
# The positive codes mean different things per signal (SIGILL code 2 is
# ILL_ILLOPN, not SEGV_ACCERR), so these names only apply to SIGSEGV.
SEGV_CODE_NAMES = {
    1: "SEGV_MAPERR",
    2: "SEGV_ACCERR",
    3: "SEGV_BNDERR",
    4: "SEGV_PKUERR",
}
# "Who sent it" codes, the same for every signal.
SENDER_CODE_NAMES = {
    0: "SI_USER",
    128: "SI_KERNEL",
    -6: "SI_TKILL",
}
SI_KERNEL = 128
SI_TKILL = -6

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
# The display engine's firmware (DMCUB) erroring, or a frame flip timing out.
# Seen together right before the 2026-11-10 hard freeze: the screen stopped
# updating while the kernel itself kept running.
DISPLAY_ENGINE_RE = re.compile(
    r"amdgpu \S+: \[drm\] \*ERROR\* .*(?P<what>DMCUB error|flip_done timed out)"
)

# How many lines to keep looking for the Comm: follow-up after an Oops line,
# before giving up and notifying without a process name.
OOPS_COMM_LOOKAHEAD = 5

# How long (seconds) to suppress a duplicate notification for the same PID,
# since a single crash typically logs both a kernel "segfault at" line and a
# systemd-coredump "dumped core" line.
DEDUP_WINDOW_SECONDS = 5

# Display-engine errors arrive in bursts (18 DMCUB lines in ~40s during the
# 2026-11-10 freeze), so notify once per burst rather than once per line.
DISPLAY_ENGINE_COOLDOWN_SECONDS = 600


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


def si_code_name(signal_name, si_code):
    if si_code in SENDER_CODE_NAMES:
        return SENDER_CODE_NAMES[si_code]
    if signal_name == "SIGSEGV":
        return SEGV_CODE_NAMES.get(si_code, str(si_code))
    return str(si_code)


def is_chrome_debug_trap(signal_name, si_code, addr):
    """SIGTRAP + SI_KERNEL + null address is how Chrome self-triggers a debug
    dump, so it shares SI_KERNEL with the hardware pattern but is harmless."""
    return signal_name == "SIGTRAP" and si_code == SI_KERNEL and addr == 0


def describe_chrome_dump(path):
    """Parse a Crashpad minidump and return
    (signal_name, si_code, si_code_name, addr, verdict)."""
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
    if signal_name == "SIGIOT":  # same signal number; SIGABRT is the familiar name
        signal_name = "SIGABRT"
    si_code = record.ExceptionFlags
    if si_code >= 2**31:  # stored as uint32, so SI_TKILL (-6) arrives as 4294967290
        si_code -= 2**32
    code_name = si_code_name(signal_name, si_code)
    addr = record.ExceptionAddress

    if is_chrome_debug_trap(signal_name, si_code, addr):
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
    elif si_code == SI_TKILL:
        verdict = (
            "Self-inflicted (SI_TKILL) — Chrome signaled itself, e.g. an "
            "abort or crash handler. Not the hardware pattern."
        )
    else:
        verdict = (
            f"Ordinary fault (si_code={code_name}). Rules out a CPU glitch but "
            "not bad RAM — if these cluster across unrelated programs, test the RAM."
        )

    return signal_name, si_code, code_name, addr, verdict


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

            signal_name, si_code, code_name, addr, verdict = result
            hardware = si_code == SI_KERNEL and not is_chrome_debug_trap(signal_name, si_code, addr)
            urgency = "critical" if hardware else "normal"
            notify(
                f"Chrome crash: {signal_name}",
                f"si_code={code_name}  addr=0x{addr:x}\n{verdict}",
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
    last_display_engine_notice = None  # monotonic timestamp

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

        m = DISPLAY_ENGINE_RE.search(line)
        if m:
            now = time.monotonic()
            if (
                last_display_engine_notice is not None
                and now - last_display_engine_notice < DISPLAY_ENGINE_COOLDOWN_SECONDS
            ):
                continue
            last_display_engine_notice = now
            notify(
                "GPU display engine error",
                f"amdgpu logged: {m.group('what')}\n"
                "This preceded the 2026-11-10 hard freeze. Save your work. "
                "If the screen freezes, try Ctrl+Alt+F3 before a hard reset.\n"
                "Details: `journalctl -k -b0 | grep -E 'DMCUB|flip_done'`.",
                urgency="critical",
                persistent=True,
            )
            continue


if __name__ == "__main__":
    main()
