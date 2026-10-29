# Segfault Watcher

Watches the systemd journal live and fires a desktop notification the moment a kernel Oops or a process crash happens, including what crashed and why. Comes with an installer for setting it up on another machine, a helper that decodes a single crash, and (opt-in) the CPU power-management settings tried while chasing the original problem.

It was built in July 2026 to track down random segfaults and kernel general protection faults on an HP ZBook Firefly 14 G11 A (Ryzen 7 PRO 8840HS). The cause turned out to be one bad DDR5 DIMM, found in October 2026 by testing each stick on its own.

## Install (new machine or rerun)

```
./install.sh
```

Run it as your normal user, not with `sudo`. It asks for `sudo` itself, only when a system change is needed. It skips steps that are already done, so rerunning it is safe. It:

1. Installs any missing packages:
   - `systemd-coredump` captures userspace crashes with backtraces. It takes over from apport's core handler.
   - `rasdaemon` logs MCE/EDAC/PCIe hardware errors. The installer also enables its service.
   - `gdb`, used by `decode-crash.sh`.
   - `libnotify-bin`, which provides `notify-send`.
   - `python3-venv`.
   - `memtest86+` on amd64, which adds a memory-test entry to the GRUB menu.
2. Creates `.venv/` in this folder with the `minidump` parser, used to decode Chrome crash dumps.
3. Writes `~/.config/autostart/segfault-watcher.desktop`, pointing at this folder.
4. Restarts the watcher in the current desktop session.

The autostart entry points at wherever this folder lives, so if you move the folder, rerun `./install.sh`.

Requirements: Ubuntu/Debian with systemd, a desktop that honours XDG autostart, and a notification daemon (XFCE's `xfce4-notifyd`, GNOME and KDE all work).

## What the watcher catches

`segfault-watcher.py` follows `journalctl -f` and matches three patterns:

1. **Kernel Oops / general protection fault.** This is the most serious signal. It fires a critical notification that stays on screen until dismissed.
2. **`systemd-coredump` "dumped core" events.** The notification includes the signal and the top backtrace frame, taken from `coredumpctl info`.
3. **Raw kernel `segfault at ...` lines.** This is the fallback for crashes that leave no coredump.

A background thread also watches `~/.config/google-chrome/Crash Reports/completed/`. Chrome sandboxes its processes in a way that suppresses coredumps, so its own Crashpad minidumps are the only record of its crashes. The watcher decodes each new dump right away.

One crash often shows up through two of these paths, so notifications are de-duplicated by PID over a 5-second window. Every notification is also appended to `events.log`, which is never truncated. That means you can check after a crash-induced reboot what was caught.

## Triage a crash

```
./decode-crash.sh <PID | file.dmp | java_error_in_*.log>
```

- **PID**: from `coredumpctl list`. The core must still be `present`, because old ones get rotated away.
- **file.dmp**: a Chrome minidump from `~/.config/google-chrome/Crash Reports/completed/`.
- **java_error_in_*.log**: a JVM crash log, which IntelliJ writes to `~`.

It prints the signal, the `si_code` and the fault address, plus a verdict:

| Verdict | Meaning |
|---|---|
| **Hardware-fault pattern** | `si_code` is `SI_KERNEL` (128). The kernel raised the signal itself, usually a general protection fault on a garbage, non-canonical address (`TRAPNO` 13 in JVM logs). Ordinary bugs essentially never do this. |
| **Deliberate trap** | `SIGTRAP` + `SI_KERNEL` + null address. This is Chrome forcing a debug dump on purpose. |
| **Self-inflicted** | `SI_TKILL` (-6). The process signaled itself, for example through `abort()` or a crash handler. |
| **Ordinary fault** | Anything else, such as `SEGV_MAPERR` or `SEGV_ACCERR`. This rules out a CPU-execution glitch, but **not** bad RAM: a pointer corrupted at rest and then used by correct code looks identical to a real bug. A cluster of these across unrelated programs is still a reason to test the RAM. |

If `SI_KERNEL` crashes or kernel Oopses keep appearing, test the RAM before anything else. Reboot, pick the memtest86+ GRUB entry, and let it run overnight. If it finds errors, test one stick at a time to find the bad one.

## CPU power-management mitigations (opt-in)

```
./install.sh --cpu-mitigations          # apply
./install.sh --remove-cpu-mitigations   # undo, back to kernel defaults
```

These are the AMD-specific settings tried on the original machine between July and September 2026, on the theory that the CPU's own voltage/frequency transitions were corrupting data:

- `amd_pstate=passive`: the kernel governor picks P-states instead of the CPU firmware.
- **Core Performance Boost off**, persisted through `/etc/tmpfiles.d/disable-boost.conf`.
- `processor.max_cstate=1`: no idle states deeper than C1.

**None of them helped there.** The worst crash storms happened with all three active, and the real cause was a bad DIMM. Each one costs something: worse battery life, no turbo, and more heat at idle. They're kept here only for a machine where RAM has been ruled out and a CPU-side fault is still suspected.

Both flags back up `/etc/default/grub` to `/etc/default/grub.bak-<timestamp>` before editing it, then run `update-grub`. The P-state and boost changes take effect immediately, but the C-state change needs a reboot. Applying refuses to run on non-AMD CPUs.

## Manage

- **Check it's running:** `pgrep -af 'python.*segfault-watcher\.py$'`
- **See what it's caught:** `cat events.log` (use `grep -a` on it, because its em-dashes can make grep treat it as binary)
- **See its own errors:** `cat watcher.log`
- **Stop it:** `pkill -f '^[^ ]*python[0-9.]* .*segfault-watcher\.py$'`. Use this anchored pattern rather than plain `pkill -f segfault-watcher.py`, which also kills any editor or shell that has the file name in its command line.
- **Disable autostart:** `rm ~/.config/autostart/segfault-watcher.desktop`

## Known limitations

- Chrome crash decoding watches Google Chrome's profile path only, not Chromium's or Brave's.
- The watcher's own Chrome notifications name `si_code` values using the SIGSEGV table for every signal, so a `SIGILL` code 2 shows as `SEGV_ACCERR`. They also show a self-inflicted abort as `4294967290` instead of `SI_TKILL`. `decode-crash.sh` gets both right, so use it when a label matters.
