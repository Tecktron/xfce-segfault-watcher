#!/bin/bash
# Decodes one crash and says whether it matches the hardware-fault pattern
# segfault-watcher.py alerts on. See README.md ("Triage a crash") for how to
# read the verdicts.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<'EOF'
Usage: decode-crash.sh <PID | file.dmp | java_error_in_*.log>

  PID                  a coredump PID from `coredumpctl list` (newest dump
                       for that PID if it was reused)
  file.dmp             a Chrome Crashpad minidump, e.g. from
                       ~/.config/google-chrome/Crash Reports/completed/
  java_error_in_*.log  a JVM hs_err crash log (IntelliJ etc.)
EOF
}

# si_code numbers are signal-specific except the negative/128 "who sent it"
# codes, so the SEGV_* names only apply to SIGSEGV.
code_name() {
    local sig=$1 code=$2
    case "$code" in
        128) echo SI_KERNEL; return ;;
        -6)  echo SI_TKILL; return ;;
        0)   echo SI_USER; return ;;
    esac
    if [[ $sig == SIGSEGV ]]; then
        case "$code" in
            1) echo SEGV_MAPERR; return ;;
            2) echo SEGV_ACCERR; return ;;
            3) echo SEGV_BNDERR; return ;;
            4) echo SEGV_PKUERR; return ;;
        esac
    fi
    echo "$code"
}

verdict() {
    local sig=$1 code=$2 addr=$3
    case "$code" in
        SI_KERNEL|128)
            if [[ $sig == SIGTRAP && $addr =~ ^(0x)?0+$ ]]; then
                echo "VERDICT: deliberate trap (SIGTRAP + SI_KERNEL + null address) - Chrome's own"
                echo "         debug-dump mechanism, not memory corruption."
            else
                echo "VERDICT: MATCHES THE HARDWARE-FAULT PATTERN (SI_KERNEL). The kernel raised this"
                echo "         itself, typically a general protection fault on a non-canonical address."
                echo "         Ordinary software bugs essentially never produce this. Take it seriously."
            fi
            ;;
        SI_TKILL|-6)
            echo "VERDICT: self-inflicted (SI_TKILL) - the process signaled itself via"
            echo "         pthread_kill/tgkill, e.g. an abort or crash handler. Not hardware."
            ;;
        *)
            echo "VERDICT: ordinary fault ($code). Rules out a CPU-execution glitch, but NOT bad"
            echo "         RAM: a pointer bit-flipped at rest and then used by correct code looks"
            echo "         exactly like this. If these cluster across unrelated programs, test the RAM."
            ;;
    esac
}

# The single-quoted $_siginfo and $1/$2/$3 below are gdb's own syntax and
# output labels, not shell variables.
# shellcheck disable=SC2016
decode_coredump() {
    local pid=$1 out signo code addr sig
    command -v coredumpctl >/dev/null || { echo "coredumpctl not installed (package systemd-coredump)." >&2; exit 1; }
    command -v gdb >/dev/null || { echo "gdb not installed." >&2; exit 1; }

    coredumpctl info --no-pager "$pid" 2>/dev/null | grep -m3 -E '^ *(Executable|Timestamp|Signal):'

    out=$(timeout 120 coredumpctl debug --no-pager "$pid" --debugger=gdb \
        --debugger-arguments='-batch -nx -ex "p $_siginfo.si_signo" -ex "p $_siginfo.si_code" -ex "p $_siginfo._sifields._sigfault.si_addr"' 2>&1)
    signo=$(sed -n 's/^\$1 = //p' <<<"$out")
    code=$(sed -n 's/^\$2 = //p' <<<"$out")
    addr=$(sed -n 's/^\$3 = .* \(0x[0-9a-f]*\)$/\1/p' <<<"$out")
    if [[ -z $signo || -z $code ]]; then
        echo "Could not read siginfo from that coredump. Check \`coredumpctl list $pid\`:" >&2
        echo "the COREFILE column must say 'present' (old cores get rotated away)." >&2
        exit 1
    fi
    sig="SIG$(kill -l "$signo")"
    [[ -z $addr ]] && addr="0x0"

    echo
    echo "signal=$sig  si_code=$(code_name "$sig" "$code")  addr=$addr"
    # Often absent: the kernel rate-limits these messages. `grep -v '^-- '`
    # drops journalctl's boot-separator and "-- No entries --" marker lines.
    local trap_line
    trap_line=$(journalctl _TRANSPORT=kernel --no-pager -o short-iso -g "\\[$pid\\]: (segfault at|general protection)|traps: .*\\[$pid\\]" 2>/dev/null | grep -v '^-- ' | tail -1)
    [[ -n $trap_line ]] && echo "kernel: $trap_line"
    echo
    verdict "$sig" "$(code_name "$sig" "$code")" "$addr"
}

decode_minidump() {
    local file=$1 py="$SCRIPT_DIR/.venv/bin/python" result sig code addr
    [[ -x $py ]] || { echo "No .venv found - run ./install.sh first (it installs the minidump parser)." >&2; exit 1; }
    result=$("$py" - "$SCRIPT_DIR/segfault-watcher.py" "$file" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("watcher", sys.argv[1])
watcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watcher)
if watcher.MinidumpFile is None:
    sys.exit("minidump package missing from .venv - rerun ./install.sh")
r = watcher.describe_chrome_dump(sys.argv[2])
if r is None:
    sys.exit("dump has no exception record")
signal_name, si_code, _, addr, _ = r
print(signal_name, si_code, hex(addr))
PY
) || exit 1
    read -r sig code addr <<<"$result"
    echo "signal=$sig  si_code=$(code_name "$sig" "$code")  addr=$addr"
    echo
    verdict "$sig" "$(code_name "$sig" "$code")" "$addr"
}

decode_jvm_log() {
    local file=$1 line sig code addr trapno
    line=$(grep -m1 '^siginfo:' "$file")
    sig=$(sed -n 's/.*si_signo: [0-9]* (\([A-Z]*\)).*/\1/p' <<<"$line")
    code=$(sed -n 's/.*si_code: \(-\{0,1\}[0-9]*\).*/\1/p' <<<"$line")
    addr=$(sed -n 's/.*si_addr: \(0x[0-9a-fA-F]*\).*/\1/p' <<<"$line")
    trapno=$(grep -m1 -o 'TRAPNO=0x[0-9a-fA-F]*' "$file" | cut -d= -f2)

    grep -m1 -A1 '^# Problematic frame:' "$file" | tail -1
    echo "signal=$sig  si_code=$(code_name "$sig" "$code")  addr=$addr"
    if [[ -n $trapno ]]; then
        case $((trapno)) in
            13) echo "TRAPNO=13 (general protection fault - fits the hardware pattern)" ;;
            14) echo "TRAPNO=14 (ordinary page fault)" ;;
            *)  echo "TRAPNO=$((trapno))" ;;
        esac
    fi
    echo
    verdict "$sig" "$(code_name "$sig" "$code")" "$addr"
}

[[ $# -eq 1 ]] || { usage >&2; exit 2; }
case "$1" in
    -h|--help) usage ;;
    *[!0-9]*|"")
        if [[ $1 == *.dmp && -f $1 ]]; then
            decode_minidump "$1"
        elif [[ -f $1 ]] && grep -q '^siginfo:' "$1"; then
            decode_jvm_log "$1"
        else
            echo "Not a PID, a .dmp file, or a JVM crash log: $1" >&2
            usage >&2
            exit 2
        fi
        ;;
    *) decode_coredump "$1" ;;
esac
