#!/bin/bash
# Sets up the segfault watcher on this machine: crash-diagnostics packages, a
# .venv for Chrome dump decoding, the login autostart entry, and (opt-in only)
# the CPU power-management mitigations. Safe to rerun; finished steps are
# skipped. See README.md.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PACKAGES=(systemd-coredump rasdaemon gdb libnotify-bin python3-venv)
MINIDUMP_VERSION="0.0.24"
AUTOSTART_FILE="$HOME/.config/autostart/segfault-watcher.desktop"
GRUB_FILE="/etc/default/grub"
BOOST_TMPFILE="/etc/tmpfiles.d/disable-boost.conf"
BOOST_SYSFS="/sys/devices/system/cpu/cpufreq/boost"
PSTATE_SYSFS="/sys/devices/system/cpu/amd_pstate/status"
MITIGATION_PARAMS=(amd_pstate=passive processor.max_cstate=1)
SUDO="sudo"
# Anchored to a python interpreter at the start of the command line. A bare
# `-f segfault-watcher.py` also matched anything merely mentioning the file
# (an editor, a pager, the shell that ran this script) and killed it.
WATCHER_PROC_RE='^[^ ]*python[0-9.]* .*segfault-watcher\.py$'

usage() {
    cat <<'EOF'
Usage: ./install.sh [--cpu-mitigations | --remove-cpu-mitigations]

Run as your normal user (not with sudo); it asks for sudo itself only when a
system change is actually needed.

Default: install packages (systemd-coredump, rasdaemon, gdb, libnotify-bin,
python3-venv, plus memtest86+ on amd64), create .venv with the minidump
parser, install the login autostart entry, and (re)start the watcher.

  --cpu-mitigations         ALSO apply the AMD power-management mitigations:
                            amd_pstate=passive, Core Performance Boost off,
                            C-states capped at C1. These did NOT fix the
                            original machine (bad RAM did) and they cost
                            battery life and turbo speed - see README.md.
  --remove-cpu-mitigations  Undo the above, back to kernel defaults.
EOF
}

die() { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARNING: $*" >&2; }

install_packages() {
    local wanted=("${PACKAGES[@]}") missing=() p
    # memtest86+ adds a "Memory test" GRUB menu entry, which is what finally
    # caught the bad DIMM. It's an x86-only package.
    [[ $(dpkg --print-architecture) == amd64 ]] && wanted+=(memtest86+)
    for p in "${wanted[@]}"; do
        dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || missing+=("$p")
    done
    if (( ${#missing[@]} )); then
        echo "Installing: ${missing[*]}"
        $SUDO apt-get update || warn "apt-get update failed; trying the install anyway."
        $SUDO apt-get install -y "${missing[@]}" || die "package install failed."
    else
        echo "Packages: all present."
    fi
    if systemctl is-enabled --quiet rasdaemon 2>/dev/null; then
        echo "rasdaemon: already enabled."
    else
        $SUDO systemctl enable --now rasdaemon || warn "could not enable rasdaemon."
    fi
}

setup_venv() {
    local py="$SCRIPT_DIR/.venv/bin/python"
    if "$py" -c "import minidump" 2>/dev/null; then
        echo ".venv: minidump already installed."
        return
    fi
    # --clear: a venv left over from an older system Python is broken, not reusable.
    python3 -m venv --clear "$SCRIPT_DIR/.venv" || die "could not create .venv (is python3-venv installed?)."
    "$SCRIPT_DIR/.venv/bin/pip" install --quiet "minidump==$MINIDUMP_VERSION" || die "pip install minidump failed."
    echo ".venv: created with minidump $MINIDUMP_VERSION."
}

watcher_command() {
    printf '"%s" "%s" >> "%s" 2>&1' "$SCRIPT_DIR/.venv/bin/python" \
        "$SCRIPT_DIR/segfault-watcher.py" "$SCRIPT_DIR/watcher.log"
}

install_autostart() {
    mkdir -p "$(dirname "$AUTOSTART_FILE")"
    # Older installs symlinked this file into the repo; writing through the
    # symlink would edit the repo copy instead of replacing the link.
    rm -f "$AUTOSTART_FILE"
    cat > "$AUTOSTART_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=Segfault Watcher
Comment=Watches the journal for kernel Oopses and process crashes, alerts via desktop notification
Exec=/bin/sh -c '$(watcher_command)'
Icon=dialog-warning
Terminal=false
X-GNOME-Autostart-enabled=true
EOF
    echo "Autostart: wrote $AUTOSTART_FILE"
}

start_watcher() {
    pkill -u "$USER" -f "$WATCHER_PROC_RE" && sleep 1
    if [[ -z ${DISPLAY:-}${WAYLAND_DISPLAY:-} ]]; then
        echo "Watcher: no graphical session here; it will start at your next desktop login."
        return
    fi
    setsid -f /bin/sh -c "$(watcher_command)"
    sleep 2
    if pgrep -u "$USER" -f "$WATCHER_PROC_RE" >/dev/null; then
        echo "Watcher: running."
    else
        warn "watcher did not stay up - check $SCRIPT_DIR/watcher.log"
    fi
}

grub_has_param() {
    grep -Eq "^GRUB_CMDLINE_LINUX_DEFAULT=\"([^\"]* )?${1//./\\.}( [^\"]*)?\"" "$GRUB_FILE"
}

grub_add_param() {
    $SUDO sed -i -E "s/^(GRUB_CMDLINE_LINUX_DEFAULT=\"[^\"]*)\"/\1 $1\"/; s/^(GRUB_CMDLINE_LINUX_DEFAULT=\") /\1/" "$GRUB_FILE"
}

grub_remove_param() {
    local re=${1//./\\.}
    $SUDO sed -i -E "/^GRUB_CMDLINE_LINUX_DEFAULT=/{s/([\" ])$re( |\")/\1\2/g; s/  +/ /g; s/=\" /=\"/; s/ \"$/\"/}" "$GRUB_FILE"
}

check_grub_overrides() {
    local f
    for f in /etc/default/grub.d/*.cfg; do
        [[ -f $f ]] && grep -q GRUB_CMDLINE_LINUX_DEFAULT "$f" &&
            warn "$f also sets GRUB_CMDLINE_LINUX_DEFAULT and is read after $GRUB_FILE - check it doesn't override this change."
    done
}

backup_grub() {
    local backup
    backup="$GRUB_FILE.bak-$(date +%Y%m%d-%H%M%S)"
    $SUDO cp -p "$GRUB_FILE" "$backup" || die "could not back up $GRUB_FILE."
    echo "Backed up $GRUB_FILE to $backup"
}

apply_cpu_mitigations() {
    grep -q AuthenticAMD /proc/cpuinfo || die "--cpu-mitigations is AMD-only (amd_pstate, AMD boost control)."
    command -v update-grub >/dev/null || die "update-grub not found; this expects Ubuntu/Debian GRUB."

    local p to_add=()
    for p in "${MITIGATION_PARAMS[@]}"; do
        grub_has_param "$p" || to_add+=("$p")
    done
    if (( ${#to_add[@]} )); then
        backup_grub
        for p in "${to_add[@]}"; do grub_add_param "$p"; done
        $SUDO update-grub || die "update-grub failed - restore the backup above before rebooting."
        check_grub_overrides
    else
        echo "GRUB: mitigation params already present."
    fi

    echo "w $BOOST_SYSFS - - - - 0" | $SUDO tee "$BOOST_TMPFILE" >/dev/null || die "could not write $BOOST_TMPFILE."
    [[ -e $BOOST_SYSFS ]] && echo 0 | $SUDO tee "$BOOST_SYSFS" >/dev/null
    [[ -e $PSTATE_SYSFS ]] && echo passive | $SUDO tee "$PSTATE_SYSFS" >/dev/null
    echo "CPU mitigations applied. Boost and pstate are live now; the C-state cap needs a reboot."
}

remove_cpu_mitigations() {
    local p to_remove=()
    for p in "${MITIGATION_PARAMS[@]}"; do
        grub_has_param "$p" && to_remove+=("$p")
    done
    if (( ${#to_remove[@]} )); then
        command -v update-grub >/dev/null || die "update-grub not found; this expects Ubuntu/Debian GRUB."
        backup_grub
        for p in "${to_remove[@]}"; do grub_remove_param "$p"; done
        $SUDO update-grub || die "update-grub failed - restore the backup above before rebooting."
    else
        echo "GRUB: no mitigation params present."
    fi

    [[ -e $BOOST_TMPFILE ]] && { $SUDO rm -f "$BOOST_TMPFILE" || die "could not remove $BOOST_TMPFILE."; }
    [[ -e $BOOST_SYSFS ]] && echo 1 | $SUDO tee "$BOOST_SYSFS" >/dev/null
    [[ -e $PSTATE_SYSFS ]] && echo active | $SUDO tee "$PSTATE_SYSFS" >/dev/null
    echo "CPU mitigations removed. Boost and pstate are live now; C-states return after a reboot."
}

main() {
    local mode=""
    while (( $# )); do
        case "$1" in
            --cpu-mitigations)        mode="apply" ;;
            --remove-cpu-mitigations) mode="remove" ;;
            -h|--help)                usage; exit 0 ;;
            *)                        usage >&2; exit 2 ;;
        esac
        shift
    done

    [[ $EUID -eq 0 ]] && die "run as your normal user, not root - the autostart entry belongs in your own home directory."
    local cmd
    for cmd in apt-get dpkg-query systemctl python3 setsid; do
        command -v "$cmd" >/dev/null || die "'$cmd' not found; this installer expects Ubuntu/Debian with systemd."
    done

    install_packages
    setup_venv
    chmod +x "$SCRIPT_DIR/segfault-watcher.py" "$SCRIPT_DIR/decode-crash.sh"
    install_autostart
    start_watcher

    case "$mode" in
        apply)  apply_cpu_mitigations ;;
        remove) remove_cpu_mitigations ;;
    esac

    echo
    echo "Done. Crashes are logged to $SCRIPT_DIR/events.log."
    echo "Decode one with: $SCRIPT_DIR/decode-crash.sh <PID | file.dmp | java_error_in_*.log>"
}

# Only run when executed, so the functions can be sourced for testing.
[[ "${BASH_SOURCE[0]}" == "$0" ]] && main "$@"
