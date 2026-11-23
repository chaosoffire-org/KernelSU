#!/system/bin/sh
# Run as root after `ksud late-load`, before handing root to anything.
# Confirms the userspace lockdown is armed; kernel-side guards do not exist in
# this C-free build (see README section 7).
set -u

fail=0

need() {
    if dmesg | grep -q "$1"; then
        echo "post-load: OK   $2"
    else
        echo "post-load: FAIL $2" >&2
        fail=1
    fi
}

need "cve_guard: per-thread CPU timers denied" "CVE-2026-98260 trigger guard is live"
need "ksu_guard: restricted root active" "restricted-root guard is live"
if ! dmesg | grep -q "ksu_stealth: path hiding active"; then
    echo "post-load: WARN stealth path hiding is not active" >&2
fi

if [ -e /data/adb/ksu/no-flash ]; then
    echo "post-load: OK   no-flash marker present"
else
    echo "post-load: FAIL no-flash marker missing; run preflight.sh" >&2
    fail=1
fi

if [ "$(getenforce 2>/dev/null)" != "Enforcing" ]; then
    echo "post-load: FAIL SELinux is not Enforcing" >&2
    fail=1
fi

if [ "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)" = "1" ]; then
    echo "post-load: OK   modules_disabled=1"
else
    echo "post-load: WARN modules are still loadable; run harden.sh" >&2
fi

if [ "$(getprop ro.boot.flash.locked 2>/dev/null)" = "1" ]; then
    echo "post-load: OK   bootloader reports locked"
else
    echo "post-load: WARN ro.boot.flash.locked is not 1; do not flash anything" >&2
fi

if [ "$fail" -ne 0 ]; then
    echo "post-load: refusing to continue" >&2
    exit 1
fi

echo "post-load: userspace lockdown armed (no kernel-side guard in this build)"
