#!/system/bin/sh
# Run as root immediately after post-load-check.sh, before handing out su.
# Removes the interfaces a root shell could use to obtain kernel R/W or to
# change the boot chain, then re-checks the guards.
#
# modules_disabled=1 is one-way until reboot: after this, `ksud unload` is no
# longer possible and the only clean exit is a reboot. That is intentional for
# a boot-scoped root.
set -u

fail=0

set_sysctl() {
	if [ -e "$1" ]; then
		if echo "$2" >"$1" 2>/dev/null; then
			echo "harden: $1 = $2"
		else
			echo "harden: FAIL cannot write $1" >&2
			fail=1
		fi
	else
		echo "harden: skip $1 (absent)"
	fi
}

# No further kernel modules: blocks a root shell from loading its own .ko.
if [ "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)" != "1" ]; then
	if echo 1 >/proc/sys/kernel/modules_disabled 2>/dev/null; then
		echo "harden: modules_disabled = 1 (unload no longer possible; reboot to exit)"
	else
		echo "harden: FAIL cannot set modules_disabled" >&2
		fail=1
	fi
fi

set_sysctl /proc/sys/kernel/kptr_restrict 2
set_sysctl /proc/sys/kernel/dmesg_restrict 1
set_sysctl /proc/sys/kernel/perf_event_paranoid 3
set_sysctl /proc/sys/kernel/unprivileged_bpf_disabled 1
set_sysctl /proc/sys/vm/unprivileged_userfaultfd 0
set_sysctl /proc/sys/kernel/yama/ptrace_scope 3

for node in /dev/mem /dev/kmem /proc/kcore; do
	if [ -e "$node" ]; then
		echo "harden: WARN $node exists; kernel memory is reachable from root" >&2
	fi
done

if [ "$(getenforce 2>/dev/null)" != "Enforcing" ]; then
	echo "harden: FAIL SELinux is not Enforcing" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	echo "harden: refusing to hand out root" >&2
	exit 1
fi

echo "harden: done"
