#!/system/bin/sh
# Run as root after the CVE-2026-98260 stage and before late-loading KernelSU.
# Arms the no-flash marker and refuses to continue on a boot chain that this
# profile was not verified against.
set -eu

PROFILE_MODEL="SM-A5560"
PROFILE_KERNEL="6.1.162-android14-11"
PROFILE_SPL="2026-10"
MARKER="/data/adb/ksu/no-flash"

fail() {
	echo "preflight: FAIL: $*" >&2
	exit 1
}

warn() {
	echo "preflight: WARN: $*" >&2
}

model="$(getprop ro.product.model 2>/dev/null || true)"
[ "$model" = "$PROFILE_MODEL" ] || fail "model is '${model}', expected ${PROFILE_MODEL}"

release="$(uname -r)"
case "$release" in
*"$PROFILE_KERNEL"*) ;;
*) fail "kernel is '${release}', expected ${PROFILE_KERNEL} (a patched or different build is out of profile)" ;;
esac

spl="$(getprop ro.build.version.security_patch 2>/dev/null || true)"
case "$spl" in
"$PROFILE_SPL"*) ;;
*) warn "security patch is '${spl}', expected ${PROFILE_SPL}: re-verify with verify-boot-image.py" ;;
esac

vbstate="$(getprop ro.boot.verifiedbootstate 2>/dev/null || true)"
case "$vbstate" in
green) ;;
orange) fail "verified boot state is orange (bootloader unlocked): this profile assumes a locked AVB chain" ;;
*) warn "verified boot state is '${vbstate}': cannot confirm the bootloader is locked" ;;
esac

locked="$(getprop ro.boot.flash.locked 2>/dev/null || true)"
case "$locked" in
1) ;;
0) fail "ro.boot.flash.locked=0: flashing is possible on this device, refusing to arm a root session" ;;
*) warn "ro.boot.flash.locked is '${locked}': proceeding, keep the no-flash rules" ;;
esac

selinux="$(getenforce 2>/dev/null || echo unknown)"
[ "$selinux" = "Enforcing" ] || warn "SELinux is '${selinux}': the late-load stage re-enables enforcing, do not reboot before it runs"

if [ -n "${STOCK_BOOT_SHA256:-}" ]; then
	for node in /dev/block/by-name/boot /dev/block/by-name/boot_a /dev/block/by-name/init_boot; do
		[ -e "$node" ] || continue
		actual="$(sha256sum "$node" | cut -d' ' -f1)"
		if [ "$actual" != "$STOCK_BOOT_SHA256" ]; then
			fail "$node hash ${actual} != stock ${STOCK_BOOT_SHA256}: the boot chain is already modified"
		fi
		echo "preflight: $node matches the stock hash"
		break
	done
fi

mkdir -p "$(dirname "$MARKER")"
: >"$MARKER"
echo "preflight: OK"
echo "  model    $model"
echo "  kernel   $release"
echo "  patch    $spl"
echo "  selinux  $selinux"
echo "  marker   $MARKER (ksud will refuse every boot/init_boot/vbmeta write)"
