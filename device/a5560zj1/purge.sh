#!/system/bin/sh
# Remove KernelSU data and the manager, then reboot to unload the kernel module
# (this profile cannot delete_module). Refuses if another root solution's data
# is present. Does NOT touch /data/misc/adb (the ADB key store).
set -u

if [ "$(id -u)" != "0" ]; then
    echo "purge: must run as root" >&2
    exit 1
fi

if [ -e /data/adb/magisk ] || [ -e /data/adb/magisk.db ]; then
    echo "purge: Magisk data found; refusing to delete /data/adb" >&2
    exit 1
fi

for p in ksud ksud_daemon; do
    pid="$(pidof "$p" 2>/dev/null || true)"
    if [ -n "$pid" ]; then
        kill -9 $pid 2>/dev/null || true
    fi
done

rm -rf /data/adb/ksu \
       /data/adb/modules \
       /data/adb/modules_update \
       /data/adb/metamodule \
       /data/adb/ksud \
       /data/adb/post-fs-data.d \
       /data/adb/service.d

rmdir /data/adb 2>/dev/null || true

pm uninstall me.weishu.kernelsu >/dev/null 2>&1 || \
    pm clear me.weishu.kernelsu >/dev/null 2>&1 || true

echo "purge: KernelSU data removed; rebooting to unload the kernel module"
sync
reboot
