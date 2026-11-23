# SM-A5560 / A5560ZHUIEZJ1 late-load root profile

Target: Samsung Galaxy A55 5G, SM-A5560, CSC TGY, firmware
`A5560ZHUIEZJ1` (built 2026-10-06). Root is **late-loaded and boot-scoped**:
nothing is written to any partition, and a reboot clears it.

## Verified against the shipped image

- Kernel `6.1.162-android14-11`, KMI `android14-6.1`, SPL **2026-10**.
- **CVE-2026-98260** (exec POSIX CPU timer UAF): **unpatched**. Fixed upstream
  only in 6.1.191; Samsung's 2026 SMRs do not list it.
- **CVE-2026-43499** (rtmutex GhostLock): **patched** (SMR-OCT-2026 backport).
- Re-check with `python3 verify-boot-image.py boot.img` (needs
  `vmlinux-to-elf` and `llvm-objdump`); it decodes IKCONFIG and inspects the
  compiled call order, not the version string.

## Chain

1. Third-party CVE-2026-98260 loader gets uid 0 (not included here).
2. `preflight.sh` checks model/kernel/lock state and arms the no-flash marker.
3. `ksud late-load` loads the KernelSU module.
4. `post-load-check.sh` checks the guards; `harden.sh` optionally sets
   `modules_disabled=1` and restricts sysctls.
5. Use `su`. No boot image, vbmeta or Knox fuse is touched.

## Guards in this fork

- **No-flash (ksud, Rust):** `boot-patch`/`boot-restore --flash`,
  `boot-patch-v2` output, and writes to `/dev/*` are refused in late-load.
- **CVE trigger guard (C):** `timer_create` denies `CLOCK_THREAD_CPUTIME_ID`
  and encoded per-thread CPU clocks for every process, installed before root.
- **Restricted root (C):** app profiles carry the capability mask; the kernel
  clamps `SYS_ADMIN/SYS_MODULE/SYS_RAWIO/MKNOD/MAC_*/SETPCAP` out of every
  profile and forces the KSU SELinux domain. `ksu_guard` additionally denies
  block-device write opens/writes/mmap and `init_module/finit_module` in that
  domain. Default su has no mount, no module load, no raw block writes.
- **Stealth (C, `KSU_STEALTH`):** for app uids (>= 10000) outside the KSU
  domain, `openat/openat2/newfstatat/faccessat/faccessat2/readlinkat/statx`
  return `-ENOENT` for `/data/adb/ksu`, `/data/adb/modules`,
  `/sys/module/kernelsu` and the manager directory under `/data/app/`. su,
  ksud and the manager app are exempt; system processes are untouched. The
  module is detached from `/proc/modules` (so it cannot be unloaded until
  reboot).

Known residuals: relative-path lookups, `getdents`/readdir listings,
`/proc/kallsyms`, 32-bit compat tables, the manager package in
`PackageManager`, and non-app callers such as adb shell (by design). Kernel modules cannot hide the app list; that requires a
framework hook. No claim of complete undetectability.

## Build (Samsung OSRC)

Source: `SM-A556B_17_Opensource.zip` from opensource.samsung.com (upload id
14364, attachment 48819) → kernel 6.1.162, `s5e8845`. Merge
`gki_defconfig` + `s5e8845-base_defconfig` + `s5e8845-bazel_defconfig` +
`s5e8845_user.cfg` + `s5e8845-user_defconfig`, enable `KSU`,
`KSU_CVE_2026_98260_GUARD`, `KSU_RESTRICTED_ROOT`, `KSU_STEALTH`, then:

```
export ARCH=arm64 LLVM=1
make -s olddefconfig
make -j12 drivers/kernelsu/
```

`kernel/include/uapi` is a symlink to `../../uapi`; if the KernelSU kernel
directory is copied instead of symlinked, repair it or the build stops at
`uapi/app_profile.h`.

Manager signing: `KSU_EXPECTED_SIZE=0x052f`, certificate SHA-256
`6efd8c76b150c7d9d33954e8665770c1740d323289ab362a826996544148e57f`
(alias `a5560`). The private key is kept outside the repo; CI reads it from
the `KEYSTORE` secret.

## Limits

- Module vermagic/symbol CRCs must be built with Samsung's clang-17/PGO/BOLT
  toolchain before it will load; not validated on device.
- The public CVE loaders do not cover SM-A5560; a per-build port is required.
- A per-thread timer armed before the module loads is not removed.
- No persistence, no OTA, no flashing. Reboot is the only full reset.
- TProxy/iptables and TC/XDP eBPF are available in this kernel; `NF_TABLES` is
  not, and sing-box's eBPF inbound is experimental/`with_ebpf`.

## Files

`verify-boot-image.py`, `preflight.sh`, `post-load-check.sh`, `harden.sh`,
this README.
