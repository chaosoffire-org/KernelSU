# SM-A5560 / A5560ZHUIEZJ1 — in-place root target

Target: **Samsung Galaxy A55 5G, SM-A5560, CSC TGY**, firmware
`A5560ZHUIEZJ1/A5560OZSIEZJ1/A5560ZCUIEZJ1/A5560ZHUIEZJ1` (built 2026-10-06).

Constraint: root **in place** — no partition writes, no boot-image flash, no
Samsung Knox warranty-bit (eFuse) trip. This directory is the device profile
for that constraint. It does not contain the exploit; it records what was
verified about this exact boot image, and it implements the no-flash lockdown
that keeps a late-loaded root from ever writing `boot`/`init_boot`/`vbmeta`.

Status: CVE identification and patch-state verification are done for
`A5560ZHUIEZJ1`. The exploit itself is third-party and not included. The
no-flash lockdown is userspace-only (ksud hard refusal, preflight marker).
The CVE trigger is closed in-kernel by a minimal C entry plus a pure-Rust
policy (section 7). A SUSFS feasibility assessment is in `SUSFS.md`.

## 1. What the image actually is

Extracted from `AP_A5560ZHUIEZJ1_..._meta_OS17.tar.md5`, `boot.img.lz4`:

|                   |                                                                    |
| ----------------- | ------------------------------------------------------------------ |
| Kernel            | `Linux version 6.1.162-android14-11`                               |
| Vermagic          | `6.1.162-android14-11 SMP preempt mod_unload modversions aarch64`  |
| Built             | Tue Oct 6 04:58:27 UTC 2026, Android clang 17.0.2 / LLD 17.0.2     |
| boot image header | v4, `os_version` = Android 14.0.0, **patch level 2026-10**         |
| KMI               | `android14-6.1` (Samsung ACK `android14-11` branch, NOT 5.15/5.10) |
| Config            | embedded IKCONFIG, 9301 lines (`kernel.config` here)               |

Relevant config: `CONFIG_POSIX_TIMERS=y`, `CONFIG_POSIX_CPU_TIMERS_TASK_WORK=y`,
`CONFIG_FUTEX_PI=y`, `CONFIG_MODULES=y`, `CONFIG_MODVERSIONS=y`,
`CONFIG_MODULE_SIG=y`, `CONFIG_MODULE_SIG_FORCE=n`, `CONFIG_MODULE_SIG_PROTECT=y`,
`CONFIG_KPROBES=y`, `CONFIG_KALLSYMS_ALL=y`, `CONFIG_DEBUG_INFO_BTF=y`,
`CONFIG_CFI_CLANG=y`, `CONFIG_KASAN_HW_TAGS=y`, `CONFIG_ARM64_MTE=y`,
`CONFIG_PANIC_ON_OOPS=y`, `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y`,
`CONFIG_STATIC_USERMODEHELPER=y` (path `""`), and the full Samsung stack:
`CONFIG_RKP=y`, `CONFIG_KDP=y`, `CONFIG_KDP_CRED=y`, `CONFIG_SECURITY_DEFEX=y`
(+ `_USER`, `_IMR_V2`, `_LINK_PROTECTION`), `CONFIG_FIVE=y`, `CONFIG_PROCA=y`.

## 2. CVE status, verified in the binary

Run `./verify-boot-image.py /path/to/boot.img`. It recovers kallsyms with
`vmlinux-to-elf` and inspects the compiled control flow, so it is independent of
`uname -r` and of Samsung's backport-without-bumping-SUBLEVEL habit.

Current result on the pinned AP:

```
CVE-2026-98260 (exec POSIX CPU timer UAF): VULNERABLE
  - call posix_cpu_timers_exit: ...0x3ab990
  - call unshare_files:        ...0x3ab8f0
  - call set_mm_exe_file:      ...0x3ab914
  - call exec_mmap:            ...0x3ab950
CVE-2026-43499 (rtmutex GhostLock):        PATCHED
```

- **CVE-2026-98260** — `exec: Cleanup POSIX timers right after de_thread()`,
  introduced in 5.7, fixed upstream only in 6.1.191 (`f6c93e8ecaaf`), 6.6.158,
  6.12.112, 6.18.54, 7.2.8. This image is 6.1.162 and still calls
  `posix_cpu_timers_exit()` **after** `unshare_files()` / `set_mm_exe_file()` /
  `exec_mmap()`. The fix moves that block directly behind `de_thread()`, i.e.
  before the fallible steps; it is absent here. Samsung's SMR lists do not
  mention the CVE at all (checked SMR-JAN…NOV-2026), so no vendor backport.
  No capabilities and no user namespaces are needed: a per-thread
  `CLOCK_THREAD_CPUTIME_ID` timer plus a `SIGKILL` that interrupts `exec_mmap()`
  is enough to leave a freed `k_itimer` node queued in a live task.

- **CVE-2026-43499** ("GhostLock") — `remove_waiter()` here loads
  `waiter->task` (`ldr x20, [x23, #0x30]`, `add x22, x20, #0x924`,
  `str xzr, [x20, #0x950]`) and never reads `SP_EL0`, i.e. the fixed form.
  Consistent with SMR-OCT-2026, which does list CVE-2026-43499. Do not spend
  time on this one.

So the in-place primitive for this build is **CVE-2026-98260**.

## 3. Why KernelSU cannot install itself

Every upstream install mode writes a boot partition and requires an unlocked
bootloader: GKI image mode (discontinued in v3.0) replaces the kernel, LKM mode
patches `boot`/`init_boot` and flashes it, built-in mode rebuilds the kernel.
KernelSU's own docs additionally state that LKM mode cannot work on
Knox-enabled Samsung devices. One UI 8/9 also removed the OEM-unlock toggle on
many models.

What does work is KernelSU's **late-load ("Jailbreak") mode**: nothing is
written, `ksud late-load` inserts the module into the running kernel after
something else has already obtained uid 0. That "something else" is the
CVE-2026-98260 chain. This is the same architecture used by the public
temporary-root projects for 6.1.162 Samsung builds.

## 4. Chain on this device

1. Run the CVE-2026-98260 payload from an app context (public references:
   `RiosWesley/SamTimer`, `NanoTurtle1145/root-my-s24`, `ylh440104/
InfinityCore-Android-CVE-2026-98260`). It gives a kernel read/write and a
   `call_usermodehelper` execution path; it deliberately does **not** rewrite
   `cred`, which is what keeps it clear of DEFEX PED and KDP credential
   protection.
2. From that root context, late-load a Samsung-compatible `kernelsu.ko`
   (3.2.5 KDP/RKP/DEFEX-patched line; 3.3.x panics on this kernel) with
   `ksud late-load`.
3. Use the matching official KernelSU manager. `su` then works until reboot.

Nothing persistent is written: `ro.boot.flash.locked` stays 1, the warranty bit
stays 0, and a reboot returns the device to a clean unrooted state. Samsung
documents the eFuse as set by Trusted Boot when it detects an unsigned kernel or
disabled SELinux at boot, neither of which this path does.

## 5. What is still missing for SM-A5560

This is a different kernel build from the S24/S25 targets the public payloads
were calibrated on. To make the chain work here:

- **Kernel build number.** The public tools key coverage on the build id inside
  `uname -r` (e.g. `6.1.162-android14-11-34343818-ab...`), not on the firmware
  string. Read it from the device; this boot image only exposes the
  `6.1.162-android14-11` prefix.
- **Per-target calibration.** KASLR slide derivation, `task_struct`/`cred`/
  `k_itimer` offsets, and the write primitive's site addresses must be rebuilt
  for this image. `CONFIG_DEBUG_INFO_BTF=y` means the BTF blob is available for
  exact struct offsets; kallsyms is recovered by the verifier here.
- **Component-specific work.** Exynos needs the no-live-text-patch build of the
  KernelSU module (patching text on Exynos EL2 panics); the module must carry
  KDP_CRED/RKP/DEFEX/FIVE/PROCA compatibility; and it must be built against the
  A55 kernel tree so vermagic and symbol CRCs match (`CONFIG_MODVERSIONS=y`).

Samsung publishes the matching kernel source for this build as
`SM-A556B_17_Opensource.zip` (release entry upload id 14364 on
opensource.samsung.com, alongside `SM-A5560_CHN_17_Opensource_dts.zip`). Build
the module against that tree with the extracted `kernel.config`, not against a
generic GKI tree.

Do **not** use the manager's "install/flash" buttons in this mode: that writes
`boot` and is the one action guaranteed to break AVB on a locked bootloader.

## 6. No-flash lockdown (userspace + kernel)

**Layer 1 — ksud hard refusal (verified).** `userspace/ksud/src/lockdown.rs`
plus guards in `userspace/ksud/src/boot_patch.rs`. When KernelSU is
late-loaded, or the marker `/data/adb/ksu/no-flash` exists:

- `boot-patch --flash`, `boot-restore --flash` and the v2 `boot-patch-v2`
  output are refused before any partition or `/dev/*` target is opened;
- `flash_partition()` refuses on entry, so no caller can bypass it;
- writing the generated image to any `/dev/*` path is refused.

No override flag. `cargo check` / `cargo clippy` are clean.

**Layer 2 — preflight (`preflight.sh`).** Root, before late-loading. Fails
unless the model is `SM-A5560`, `uname -r` contains `6.1.162-android14-11`,
`verifiedbootstate` is green and `ro.boot.flash.locked` is not 0; then arms the
marker. Can compare the live boot partition against `STOCK_BOOT_SHA256`.
Syntax-checked with `sh -n`.

**Layer 3 — kernel (`ksu_guard.c`, section 8).** For processes in the KSU
SELinux domain, `file_open`/`file_permission`/`mmap_file` deny write access to
block devices. This covers a root shell, and it also covers ksud itself, so a
manager "install" cannot reach the boot partition even if the userspace guard
were bypassed. Normal Android (vold, update_engine, OTA) is not in that domain
and is unaffected.

## 7. CVE trigger mitigation (pure C, compile-verified)

The earlier Rust experiment was dropped: the policy is five lines, so it lives
in C next to the syscall entry.

`kernel/feature/cve_guard.c`:

- `cve_guard_entry()` is the syscall-table function. It must be clang-built:
  kCFI (`CONFIG_CFI_CLANG=y`, non-permissive) checks the 4-byte type hash
  before every indirect call; the built object carries `0xb02b34d9` before the
  entry.
- It denies `CLOCK_THREAD_CPUTIME_ID` and every encoded per-thread CPU clock
  (`clockid & 4`), for all processes, root included. The kernel accepts the
  encoded `make_thread_cpuclock()` form from userspace, so checking only
  clockid 3 would be bypassable.
- Native and compat (`compat_sys_call_table[257]`) slots are patched; the
  compat slot is verified to hold `timer_create` before patching.
- No allocation, no user pointers, originals null-checked, patches verified by
  read-back, compat slot restored on exit.

Installed from `kernelsu_init()` right after `ksu_syscall_hook_init()` and
before `escape_to_root_for_init()`, so it is live before su can answer.
Mitigation, not a fix: a per-thread timer armed before load is not removed.

## 8. Restricted root (implemented)

Assumption: KSU is the only root provider; the loader runs before the module.

**Capabilities come from the app profile (kernel-enforced).** KernelSU's
`struct root_profile` already carries `capabilities.effective/permitted/
inheritable`, and `escape_with_root_profile()` copies them into the new cred,
including `cap_bset`. The manager exposes this as profile/template
capabilities (`TemplateInfo.capabilities`), so no custom `--ksu-caps` is
needed.

This fork adds two kernel-side guarantees on top:

- `init_default_profiles()` starts from `CAP_FULL_SET` and calls
  `ksu_clamp_default_caps()`, so a su shell **without** a profile keeps
  DAC/KILL/NET_*/SETUID but has no `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`,
  `CAP_SYS_RAWIO`, `CAP_MKNOD`, `CAP_MAC_*`, `CAP_SETPCAP`, `CAP_BPF`,
  `CAP_PERFMON` or `CAP_CHECKPOINT_RESTORE`.
- `escape_with_root_profile()` clamps only the brick/kernel-write caps
  (`SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `MKNOD`, `MAC_*`, `SETPCAP`) out of
  every profile's effective/permitted/bset/inheritable/ambient **even if the
  template asks for them**. `CAP_BPF`/`CAP_PERFMON`/`CAP_CHECKPOINT_RESTORE`
  are profile-grantable, and the SELinux domain is forced to `u:r:ksu:s0` so
  the kernel guard's domain scope cannot be escaped by a profile.

Practical templates:

| Profile | Extra caps | Use |
|---|---|---|
| default | none (NET_ADMIN/NET_RAW already kept) | TProxy / iptables / ip rule |
| `ebpf` | add `CAP_BPF` | TC/XDP program load; `CAP_NET_ADMIN` for attach |
| never possible | SYS_ADMIN, SYS_MODULE, SYS_RAWIO, MKNOD, MAC_*, SETPCAP | removed by the clamp |

The profile key is the requesting app's uid. If sing-box is started from a
terminal, configure that terminal's profile; if it ships as its own app/uid,
give that uid the profile.

`su -Z` is rejected: the domain is fixed to `u:r:ksu:s0` by the kernel clamp.

**Kernel backstop (`kernel/feature/ksu_guard.c`).** For the KSU domain:

| Operation | Enforcement |
|---|---|
| open block device for write | `file_open` → `-EPERM` |
| `write()` on a block device | `file_permission` → `-EPERM` |
| `mmap(PROT_WRITE)` on a block device | `mmap_file` → `-EPERM` |
| `init_module` / `finit_module` | syscall hook → `-EPERM` |
| `mount`, `mknod`, `bpf`, `perf`, `setns` | no capability (cap drop) |

`delete_module` is deliberately allowed so ksud can still unload cleanly; the
su shell has no `CAP_SYS_MODULE` and cannot.

**What a su shell can still do:** read/write `/data` (DAC override stays),
manage processes, use network capabilities, ptrace within policy, reboot. It
cannot flash, mount, load a module, or create device nodes.

## 9. Hiding and the app list (design, not implemented)

Two different problems are often conflated:

1. **Root artifacts** — paths, mounts, module presence, symbols. A kernel
   module can hide these (this is what SUSFS does: `sus_path`, `sus_mount`,
   `sus_kstat`, uname/cmdline, maps, kallsyms). It needs syscall/VFS-level
   filtering and is a real project; none of it is implemented here yet.
2. **The installed-app list** — what `PackageManager.getInstalledPackages()`
   returns. This is **not** file-based and cannot be fixed by a kernel module.
   PackageManager lives in system_server, keeps the list in memory, and apps
   query it over Binder. A kernel hook would have to parse Binder parcels and
   rewrite replies for framework-version-specific transaction codes; that is
   fragile and will crash system_server. SUSFS does not do it either.

So a "built-in module that hides the app list" is not implementable as a
kernel module. The options are:

- **Reduce the target**: build the manager with a random package name and no
  launcher icon (`KSU_PACKAGE_NAME`), so casual package-name checks fail. Apps
  holding `QUERY_ALL_PACKAGES` still see it.
- **Hide artifacts** (phase 1 above): `/data/adb/ksu`, module dirs, manager APK
  path, `/proc/modules`, `/sys/module/kernelsu`, mountinfo, kallsyms names.
  This defeats file/string scanners, not package enumeration.
- **Framework hook** (LSPosed/HMA-style) if app-list hiding is mandatory. That
  is code injection into system_server/apps, with its own detection surface;
  it contradicts the no-injection design.
- Android 11+ package visibility already hides packages from apps without
  `QUERY_ALL_PACKAGES`; you cannot revoke that permission per-app from the
  kernel.

Recommendation: do phase 1 (artifact hiding) and package-name obfuscation; do
not promise app-list hiding in a kernel module.

## 10. Risk notes

- The timer UAF is probabilistic. A failed run can leave the device unstable
  until reboot; run once per boot and reboot after a failure.
- `CONFIG_PANIC_ON_OOPS=y` turns a bad dereference into an immediate panic.
- `CONFIG_CFI_CLANG=y` (kCFI) rejects indirect-call targets; the write primitive
  must stay data-only.
- This is boot-scoped root, not persistence. That is the price of not touching
  the boot chain.

## References

- CVE-2026-98260 announcement: https://lists.openwall.net/linux-cve-announce/2026/10/06/118
- Fix (6.1.191): https://git.kernel.org/stable/c/f6c93e8ecaaf12959b7ef6eb611351001db2ff5d
- CVE-2026-43499 fix used for the binary check: https://github.com/torvalds/linux/commit/3bfdc63936dd
- KernelScan entry: https://kernelscan.io/cve/CVE-2026-98260
- KernelSU late-load: `userspace/ksud/src/late_load.rs`, `kernel/core/init.c`
- Samsung Knox warranty bit: https://docs.samsungknox.com/admin/fundamentals/whitepaper/samsung-knox-mobile-security/system-security/hw-backed-security/
- Samsung SMR: https://security.samsungmobile.com/securityUpdate.smsb
