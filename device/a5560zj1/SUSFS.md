# SUSFS on this device: what is portable into a late-load module

Short verdict: **the SUSFS4KSU module cannot be prebuilt into this design.** The
module repository only ships userspace helpers (`ksu_susfs`, `sus_su`) for a
kernel that has already been patched with SUSFS; its README says so in the
first line. The kernel side is a source patch, not a loadable module.

## What the kernel side actually is

`susfs4ksu` branch `gki-android14-6.1` (the 6.1 line this phone runs):
`50_add_susfs_in_gki-android14-6.1.patch`, **3438 lines, 29 files**:

```
block/ioprio.c            fs/namei.c              fs/statfs.c
drivers/input/input.c     fs/namespace.c          fs/super.c
fs/Makefile               fs/notify/fdinfo.c      kernel/kallsyms.c
fs/exec.c                 fs/open.c               kernel/reboot.c
fs/proc/base.c            fs/proc/bootconfig.c    kernel/sys.c
fs/proc/fd.c              fs/proc_namespace.c     mm/memory.c
fs/proc/task_mmu.c        fs/readdir.c            security/selinux/avc.c
fs/read_write.c           fs/stat.c               security/selinux/hooks.c
                                                   security/selinux/selinuxfs.c
                                                   security/selinux/ss/services.c
                                                   security/selinux/status.c
```

It edits internal functions directly (`lookup_fast`, `__lookup_slow`,
`walk_component`, `vfs_readlink`, `do_faccessat`, `filldir`, `ksys_read`,
`show_map_vma`, `show_vfsmnt`, `s_show`, `newuname`, `__sys_setresuid`, SELinux
hooks, ...). None of that can be dropped into a `.ko`.

## What a module can reproduce

A late-load module has exactly the primitives KernelSU already uses: syscall
table entries, the `sys_enter` tracepoint dispatcher, LSM slots, and direct
kernel data writes. Mapping SUSFS features onto those:

| SUSFS feature                | SUSFS hook site                            | In-module equivalent                                                                                                       | Coverage                                                      |
| ---------------------------- | ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `sus_path` (hide files/dirs) | `namei.c`, `readdir.c`, `open.c`, `stat.c` | syscall-table filter on `openat/openat2/faccessat/readlinkat/getdents/stat*`                                               | app-visible syscalls only; internal kernel lookups unaffected |
| `sus_mount` (hide mounts)    | `namespace.c`, `proc_namespace.c`          | avoid creating visible mounts (private mount ns, detached mounts); no reliable output filter without hooking `show_vfsmnt` | partial; `/proc/self/mounts` content only                     |
| `sus_kstat` (spoof stat)     | `stat.c`, `statfs.c`                       | syscall filter on `stat/statx/statfs`                                                                                      | partial; internal stat calls unaffected                       |
| `spoof_uname`                | `kernel/sys.c:newuname`                    | syscall hook on `uname`                                                                                                    | full for `uname(2)`                                           |
| `spoof_cmdline`              | `proc/bootconfig.c`                        | overwrite `saved_command_line` (data) or filter `read()`                                                                   | global, easy                                                  |
| `sus_map` (hide mappings)    | `task_mmu.c`                               | not needed here: this design injects nothing into app processes                                                            | —                                                             |
| `hide ksu/susfs symbols`     | `kernel/kallsyms.c:s_show`                 | data-side hiding or read filter                                                                                            | partial                                                       |
| SELinux context hiding       | `security/selinux/*`                       | not portable as a module                                                                                                   | —                                                             |
| `sus_su`                     | `fs/exec.c`, `kernel/sys.c`                | not used; KernelSU already provides `su`                                                                                   | —                                                             |
| ioprio/input filters         | `ioprio.c`, `input.c`                      | not relevant                                                                                                               | —                                                             |

The two things that matter most for banking apps — a clean boot state and no
injected code in their process — are already properties of this design:

- no partition is written, so `verifiedbootstate`, vbmeta digest and Knox stay
  untouched; hardware-backed attestation sees a stock boot chain;
- no Zygisk, no library injection, no overlay into app processes, so
  `/proc/self/maps` is clean without any hiding.

What remains detectable is the root _presence_: manager package name, the loaded
module (`/proc/modules`, `/sys/module/*`), mount entries if you mount anything,
and the usual props/paths. Those are the vectors a minimal in-module hiding
layer should cover.

## Why not just port SUSFS

- It is a 3.4k-line change spread over VFS, proc, mm and SELinux internals; as a
  module it would need text patching of those functions.
- KernelSU's Samsung-compatible line deliberately avoids live text patching
  (kprobes) on Exynos; what it does rely on, and what works, is syscall-table /
  rodata patching (its own `read`/`fstat` hooks and the dispatcher slot).
- Porting the whole patch would also import a large amount of third-party
  kernel code that you said you do not trust — with root.

## Practical recommendation

1. Do not vendor `susfs4ksu-module`; it does nothing without the kernel patch.
2. Do not vendor Zygisk Next: the current license forbids modification and
   redistribution, and injecting into app processes is the opposite of the
   hiding goal.
3. Implement a minimal hiding layer in the module, only for vectors that
   actually matter: manager package/paths, module and sysfs entries, mount
   entries you create, `uname`/cmdline spoofing, kallsyms name filtering.
4. Keep the module list empty (no third-party KSU modules). That is the biggest
   trust and detection reduction available.
5. Accept that "invisible to every detector" is not a state you can prove; the
   goal is a stock-attestation-clean device with no injected code and no
   user-visible root artifacts.

## Engineering vs real limits

| Claim                                            | Class                             | Why                                                                             |
| ------------------------------------------------ | --------------------------------- | ------------------------------------------------------------------------------- |
| No boot write, no eFuse, attestation stays clean | **real, achieved**                | nothing is persisted                                                            |
| Block-device write refusal                       | engineering                       | done in ksud + optional kernel guard                                            |
| Hide root presence                               | engineering, partial              | syscall/data level only; internal proc/VFS output needs text patching           |
| Prevent other apps from using CVE-2026-98260     | engineering, partial              | timer_create denial is in place; a pre-armed timer needs the execve check       |
| Zero residue                                     | **real limit**                    | hooks restore on unload, but the exploit can leave a parked zombie until reboot |
| Invisible to all apps                            | **not achievable as an absolute** | kernel-level detectors and continuous updates                                   |
| Zygisk Next in the fork                          | **legal blocker**                 | all rights reserved, no redistribution                                          |
