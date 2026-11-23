#!/usr/bin/env python3
"""
Verify the patch state of two Samsung/ACL-relevant kernel LPEs directly in an
Android boot image, without trusting `uname -r` or the build's SPL string:

  CVE-2026-98260  exec: cleanup POSIX CPU timers right after de_thread()
  CVE-2026-43499  rtmutex: use waiter::task instead of current in remove_waiter()

Method (both checks are structural, not string based):

  * 98260: in fs/exec.c:begin_new_exec() the fix moves the
    posix_cpu_timers_exit()/exit_itimers() block to directly after
    de_thread(), i.e. *before* unshare_files()/set_mm_exe_file()/exec_mmap().
    If the call still sits after those fallible calls, the build is vulnerable.

  * 43499: in kernel/locking/rtmutex.c:remove_waiter() the fix replaces
    `current->pi_lock` / `current->pi_blocked_on` with `waiter->task`.
    The vulnerable form therefore has to materialise `current` via
    `mrs <reg>, SP_EL0` before taking pi_lock; the fixed form loads
    waiter->task and never reads SP_EL0.

Usage:
    ./verify-boot-image.py boot.img
    ./verify-boot-image.py AP_*.tar.md5          # boots .tar.md5, takes boot.img.lz4
    ./verify-boot-image.py boot.img --keep       # keep extracted kernel/ELF

Requires: python3, vmlinux-to-elf, llvm-objdump (or an aarch64 objdump).
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

PAGE = 4096
BOOT_MAGIC = b"ANDROID!"


def die(msg: str) -> "NoReturn":
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def find_tool(*names: str) -> str:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    die(f"none of {names} found in PATH")


def read_boot_kernel(path: str) -> bytes:
    """Return the raw kernel blob from an Android boot image (header v2-v4)."""
    with open(path, "rb") as f:
        hdr = f.read(4096)
        if hdr[:8] != BOOT_MAGIC:
            die(f"{path}: not an Android boot image (magic {hdr[:8]!r})")
        kernel_size, ramdisk_size = struct.unpack_from("<II", hdr, 8)
        header_version = struct.unpack_from("<I", hdr, 40)[0]
        os_version = struct.unpack_from("<I", hdr, 16)[0]
        if header_version < 2:
            page = struct.unpack_from("<I", hdr, 36)[0] or PAGE
        else:
            page = PAGE
        f.seek(page)
        kernel = f.read(kernel_size)
        if len(kernel) != kernel_size:
            die(f"{path}: truncated kernel ({len(kernel)}/{kernel_size})")
        return kernel, os_version, ramdisk_size


def decode_spl(os_version: int) -> str:
    year = 2000 + ((os_version >> 4) & 0x7F)
    month = os_version & 0xF
    major = (os_version >> 25) & 0x7F
    minor = (os_version >> 18) & 0x7F
    patch = (os_version >> 11) & 0x7F
    return f"android {major}.{minor}.{patch}, patch level {year:04d}-{month:02d}"


def extract_config(kernel: bytes) -> dict[str, str]:
    """Pull the IKCONFIG blob out of the kernel image, if present."""
    start = kernel.find(b"IKCFG_ST")
    end = kernel.find(b"IKCFG_ED")
    if start < 0 or end < start:
        return {}
    import gzip

    try:
        text = gzip.decompress(kernel[start + 8 : end]).decode("utf-8", "replace")
    except OSError as exc:
        print(
            f"warning: IKCONFIG present but not decompressible: {exc}", file=sys.stderr
        )
        return {}
    cfg = {}
    for line in text.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            k, v = line.split("=", 1)
            cfg[k] = v
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            cfg[line[2:-11]] = "n"
    return cfg


def recover_symbols(kernel_path: str, workdir: str) -> str:
    tool = find_tool("vmlinux-to-elf")
    out_elf = os.path.join(workdir, "vmlinux.elf")
    res = subprocess.run(
        [tool, kernel_path, out_elf],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=900,
    )
    if res.returncode != 0 or not os.path.exists(out_elf):
        die("vmlinux-to-elf failed:\n" + res.stdout[-2000:])
    return out_elf


def symbol_table(elf: str, objdump: str) -> dict[str, int]:
    """address -> name, recovered from kallsyms."""
    res = subprocess.run(
        [objdump, "-t", elf],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    syms: dict[str, int] = {}
    for line in res.stdout.splitlines():
        # llvm-objdump -t: "<addr> l  F .kernel <size> <name>"
        parts = line.split()
        if len(parts) < 3 or not re.fullmatch(r"[0-9a-fA-F]{8,16}", parts[0]):
            continue
        name = parts[-1]
        if not re.fullmatch(r"[A-Za-z0-9_.$]+", name):
            continue
        addr = int(parts[0], 16)
        syms.setdefault(name, addr)
        if "." in name:
            syms.setdefault(name.split(".")[0], addr)
    return syms


def disasm(elf: str, objdump: str, start: int, stop: int) -> list[tuple[int, str]]:
    res = subprocess.run(
        [
            objdump,
            "-d",
            "--no-show-raw-insn",
            f"--start-address=0x{start:x}",
            f"--stop-address=0x{stop:x}",
            elf,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    insns = []
    for line in res.stdout.splitlines():
        m = re.match(r"^\s*([0-9a-f]{8,16}):\s+(.+)$", line)
        if m:
            insns.append((int(m.group(1), 16), m.group(2).strip()))
    return insns


def next_symbol(syms: dict[str, int], addr: int, limit: int) -> int:
    cands = [a for a in syms.values() if addr < a <= addr + limit]
    return min(cands) if cands else addr + limit


def call_targets(insns: list[tuple[int, str]]) -> list[tuple[int, int]]:
    """[(insn_addr, target_addr)] for every direct `bl`."""
    out = []
    for addr, text in insns:
        m = re.match(r"bl\s+0x([0-9a-f]+)", text)
        if m:
            out.append((addr, int(m.group(1), 16)))
    return out


def check_98260(elf: str, objdump: str, syms: dict[str, int]) -> tuple[str, list[str]]:
    if "begin_new_exec" not in syms:
        return "UNKNOWN", ["begin_new_exec symbol not recovered"]
    start = syms["begin_new_exec"]
    stop = next_symbol(syms, start, 0x1000)
    insns = disasm(elf, objdump, start, stop)
    calls = call_targets(insns)
    by_addr = {a: n for n, a in syms.items()}

    def first_call(name: str) -> int | None:
        target = syms.get(name)
        if target is None:
            return None
        for addr, tgt in calls:
            if tgt == target:
                return addr
        return None

    posix = first_call("posix_cpu_timers_exit")
    guards = {
        n: first_call(n)
        for n in (
            "unshare_files",
            "set_mm_exe_file",
            "exec_mmap",
            "exec_task_namespaces",
        )
    }
    notes = [f"begin_new_exec @ 0x{start:x}..0x{stop:x}"]
    notes.append(f"call posix_cpu_timers_exit: {hex(posix) if posix else 'not found'}")
    for n, a in guards.items():
        if a is not None:
            notes.append(f"call {n}: 0x{a:x}")
    if posix is None:
        return "UNKNOWN", notes + ["cleanup call not found; inspect manually"]

    first_guard = (
        min(a for a in guards.values() if a is not None)
        if any(guards.values())
        else None
    )
    if first_guard is not None and posix < first_guard:
        return "PATCHED", notes + ["cleanup runs before the fallible exec steps"]
    return "VULNERABLE", notes + ["cleanup still runs after unshare_files/exec_mmap"]


def check_43499(elf: str, objdump: str, syms: dict[str, int]) -> tuple[str, list[str]]:
    if "remove_waiter" not in syms:
        return "UNKNOWN", ["remove_waiter symbol not recovered"]
    start = syms["remove_waiter"]
    stop = next_symbol(syms, start, 0x300)
    insns = disasm(elf, objdump, start, stop)
    notes = [f"remove_waiter @ 0x{start:x}..0x{stop:x}"]

    # The vulnerable code needs `current` for raw_spin_lock(&current->pi_lock),
    # which on arm64 is `mrs <reg>, SP_EL0`. The fixed code uses waiter->task.
    mrs = [(a, t) for a, t in insns[:48] if re.search(r"\bmrs\b.*\bSP_EL0\b", t)]
    if mrs:
        notes.append(f"mrs SP_EL0 at 0x{mrs[0][0]:x} (reads current)")
        return "VULNERABLE", notes
    notes.append("no SP_EL0 read before pi_lock; waiter->task used")
    return "PATCHED", notes


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "image", help="boot.img or an Odin AP tar.md5 containing boot.img.lz4"
    )
    ap.add_argument("--keep", action="store_true", help="keep the working directory")
    ap.add_argument("--objdump", default=None)
    args = ap.parse_args()

    objdump = args.objdump or find_tool(
        "llvm-objdump", "aarch64-linux-gnu-objdump", "objdump"
    )
    workdir = tempfile.mkdtemp(prefix="a5560-verify-")
    try:
        src = args.image
        if src.endswith(".tar.md5") or src.endswith(".tar"):
            subprocess.run(["tar", "-xf", src, "boot.img.lz4"], cwd=workdir, check=True)
            lz4 = find_tool("lz4")
            subprocess.run(
                [
                    lz4,
                    "-d",
                    "-f",
                    os.path.join(workdir, "boot.img.lz4"),
                    os.path.join(workdir, "boot.img"),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            src = os.path.join(workdir, "boot.img")

        kernel, os_version, ramdisk = read_boot_kernel(src)
        print(f"boot image : {args.image}")
        print(f"kernel     : {len(kernel)} bytes, ramdisk {ramdisk} bytes")
        print(f"boot header: {decode_spl(os_version)}")

        cfg = extract_config(kernel)
        interesting = [
            "CONFIG_POSIX_TIMERS",
            "CONFIG_POSIX_CPU_TIMERS_TASK_WORK",
            "CONFIG_FUTEX_PI",
            "CONFIG_MODULES",
            "CONFIG_MODULE_SIG_FORCE",
            "CONFIG_MODULE_SIG_PROTECT",
            "CONFIG_MODVERSIONS",
            "CONFIG_KPROBES",
            "CONFIG_KALLSYMS_ALL",
            "CONFIG_KASAN_HW_TAGS",
            "CONFIG_ARM64_MTE",
            "CONFIG_CFI_CLANG",
            "CONFIG_PANIC_ON_OOPS",
            "CONFIG_RKP",
            "CONFIG_KDP_CRED",
            "CONFIG_SECURITY_DEFEX",
            "CONFIG_FIVE",
            "CONFIG_PROCA",
            "CONFIG_STATIC_USERMODEHELPER",
            "CONFIG_STATIC_USERMODEHELPER_PATH",
        ]
        print("config     :")
        for k in interesting:
            if k in cfg:
                print(f"  {k}={cfg[k]}")

        kernel_path = os.path.join(workdir, "kernel.img")
        with open(kernel_path, "wb") as f:
            f.write(kernel)

        print("recovering kallsyms (this takes a minute on a 40 MB Image)...")
        elf = recover_symbols(kernel_path, workdir)
        syms = symbol_table(elf, objdump)
        print(f"symbols    : {len(syms)}")

        v98260, n1 = check_98260(elf, objdump, syms)
        v43499, n2 = check_43499(elf, objdump, syms)
        print()
        print(f"CVE-2026-98260 (exec POSIX CPU timer UAF): {v98260}")
        for n in n1:
            print(f"  - {n}")
        print(f"CVE-2026-43499 (rtmutex GhostLock):        {v43499}")
        for n in n2:
            print(f"  - {n}")

        if v98260 == "VULNERABLE":
            print("\n=> a runtime (no-flash) root primitive exists on this image.")
            print("   KernelSU cannot install itself here; it must be late-loaded")
            print("   after the exploit gives uid 0 (see device/a5560zj1/README.md).")
        elif v98260 == "PATCHED":
            print("\n=> this image is patched against CVE-2026-98260.")
        else:
            print("\n=> inconclusive; inspect the disassembly noted above.")
    finally:
        if args.keep:
            print(f"\nworking dir kept: {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
