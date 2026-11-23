// SPDX-License-Identifier: GPL-2.0
/*
 * CVE-2026-98260 mitigation.
 *
 * This file owns the syscall-table entry, which the kernel reaches through a
 * kCFI-checked indirect call requiring a clang-built function, and chains to
 * the original syscall. The policy is the clockid comparison below, which
 * covers both CLOCK_THREAD_CPUTIME_ID and the encoded per-thread CPU clocks.
 *
 * The guard denies CLOCK_THREAD_CPUTIME_ID for every process once loaded. The
 * loader runs before this module, so nothing legitimate needs it afterwards,
 * and a root shell cannot replay the exploit. This is a mitigation, not a
 * kernel fix: a per-thread timer armed before the module loaded is not
 * removed.
 */
#if IS_ENABLED(CONFIG_KSU_CVE_2026_98260_GUARD)

#include <linux/errno.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

#include "arch.h"
#include "feature/cve_guard.h"
#include "hook/patch_memory.h"
#include "hook/syscall_hook.h"
#include "infra/symbol_resolver.h"
#include "klog.h"

#define CVE_GUARD_ARM_COMPAT_TIMER_CREATE 257
#define CVE_GUARD_CLOCK_THREAD_CPUTIME_ID 3
#define CVE_GUARD_CPUCLOCK_PERTHREAD_MASK 4

static bool cve_guard_should_deny(int clockid)
{
	return clockid == CVE_GUARD_CLOCK_THREAD_CPUTIME_ID ||
	       (clockid & CVE_GUARD_CPUCLOCK_PERTHREAD_MASK) != 0;
}

static syscall_fn_t cve_guard_native_orig;
static syscall_fn_t *cve_guard_compat_table;
static syscall_fn_t cve_guard_compat_orig;

static long cve_guard_entry(const struct pt_regs *regs)
{
	int clockid = (int)PT_REGS_SYSCALL_PARM1(regs);

	if (cve_guard_should_deny(clockid))
		return -EPERM;

#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		if (unlikely(!cve_guard_compat_orig))
			return -ENOSYS;
		return cve_guard_compat_orig(regs);
	}
#endif
	if (unlikely(!cve_guard_native_orig))
		return -ENOSYS;
	return cve_guard_native_orig(regs);
}

static void cve_guard_patch_compat(void)
{
	unsigned long table;
	unsigned long sym;
	unsigned long alt;
	syscall_fn_t orig;
	syscall_fn_t hook = cve_guard_entry;

	table = find_kernel_symbol_exact("compat_sys_call_table");
	sym = find_kernel_symbol_exact("__arm64_compat_sys_timer_create");
	alt = find_kernel_symbol_exact("__arm64_sys_timer_create");
	if (!table || (!sym && !alt)) {
		pr_warn("cve_guard: 32-bit timer_create entry not resolved\n");
		return;
	}

	cve_guard_compat_table = (syscall_fn_t *)table;
	orig = READ_ONCE(cve_guard_compat_table[CVE_GUARD_ARM_COMPAT_TIMER_CREATE]);
	if ((!sym || orig != (syscall_fn_t)sym) && (!alt || orig != (syscall_fn_t)alt)) {
		pr_warn("cve_guard: compat slot is not timer_create, not patched\n");
		cve_guard_compat_table = NULL;
		return;
	}

	if (ksu_patch_text(&cve_guard_compat_table[CVE_GUARD_ARM_COMPAT_TIMER_CREATE],
			   &hook, sizeof(hook), KSU_PATCH_TEXT_FLUSH_DCACHE)) {
		pr_err("cve_guard: compat patch failed\n");
		cve_guard_compat_table = NULL;
		return;
	}

	if (READ_ONCE(cve_guard_compat_table[CVE_GUARD_ARM_COMPAT_TIMER_CREATE]) != hook) {
		pr_err("cve_guard: compat patch did not stick\n");
		cve_guard_compat_table = NULL;
		return;
	}

	cve_guard_compat_orig = orig;
}

int cve_guard_init(void)
{
	if (!ksu_syscall_table)
		return -ENOENT;

	cve_guard_native_orig = READ_ONCE(ksu_syscall_table[__NR_timer_create]);
	ksu_syscall_table_hook(__NR_timer_create, cve_guard_entry, NULL);
	if (READ_ONCE(ksu_syscall_table[__NR_timer_create]) != cve_guard_entry) {
		pr_err("cve_guard: native hook not installed\n");
		return -EIO;
	}

	cve_guard_patch_compat();
	pr_info("cve_guard: per-thread CPU timers denied (policy: clockid)\n");
	return 0;
}

void cve_guard_exit(void)
{
	syscall_fn_t orig;

	if (!cve_guard_compat_table)
		return;

	orig = cve_guard_compat_orig;
	if (ksu_patch_text(&cve_guard_compat_table[CVE_GUARD_ARM_COMPAT_TIMER_CREATE],
			   &orig, sizeof(orig), KSU_PATCH_TEXT_FLUSH_DCACHE))
		pr_err("cve_guard: compat restore failed\n");

	cve_guard_compat_table = NULL;
	cve_guard_compat_orig = NULL;
}

#endif /* CONFIG_KSU_CVE_2026_98260_GUARD */
