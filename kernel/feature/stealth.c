// SPDX-License-Identifier: GPL-2.0
/*
 * KSU_STEALTH: hide KernelSU artifacts from processes outside the KSU
 * SELinux domain.
 *
 * This is a late-load-module subset of the SUSFS "sus_path" idea. It hooks a
 * few path-resolving syscall entries and returns -ENOENT for the hidden paths
 * when the caller is not in the KSU domain. Everything else chains to the
 * original entry, and every entry is registered through
 * ksu_syscall_table_hook(), so ksu_syscall_hook_exit() restores it.
 *
 * newfstatat and faccessat are already registered in KSU's sys_enter
 * dispatcher: the dispatcher handler chains to ksu_syscall_table[nr], which is
 * the entry patched below, so the direct hook still runs for both marked
 * (dispatched) and unmarked (direct) callers.
 *
 * No kprobes and no live text patching of kernel text: only the sys_call_table
 * slots are rewritten with the existing KSU helper.
 */
#if IS_ENABLED(CONFIG_KSU_STEALTH)

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>

#include "arch.h"
#include "feature/stealth.h"
#include "hook/syscall_hook.h"
#include "manager/manager_identity.h"
#include "selinux/selinux.h"
#include "klog.h" // IWYU pragma: keep

#ifndef KSU_PACKAGE_NAME
#define KSU_PACKAGE_NAME "me.weishu.kernelsu"
#endif

/* "<slash>" + manager package name, e.g. "/me.weishu.kernelsu" */
#define KSU_STEALTH_MANAGER_NEEDLE "/" KSU_PACKAGE_NAME

/*
 * A full PATH_MAX buffer does not fit the kernel's 2 KiB frame limit
 * (-Wframe-larger-than), so the window is bounded to 512 bytes. Every hidden
 * prefix and the manager directory name inside /data/app are well inside that
 * window; longer trailing components do not affect the prefix match.
 */
#define KSU_STEALTH_PATH_MAX 512

struct ksu_stealth_prefix {
	const char *path;
	size_t len;
};

static const struct ksu_stealth_prefix ksu_stealth_prefixes[] = {
	{ "/data/adb/ksu", sizeof("/data/adb/ksu") - 1 },
	{ "/data/adb/modules", sizeof("/data/adb/modules") - 1 },
	{ "/sys/module/kernelsu", sizeof("/sys/module/kernelsu") - 1 },
};

static const char ksu_stealth_app_prefix[] = "/data/app/";

/*
 * Match a whole path component prefix: "/data/adb/ksu" matches the directory
 * and everything under it, but not the sibling binary "/data/adb/ksud" that
 * sucompat substitutes into stat/faccessat for allowlisted apps.
 */
static bool ksu_stealth_prefix_match(const char *path, const struct ksu_stealth_prefix *prefix)
{
	if (strncmp(path, prefix->path, prefix->len))
		return false;

	return path[prefix->len] == '\0' || path[prefix->len] == '/';
}

static bool ksu_stealth_path_hidden(const char *path)
{
	size_t i;

	/* Relative paths resolve against cwd/fd, so let the original handle them. */
	if (path[0] != '/')
		return false;

	for (i = 0; i < ARRAY_SIZE(ksu_stealth_prefixes); i++) {
		if (ksu_stealth_prefix_match(path, &ksu_stealth_prefixes[i]))
			return true;
	}

	if (!strncmp(path, ksu_stealth_app_prefix, sizeof(ksu_stealth_app_prefix) - 1) &&
	    strnstr(path, KSU_STEALTH_MANAGER_NEEDLE, KSU_STEALTH_PATH_MAX))
		return true;

	return false;
}

/*
 * Copy the user path argument (parm 2 for every syscall hooked here) into the
 * bounded buffer above. Never dereferences the user pointer directly.
 */
static bool ksu_stealth_should_hide(const struct pt_regs *regs)
{
	const char __user *filename = (const char __user *)PT_REGS_PARM2(regs);
	char path[KSU_STEALTH_PATH_MAX];
	uid_t uid = current_uid().val;
	long len;

	if (!filename)
		return false;
	/* Only non-su apps: system processes, su/ksud and the manager are exempt. */
	if (uid < 10000)
		return false;
	if (is_ksu_domain() || is_manager())
		return false;

	len = strncpy_from_user(path, (const char __user *)untagged_addr((unsigned long)filename),
				sizeof(path) - 1);
	if (len < 0)
		return false;
	path[sizeof(path) - 1] = '\0';

	return ksu_stealth_path_hidden(path);
}

#define KSU_STEALTH_HOOK(name)                                                       \
	static syscall_fn_t ksu_stealth_orig_##name;                                 \
	static long ksu_stealth_##name(const struct pt_regs *regs)                   \
	{                                                                            \
		if (ksu_stealth_should_hide(regs))                                   \
			return -ENOENT;                                              \
		if (unlikely(!ksu_stealth_orig_##name))                              \
			return -ENOSYS;                                              \
		return ksu_stealth_orig_##name(regs);                                \
	}

KSU_STEALTH_HOOK(openat)
KSU_STEALTH_HOOK(newfstatat)
KSU_STEALTH_HOOK(faccessat)
KSU_STEALTH_HOOK(readlinkat)
KSU_STEALTH_HOOK(statx)

#ifdef __NR_openat2
KSU_STEALTH_HOOK(openat2)
#endif
#ifdef __NR_faccessat2
KSU_STEALTH_HOOK(faccessat2)
#endif

static void ksu_stealth_install(int nr, syscall_fn_t hook, syscall_fn_t *orig)
{
	if (nr < 0 || nr >= __NR_syscalls)
		return;

	*orig = READ_ONCE(ksu_syscall_table[nr]);
	ksu_syscall_table_hook(nr, hook, NULL);
	if (READ_ONCE(ksu_syscall_table[nr]) != hook) {
		pr_err("ksu_stealth: syscall %d hook not installed\n", nr);
		*orig = NULL;
	}
}

int ksu_stealth_init(void)
{
	/*
	 * /proc/modules walks the global modules list. Detaching this module
	 * removes it from that list for good; a later delete_module() cannot
	 * find it either, which is acceptable for a boot-scoped module (the
	 * device harden script sets modules_disabled=1). THIS_MODULE is NULL
	 * for a built-in build, which never appears in /proc/modules anyway.
	 */
	if (THIS_MODULE) {
		list_del_init(&THIS_MODULE->list);
		pr_info("ksu_stealth: module detached from /proc/modules\n");
	}

	if (!ksu_syscall_table) {
		pr_err("ksu_stealth: sys_call_table unavailable, path hiding disabled\n");
		return -ENOENT;
	}

	ksu_stealth_install(__NR_openat, ksu_stealth_openat, &ksu_stealth_orig_openat);
	ksu_stealth_install(__NR_newfstatat, ksu_stealth_newfstatat, &ksu_stealth_orig_newfstatat);
	ksu_stealth_install(__NR_faccessat, ksu_stealth_faccessat, &ksu_stealth_orig_faccessat);
	ksu_stealth_install(__NR_readlinkat, ksu_stealth_readlinkat, &ksu_stealth_orig_readlinkat);
	ksu_stealth_install(__NR_statx, ksu_stealth_statx, &ksu_stealth_orig_statx);
#ifdef __NR_openat2
	ksu_stealth_install(__NR_openat2, ksu_stealth_openat2, &ksu_stealth_orig_openat2);
#endif
#ifdef __NR_faccessat2
	ksu_stealth_install(__NR_faccessat2, ksu_stealth_faccessat2, &ksu_stealth_orig_faccessat2);
#endif

	pr_info("ksu_stealth: path hiding active for non-KSU domain\n");
	return 0;
}

#endif /* CONFIG_KSU_STEALTH */
