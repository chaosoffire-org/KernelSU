// SPDX-License-Identifier: GPL-2.0
/*
 * Restricted root for KernelSU-dispatched su.
 *
 * Applies to the KSU SELinux domain and to uid-0 tasks that lack
 * CAP_SYS_ADMIN/CAP_SYS_MODULE (the capability clamp survives a setcon escape
 * from the permissive KSU domain). Normal Android (init/vold/update_engine/
 * OTA) keeps both capabilities and is unaffected; the loader shell is the
 * trust root and is not restricted.
 *   - opening a block device for write is denied (file_open);
 *   - write()/mmap(PROT_WRITE) on a block device is denied as backstop;
 *   - init_module()/finit_module() are denied, so a su shell cannot load a
 *     module to obtain kernel R/W.
 * Capabilities are also dropped by ksud before exec; see userspace/ksud.
 *
 * This is a foot-gun guard against a root shell bricking the device, not a
 * boundary against the loader, which runs before this module.
 */
#if IS_ENABLED(CONFIG_KSU_RESTRICTED_ROOT)

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mman.h>
#include <linux/stat.h>
#include <asm/unistd.h>

#include "arch.h"
#include "feature/ksu_guard.h"
#include "hook/lsm_hook.h"
#include "hook/syscall_hook.h"
#include "selinux/selinux.h"
#include "klog.h"

/*
 * Restricted root is the KSU domain plus any uid-0 task that lacks the
 * dangerous capabilities. The capability test survives a setcon/exec_sid
 * escape from the permissive KSU domain because the capability bounding set
 * was clamped at grant time. init/vold keep both capabilities and are not
 * affected; the loader shell is the trust root.
 */
static bool ksu_guard_is_restricted(void)
{
	if (is_ksu_domain())
		return true;
	if (current_uid().val != 0)
		return false;
	return !capable(CAP_SYS_ADMIN) || !capable(CAP_SYS_MODULE);
}

static bool ksu_guard_block_write(struct file *file, bool write_access)
{
	struct inode *inode;

	if (!write_access)
		return false;

	inode = file_inode(file);
	if (!inode || !S_ISBLK(inode->i_mode))
		return false;

	return ksu_guard_is_restricted();
}

static int ksu_guard_file_open(struct file *file);
static int ksu_guard_file_permission(struct file *file, int mask);
static int ksu_guard_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot,
			       unsigned long flags);

typedef typeof(((union security_list_options *)0)->file_open) file_open_fn;
typedef typeof(((union security_list_options *)0)->file_permission) file_permission_fn;
typedef typeof(((union security_list_options *)0)->mmap_file) mmap_file_fn;

static struct ksu_lsm_hook ksu_guard_file_open_hook =
	KSU_LSM_HOOK_INIT(file_open, "selinux_file_open", ksu_guard_file_open, 0);
static struct ksu_lsm_hook ksu_guard_file_permission_hook =
	KSU_LSM_HOOK_INIT(file_permission, "selinux_file_permission", ksu_guard_file_permission, 0);
static struct ksu_lsm_hook ksu_guard_mmap_file_hook =
	KSU_LSM_HOOK_INIT(mmap_file, "selinux_mmap_file", ksu_guard_mmap_file, 0);

static int ksu_guard_file_open(struct file *file)
{
	if (ksu_guard_block_write(file, file->f_mode & FMODE_WRITE)) {
		pr_warn_ratelimited("ksu_guard: denied block-device write open\n");
		return -EPERM;
	}
	return ((file_open_fn)ksu_guard_file_open_hook.original)(file);
}

static int ksu_guard_file_permission(struct file *file, int mask)
{
	if ((mask & MAY_WRITE) && ksu_guard_block_write(file, true)) {
		pr_warn_ratelimited("ksu_guard: denied block-device write\n");
		return -EPERM;
	}
	return ((file_permission_fn)ksu_guard_file_permission_hook.original)(file, mask);
}

static int ksu_guard_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot,
			       unsigned long flags)
{
	if ((prot & PROT_WRITE) && ksu_guard_block_write(file, true)) {
		pr_warn_ratelimited("ksu_guard: denied block-device mmap write\n");
		return -EPERM;
	}
	return ((mmap_file_fn)ksu_guard_mmap_file_hook.original)(file, reqprot, prot, flags);
}

static syscall_fn_t ksu_guard_orig_init_module;
static syscall_fn_t ksu_guard_orig_finit_module;

static long ksu_guard_init_module(const struct pt_regs *regs)
{
	if (ksu_guard_is_restricted())
		return -EPERM;
	if (unlikely(!ksu_guard_orig_init_module))
		return -ENOSYS;
	return ksu_guard_orig_init_module(regs);
}

static long ksu_guard_finit_module(const struct pt_regs *regs)
{
	if (ksu_guard_is_restricted())
		return -EPERM;
	if (unlikely(!ksu_guard_orig_finit_module))
		return -ENOSYS;
	return ksu_guard_orig_finit_module(regs);
}

static void ksu_guard_hook_module_load(void)
{
	if (!ksu_syscall_table)
		return;

	ksu_guard_orig_init_module = READ_ONCE(ksu_syscall_table[__NR_init_module]);
	ksu_syscall_table_hook(__NR_init_module, ksu_guard_init_module, NULL);
	if (READ_ONCE(ksu_syscall_table[__NR_init_module]) != ksu_guard_init_module)
		pr_err("ksu_guard: init_module hook not installed\n");

	ksu_guard_orig_finit_module = READ_ONCE(ksu_syscall_table[__NR_finit_module]);
	ksu_syscall_table_hook(__NR_finit_module, ksu_guard_finit_module, NULL);
	if (READ_ONCE(ksu_syscall_table[__NR_finit_module]) != ksu_guard_finit_module)
		pr_err("ksu_guard: finit_module hook not installed\n");
}

int ksu_guard_init(void)
{
	int ret;

	ret = ksu_lsm_hook(&ksu_guard_file_open_hook);
	if (ret) {
		pr_err("ksu_guard: file_open hook failed: %d\n", ret);
		return ret;
	}

	ret = ksu_lsm_hook(&ksu_guard_file_permission_hook);
	if (ret) {
		pr_err("ksu_guard: file_permission hook failed: %d\n", ret);
		return ret;
	}

	ret = ksu_lsm_hook(&ksu_guard_mmap_file_hook);
	if (ret) {
		pr_err("ksu_guard: mmap_file hook failed: %d\n", ret);
		return ret;
	}

	ksu_guard_hook_module_load();

	pr_info("ksu_guard: restricted root active (no block writes, no module load)\n");
	return 0;
}

#endif /* CONFIG_KSU_RESTRICTED_ROOT */
