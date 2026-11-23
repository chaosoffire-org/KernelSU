/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_RESTRICTED_CAPS
#define __KSU_H_RESTRICTED_CAPS

#include <linux/capability.h>

#define KSU_CAP_DROP(caps, c) \
	((caps)->cap[CAP_TO_INDEX(c)] &= ~CAP_TO_MASK(c))

/*
 * Capabilities that turn a root shell into a brick or kernel-R/W risk.
 * App profiles may grant networking/BPF capabilities, but never these.
 */
static inline void ksu_clamp_brick_caps(kernel_cap_t *caps)
{
	KSU_CAP_DROP(caps, CAP_SYS_MODULE);
	KSU_CAP_DROP(caps, CAP_SYS_RAWIO);
	KSU_CAP_DROP(caps, CAP_SYS_ADMIN);
	KSU_CAP_DROP(caps, CAP_MKNOD);
	KSU_CAP_DROP(caps, CAP_MAC_OVERRIDE);
	KSU_CAP_DROP(caps, CAP_MAC_ADMIN);
	KSU_CAP_DROP(caps, CAP_SETPCAP);
}

/* Default su (no profile): also keep tracing/checkpoint capabilities out. */
static inline void ksu_clamp_default_caps(kernel_cap_t *caps)
{
	ksu_clamp_brick_caps(caps);
	KSU_CAP_DROP(caps, CAP_PERFMON);
	KSU_CAP_DROP(caps, CAP_BPF);
	KSU_CAP_DROP(caps, CAP_CHECKPOINT_RESTORE);
}

#endif /* __KSU_H_RESTRICTED_CAPS */
