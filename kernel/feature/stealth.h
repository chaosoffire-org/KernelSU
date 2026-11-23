/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_STEALTH
#define __KSU_H_STEALTH

#include <linux/kconfig.h>

#if IS_ENABLED(CONFIG_KSU_STEALTH)
int ksu_stealth_init(void);
#else
static inline int ksu_stealth_init(void)
{
	return 0;
}
#endif

#endif /* __KSU_H_STEALTH */
