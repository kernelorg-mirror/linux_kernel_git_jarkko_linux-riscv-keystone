// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2018-2022 The Regents of the University of California (Regents).
 * Copyright (c) 2023 Univrsity of Tampere.
 *
 * Authors:
 * Dayeol Lee <dayeol@berkeley.edu>
 * Evgeny Pobachienko <evgenyp@berkeley.edu>
 * Jarkko Sakkinen <jarkko.sakkinen@tuni.fi>
 */

#include <linux/kernel.h>
#include <linux/dma-mapping.h>
#include "riscv64.h"
#include "keystone.h"

/*
 * Initialize Enclave Private Memory (EPM).
 */
int epm_init(struct epm *epm, unsigned long requested_pages)
{
	unsigned long aligned_pages = __roundup_pow_of_two(requested_pages);
	phys_addr_t __maybe_unused device_phys_addr = 0;
	unsigned long order = ilog2(aligned_pages);
	void *ptr = NULL;

#ifdef CONFIG_CMA
	ptr = dma_alloc_coherent(keystone_dev.this_device,
				 aligned_pages << PAGE_SHIFT,
				 &device_phys_addr,
				 GFP_KERNEL);
#else
	if (order < MAX_ORDER)
		ptr = __get_free_pages(GFP_HIGHUSER, order);
	else
		return -EINVAL;
#endif

	if (!ptr)
		return -ENOMEM;

	/* Zero the payload: */
	memset(ptr, 0, aligned_pages);

	epm->pa = __pa(ptr);
	epm->order = order;
	epm->size = aligned_pages << PAGE_SHIFT;
	epm->ptr = ptr;
	return 0;
}

/*
 * Initialize UnTrusted Memory (UTM).
 */
int utm_init(struct utm *utm, unsigned long requested_pages)
{

	unsigned long aligned_pages = __roundup_pow_of_two(requested_pages);
	phys_addr_t __maybe_unused device_phys_addr = 0;
	unsigned long order = ilog2(aligned_pages);

	utm->ptr = (void *)__get_free_pages(GFP_HIGHUSER, order);
	if (!utm->ptr)
		return -ENOMEM;

	utm->order = order;
	utm->size = aligned_pages << PAGE_SHIFT;
	return 0;
}
