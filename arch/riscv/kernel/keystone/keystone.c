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

#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include <linux/anon_inodes.h>
#include <uapi/asm/keystone.h>
#include "keystone.h"
#include "sbi.h"

static const struct file_operations keystone_fops = {
	.owner = THIS_MODULE,
	.mmap = keystone_mmap,
	.unlocked_ioctl = keystone_ioctl,
	.release = keystone_release
};

struct miscdevice keystone_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "keystone_enclave",
	.fops = &keystone_fops,
	.mode = 0666,
};

struct file *keystone_open(void)
{
	return anon_inode_getfile("[keystone]", &keystone_fops, NULL, O_RDWR);
}
EXPORT_SYMBOL_GPL(keystone_open);

int keystone_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct enclave *enclave = filep->private_data;
	unsigned long vsize, psize;
	struct utm *utm;
	struct epm *epm;
	vaddr_t paddr;

	if (!enclave)
		return -EIO;

	utm = enclave->utm;
	epm = enclave->epm;
	vsize = vma->vm_end - vma->vm_start;

	if (enclave->is_init) {
		if (vsize > PAGE_SIZE)
			return -EINVAL;

		paddr = __pa(epm->ptr) + (vma->vm_pgoff << PAGE_SHIFT);
		remap_pfn_range(vma, vma->vm_start, paddr >> PAGE_SHIFT, vsize, vma->vm_page_prot);
	} else {
		psize = utm->size;
		if (vsize > psize)
			return -EINVAL;

		remap_pfn_range(vma, vma->vm_start, __pa(utm->ptr) >> PAGE_SHIFT, vsize,
				vma->vm_page_prot);
	}

	return 0;
}

static int __init keystone_init(void)
{
	int ret;

	ret = misc_register(&keystone_dev);
	if (ret < 0)
		return ret;

	keystone_dev.this_device->coherent_dma_mask = DMA_BIT_MASK(32);
	return 0;
}

device_initcall(keystone_init);
