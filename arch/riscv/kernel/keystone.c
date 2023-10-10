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
#include <linux/genalloc.h>
#include <linux/slab.h>
#include <asm/sbi.h>
#include <uapi/asm/keystone.h>

#undef pr_fmt
#define pr_fmt(fmt) "keystone: " fmt

#define KEYSTONE_SBI_EXT_ID 0x08424b45
#define SBI_SM_CREATE_ENCLAVE 2001
#define SBI_SM_DESTROY_ENCLAVE 2002
#define SBI_SM_RUN_ENCLAVE 2003
#define SBI_SM_RESUME_ENCLAVE 2005

struct keystone_sbi_create {
	u64 epm_pa;
	u64 epm_size;
	u64 utm_pa;
	u64 utm_size;
	u64 runtime_paddr;
	u64 user_paddr;
	u64 free_paddr;
	u64 runtime_entry;
	u64 user_entry;
	u64 untrusted_ptr;
	u64 untrusted_size;
};

struct keystone_mem {
	u64 va;
	u64 pa;
	struct gen_pool *pool;
};

struct keystone_region {
	u64 va;
	u64 pa;
	u64 size;
};

struct keystone_enclave {
	long eid;
	unsigned long busy;
	struct keystone_region utm;
	struct keystone_region epm;
};

#define sbi_sm_call(id, value) sbi_ecall(KEYSTONE_SBI_EXT_ID, (id), (value), 0, 0, 0, 0, 0)

static const unsigned long KEYSTONE_POOL_SIZE = 256UL << 20;
static const long KEYSTONE_EID_NULL = -1;
static const long KEYSTONE_EID_LAST = 15;

static struct keystone_mem keystone_mem;

static inline bool keystone_region_empty(struct keystone_region *region)
{
	return !memchr_inv(region, 0, sizeof(*region));
}

static inline bool keystone_is_valid_eid(long eid)
{
	if (eid >= 0 && eid <= KEYSTONE_EID_LAST)
		return true;

	if (eid != KEYSTONE_EID_NULL)
		pr_err("%s: Unknown EID %ld\n", __func__, eid);

	return false;
}

static int keystone_alloc_region(struct keystone_region *region, unsigned long requested_pages)
{
	unsigned long order = ilog2(requested_pages - 1) + 1;
	unsigned long aligned_pages = 1UL << order;
	unsigned long size = aligned_pages << PAGE_SHIFT;
	dma_addr_t pa;
	u64 va;

	if (!keystone_region_empty(region))
		return -EPERM;

	va = (u64)gen_pool_dma_zalloc_align(keystone_mem.pool, size, &pa, size);
	if (!va)
		return -ENOMEM;

	region->va = va;
	region->pa = pa;
	region->size = size;
	return 0;
}

static void keystone_free_region(struct keystone_region *region)
{
	if (keystone_region_empty(region))
		return;

	gen_pool_free(keystone_mem.pool, region->va, region->size);
	memset(region, 0, sizeof(*region));
}

static int keystone_ioc_create_enclave(struct file *filep, unsigned long arg)
{
	struct keystone_ioctl_enclave *enclp = (struct keystone_ioctl_enclave *)arg;
	struct keystone_enclave *enclave = filep->private_data;

	if (keystone_is_valid_eid(enclave->eid))
		return -EPERM;

	if (keystone_alloc_region(&enclave->epm, enclp->min_pages))
		return -ENOMEM;

	enclp->pt_ptr = enclave->epm.pa;
	enclp->epm_size = enclave->epm.size;
	return 0;
}

static int keystone_ioc_finalize_enclave(struct file *filep, unsigned long arg)
{
	struct keystone_ioctl_enclave *enclp = (struct keystone_ioctl_enclave *)arg;
	struct keystone_enclave *enclave = filep->private_data;
	struct keystone_sbi_create args;
	struct sbiret ret;

	/* At minimum EPM needs to be created: */
	if (keystone_is_valid_eid(enclave->eid) || keystone_region_empty(&enclave->epm))
		return -EPERM;

	args.epm_pa = enclave->epm.pa;
	args.epm_size = enclave->epm.size;
	args.utm_pa = enclave->utm.pa;
	args.utm_size = enclave->utm.size;
	args.runtime_paddr = enclp->runtime_paddr;
	args.user_paddr = enclp->user_paddr;
	args.free_paddr = enclp->free_paddr;
	args.runtime_entry = enclp->runtime_entry;
	args.user_entry = enclp->user_entry;
	args.untrusted_ptr = enclp->untrusted_ptr;
	args.untrusted_size = enclp->untrusted_size;

	ret = sbi_sm_call(SBI_SM_CREATE_ENCLAVE, (unsigned long)&args);
	if (ret.error) {
		pr_err("SBI_SM_CREATE_ENCLAVE error %ld\n", ret.error);
		return -EIO;
	}

	if (!keystone_is_valid_eid(ret.value))
		return -EIO;

	enclave->eid = ret.value;
	return 0;
}

static int keystone_ioc_run_enclave(struct file *filep, unsigned long data)
{
	struct keystone_ioctl_run *arg = (struct keystone_ioctl_run *)data;
	struct keystone_enclave *enclave = filep->private_data;
	struct sbiret ret;

	if (!keystone_is_valid_eid(enclave->eid))
		return -EPERM;

	ret = sbi_sm_call(SBI_SM_RUN_ENCLAVE, enclave->eid);
	arg->error = ret.error;
	arg->value = ret.value;
	return 0;
}

static int __keystone_ioc_destroy_enclave(struct keystone_enclave *enclave)
{
	struct sbiret ret;

	if (keystone_is_valid_eid(enclave->eid)) {
		ret = sbi_sm_call(SBI_SM_DESTROY_ENCLAVE, enclave->eid);
		if (ret.error) {
			pr_warn("SBI_SM_DESTROY_ENCLAVE error %ld\n", ret.error);
			return -EIO;
		}
	}

	keystone_free_region(&enclave->epm);
	keystone_free_region(&enclave->utm);
	enclave->eid = KEYSTONE_EID_NULL;
	return 0;
}

static int keystone_ioc_destroy_enclave(struct file *filep, unsigned long arg)
{
	struct keystone_enclave *enclave = filep->private_data;

	return __keystone_ioc_destroy_enclave(enclave);
}

static int keystone_ioc_resume_enclave(struct file *filep, unsigned long data)
{
	struct keystone_ioctl_run *arg = (struct keystone_ioctl_run *)data;
	struct keystone_enclave *enclave = filep->private_data;
	struct sbiret ret;

	if (!keystone_is_valid_eid(enclave->eid))
		return -EPERM;

	ret = sbi_sm_call(SBI_SM_RESUME_ENCLAVE, enclave->eid);
	arg->error = ret.error;
	arg->value = ret.value;
	return 0;
}

static int keystone_ioc_utm_init(struct file *filep, unsigned long arg)
{
	struct keystone_ioctl_enclave *enclp = (struct keystone_ioctl_enclave *)arg;
	unsigned long pages = PFN_DOWN(ALIGN(enclp->untrusted_size, PAGE_SIZE));
	struct keystone_enclave *enclave = filep->private_data;
	int ret;

	if (keystone_is_valid_eid(enclave->eid))
		return -EPERM;

	ret = keystone_alloc_region(&enclave->utm,  pages);
	if (!ret)
		enclp->utm_free_ptr = enclave->utm.pa;

	return ret;
}

static long keystone_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct keystone_enclave *enclave = filep->private_data;
	size_t ioc_size;
	char data[512];
	long ret;

	if (!enclave)
		return -EIO;

	if (test_and_set_bit(true, &enclave->busy))
		return -EBUSY;

	ioc_size = _IOC_SIZE(cmd);
	ioc_size = ioc_size > sizeof(data) ? sizeof(data) : ioc_size;

	if (copy_from_user(data, (void __user *)arg, ioc_size)) {
		ret = -EFAULT;
		goto err;
	}

	switch (cmd) {
	case KEYSTONE_IOC_CREATE_ENCLAVE:
		ret = keystone_ioc_create_enclave(filep, (unsigned long)data);
		break;
	case KEYSTONE_IOC_FINALIZE_ENCLAVE:
		ret = keystone_ioc_finalize_enclave(filep, (unsigned long)data);
		break;
	case KEYSTONE_IOC_DESTROY_ENCLAVE:
		ret = keystone_ioc_destroy_enclave(filep, (unsigned long)data);
		break;
	case KEYSTONE_IOC_RUN_ENCLAVE:
		ret = keystone_ioc_run_enclave(filep, (unsigned long)data);
		break;
	case KEYSTONE_IOC_RESUME_ENCLAVE:
		ret = keystone_ioc_resume_enclave(filep, (unsigned long)data);
		break;
	case KEYSTONE_IOC_UTM_INIT:
		ret = keystone_ioc_utm_init(filep, (unsigned long)data);
		break;
	default:
		ret = -ENOIOCTLCMD;
		break;
	}

	if (!ret && copy_to_user((void __user *)arg, data, ioc_size))
		ret = -EFAULT;

err:
	clear_bit(true, &enclave->busy);
	return ret;
}

static int keystone_open(struct inode *inode, struct file *file)
{
	struct keystone_enclave *enclave;

	enclave = kzalloc(sizeof(*enclave), GFP_KERNEL);
	if (!enclave)
		return -ENOMEM;

	enclave->eid = KEYSTONE_EID_NULL;
	file->private_data = enclave;
	return 0;
}

static int keystone_release(struct inode *inode, struct file *file)
{
	struct keystone_enclave *enclave = file->private_data;
	int ret = 0;

	WARN_ON(!enclave);

	if (enclave) {
		ret = __keystone_ioc_destroy_enclave(enclave);
		kfree(enclave);
	}

	return ret;
}

static int keystone_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct keystone_enclave *enclave = filep->private_data;
	unsigned long vma_size = vma->vm_end - vma->vm_start;
	unsigned long pfn;

	if (!enclave)
		return -EIO;

	if (!keystone_is_valid_eid(enclave->eid)) {
		if (vma_size > PAGE_SIZE)
			return -EINVAL;

		pfn = PFN_DOWN(enclave->epm.pa + (vma->vm_pgoff << PAGE_SHIFT));
	} else {
		if (vma_size > enclave->utm.size)
			return -EINVAL;

		pfn = PFN_DOWN(enclave->utm.pa);
	}

	return remap_pfn_range(vma, vma->vm_start, pfn, vma_size, vma->vm_page_prot);
}

static const struct file_operations keystone_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = keystone_ioctl,
	.open = keystone_open,
	.release = keystone_release,
	.mmap = keystone_mmap,
};

struct miscdevice keystone_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "keystone_enclave",
	.fops = &keystone_fops,
	.mode = 0666,
};

static int __init keystone_mem_init(void)
{
	struct device *dev = keystone_dev.this_device;
	struct gen_pool *pool;
	dma_addr_t pa;
	void *va_ptr;
	int ret;

	dev->coherent_dma_mask = DMA_BIT_MASK(32);

	pool = gen_pool_create(__ffs(PAGE_SIZE), -1);
	if (!pool)
		return -ENOMEM;

	va_ptr = dma_alloc_coherent(dev, KEYSTONE_POOL_SIZE, &pa, GFP_KERNEL | __GFP_ZERO);
	if (!va_ptr) {
		ret = -ENOMEM;
		goto err_alloc;
	}

	ret = gen_pool_add_virt(pool, (unsigned long)va_ptr, pa, KEYSTONE_POOL_SIZE, -1);
	if (ret < 0)
		goto err_attach;

	keystone_mem.pool = pool;
	keystone_mem.va = (unsigned long)va_ptr;
	keystone_mem.pa = pa;
	pr_info("%s: %lu MiB\n", __func__, KEYSTONE_POOL_SIZE >> 20);
	return 0;

err_attach:
	dma_free_coherent(dev, KEYSTONE_POOL_SIZE, (void *)va_ptr, pa);

err_alloc:
	gen_pool_destroy(pool);
	return ret;
}

static int __init keystone_init(void)
{
	int ret;

	ret = misc_register(&keystone_dev);
	if (ret < 0)
		return ret;

	ret = keystone_mem_init();
	if (ret < 0) {
		misc_deregister(&keystone_dev);
		return ret;
	}

	return 0;
}

device_initcall(keystone_init);
