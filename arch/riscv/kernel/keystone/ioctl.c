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

#include <linux/uaccess.h>
#include <asm/sbi.h>
#include <uapi/asm/keystone.h>
#include "keystone.h"
#include "sbi.h"

static int keystone_ioc_create_enclave(struct file *filep, unsigned long arg)
{
	struct keystone_enclave *enclp = (struct keystone_enclave *)arg;
	struct enclave *enclave;
	struct epm *epm;
	ssize_t ret;

	enclave = keystone_enclave_create(enclp->min_pages);
	if (!enclave)
		return -ENOMEM;

	ret = keystone_alloc_eid(enclave);
	if (ret < 0) {
		keystone_enclave_destroy(enclave);
		return ret;
	}

	filep->private_data = enclave;

	epm = enclave->epm;

	enclp->eid = ret;
	enclp->pt_ptr = __pa(epm->ptr);
	enclp->epm_size = epm->size;

	return 0;
}

static int keystone_ioc_finalize_enclave(struct file *filep, unsigned long arg)
{
	struct keystone_enclave *enclp = (struct keystone_enclave *)arg;
	struct enclave *enclave = filep->private_data;
	struct keystone_sbi_create args;
	struct sbiret ret;
	struct utm *utm;

	if (!enclave)
		return -EIO;

	enclave->is_init = false;

	/* PMP: */
	args.epm_region.paddr = enclave->epm->pa;
	args.epm_region.size = enclave->epm->size;

	pr_debug("Enclave Private Memory (EPM): 0x%016llx - 0x%016llx\n",
		 args.epm_region.paddr,
		 args.epm_region.paddr + args.epm_region.size);

	/* Untrusted memory: */
	utm = enclave->utm;
	if (utm) {
		args.utm_region.paddr = __pa(utm->ptr);
		args.utm_region.size = utm->size;

	} else {
		args.utm_region.paddr = 0;
		args.utm_region.size = 0;
	}

	pr_debug("Untrusted memory (UTM): 0x%016llx - 0x%016llx\n",
		 args.utm_region.paddr,
		 args.utm_region.paddr + args.utm_region.size);

	/* Physical addresses: */
	args.runtime_paddr = enclp->runtime_paddr;
	args.user_paddr = enclp->user_paddr;
	args.free_paddr = enclp->free_paddr;

	args.params = enclp->params;

	ret = sbi_sm_call(SBI_SM_CREATE_ENCLAVE, (unsigned long)&args);
	if (ret.error) {
		pr_err("SBI_SM_CREATE_ENCLAVE error %ld\n", ret.error);
		goto err;
	}

	enclave->eid = ret.value;
	return 0;

err:
	keystone_enclave_destroy(enclave);
	return -EIO;
}

static int keystone_ioc_run_enclave(struct file *filep, unsigned long data)
{
	struct keystone_run *arg = (struct keystone_run *)data;
	struct enclave *enclave = filep->private_data;
	struct sbiret ret;

	if (!enclave)
		return -EIO;

	ret = sbi_sm_call(SBI_SM_RUN_ENCLAVE, enclave->eid);
	arg->error = ret.error;
	arg->value = ret.value;

	return 0;
}

static int __keystone_ioc_destroy_enclave(struct enclave *enclave)
{
	struct sbiret ret;

	ret = sbi_sm_call(SBI_SM_DESTROY_ENCLAVE, enclave->eid);
	if (ret.error) {
		pr_err("SBI_SM_DESTROY_ENCLAVE error %ld\n", ret.error);
		return -EIO;
	}

	keystone_enclave_destroy(enclave);
	keystone_free_eid(enclave->eid);

	return 0;
}

/*
 * Do not free up the software resources (physical memory regions and idr to be
 * more specific) in the case of SBI failure because otherwise there would be a
 * mismatch between the software and hardware states.
 */
static int keystone_ioc_destroy_enclave(struct file *filep, unsigned long arg)
{
	struct enclave *enclave = filep->private_data;
	int ret;

	if (!enclave) {
		pr_debug("%s: enclave already destroyed\n", __func__);
		return -EIO;
	}

	ret = __keystone_ioc_destroy_enclave(enclave);
	if (ret)
		return ret;

	filep->private_data = NULL;
	return 0;
}

static int keystone_ioc_resume_enclave(struct file *filep, unsigned long data)
{
	struct keystone_run *arg = (struct keystone_run *)data;
	struct enclave *enclave = filep->private_data;
	struct sbiret ret;

	if (!enclave)
		return -EIO;

	ret = sbi_sm_call(SBI_SM_RESUME_ENCLAVE, enclave->eid);
	arg->error = ret.error;
	arg->value = ret.value;

	return 0;
}

static int keystone_ioc_utm_init(struct file *filep, unsigned long arg)
{
	struct keystone_enclave *enclp = (struct keystone_enclave *)arg;
	u64 untrusted_size = enclp->params.untrusted_size;
	struct enclave *enclave = filep->private_data;
	struct utm *utm;
	int ret = 0;

	if (!enclave)
		return -EIO;

	utm = kzalloc(sizeof(*utm), GFP_KERNEL);
	if (!utm) {
		ret = -ENOMEM;
		return ret;
	}

	ret = utm_init(utm, PFN_UP(untrusted_size));
	if (ret) {
		pr_warn("utm_init() returned %d\n", ret);
		kfree(utm);
		return ret;
	}

	/* Prepare for mmap: */
	enclave->utm = utm;
	enclp->utm_free_ptr = __pa(utm->ptr);

	return ret;
}

static int keystone_ioc_finalize_library_enclave(struct file *filep, unsigned long arg)
{
	struct keystone_enclave *enclp = (struct keystone_enclave *)arg;
	struct enclave *enclave = filep->private_data;
	struct keystone_sbi_create create_args;
	struct sbiret ret;

	if (!enclave)
		return -EIO;

	enclave->is_init = false;

	create_args.epm_region.paddr = enclave->epm->pa;
	create_args.epm_region.size = enclave->epm->size;
	// Don't need untrusted memory for library enclaves:
	create_args.utm_region.paddr = 0;
	create_args.utm_region.size = 0;

	if (strncpy_from_user(create_args.library_name,
			      (const char __user *)enclp->library_name,
			      NAME_MAX) < 0)
		return -EFAULT;

	ret = sbi_sm_call(SBI_SM_CREATE_LIBRARY_ENCLAVE, (unsigned long)&create_args);
	if (ret.error) {
		pr_err("SBI_SM_CREATE_LIBRARY_ENCLAVE error %ld\n", ret.error);
		goto err;
	}

	enclave->eid = ret.value;
	return 0;

err:
	keystone_enclave_destroy(enclave);
	return -EIO;
}

/*
 * Do not free up the software resources (physical memory regions and idr to be
 * more specific) in the case of SBI failure because otherwise there would be a
 * mismatch between the software and hardware states.
 */
static int keystone_ioc_destroy_library_enclave(struct file *filep, unsigned long arg)
{
	struct enclave *enclave = filep->private_data;
	struct sbiret ret;

	if (!enclave)
		return -EIO;

	ret = sbi_sm_call(SBI_SM_DESTROY_LIBRARY_ENCLAVE, enclave->eid);
	if (ret.error) {
		pr_err("SBI_SM_DESTROY_LIBRARY_ENCLAVE error %ld\n", ret.error);
		return -EIO;
	}

	keystone_enclave_destroy(enclave);
	filep->private_data = NULL;
	return 0;
}

long keystone_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct enclave *enclave = filep->private_data;
	size_t ioc_size;
	char data[512];
	long ret;

	if (!enclave)
		return -EIO;

	/* Mutually exclude concurrent threads: */
	if (test_and_set_bit(true, &enclave->busy)) {
		pr_info("%d busy\n", enclave->eid);
		return -EBUSY;
	}

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
	case KEYSTONE_IOC_FINALIZE_LIBRARY_ENCLAVE:
		ret = keystone_ioc_finalize_library_enclave(filep, (unsigned long)data);
		break;
	case KEYSTONE_IOC_DESTROY_LIBRARY_ENCLAVE:
		ret = keystone_ioc_destroy_library_enclave(filep, (unsigned long)data);
		break;
	default:
		ret = -ENOIOCTLCMD;
		break;
	}

	/* Copy back only on success: */
	if (!ret && copy_to_user((void __user *)arg, data, ioc_size))
		ret = -EFAULT;

err:
	clear_bit(true, &enclave->busy);
	return ret;
}

int keystone_release(struct inode *inode, struct file *file)
{
	struct enclave *enclave = file->private_data;

	if (!enclave) {
		pr_warn("%s: enclave was already destroyed\n", __func__);
		return 0;
	}

	if (enclave->close_on_pexit)
		return __keystone_ioc_destroy_enclave(enclave);

	return 0;
}
