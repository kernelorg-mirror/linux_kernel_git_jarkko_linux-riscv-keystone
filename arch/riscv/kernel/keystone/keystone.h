/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2018-2022 The Regents of the University of California (Regents).
 * Copyright (c) 2023 Univrsity of Tampere.
 *
 * Authors:
 * Dayeol Lee <dayeol@berkeley.edu>
 * Evgeny Pobachienko <evgenyp@berkeley.edu>
 * Jarkko Sakkinen <jarkko.sakkinen@tuni.fi>
 */

#ifndef RISCV_KEYSTONE_H
#define RISCV_KEYSTONE_H

#include <asm/sbi.h>
#include <asm/csr.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/idr.h>
#include <linux/file.h>
#include "riscv64.h"

#undef pr_fmt
#define pr_fmt(fmt) "keystone: " fmt

typedef u64 vaddr_t;
typedef u64 paddr_t;

extern struct miscdevice keystone_dev;

long keystone_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
int keystone_release(struct inode *inode, struct file *file);
int keystone_mmap(struct file *filp, struct vm_area_struct *vma);

struct epm {
	void *ptr;
	size_t size;
	unsigned long order;
	phys_addr_t pa;
};

struct utm {
	void *ptr;
	size_t size;
	unsigned long order;
};

struct enclave {
	int eid;
	int close_on_pexit;
	struct utm *utm;
	struct epm *epm;
	bool is_init;
	/* marks when ioctl is active with another thread: */
	unsigned long busy;
};

struct enclave *keystone_enclave_create(unsigned long min_pages);
void keystone_enclave_destroy(struct enclave *enclave);

int keystone_alloc_eid(struct enclave *enclave);
struct enclave *keystone_free_eid(unsigned int ueid);

int epm_init(struct epm *epm, unsigned long requested_pages);
int utm_init(struct utm *utm, unsigned long requested_pages);

#endif /* RISCV_KEYSTONE_H */
