/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2018-2022 The Regents of the University of California (Regents).
 * Copyright (c) 2023 University of Tampere.
 *
 * Authors:
 * Dayeol Lee <dayeol@berkeley.edu>
 * Evgeny Pobachienko <evgenyp@berkeley.edu>
 * Jarkko Sakkinen <jarkko.sakkinen@tuni.fi>
 */

#ifndef UAPI_ASM_RISCV_KEYSTONE_H
#define UAPI_ASM_RISCV_KEYSTONE_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* Same as TEE_IOC_MAGIC */
#define KEYSTONE_IOC 0xA4

#define KEYSTONE_IOC_CREATE_ENCLAVE _IOR(KEYSTONE_IOC, 0x00, struct keystone_ioctl_enclave)
#define KEYSTONE_IOC_DESTROY_ENCLAVE _IOW(KEYSTONE_IOC, 0x01, struct keystone_ioctl_enclave)
#define KEYSTONE_IOC_RUN_ENCLAVE _IOR(KEYSTONE_IOC, 0x04, struct keystone_ioctl_run)
#define KEYSTONE_IOC_RESUME_ENCLAVE _IOR(KEYSTONE_IOC, 0x05, struct keystone_ioctl_run)
#define KEYSTONE_IOC_FINALIZE_ENCLAVE _IOR(KEYSTONE_IOC, 0x06, struct keystone_ioctl_enclave)
#define KEYSTONE_IOC_UTM_INIT _IOR(KEYSTONE_IOC, 0x07, struct keystone_ioctl_enclave)

struct keystone_ioctl_enclave {
	__u64 eid;			/* out */
	__u64 min_pages;		/* in */
	__u64 runtime_vaddr;		/* not used by the driver */
	__u64 user_vaddr;		/* not used by the driver */
	__u64 pt_ptr;
	__u64 utm_free_ptr;
	__u64 epm_paddr;
	__u64 utm_paddr;
	__u64 runtime_paddr;
	__u64 user_paddr;
	__u64 free_paddr;
	__u64 epm_size;
	__u64 utm_size;
	__u64 runtime_entry;		/* in */
	__u64 user_entry;		/* in */
	__u64 untrusted_ptr;		/* in */
	__u64 untrusted_size;		/* in */
};

struct keystone_ioctl_run {
	__u64 eid;
	__u64 error;
	__u64 value;
};

#endif /* UAPI_ASM_RISCV_KEYSTONE_H */
