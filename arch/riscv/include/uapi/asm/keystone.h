/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2018-2022 The Regents of the University of California (Regents).
 * Copyright (c) 2023 Univrsity of Tampere.
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

#define KEYSTONE_IOC_CREATE_ENCLAVE _IOR(KEYSTONE_IOC, 0x00, struct keystone_enclave)
#define KEYSTONE_IOC_DESTROY_ENCLAVE _IOW(KEYSTONE_IOC, 0x01, struct keystone_enclave)
#define KEYSTONE_IOC_RUN_ENCLAVE _IOR(KEYSTONE_IOC, 0x04, struct keystone_run)
#define KEYSTONE_IOC_RESUME_ENCLAVE _IOR(KEYSTONE_IOC, 0x05, struct keystone_run)
#define KEYSTONE_IOC_FINALIZE_ENCLAVE _IOR(KEYSTONE_IOC, 0x06, struct keystone_enclave)
#define KEYSTONE_IOC_UTM_INIT _IOR(KEYSTONE_IOC, 0x07, struct keystone_enclave)
#define KEYSTONE_IOC_FINALIZE_LIBRARY_ENCLAVE _IOR(KEYSTONE_IOC, 0x09, struct keystone_enclave)
#define KEYSTONE_IOC_DESTROY_LIBRARY_ENCLAVE _IOW(KEYSTONE_IOC, 0x0a, struct keystone_enclave)

#define RT_NOEXEC 0
#define USER_NOEXEC 1
#define RT_FULL 2
#define USER_FULL 3
#define UTM_FULL 4

struct runtime_params_t {
	__u64 runtime_entry;
	__u64 user_entry;
	__u64 untrusted_ptr;
	__u64 untrusted_size;
};

struct keystone_enclave {
	__u64 eid;
	__u64 min_pages;
	__u64 runtime_vaddr;
	__u64 user_vaddr;
	__u64 pt_ptr;
	__u64 utm_free_ptr;
	__u64 epm_paddr;
	__u64 utm_paddr;
	__u64 runtime_paddr;
	__u64 user_paddr;
	__u64 free_paddr;
	__u64 epm_size;
	__u64 utm_size;
	struct runtime_params_t params;
	__u64 library_name;
};

struct keystone_run {
	__u64 eid;
	__u64 error;
	__u64 value;
};

#endif /* UAPI_ASM_RISCV_KEYSTONE_H */
