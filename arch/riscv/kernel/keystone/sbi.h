/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2018-2022 The Regents of the University of California (Regents).
 * Copyright (c) 2023 Univrsity of Tampere.
 *
 * Dayeol Lee <dayeol@berkeley.edu>
 * Evgeny Pobachienko <evgenyp@berkeley.edu>
 * Jarkko Sakkinen <jarkko.sakkinen@tuni.fi>
 */

#ifndef RISCV_KEYSTONE_SBI_H
#define RISCV_KEYSTONE_SBI_H

#include <uapi/asm/keystone.h>
#include <asm/sbi.h>

#define KEYSTONE_SBI_EXT_ID 0x08424b45
#define SBI_SM_CREATE_ENCLAVE 2001
#define SBI_SM_DESTROY_ENCLAVE 2002
#define SBI_SM_RUN_ENCLAVE 2003
#define SBI_SM_RESUME_ENCLAVE 2005
#define SBI_SM_CREATE_LIBRARY_ENCLAVE 2006
#define SBI_SM_DESTROY_LIBRARY_ENCLAVE 2007

struct keystone_sbi_pregion {
	u64 paddr;
	size_t size;
};

struct keystone_sbi_create {
	/* memory regions */
	struct keystone_sbi_pregion epm_region;
	struct keystone_sbi_pregion utm_region;

	/* physical addresses */
	u64 runtime_paddr;
	u64 user_paddr;
	u64 free_paddr;

	/* parameters */
	struct runtime_params_t params;
	char library_name[NAME_MAX];
};

#define sbi_sm_call(id, value) sbi_ecall(KEYSTONE_SBI_EXT_ID, (id), (value), 0, 0, 0, 0, 0)

#endif /* RISCV_KEYSTONE_SBI_H */
