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

#ifndef RISCV64_H
#define RISCV64_H

#include <asm/page.h>
#include <linux/types.h>

#define PRV_U 0
#define PRV_S 1
#define PRV_H 2
#define PRV_M 3

#define SATP32_MODE 0x80000000
#define SATP32_ASID 0x7FC00000
#define SATP32_PPN 0x003FFFFF
#define SATP64_MODE 0xF000000000000000
#define SATP64_ASID 0x0FFFF00000000000
#define SATP64_PPN 0x00000FFFFFFFFFFF

#define SATP_MODE_OFF 0
#define SATP_MODE_SV32 1
#define SATP_MODE_SV39 8
#define SATP_MODE_SV48 9
#define SATP_MODE_SV57 10
#define SATP_MODE_SV64 11

/* page table entry (PTE) fields */
#define PTE_V 0x001 /* Valid */
#define PTE_R 0x002 /* Read */
#define PTE_W 0x004 /* Write */
#define PTE_X 0x008 /* Execute */
#define PTE_U 0x010 /* User */
#define PTE_G 0x020 /* Global */
#define PTE_A 0x040 /* Accessed */
#define PTE_D 0x080 /* Dirty */
#define PTE_SOFT 0x300 /* Reserved for Software */

#define PTE_PPN_SHIFT 10

#define PTE_TABLE(PTE) (((PTE) & (PTE_V | PTE_R | PTE_W | PTE_X)) == PTE_V)

#define MSTATUS_SD MSTATUS64_SD
#define SSTATUS_SD SSTATUS64_SD
#define RISCV_PGLEVEL_BITS 9

#define RISCV_PGSHIFT 12
#define RISCV_PGSIZE BIT(RISCV_PGSHIFT)

#define MEGAPAGE_SIZE ((u64)(RISCV_PGSIZE << RISCV_PGLEVEL_BITS))
#define SATP_MODE_CHOICE \
	((0 & (~SATP64_MODE)) | (SATP_MODE_SV39 * (SATP64_MODE & (~(SATP64_MODE - 1)))))

#define GIGAPAGE_SIZE (MEGAPAGE_SIZE << RISCV_PGLEVEL_BITS)

static inline void flush_tlb(void)
{
	asm volatile("sfence.vma");
}

static inline pte_t pte_create(unsigned long ppn, int type)
{
	return __pte((ppn << PTE_PPN_SHIFT) | PTE_V | type);
}

static inline pte_t ptd_create(unsigned long ppn)
{
	return pte_create(ppn, PTE_V);
}

#endif /* RISCV64_H */
