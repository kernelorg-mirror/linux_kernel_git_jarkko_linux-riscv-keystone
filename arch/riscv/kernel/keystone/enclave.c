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
#include "keystone.h"

/* database for enclave ID's (EID's) of active enclaves: */
DEFINE_IDR(idr_enclave);
/* lock for idr_enclave: */
DEFINE_MUTEX(idr_enclave_lock);

#define ENCLAVE_IDR_MIN 0x1000
#define ENCLAVE_IDR_MAX 0xffff

void keystone_enclave_destroy(struct enclave *enclave)
{
	struct epm *epm;
	struct utm *utm;

	WARN_ON_ONCE(!enclave);

	if (!enclave)
		return;

	epm = enclave->epm;
	utm = enclave->utm;

	if (epm) {
#ifdef CONFIG_CMA
		dma_free_coherent(keystone_dev.this_device, epm->size, epm->ptr, epm->pa);
#else
		free_pages(epm->ptr, epm->order);
#endif
		kfree(epm);
	}

	if (utm) {
		if (utm->ptr)
			free_pages((vaddr_t)utm->ptr, utm->order);

		kfree(utm);
	}

	kfree(enclave);
}

struct enclave *keystone_enclave_create(unsigned long min_pages)
{
	struct enclave *enclave;

	enclave = kzalloc(sizeof(*enclave), GFP_KERNEL);
	if (!enclave)
		return NULL;

	enclave->eid = -1; /* invalid */
	enclave->utm = NULL;
	enclave->close_on_pexit = 1;
	enclave->is_init = true;

	enclave->epm = kzalloc(sizeof(*enclave->epm), GFP_KERNEL);
	if (!enclave->epm)
		goto err;

	if (epm_init(enclave->epm, min_pages))
		goto err;

	return enclave;

err:
	keystone_enclave_destroy(enclave);
	return NULL;
}

int keystone_alloc_eid(struct enclave *enclave)
{
	int ret;

	mutex_lock(&idr_enclave_lock);
	ret = idr_alloc(&idr_enclave, enclave, ENCLAVE_IDR_MIN, ENCLAVE_IDR_MAX, GFP_KERNEL);
	mutex_unlock(&idr_enclave_lock);

	return ret;
}

struct enclave *keystone_free_eid(unsigned int ueid)
{
	struct enclave *enclave;

	mutex_lock(&idr_enclave_lock);
	enclave = idr_remove(&idr_enclave, ueid);
	mutex_unlock(&idr_enclave_lock);

	return enclave;
}
