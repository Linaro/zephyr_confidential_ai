/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/zephyr.h>
#include <provision.h>
#include <psa/protected_storage.h>

/* Mutex/condition to coordinate device provisioning. */
static K_MUTEX_DEFINE(prov_lock);
static K_CONDVAR_DEFINE(prov_cond);

/* The above protect this variable, which indicates that device provisioning has
 * completed.
 * TODO: This provisioning currently isn't tested (and certainly won't work)
 * reading the provisioned data on startup.  To implement this, we need to query
 * the items on first attemp, and read them from PS if possible.
 */

static enum provision_present prov_present;

int provision_store(const struct provision_data *prov)
{
	psa_status_t pres;
	int rc = -EINVAL;

	k_mutex_lock(&prov_lock, K_FOREVER);

	if ((prov->present & PROVISION_TLS_CERT) != 0) {
		pres = psa_ps_set(APP_PS_TLS_CERT, prov->tls_cert_der_len, prov->tls_cert_der,
				  PSA_STORAGE_FLAG_NONE);
		if (pres < 0) {
			/* TODO: Better error code here? */
			rc = -EINVAL;
			goto unlock_out;
		}

		prov_present |= PROVISION_TLS_CERT;
	}

	if ((prov->present & PROVISION_HUBNAME) != 0) {
		pres = psa_ps_set(APP_PS_HUBNAME, prov->hubname_len, prov->hubname,
				  PSA_STORAGE_FLAG_NONE);
		if (pres < 0) {
			/* TODO: Better error code here? */
			rc = -EINVAL;
			goto unlock_out;
		}

		prov_present |= PROVISION_HUBNAME;
	}

	if ((prov->present & PROVISION_HUBPORT) != 0) {
		pres = psa_ps_set(APP_PS_HUBPORT, sizeof(uint16_t), &prov->hubport,
				  PSA_STORAGE_FLAG_NONE);
		if (pres < 0) {
			/* TODO: Better error code here? */
			rc = -EINVAL;
			goto unlock_out;
		}

		prov_present |= PROVISION_HUBPORT;
	}

	/* After writing everything out, we are considered provisioned, so we can tell everyone. */
	k_condvar_broadcast(&prov_cond);

unlock_out:
	k_mutex_unlock(&prov_lock);
	return 0;
}

int provision_wait(enum provision_present mask)
{
	k_mutex_lock(&prov_lock, K_FOREVER);
	while ((prov_present & mask) != mask) {
		k_condvar_wait(&prov_cond, &prov_lock, K_FOREVER);
	}
	k_mutex_unlock(&prov_lock);
	return 0;
}

/**
 * @brief Map the return result from #psa_ps_get to an RC code.
 *
 * @param pres the status from the #psa_ps_get call.
 * @return int Either 0, or a negative errno-type error.
 */
static int map_psa_ps_error(psa_status_t pres)
{
	switch (pres) {
	case PSA_ERROR_INVALID_ARGUMENT:
		return -ENOMEM;
	case PSA_ERROR_DOES_NOT_EXIST:
		return -ENOENT;
	case PSA_SUCCESS:
		return 0;
	default:
		return -EINVAL;
	}
}

int provision_get(struct provision_data *prov, char *buf, size_t buf_len)
{
	int rc = 0;
	size_t total_len = 0;
	size_t out_len;
	psa_status_t pres;

	k_mutex_lock(&prov_lock, K_FOREVER);
	if (prov_present != ALL_PROVISION_DATA) {
		rc = -ENOENT;
		goto out;
	}

	/* Retrieve the TLS certificate. */
	pres = psa_ps_get(APP_PS_TLS_CERT, 0, buf_len, buf, &out_len);
	rc = map_psa_ps_error(pres);
	if (rc != 0) {
		goto out;
	}
	prov->tls_cert_der = buf;
	prov->tls_cert_der_len = out_len;
	total_len += out_len;
	buf += out_len;
	buf_len -= out_len;

	/* Ensure we have enough space for a possible hubname, and a null
	 * termination. */
	if (buf_len < 2) {
		rc = -ENOSPC;
		goto out;
	}

	/* Retrieve the hubname.  We use buf_len-1 to allow space for the
	 * terminating null on the string. */
	pres = psa_ps_get(APP_PS_HUBNAME, 0, buf_len, buf, &out_len);
	rc = map_psa_ps_error(pres);
	if (rc != 0) {
		goto out;
	}
	prov->hubname = buf;
	prov->hubname_len = out_len;
	total_len += out_len + 1;
	buf += out_len;
	*(buf++) = '\0';
	buf_len -= out_len + 1;

	/* Retrieve the port. */
	pres = psa_ps_get(APP_PS_HUBPORT, 0, sizeof(uint16_t), &prov->hubport, &out_len);
	rc = map_psa_ps_error(pres);
	if (rc != 0) {
		goto out;
	}
	if (out_len != sizeof(uint16_t)) {
		rc = -EINVAL;
		goto out;
	}

	rc = total_len;
out:
	k_mutex_unlock(&prov_lock);
	return rc;
}
