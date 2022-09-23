/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <tfm_veneers.h>
#include <tfm_ns_interface.h>

#include "tfm_partition_huk.h"
#include "psa/client.h"
#include "psa_manifest/sid.h"

psa_status_t psa_huk_get_pubkey(psa_key_id_t *key_id,
				uint8_t *ec_pk_data,
				size_t ec_pk_data_size)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_invec in_vec[] = {
		{ .base = key_id, .len = sizeof(psa_key_id_t) },
	};

	psa_outvec out_vec[] = {
		{ .base = ec_pk_data, .len = ec_pk_data_size },
	};

	handle = psa_connect(TFM_HUK_EXPORT_PUBKEY_SID,
			     TFM_HUK_EXPORT_PUBKEY_VERSION);
	if (!PSA_HANDLE_IS_VALID(handle)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

	status = psa_call(handle,
			  PSA_IPC_CALL,
			  in_vec,
			  IOVEC_LEN(in_vec),
			  out_vec,
			  IOVEC_LEN(out_vec));

	psa_close(handle);

	return status;
}

psa_status_t psa_huk_ec_key_stat(psa_key_id_t *key_id,
				 enum km_key_stat *stat)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_invec in_vec[] = {
		{ .base = key_id, .len = sizeof(psa_key_id_t) },
	};

	psa_outvec out_vec[] = {
		{ .base = stat, .len = sizeof(enum km_key_stat) },
	};

	handle = psa_connect(TFM_HUK_EC_KEY_STAT_SID,
			     TFM_HUK_EC_KEY_STAT_VERSION);
	if (!PSA_HANDLE_IS_VALID(handle)) {
		return PSA_HANDLE_TO_ERROR(handle);
	}

	status = psa_call(handle,
			  PSA_IPC_CALL,
			  in_vec,
			  IOVEC_LEN(in_vec),
			  out_vec,
			  IOVEC_LEN(out_vec));

	psa_close(handle);

	return status;
}

psa_status_t psa_huk_get_uuid(void *uuid,
			      size_t uuid_size)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_outvec out_vec[] = {
		{ .base = uuid, .len = uuid_size }
	};

	handle = psa_connect(TFM_HUK_GEN_UUID_SID,
			     TFM_HUK_GEN_UUID_VERSION);
	if (!PSA_HANDLE_IS_VALID(handle)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

	status = psa_call(handle,
			  PSA_IPC_CALL,
			  NULL,
			  0,
			  out_vec,
			  IOVEC_LEN(out_vec));

	psa_close(handle);

	return status;
}

psa_status_t psa_huk_hash_sign(psa_key_id_t *key_id,
			       uint8_t *csr_data,
			       size_t csr_data_size,
			       uint8_t *sig,
			       size_t sig_size,
			       size_t *sig_len)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_invec in_vec[] = {
		{ .base = key_id, .len = sizeof(psa_key_id_t) },
		{ .base = csr_data, .len = csr_data_size },
	};

	psa_outvec out_vec[] = {
		{ .base = sig, .len = sig_size },
		{ .base = sig_len, .len = sizeof(size_t) },
	};

	handle = psa_connect(TFM_HUK_HASH_SIGN_SID,
			     TFM_HUK_HASH_SIGN_VERSION);
	if (!PSA_HANDLE_IS_VALID(handle)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

	status = psa_call(handle,
			  PSA_IPC_CALL,
			  in_vec,
			  IOVEC_LEN(in_vec),
			  out_vec,
			  IOVEC_LEN(out_vec));

	psa_close(handle);

	return status;
}

psa_status_t psa_huk_aat(uint8_t *encoded_buf,
			 size_t encoded_buf_size,
			 size_t *encoded_buf_len)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_outvec out_vec[] = {
		{ .base = encoded_buf, .len = encoded_buf_size },
		{ .base = encoded_buf_len, .len = sizeof(size_t) },
	};

	handle = psa_connect(TFM_HUK_AAT_SID,
			     TFM_HUK_AAT_VERSION);
	if (!PSA_HANDLE_IS_VALID(handle)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

	status = psa_call(handle,
			  PSA_IPC_CALL,
			  NULL,
			  0,
			  out_vec,
			  IOVEC_LEN(out_vec));

	psa_close(handle);

	return status;
}
