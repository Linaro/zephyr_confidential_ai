/*
 * Copyright (c) 2021-2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tfm_huk_deriv_srv_api.h"

psa_status_t psa_huk_cose_sign(float *inf_value, huk_enc_format_t enc_format, uint8_t *encoded_buf,
			       size_t encoded_buf_size, size_t *encoded_buf_len)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_invec in_vec[] = {
		{.base = inf_value, .len = sizeof(float)},
		{.base = &enc_format, .len = sizeof(huk_enc_format_t)},
	};

	psa_outvec out_vec[] = {
		{.base = encoded_buf, .len = encoded_buf_size},
		{.base = encoded_buf_len, .len = sizeof(size_t)},
	};

	handle = psa_connect(TFM_HUK_COSE_CBOR_ENC_SIGN_SID, TFM_HUK_COSE_CBOR_ENC_SIGN_VERSION);
	if (!PSA_HANDLE_IS_VALID(handle)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

	status = psa_call(handle, PSA_IPC_CALL, in_vec, IOVEC_LEN(in_vec), out_vec,
			  IOVEC_LEN(out_vec));

	psa_close(handle);

	return status;
}

psa_status_t psa_huk_cose_aat_sign(infer_version_t *tflm_infer_ver, infer_version_t *utvm_infer_ver,
				   uint8_t *encoded_buf, size_t encoded_buf_size,
				   size_t *encoded_buf_len)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_invec in_vec[] = {
		{.base = tflm_infer_ver, .len = sizeof(infer_version_t)},
		{.base = utvm_infer_ver, .len = sizeof(infer_version_t)},
	};

	psa_outvec out_vec[] = {
		{.base = encoded_buf, .len = encoded_buf_size},
		{.base = encoded_buf_len, .len = sizeof(size_t)},
	};

	handle = psa_connect(TFM_HUK_COSE_AAT_SIGN_SID, TFM_HUK_COSE_AAT_SIGN_VERSION);
	if (!PSA_HANDLE_IS_VALID(handle)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

	status = psa_call(handle, PSA_IPC_CALL, in_vec, IOVEC_LEN(in_vec), out_vec,
			  IOVEC_LEN(out_vec));

	psa_close(handle);

	return status;
}
