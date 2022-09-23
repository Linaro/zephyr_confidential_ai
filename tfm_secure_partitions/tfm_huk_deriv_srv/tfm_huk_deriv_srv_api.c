/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tfm_huk_deriv_srv_api.h"

psa_status_t psa_huk_cose_sign(float *inf_value,
			       huk_enc_format_t enc_format,
			       uint8_t *encoded_buf,
			       size_t encoded_buf_size,
			       size_t *encoded_buf_len)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_invec in_vec[] = {
		{ .base = inf_value, .len = sizeof(float) },
		{ .base = &enc_format, .len = sizeof(huk_enc_format_t) },
	};

	psa_outvec out_vec[] = {
		{ .base = encoded_buf, .len = encoded_buf_size },
		{ .base = encoded_buf_len, .len = sizeof(size_t) },
	};

	handle = psa_connect(TFM_HUK_COSE_CBOR_ENC_SIGN_SID,
			     TFM_HUK_COSE_CBOR_ENC_SIGN_VERSION);
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
