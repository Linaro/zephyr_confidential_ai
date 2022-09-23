/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <tfm_veneers.h>
#include <tfm_ns_interface.h>

#include "tfm_partition_utvm.h"
#include "psa/client.h"
#include "psa_manifest/sid.h"

psa_status_t psa_si_utvm(infer_config_t *infer_config,
			 void *input,
			 size_t input_data_size,
			 uint8_t *encoded_buf,
			 size_t infval_enc_buf_size,
			 size_t *encoded_buf_len)
{
	psa_status_t status;
	psa_handle_t handle;
	psa_invec in_vec[] = {
		{ .base = input, .len =  input_data_size },
		{ .base = infer_config, .len = sizeof(infer_config_t) },
	};

	psa_outvec out_vec[] = {
		{ .base = encoded_buf, .len = infval_enc_buf_size },
		{ .base = encoded_buf_len, .len = sizeof(size_t) },
	};

	handle = psa_connect(TFM_UTVM_SINE_MODEL_SERVICE_SID,
			     TFM_UTVM_SINE_MODEL_SERVICE_VERSION);
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
