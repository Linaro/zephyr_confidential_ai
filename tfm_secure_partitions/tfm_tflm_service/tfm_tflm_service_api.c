/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tfm_tflm_service_api.h"

psa_status_t psa_tflm_model_version(char *model,
				    size_t model_len,
				    char *tflm_model_ver,
				    size_t tflm_model_ver_len)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_invec in_vec[] = {
		{ .base = model, .len = model_len }
	};

	psa_outvec out_vec[] = {
		{ .base = tflm_model_ver, .len = tflm_model_ver_len }
	};

	handle = psa_connect(TFM_TFLM_MODEL_VERSION_INFO_SERVICE_SID,
			     TFM_TFLM_MODEL_VERSION_INFO_SERVICE_VERSION);
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

psa_status_t psa_tflm_version(char *tflm_ver,
			      size_t tflm_ver_len)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_outvec out_vec[] = {
		{ .base = tflm_ver, .len =  tflm_ver_len },
	};

	handle = psa_connect(TFM_TFLM_VERSION_INFO_SERVICE_SID,
			     TFM_TFLM_VERSION_INFO_SERVICE_VERSION);
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
