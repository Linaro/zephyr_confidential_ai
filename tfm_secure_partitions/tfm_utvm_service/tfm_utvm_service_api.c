/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tfm_utvm_service_api.h"

psa_status_t psa_utvm_model_version(char *model,
				    uint8_t model_len,
				    char *utvm_model_ver,
				    size_t utvm_model_ver_len)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_invec in_vec[] = {
		{ .base = model, .len = model_len }
	};

	psa_outvec out_vec[] = {
		{ .base = utvm_model_ver, .len = utvm_model_ver_len }
	};

	handle = psa_connect(TFM_UTVM_MODEL_VERSION_INFO_SERVICE_SID,
			     TFM_UTVM_MODEL_VERSION_INFO_SERVICE_VERSION);
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

psa_status_t psa_utvm_version(char *utvm_ver,
			      size_t utvm_ver_len)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_outvec out_vec[] = {
		{ .base = utvm_ver, .len =  utvm_ver_len },
	};

	handle = psa_connect(TFM_UTVM_VERSION_INFO_SERVICE_SID,
			     TFM_UTVM_VERSION_INFO_SERVICE_VERSION);
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
