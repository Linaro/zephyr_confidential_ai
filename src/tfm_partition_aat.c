/*
 * Copyright (c) 2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <tfm_ns_interface.h>

#include "tfm_partition_aat.h"
#include "psa/client.h"
#include "psa_manifest/sid.h"

psa_status_t psa_aat(uint8_t *encoded_buf, size_t encoded_buf_size, size_t *encoded_buf_len)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_outvec out_vec[] = {
		{.base = encoded_buf, .len = encoded_buf_size},
		{.base = encoded_buf_len, .len = sizeof(size_t)},
	};

	handle = psa_connect(TFM_AAT_SERVICE_SID, TFM_AAT_SERVICE_VERSION);
	if (!PSA_HANDLE_IS_VALID(handle)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

	status = psa_call(handle, PSA_IPC_CALL, NULL, 0, out_vec, IOVEC_LEN(out_vec));

	psa_close(handle);

	return status;
}
