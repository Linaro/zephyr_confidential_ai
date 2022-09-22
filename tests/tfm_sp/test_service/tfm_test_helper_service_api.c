/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "tfm_test_helper_service_api.h"
#include "psa/client.h"
#include "psa_manifest/sid.h"

#define OUT_VEC_MAX 3
#define OUT_VEC_BUF_IDX 1
#define OUT_VEC_BUF_LEN_IDX 2

psa_status_t psa_test_helper(tfm_th_test_list_t test,
			     test_run_status_t *sts,
			     uint8_t *buf,
			     size_t *buf_len)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_invec in_vec[] = {
		{ .base = &test, .len = sizeof(tfm_th_test_list_t) }
	};

	psa_outvec out_vec[OUT_VEC_MAX] = {
		{ .base = sts, .len = sizeof(test_run_status_t) }
	};

	if (buf != NULL) {
		out_vec[OUT_VEC_BUF_IDX].base = buf;
		out_vec[OUT_VEC_BUF_IDX].len = BUF_MAX_VALUE_SZ;
		out_vec[OUT_VEC_BUF_LEN_IDX].base = buf_len;
		out_vec[OUT_VEC_BUF_LEN_IDX].len = sizeof(size_t);
	}

	handle = psa_connect(TFM_TEST_HELPER_SERVICE_SID,
			     TFM_TEST_HELPER_SERVICE_VERSION);
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
