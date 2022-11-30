/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __TFM_TEST_HELPER_SERVICE_API_H__
#define __TFM_TEST_HELPER_SERVICE_API_H__

#include <stddef.h>
#include <stdbool.h>

#include "psa_manifest/sid.h"
#include "psa/crypto.h"

#define BUF_MAX_VALUE_SZ (256)

/*
 * Enum to list supported test
 */
typedef enum {
	TEST_HUK_ENC_CBOR=1,
	TEST_HUK_ENC_COSE_SIGN1,
	TEST_HUK_ENC_WRONG_FORMAT,
	TEST_HUK_ENC_BUFFER_OVERFLOW,
	TEST_HUK_COSE_VERIFY_SIGN,
	TFLM_HUK_MAX_TEST
} tfm_th_test_list_t;

/*
 * Test run status
 */
typedef enum {
	TEST_SUCCEED = 0,
	TEST_FAILED,
	TEST_UNKNOWN
} test_run_status_t;

/**
 * \brief TF-M test helper API
 *
 * \param[in]  test              Test to run on secure side.
 * \param[out] test_run_status_t Test execution status
 * \param[out] buf               Pointer to memory to store the test response.
 * \param[out] buf_len           Pointer to memory about the filled buffer.
 *
 * \return A status indicating the success/failure of the operation
 */
psa_status_t psa_test_helper(tfm_th_test_list_t test,
			     test_run_status_t *sts,
			     uint8_t *buf,
			     size_t *buf_len);
#endif // __TFM_TEST_HELPER_SERVICE_API_H__
