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

/*
 * Enum to list supported test
*/
typedef enum {
	TEST_HUK_ENC_CBOR=1,
	TEST_HUK_ENC_COSE_SIGN1,
	TEST_HUK_ENC_WRONG_FORMAT,
	TEST_HUK_ENC_BUFFER_UNDERFLOW,
	TEST_HUK_COSE_VERIFY_SIGN,
	TEST_HUK_VERIFY_COSE_SIGN_FAIL,
	TFLM_HUK_MAX_TEST
} tfm_th_test_list_t;

/*
 * Test run status
 */
typedef enum {
	TEST_SUCCEED = 0,
	TEST_FAILED,
	TEST_UNKNOWN
}test_run_status_t;

/**
 * \brief TF-M test helper API
 *
 * \param[in] test               Test to run on secure side.
 * \param[out] test_run_status_t Test execution status
 *
 * \return A status indicating the success/failure of the operation
 */
psa_status_t psa_test_helper(tfm_th_test_list_t test,
			     test_run_status_t *sts);

#endif // __TFM_TEST_HELPER_SERVICE_API_H__
