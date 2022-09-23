/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include "tfm_test_helper_service_api.h"

/**
 * @brief Test CBOR encode
 *
 * This test verifies CBOR encode.
 *
 */
ZTEST(tfm_huk_cbor_enc, test_huk_cbor_enc){
	psa_status_t status;
	test_run_status_t test_status = TEST_FAILED;

	status = psa_test_helper(TEST_HUK_ENC_CBOR, &test_status);
	zassert_equal(PSA_SUCCESS, status, "PSA test helper API called failed");
	zassert_equal(TEST_SUCCEED, test_status, "test_huk_cbor_enc test failed");
}

/**
 * @brief Test COSE encode sign
 *
 * This test verifies COSE encode sign.
 *
 */
ZTEST(tfm_huk_cose_enc_sign, test_huk_cose_enc_sign){
	psa_status_t status;
	test_run_status_t test_status = TEST_FAILED;

	status = psa_test_helper(TEST_HUK_ENC_COSE_SIGN1, &test_status);
	zassert_equal(PSA_SUCCESS, status, "PSA test helper API called failed");
	zassert_equal(TEST_SUCCEED, test_status, "test_huk_cose_enc_sign test failed");
}

ZTEST_SUITE(tfm_huk_cbor_enc, NULL, NULL, NULL, NULL, NULL);
ZTEST_SUITE(tfm_huk_cose_enc_sign, NULL, NULL, NULL, NULL, NULL);
