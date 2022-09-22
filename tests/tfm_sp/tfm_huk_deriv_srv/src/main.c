/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <zephyr/logging/log.h>

#include "tfm_test_helper_service_api.h"
#include "key_mgmt.h"
#include "cose/cose_verify.h"
#include "tfm_partition_huk.h"
#include "cose/mbedtls_ecdsa_verify_sign.h"
#include "psa_manifest/sid.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

/*
 * @brief  Verifies the COSE SIGN1 signature of the supplied payload.
 */
psa_status_t tfm_huk_cose_verify_signature(uint8_t *enc_buf,
					   size_t enc_buf_len,
					   uint8_t *pubkey,
					   size_t pubkey_len)
{
	uint8_t *dec;
	size_t len_dec;
	cose_sign_context_t ctx;
	int status;

	status = mbedtls_ecp_load_pubkey(&ctx.pk,
					 pubkey,
					 pubkey_len);

	if (status != 0) {
		LOG_ERR("Load the public key failed\n");
		goto err;
	}

	status = cose_sign_init(&ctx);
	if (status != COSE_ERROR_NONE) {
		LOG_ERR("Failed to initialize COSE signing context.\n");
		goto err;
	}

	status = cose_verify_sign1(&ctx,
				   enc_buf,
				   enc_buf_len,
				   (const uint8_t **) &dec,
				   &len_dec);
	if (status != COSE_ERROR_NONE) {
		LOG_ERR("Failed to authenticate signature. %d\n", status);
		goto err;
	}

	return status;
err:
	cose_sign_free(&ctx);
	return status;
}

/**
 * @brief Test CBOR encode
 *
 * This test verifies CBOR encode.
 *
 */
ZTEST(tfm_huk_deriv_srv, test_huk_cbor_enc){
	psa_status_t status;
	test_run_status_t test_status = TEST_FAILED;

	status = psa_test_helper(TEST_HUK_ENC_CBOR, &test_status, NULL, NULL);
	zassert_equal(PSA_SUCCESS, status, "PSA test helper API called failed");
	zassert_equal(TEST_SUCCEED, test_status, "test_huk_cbor_enc test failed");
}

/**
 * @brief Test COSE encode sign
 *
 * This test verifies COSE encode sign.
 *
 */
ZTEST(tfm_huk_deriv_srv, test_huk_cose_enc_sign){
	psa_status_t status;
	test_run_status_t test_status = TEST_FAILED;

	status = psa_test_helper(TEST_HUK_ENC_COSE_SIGN1, &test_status, NULL, NULL);
	zassert_equal(PSA_SUCCESS, status, "PSA test helper API called failed");
	zassert_equal(TEST_SUCCEED, test_status, "test_huk_cose_enc_sign test failed");
}

/**
 * @brief Test COSE encode wrong format
 *
 * This test verifies invalid COSE encode wrong format.
 *
 */
ZTEST(tfm_huk_deriv_srv, test_huk_cose_enc_wrong_format){
	psa_status_t status;
	test_run_status_t test_status = TEST_FAILED;

	status = psa_test_helper(TEST_HUK_ENC_WRONG_FORMAT, &test_status, NULL, NULL);
	zassert_equal(PSA_ERROR_INVALID_ARGUMENT, status, "PSA test helper API called failed");
	zassert_equal(TEST_SUCCEED, test_status, "test_huk_cose_enc_wrong_format test failed");
}

/**
 * @brief Test COSE encode buffer overflow
 *
 * This test verifies COSE encode buffer overflow negative test.
 *
 */
ZTEST(tfm_huk_deriv_srv, test_huk_cose_enc_buffer_overflow){
	psa_status_t status;
	test_run_status_t test_status = TEST_FAILED;

	status = psa_test_helper(TEST_HUK_ENC_BUFFER_OVERFLOW, &test_status, NULL, NULL);
	zassert_equal(PSA_ERROR_BUFFER_TOO_SMALL, status, "PSA test helper API called failed");
	zassert_equal(TEST_SUCCEED, test_status, "test_huk_cose_enc_buffer_overflow test failed");
}

/**
 * @brief Test COSE encode verify the signature using public key
 *
 * This test verifies the signature of the COSE encoded payload.
 *
 */
ZTEST(tfm_huk_deriv_srv, test_huk_cose_verify_sign){
	psa_status_t status;
	test_run_status_t test_status = TEST_FAILED;
	uint8_t encoded_buf[BUF_MAX_VALUE_SZ];
	size_t encoded_buf_len = 0;
	uint8_t public_key[KM_PUBLIC_KEY_SIZE] = { 0 };   /* EC public key = 65 bytes. */
	psa_key_id_t key_id = KEY_ID_COSE;

	status = psa_test_helper(TEST_HUK_COSE_VERIFY_SIGN, &test_status, encoded_buf, &encoded_buf_len);
	zassert_equal(PSA_SUCCESS, status, "PSA test helper API called failed");

	status = psa_huk_get_pubkey(&key_id,
				    public_key,
				    KM_PUBLIC_KEY_SIZE);
	zassert_equal(PSA_SUCCESS, status, "psa_export_public_key failed");

	status = tfm_huk_cose_verify_signature(encoded_buf,
					       encoded_buf_len,
					       public_key,
					       KM_PUBLIC_KEY_SIZE);
	zassert_equal(COSE_ERROR_NONE, status, "test_huk_cose_verify_sign test failed");
}

ZTEST_SUITE(tfm_huk_deriv_srv, NULL, NULL, NULL, NULL, NULL);
