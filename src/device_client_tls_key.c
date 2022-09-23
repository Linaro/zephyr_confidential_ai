/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "device_client_tls_key.h"
#include <zephyr/zephyr.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/logging/log.h>
#include <tfm_crypto_defs.h>
#include <stdio.h>

#define PRIVATE_KEY_OFFSET 7
#define PRIVATE_KEY_SIZE (2 * KEY_LEN_BYTES)

/* Template for an ASN.1 encoded EC private key.  See RFC5915. */
static const uint8_t key_template[] = {
	/* SEQUENCE (length) */
	0x30,
	3 + 2 + 32 + 12,
	/* INTEGER 1 (version) */
	0x02, 0x01, 0x01,
	/* OCTET STRING (32 bytes) */
	0x04, 0x20,
	/* Private key, 32 bytes. */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* OID: prime256v1. */
	0xa0, 0x0a,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
	0x01, 0x07,
};

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

static psa_status_t psa_huk_deriv_key(uint8_t *key_data,
				      size_t key_data_size,
				      size_t *key_data_len,
				      uint8_t *label,
				      size_t label_size)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_key_id_t derived_key_id;

	if (key_data_size < KEY_LEN_BYTES) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}

	if (label == NULL || label_size == 0) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	/* Currently, MbedTLS does not support key derivation for Elliptic curves.
	 * There is a PR https://github.com/ARMmbed/mbedtls/pull/5139 in progress
	 * though. Once this PR is merged, TF-M updates MbedTLS and finally, once
	 * Zephyr updates to latest TF-M, then we can use derive key/s for Elliptic
	 * curve instead of using symmetric keys as starting point for Elliptic
	 * curve key derivation.
	 */

	/* Set the key attributes for the key */
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT |
				PSA_KEY_USAGE_DECRYPT |
				PSA_KEY_USAGE_EXPORT);

	/* Set the algorithm, key type and the number of bits of the key. This is
	 * mandatory for key derivation. Setting these attributes will ensure that
	 * derived key is in accordance with the standard, if any.
	 */
	psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(KEY_LEN_BYTES));

	/* Set up a key derivation operation with HUK derivation as the alg */
	status = psa_key_derivation_setup(&op, TFM_CRYPTO_ALG_HUK_DERIVATION);
	if (status != PSA_SUCCESS) {
		return status;
	}

	/* Supply the UUID label as an input to the key derivation */
	status = psa_key_derivation_input_bytes(&op,
						PSA_KEY_DERIVATION_INPUT_LABEL,
						label,
						label_size);
	if (status != PSA_SUCCESS) {
		goto err_release_op;
	}

	/* Create the storage key from the key derivation operation */
	status = psa_key_derivation_output_key(&attributes, &op, &derived_key_id);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Key derivation failed with %d", status);
		goto err_release_op;
	}

	status =  psa_export_key(derived_key_id, key_data, key_data_size, key_data_len);

	if (status != PSA_SUCCESS) {
		LOG_ERR("Export key failed with %d", status);
		goto err_release_op;
	}

	/* Free resources associated with the key derivation operation */
	status = psa_key_derivation_abort(&op);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_destroy_key(derived_key_id);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Destroy key ID failed with %d", status);
		return status;
	}

	return PSA_SUCCESS;

err_release_op:
	(void)psa_key_derivation_abort(&op);

	return status;
}

/**
 * Generate EC Key for device client TLS
 */
static psa_status_t psa_huk_deriv_ec_key(const uint8_t *rx_label,
					 struct km_key_context *ctx,
					 psa_key_usage_t key_usage_flag)
{
	psa_status_t status = PSA_SUCCESS;
	uint8_t *ec_priv_key_data;
	size_t ec_priv_key_data_len = 0;

	if ((ctx == NULL)  || (sizeof(key_template) != sizeof(ctx->local_private))) {
		LOG_ERR("Key ctx is NULL");
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	ec_priv_key_data = ctx->local_private + PRIVATE_KEY_OFFSET;
	uint8_t label_hi[40] = { 0 };
	uint8_t label_lo[40] = { 0 };

	/* Add LABEL_HI to rx_label to create label_hi. */
	sprintf((char *)label_hi, "%s%s", rx_label, LABEL_HI);

	/* Add LABEL_LO to rx_label to create label_lo. */
	sprintf((char *)label_lo, "%s%s", rx_label, LABEL_LO);

	/* For MPS2 AN521 platform, TF-M always returns a 16-byte sample key
	 * as the HUK derived key. But the size of EC private key is 32-bytes.
	 * Therefore, we decided to call HUK based key derivation twice.
	 */
	status = psa_huk_deriv_key(ec_priv_key_data,
				   KEY_LEN_BYTES,
				   &ec_priv_key_data_len,
				   label_hi,
				   strlen((char *)label_hi));
	if (status != PSA_SUCCESS) {
		LOG_ERR("Key deriv failed with %d", status);
		return status;
	}

	status = psa_huk_deriv_key(&ec_priv_key_data[ec_priv_key_data_len],
				   KEY_LEN_BYTES,
				   &ec_priv_key_data_len,
				   label_lo,
				   strlen((char *)label_lo));
	if (status != PSA_SUCCESS) {
		LOG_ERR("Key deriv failed with %d", status);
		return status;
	}

	/* Setup the key's attributes before the creation request. */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&key_attributes, key_usage_flag);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));

	status = psa_import_key(&key_attributes,
				ec_priv_key_data,
				PRIVATE_KEY_SIZE,
				&ctx->key_handle);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Import key failed with %d", status);
		return status;
	}

	LOG_DBG("PSA: Import key: 0x%x", ctx->key_handle);
	ctx->local_private_len = sizeof(key_template);
	ctx->status = KEY_GEN;

	LOG_INF("Successfully derived the key for %s", rx_label);

	return status;
}

void device_client_tls_key_init(struct km_key_context *ctx)
{
	psa_status_t status = PSA_SUCCESS;
	/** These are the hpke_info passed to key derivation for generating
	 *  a unique keys for Device client TLS.
	 */
	const char *hpke_info[1] = {
		"HUK_CLIENT_TLS"
	};

	status = psa_huk_deriv_ec_key((const uint8_t *)hpke_info[0],
				      ctx,
				      (PSA_KEY_USAGE_SIGN_HASH |
				       PSA_KEY_USAGE_VERIFY_MESSAGE |
				       PSA_KEY_USAGE_EXPORT));
	if (status != PSA_SUCCESS) {
		LOG_ERR("EC key deriv failed with %d", status);
		goto err;
	}

	return;
err:
	k_panic();
}
