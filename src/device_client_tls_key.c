/*
 * Copyright (c) 2022-2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "device_client_tls_key.h"
#include <zephyr/kernel.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/logging/log.h>
#include <crypto_keys/tfm_builtin_key_ids.h>
#include <stdio.h>

#define PRIVATE_KEY_OFFSET 7

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

static psa_status_t psa_huk_deriv_key(uint8_t *label, size_t label_size,
				      psa_key_usage_t key_usage_flag, psa_key_handle_t *key_handle)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

	if (label == NULL || label_size == 0) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	/* Set the key attributes for the key */
	psa_set_key_usage_flags(&attributes, key_usage_flag);

	/* Set the algorithm, key type and the number of bits of the key. This is
	 * mandatory for key derivation. Setting these attributes will ensure that
	 * derived key is in accordance with the standard, if any.
	 */
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(KEY_LEN_BYTES));

	/* Set up a key derivation operation with HUK derivation as the alg */
	status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
					      TFM_BUILTIN_KEY_ID_HUK);
	if (status != PSA_SUCCESS) {
		return status;
	}

	/* Supply the UUID label as an input to the key derivation */
	status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, label,
						label_size);
	if (status != PSA_SUCCESS) {
		goto err_release_op;
	}

	/* Create the storage key from the key derivation operation */
	status = psa_key_derivation_output_key(&attributes, &op, key_handle);
	if (status != PSA_SUCCESS) {
		goto err_release_op;
	}

	return PSA_SUCCESS;

err_release_op:
	(void)psa_key_derivation_abort(&op);

	return status;
}

/**
 * Generate EC Key for device client TLS
 */
static psa_status_t psa_huk_deriv_ec_key(const uint8_t *rx_label, struct km_key_context *ctx,
					 psa_key_usage_t key_usage_flag)
{
	psa_status_t status = PSA_SUCCESS;
	uint8_t *ec_priv_key_data;

	if ((ctx == NULL) || (sizeof(key_template) != sizeof(ctx->local_private))) {
		LOG_ERR("Key ctx is NULL");
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	ec_priv_key_data = ctx->local_private + PRIVATE_KEY_OFFSET;
	uint8_t label[40] = {0};

	/* Add LABEL to rx_label to create unique label. */
	sprintf((char *)label, "%s%s", rx_label, LABEL);

	/* For MPS2 AN521 platform, TF-M always returns a 16-byte sample key
	 * as the HUK derived key. But the size of EC private key is 32-bytes.
	 * Therefore, we decided to call HUK based key derivation twice.
	 */
	status = psa_huk_deriv_key(label, strlen((char *)label), key_usage_flag,
				   &ctx->key_handle);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Key deriv failed with %d", status);
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
	const char *hpke_info[1] = {"HUK_CLIENT_TLS"};

	status = psa_huk_deriv_ec_key((const uint8_t *)hpke_info[0], ctx,
				      (PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE));
	if (status != PSA_SUCCESS) {
		LOG_ERR("EC key deriv failed with %d", status);
		goto err;
	}

	return;
err:
	k_panic();
}
