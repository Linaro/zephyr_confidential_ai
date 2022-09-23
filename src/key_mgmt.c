/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <zephyr/logging/log.h>

#include "key_mgmt.h"
#include "tfm_partition_huk.h"
#include "util_app_log.h"
#include "x509_csr_gen.h"
#include "device_client_tls_key.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

/**
 * @brief Initialise the supplied key context, populating it via calls to
 *        the HUK key derivation service on the secure side.
 *
 *        Takes the supplied struct km_key_context reference, and populates it
 *        with the public details for the corresponding key. Specifically,
 *        it will associate a PSA key ID the specified key, allowing access to
 *        the public key via the PSA Crypto API. This must be called once
 *        before the key context can be used.
 *
 * @param ctx      Pointer to the key context.
 * @param key_id   The key ID in the HUK secure service (see enum km_key_type).
 * @param label    Unique, descriptive string describing this key context.
 */
void km_context_init(struct km_key_context *ctx,
		     enum km_key_type key_id,
		     const unsigned char *label)
{
	psa_status_t status;
	enum km_key_stat stat;

	/* Set the key ID to match the secure service list. */
	ctx->key_id = key_id;

	/* Assign a unique label, within the limits of available memory. */
	if (sizeof(ctx->label) > (strlen(label) + 1)) {
		strcpy(ctx->label, label);
	} else {
		LOG_ERR("Insufficient memory to copy key label\n");
		goto err;
	}
	switch (key_id) {
	case KEY_ID_CLIENT_TLS:
		device_client_tls_key_init(ctx);
		break;
	case KEY_ID_COSE:
		/* Get the key status from the secure service. */
		status = al_psa_status(
			psa_huk_ec_key_stat(&ctx->key_id, &stat),
			__func__);
		if (status != PSA_SUCCESS) {
			LOG_ERR("Failed to get the key status with %d\n", status);
			goto err;
		} else {
			ctx->status = stat;
		}
		break;
	default:
		LOG_ERR("Invalid key ID");
		goto err;
	}

	return;
err:
	/* Dump any queued log messages, and wait for system events. */
	al_dump_log();
	exit(0);
}

psa_status_t km_get_uuid(unsigned char *uuid, size_t uuid_size)
{
	psa_status_t status;

	/* Request device UUID (derived at startup from the HUK) */
	status = al_psa_status(
		psa_huk_get_uuid(uuid, uuid_size),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Unable to get UUID.");
	}

	return status;
}

psa_status_t km_get_pubkey(uint8_t *public_key, size_t public_key_len,
			   const enum km_key_idx key_idx)
{
	psa_status_t status = PSA_SUCCESS;
	struct km_key_context *ctx = km_get_context(key_idx);
	size_t public_key_data_len;

	if (ctx == NULL) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	switch (ctx->key_id) {
	case KEY_ID_CLIENT_TLS:
		status = al_psa_status(
			psa_export_public_key(ctx->key_handle,
					      public_key,
					      public_key_len,
					      &public_key_data_len),
			__func__);
		if (status != PSA_SUCCESS) {
			LOG_ERR("Failed to export the_public_key for 0x%x", KEY_ID_CLIENT_TLS);
			goto err;
		}
		break;
	case KEY_ID_COSE:
		status = al_psa_status(
			psa_huk_get_pubkey(&ctx->key_id,
					   public_key,
					   public_key_len),
			__func__);
		if (status != PSA_SUCCESS) {
			LOG_ERR("Failed to export the_public_key for 0x%x", KEY_ID_COSE);
			goto err;
		}
		break;
	default:
		LOG_ERR("Invalid key ID");
		status = PSA_ERROR_INVALID_ARGUMENT;
		break;
	}

err:
	return status;
}

psa_status_t km_enc_pubkey_der(const enum km_key_idx key_idx,
			       unsigned char *public_key,
			       size_t public_key_size,
			       size_t *public_key_len)
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	unsigned char *c;
	size_t par_len = 0,
	       oid_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_SECP256R1);
	mbedtls_pk_type_t pk_type = MBEDTLS_PK_ECKEY;
	const char *oid = MBEDTLS_OID_EC_GRP_SECP256R1;

	if (public_key == NULL) {
		return(MBEDTLS_ERR_PK_BAD_INPUT_DATA);
	}

	if (public_key_size == 0) {
		return(MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}

	c = public_key + public_key_size;
	c -= KM_PUBLIC_KEY_SIZE;
	if (c > public_key) {
		if (km_get_pubkey(c, KM_PUBLIC_KEY_SIZE, key_idx) != 0) {
			return MBEDTLS_ERR_PK_INVALID_PUBKEY;
		} else {
			*public_key_len += KM_PUBLIC_KEY_SIZE;
		}
	} else {
		return (MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}

	if (c - public_key < 1) {
		return(MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}

	/*
	 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
	 *       algorithm            AlgorithmIdentifier,
	 *       subjectPublicKey     BIT STRING }
	 */
	*--c = 0;
	*public_key_len += 1;

	MBEDTLS_ASN1_CHK_ADD(*public_key_len, mbedtls_asn1_write_len(&c, public_key, *public_key_len));
	MBEDTLS_ASN1_CHK_ADD(*public_key_len, mbedtls_asn1_write_tag(&c, public_key, MBEDTLS_ASN1_BIT_STRING));

	/* Write EC algorithm parameters; that's akin
	 * to pk_write_ec_param() above. */
	MBEDTLS_ASN1_CHK_ADD(par_len,
			     mbedtls_asn1_write_oid(&c,
						    public_key,
						    oid,
						    oid_len));


	if ((ret = mbedtls_oid_get_oid_by_pk_alg(pk_type,
						 &oid,
						 &oid_len)) != 0) {
		return(ret);
	}

	MBEDTLS_ASN1_CHK_ADD(*public_key_len,
			     mbedtls_asn1_write_algorithm_identifier(&c,
								     public_key,
								     oid,
								     oid_len,
								     par_len));

	MBEDTLS_ASN1_CHK_ADD(*public_key_len, mbedtls_asn1_write_len(&c, public_key, *public_key_len));
	MBEDTLS_ASN1_CHK_ADD(*public_key_len,
			     mbedtls_asn1_write_tag(&c,
						    public_key,
						    MBEDTLS_ASN1_CONSTRUCTED |
						    MBEDTLS_ASN1_SEQUENCE));

	return 0;
}

/**
 * @brief This function gets the public key in (Format + X + Y) from TFM HUK
 * export public key secure service and using MbedTLS to encode PEM format.
 */
psa_status_t km_enc_pubkey_pem(const enum km_key_idx key_idx,
			       uint8_t *public_key,
			       size_t public_key_size,
			       size_t *public_key_len)
{
	psa_status_t status;
	size_t olen = 0;

	/* Convert public key from (Format + X + Y) to DER format using MbedTLS */
	status = km_enc_pubkey_der(key_idx,
				   public_key,
				   public_key_size,
				   public_key_len);

	if (status != 0) {
		return status;
	}

	/* Convert public key from DER to PEM format using MbedTLS */
	(status = mbedtls_pem_write_buffer(EC_PUBLIC_PEM_BEGIN,
					   EC_PUBLIC_PEM_END,
					   public_key + public_key_size - *public_key_len,
					   *public_key_len,
					   public_key,
					   public_key_size,
					   &olen));

	if (status != 0) {
		return status;
	}

	*public_key_len = olen;
	return status;
}

struct km_key_context *km_get_context(enum km_key_idx key_idx)
{
	static struct km_key_context k_ctx[KEY_COUNT] = { 0 };

	if (key_idx < 0 || key_idx >= KEY_COUNT) {
		return NULL;
	}

	return &k_ctx[key_idx];
}

void km_keys_init(void)
{
	struct km_key_context *ctx = km_get_context(KEY_CLIENT_TLS);
	assert(ctx != NULL);

	/* Populate the TLS client key context. */
	km_context_init(ctx,
			KEY_ID_CLIENT_TLS,
			"Device Client TLS");

	ctx = km_get_context(KEY_COSE);
	assert(ctx != NULL);

	/* Populate the COSE SIGN/Encrypt key context. */
	km_context_init(ctx,
			KEY_ID_COSE,
			"Device COSE SIGN/Encrypt");
}
