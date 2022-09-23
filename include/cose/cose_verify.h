/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef COSE_VERIFY_H
#define COSE_VERIFY_H

#include <zephyr/zephyr.h>
#include <string.h>
#include "nanocbor/nanocbor.h"
#include "psa/crypto_types.h"

#include "key_mgmt.h"

#define COSE_ERROR_NONE                 0x00
#define COSE_ERROR_UNSUPPORTED          0x01
#define COSE_ERROR_DECODE               0x02
#define COSE_ERROR_AUTHENTICATE         0x03
#define COSE_ERROR_HASH                 0x04

#if CONFIG_NONSECURE_COSE_VERIFY_SIGN
#ifndef CONFIG_MBEDTLS_CFG_FILE
#include "mbedtls/config-tls-generic.h"
#else
#include CONFIG_MBEDTLS_CFG_FILE
#endif

#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>

#define COSE_ALG_ECDSA_SHA256 -7
#define COSE_CONTEXT_SIGN1 "Signature1"

typedef enum {
	cose_header_algorithm           = 1,
	cose_header_critical            = 2,
	cose_header_content_type        = 3,
	cose_header_kid                 = 4,
	cose_header_iv                  = 5,
	cose_header_partial_iv          = 6,
	cose_header_countersign         = 7,
	cose_header_operation_time      = 8,
	cose_header_countersign0        = 9,
	cose_header_hkdf_salt           = -20,
	cose_header_kdf_u_name          = -21,
	cose_header_kdf_u_nonce         = -22,
	cose_header_kdf_u_other         = -23,
	cose_header_kdf_v_name          = -24,
	cose_header_kdf_v_nonce         = -25,
	cose_header_kdf_v_other         = -26,
	cose_header_ecdh_ephemeral      = -1,
	cose_header_ecdh_static         = -2,
	cose_header_ecdh_epk            = -1,
	cose_header_ecdh_spk            = -2,
	cose_header_ecdh_spk_kid        = -3,
} cose_header_t;

typedef struct {
	/* internal */
	size_t len_sig;
	size_t len_hash;
	mbedtls_pk_context pk;
} cose_sign_context_t;

/**
 * @brief Initialize COSE signing context
 *
 * @param       ctx     Pointer to uninitialized signing context
 * @param       mode    0 for signature generation, 1 for verification
 * @param       pem     PEM-formatted key string
 *
 * @return COSE_ERROR_NONE              Success
 *         COSE_ERROR_UNSUPPORTED       Crypto algorithm not supported
 */
int cose_sign_init(cose_sign_context_t *ctx);

/**
 * @brief Decode a COSE object and verify the signature
 *
 * @param       ctx     Pointer to the COSE signing context
 * @param       obj     Pointer to the encoded COSE object
 * @param       len_obj Length of encode COSE object
 * @param[out]  pld     Pointer to payload within COSE object
 * @param[out]  len_pld Payload length
 *
 * @return COSE_ERROR_NONE              Success
 *         COSE_ERROR_DECODE            Failed to decode COSE object
 *         COSE_ERROR_HASH              Failed to hash authenticated data
 *         COSE_ERROR_AUTHENTICATE      Failed to authenticate signature
 */
int cose_verify_sign1(cose_sign_context_t *ctx,
		      const uint8_t *obj,
		      const size_t len_obj,
		      const uint8_t **pld,
		      size_t *len_pld);

/**
 * @brief Free underlying MbedTLS contexts
 *
 * @param ctx MbedTLS signing contexts to free.
 */
void cose_sign_free(cose_sign_context_t *ctx);

#endif /* CONFIG_NONSECURE_COSE_VERIFY_SIGN */

/**
 * @brief Decode a SIGN1 COSE payload
 *
 * @param       obj     Pointer to the encoded COSE object
 * @param       len_obj Length of encode COSE object
 * @param[out]  pld     Pointer to payload within COSE object
 * @param[out]  len_pld Payload length
 * @param[out]  sig     Pointer to extracted sign payload within COSE object
 * @param[out]  len_sig sign payload length
 *
 * Note:
 *  if sig arg is NULL, then this function does only get the payload from
 *  encoded COSE object.
 *
 * @return COSE_ERROR_NONE              Success
 *         COSE_ERROR_DECODE            Failed to decode COSE object
 */
int cose_sign1_decode(const uint8_t *obj, const size_t len_obj,
		      const uint8_t **pld, size_t *len_pld,
		      const uint8_t **sig, size_t *len_sig);

/**
 * @brief Retrieve the inference value from a COSE encoded payload
 *
 * @param       obj            Pointer to the encoded COSE encoded payload
 *                             object
 * @param       len_obj        Length of encode COSE object
 * @param[out]  inf_sig_value  Pointer to the inference value extracted from
 *                             the encoded payload
 *
 * @return COSE_ERROR_NONE     Success
 *         COSE_ERROR_DECODE   Failed to decode COSE object
 */
int cose_payload_decode(const uint8_t *obj,
			const size_t len_obj,
			float *inf_sig_value);

#endif /* COSE_VERIFY_H */
