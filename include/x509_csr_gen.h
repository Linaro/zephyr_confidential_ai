/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef X509_CSR_GEN_H
#define X509_CSR_GEN_H

#include <zephyr/logging/log.h>

#include "mbedtls/x509_csr.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"

#if defined(MBEDTLS_PEM_WRITE_C)
#include "mbedtls/pem.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#endif

#include "key_mgmt.h"
#include "tfm_partition_huk.h"

#define X509_CSR_PEM_BEGIN          "-----BEGIN CERTIFICATE REQUEST-----\n"
#define X509_CSR_PEM_END             "-----END CERTIFICATE REQUEST-----\n"
#define X509_CSR_SUB_ORG "O=Linaro" /**< CSR subject name of Organization */

/** Inidicates CSR format. */
typedef enum {
	CSR_PEM_FORMAT = 0,     /**< CSR in PEM format */
	CSR_JSON_FORMAT,        /**< CSR in JSON format */
	CSR_DER_FORMAT,         /**< CSR in DER format */
	CSR_NONE,
} x509_csr_fmt_t;

/**
 * @brief Generates device certificate signing request (CSR) using Mbed TLS
 * X.509 and TF-M HUK CSR service.
 *
 * @param key_idx     Key context index.
 * @param csr         Pointer to the buffer to store CSR.
 * @param csr_len     The size in bytes of @p csr.
 * @param uuid        Unique UUID.
 * @param uuid_size   UUID size in bytes.
 * @param fmt         CSR generation format @p x509_csr_fmt_t.
 *
 * @return            length of data written if successful for DER format,
 *                    PEM or JSON returns zero on success or a specific error code.
 */
int x509_csr_generate(const enum km_key_idx key_idx,
			       unsigned char *csr,
			       size_t csr_len,
			       unsigned char *uuid,
			       size_t uuid_size,
			       x509_csr_fmt_t fmt);

/**
 * @brief Generate device certificate signing request (CSR) using Mbed
 * TLS X.509 and TF-M HUK CSR or crypto service. The key will be DER encoded.
 *
 * @param key_idx    Key context index.
 * @param csr_cbor   Buffer to store CSR.
 * @param csr_len    in/out The size of the buffer, in bytes.  On
 *                   return, will be set to the number of bytes used.
 * @param uuid       UUID for the device ID of the CSR.
 * @param uuid_size  Size of UUID
 */
psa_status_t x509_csr_cbor(const enum km_key_idx key_idx,
			   unsigned char *csr_cbor,
			   size_t *csr_cbor_len,
			   unsigned char *uuid,
			   size_t uuid_size);

/**
 * @brief Encode CSR to JSON format.
 *
 * @param csr                Pointer to the buffer of stored CSR.
 * @param csr_json_buff      Pointer to the buffer to store CSR encoded JSON.
 * @param csr_json_buff_len  The size in bytes of @p csr_json_buff.
 *
 * @return psa_status_t
 */
psa_status_t x509_csr_json_encode(unsigned char *csr,
				  unsigned char *csr_json_buff,
				  size_t csr_json_buff_len);

#endif  /* X509_CSR_GEN_H */
