/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/logging/log.h>

#include "cose/mbedtls_ecdsa_verify_sign.h"
#include "util_app_log.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

int mbedtls_ecp_load_pubkey(mbedtls_pk_context *ctx,
			    const uint8_t *data,
			    size_t data_length)
{
	size_t curve_bytes = data_length;
	const mbedtls_pk_info_t *pk_info;
	size_t curve_bits;
	int status = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

	/* A Weierstrass public key is represented as:
	 * - The byte 0x04;
	 * - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
	 * - `y_P` as a `ceiling(m/8)`-byte string, big-endian.
	 * So its data length is 2m+1 where m is the curve size in bits.
	 */
	if ((data_length & 1) == 0) {
		LOG_ERR("Invalid public key len.\n");
		goto err;
	}
	curve_bytes = data_length / 2;
	mbedtls_pk_init(ctx);
	/* We need to infer the bit-size from the data. Since the only
	* information we have is the length in bytes, the value of curve_bits
	* at this stage is rounded up to the nearest multiple of 8. */
	curve_bits = (curve_bytes * 8);
	pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
	if (pk_info == NULL) {
		LOG_ERR("Invalid public key type.\n");
		status = MBEDTLS_ERR_PK_TYPE_MISMATCH;
		goto err;
	}
	status = mbedtls_pk_setup(ctx, pk_info);
	if (status != 0) {
		LOG_ERR("Public key config failed.\n");
		goto err;
	}

	/* Load the group. */
	status = mbedtls_ecp_group_load(
		&mbedtls_pk_ec(*ctx)->MBEDTLS_PRIVATE(grp),
		MBEDTLS_ECP_DP_SECP256R1);
	if (status != 0) {
		LOG_ERR("ECP group load failed.\n");
		goto err;
	}


	/* Load the public key value. */
	status = mbedtls_ecp_point_read_binary(
		&mbedtls_pk_ec(*ctx)->MBEDTLS_PRIVATE(grp),
		&mbedtls_pk_ec(*ctx)->MBEDTLS_PRIVATE(Q),
		data,
		data_length);
	if (status != 0) {
		LOG_ERR("The public key (format + X + Y) read failed.\n");
		goto err;
	}

	/* Check that the point is on the curve. */
	status = mbedtls_ecp_check_pubkey(
		&mbedtls_pk_ec(*ctx)->MBEDTLS_PRIVATE(grp),
		&mbedtls_pk_ec(*ctx)->MBEDTLS_PRIVATE(Q));
	if (status != 0) {
		LOG_ERR("Verifying the previous step of the loaded public key check failed.\n");
		goto err;
	}

err:
	return status;
}

/*
 * Verify an ECDSA signature
 */
int mbedtls_ecdsa_verify_sign(mbedtls_pk_context ctx,
			      const unsigned char *hash,
			      size_t hash_len,
			      const unsigned char *sig,
			      size_t sig_len)
{
	mbedtls_mpi r;
	mbedtls_mpi s;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	int status = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	if (mbedtls_mpi_read_binary(&r, sig, sig_len / 2) ||
	    mbedtls_mpi_read_binary(&s, &sig[sig_len / 2], sig_len / 2)) {
		LOG_ERR("Failed to the read signature.\n");
		status = MBEDTLS_ERR_MPI_ALLOC_FAILED;
		goto err;
	}
	status = mbedtls_ecdsa_verify(&mbedtls_pk_ec(ctx)->MBEDTLS_PRIVATE(grp),
				      hash, hash_len,
				      &mbedtls_pk_ec(ctx)->MBEDTLS_PRIVATE(Q), &r,
				      &s);
	if (status != 0) {
		LOG_ERR("Signature verification failed.\n");
		goto err;
	}
	return status;
err:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return status;
}
