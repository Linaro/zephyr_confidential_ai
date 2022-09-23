/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __BOOTSTRAP_H__
#define __BOOTSTRAP_H__

/**
 * @brief The context for bootstrap REST requests.
 */
struct bootstrap {
	int sock;
};

/**
 * @brief Open a connection to the bootstrap server.
 *
 * Note that this function is not reentrant, as some of the
 * initialization needs to be performed once, and this is not
 * protected.  If use from multiple threads is needed, this will need
 * to include a locking mechanism.
 *
 * @return 0 for success, or a negative errno
 */
int bootstrap_open(struct bootstrap *ctx);

/**
 * @brief Close a CA server connection.
 *
 * @return 0 for success, or a negative errno
 */
int bootstrap_close(struct bootstrap *ctx);

/**
 * @brief The context needed for the CSR request.
 *
 * All fields are private.  The struct is exposed because the caller
 * is responsible for the allocation of this data.
 */
struct csr_req {
	uint8_t uuid[37];
	uint8_t cbor[1024];
	size_t cbor_len;
};

/**
 * @brief Perform a CSR request for the given key
 *
 * @return 0 for success, or a negative errno
 */
int bootstrap_csr(struct bootstrap *ctx, struct csr_req *req, uint8_t key_idx);

/**
 * @brief Request service configuration
 *
 * @return 0 for success, or negative errno
 */
int bootstrap_service(struct bootstrap *ctx);

#endif /* not __BOOTSTRAP_H__ */
