/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "key_mgmt.h"

#define KEY_LEN_BYTES 16

/* This macro appends an optional SECURE_INFER_HUK_DERIV_LABEL_EXTRA config string to the
 * label used for key derivation, enabling key diversity during testing
 * on emulated platforms with a fixed HUK value.
 */
#define LABEL_CONCAT(A) #A CONFIG_SECURE_INFER_HUK_DERIV_LABEL_EXTRA
#define LABEL_HI    LABEL_CONCAT(_EC_PRIV_KEY_HI)
#define LABEL_LO    LABEL_CONCAT(_EC_PRIV_KEY_LO)
#define LABEL_UUID  LABEL_CONCAT(UUID)

/**
 * @brief Setup the device client TLS key.
 *
 * @param ctx   Pointer to the key context.
 */
void device_client_tls_key_init(struct km_key_context *ctx);
