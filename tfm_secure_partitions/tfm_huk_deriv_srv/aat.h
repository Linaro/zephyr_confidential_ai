/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __AAT_H__
#define __AAT_H__

#include <stdint.h>
#include "psa/service.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Create Application Attestation Token (AAT) with claim data of TFLM and UTVM version plus
 * it's model version, using the private key of the given key handle to sign.
 *
 * \param[in]   key_handle        Key handle.
 * \param[out]  encoded_buf       Buffer to which encoded data is written into.
 * \param[in]   encoded_buf_size  Size of encoded_buf in bytes.
 * \param[out]  encoded_buf_len   Encoded and signed payload len in bytes.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t tfm_cose_create_aat(psa_key_handle_t key_handle,
				 uint8_t *encoded_buf,
				 size_t encoded_buf_size,
				 size_t *encoded_buf_len);

#ifdef __cplusplus
}
#endif

#endif /* __AAT_H__ */
