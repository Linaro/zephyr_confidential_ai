/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __CBOR_COSE_API_H__
#define __CBOR_COSE_API_H__

#include <stdint.h>
#include "psa/service.h"
#include "cbor_cose.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief CBOR encode and sign the encoded inference value using private key of
 * the given key handle.
 *
 * \param[in]   key_handle                Key handle.
 * \param[in]   inf_val                   The inference input value.
 * \param[out]  inf_val_encoded_buf       Buffer to which encoded data *
 *                                        is written into.
 * \param[in]   inf_val_encoded_buf_size  Size of inf_val_encoded_buf in bytes.
 * \param[out]  inf_val_encoded_buf_len   Encoded and signed payload len in
 *                                        bytes.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t tfm_cose_encode_sign(psa_key_handle_t key_handle,
				  float inf_val,
				  uint8_t *inf_val_encoded_buf,
				  size_t inf_val_encoded_buf_size,
				  size_t *inf_val_encoded_buf_len);

/**
 * \brief Encoding the inference value in CBOR format.
 *
 * \param[in]   inf_val                   The inference input value.
 * \param[out]  inf_val_encoded_buf       Buffer to which encoded data
 *                                        is written into.
 * \param[in]   inf_val_encoded_buf_size  Size of inf_val_encoded_buf in bytes.
 * \param[out]  inf_val_encoded_buf_len   Encoded and signed payload len in
 *                                        bytes.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t tfm_cbor_encode(float inf_val,
			     uint8_t *inf_val_encoded_buf,
			     size_t inf_val_encoded_buf_size,
			     size_t *inf_val_encoded_buf_len);

/**
 * \brief This function sets up the CBOR and COSE contexts.
 *
 * \param[in] key_handle   Key handle.
 * \param[in] me           The token creation context to be initialized.
 * \param[in] cose_alg_id  The algorithm to sign with. The IDs are
 *                         defined in [COSE (RFC 8152)]
 *                         (https://tools.ietf.org/html/rfc8152) or
 *                         in the [IANA COSE Registry]
 *                         (https://www.iana.org/assignments/cose/cose.xhtml).
 * \param[out] out_buf     The output buffer to write the encoded token into.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t tfm_cose_encode_start(psa_key_handle_t key_handle,
				   struct tfm_cose_encode_ctx *me,
				   int32_t cose_alg_id,
				   const struct q_useful_buf *out_buf);

/**
 * \brief Completes the token after the payload has been added. When this is called
 *  the signing algorithm is run and the final formatting of the token is completed.
 *
 * \param[in] me                Token Creation Context.
 * \param[out] completed_token  Pointer and length to completed token.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t tfm_cose_encode_finish(struct tfm_cose_encode_ctx *me,
				    struct q_useful_buf_c *completed_token);

/**
 * \brief Add a binary string claim/data
 *
 * \param[in] token_ctx Token creation context.
 * \param[in] label     Integer label for claim.
 * \param[in] data      The claim data.
 * \param[in] data_len  The claim data length.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t tfm_cose_add_data(struct tfm_cose_encode_ctx *token_ctx, int64_t label,
			       void *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* __CBOR_COSE_API_H__ */
