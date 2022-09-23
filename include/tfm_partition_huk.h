/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __TFM_PARTITION_HUK_H__
#define __TFM_PARTITION_HUK_H__

#include "tfm_api.h"
#include "psa/crypto.h"
#include "key_mgmt.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Get the public key from HUK export public key service
 *
 * \param[in] key_id           EC key id for persistent key
 * \param[in] ec_pk_data       Buffer to which exported public key
 *                                     is written into
 * \param[in] ec_pk_data_size  Size of ec_pk_data in bytes
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t psa_huk_get_pubkey(psa_key_id_t *key_id,
				uint8_t *ec_pk_data,
				size_t ec_pk_data_size);

/**
 * \brief Get the EC key status from HUK EC key status secure service
 *
 * \param[in] key_id    EC key id for persistent key
 * \param[in] stat      Pointer to the buffer to store the key status
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t psa_huk_ec_key_stat(psa_key_id_t *key_id,
				 enum km_key_stat *stat);

/**
 * \brief Get the UUID from HUK generate UUID service
 *
 * \param[out] uuid          Buffer to write UUID
 * \param[in] uuid_size      Size of UUID buffer
 *
 * \return A status indicating the success/failure of the operation
 */
psa_status_t psa_huk_get_uuid(void *uuid,
			      size_t uuid_size);


/**
 * @brief Calculate the SHA256 hash value of the given CSR payload and sign the hash
 * value using the private key of the given key ID.
 *
 * @param key_id         Key ID.
 * @param csr_data       Pointer to the buffer to store CSR.
 * @param csr_data_size  The size in bytes of @p csr_data.
 * @param sig            Pointer to the buffer to store Signature.
 * @param sig_size       The size in byters of @p sig.
 * @param sig_len        The Signed CSR hash len in bytes.
 *
 * @return psa_status_t
 */
psa_status_t psa_huk_hash_sign(psa_key_id_t *key_id,
			       uint8_t *csr_data,
			       size_t csr_data_size,
			       uint8_t *sig,
			       size_t sig_size,
			       size_t *sig_len);

/**
 * \brief Create Application Attestation Token (AAT) with claim data of TFLM and UTVM
 * version plus it's model version.
 *
 * \param[out]  encoded_buf       Buffer to which encoded data is written into.
 * \param[in]   encoded_buf_size  Size of encoded_buf in bytes.
 * \param[out]  encoded_buf_len   Encoded and signed payload len in bytes.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t psa_huk_aat(uint8_t *encoded_buf,
			 size_t encoded_buf_size,
			 size_t *encoded_buf_len);

#ifdef __cplusplus
}
#endif

#endif /* __TFM_PARTITION_HUK_H__ */
