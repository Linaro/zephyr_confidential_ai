/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef KEY_MGMT_H
#define KEY_MGMT_H

#include "psa/crypto.h"

#define EC_PUBLIC_PEM_BEGIN          "-----BEGIN PUBLIC KEY-----\n"
#define EC_PUBLIC_PEM_END             "-----END PUBLIC KEY-----\n"

/** EC public keys are 65 bytes. */
#define KM_PUBLIC_KEY_SIZE (65)

/** EC private keys are 32 bytes, but encoded in ASN.1 */
#define KM_PRIVATE_KEY_SIZE (2 + 3 + 2 + 32 + 12)

/** Maximum X.509 certificate size in bytes. */
#define KM_CERT_MAX_SIZE (1024)

/** Define the index for the key in the key context array. */
enum km_key_idx {
	KEY_CLIENT_TLS = 0,             /**< TLS client key ID */
	KEY_COSE,                       /**< COSE SIGN/Encrypt key ID */
	KEY_COUNT,                      /**< Number of keys present */
};

/** Inidicates key provisioning status. */
enum km_key_stat {
	KEY_NONE = 0,
	KEY_GEN,                /**< Key generated */
	KEY_X_509_CERT_GEN,     /**< X.509 certificate generated */
};

/** ID in the HUK key derivation service for the specified key. */
enum km_key_type {
	KEY_ID_CLIENT_TLS       = 0x5001,       /**< Client TLS key ID */
	KEY_ID_COSE             = 0x5002,       /**< COSE SIGN/Encrypt key ID */
};

/** Key context. */
struct km_key_context {
	/** PSA Crypto key ID. */
	psa_key_id_t key_id;
	/** Display name. */
	char label[32];
	/** Key status, indicate if a certificate is available. */
	enum km_key_stat status;
	/** For local converted keys, the real private key is kept here, so that
	 * we can use it locally. */
	uint8_t local_private[KM_PRIVATE_KEY_SIZE];
	/** Used bytes of this local private key. */
	size_t local_private_len;
	/** PSA Crypto key handle for the key in the secure domain. */
	psa_key_handle_t key_handle;
};

/** X.509 certificate context. */
struct km_x509_cert {
	/** Size of the cert payload in bytes. 0 if NULL. */
	size_t sz;
	/** X.509 certificate payload. Max 1 KB. */
	char cert[KM_CERT_MAX_SIZE];
};

/**
 * @brief Get the HUK-derived UUID from the secure partition.
 *
 * @param uuid       Pointer to the buffer to store the UUID.
 * @param uuid_size  Size of UUID buffer.
 *
 * @return psa_status_t
 */
psa_status_t km_get_uuid(unsigned char *uuid, size_t uuid_size);

/**
 * @brief Get the public key from the HUK-derived key on the secure partition.
 *
 * @param public_key      Pointer to the buffer to store the public key.
 * @param public_key_len  Public key buffer length.
 * @param key_idx         Key context index.
 *
 * @return psa_status_t
 */
psa_status_t km_get_pubkey(uint8_t *public_key,
			   size_t public_key_len,
			   const enum km_key_idx key_idx);

/**
 * @brief Gets a reference to the struct km_key_context array in memory. The data this
 *        pointer references is NULL-initialised by default, and needs to be
 *        initialised before it can be used.
 *
 * @return Returns a pointer to the key context array
 */
struct km_key_context *km_get_context(enum km_key_idx key_idx);

/**
 * @brief Initialise the key context with the EC keys derived from the HUK at
 *        secure boot. This provides us with the key handles required to
 *        request the public key, or to request operations based on these
 *        keys.
 */
void km_keys_init(void);

/**
 * @brief Encode the public key to PEM format.
 *
 * @param key_idx      Key context index.
 * @param public_key   Pointer to the buffer to store public key in PEM format.
 * @param public_key_size The size in bytes of @p public_key buffer.
 * @param public_key_len  The size in bytes of encoded length.
 *
 * @return psa_status_t
 */
psa_status_t km_enc_pubkey_pem(const enum km_key_idx key_idx,
			       uint8_t *public_key,
			       size_t public_key_size,
			       size_t *public_key_len);

/**
 * @brief Encode the public key to DER format.
 *
 * @param key_idx      Key context index.
 * @param public_key   Pointer to the buffer to store public key in DER format.
 * @param public_key_size The size in bytes of @p public_key buffer.
 * @param public_key_len  The size in bytes of encoded length.
 *
 * @return psa_status_t
 */
psa_status_t km_enc_pubkey_der(const enum km_key_idx key_idx,
			       unsigned char *public_key,
			       size_t public_key_size,
			       size_t *public_key_len);
#endif /* KEY_MGMT_H */
