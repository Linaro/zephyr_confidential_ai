/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __TFM_HUK_DERIV_SRV_H__
#define __TFM_HUK_DERIV_SRV_H__

#include <psa/crypto.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "tfm_secure_api.h"
#include "tfm_api.h"

#include "cbor_cose_api.h"
#include "tfm_sp_log.h"
#include "tfm_crypto_defs.h"
#include "psa/crypto.h"
#include "psa/service.h"
#include "psa_manifest/tfm_huk_deriv_srv.h"
#include "tfm_huk_deriv_srv_api.h"
#include "aat.h"

#define KEY_LEN_BYTES 16
/* This macro appends an optional HUK_DERIV_LABEL_EXTRA string to the
 * label used for key derivation, enabling key diversity during testing
 * on emulated platforms with a fixed HUK value.
 * It can be set at compile time via '-DHUK_DERIV_LABEL_EXTRA=value'.
 */
#define LABEL_CONCAT(A) #A HUK_DERIV_LABEL_EXTRA
#define LABEL_HI    LABEL_CONCAT(_EC_PRIV_KEY_HI)
#define LABEL_LO    LABEL_CONCAT(_EC_PRIV_KEY_LO)
#define LABEL_UUID  LABEL_CONCAT(UUID)

#define SERV_NAME "HUK DERIV SERV"

/** Define the index for the key in the key context array. */
typedef enum {
	HUK_KEY_COSE = 0,                       /**< COSE SIGN/Encrypt key ID */
	HUK_KEY_COUNT,                          /**< Number of keys present */
} huk_key_idx_t;

/** Inidicates key provisioning status. */
typedef enum {
	HUK_NONE = 0,
	HUK_KEY_GEN,            /**< Key generated */
	HUK_X_509_CERT_GEN,     /**< X.509 certificate generated */
} huk_key_stat_t;

/** Key context. */
typedef struct {
	/** Key context key_handle is used for storing the key handle of the
	 *  imported private key to the crypto secure domain which is created
	 *  at run time of the psa_import_key function call. The key handle is
	 *  unique on every import and requires any further access to the imported public/private
	 *  key from the secure domain.
	 */
	psa_key_handle_t key_handle;
	/** The key handle is dynamically generated at the psa_import_key call.
	 *  key id is a predefined value which is internal and interfaces to secure
	 *  inference application.PSA Crypto key id use for internal.
	 */
	psa_key_id_t key_id;
	/** Key status, indicate if a certificate is available. */
	huk_key_stat_t status;
} huk_key_context_t;

typedef psa_status_t (*signal_handler_t)(psa_msg_t *);

const char hex_digits[] = { '0', '1', '2', '3', '4', '5', '6', '7',
			    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

#define UUID_STR_LEN ((KEY_LEN_BYTES * 2) + 4 + 1)
#define UUID_7TH_BYTE_MASK  0x0f        /* 0b0000_1111*/
#define UUID_7TH_BYTE_SET   0x40        /* 0b0100_0000 */
#define UUID_9TH_BYTE_MASK  0x3f        /* 0b0011_1111*/
#define UUID_9TH_BYTE_SET   0x80        /* 0b1000_0000*/
#define TFM_HUK_ASN1_CONSTRUCTED      0x20
#define TFM_HUK_ASN1_SEQUENCE         0x10
#define TFM_HUK_ASN1_DATA_LENGTH_0_255 1

#endif // __TFM_HUK_DERIV_SRV_H__
