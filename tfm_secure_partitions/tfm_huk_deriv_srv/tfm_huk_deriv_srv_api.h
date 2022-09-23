/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __TFM_HUK_DERIV_SRV_API_H__
#define __TFM_HUK_DERIV_SRV_API_H__

#include <stddef.h>
#include <stdbool.h>

#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "psa/crypto.h"

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define log_info_print(FMT, ARGS ...)		   \
	do { LOG_INFFMT("[%s] " FMT "\n", \
			SERV_NAME, ## ARGS); } while (0)

#define log_err_print(FMT, ARGS ...)						\
	do { LOG_ERRFMT("[%s] <err> %s:%s():%d " FMT "\n",			\
			SERV_NAME, __FILENAME__,  __func__, __LINE__, ## ARGS);	\
	} while (0)

#define log_dbg_print(FMT, ARGS ...)						\
	do { LOG_DBGFMT("[%s] <err> %s:%s():%d " FMT "\n",			\
			SERV_NAME, __FILENAME__,  __func__, __LINE__, ## ARGS);	\
	} while (0)

typedef enum {
	HUK_COSE        = 0x5002,               // COSE SIGN key id
} huk_key_type_t;

/** Supported encoding format for the inference output. */
typedef enum {
	HUK_ENC_CBOR = 0,               /**< Request a simple CBOR payload. */
	HUK_ENC_COSE_SIGN1,             /**< Request a COSE SIGN1 payload. */
	HUK_ENC_COSE_ENCRYPT0,          /**< Request a COSE ENCRYPT0 payload. */
	HUK_ENC_NONE,
} huk_enc_format_t;

/**
 * \brief COSE CBOR encode and sign
 *
 * COSE CBOR encode and sign
 *
 * \param[in]  inf_value        Tflm inference value to encode and sign
 * \param[in]  cfg              Pointer to COSE CBOR config
 * \param[out] encoded_buf      Buffer to which encoded data
 *                              is written into
 * \param[out] encoded_buf_len  Encoded buffer len in bytes
 *
 * \return A status indicating the success/failure of the operation
 */
psa_status_t psa_huk_cose_sign(float *inf_value,
			       huk_enc_format_t enc_format,
			       uint8_t *encoded_buf,
			       size_t encoded_buf_size,
			       size_t *encoded_buf_len);

#endif // __TFM_HUK_DERIV_SRV_API_H__
