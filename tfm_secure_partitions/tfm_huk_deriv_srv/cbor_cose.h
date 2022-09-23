/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __CBOR_COSE_H__
#define __CBOR_COSE_H__

#include <stdint.h>
#include "qcbor.h"
#include "t_cose_sign1_sign.h"
#include "t_cose_sign1_verify.h"

#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * The context for encoding inference value.  The caller of
 * tfm_cose_encode_sign must create one of these and
 * pass it to the functions here. It is small enough that it can go
 * on the stack. It is most of the memory needed to create a token
 * except the output buffer and any memory requirements for the
 * cryptographic operations.
 *
 * The structure is opaque for the caller.
 *
 * This is roughly 148 + 32 = 180 bytes
 */
struct tfm_cose_encode_ctx {
	/* Private data structure */
	QCBOREncodeContext cbor_enc_ctx;
	struct t_cose_sign1_sign_ctx signer_ctx;
};

/* Labels for CBOR encoding */
#define EAT_CBOR_LINARO_RANGE_BASE                     (-80000)
#define EAT_CBOR_LINARO_LABEL_INFERENCE_VALUE          (EAT_CBOR_LINARO_RANGE_BASE - 0)
#define EAT_CBOR_LINARO_LABEL_TFLM_VERSION             (EAT_CBOR_LINARO_RANGE_BASE - 1)
#define EAT_CBOR_LINARO_LABEL_TFLM_SINE_MODEL_VERSION  (EAT_CBOR_LINARO_RANGE_BASE - 2)
#define EAT_CBOR_LINARO_LABEL_MTVM_VERSION             (EAT_CBOR_LINARO_RANGE_BASE - 3)
#define EAT_CBOR_LINARO_LABEL_MTVM_SINE_MODEL_VERSION  (EAT_CBOR_LINARO_RANGE_BASE - 4)

#ifdef NV_PS_COUNTERS_SUPPORT
#define EAT_CBOR_LINARO_NV_COUNTER_ROLL_OVER           (EAT_CBOR_LINARO_RANGE_BASE - 5)
#define EAT_CBOR_LINARO_NV_COUNTER_VALUE               (EAT_CBOR_LINARO_RANGE_BASE - 6)
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CBOR_COSE_H__ */
