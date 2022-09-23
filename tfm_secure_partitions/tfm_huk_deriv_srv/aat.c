/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cbor_cose_api.h"
#include "tfm_huk_deriv_srv_api.h"
#include "tfm_sp_log.h"

#if(!BUILD_HUK_KEY_DERIV_TEST)
#include "tfm_tflm_service_api.h"
#include "tfm_utvm_service_api.h"
#endif

/* The algorithm used in COSE */
#define T_COSE_ALGORITHM              T_COSE_ALGORITHM_ES256

#define SERV_NAME "AAT SERVICE"

/*
 * Create Application Attestation Token (AAT) with claim data of TFLM and UTVM version plus
 * it's model version.
 */
psa_status_t tfm_cose_create_aat(psa_key_handle_t key_handle,
				 uint8_t *encoded_buf,
				 size_t encoded_buf_size,
				 size_t *encoded_buf_len)
{
	psa_status_t status = PSA_SUCCESS;
	struct tfm_cose_encode_ctx encode_ctx;
	struct q_useful_buf encode_sign;
	struct q_useful_buf_c completed_encode_sign;

#if(!BUILD_HUK_KEY_DERIV_TEST)
	char infer_version[42] = { 0 };
	char model_version[42] = { 0 };
	char *supported_model[3] = { "TFLM_MODEL_SINE", "UTVM_MODEL_SINE" };
#else
	char infer_version[42] = { "TEST_20072022_1.0" };
	char model_version[42] = { "TEST_1.0" };
#endif

	encode_sign.ptr = encoded_buf;
	encode_sign.len = encoded_buf_size;

	/* Get started creating the token. This sets up the CBOR and COSE contexts
	 * which causes the COSE headers to be constructed.
	 */
	status = tfm_cose_encode_start(key_handle,
				       &encode_ctx,
				       T_COSE_ALGORITHM,     /* alg_select   */
				       &encode_sign);

	if (status != PSA_SUCCESS) {
		return status;
	}

#if(!BUILD_HUK_KEY_DERIV_TEST)
	/* Get the TFLM version */
	status =  psa_tflm_version(infer_version, sizeof(infer_version));
	if (status != PSA_SUCCESS) {
		return status;
	}
#endif

	/* Add TFLM version details */
	status = tfm_cose_add_data(&encode_ctx,
				   EAT_CBOR_LINARO_LABEL_TFLM_VERSION,
				   (void *)infer_version,
				   strlen(infer_version));
	if (status != PSA_SUCCESS) {
		return status;
	}

#if(!BUILD_HUK_KEY_DERIV_TEST)
	/* Get the TFLM sine model version */
	status =  psa_tflm_model_version(supported_model[0],
					 strlen(supported_model[0]) + 1,
					 model_version,
					 sizeof(model_version));
	if (status != PSA_SUCCESS) {
		return status;
	}
#endif
	/* Add TFLM model version details */
	status = tfm_cose_add_data(&encode_ctx,
				   EAT_CBOR_LINARO_LABEL_TFLM_SINE_MODEL_VERSION,
				   (void *)model_version,
				   strlen(model_version));
	if (status != PSA_SUCCESS) {
		return status;
	}

#if(!BUILD_HUK_KEY_DERIV_TEST)
	memset(infer_version, 0, sizeof(infer_version));
	memset(model_version, 0, sizeof(model_version));
	/* Get the MicroTVM version */
	status =  psa_utvm_version(infer_version, sizeof(infer_version));
	if (status != PSA_SUCCESS) {
		return status;
	}
#endif

	/* Add MicroTVM version details */
	status = tfm_cose_add_data(&encode_ctx,
				   EAT_CBOR_LINARO_LABEL_MTVM_VERSION,
				   (void *)infer_version,
				   strlen(infer_version));
	if (status != PSA_SUCCESS) {
		return status;
	}

#if(!BUILD_HUK_KEY_DERIV_TEST)
	/* Get the MicroTVM model version */
	status =  psa_utvm_model_version(supported_model[1],
					 strlen(supported_model[1]) + 1,
					 model_version,
					 sizeof(model_version));
	if (status != PSA_SUCCESS) {
		return status;
	}
#endif

	/* Add MicroTVM sine model version details */
	status = tfm_cose_add_data(&encode_ctx,
				   EAT_CBOR_LINARO_LABEL_MTVM_SINE_MODEL_VERSION,
				   (void *)&model_version,
				   strlen(model_version));
	if (status != PSA_SUCCESS) {
		return status;
	}

	/* Finish up creating the token. This is where the actual signature
	 * is generated. This finishes up the CBOR encoding too.
	 */
	status = tfm_cose_encode_finish(&encode_ctx,
					&completed_encode_sign);
	if (status != PSA_SUCCESS) {
		log_err_print("failed with %d", status);
		return status;
	}

	encoded_buf = (uint8_t *)completed_encode_sign.ptr;
	*encoded_buf_len = completed_encode_sign.len;

#if CONFIG_COSE_VERIFY_SIGN_ON_S_SIDE
	/* Verify signature */
	struct t_cose_key sign_key;

	sign_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;
	sign_key.k.key_handle = key_handle;

	struct q_useful_buf_c payload;
	int32_t return_value;
	struct t_cose_sign1_verify_ctx verify_ctx;

	t_cose_sign1_verify_init(&verify_ctx, 0);

	t_cose_sign1_set_verification_key(&verify_ctx, sign_key);

	return_value =  t_cose_sign1_verify(&verify_ctx,
					    completed_encode_sign,      /* COSE to verify */
					    &payload,                   /* Payload from signed_cose */
					    NULL);                      /* Don't return parameters */

	if (return_value != T_COSE_SUCCESS) {
		log_err_print("failed with %d", return_value);
	} else {
		log_info_print("COSE signature verification succeeded");
	}

#endif
	return status;
}
