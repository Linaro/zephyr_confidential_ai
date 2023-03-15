/*
 * Copyright (c) 2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tfm_aat_service.h"

/*
 * Create Application Attestation Token (AAT) with claim data of TFLM and UTVM version plus
 * it's model version.
 */
psa_status_t tfm_cose_create_aat(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	uint8_t encoded_buf[msg->out_size[0]];
	size_t encoded_buf_len = 0;

#if (!BUILD_HUK_KEY_DERIV_TEST)
	infer_version_t tflm_inf_ver;
	infer_version_t utvm_inf_ver;
	char *supported_model[3] = {"TFLM_MODEL_SINE", "UTVM_MODEL_SINE"};
#else
	char infer_version[42] = {"TEST_20072022_1.0"};
	char model_version[42] = {"TEST_1.0"};
#endif

#if (!BUILD_HUK_KEY_DERIV_TEST)
	/* Get the TFLM version */
	status = psa_tflm_version(tflm_inf_ver.infer_version, sizeof(tflm_inf_ver.infer_version));
	if (status != PSA_SUCCESS) {
		return status;
	}
	tflm_inf_ver.infer_ver_len = strlen(tflm_inf_ver.infer_version);
#endif

#if (!BUILD_HUK_KEY_DERIV_TEST)
	/* Get the TFLM sine model version */
	status = psa_tflm_model_version(supported_model[0], strlen(supported_model[0]) + 1,
					tflm_inf_ver.model_version,
					sizeof(tflm_inf_ver.model_version));
	if (status != PSA_SUCCESS) {
		return status;
	}
	tflm_inf_ver.model_ver_len = strlen(tflm_inf_ver.model_version);
#endif

#if (!BUILD_HUK_KEY_DERIV_TEST)
	/* Get the MicroTVM version */
	status = psa_utvm_version(utvm_inf_ver.infer_version, sizeof(utvm_inf_ver.infer_version));
	if (status != PSA_SUCCESS) {
		return status;
	}
	utvm_inf_ver.infer_ver_len = strlen(utvm_inf_ver.infer_version);
#endif

#if (!BUILD_HUK_KEY_DERIV_TEST)
	/* Get the MicroTVM model version */
	status = psa_utvm_model_version(supported_model[1], strlen(supported_model[1]) + 1,
					utvm_inf_ver.model_version,
					sizeof(utvm_inf_ver.model_version));
	if (status != PSA_SUCCESS) {
		return status;
	}
	utvm_inf_ver.model_ver_len = strlen(utvm_inf_ver.model_version);
#endif

	status = psa_huk_cose_aat_sign(&tflm_inf_ver, &utvm_inf_ver, encoded_buf,
				       sizeof(encoded_buf), &encoded_buf_len);

	psa_write(msg->handle, 0, encoded_buf, encoded_buf_len);
	psa_write(msg->handle, 1, &encoded_buf_len, sizeof(encoded_buf_len));

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

	return_value = t_cose_sign1_verify(&verify_ctx, completed_encode_sign, /* COSE to verify */
					   &payload, /* Payload from signed_cose */
					   NULL);    /* Don't return parameters */

	if (return_value != T_COSE_SUCCESS) {
		log_err_print("failed with %d", return_value);
	} else {
		log_info_print("COSE signature verification succeeded");
	}

#endif
	return status;
}

static void tfm_aat_signal_handle(psa_signal_t signal, signal_handler_t pfn)
{
	psa_status_t status;
	psa_msg_t msg;

	status = psa_get(signal, &msg);
	switch (msg.type) {
	case PSA_IPC_CONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;
	case PSA_IPC_CALL:
		status = pfn(&msg);
		psa_reply(msg.handle, status);
		break;
	case PSA_IPC_DISCONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;
	default:
		psa_panic();
	}
}

psa_status_t tfm_aat_req_mgr_init(void)
{
	psa_signal_t signals = 0;

	while (1) {
		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
		if (signals & TFM_AAT_SERVICE_SIGNAL) {
			tfm_aat_signal_handle(TFM_AAT_SERVICE_SIGNAL, tfm_cose_create_aat);
		} else {
			psa_panic();
		}
	}

	return PSA_SUCCESS;
}
