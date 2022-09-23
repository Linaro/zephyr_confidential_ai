/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <string.h>

#include "psa/service.h"
#include "psa_manifest/tfm_test_helper_service.h"
#include "psa/crypto.h"
#include "tfm_sp_log.h"
#include "tfm_plat_test.h"
#include "target_cfg.h"

#include "../../tests/tfm_sp/test_service/tfm_test_helper_service_api.h"
#include "../tfm_huk_deriv_srv/tfm_huk_deriv_srv_api.h"

#if defined(CONFIG_SOC_MPS2_AN521) || \
	defined(CONFIG_SOC_MPS3_AN547)
#include "platform_regs.h"
#endif

#define SERV_NAME "TEST_HELPER SERVICE"
#define INFER_ENC_MAX_VALUE_SZ (256)

typedef psa_status_t (*signal_handler_t)(psa_msg_t *);
/**
 * \brief Run tfm test helper service
 */
psa_status_t tfm_test_helper_run(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	tfm_th_test_list_t test_to_run;
	float y_value = 0.0;
	uint8_t encoded_buf[INFER_ENC_MAX_VALUE_SZ];
	size_t encoded_buf_len = 0;
	test_run_status_t sts = TEST_UNKNOWN;

	// Check size of invec/outvec parameter
	if (msg->in_size[0] != sizeof(tfm_th_test_list_t)) {

		status = PSA_ERROR_PROGRAMMER_ERROR;
		goto err;
	}

	psa_read(msg->handle, 0, &test_to_run, msg->in_size[0]);

	switch (test_to_run) {
	case TEST_HUK_ENC_CBOR:
		log_info_print("TEST: Starting CBOR encoding");
		y_value = 0.203328; /* Sample sin(9) */
		status = psa_huk_cose_sign(&y_value,
					   HUK_ENC_CBOR,
					   encoded_buf,
					   INFER_ENC_MAX_VALUE_SZ,
					   &encoded_buf_len);
		if (status != PSA_SUCCESS) {
			log_err_print("failed with %d", status);
			goto err;
		}
		sts = TEST_SUCCEED;
		break;
	case TEST_HUK_ENC_COSE_SIGN1:
		log_info_print("TEST: Starting COSE SIGN");
		y_value = 0.237216; /* Sample sin(10) */
		status = psa_huk_cose_sign(&y_value,
					   HUK_ENC_COSE_SIGN1,
					   encoded_buf,
					   INFER_ENC_MAX_VALUE_SZ,
					   &encoded_buf_len);
		if (status != PSA_SUCCESS) {
			log_err_print("failed with %d", status);
			goto err;
		}
		sts = TEST_SUCCEED;
		break;
	case TEST_HUK_ENC_WRONG_FORMAT:
		log_info_print("TEST: CBOR encoding wrong format");
		break;
	case TEST_HUK_ENC_BUFFER_UNDERFLOW:
		log_info_print("TEST: Buffer Underflow");
		break;
	case TEST_HUK_COSE_VERIFY_SIGN:
		log_info_print("TEST: VERIFY SIGN");
		break;
	case TEST_HUK_VERIFY_COSE_SIGN_FAIL:
		log_info_print("TEST: COSE Sign failed");
		break;
	}
	psa_write(msg->handle,
		  0,
		  &sts,
		  sizeof(test_run_status_t));

err:
	return status;
}

void tfm_test_helper_signal_handle(psa_signal_t signal, signal_handler_t pfn)
{
	psa_status_t status;
	psa_msg_t msg;

	status = psa_get(signal, &msg);
	/* Decode the message */
	switch (msg.type) {
	/* Any setup or teardown on IPC connect or disconnect goes here. If
	 * nothing then just reply with success.
	 */
	case PSA_IPC_CONNECT:
	case PSA_IPC_DISCONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;

	case PSA_IPC_CALL:
		status = pfn(&msg);
		psa_reply(msg.handle, status);
		break;
	default:
		psa_panic();
	}
}

/**
 * \brief The TFLM service partition's entry function.
 */
void tfm_test_helper_service_req_mngr_init(void)
{
	psa_signal_t signals;

	log_info_print("TFM Test helper service");

	/* Continually wait for one or more of the partition's RoT Service or
	 * interrupt signals to be asserted and then handle the asserted signal(s).
	 */
	while (1) {
		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

		if (signals & TFM_TEST_HELPER_SERVICE_SIGNAL) {
			tfm_test_helper_signal_handle(
				TFM_TEST_HELPER_SERVICE_SIGNAL,
				tfm_test_helper_run);
		} else {
			psa_panic();
		}
	}
}
