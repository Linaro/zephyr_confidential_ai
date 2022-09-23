/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <string.h>

#include "psa/service.h"
#include "psa_manifest/tfm_utvm_service.h"
#include "psa/crypto.h"
#include "tfm_sp_log.h"
#include "tfm_plat_test.h"
#include "target_cfg.h"
#include "../tfm_huk_deriv_srv/tfm_huk_deriv_srv_api.h"
#include "tfm_utvm_service_api.h"
#if defined(CONFIG_SOC_MPS2_AN521) || \
	defined(CONFIG_SOC_MPS3_AN547)
#include "platform_regs.h"
#endif
#include "tvmgen_default.h"
#include "utvm_platform.h"

#define SERV_NAME "UTVM SERVICE"

typedef psa_status_t (*signal_handler_t)(psa_msg_t *);

/* The model index is key to finding the utvm model from the utvm_models array
 * and this gets validated in the utvm secure service to select the model to
 * run the inference engine.
 */
typedef enum {
	UTVM_MODEL_SINE = 0,                    /**< Sine inference model index*/
	UTVM_MODEL_COUNT,                       /**< Number of models present */
} utvm_model_idx_t;

typedef struct {
	char utvm_model[UTVM_MODEL_BUFF_SIZE];                  /* List of supported utvm models */
	char utvm_model_version[UTVM_VERSION_BUFF_SIZE];        /* md5sum tflite model calculated value */
} utvm_model_version_t;

typedef struct {
	huk_enc_format_t enc_format;
	char model[32];
} utvm_config_t;

/* Get the MicroTVM version using `tvmc --version` command */
static const char utvm_version[UTVM_VERSION_BUFF_SIZE] = "0.9.dev0";

/* Sine model version is created using `md5sum /path/to/sine_model.tflite` */
static const utvm_model_version_t utvm_model_version[UTVM_MODEL_COUNT] =
{ { "UTVM_MODEL_SINE", "b8085238f6e790f25de393e203136776" } };

/**
 * \brief Run inference using UTVM
 */
psa_status_t tfm_utvm_infer_run(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	float model_in_val, model_out_val;
	uint8_t inf_val_encoded_buf[msg->out_size[0]];
	_Bool is_model_supported = false;
	size_t inf_val_encoded_buf_len = 0;
	utvm_config_t cfg;

	/* Check size of invec/outvec parameter */
	if (msg->in_size[1] != sizeof(utvm_config_t)) {
		status = PSA_ERROR_PROGRAMMER_ERROR;
		goto err;
	}

	utvm_stack_mgr_init();
	psa_read(msg->handle, 0, &model_in_val, msg->in_size[0]);
	psa_read(msg->handle, 1, &cfg, sizeof(utvm_config_t));

	for (int i = 0; i < UTVM_MODEL_COUNT; i++) {
		if (strcmp(utvm_model_version[i].utvm_model, cfg.model) == 0) {
			is_model_supported = true;
			break;
		}
	}

	if (!is_model_supported) {
		log_err_print("%s model is not supported", cfg.model);
		status = PSA_ERROR_NOT_SUPPORTED;
		goto err;
	}

	struct tvmgen_default_inputs inputs = {
		.dense_4_input = (void *)&model_in_val,
	};
	struct tvmgen_default_outputs outputs = {
		.Identity = (void *)&model_out_val,
	};

	/* Run inference */
	log_info_print("Starting secure inferencing");
	status = tvmgen_default_run(&inputs, &outputs);
	if (status != 0) {
		log_err_print("failed with %d", status);
		goto err;
	}

	log_info_print("Starting CBOR/COSE encoding");
	status = psa_huk_cose_sign(&model_out_val,
				   cfg.enc_format,
				   inf_val_encoded_buf,
				   msg->out_size[0],
				   &inf_val_encoded_buf_len);
	if (status != PSA_SUCCESS) {
		log_err_print("failed with %d", status);
		goto err;
	}

	psa_write(msg->handle,
		  0,
		  inf_val_encoded_buf,
		  inf_val_encoded_buf_len);
	psa_write(msg->handle,
		  1,
		  &inf_val_encoded_buf_len,
		  sizeof(inf_val_encoded_buf_len));

err:
	return status;
}

psa_status_t tfm_utvm_model_version(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	char model[42] = { 0 };
	_Bool is_model_supported = false;
	int ctx_index = 0;

	/* Check size of invec/outvec parameter */
	if (msg->in_size[0] > sizeof(model) ||
	    msg->out_size[0] != UTVM_VERSION_BUFF_SIZE) {
		status = PSA_ERROR_PROGRAMMER_ERROR;
		goto err;
	}

	psa_read(msg->handle, 0, model, msg->in_size[0]);
	for (int i = 0; i < UTVM_MODEL_COUNT; i++) {
		if (strcmp(utvm_model_version[i].utvm_model, model) == 0) {
			is_model_supported = true;
			ctx_index = i;
			break;
		}
	}

	if (!is_model_supported) {
		log_err_print("%s model is not supported", model);
		status = PSA_ERROR_NOT_SUPPORTED;
		goto err;
	}

	psa_write(msg->handle,
		  0,
		  utvm_model_version[ctx_index].utvm_model_version,
		  strlen(utvm_model_version[ctx_index].utvm_model_version));

err:
	return status;
}

psa_status_t tfm_utvm_version_info(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;

	/* Check size of invec/outvec parameter */
	if (msg->out_size[0] != UTVM_VERSION_BUFF_SIZE) {
		status = PSA_ERROR_PROGRAMMER_ERROR;
		goto err;
	}

	psa_write(msg->handle,
		  0,
		  utvm_version,
		  strlen(utvm_version));
err:
	return status;
}

void tfm_utvm_signal_handle(psa_signal_t signal, signal_handler_t pfn)
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
 * \brief The UTVM service partition's entry function.
 */
void tfm_utvm_service_req_mngr_init(void)
{
	psa_signal_t signals;

	log_info_print("UTVM initalisation completed");

	/* Continually wait for one or more of the partition's RoT Service or
	 * interrupt signals to be asserted and then handle the asserted signal(s).
	 */
	while (1) {
		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

		if (signals & TFM_UTVM_SINE_MODEL_SERVICE_SIGNAL) {
			tfm_utvm_signal_handle(
				TFM_UTVM_SINE_MODEL_SERVICE_SIGNAL,
				tfm_utvm_infer_run);
		} else if (signals & TFM_UTVM_MODEL_VERSION_INFO_SERVICE_SIGNAL) {
			tfm_utvm_signal_handle(
				TFM_UTVM_MODEL_VERSION_INFO_SERVICE_SIGNAL,
				tfm_utvm_model_version);
		} else if (signals & TFM_UTVM_VERSION_INFO_SERVICE_SIGNAL) {
			tfm_utvm_signal_handle(
				TFM_UTVM_VERSION_INFO_SERVICE_SIGNAL,
				tfm_utvm_version_info);
		} else {
			psa_panic();
		}
	}
}
