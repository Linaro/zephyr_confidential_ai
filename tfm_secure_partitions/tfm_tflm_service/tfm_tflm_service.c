/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <string.h>

#include "psa/service.h"
#include "psa_manifest/tfm_tflm_service.h"
#include "psa/crypto.h"
#include "tfm_sp_log.h"
#include "tfm_plat_test.h"
#include "target_cfg.h"

#include "constants.h"
#include "../tfm_huk_deriv_srv/tfm_huk_deriv_srv_api.h"
#include "tfm_tflm_service_api.h"
// #include "Driver_I2C.h"
#if defined(CONFIG_SOC_MPS2_AN521) || \
	defined(CONFIG_SOC_MPS3_AN547)
#include "platform_regs.h"
#endif

#include "main_functions.h"

#define SERV_NAME "TFLM SERVICE"

typedef psa_status_t (*signal_handler_t)(psa_msg_t *);



/* The model index is key to finding the tflm model from the tflm_model array
 * and this gets validated in the tflm secure service to select the model to
 * run the inference engine.
 */
typedef enum {
	TFLM_MODEL_SINE = 0,                    /**< Sine inference model index*/
	TFLM_MODEL_COUNT,                       /**< Number of models present */
} tflm_model_idx_t;

typedef struct {
	char tflm_model[TFLM_MODEL_BUFF_SIZE];                  /* List of supported tflm models */
	char tflm_model_version[TFLM_VERSION_BUFF_SIZE];        /* md5sum tflite model calculated value */
} tflm_model_version_t;

typedef struct {
	huk_enc_format_t enc_format;
	char model[32];
} tflm_config_t;

/* Example exported GitHub commit ID is used as a TFLM version because of tflite-micro source
 * (where examples exported) did not have any version attributes.
 */
static const char tflm_version[TFLM_VERSION_BUFF_SIZE] =
	"c2018a7bf84364cc743491a52b41248497569e03";

/* Sine model version is created using
 * `md5sum /path/to/tflite-micro/tensorflow/lite/micro/examples/hello_world/hello_world.tflite`
 */
static const tflm_model_version_t tflm_model_version[TFLM_MODEL_COUNT] =
{ { "TFLM_MODEL_SINE", "27036dd122bc82da54fc0f2d7d99497b" } };

// /* I2C driver name for LSM303 peripheral */
// extern ARM_DRIVER_I2C LSM303_DRIVER;

// /* I2C address of LSM303 peripheral */
// extern const uint8_t lsm303_addr;

// /**
//  * \brief Send data to I2C peripheral
//  */

// static psa_status_t i2c_send_data(uint8_t* i2c_data,
//                                  uint32_t i2c_data_len,
//                                  bool xfer_pending)
// {
//     psa_status_t status = PSA_SUCCESS;

//     LSM303_DRIVER.MasterTransmit (lsm303_addr, i2c_data, i2c_data_len, xfer_pending);

//     /* Wait until transfer completed */
//     while (LSM303_DRIVER.GetStatus().busy);
//     /* Check if all data transferred */
//     if (LSM303_DRIVER.GetDataCount () != i2c_data_len) {
//         LOG_INFFMT("[Example partition] Master transmit data count didn't match...\r\n");
//         status = PSA_ERROR_HARDWARE_FAILURE;
//     }

//     return status;
// }

// /**
//  * \brief Receive data from I2C peripheral
//  */

// static psa_status_t i2c_receive_data(uint8_t* i2c_data,
//                                     uint32_t i2c_data_len,
//                                     bool xfer_pending)
// {
//     psa_status_t status = PSA_SUCCESS;

//     LSM303_DRIVER.MasterReceive (lsm303_addr, i2c_data, i2c_data_len, false);

//     /* Wait until transfer completed */
//     while (LSM303_DRIVER.GetStatus().busy);
//     /* Check if all data transferred */
//     if (LSM303_DRIVER.GetDataCount () != i2c_data_len) {
//         LOG_INFFMT("[Example partition] Master receive data count didn't match...\r\n");
//         status = PSA_ERROR_HARDWARE_FAILURE;
//     }

//     return status;
// }

// /**
//  * \brief Convert LSM303 data
//  */
// static inline double lsm303_data_to_double(const uint16_t data)
// {
//      int32_t tmp_data1;
//     int32_t tmp_data2;

//     tmp_data1 = data / 1100;
//      tmp_data2 = (1000000 * data / 1100) % 1000000;
//     return (double)tmp_data1 + (double)tmp_data2 / 1000000;
// }

// /**
//  * \brief Read from LSM303 peripheral
//  */
// static void tfm_example_read_lsm303(uint8_t hw_initialised)
// {
//     psa_status_t status;
//     psa_msg_t msg;

//     uint8_t i2c_reg_addr;
//     uint8_t i2c_reg_data[6] = {0};
//     // double lsm303_data[3] = {0};

//     /* Retrieve the message corresponding to the example service signal */
//     status = psa_get(TFM_EXAMPLE_READ_LSM303_SIGNAL, &msg);
//     if (status != PSA_SUCCESS) {
//         return;
//     }

//     /* Decode the message */
//     switch (msg.type) {
//     /* Any setup or teardown on IPC connect or disconnect goes here. If
//      * nothing then just reply with success.
//      */
//     case PSA_IPC_CONNECT:
//     case PSA_IPC_DISCONNECT:
//         /* This service does not require any setup or teardown on connect or
//          * disconnect, so just reply with success.
//          */
//         status = PSA_SUCCESS;
//         break;

//     case PSA_IPC_CALL:
//         // Check size of outvec parameter
//         if (msg.out_size[0] != sizeof(i2c_reg_data)) {
//             status = PSA_ERROR_PROGRAMMER_ERROR;
//             break;
//         }

//         /* Hardware init failed, return failure status to unblock the client */
//         if(!hw_initialised) {
//             psa_reply(msg.handle, PSA_ERROR_HARDWARE_FAILURE);
//         }

//         /* Read from LSM303 peripheral */
//         LOG_INFFMT("[Example partition] Start reading LSM303 peripheral...\r\n");

//         /* Check data ready */
//         i2c_reg_addr = 0x9;
//         i2c_send_data(&i2c_reg_addr, sizeof(i2c_reg_addr), true);

//         i2c_receive_data(&i2c_reg_data[0], 1, false);
//         if(!(i2c_reg_data[0] & 1)) {
//             LOG_INFFMT("[Example partition] Sensor data not available...\r\n");
//             status = PSA_ERROR_INSUFFICIENT_DATA;
//             break;
//         }

//         /* Read magnetic sensor data */
//         i2c_reg_addr = 0x3;
//         i2c_send_data(&i2c_reg_addr, sizeof(i2c_reg_addr), true);

//         i2c_receive_data(i2c_reg_data, sizeof(i2c_reg_data), false);

//         // lsm303_data[0] = lsm303_data_to_double((uint16_t)((i2c_reg_data[0] << 8) | i2c_reg_data[1]));
//         // lsm303_data[1] = lsm303_data_to_double((uint16_t)((i2c_reg_data[4] << 8) | i2c_reg_data[5]));
//         // lsm303_data[2] = lsm303_data_to_double((uint16_t)((i2c_reg_data[2] << 8) | i2c_reg_data[3]));

//         psa_write(msg.handle, 0, i2c_reg_data, sizeof(i2c_reg_data));
//         status = PSA_SUCCESS;
//         break;
//     default:
//         /* Invalid message type */
//         status = PSA_ERROR_PROGRAMMER_ERROR;
//         break;
//     }

//     /* Reply with the message result status to unblock the client */
//     psa_reply(msg.handle, status);
// }

/**
 * \brief Run inference using Tensorflow lite-micro
 */
psa_status_t tfm_tflm_infer_run(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	float x_value, y_value;
	uint8_t inf_val_encoded_buf[msg->out_size[0]];
	size_t inf_val_encoded_buf_len = 0;
	tflm_config_t cfg;
	_Bool is_model_supported = false;

	// Check size of invec/outvec parameter
	if (msg->in_size[1] != sizeof(tflm_config_t)) {

		status = PSA_ERROR_PROGRAMMER_ERROR;
		goto err;
	}

	psa_read(msg->handle, 0, &x_value, msg->in_size[0]);
	psa_read(msg->handle, 1, &cfg, sizeof(tflm_config_t));

	for (int i = 0; i < TFLM_MODEL_COUNT; i++) {
		if (strcmp(tflm_model_version[i].tflm_model, cfg.model) == 0) {
			is_model_supported = true;
			break;
		}
	}

	if (!is_model_supported) {
		log_err_print("%s model is not supported", cfg.model);
		status = PSA_ERROR_NOT_SUPPORTED;
		goto err;
	}


	/* This constant kXrange represents the range of x values our model
	 * was trained on, which is from 0 to (2 * Pi). We approximate Pi
	 * to avoid requiring additional libraries.
	 */
	if ((kXrange < x_value) || (x_value < 0.0f)) {
		status = PSA_ERROR_PROGRAMMER_ERROR;
		goto err;
	}

	/* Run inference */
	log_info_print("Starting secure inferencing");
	y_value = loop(x_value);

	log_info_print("Starting CBOR/COSE encoding");
	status = psa_huk_cose_sign(&y_value,
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

psa_status_t tfm_tflm_model_version(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	char model[42] = { 0 };
	_Bool is_model_supported = false;
	int ctx_index = 0;

	/* Check size of invec/outvec parameter */
	if (msg->in_size[0] > sizeof(model) ||
	    msg->out_size[0] != TFLM_VERSION_BUFF_SIZE) {
		status = PSA_ERROR_PROGRAMMER_ERROR;
		goto err;
	}

	psa_read(msg->handle, 0, model, msg->in_size[0]);
	for (int i = 0; i < TFLM_MODEL_COUNT; i++) {
		if (strcmp(tflm_model_version[i].tflm_model, model) == 0) {
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
		  tflm_model_version[ctx_index].tflm_model_version,
		  strlen(tflm_model_version[ctx_index].tflm_model_version));
err:
	return status;
}

psa_status_t tfm_tflm_version_info(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;

	/* Check size of invec/outvec parameter */
	if (msg->out_size[0] != TFLM_VERSION_BUFF_SIZE) {
		status = PSA_ERROR_PROGRAMMER_ERROR;
		goto err;
	}

	psa_write(msg->handle,
		  0,
		  tflm_version,
		  strlen(tflm_version));
err:
	return status;
}

void tfm_tflm_signal_handle(psa_signal_t signal, signal_handler_t pfn)
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
void tfm_tflm_service_req_mngr_init(void)
{
	psa_signal_t signals;

	// uint8_t i2c_reg_data[2] = {0};
	// uint8_t lsm303_init_completed = 1;

	// /* LSM303 DLHC */
	// LOG_INFFMT("[Example partition] Configuring I2C3 as secure peripheral...\r\n");
	// ppc_configure_to_secure(PPC_SP_APB_PPC_EXP1, CMSDK_I2C3_APB_PPC_POS);

	// LOG_INFFMT("[Example partition] Initialising I2C bus...\r\n");
	// LSM303_DRIVER.Initialize(NULL);
	// LSM303_DRIVER.PowerControl (ARM_POWER_FULL);
	// LSM303_DRIVER.Control      (ARM_I2C_BUS_SPEED, ARM_I2C_BUS_SPEED_STANDARD);
	// LSM303_DRIVER.Control      (ARM_I2C_BUS_CLEAR, 0);

	// /* Set magnetometer output data rate */
	// i2c_reg_data[0] = 0x0;
	// i2c_reg_data[1] = 0x0;
	// if(i2c_send_data(i2c_reg_data, sizeof(i2c_reg_data), false) != PSA_SUCCESS) {
	//     lsm303_init_completed = 0;
	// }

	// /* Set magnetometer full scale range */
	// i2c_reg_data[0] = 0x1;
	// i2c_reg_data[1] = 1 << 5;
	// if(i2c_send_data(i2c_reg_data, sizeof(i2c_reg_data), false) != PSA_SUCCESS) {
	//     lsm303_init_completed = 0;
	// }

	// /* Continuous update */
	// i2c_reg_data[0] = 0x2;
	// i2c_reg_data[1] = 0x0;
	// if(i2c_send_data(i2c_reg_data, sizeof(i2c_reg_data), false) != PSA_SUCCESS) {
	//     lsm303_init_completed = 0;
	// }

	// LOG_INFFMT("[Example partition] Initialisation of I2C bus completed\r\n");

	/* Tensorflow lite-micro initialisation */
	setup();

	log_info_print("TFLM initalisation completed");

	/* Continually wait for one or more of the partition's RoT Service or
	 * interrupt signals to be asserted and then handle the asserted signal(s).
	 */
	while (1) {
		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

		// if (signals & TFM_READ_LSM303_SIGNAL) {
		//     tfm_example_read_lsm303(lsm303_init_completed);
		// }

		if (signals & TFM_TFLM_SERVICE_HELLO_SIGNAL) {
			tfm_tflm_signal_handle(
				TFM_TFLM_SERVICE_HELLO_SIGNAL,
				tfm_tflm_infer_run);
		} else if (signals & TFM_TFLM_MODEL_VERSION_INFO_SERVICE_SIGNAL) {
			tfm_tflm_signal_handle(
				TFM_TFLM_MODEL_VERSION_INFO_SERVICE_SIGNAL,
				tfm_tflm_model_version);
		} else if (signals & TFM_TFLM_VERSION_INFO_SERVICE_SIGNAL) {
			tfm_tflm_signal_handle(
				TFM_TFLM_VERSION_INFO_SERVICE_SIGNAL,
				tfm_tflm_version_info);
		} else {
			psa_panic();
		}
	}
}
