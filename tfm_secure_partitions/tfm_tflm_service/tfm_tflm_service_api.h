/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __TFM_TFLM_SERVICE_API_H__
#define __TFM_TFLM_SERVICE_API_H__

#include <stddef.h>
#include <stdbool.h>

#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "psa/crypto.h"

#define TFLM_VERSION_BUFF_SIZE 42
#define TFLM_MODEL_BUFF_SIZE 32

/**
 * \brief Get the TFLM version
 *
 * \param[out] tflm_ver     Buffer to which TFLM version data is written into
 * \param[out] tflm_ver_len tflm_ver buffer length in bytes
 *
 * \return A status indicating the success/failure of the operation
 */
psa_status_t psa_tflm_version(char *tflm_ver,
			      size_t tflm_ver_len);

/**
 * \brief Get the TFLM model version
 *
 * \param[in]  model              Model name
 * \param[in]  model_len          Model name length in bytes
 * \param[out] tflm_model_ver     Buffer to which tflm model version data is written into
 * \param[out] tflm_model_ver_len tflm_model_ver buffer length in bytes
 *
 * \return A status indicating the success/failure of the operation
 */
psa_status_t psa_tflm_model_version(char *model,
				    size_t model_len,
				    char *tflm_model_ver,
				    size_t tflm_model_ver_len);

#endif // __TFM_TFLM_SERVICE_API_H__
