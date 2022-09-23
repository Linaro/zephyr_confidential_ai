/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __TFM_UTVM_SERVICE_API_H__
#define __TFM_UTVM_SERVICE_API_H__

#include <stddef.h>
#include <stdbool.h>

#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "psa/crypto.h"

#define UTVM_VERSION_BUFF_SIZE 42
#define UTVM_MODEL_BUFF_SIZE   32

/**
 * \brief Get the MicroTVM version
 *
 * \param[out] utvm_ver     Buffer to which TFLM version data is written into
 * \param[out] utvm_ver_len utvm_ver buffer length in bytes
 *
 * \return A status indicating the success/failure of the operation
 */
psa_status_t psa_utvm_version(char *utvm_ver,
			      size_t utvm_ver_len);

/**
 * \brief Get the MicroTVM model version
 *
 * \param[in]  model              Model name
 * \param[in]  model_len          Model name length in bytes
 * \param[out] utvm_model_ver     Buffer to which MicroTVM model version data is written into
 * \param[out] utvm_model_ver_len utvm_model_ver buffer length in bytes
 *
 * \return A status indicating the success/failure of the operation
 */
psa_status_t psa_utvm_model_version(char *model,
				    uint8_t model_len,
				    char *utvm_model_ver,
				    size_t utvm_model_ver_len);

#endif // __TFM_UTVM_SERVICE_API_H__
