/*
 * Copyright (c) 2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __TFM_AAT_SERVICE_H__
#define __TFM_AAT_SERVICE_H__

#include <string.h>
#include "tfm_api.h"

#include "psa/service.h"
#include "psa_manifest/tfm_aat_service.h"
#include "../tfm_huk_deriv_srv/tfm_huk_deriv_srv_api.h"
#include "../tfm_tflm_service/tfm_tflm_service_api.h"
#include "../tfm_utvm_service/tfm_utvm_service_api.h"
#define SERV_NAME "AAT SERV"

typedef psa_status_t (*signal_handler_t)(psa_msg_t *);

#endif // __TFM_AAT_SERVICE_H__
