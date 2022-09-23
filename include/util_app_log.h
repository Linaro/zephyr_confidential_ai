/*
 * Copyright (c) 2021 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __UTIL_APP_LOG_H__
#define __UTIL_APP_LOG_H__

#include <stdarg.h>

#include "psa/error.h"
#include "psa/initial_attestation.h"
#include "psa/protected_storage.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Logs PSA response messages other than PSA_SUCCESS for debugging
 *        purposes.
 *
 * @param status        The psa_status_t value to log.
 * @param func_name     The name of the function that made this function call.
 *
 * @return Returns the psa_status_t value passed into the function.
 */
psa_status_t al_psa_status(psa_status_t status, const char *func_name);

/**
 * @brief Calls 'LOG_PROCESS' in Zephyr to dump any queued log messages.
 */
void al_dump_log(void);

#ifdef __cplusplus
}
#endif

#endif /* not __UTIL_APP_LOG_H__ */
