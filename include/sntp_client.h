/*
 * Copyright (c) 2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/net/sntp.h>
#include <time.h>
#include <mbedtls/platform_time.h>

/**
 * @brief Initialize the SNTP client and
 * store elapsed real time since the system booted in
 * milliseconds from 1st Jan 1970.
 */
void sntp_client_init();

/**
 * @brief Get the time from SNTP server and resync the time base.
 */
void sntp_resync_time();

/**
 * @brief Utility helps to get the current date and time.
 *
 * @param info   Pointer to store the date and time info to time
 * management structure.
 */
void get_current_date_time(struct tm *info);

/**
 * @brief Check the SNTP client initialization.
 *
 * @return True if the SNTP client is initialized.
 *         False if the SNTP client is not initialized.
 */
bool is_sntp_init_done();
