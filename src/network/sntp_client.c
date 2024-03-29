/*
 * Copyright (c) 2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
#include <zephyr/posix/time.h>
#include <zephyr/posix/sys/time.h>
#include "sntp_client.h"
#include "netmon_stats.h"

LOG_MODULE_REGISTER(sntp_client, CONFIG_LOG_DEFAULT_LEVEL);

#define SNTP_TIME_SYNC_BIT_POSITION 0
#define SNTP_TIME_SYNC_ATOMIC_NUM_BITS	   1

/* The network status atomic variable is used for finding the network condition,
 * which can be read and modified by threads in an uninterruptible manner.
 */
ATOMIC_DEFINE(sntp_time_up, SNTP_TIME_SYNC_ATOMIC_NUM_BITS);

#define SNTP_MAX_RETRY_SERVER_REQ 2

/* Store elapsed real time since the system booted in milliseconds. */
static int64_t device_up_time_ms;

mbedtls_time_t sub_mbedtls_time(mbedtls_time_t *time)
{
	(void)time;
	int res;
	struct timeval spec;

	res = gettimeofday(&spec, NULL);
	if (res) {
		LOG_ERR("gettimeofday failed, errno %d", res);
		return -ENODATA;
	}

	return spec.tv_sec;
}

bool is_sntp_init_done()
{
	return atomic_test_bit(sntp_time_up, SNTP_TIME_SYNC_BIT_POSITION);
}

/* Get the timestamp in seconds since 1st Jan 1970 and store it
 * in the time_base tracking variable.
 */
int sntp_client_get_time(time_t *sec)
{
	int ret;
	struct sntp_time sntp_time;
	struct timespec time_spec;

	LOG_INF("Sending SNTP request for current time:");
	for (int retry = 1; retry <= SNTP_MAX_RETRY_SERVER_REQ; retry++) {
		ret = sntp_simple(CONFIG_SNTP_SERVER, SYS_FOREVER_MS, &sntp_time);
		if (ret < 0) {
			LOG_ERR("Failed to SNTP current time: %d", ret);
			if (retry == SNTP_MAX_RETRY_SERVER_REQ) {
				return ret;
			}
		} else {
			break;
		}
	}
	/* Update the system clock time */
	time_spec.tv_sec = sntp_time.seconds;
	time_spec.tv_nsec = ((uint64_t)sntp_time.fraction * (1000 * 1000 * 1000)) >> 32;
	ret = clock_settime(CLOCK_REALTIME, &time_spec);
	if (ret != 0) {
		LOG_ERR("Failed to set system time, %d", ret);
	}

	*sec = sntp_time.seconds;

	/* Increment the sntp time req stats counter */
	netmon_sntp_time_req_count_stats(get_netmon_stats_inst());

	return ret;
}

/* Get the current time in seconds since 1st Jan 1970.
 */
time_t get_current_time()
{
	int res;
	struct timeval spec;

	res = gettimeofday(&spec, NULL);
	if (res) {
		LOG_ERR("gettimeofday failed, errno %d", res);
		return -ENODATA;
	}

	time_t current_time_ms = spec.tv_sec * 1000;

	return current_time_ms;
}

/* Get the real date and timestamp info in the time management structure. */
void get_current_date_time(struct tm *info)
{
	time_t current_time_sec;

	current_time_sec = get_current_time() / MSEC_PER_SEC;
	gmtime_r(&current_time_sec, info);
	LOG_INF("Data and time: %04u-%02u-%02u %02u:%02u:%02u", info->tm_year + 1900,
		info->tm_mon + 1, info->tm_mday, info->tm_hour, info->tm_min, info->tm_sec);
}

/* Get the latest time from the SNTP server and align the time base. */
void sntp_resync_time()
{
	int ret;
	time_t sec;
	struct tm info;

	ret = sntp_client_get_time(&sec);
	if (ret < 0) {
		LOG_ERR("Failed to sync time: %d", ret);
		return;
	}

	get_current_date_time(&info);
}

void sntp_client_init()
{
	struct tm info;
	int ret;
	time_t sec;

	ret = sntp_client_get_time(&sec);
	if (ret < 0) {
		LOG_ERR("Failed to SNTP init: %d", ret);
		return;
	}
	device_up_time_ms = (sec * MSEC_PER_SEC - k_uptime_get());
	mbedtls_platform_set_time(sub_mbedtls_time);
	atomic_set_bit(sntp_time_up, SNTP_TIME_SYNC_BIT_POSITION);
	gmtime_r(&sec, &info);
	LOG_INF("Data and time: %04u-%02u-%02u %02u:%02u:%02u", info.tm_year + 1900,
		info.tm_mon + 1, info.tm_mday, info.tm_hour, info.tm_min, info.tm_sec);
}
