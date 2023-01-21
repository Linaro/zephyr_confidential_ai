/*
 * Copyright (c) 2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include "sntp_client.h"
#include "dhcpwait.h"

LOG_MODULE_REGISTER(netmon_mgmt, CONFIG_LOG_DEFAULT_LEVEL);

#define NETMON_THREAD_PRIORITY 5
static struct k_work_delayable time_sync;

/* Network monitor management worker thread work item to sync
 * the time with SNTP server.
 */
static void netmon_mgmt_time_sync(struct k_work *work)
{

	if (!is_dhcp_up()) {
		LOG_ERR("Network down");
		k_work_cancel_delayable(&time_sync);
		return;
	}
	sntp_resync_time();

	/* Reschedule the worker therad to resync the time base with SNTP server. */
	k_work_reschedule(&time_sync, K_HOURS(24));
}

void netmon_mgmt_sntp_init()
{
	sntp_client_init();
	k_work_reschedule(&time_sync, K_HOURS(24));
}

/* Network monitor management thread */
void netmon_mgmt_thread(void)
{
	/* Wait for the network interface to be up. */
	LOG_INF("Netmon: waiting for network...");
	await_dhcp();
	k_work_init_delayable(&time_sync, netmon_mgmt_time_sync);
	netmon_mgmt_sntp_init();
	/* Start a network monitoring. */
	while (true) {
		if (is_dhcp_up()) {
			k_sleep(K_SECONDS(4));
		} else {
			/* TO handle network down */
			k_work_cancel_delayable(&time_sync);
			// TODO implementation to log any critical events
			await_dhcp();
			// TODO TLS re-intialization
			k_work_reschedule(&time_sync, K_SECONDS(1));
		}
	}
}

K_THREAD_DEFINE(netmon_mgmt, CONFIG_NETMON_STACK_SIZE, netmon_mgmt_thread, NULL, NULL, NULL,
		NETMON_THREAD_PRIORITY, 0, 500);
