/*
 * Copyright (c) 2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include "sntp_client.h"
#include "dhcpwait.h"
#include "netmon_stats.h"

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
	netmon_sntp_time_sync_call_stats(get_netmon_stats_inst());

	/* Reschedule the worker therad to resync the time base with SNTP server. */
	k_work_reschedule(&time_sync, K_HOURS(CONFIG_NETMON_SNTP_RESYNC_TIMEBASE));
}

void netmon_mgmt_sntp_init()
{
	sntp_client_init();
	k_work_reschedule(&time_sync, K_HOURS(CONFIG_NETMON_SNTP_RESYNC_TIMEBASE));
}

/* Network monitor management thread */
void netmon_mgmt_thread(void)
{
	/* Initialize the netmon stats */
	netmon_stats_init();
	/* Wait for the network interface to be up. */
	LOG_INF("Waiting for network...");
	await_dhcp();
	netmon_dhcp_stats(true, get_netmon_stats_inst());
	k_work_init_delayable(&time_sync, netmon_mgmt_time_sync);
	netmon_mgmt_sntp_init();
	/* Start a network monitoring. */
	while (true) {
		if (is_dhcp_up()) {
			k_sleep(K_SECONDS(4));
		} else {
			/* TO handle network down */
			k_work_cancel_delayable(&time_sync);
			netmon_dhcp_stats(false, get_netmon_stats_inst());
			await_dhcp();
			netmon_dhcp_stats(true, get_netmon_stats_inst());
			/* TODO TLS re-intialization */
			k_work_reschedule(&time_sync, K_SECONDS(1));
		}
	}
}

K_THREAD_DEFINE(netmon_mgmt, CONFIG_NETMON_STACK_SIZE, netmon_mgmt_thread, NULL, NULL, NULL,
		NETMON_THREAD_PRIORITY, 0, 500);
