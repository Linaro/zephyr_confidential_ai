/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/zephyr.h>
#include <net/socket.h>

#include <dhcpwait.h>

LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

/* Mutex/condition to indicate state of network status. */
static K_MUTEX_DEFINE(dhcp_lock);
static K_CONDVAR_DEFINE(dhcp_cond);

/* The above protect this variable, which indicates if networking is
 * available. */
static bool dhcp_running;

/* Worker for handling the networking events. */
static struct k_work_delayable check_network_conn;

#define L4_EVENT_MASK (NET_EVENT_L4_CONNECTED | NET_EVENT_L4_DISCONNECTED)

static struct net_mgmt_event_callback l4_mgmt_cb;

/* Wait for networking to be ready.  This can be called by as many
 * threads as desired. */
void await_dhcp(void)
{
	k_mutex_lock(&dhcp_lock, K_FOREVER);
	while (!dhcp_running) {
		k_condvar_wait(&dhcp_cond, &dhcp_lock, K_FOREVER);
	}
	k_mutex_unlock(&dhcp_lock);
}

/* DHCP renewal doesn't generate an event, so this worker is needed to
 * poll the network status.
 */
static void check_network_connection(struct k_work *work)
{
	struct net_if *iface;

	iface = net_if_get_default();
	if (!iface) {
		goto end;
	}

	if (iface->config.dhcpv4.state == NET_DHCPV4_BOUND) {
		/* Wake anyone waiting for network availability */
		k_mutex_lock(&dhcp_lock, K_FOREVER);
		dhcp_running = true;
		k_condvar_broadcast(&dhcp_cond);
		k_mutex_unlock(&dhcp_lock);
		return;
	}

	/* Network was not available, check again in a few seconds. */
end:
	k_work_reschedule(&check_network_conn, K_SECONDS(3));
}

static void l4_event_handler(struct net_mgmt_event_callback *cb,
			     uint32_t mgmt_event, struct net_if *iface)
{
	if ((mgmt_event & L4_EVENT_MASK) != mgmt_event) {
		return;
	}

	if (mgmt_event == NET_EVENT_L4_CONNECTED) {
		/* Start polling to wait for DHCP to be ready. */
		k_work_reschedule(&check_network_conn, K_SECONDS(3));

		return;
	}

	if (mgmt_event == NET_EVENT_L4_DISCONNECTED) {
		/* Stop the connection. */
		k_work_cancel_delayable(&check_network_conn);

		return;
	}
}

/* Setup the dhcp waiter, registering callbacks that will wake up
 * anyone waiting for network availability.
 */
void init_dhcp_wait(void)
{
	k_work_init_delayable(&check_network_conn, check_network_connection);

	net_mgmt_init_event_callback(&l4_mgmt_cb, l4_event_handler,
				     L4_EVENT_MASK);
	net_mgmt_add_event_callback(&l4_mgmt_cb);
}
