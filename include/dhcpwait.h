/*
 * Copyright (c) 2022-2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __DHCPWAIT_H__
#define __DHCPWAIT_H__

/**
 * @brief Setup the dhcp waiter, registering callbacks that will wake up
 * anyone waiting for network availability.
 */
void init_dhcp_wait(void);

/**
 * @brief Wait for networking to be ready.  This can be called by as many
 * threads as desired.
 */
void await_dhcp(void);

/**
 * @brief Check the network state.
 *
 * @return True if the network is up.
 *         False if the network is down.
 */
bool is_dhcp_up(void);

#endif /* not __DHCPWAIT_H__ */
