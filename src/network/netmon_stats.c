/*
 * Copyright (c) 2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "netmon_stats.h"

#if defined(CONFIG_NETMON_STATS)
struct stats_netmon *get_netmon_stats_inst()
{
	static struct stats_netmon stats;

	return &stats;
}
#else
#include <stddef.h>
struct stats_netmon *get_netmon_stats_inst()
{
	return (struct stats_netmon *)NULL;
}
#endif
