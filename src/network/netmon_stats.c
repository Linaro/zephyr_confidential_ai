/*
 * Copyright (c) 2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "netmon_stats.h"

#if !defined(CONFIG_NETMON_STATS)
#include <stddef.h>
#endif

struct stats_netmon *get_netmon_stats_inst()
{
#if defined(CONFIG_NETMON_STATS)
	static struct stats_netmon stats;
	return &stats;
#else
	return (struct stats_netmon *)NULL;
#endif
}
