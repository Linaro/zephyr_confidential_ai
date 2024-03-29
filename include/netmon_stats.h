/*
 * Copyright (c) 2023 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>

#if defined(CONFIG_NETMON_STATS)
#include <zephyr/stats/stats.h>

STATS_SECT_START(netmon)
STATS_SECT_ENTRY32(dhcp_up)
STATS_SECT_ENTRY32(dhcp_down)
STATS_SECT_ENTRY32(sntp_time_sync_count)
STATS_SECT_ENTRY32(sntp_time_req_count)
STATS_SECT_END;

STATS_NAME_START(netmon)
STATS_NAME(netmon, dhcp_up)
STATS_NAME(netmon, dhcp_down)
STATS_NAME(netmon, sntp_time_sync_count)
STATS_NAME(netmon, sntp_time_req_count)
STATS_NAME_END(netmon);
#else
struct stats_netmon {
};
#endif /* CONFIG_NETMON_STATS */

struct stats_netmon *get_netmon_stats_inst();

static inline void netmon_sntp_time_sync_call_stats(struct stats_netmon *stats)
{
#if defined(CONFIG_NETMON_STATS)
	STATS_INC(*stats, sntp_time_sync_count);
#else
	(void)(stats);
#endif
}

static inline void netmon_sntp_time_req_count_stats(struct stats_netmon *stats)
{
#if defined(CONFIG_NETMON_STATS)
	STATS_INC(*stats, sntp_time_req_count);
#else
	(void)(stats);
#endif
}

static inline void netmon_dhcp_stats(bool net_sts, struct stats_netmon *stats)
{
#if defined(CONFIG_NETMON_STATS)
	if (net_sts) {
		STATS_INC(*stats, dhcp_up);
	} else {
		STATS_INC(*stats, dhcp_down);
	}
#else
	(void)(net_sts);
	(void)(stats);
#endif
}

static inline void netmon_stats_init()
{
#if defined(CONFIG_NETMON_STATS)
	struct stats_netmon *stats = get_netmon_stats_inst();

	stats_init(&stats->s_hdr, STATS_SIZE_32, 4, STATS_NAME_INIT_PARMS(netmon));
	stats_register("Netmon", &(stats->s_hdr));
#endif
}
