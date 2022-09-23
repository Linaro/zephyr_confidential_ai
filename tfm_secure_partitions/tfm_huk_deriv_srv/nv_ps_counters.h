/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __NV_PS_COUNTERS_H__
#define __NV_PS_COUNTERS_H__

#ifdef NV_PS_COUNTERS_SUPPORT

#include <stdint.h>
#include "psa/service.h"

/* The rollover counter tracker is incremented after this max value is reached by the current NV
 * counter tracker and reset the current NV counter tracker to zero.
 */
#define NV_PS_COUNTER_ROLLOVER_MAX (UINT32_MAX - \
				    (UINT32_MAX % NV_COUNTER_TRACKER_THRESHOLD_LIMIT))

typedef psa_status_t (*signal_handler_t)(psa_msg_t *);

typedef enum {
	NV_PS_COUNTER_ROLLOVER_TRACKER = 0,
	NV_PS_COUNTER_TRACKER,
	NS_PS_COUNTER_MAX,
} nv_counter_id_t;

/**
 * \brief Utility function to initialize all NV tracker counters.
 *
 * \param[in]   counter_id  Unique counter ID.
 * \param[out]  value       Pointer to the buffer to store the NV counter value.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
void psa_nv_ps_counter_tracker_init();

/**
 * \brief Utility function to get current NV tracker counter value of given counter ID.
 *
 * \param[in]   counter_id  Unique counter ID.
 * \param[out]  value       Pointer to the buffer to store the NV counter value.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t tfm_get_nv_ps_counter_tracker(nv_counter_id_t counter_id, uint32_t *value);

/**
 * \brief Utility function to increment NV tracker counter value of given counter ID.
 *
 * \param[in]   counter_id  Unique counter ID.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t tfm_inc_nv_ps_counter_tracker(nv_counter_id_t counter_id);

/**
 * \brief Utility function to set NV tracker counter value of the given counter ID.
 *
 * \param[in]   counter_id  Unique counter ID.
 * \param[out]  value       The value to set on the NV counter.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t tfm_set_nv_ps_counter_tracker(nv_counter_id_t counter_id, uint32_t value);

/**
 * \brief Utility function to read NV counter value of the given counter ID from PS.
 *
 * \param[in]   counter_id  Unique counter ID.
 * \param[out]  value       Pointer to the buffer to store the NV counter value.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t psa_read_nv_ps_counter(nv_counter_id_t counter_id, uint32_t *value);

/**
 * \brief Utility function to write NV tracker counter value of the given counter ID to PS.
 *
 * \param[in]   counter_id  Unique counter ID.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t psa_write_nv_ps_counter(nv_counter_id_t counter_id);
#endif

#endif /* __NV_PS_COUNTERS_H__ */
