/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "nv_ps_counters.h"
#include "psa/storage_common.h"
#include "psa/protected_storage.h"
#include <string.h>
#include "tfm_sp_log.h"
#include "tfm_huk_deriv_srv_api.h"

#define SERV_NAME "NV PS COUNTERS"

typedef enum {
	NV_PS_COUNTER_ROLLOVER_TRACKER_UID      = 0x4000,
	NV_PS_COUNTER_TRACKER_UID               = 0x4001,
} nv_ps_counters_uid;

static uint32_t nv_ps_counters_tracker[NS_PS_COUNTER_MAX] = { 0 };
static psa_storage_uid_t nv_ps_counter_uids[NS_PS_COUNTER_MAX] = {
	NV_PS_COUNTER_ROLLOVER_TRACKER_UID,
	NV_PS_COUNTER_TRACKER_UID
};
static psa_storage_create_flags_t nv_ps_counter_uid_flag = PSA_STORAGE_FLAG_NONE;

/**
 * \brief Utility function to get current NV counter value of the given counter ID.
 */
psa_status_t tfm_get_nv_ps_counter_tracker(nv_counter_id_t counter_id, uint32_t *value)
{
	if ((counter_id < NV_PS_COUNTER_ROLLOVER_TRACKER) || (counter_id >= NS_PS_COUNTER_MAX)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	*value = nv_ps_counters_tracker[counter_id];
	return PSA_SUCCESS;
}

/**
 * \brief Utility function to increment NV counter value of the given counter ID.
 */
psa_status_t tfm_inc_nv_ps_counter_tracker(nv_counter_id_t counter_id)
{
	if ((counter_id < NV_PS_COUNTER_ROLLOVER_TRACKER) || (counter_id >= NS_PS_COUNTER_MAX)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	nv_ps_counters_tracker[counter_id] += 1;
	return PSA_SUCCESS;
}

/**
 * \brief Utility function to set NV counter value of the given counter ID.
 */
psa_status_t tfm_set_nv_ps_counter_tracker(nv_counter_id_t counter_id, uint32_t value)
{
	if ((counter_id < NV_PS_COUNTER_ROLLOVER_TRACKER) || (counter_id >= NS_PS_COUNTER_MAX)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	nv_ps_counters_tracker[counter_id] = value;
	return PSA_SUCCESS;
}

/**
 * \brief Utility function to write NV tracker counter value of the given counter ID to PS.
 */
psa_status_t psa_write_nv_ps_counter(nv_counter_id_t counter_id)
{
	psa_status_t status = PSA_SUCCESS;

	if ((counter_id < NV_PS_COUNTER_ROLLOVER_TRACKER) || (counter_id >= NS_PS_COUNTER_MAX)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	status = psa_ps_set(nv_ps_counter_uids[counter_id],
			    sizeof(uint32_t),
			    &nv_ps_counters_tracker[counter_id],
			    nv_ps_counter_uid_flag);
	if (status != PSA_SUCCESS) {
		log_err_print("Failed to overwrite id %d nv_ps_counter! (%d)\n", counter_id, status);
	}
	return status;
}

/**
 * \brief Utility function to read NV counter value of the given counter ID.
 */
psa_status_t psa_read_nv_ps_counter(nv_counter_id_t counter_id, uint32_t *value)
{
	psa_status_t status = PSA_SUCCESS;
	size_t bytes_read;

	if ((counter_id < NV_PS_COUNTER_ROLLOVER_TRACKER) || (counter_id >= NS_PS_COUNTER_MAX)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	status = psa_ps_get(nv_ps_counter_uids[counter_id],
			    0,
			    sizeof(uint32_t),
			    value,
			    &bytes_read);
	if (status != PSA_SUCCESS && status != PSA_ERROR_DOES_NOT_EXIST) {
		log_err_print("Failed to get data stored in nv_ps_counter_rollover_uid! (%d)\n",
			      status);
	}
	return status;
}

/**
 * \brief Utility function to initialize all NV tracker counters.
 */
void psa_nv_ps_counter_tracker_init()
{
	psa_status_t status = 0;
	uint32_t nv_ps_counter = 0;

	status = psa_read_nv_ps_counter(NV_PS_COUNTER_TRACKER, &nv_ps_counter);
	if (status != PSA_SUCCESS && status != PSA_ERROR_DOES_NOT_EXIST) {
		log_err_print("Failed to get data stored in nv_ps_counter_uid! (%d)\n",
			      status);
		return status;
	}
	status = tfm_set_nv_ps_counter_tracker(NV_PS_COUNTER_TRACKER, nv_ps_counter);
	if (status != PSA_SUCCESS) {
		return status;
	}
	log_info_print("nv_ps_counter_tracker %u", nv_ps_counter);

	nv_ps_counter = 0;
	status = psa_read_nv_ps_counter(NV_PS_COUNTER_ROLLOVER_TRACKER, &nv_ps_counter);
	if (status != PSA_SUCCESS && status != PSA_ERROR_DOES_NOT_EXIST) {
		log_err_print("Failed to get data stored in nv_ps_counter_rollover_uid! (%d)\n",
			      status);
		return status;
	}
	status = tfm_set_nv_ps_counter_tracker(NV_PS_COUNTER_ROLLOVER_TRACKER, nv_ps_counter);
	if (status != PSA_SUCCESS) {
		return status;
	}
	log_info_print("nv_ps_counter_rollover_tracker %u", nv_ps_counter);
	log_info_print("NV_PS_COUNTER_ROLLOVER_MAX %u", NV_PS_COUNTER_ROLLOVER_MAX);
	log_info_print("NV_COUNTER_TRACKER_THRESHOLD_LIMIT %u", NV_COUNTER_TRACKER_THRESHOLD_LIMIT);
}
