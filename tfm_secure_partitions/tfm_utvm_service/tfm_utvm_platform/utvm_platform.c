/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "utvm_platform.h"
#include "tfm_sp_log.h"

#define SERV_NAME "UTVM SERVICE"

/* Memory pool for stack memory manager */
static uint8_t g_aot_memory[WORKSPACE_SIZE];

tvm_workspace_t app_workspace;

void TVMPlatformAbort(tvm_crt_error_t error)
{
	log_err_print("failed with %08x", error);
	psa_panic();

	/* TVMPlatformAbort is declared as __attribute__((noreturn)) and without
	 * the below loop statement it assumes code returns and throws compile
	 * warning.
	 */
	while (true);
}

tvm_crt_error_t TVMPlatformMemoryAllocate(size_t num_bytes,
					  DLDevice dev,
					  void **out_ptr)
{
	return StackMemoryManager_Allocate(&app_workspace, num_bytes, out_ptr);
}

tvm_crt_error_t TVMPlatformMemoryFree(void *ptr, DLDevice dev)
{
	return StackMemoryManager_Free(&app_workspace, ptr);
}

void *TVMBackendAllocWorkspace(int device_type,
			       int device_id,
			       uint64_t nbytes,
			       int dtype_code_hint,
			       int dtype_bits_hint)
{
	tvm_crt_error_t err = kTvmErrorNoError;
	void *ptr = 0;
	DLDevice dev = { device_type, device_id };

	assert(nbytes > 0);
	err = TVMPlatformMemoryAllocate(nbytes, dev, &ptr);
	if (err != kTvmErrorNoError) {
		log_err_print("failed with %08x", err);
	}
	return ptr;
}

int TVMBackendFreeWorkspace(int device_type, int device_id, void *ptr)
{
	tvm_crt_error_t err = kTvmErrorNoError;
	DLDevice dev = { device_type, device_id };

	err = TVMPlatformMemoryFree(ptr, dev);
	return err;
}

void utvm_stack_mgr_init()
{
	tvm_crt_error_t err = StackMemoryManager_Init(&app_workspace, g_aot_memory, WORKSPACE_SIZE);

	if (err != kTvmErrorNoError) {
		log_err_print("failed with %08x", err);
	}
}

#if 0 // TODO
// Called to start system timer.
tvm_crt_error_t TVMPlatformTimerStart()
{
	if (g_microtvm_timer_running) {
		TVMLogf("timer already running");
		return kTvmErrorPlatformTimerBadState;
	}

	k_timer_start(&g_microtvm_timer, TIME_TIL_EXPIRY, TIME_TIL_EXPIRY);
	g_microtvm_start_time = k_cycle_get_32();
	g_microtvm_timer_running = 1;
	return kTvmErrorNoError;
}

// Called to stop system timer.
tvm_crt_error_t TVMPlatformTimerStop(double *elapsed_time_seconds)
{
	if (!g_microtvm_timer_running) {
		TVMLogf("timer not running");
		return kTvmErrorSystemErrorMask | 2;
	}

	uint32_t stop_time = k_cycle_get_32();

	// compute how long the work took
	uint32_t cycles_spent = stop_time - g_microtvm_start_time;
	if (stop_time < g_microtvm_start_time) {
		// we rolled over *at least* once, so correct the rollover it was *only*
		// once, because we might still use this result
		cycles_spent = ~((uint32_t)0) - (g_microtvm_start_time - stop_time);
	}

	uint32_t ns_spent = (uint32_t)k_cyc_to_ns_floor64(cycles_spent);
	double hw_clock_res_us = ns_spent / 1000.0;

	// need to grab time remaining *before* stopping. when stopped, this function
	// always returns 0.
	int32_t time_remaining_ms = k_timer_remaining_get(&g_microtvm_timer);
	k_timer_stop(&g_microtvm_timer);
	// check *after* stopping to prevent extra expiries on the happy path
	if (time_remaining_ms < 0) {
		return kTvmErrorSystemErrorMask | 3;
	}
	uint32_t num_expiries = k_timer_status_get(&g_microtvm_timer);
	uint32_t timer_res_ms = ((num_expiries * MILLIS_TIL_EXPIRY) + time_remaining_ms);
	double approx_num_cycles =
		(double)k_ticks_to_cyc_floor32(1) * (double)k_ms_to_ticks_ceil32(timer_res_ms);
	// if we approach the limits of the HW clock datatype (uint32_t), use the
	// coarse-grained timer result instead
	if (approx_num_cycles > (0.5 * (~((uint32_t)0)))) {
		*elapsed_time_seconds = timer_res_ms / 1000.0;
	} else {
		*elapsed_time_seconds = hw_clock_res_us / 1e6;
	}

	g_microtvm_timer_running = 0;
	return kTvmErrorNoError;
}
#endif
