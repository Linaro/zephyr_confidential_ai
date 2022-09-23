/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __TFM_UTVM_PLATFORM__
#define __TFM_UTVM_PLATFORM__
#include <assert.h>
#include <tvm/runtime/c_runtime_api.h>
#include <tvm/runtime/crt/stack_allocator.h>
#include <psa/service.h>
#include <string.h>

#include "../../tfm_huk_deriv_srv/tfm_huk_deriv_srv_api.h"
#include "tvmgen_default.h"

/* Memory footprint for running the inference model */
#define WORKSPACE_SIZE TVMGEN_DEFAULT_WORKSPACE_SIZE

/**
 * \brief Initialize the stack manager
 */
void utvm_stack_mgr_init();

#endif // __TFM_UTVM_PLATFORM__
