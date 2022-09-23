#-------------------------------------------------------------------------------
# Copyright (c) 2022, Linaro. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#-------------------------------------------------------------------------------

# The MPS2/MPS3 boards in TF-M use a hard-coded value for the HUK, meaning
# every HUK-derived key value will be identical. HUK_DERIV_LABEL_EXTRA appends
# the supplied string to the label used for key derivation, enabling key
# diversity during testing with MPSx boards in QEMU. It can be set at compile
# time via '-DHUK_DERIV_LABEL_EXTRA=value'.
set(HUK_DERIV_LABEL_EXTRA  "" CACHE STRING "Additional key derivation label value.")
set(NV_PS_COUNTERS_SUPPORT OFF CACHE BOOL "NV PS counters support.")
set(BUILD_HUK_KEY_DERIV_TEST false CACHE BOOL "HUK key deriv integration test")

# To avoid buffer issues, the string must be <= 15 characters
string(LENGTH "${HUK_DERIV_LABEL_EXTRA}" size)
if(size GREATER 15)
  message(FATAL_ERROR "HUK_DERIV_LABEL_EXTRA must be less than 16 characters")
endif()

# Display label value if available
string(COMPARE NOTEQUAL "${HUK_DERIV_LABEL_EXTRA}" "" notnull)
if(notnull)
  message("-- HUK_DERIV_LABEL_EXTRA is set to ${HUK_DERIV_LABEL_EXTRA}")
endif()

# Make the label value available in the C project
add_compile_definitions(HUK_DERIV_LABEL_EXTRA="${HUK_DERIV_LABEL_EXTRA}")

# Define the NV_PS_COUNTERS_SUPPORT in the C project
if(NV_PS_COUNTERS_SUPPORT)
    add_compile_definitions(NV_PS_COUNTERS_SUPPORT)
endif()

# Make the NV_COUNTER_TRACKER_THRESHOLD_LIMIT available in the C project
add_compile_definitions(NV_COUNTER_TRACKER_THRESHOLD_LIMIT=${NV_COUNTER_TRACKER_THRESHOLD_LIMIT})

# Make the BUILD_HUK_KEY_DERIV_TEST available in the C project
add_compile_definitions(BUILD_HUK_KEY_DERIV_TEST=${BUILD_HUK_KEY_DERIV_TEST})
