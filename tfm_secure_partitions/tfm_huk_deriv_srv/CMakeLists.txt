#
# Copyright (c) 2021-2022 Linaro Limited
#
# SPDX-License-Identifier: Apache-2.0
#

# The name of the target is required to be of the pattern
# tfm_app_rot_partition_x or tfm_psa_rot_partition_x, as it affects how the
# linker script will lay the partition in memory.
add_library(tfm_app_rot_partition_huk_deriv STATIC)

include(config.cmake)

target_include_directories(tfm_app_rot_partition_huk_deriv
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_huk_deriv_srv
)
target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_huk_deriv_srv
)

if(NV_PS_COUNTERS_SUPPORT)
    list(APPEND tfm_huk_service_files
      nv_ps_counters.c
    )
endif()

list(APPEND tfm_huk_service_files
    tfm_huk_deriv_srv.c
    tfm_huk_deriv_srv_api.c
    cbor_cose.c
    aat.c
)

target_sources(tfm_app_rot_partition_huk_deriv
    PRIVATE
        ${tfm_huk_service_files}
)

# The generated sources
target_sources(tfm_app_rot_partition_huk_deriv
    PRIVATE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_huk_deriv_srv/auto_generated/intermedia_tfm_huk_deriv_srv.c>
)
target_sources(tfm_partitions
    INTERFACE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_huk_deriv_srv/auto_generated/load_info_tfm_huk_deriv_srv.c>
)

target_link_libraries(tfm_app_rot_partition_huk_deriv
    PRIVATE
        tfm_secure_api
        psa_interface
        secure_fw
        platform_s
        tfm_qcbor_s
        tfm_t_cose_s
        tfm_sprt
        tfm_psa_rot_partition_crypto
)

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_huk_deriv
)

target_compile_definitions(tfm_partition_defs
    INTERFACE
        TFM_PARTITION_HUK_KEY_DERIVATION
)
