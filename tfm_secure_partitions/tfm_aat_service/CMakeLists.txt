#
# Copyright (c) 2023 Linaro Limited
#
# SPDX-License-Identifier: Apache-2.0
#

# The name of the target is required to be of the pattern
# tfm_app_rot_partition_x or tfm_psa_rot_partition_x, as it affects how the
# linker script will lay the partition in memory.
add_library(tfm_app_rot_partition_aat_service STATIC)

target_include_directories(tfm_app_rot_partition_aat_service
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_aat_service
)
target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_aat_service
)

target_sources(tfm_app_rot_partition_aat_service
    PRIVATE
        tfm_aat_service.c
)

# The generated sources
target_sources(tfm_app_rot_partition_aat_service
    PRIVATE
       ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_aat_service/auto_generated/intermedia_tfm_aat_service.c
)
target_sources(tfm_partitions
    INTERFACE
       ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_aat_service/auto_generated/load_info_tfm_aat_service.c
)

target_link_libraries(tfm_app_rot_partition_aat_service
    PRIVATE
        platform_s
        tfm_sprt
        tfm_app_rot_partition_tflm
        tfm_app_rot_partition_utvm
)

target_link_libraries(tfm_spm
    PRIVATE
        tfm_app_rot_partition_aat_service
)

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_aat_service
)

target_compile_definitions(tfm_partition_defs
    INTERFACE
        TFM_PARTITION_AAT_SERVICE
)
