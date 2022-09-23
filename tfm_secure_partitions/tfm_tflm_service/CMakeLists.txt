#
# Copyright (c) 2021-2022 Linaro Limited
#
# SPDX-License-Identifier: Apache-2.0
#

# TFLM Source files
add_subdirectory(tflm)
add_subdirectory(hello_world)

# The name of the target is required to be of the pattern
# tfm_app_rot_partition_x or tfm_psa_rot_partition_x, as it affects how the
# linker script will lay the partition in memory.
add_library(tfm_app_rot_partition_tflm_service STATIC)

target_include_directories(tfm_app_rot_partition_tflm_service
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_tflm_service
)
target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_tflm_service
)

target_sources(tfm_app_rot_partition_tflm_service
    PRIVATE
        tfm_tflm_service.c
        tfm_tflm_service_api.c
)

# The generated sources
target_sources(tfm_app_rot_partition_tflm_service
    PRIVATE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_tflm_service/auto_generated/intermedia_tfm_tflm_service.c>
)
target_sources(tfm_partitions
    INTERFACE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_tflm_service/auto_generated/load_info_tfm_tflm_service.c>
)

target_include_directories(tfm_app_rot_partition_tflm_service
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_tflm_service
)

target_link_libraries(tfm_app_rot_partition_tflm_service
    PRIVATE
        tfm_secure_api
        psa_interface
        platform_s
        tfm_sprt
        tfm_app_rot_partition_tflm_hello_world
        tfm_app_rot_partition_huk_deriv
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_tflm_service
)

target_compile_definitions(tfm_partition_defs
    INTERFACE
        TFM_PARTITION_TFLM_SERVICE
)
