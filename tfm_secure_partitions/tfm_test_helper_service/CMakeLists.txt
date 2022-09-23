#
# Copyright (c) 2022 Linaro Limited
#
# SPDX-License-Identifier: Apache-2.0
#
add_library(tfm_app_rot_partition_test_helper STATIC)

target_include_directories(tfm_app_rot_partition_test_helper
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_test_helper_service
)
target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_test_helper_service
)

target_sources(tfm_app_rot_partition_test_helper
    PRIVATE
        tfm_test_helper_service.c
)

# The generated sources
target_sources(tfm_app_rot_partition_test_helper
    PRIVATE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_test_helper_service/auto_generated/intermedia_tfm_test_helper_service.c>
)
target_sources(tfm_partitions
    INTERFACE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_test_helper_service/auto_generated/load_info_tfm_test_helper_service.c>
)

target_include_directories(tfm_app_rot_partition_test_helper
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_test_helper_service
)

target_link_libraries(tfm_app_rot_partition_test_helper
    PRIVATE
        tfm_secure_api
        psa_interface
        platform_s
        tfm_sprt
        tfm_app_rot_partition_huk_deriv
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_test_helper
)

target_compile_definitions(tfm_partition_defs
    INTERFACE
        TFM_PARTITION_TEST_HELPER_SERVICE
)
