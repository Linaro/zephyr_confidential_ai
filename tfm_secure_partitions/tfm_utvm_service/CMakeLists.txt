#
# Copyright (c) 2022 Linaro Limited
#
# SPDX-License-Identifier: Apache-2.0
#

# The name of the target is required to be of the pattern
# tfm_app_rot_partition_x or tfm_psa_rot_partition_x, as it affects how the
# linker script will lay the partition in memory.
add_library(tfm_app_rot_partition_utvm STATIC)

target_include_directories(tfm_app_rot_partition_utvm
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_utvm_service
)
target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_utvm_service
)

file(GLOB_RECURSE
    UTVM_MEMORY_FILES
        ${CMAKE_CURRENT_LIST_DIR}/utvm/sine/runtime/src/runtime/crt/memory/*.c
)

file(GLOB_RECURSE
    UTVM_RPC_COMMON_FILES
        ${CMAKE_CURRENT_LIST_DIR}/utvm/sine/runtime/src/runtime/crt/microtvm_rpc_common/*.c
        ${CMAKE_CURRENT_LIST_DIR}/utvm/sine/runtime/src/runtime/crt/microtvm_rpc_common/*.cc
)

file(GLOB_RECURSE
    UTVM_COMMON_FILES
        ${CMAKE_CURRENT_LIST_DIR}/utvm/sine/runtime/src/runtime/crt/common/*.c
)

file(GLOB_RECURSE
    UTVM_MODEL_FILES
        ${CMAKE_CURRENT_LIST_DIR}/utvm/sine/codegen/host/src/*.c
)

target_sources(tfm_app_rot_partition_utvm
    PRIVATE
        ${UTVM_MEMORY_FILES}
        ${UTVM_RPC_COMMON_FILES}
        ${UTVM_COMMON_FILES}
        ${UTVM_MODEL_FILES}
        tfm_utvm_service.c
        tfm_utvm_platform/utvm_platform.c
        tfm_utvm_service_api.c
)

# The generated sources
target_sources(tfm_app_rot_partition_utvm
    PRIVATE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_utvm_service/auto_generated/intermedia_tfm_utvm_service.c>
)
target_sources(tfm_partitions
    INTERFACE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_utvm_service/auto_generated/load_info_tfm_utvm_service.c>
)

target_include_directories(tfm_app_rot_partition_utvm
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/utvm/sine/runtime/include
        ${CMAKE_CURRENT_LIST_DIR}/utvm/crt_config
        ${CMAKE_CURRENT_LIST_DIR}/utvm/sine/codegen/host/include
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_utvm_service
        tfm_utvm_platform
)

# TVM-generated code tends to include lots of these.
target_compile_options(tfm_app_rot_partition_utvm
    PRIVATE
        -Wno-unused-variable
)

target_link_libraries(tfm_app_rot_partition_utvm
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
        tfm_app_rot_partition_utvm
)

target_compile_definitions(tfm_partition_defs
    INTERFACE
        TFM_PARTITION_UTVM_SERVICE
)
