#
# Copyright (c) 2022 Linaro Limited
#
# SPDX-License-Identifier: Apache-2.0
#
cmake_minimum_required(VERSION 3.13.1)

add_library(tfm_app_rot_partition_utvm_crt STATIC)

file(GLOB_RECURSE
    UTVM_MEMORY_FILES
        ${CMAKE_CURRENT_LIST_DIR}/sine/runtime/src/runtime/crt/memory/*.c
)

file(GLOB_RECURSE
    UTVM_RPC_COMMON_FILES
        ${CMAKE_CURRENT_LIST_DIR}/sine/runtime/src/runtime/crt/microtvm_rpc_common/*.c
        ${CMAKE_CURRENT_LIST_DIR}/sine/runtime/src/runtime/crt/microtvm_rpc_common/*.cc
)

file(GLOB_RECURSE
    UTVM_COMMON_FILES
        ${CMAKE_CURRENT_LIST_DIR}/sine/runtime/src/runtime/crt/common/*.c
)

target_sources(tfm_app_rot_partition_utvm_crt
    PRIVATE
        ${UTVM_MEMORY_FILES}
        ${UTVM_RPC_COMMON_FILES}
        ${UTVM_COMMON_FILES}
)

target_include_directories(tfm_app_rot_partition_utvm_crt
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/sine/runtime/include
        ${CMAKE_CURRENT_LIST_DIR}/crt_config
)

add_library(tfm_app_rot_partition_utvm_model STATIC)

file(GLOB_RECURSE
    UTVM_MODEL_FILES
        ${CMAKE_CURRENT_LIST_DIR}/sine/codegen/host/src/*.c
)

target_sources(tfm_app_rot_partition_utvm_model
    PRIVATE
        ${UTVM_MODEL_FILES}
)

target_include_directories(tfm_app_rot_partition_utvm_model
    PUBLIC
       ${CMAKE_CURRENT_LIST_DIR}/sine/codegen/host/include
)

# TVM-generated code tends to include lots of these.
target_compile_options(tfm_app_rot_partition_utvm_model
    PRIVATE
        -Wno-unused-variable
)

target_link_libraries(tfm_app_rot_partition_utvm_model
    PUBLIC
        tfm_app_rot_partition_utvm_crt
)
