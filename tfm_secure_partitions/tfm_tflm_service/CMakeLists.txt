#
# Copyright (c) 2021-2022 Linaro Limited
#
# SPDX-License-Identifier: Apache-2.0
#

# The name of the target is required to be of the pattern
# tfm_app_rot_partition_x or tfm_psa_rot_partition_x, as it affects how the
# linker script will lay the partition in memory.
add_library(tfm_app_rot_partition_tflm STATIC)

target_include_directories(tfm_app_rot_partition_tflm
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_tflm_service
)
target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_tflm_service
)

file(GLOB_RECURSE
    TFLM_C_FILES
        ${CMAKE_CURRENT_LIST_DIR}/tflm/tensorflow/lite/c/*.c
)

file(GLOB_RECURSE
    TFLM_CORE_FILES
        ${CMAKE_CURRENT_LIST_DIR}/tflm/tensorflow/lite/core/*.cc
)

file(GLOB_RECURSE
    TFLM_KERNELS_FILES
        ${CMAKE_CURRENT_LIST_DIR}/tflm/tensorflow/lite/kernels/*.cc
)

file(GLOB_RECURSE
    TFLM_MICRO_FILES
        ${CMAKE_CURRENT_LIST_DIR}/tflm/tensorflow/lite/micro/*.cc
)

file(GLOB_RECURSE
    TFLM_SCHEMA_FILES
        ${CMAKE_CURRENT_LIST_DIR}/tflm/tensorflow/lite/schema/*.cc
)

target_sources(tfm_app_rot_partition_tflm
    PRIVATE
        ${TFLM_C_FILES}
        ${TFLM_CORE_FILES}
        ${TFLM_KERNELS_FILES}
        ${TFLM_MICRO_FILES}
        ${TFLM_SCHEMA_FILES}
        ${CMAKE_CURRENT_SOURCE_DIR}/hello_world/constants.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/hello_world/hello_world_model_data.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/hello_world/main_functions.cc
        tfm_tflm_service.c
        tfm_tflm_service_api.c
)

# The generated sources
target_sources(tfm_app_rot_partition_tflm
    PRIVATE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_tflm_service/auto_generated/intermedia_tfm_tflm_service.c>
)
target_sources(tfm_partitions
    INTERFACE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_tflm_service/auto_generated/load_info_tfm_tflm_service.c>
)

target_include_directories(tfm_app_rot_partition_tflm
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tflm
        ${CMAKE_CURRENT_LIST_DIR}/tflm/tensorflow/lite/c
        ${CMAKE_CURRENT_LIST_DIR}/tflm/tensorflow/lite/core/api
        ${CMAKE_CURRENT_LIST_DIR}/tflm/third_party/gemmlowp
        ${CMAKE_CURRENT_LIST_DIR}/tflm/third_party/gemmlowp/internal
        ${CMAKE_CURRENT_LIST_DIR}/tflm/third_party/flatbuffers/include
        ${CMAKE_CURRENT_LIST_DIR}/tflm/third_party/ruy
        ${CMAKE_CURRENT_LIST_DIR}/tflm/tensorflow/lite/kernels
        ${CMAKE_CURRENT_LIST_DIR}/tflm/tensorflow/lite/kernels/internal
        ${CMAKE_CURRENT_LIST_DIR}/tflm/ensorflow/lite/kernels/internal/optimized
        ${CMAKE_CURRENT_LIST_DIR}/tflm/tensorflow/lite/kernels/internal/reference
        ${CMAKE_CURRENT_LIST_DIR}/tflm/tensorflow/lite/kernels/internal/reference/integer_ops
        ${CMAKE_CURRENT_LIST_DIR}/tflm/tensorflow/lite/micro
        ${CMAKE_CURRENT_LIST_DIR}/tflm/tensorflow/lite/micro/kernels
        ${CMAKE_CURRENT_LIST_DIR}/tflm/lite/micro/memory_planner
        ${CMAKE_CURRENT_LIST_DIR}/tflm/lite/schema
        ${CMAKE_CURRENT_LIST_DIR}/hello_world
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        ${CMAKE_BINARY_DIR}/tfm_secure_partitions/tfm_tflm_service
)

target_link_libraries(tfm_app_rot_partition_tflm
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
        tfm_app_rot_partition_tflm
)

target_compile_definitions(tfm_partition_defs
    INTERFACE
        TFM_PARTITION_TFLM_SERVICE
)
