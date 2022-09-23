# Copyright 2021 The TensorFlow Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0079 NEW)

# The name of the target is required to be of the pattern
# tfm_app_rot_partition_x or tfm_psa_rot_partition_x, as it affects how the
# linker script will lay the partition in memory.
add_library(tfm_app_rot_partition_tflm STATIC)

file(GLOB_RECURSE
    TFLM_C_FILES
        ${CMAKE_CURRENT_LIST_DIR}/tensorflow/lite/c/*.c
)

file(GLOB_RECURSE
    TFLM_CORE_FILES
        ${CMAKE_CURRENT_LIST_DIR}/tensorflow/lite/core/*.cc
)

file(GLOB_RECURSE
    TFLM_KERNELS_FILES
        ${CMAKE_CURRENT_LIST_DIR}/tensorflow/lite/kernels/*.cc
)

file(GLOB_RECURSE
    TFLM_MICRO_FILES
        ${CMAKE_CURRENT_LIST_DIR}/tensorflow/lite/micro/*.cc
)

file(GLOB_RECURSE
    TFLM_SCHEMA_FILES
        ${CMAKE_CURRENT_LIST_DIR}/tensorflow/lite/schema/*.cc
)

target_sources(tfm_app_rot_partition_tflm
    PRIVATE
        ${TFLM_C_FILES}
        ${TFLM_CORE_FILES}
        ${TFLM_KERNELS_FILES}
        ${TFLM_MICRO_FILES}
        ${TFLM_SCHEMA_FILES}
)

target_include_directories(tfm_app_rot_partition_tflm
    PUBLIC
        .
        ${CMAKE_CURRENT_LIST_DIR}/tensorflow/lite/c
        ${CMAKE_CURRENT_LIST_DIR}/tensorflow/lite/core/api
        ${CMAKE_CURRENT_LIST_DIR}/tensorflow/lite/kernels
        ${CMAKE_CURRENT_LIST_DIR}/tensorflow/lite/kernels/internal
        ${CMAKE_CURRENT_LIST_DIR}/ensorflow/lite/kernels/internal/optimized
        ${CMAKE_CURRENT_LIST_DIR}/tensorflow/lite/kernels/internal/reference
        ${CMAKE_CURRENT_LIST_DIR}/tensorflow/lite/kernels/internal/reference/integer_ops
        ${CMAKE_CURRENT_LIST_DIR}/tensorflow/lite/micro
        ${CMAKE_CURRENT_LIST_DIR}/tensorflow/lite/micro/kernels
        ${CMAKE_CURRENT_LIST_DIR}/lite/micro/memory_planner
        ${CMAKE_CURRENT_LIST_DIR}/third_party/flatbuffers/include
        ${CMAKE_CURRENT_LIST_DIR}/third_party/gemmlowp
        ${CMAKE_CURRENT_LIST_DIR}/third_party/gemmlowp/internal
        ${CMAKE_CURRENT_LIST_DIR}/third_party/ruy
)
