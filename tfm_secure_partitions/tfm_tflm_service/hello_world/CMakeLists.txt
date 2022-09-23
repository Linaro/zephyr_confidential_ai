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
add_library(tfm_app_rot_partition_tflm_hello_world STATIC)

target_sources(tfm_app_rot_partition_tflm_hello_world
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/constants.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/hello_world_model_data.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/main_functions.cc
)

target_include_directories(tfm_app_rot_partition_tflm_hello_world
    PUBLIC
        .
)

target_link_libraries(tfm_app_rot_partition_tflm_hello_world
    PRIVATE
        tfm_app_rot_partition_tflm
)
