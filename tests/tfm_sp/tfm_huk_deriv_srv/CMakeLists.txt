# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

set(ZEPHY_SECURE_INFER_SRC_PATH ${CMAKE_CURRENT_LIST_DIR}/../../../)

get_target_property(TFM_BINARY_DIR tfm TFM_BINARY_DIR)
set(APP_SOURCE_DIR ${ZEPHY_SECURE_INFER_SRC_PATH})
configure_file(
  ${ZEPHY_SECURE_INFER_SRC_PATH}/tfm_secure_partitions/tfm_manifest_list.yaml.in
  ${CMAKE_CURRENT_BINARY_DIR}/tfm_secure_partitions/tfm_manifest_list.yaml
  @ONLY
)

set_property(TARGET zephyr_property_target
  APPEND PROPERTY TFM_CMAKE_OPTIONS
  -DTFM_EXTRA_MANIFEST_LIST_FILES=${CMAKE_CURRENT_BINARY_DIR}/tfm_secure_partitions/tfm_manifest_list.yaml
  -DTFM_EXTRA_PARTITION_PATHS="${ZEPHY_SECURE_INFER_SRC_PATH}/tfm_secure_partitions/tfm_huk_deriv_srv\\\;${ZEPHY_SECURE_INFER_SRC_PATH}/tfm_secure_partitions/tfm_test_helper_service")

if(${CONFIG_BUILD_HUK_KEY_DERIV_TEST})
    set_property(TARGET zephyr_property_target
        APPEND PROPERTY TFM_CMAKE_OPTIONS
        -DBUILD_HUK_KEY_DERIV_TEST=true
        )
endif()

project(tfm_huk_deriv_srv_test)

FILE(GLOB TESTSUITE_SOURCES src/*.c)
FILE(GLOB TEST_HELPER_SERVICE_API ../test_service/*.c)
target_sources(app
    PRIVATE
        ${TESTSUITE_SOURCES}
        ${TEST_HELPER_SERVICE_API})

target_include_directories(app
    PRIVATE
        ${ZEPHYR_TRUSTED_FIRMWARE_M_MODULE_DIR}/interface/include
        ${CMAKE_CURRENT_LIST_DIR}/../test_service
)

target_compile_definitions(app PRIVATE
  TFM_PARTITION_HUK_KEY_DERIVATION
  TFM_PARTITION_TEST_HELPER_SERVICE
)

# In TF-M, default value of CRYPTO_ENGINE_BUF_SIZE is 0x2080. It causes
# insufficient memory failure while verifying signature. Increase it to 0x2400.
set_property(TARGET zephyr_property_target
             APPEND PROPERTY TFM_CMAKE_OPTIONS
             -DCRYPTO_ENGINE_BUF_SIZE=0x2400
)

zephyr_include_directories(${ZEPHY_SECURE_INFER_SRC_PATH}/src/tls_config)
