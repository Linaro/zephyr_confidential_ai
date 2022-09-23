#
# Copyright (c) 2021-2022 Linaro Limited
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.13.1)

# Disable QEMU emulation of the LSM303DLHC magn for now since it requires a specific QEMU build
# if((BOARD MATCHES "mps2_an521") OR (BOARD MATCHES "mps3_an547"))
#   list(APPEND QEMU_EXTRA_FLAGS -device lsm303dlhc_mag,id=lsm303,address=0x1E)
# endif()

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

get_target_property(TFM_BINARY_DIR tfm TFM_BINARY_DIR)
set(APP_SOURCE_DIR ${APPLICATION_SOURCE_DIR})
configure_file(
  ${CMAKE_CURRENT_LIST_DIR}/tfm_secure_partitions/tfm_manifest_list.yaml.in
  ${CMAKE_CURRENT_BINARY_DIR}/tfm_secure_partitions/tfm_manifest_list.yaml
  @ONLY
)

set_property(TARGET zephyr_property_target
  APPEND PROPERTY TFM_CMAKE_OPTIONS
  -DTFM_EXTRA_MANIFEST_LIST_FILES=${CMAKE_CURRENT_BINARY_DIR}/tfm_secure_partitions/tfm_manifest_list.yaml
  -DTFM_EXTRA_PARTITION_PATHS="${CMAKE_CURRENT_LIST_DIR}/tfm_secure_partitions/tfm_huk_deriv_srv\\\;${CMAKE_CURRENT_LIST_DIR}/tfm_secure_partitions/tfm_tflm_service\\\;${CMAKE_CURRENT_LIST_DIR}/tfm_secure_partitions/tfm_utvm_service"
  )

if(${CONFIG_NV_PS_COUNTERS_SUPPORT})
    set_property(TARGET zephyr_property_target
        APPEND PROPERTY TFM_CMAKE_OPTIONS
        -DNV_PS_COUNTERS_SUPPORT=ON -DNV_COUNTER_TRACKER_THRESHOLD_LIMIT=${CONFIG_NV_COUNTER_TRACKER_THRESHOLD_LIMIT}
        )
endif()

# set_property(TARGET zephyr_property_target
#   APPEND_STRING PROPERTY TFM_PARTITION_PATHS
#   ${PARTITION_PATHS}
#   )

project(tfm_secure_inference)

list(APPEND secure_app_files
  src/cose/cose_verify.c
  src/cose/mbedtls_ecdsa_verify_sign.c
  src/shell/cmd_azure.c
  src/shell/cmd_infer.c
  src/shell/cmd_info.c
  src/shell/cmd_keys.c
  src/shell/shell_common.c
  src/infer_mgmt.c
  src/key_mgmt.c
  src/main.c
  src/provision.c
  src/test_certs.c
  src/tfm_partition_huk.c
  src/tfm_partition_tflm.c
  src/tfm_partition_utvm.c
  src/util_app_log.c
  src/x509_csr_gen.c
  ext/NanoCBOR/src/decoder.c
  ext/NanoCBOR/src/encoder.c
  src/device_client_tls_key.c
)

if(CONFIG_APP_NETWORKING)
  list(APPEND secure_app_files
    src/azure.c
    src/bootstrap.c
    src/dhcpwait.c
  )
endif()

target_sources(app PRIVATE ${secure_app_files})
#target_sources(app PRIVATE
#if (CONFIG_APP_NETWORKING)
#  src/azure.c
#endif()

target_include_directories(app PRIVATE
  ${ZEPHYR_TRUSTED_FIRMWARE_M_MODULE_DIR}/interface/include
  ext/NanoCBOR/include
  include
)

target_compile_definitions(app PRIVATE
  TFM_PARTITION_HUK_KEY_DERIVATION
  TFM_PARTITION_TFLM_SERVICE
  TFM_PARTITION_UTVM_SERVICE
  NANOCBOR_BYTEORDER_HEADER=<zephyr/sys/byteorder.h>
  NANOCBOR_BE64TOH_FUNC=sys_be64_to_cpu
  NANOCBOR_HTOBE64_FUNC=sys_cpu_to_be64
  NANOCBOR_HTOBE32_FUNC=sys_cpu_to_be32
)

# In TF-M, default value of CRYPTO_ENGINE_BUF_SIZE is 0x2080. It causes
# insufficient memory failure while verifying signature. Increase it to 0x2400.
set_property(TARGET zephyr_property_target
             APPEND PROPERTY TFM_CMAKE_OPTIONS
             -DCRYPTO_ENGINE_BUF_SIZE=0x2400
)

# Since the MPS2/MPS3 boards in TF-M use a hard-coded HUK value, we need to
# append a custom label value during key derivation for unique key(s). This
# value is exposed here as a convenience so that west can pass it on to TF-M,
# but is only used in the secure partition(s).
if (CONFIG_SECURE_INFER_HUK_DERIV_LABEL_EXTRA)
  set_property(TARGET zephyr_property_target
              APPEND PROPERTY TFM_CMAKE_OPTIONS
              -DHUK_DERIV_LABEL_EXTRA=${CONFIG_SECURE_INFER_HUK_DERIV_LABEL_EXTRA}
  )
endif()

zephyr_include_directories(${APPLICATION_SOURCE_DIR}/src/tls_config)
