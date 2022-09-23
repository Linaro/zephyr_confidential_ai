# TensorFlow Lite for Microcontrollers as TF-M secure service

TensorFlow Lite for Microcontrollers (TFLM) is designed to run machine learning
models on microcontrollers and other devices with only a few kilobytes of
memory.

The core runtime just fits in 16 KB on an Arm Cortex M3 and can run many basic
models [ref](https://www.tensorflow.org/lite/microcontrollers).


## Prerequisites

## Installing dependency for Ubuntu:

1. Run the command to install python3, pip, git:

    ```bash
    $ sudo apt install python3 python3-pip git
    ```

## Installing dependency for macOS

1. Download and install [Python 3 from the official website](https://www.python.org/downloads/mac-osx/).
2. Run the command to install Git:

    ```bash
    $ brew install git
    ```

## Exporting TFLM hello_world and run time

1. Run the command to clone the tflite-micro repository:

     ```bash
     $ git clone git@github.com:tensorflow/tflite-micro.git
     ```

2. Change directory to cloned tflite-micro:

     ```bash
     $ cd tflite-micro
     ```

3. Tensorflow lite-micro provides a python script to export sources without a
build system and run the command to export hello_world example and tflm
runtime:

     ```bash
     $ python3 tensorflow/lite/micro/tools/project_generation/create_tflm_tree.py \
             -e hello_world \
             /tmp/tflm-tree
     ```

4. You can find the exported hello_world and runtime sources under
`/tmp/tflm-tree`, and the directory layout looks below:

    ```
    tflm-tree
    │
    └───tensorflow
    │   └─── lite
    └───examples
    │   └─── hello_world
    └───third_party
        │─── flatbuffers
        │─── gemmlowp
        │─── kissfft
        └─── ruy
     ```

## Copy hello_world and TFLM runtime to TF-M

1. Run the `cp` command to copy hello_world example, TFLM runtime and
third_party to TFM tflm secure service:

     ```bash
     $ cp /tmp/tflm-tree/tensorflow path/to/zephyr_secure_inference/tfm_secure_partitions/tfm_tflm_service/tflm
     $ cp /tmp/tflm-tree/third_party path/to/path/to/zephyr_secure_inference/tfm_secure_partitions/tfm_tflm_service/tflm
     $ cp /tmp/tflm-tree/examples/hello_world/* path/to/zephyr_secure_inference/tfm_secure_partitions/tfm_tflm_service/hello_world
     ```

2. Update `CMakeLists.txt` in `path/to/zephyr_secure_inference/tfm_secure_partitions/tfm_tflm_service/hello_world`, `path/to/zephyr_secure_inference/tfm_secure_partitions/tfm_tflm_service/tflm/` if necessary.

## Build and run

1. Zephyr setup - setting up the environment required to build Zephyr is
described [here](https://docs.zephyrproject.org/latest/getting_started/index.html).
Use [fork of Zephyr](https://github.com/microbuilder/zephyr) instead of
upstream Zephyr and check out the `tfm_secure_inference` branch.

2. Build basic blinky example to confirm zephyr setup using
`west build -p auto -b mps2_an521 samples/basic/blinky` command.

3. Copy the `zephyr_secure_inference` directory to
`path/to/zephyr/modules/outoftree/`.

4. Run the command to build and run secure inference using QEMU:

    ```bash
    $ west build -p auto -b mps2_an521_ns modules/outoftree/zephyr_secure_inference -t run
    ```

5. Expected output:

    ```bash
     TF-M FP mode: Software
     Booting TFM v1.5.0
     Creating an empty ITS flash layout.
     Creating an empty PS flash layout.
     [HUK DERIV SERV] tfm_huk_deriv_ec_key()::382 Successfully derived the key for HUK_CLIENT_TLS1
     [HUK DERIV SERV] tfm_huk_deriv_ec_key()::382 Successfully derived the key for HUK_COSE_SIGN1
     [HUK DERIV SERV] tfm_huk_deriv_ec_key()::382 Successfully derived the key for HUK_COSE_ENCRYPT1
     [UTVM SERVICE] tfm_utvm_service_req_mngr_init()::215 UTVM initalisation completed
     [TFLM SERVICE] tfm_tflm_service_req_mngr_init()::398 initalisation completed
     *** Booting Zephyr OS build v2.7.99-2785-ge3c585041afe  ***
     [HUK DERIV SERV] tfm_huk_gen_uuid()::610 Generated UUID: 5319786e-d335-4f9e-93bd-701c20259073


     uart:~$
     ```

6. Type the `infer get tflm_sine 1` shell command:

    ```bash
    uart:~$ infer get tflm_sine 1
    ```

7. Secure inference logs:

    ```bash
     Start: 1.00 End: 1.00 stride: 1.00
     [TFLM SERVICE] tfm_tflm_infer_run()::236 Starting secure inferencing...
     [TFLM SERVICE] tfm_tflm_infer_run()::239 Starting CBOR encoding and COSE signing...
     CBOR encoded and COSE signed inference value:
     00000000: d2 84 43 a1 01 26 a0 4b  a1 3a 00 01 38 7f 44 2c |..C..&.K .:..8.D,|
     00000010: ce 8a 3c 58 40 36 fb fb  d9 f5 8e ce f9 d0 3e dc |..<X@6.. ......>.|
     00000020: 2c 3f 40 52 4e 91 51 cd  86 4b 84 f0 90 7d d1 ee |,?@RN.Q. .K...}..|
     00000030: 3c 20 06 1b 5a 1e 3f d3  4f 24 71 b1 c0 a6 ec 7d |< ..Z.?. O$q....}|
     00000040: 5f 51 0f 90 0f e4 99 bc  4f c9 7f 79 4c 59 c2 10 |_Q...... O..yLY..|
     00000050: b0 3e 75 a1 f1                                   |.>u..            |
     Verified the signature using the public key.
     Model: Sine of 1.00 deg is: 0.016944
     C Mathlib: Sine of 1.00 deg is: 0.017452
     Deviation: 0.824527

     uart:~$
    ```

## Debugging

The size of TF-M + TFLM is higher than the memory allocated to TF-M when
debugging is enabled. In order to debug both TF-M + TFLM and Zephyr, we need
to modify linker scripts to increase the memory allocated to TF-M at the same
time reducing the memory allocated to Zephyr.

Zephyr:

```bash
--- a/boards/arm/mps2_an521/mps2_an521_ns.dts
+++ b/boards/arm/mps2_an521/mps2_an521_ns.dts
@@ -105,8 +105,8 @@
         * https://git.trustedfirmware.org/TF-M/trusted-firmware-m.git/tree/platform/ext/target/mps2/an521/partition/flash_layout.h
         */

-       code: memory@100000 {
-           reg = <0x00100000 DT_SIZE_K(512)>;
+       code: memory@140000 {
+           reg = <0x00140000 DT_SIZE_K(256)>;
```

TF-M:

```
--- a/trusted-firmware-m/platform/ext/target/arm/mps2/an521/partition/flash_layout.h
+++ b/trusted-firmware-m/platform/ext/target/arm/mps2/an521/partition/flash_layout.h
@@ -60,8 +60,8 @@
  */

 /* Size of a Secure and of a Non-secure image */
-#define FLASH_S_PARTITION_SIZE          (0x80000) /* S partition: 512 KB */
-#define FLASH_NS_PARTITION_SIZE         (0x80000) /* NS partition: 512 KB */
+#define FLASH_S_PARTITION_SIZE          (0xC0000) /* S partition: 768 KB */
+#define FLASH_NS_PARTITION_SIZE         (0x40000) /* NS partition: 256 KB */
 #define FLASH_MAX_PARTITION_SIZE        ((FLASH_S_PARTITION_SIZE >   \
                                           FLASH_NS_PARTITION_SIZE) ? \
                                          FLASH_S_PARTITION_SIZE :    \
```

## Observations

The linker variable `__exidx_end` is not defined for `TFM_LVL == 1`, however,
adding TFLM causes build failure due to missing `__exidx_end`. We need to
check this with TF-M.

```bash
--- a/trusted-firmware-m/platform/ext/common/gcc/tfm_common_s.ld
+++ b/trusted-firmware-m/platform/ext/common/gcc/tfm_common_s.ld
@@ -183,7 +183,7 @@ SECTIONS
     Image$$ER_CODE_SRAM$$Limit = ADDR(.ER_CODE_SRAM) + SIZEOF(.ER_CODE_SRAM);
 #endif

-#if TFM_LVL != 1
+/* #if TFM_LVL != 1 */
     .ARM.extab :
     {
         *(.ARM.extab* .gnu.linkonce.armextab.*)
@@ -196,7 +196,7 @@ SECTIONS
     } > FLASH
     __exidx_end = .;

-#endif /* TFM_LVL != 1 */
+/* #endif TFM_LVL != 1 */
```
