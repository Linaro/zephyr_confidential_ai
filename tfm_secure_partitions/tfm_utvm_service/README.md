# Micro TVM as TF-M secure service

TVM is a model deployment framework that has demonstrated good performance
across a wide range of models on traditional operating systems. micro TVM is a
natural extension to target bare metal devices.
[ref](https://tvm.apache.org/docs/arch/microtvm_design.html#microtvm-design).

## Prerequisites

### Installing Ansible on Ubuntu 20.04

1. To configure the PPA on your machine and install Ansible run these commands:

    ```bash
    $ sudo apt install -y software-properties-common
    $ sudo add-apt-repository --yes --update ppa:ansible/ansible
    $ sudo apt update
    $ sudo apt install -y ansible
    ```

2. Run the below command to check the installed version and installation:

    ```bash
    $ ansible --version
    ```

3. Run the command to install python3, pip, git:

     ```
     $ sudo apt install python3 python3-pip git
     ```

### Installing Ansible on MacOS

1. Install Ansible run these commands:

    ```bash
    $ brew install ansible
    $ brew install hudochenkov/sshpass/sshpass
    ```

2. Create `$HOME/.ansible.cfg` on your home directory and add the below
configuration:

    ```
    [defaults]
    host_key_checking = False
    DEFAULT_HOST_LIST = $HOME/.ansible/hosts
    inventory =  $HOME/.ansible/hosts
    ```

3. Add the following config to `.bashrc` or `.zshrc`

    ```bash
    ANSIBLE_CONFIG=$HOME/.ansible.cfg
    ```

4. Verify the host file location:

    ```bash
    $ ansible-config dump | grep DEFAULT_HOST_LIST
    ```

5. Download and install [Python 3 from the official website](https://www.python.org/downloads/mac-osx/).

6. Run the command to install Git:

    ```bash
    $ brew install git
    ```

## Setup TVM build environment

1. Run the command to clone the repository:

    ```bash
    $ git clone https://github.com/gromero/ansible.git
    $ cd ansible
    ```

2. Add the following to your host file (`/etc/ansible/hosts` on ubuntu or
`$HOME/.ansible/hosts` on MacOS), update IP address or hostname and ssh
username as appropriate for your VM:

    ```bash
    [tvm-dev]
    <VM IP address or hostname> ansible_connection=ssh	ansible_user=<USERNAME> ansible_ssh_pass=<PASSWORD>
    ```

    Example:

    ```bash
    [tvm-dev]
    192.168.64.16	ansible_connection=ssh	ansible_user=ansible ansible_ssh_pass=ansible
    ```

3. Run the command to setup the complete build environment of TVM and microTVM
from the source, and tvm sources are cloned under the `$HOME/git/tvm`
directory:

    ```bash
    $ ansible-playbook ./tvm.yml --ask-become-pass -vv
    ```

## Build TVM

1. SSH into the VM, and run the commands:

    ```bash
    $ cd $HOME/git/tvm/build
    $ cmake ..
    $ make -j $(nproc)
    ```

2. Create a `tvmc` alias for tvm build command:

    ```bash
    $ alias tvmc="python3 -m tvm.driver.tvmc"
    ```

3. Run the below command to check the tvmc version:

    ```bash
    $ tvmc --version
    ```

## Generate the tvm sine model and run time

1. Run the command to get the TFLite sine model:

    ```bash
    $ wget https://people.linaro.org/~tom.gall/sine_model.tflite
    ```

2. Run the `tvmc` compile command to generate the source for the TFLite sine
model for cortex-m33:

    ```bash
    $ tvmc compile --target="c" --target-c-mcpu=cortex-m33 \
      --runtime=crt --executor=aot --executor-aot-interface-api=c \
      --executor-aot-unpacked-api=1 --output-format mlf \
      --pass-config tir.disable_vectorize=1 --disabled-pass="AlterOpLayout" \
      sine_model.tflite \
      --output sine.tar
    ```

3. Unzip `sine.tar`:

    ```bash
    $ mkdir sine && cd sine
    $ tar xf ../sine.tar
    ```

4. Generated sine model directory layout looks below and refers
[here](https://tvm.apache.org/docs/arch/model_library_format.html#directory-layout)
for more details:

    ```
    sine
    │
    └───codegen/host
    │   │─── include
    │   └─── src
    └───parameters
    └───runtime
    │   │─── host
    │   │─── include
    │   │─── src
    │   └─── template
    └─── src
    ```

## Copy generated uTVM Sine model and runtime to TF-M

1. Copy sine directory to TFM utvm secure service:

    ```bash
    cp -r $HOME/git/tvm/build/sine path/to/zephyr_secure_inference/tfm_secure_partitions/tfm_utvm_service/utvm/
    ```

2. Update `CMakeLists.txt` in ` zephyr_secure_inference/tfm_secure_partitions/tfm_utvm_service/utvm/CMakeLists.txt ` if necessary.

## TF-M TVM Platform APIs implementation:

1. Generated uTVM sine model and runtime is dependent on the platform abort and
memory handling APIs as listed below and those APIs are implemented in this
`path/to/zephyr_secure_inference/tfm_secure_partitions/tfm_utvm_service/tfm_utvm_platform/utvm_platform.c`
file based on TF-M:

    ```
    void TVMPlatformAbort(tvm_crt_error_t error)
    tvm_crt_error_t TVMPlatformMemoryAllocate(size_t num_bytes, DLDevice dev, void **out_ptr)
    tvm_crt_error_t TVMPlatformMemoryFree(void *ptr, DLDevice dev)
    int TVMBackendFreeWorkspace(int device_type, int device_id, void *ptr)
    ```

2. Implement the additional APIs, If you would like to measure the performance
or execution time of the inference engine:

    ```
    tvm_crt_error_t TVMPlatformTimerStart()
    tvm_crt_error_t TVMPlatformTimerStop(double *elapsed_time_seconds)
    ```

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
    west build -p auto -b mps2_an521_ns modules/outoftree/zephyr_secure_inference -t run
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

6. Type the `infer get utvm_sine 1` shell command:

    ```bash
    uart:~$ infer get utvm_sine 1
    ```

7. Secure inference logs:

    ```bash
    Start: 1.00 End: 1.00 stride: 1.00
    [UTVM SERVICE] tfm_utvm_infer_run()::85 Starting secure inferencing
    [UTVM SERVICE] tfm_utvm_infer_run()::92 Starting CBOR encoding and COSE signing...
    CBOR encoded and COSE signed inference value:
    00000000: d2 84 43 a1 01 26 a0 4b  a1 3a 00 01 38 7f 44 80 |..C..&.K .:..8.D.|
    00000010: 50 45 3d 58 40 59 23 3e  80 5e e0 9f fa e3 f4 14 |PE=X@Y#> .^......|
    00000020: 62 d3 15 a5 b0 95 b5 e5  cb 79 92 f8 f1 a0 fe 14 |b....... .y......|
    00000030: 0c 6c 84 2a 41 ea f4 16  58 83 7b 65 87 7f 4f ac |.l.*A... X.{e..O.|
    00000040: 52 4d c4 a4 9b 9d ed 5c  f2 77 5c 4e de 27 70 99 |RM.....\ .w\N.'p.|
    00000050: f9 2d 78 64 b4                                   |.-xd.            |
    Verified the signature using the public key.
    Model: Sine of 1.00 deg is: 0.048172
    C Mathlib: Sine of 1.00 deg is: 0.017452
    Deviation: 0.793299

    uart:~$
    ```

## Debugging

The size of TF-M + TFLM is higher than the memory allocated to TF-M when
debugging is enabled. In order to debug both TF-M + TFLM and Zephyr, we need to
modify linker scripts to increase the memory allocated to TF-M at the same time
reducing the memory allocated to Zephyr.

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