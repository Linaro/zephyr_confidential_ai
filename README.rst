.. _tfm_secure_inference:

Confidential AI (TF-M + Zephyr)
###############################

What is Confidential AI?
************************

Confidential AI is:

* An attempt to demonstrate end-to-end (boot-to-cloud) security best practices
* ... making use of the security features on modern Armv8-M (M33/M55) hardware
* ... based on open source software and open standards
* ... with AI/ML workloads as a test case

The project has the following design goals:

* Remain vendor nuetral:

  * TensorFlow Lite Micro or TVM as an inference engine
  * Multiple cloud providers possible

* Emulation friendly:

  * Cortex-M33 (AN521) and Cortex-M55 (AN547) emulation in QEMU or Arm FVP

* Based on open source projects:

  * MCUBoot
  * Trusted Firmware-M
  * Zephyr
  * LITE Bootstrap Server (certificate authority)

* ... and open standards:

  * TLS
  * X.509 certificates
  * COSE for data encoding, signing and encryption

.. image:: https://github.com/Linaro/zephyr_secure_inference/blob/main/docs/arch-overview.flat.png?raw=true
  :alt: Confidential AI Architecture Overview

Overview
########

This Zephyr project provides a complete secure (S) plus non-secure (NS)
firmware solution for execution of an inference engine in the secure
processing environment, as well as end-to-end processing of inference outputs.

Outputs from the inference engine are encoded as CBOR payloads, with COSE used
to enable optional signing and encryption of the data.

Secure boot is based on MCUBoot. The secure firmware is based on
Trusted-Firmware-M. The non-secure firmware is based on Zephyr RTOS.

Build Process
*************

Zephyr controls the entire build process, building TF-M as well as the secure
bootloader during the normal Zephyr build. The secure and non-secure
firmware images are signed as part of the build process, with the public
signing keys written into the bootloader for verification during firmware
updates.

Secure Services
***************

Custom secure services are included in the sample in the
``tfm_secure_inference_partitions`` folder:

* ``tfm_huk_deriv_srv``: Device-bound UUID and key derivation from the hardware
  unique key (HUK).
* ``tfm_tflm_service``: TensorFlow Lite Micro inference engine and model
  execution
* ``tfm_utvm_service``: TVM inference engine and model execution

These secure services are added to TF-M as part of the secure build process
that takes place before the NS Zephyr application is built, and are
available to the NS environment based on the access-rights specified in
the service definition files.

Inference Engine(s)
*******************

This sample currently uses TensorFlow Lite Micro (TFLM) and TVM as the
inference engines, with a simple sine-wave model by default.

You can interact with the sine wave model from the NS side via the ``infer``
shell command.

More complex AI/ML models in the future.

Key and Certificate Management
******************************

Certain operations like signing or encrypting the COSE-encoded inference engine
outputs require the use of keys, and X.509 certificates for these keys.

All keys used in this project are derived at startup from the Hardware Unique
Key (HUK), meaning that they are device-bound (i.e. explicitly tied to a
specific instance of an SoC), storage-free (meaning they can't be retrieved
by dumping flash memory or firmware analysis), and repeatable across firmware
updates.

X.509 certificates generated for these keys are associated with a UUID, which
is also derived from the HUK. This derived UUID allows us to uniquely and
consistently identify a single SoC or embedded device.

The following EC keys are currently generated:

- Device Client TLS key (secp256r1)
- Device COSE SIGN/ENCRYPT (secp256r1)

The non-secure processing environment exposes a ``keys`` shell command that can
be used to retrieve the public key component of the above private keys, as well
as generate a certificate signing request (CSR) for a specific key.

Non-Volatile Counter
********************

TF-M has a standard NV Counter API, defined here:
``https://git.trustedfirmware.org/TF-M/trusted-firmware-m.git/tree/platform/include/tfm_plat_nv_counters.h``,
but which can't be used by application ROT services as it is pre-allocated.

Created custom NV counters support based on protected storage in secure
inference, currently, two NV counters of 4bytes in each size for NV counter and
NV roll-over counter, avoid frequent read-write to PS, added another two RAM
based static local tracker of NV tracker counter and NV rollover tracker
counter.

NV counters support is enabled via project Kconfig variable
``NV_PS_COUNTERS_SUPPORT`` (default enabled) in the build and another variable
``NV_COUNTER_TRACKER_THRESHOLD_LIMIT`` for setting the threshold limit to write
back NV tracker counter value to PS (by default threshold limit set as 100).

On every boot (or first use), read both counters from PS, and store them to
local tracker counter variables.

Roll over NV counter is incremented whenever the current NV tracker counter
value is greater than the UINT32_MAX (which is aligned with
``NV_COUNTER_TRACKER_THRESHOLD_LIMIT`` value), reset current NV tracker counter
to zero, and write back both tracker counters (NV counter and NV rollover
counter) to PS.

NV tracker counter value will be inserted into every COSE/CBOR payload as an
additional field along with the inference value.

Setup
#####

This sample assumes you have already cloned zephyr locally, and have a copy
of this repository available somewhere out-of-tree (relative to Zephyr).

Zephyr Setup
************

You will need to use a specific commit of zephyr to be sure that certain
assumptions in this codebase are met.

This Zephyr commit hash used is:

- ``45e1ff94cdbc395ab9f87d948580cefd585479c5``

Run these commands to checkout the expected commit hash, and apply a required
patch to TF-M, allowing us to enable CPP support in the TF-M build system. This
patch also modifies relevant target's flash layout(s) to increase flash
allocation for the secure image(s), where required:

.. code-block:: console

   $ cd path/to/zephyrproject/zephyr
   $ source zephyr-env.sh
   $ git checkout 45e1ff94cdbc395ab9f87d948580cefd585479c5
   $ west update
   $ cd ../modules/tee/tf-m/trusted-firmware-m
   $ git apply --verbose <zephyr_secure_inference_path>/patch/tfm.patch


Provisioning Key/Cert Setup
***************************

If you are building with networking support, some files from the
`LITE Bootstrap Server <https://github.com/Linaro/lite_bootstrap_server>`_
are also required to be copied into your sample application.

This bootstrap server is used to provide connection details for the MQTT
broker, and as a certificate authority to process certificate signing
requests (CSRs). Once a device is registered in the bootstrap server, other
devices or services can verify the existence and validity of device
certificates and get the public keys required to verify signed payloads, etc.

Communicating with the LITE Bootstrap server requires having a shared
'bootstrap' private key and certificate available on the connecting device,
as well as a copy of the CA certificate to verify the TLS connection.

Once you've cloned and built the LITE Bootstrap Server, run the following
scripts once in that repo, which will generate the files we need to
copy into this Zephyr application:

- ``setup-ca.sh``
- ``setup-bootstrap.sh``

The following files need to be copied into this codebase:

.. code-block::

   <bootstrap>/certs/bootstrap_crt.txt -> src/bootstrap_crt.txt
   <bootstrap>/certs/bootstrap_key.txt -> src/bootstrap_key.txt
   <bootstrap>/certs/ca_crt.txt        -> src/ca_crt.txt

Before running this codebase, be sure that you also execute the
``run-server.sh`` script to start the LITE Bootstrap Server.

If everything is configured correctly you can run the ``keys ca 5001`` shell
command to get an X.509 certificate for the client TLS key:

.. code-block::

   uart:~$ keys ca 5001
   TODO: Add sample output

And you should see the following log message for the bootstrap server:

.. code-block::

   $ ./run-server.sh
   TODO: Add output with log message from device registration


Building and Running
********************

On Target
=========

ToDo: Add build instructions for B-U585I-IOT02A:

* Without networking
* With Mikroe Wifi ESP click shield (MIKROE-2542)
* With Mikroe ETH click shield (MIKROE-971)

On QEMU:
========

Build without networking support:

.. code-block:: console

   $ west build -p auto -b mps2_an521_ns -t run

Build with networking support and QEMU user mode for networking:

.. code-block:: console

   $ west build -p auto -b mps2_an521_ns -t run -- \
       -DOVERLAY_CONFIG="overlay-smsc911x.conf overlay-network.conf" \
       -DCONFIG_NET_QEMU_USER=y \
       -DCONFIG_BOOTSTRAP_SERVER_HOST=\"hostname.domain.com\"

.. note::

   ``DCONFIG_BOOTSTRAP_SERVER_HOST`` should point to the domain name where
   the bootstrap server is located. This may be a proper domain, or the
   output of the `hostname` command, depending on how the bootstrap server
   was configured. See https://github.com/Linaro/lite_bootstrap_server
   for details.

Sample Output
=============

.. code-block:: console

   $ west build -t run
   -- west build: running target run
   [0/25] Performing build step for 'tfm'
   ninja: no work to do.
   [1/2] To exit from QEMU enter: 'CTRL+a, x'[QEMU] CPU: cortex-m33
   char device redirected to /dev/pts/1 (label hostS0)
   qemu-system-arm: warning: nic lan9118.0 has no peer
   [INF] Beginning TF-M provisioning
   [WRN] TFM_DUMMY_PROVISIONING is not suitable for production! This device is NOT SECURE
   [Sec Thread] Secure image initializing!
   Booting TF-M v1.6.0+8cffe127
   [UTVM SERVICE] UTVM initalisation completed
   [TFLM SERVICE] TFLM initalisation completed
   Creating an empty ITS flash layout.
   Creating an empty PS flash layout.
   [HUK DERIV SERV] Successfully derived the key for HUK_COSE
   [NV PS COUNTERS] nv_ps_counter_tracker 0
   [NV PS COUNTERS] nv_ps_counter_rollover_tracker 0
   [NV PS COUNTERS] NV_PS_COUNTER_ROLLOVER_MAX 4294967200
   [NV PS COUNTERS] NV_COUNTER_TRACKER_THRESHOLD_LIMIT 100
   *** Booting Zephyr OS build zephyr-v3.2.0-1553-g45e1ff94cdbc ***
   [HUK DERIV SERV] Generated UUID: 45b51869-8132-4e15-b780-288d521a5078


   <inf> app: Successfully derived the key for HUK_CLIENT_TLS

   [    2.631000] <inf> app: Azure: waiting for network...
   [    7.141000] <inf> app: Azure: Waiting for provisioning...

After waiting for the "Waiting for provisioning" message, the ``keys ca 5001``
command can be used to query the bootstrap server.

.. code-block:: console

   uart:~$ keys ca 5001
   argc: 2
   [    9.288000] <inf> app: uuid: d74696ad-cb3b-4275-b74a-c346ffe71ea9

   Generating X.509 CSR for 'Device Client TLS' key:
   Subject: O=Linaro,CN=d74696ad-cb3b-4275-b74a-c346ffe71ea9,OU=Device Client TLS
   [HUK DERIV SERV] tfm_huk_hash_sign_csr()::503 Verified ASN.1 tag and length of the payload
   [HUK DERIV SERV] tfm_huk_hash_sign_csr()::511 Key id: 0x5001
   cert starts at 0x2e2 into buffer
   [    9.527000] <inf> app: Got DNS for linaroca
   [    9.658000] <inf> app: All data received 595 bytes
   [    9.658000] <inf> app: Response to req
   [    9.658000] <inf> app: Status OK
   [    9.659000] <inf> app: Result: 3
   [    9.659000] <inf> app: cert: 460 bytes

            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
   00000000 30 82 01 C8 30 82 01 6F A0 03 02 01 02 02 08 16 0...0..o........
   00000010 EB F5 18 21 87 AE 38 30 0A 06 08 2A 86 48 CE 3D ...!..80...*.H.=
   ...
   [    9.725000] <inf> app: provisioned host: davidb-zephyr, port 8883
   [    9.725000] <inf> app: our uuid: d74696ad-cb3b-4275-b74a-c346ffe71ea9
   [    9.726000] <inf> app: Device Topic: devices/d74696ad-cb3b-4275-b74a-c346ffe71ea9/messages/devicebound/#
   [    9.727000] <inf> app: Event Topic: devices/d74696ad-cb3b-4275-b74a-c346ffe71ea9/messages/events/
   [    9.727000] <inf> app: Azure hostname: davidb-zephyr.azure-devices.net
   [    9.728000] <inf> app: Azure port: 8883
   [    9.728000] <inf> app: Azure user: davidb-zephyr.azure-devices.net/d74696ad-cb3b-4275-b74a-c346ffe71ea9
   [    9.729000] <inf> app: Azure: Provisioning available

            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
   00000000 30 82 01 C8 30 82 01 6F A0 03 02 01 02 02 08 16 0...0..o........
   00000010 EB F5 18 21 87 AE 38 30 0A 06 08 2A 86 48 CE 3D ...!..80...*.H.=
   ...

Test Suite (Twister/ZTest)
##########################

You can find the integration tests in the ``tests`` folder, with the following
structure:

.. code-block:: console

   tests
   │
   └───test_service
   └───tfm_huk_deriv_srv
       │─── src
       │─── CMakeLists.tx
       │─── prj.conf
       └─── testcase.yaml


Building and Running the Tests on QEMU
**************************************

To run the entire test suite:

.. code-block:: console

   $ cd path/to/zephyr
   $ source zephyr-env.sh
   $ twister -p mps2_an521_ns -N --inline-logs \
      -T path/to/modules/outoftree/zephyr_secure_inference/tests


To run a specific test (HUK key derivation service test here):

.. code-block:: console

   $ twister -p mps2_an521_ns -N --inline-logs \
     -T modules/outoftree/zephyr_secure_inference/tests/tfm_sp/tfm_huk_deriv_srv/


Common Problems
###############

Compilation fails with ``ca_crt.txt: No such file or directory``
****************************************************************

If you are building with networking support, some files from the
`LITE Bootstrap Server <https://github.com/Linaro/lite_bootstrap_server>`_
are required to be copied into your sample application so that it can generate
X.509 certificates, and communicate with the MQTT Broker that the bootstrap
server describes.

This error means that you didn't copy the required key and certificate files
over, as described in the 'Provisioning' setup section of this guide.

Why are my derived keys values and UUID always the same?
********************************************************

TF-M defines a hard-coded HUK value for the mps2 and mps3 platforms, meaning
that every instance of this sample run on these platforms will derive the same
key values.

This project defines an optional ``HUK_DERIV_LABEL_EXTRA`` value in the secure
parition that can be used to provide an additional label component for key
derivation, enabling key diversity when testing on emulated platforms.

A KConfig wrapper for this variable is also added via the
``DCONFIG_SECURE_INFER_HUK_DERIV_LABEL_EXTRA`` config flag to facilitate passing
the label from Zephyr's build system up to the TF-M build system.

The label value must be less than 16 characters in size!

It can be defined at compile time with west via:

.. code-block:: console

   $ west build -p -b mps2_an521_ns -t run -- \
     -DCONFIG_SECURE_INFER_HUK_DERIV_LABEL_EXTRA=\"123456789012345\"

How to disable TrustZone on the ``B-U585I-IOT02A``?
***************************************************

If you have flashed a sample to the B-U585I-IOT02A board that enables TrustZone,
you will need to disable it before you can flash and run a new non-TrustZone
sample on the board.

To disable TrustZone on the `B-U585I-IOT02A <https://www.st.com/en/evaluation-tools/b-u585i-iot02a.html>`_
board, i.e. set TZEN bit from 1 to 0 in the User Configuration register, it's
necessary to change AT THE SAME TIME the TZEN and the RDP bits.

Hence, TZEN needs to get set from 1 to 0 and RDP, AT THE SAME TIME, needs to get
set from DC to AA (step 3 below).

This is documented in the `AN5347, in section 9, "TrustZone deactivation" <https://www.st.com/resource/en/application_note/dm00625692-stm32l5-series-trustzone-features-stmicroelectronics.pdf>`_.

However it happens that the RDP bit is probably not set to DC yet, so first you
need to set it to DC (step 2).

Finally you need to set the "Write Protection 1 & 2" bytes properly, otherwise
some memory regions won't be erasable and mass erase will fail (step 4).

The following command sequence will fully deactivate TZ:

Step 1:

Ensure U23 BOOT0 switch is set to 1 (switch is on the left, assuming you read
"BOOT0" silkscreen label from left to right). You need to press "Reset" (B2 RST
switch) after changing the switch to make the change effective.

Step 2:

.. code-block:: console

   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob rdp=0xDC

Step 3:

.. code-block:: console

   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -tzenreg

Step 4:

.. code-block:: console

   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp1a_pstrt=0x7f
   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp1a_pend=0x0
   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp1b_pstrt=0x7f
   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp1b_pend=0x0
   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp2a_pstrt=0x7f
   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp2a_pend=0x0
   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp2b_pstrt=0x7f
   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp2b_pend=0x0

Adding an external WIFI interface shield based on MikroE click boards
**********************************************************************

It is possible to add an external WiFI interface based on MikroElektronika click boards attaching
them to the arduino_serial or mikrobus_serial nodes of a board like B-U585I-IOT02A, these shields are based
on ESP8266 which are very affordable way to run the samples on SoCs that don't have a native networking support.

.. image:: https://github.com/Linaro/zephyr_secure_inference/blob/main/docs/wifi-esp-click.png?raw=true
  :alt: MikroElektronika WiFi-ESP-Click board.

The board pinout is referred below:

+-----------------------+---------------------------------------------+
| Shield Connector Pin  | Function                                    |
+=======================+=============================================+
| RST#                  | ESP8266 Module Reset                        |
+-----------------------+---------------------------------------------+
| TXD                   | Serial data transmission output pin         |
+-----------------------+---------------------------------------------+
| RXD                   | Serial data reception input pin             |
+-----------------------+---------------------------------------------+

Before usage, This shield should be loaded with the `ESP8266 AT Bin`_ software which is available at 
Espressif Systems web site. This version is command compatible with ESP8266 AT Bin 2.0.0, after getting 
the binary from Espressif site, connect the J1 of the board to a serial-to-USB converter of your
preference, or to one Espressif programming boards like ESP-Prog on the HD1 connector, short circuit 
pins 5 and 6 to put the ESP8266 into download mode, on other modules, this is the same to tie the 
IO0 pin to GND. Install the `ESP-Tool`_, then extract the downloaded folder, navigate inside 
<extraction_directory>/ESP8266_NonOS_AT_Bin_V1.7.5_1/ESP8266_NonOS_AT_Bin_V1.7.5/bin, then type the 
following command to flash the device:

.. code-block:: console

   esptool.py --chip auto --baud 115200 --before default_reset --after hard_reset write_flash \
   --flash_mode dio \
   --flash_freq 40m \
   --flash_size 2MB \
   0x00000 boot_v1.7.bin \
   0x01000 at/512+512/user1.1024.new.2.bin \
   0xfc000 esp_init_data_default.bin \
   0x7e000 blank.bin \
   0xfe000 blank.bin \

If necessary, you can indicate a specific port via ``--port <Selected PORT>``.

Once flashed, it is possible to verify the module. While connected, open your preferred
terminal configured as 115200, 8, N, 1 and perform a board reset. You should see an
initial log and last message should be the version of the AT firmware flashed.

After flashing the firmware you may also able to build the the sample and tests 
with the shield enabled as network interface to do so Set ``-DSHIELD=<shield designation>`` 
when you invoke ``west build``.

See this example for the b_u585i_iot02a development kit, using the Arduino connector for the UART pins:

.. code-block:: console

   $ west build -p auto -b b_u585i_iot02a -- -DSHIELD=esp_8266_arduino

References
**********

.. target-notes::

.. _ESP8266 AT Bin:
   https://www.espressif.com/sites/default/files/ap/ESP8266_NonOS_AT_Bin_V1.7.5_1.zip
