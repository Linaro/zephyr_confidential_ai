# Hardware Notes: ESP WiFi Modules

It's possible to enable WiFi connectivity on your board via an external ESP32
or ESP8266 module, using something like MikroElektronika Click shield. The
WiFi offload chip is connected to the host development board via the
`arduino_serial` or `mikrobus_serial` devicetree nodes, communicating with a
custom AT command set.

These relatively easy-to-source boards and modules offer an easy way to enable
TLS connectivity on SoCs that don't have native networking support.

## Software Requirements

Both the ESP32 and ESP8266 modules can be flashed using
[esptool](https://github.com/espressif/esptool/releases). Make sure this tool
is available on your system `$PATH`.

## ESP32-WROOM-32 (ESP32)

Zephyr's ESP32 driver assumes **AT bin firmware 2.0.x** is being used
(`CONFIG_WIFI_ESP_AT_VERSION_2_0`).

Please be sure that your module has the correct firmware flashed, following
the update instructions below to flash the correct firmware to the device if
necessary:

### AT 2.0.0 Firmware Update for ESP32

- Download and extract `v2.0.0.0 ESP32-WROOM-32_AT_Bin_V2.0.0.0.zip` from
  [Espressif Released Firmware][ESP32FW]
- Connect the USB/UART adapter to TX/RX on the ESP32 board
- Run the following command (updating the `--port` parameter as appropriate!):

```bash
$ esptool \
  --port /dev/tty.usbserial-21110 \
  --baud 115200 \
  --chip auto \
  --before default_reset \
  --after hard_reset write_flash \
  --flash_mode dio \
  --flash_freq 40m \
  --flash_size detect \
  0x10000 ota_data_initial.bin \
  0x1000 bootloader/bootloader.bin \
  0x20000 at_customize.bin \
  0x21000 customized_partitions/ble_data.bin \
  0x24000 customized_partitions/server_cert.bin \
  0x26000 customized_partitions/server_key.bin \
  0x28000 customized_partitions/server_ca.bin \
  0x2a000 customized_partitions/client_cert.bin \
  0x2c000 customized_partitions/client_key.bin \
  0x2e000 customized_partitions/client_ca.bin \
  0x30000 customized_partitions/factory_param.bin \
  0xf000 phy_init_data.bin \
  0x100000 esp-at.bin \
  0x8000 partitions_at.bin
```

[ESP32FW]: https://docs.espressif.com/projects/esp-at/en/latest/esp32/AT_Binary_Lists/ESP32_AT_binaries.html

## ESP-WROOM-02 (ESP8266)

Zephyr's ESP8266 driver assumes **AT bin firmware 1.7.x** is being used
(`CONFIG_WIFI_ESP_AT_VERSION_1_7`).

This sample was tested with a [Mikroe-2542][MIKROE2542] (WiFi ESP Click)
shield, which ships with **1.7.x firmware by default**. This means the shield
should work out of the box with Zephyr.

If you are using a different module, or don't know the firmware version used
by your module, you can reflash the device with the 1.7.5 AT firmware using
the instructions below.

> NOTE: Hardware flow control (CTS+RTS) is not required for lower baud
  rates, such as the default 115200 used by these modules and the Zephyr
  driver for them.

### AT 1.7.5 Firmware Update for ESP8266

> These steps are optional for the Mikroe-2542, which ships with the 1.7.x AT
  firmware by default. The instructions are provided to reflash other ESP8266
  modules with the 1.7.5 AT firmware.

> The 1.7.x firmware can no longer be downloaded directly from Espressif's
  firmware download page, so the instructions below download the image
  directly from a specific URL.

- Download the ESP8266 IDF AT Bin v1.7.5 firmware via:

```bash
$ wget https://www.espressif.com/sites/default/files/ap/ESP8266_NonOS_AT_Bin_V1.7.5_1.zip
```

- Unzip the downloaded firmware
- Connect the USB/UART adapter to TX/RX/GND/3.3V on the ESP8266 module
- Connect `P0` to `GND` on the Mikroe-2542 module on the optional 6-pin header,
  which puts the ESP8266 into **download** mode
- Reset the board by connecting `RST` to `GND` then removing the RST connection
- Run the following command from the `ESP8266_NonOS_AT_Bin_V1.7.5/bin` folder,
  updating the `--port` parameter as appropriate:

```bash
$ esptool \
  --chip esp8266 \
  --port /dev/tty.usbserial-21110 \
  --baud 115200 \
  --before default_reset \
  --after hard_reset write_flash \
  --flash_mode dio \
  --flash_freq 40m \
  --flash_size 2MB \
  0x00000 boot_v1.7.bin \
  0x01000 at/512+512/user1.1024.new.2.bin \
  0xfc000 esp_init_data_default_v08.bin \
  0x7e000 blank.bin \
  0xfe000 blank.bin
```

- Remove the jumper setting `P0` to `GND` to prevent booting into download
  mode on subsequent resets

[MIKROE2542]: https://www.mikroe.com/wifi-esp-click

## Building with ESP module support

After flashing the firmware you should be able to build the the sample and
verify that the shield is enabled as a network interface by setting
`-DSHIELD=<shield designation>` when you invoke ``west build``.

For the `b_u585i_iot02a` board target, for example, using the Arduino connector
for the UART pins and the Mikroe-2542 (ESP8266) shield, we could run:

```bash
$ west build -p auto -b b_u585i_iot02a_ns -- \
    -DOVERLAY_CONFIG="overlay-network.conf" \
    -DCONFIG_NET_QEMU_USER=y \
    -DCONFIG_BOOTSTRAP_SERVER_HOST=\"hostname.domain.com\" \
    -DSHIELD=esp_8266_arduino
```
