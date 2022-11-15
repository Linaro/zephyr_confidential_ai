# Hardware Notes: Ethernet Modules

It is possible to add an external ethernet interface based on Mikroe
Elektronika Click boards, attaching it, for example, to the `mikrobus_spi`
devicetree node on a board that supports mikrobus and Click shields.

These affordable shields offer an easy way to run this sample on SoCs that
don't have native networking support.

## Mikroe ETH Click (ENC28J60)

The [Mikroe ETH Click][MIKROE971] board (Mikroe-971) is based on the
[ENC28J60][ENC28J60] 10Base-T ethernet controller, communicating over the SPI
bus, and has the following pinout:

| Shield Connector Pin  | Function                                    |
|-----------------------|---------------------------------------------|
| RST#                  | Ethernet Controller's Reset                 |
| CS#                   | SPI's Chip Select                           |
| SCK                   | SPI's ClocK                                 |
| SDO                   | SPI's Slave Data Output  (MISO)             |
| SDI                   | SPI's Slave Data Input   (MISO)             |
| INT                   | Ethernet Controller's Interrupt Output      |

> You'll need a development board that includes support for a `mikrobus_spi`
  node, and an overlay that sets the `CS`, `INT`, and `RST` pins correctly for
  the SPI bus and the ENC28J60. The LPCXpresso55s69-EVK is one possibility.

[MIKROE971]: https://www.mikroe.com/eth-click
[ENC28J60]: https://www.microchip.com/en-us/product/ENC28J60

### Build with `mikroe_eth_click` support

The ethernet shield can be enabled via the `-DSHIELD=mikroe_eth_click` flag
when compiling with `west`:

```bash
$ west build -p auto -b lpcxpresso55s69_cpu0 \
  samples/net/dhcp_client -- \
  -DSHIELD=mikroe_eth_click 
```
