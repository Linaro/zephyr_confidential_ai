# Generating device keys

This application requires a device-specific key and certificate, which
will ultimately be placed on the device through a provisioning
process.

For now, this must be generated and processed manually.

## Configuring for the specific service and device

Please copy `src/azure-config.h.template` to `src/azure-config.h` and
edit the file, configuring it for your specific IoT Hub and device.
The device ID here should match the one in the certificate you will
provision on this device.

## Including the certificate.

The program expects the certificate to be placed in a file called
`src/device_crt.txt` as a C string, in PEM format.  This can be
generated from the PEM format certificate file using something like:

```
sed s'/.*/"&\\r\\n"/' .../linaroca/certs/<UUID>.crt > src/device_crt.txt
```

## Including the device private key

The private key also needs to be encoded in a format that can be
compiled into C.

```
xxd -i < .../linaroca/certs/<UUID>.key > src/device_key.txt
```

These files should not be checked in.

## Including the bootstrap CA certificate

Bring in the bootstrap CA certificate.  The LinaroCA setup-ca.sh
script should have extracted a file `certs/ca_crt.txt`, which can be
placed in the `src` directory.
