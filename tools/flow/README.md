# Setting things up.

Flow doesn't try to recreate the key creation parts of what
`lite_bootstrap_server` does, so we will start by using the scripts from that
tool to create the service key as well as the device keys.

The `setup-ca.sh` can be used to create the CA.cert file.  We will
need to create key for the service, which can be created as if it were
an ordinary device:

Once the server is running, use the `new-device.sh` script to create a
device for testing flow, and a service device.

CA uses the openssl-specific format for private keys, and these will
need to be converted to pkcs8 to be usable by flow.  This can be done
with:

```
$ openssl pkcs8 -in certs/devuuid.key -inform PEM \
        -out certs/devuuid.pk8 -topk8 -nocrypt
$ openssl pkcs8 -in certs/stuff.key -inform PEM -out certs/stuff.pk8 -topk8 -nocrypt
