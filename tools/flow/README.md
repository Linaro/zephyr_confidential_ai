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
```

## Encrypted flow

The following commands demonstrate how this command can be used to encrypt using
the 'flow' process. This assumes that the device certificate is placed in a file
called `certs/device.crt`, with the private key in `certs/device.pk8`, and the
service certificate will be in `certs/cloud1.crt`, with its private key in
`certs/cloud1.pk8`.

A session captures a secret key that can be used so that later messages of
encrypted data are both smaller as well as faster to create and process. The
state file holds this session key. On a target, this will generally be kept in
RAM, and a new session created on a subsequent boot. The session has a randomly
generated session ID that is used to correlate payload with the session.

```
cargo run -- new-session \
      --device-key certs/device.crt \
      --service-cert certs/cloud1.crt \
      --state tmp-session1 \
      --output session1.cbor
```

Once a session is esablished, it can be used to encrypt a payload packet. The
packet uses the session key from the state file to encrypt and authenticate a
message.

```
echo 'Sample payload' > payload.txt

cargo run -- encrypt \
      --state tmp-session1 \
      --input payload.txt \
      --output payload-enc.cbor
```

This packet of data can be decrypted using the session packet and the payload
packet. In this case, we need the private key of the cloud service.

```
cargo run -- decrypt \
      --session session1.cbor \
      --service-cert certs/cloud1.crt \
      --device-cert certs/device.crt \
      --input payload-enc.cbor \
      --output payload-plain.txt
```

In addition to the above, it is also possible to perform a simple-encrypt, where
the payload is directly encrypted and signed. This can be useful for
infrequently sent information.

```
cargo run -- simple-encrypt \
      --input payload.txt \
      --output payload-simple.cbor \
      --device-key certs/device.crt \
      --service-cert certs/cloud1.crt

cargo run -- simple-decrypt \
      --input payload-simple.cbor \
      --output payload-sim-plain.txt \
      --device-cert certs/device.crt \
      --service-cert certs/cloud1.crt
```
