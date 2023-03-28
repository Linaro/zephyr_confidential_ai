# Setting things up.

Flow doesn't try to recreate the key creation parts of what
`lite_bootstrap_server` does, so we will start by using the scripts from that
tool to create the service key as well as the device keys.

There are two ways to setup the keys for flow. You can use the
`lite_bootstrap_server` to create the keys and certificates, or you can use a
small script with the tool that creates simple self-signed certificates that are
sufficient for flow.

## Simple self-signed certs

The `./create-certs.sh` script will create device and cloud1 certificates that
will allow the commands below to demonstrate the flow. These certificates will
be self signed, and not verified or correlated to any other keys. This makes it
easy to quickly test with flow.

```
$ ./create-certs.sh
```

## Using the `lite_bootstrap_server`

If you already have the `lite_bootstrap_server` running, it maybe easiest to
just use keys that it has created. At the time of writing, this tool was only
able to create device certificates. However, since flow doesn't really care
about the details of the certificate, the cloud service can be faked by just
creating another device key for it.

The `setup-ca.sh` can be used to create the CA.cert file.  We will
need to create key for the service, which can be created as if it were
an ordinary device:

Once the server is running, use the `new-device.sh` script to create a device
for testing flow (`device.*` below), and a service device (`cloud1.*` below).

CA uses the openssl-specific format for private keys, and these will
need to be converted to pkcs8 to be usable by flow.  This can be done
with:

```
$ openssl pkcs8 -in certs/device.key -inform PEM \
        -out certs/device.pk8 -topk8 -nocrypt
$ openssl pkcs8 -in certs/cloud1.key -inform PEM -out certs/cloud1.pk8 -topk8 -nocrypt
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
