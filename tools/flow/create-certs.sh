#! /bin/bash

set -e

# Create the minimal certificates required for the flow demo.
#
# Flow does not care about the contents of the certificates, only about the
# subject name, and the keys used. This script will create a pair of minimal
# certificates that are just self signed. It is also possible to use the
# `lite_bootstrap_server` to create certificates, according to the instructions
# in the `README.md`.

# Make a key with a basename of $1 and a subject of $2
make_key()
{
    if [[ -f "$1".pk8 ]] || [[ -f "$1".key ]] || [[ -f "$1".crt ]]; then
        echo "Files exist with base of $1.*"
        exit 1
    fi

    # Create the private key
    openssl ecparam -name prime256v1 -genkey -out "$1".key

    # Convert to pkcs 8
    openssl pkcs8 -in "$1".key -inform PEM \
            -out "$1".pk8 \
            -topk8 -nocrypt

    # Generate a signed certificate.
    openssl req -new -x509 -days 3650 -key "$1".key \
            -out "$1".crt \
            -subj "$2"
}

mkdir -p certs
make_key certs/cloud1 "/O=Linaro/CN=Flow test cloud"
make_key certs/device "/O=Linaro/CN=Flow test device"
