# Flow of data through the system.

## Background

This document describes the flow of data through the system, how it is
encoded, and the specifics of the encryption and authentication used.

The following documents define the COSE encoding used for the data
described in this document.

- [RFC9052]  Schaad, J., "CBOR Object Signing and Encryption (COSE):
  Structures and Process", STD 96, RFC 9052, DOI 10.17487/RFC9052,
  August 2022, <https://www.rfc-editor.org/info/rfc9052>.
- [RFC9053]  Schaad, J., "CBOR Object Signing and Encryption (COSE):
  Initial Algorithms", STD 96, RFC 9053, DOI 10.17487/RFC9053,
  August 2022, <https://www.rfc-editor.org/info/rfc9053>.

The references section of these documents will link to numerous other
documents that will be helpful in understanding both the encryption
involved, and various aspects of the encoding itself.

Specifically, this document will use the CBOR diagnostic notation
defined in RFC 8949 in examples given.

## Encryption and Authentication

This flow uses both encryption and authentication to enhance the
integrity and privacy of the data communicated off of the device.
Because of the small and embedded nature of these devices, we have
chosen specific algorithms for this implementation.  The algorithms
are represented in the COSE structures, and as such, can be modified
or enhanced if the need arises.

For encryption, we use AES 128 with GCM.  AES 128 uses 128-bit keys,
and a 128-bit IV.  These are stored as `bstr` values in CBOR.

For authentication, as well as key agreement we use elliptic curves,
with the NIST P-256 curve, also known as secp256r1.  For digital
signatures, we use ECDSA, and for key agreement, we use ECDH
ephemeral-static, along with AES key wrap.  The key wrap allows for
future extension to allow multiple recipients.

## Keys involved

The following EC keypairs exist in the system:

- Device private.  Each device generates its own private key.  This
  will either be derived from a hardware unique key, or randomly
  generated and stored in secure storage on the device.  The private
  key never leaves the device.
- Device certificate.  This certificate, signed by the device private
  key as well as the CA key.
- Cloud private.  This private key is generated externally and kept
  private within the cloud service that consumes messages.
- Cloud certificate.  This certificate, signed by the CA, will be
  given to each device.

The overall flow follows the following model:

![Encrypted data flow](cose-payload.drawio.png)

## The initial message

In order to begin communicating secure payload, the device must create
a secret key (the session key or NONCE in the diagram).  This must be
securely generated from a good source of pseudorandom data.

This will be wrapped in a COSE Encrypt message, encrypted using the
Cloud Public key, so that the cloud service can decrypt it.  This
message is then wrapped in a COSE Sign1 message, signed by the devices
private key.  This ensures integrity of this, and that it came from
this device.

Included in the message must be a 'keyid' COSE protected header that
indicates a unique value for this particular key.  The device should
try to make this unique, using either a timestamp, if it has a notion
of time, or a non-decreasing integer value.

The payload data itself will be encrypted using COSE Encrypt0.  The
keyid should match the above message to match which NONCE/session key
has been used.  The Encrypt0 message provides both encryption and data
integrity, to ensure the payload is correctly communicated.

If neceesary, it is also possibly to embed a sequence number in the
protected header of this message.  (TODO: What COSE value should be
used).

## MQTT

The Sign1(Encrypt(nonce)) message should be sent with a QoS of
"exactly once".  This is more expensive through the MQTT
infrstructure, but ensures that the message has been delivered, and
that the cloud service will be able to decrypt any subsequent
messages.

The actual payload messages can be delivered with "at most once" QoS,
or with "at least once", depending on the significant of the payload.
If there is a sequence number, this can be used to remove duplicated
messages, and because the sequence number will be in a protected
header, it will not be subject to tampering, or replay.

## Future ideas.

Current proposals for `t_cose` patches to support encryption will
require the above protocol.  Future versions may allow the implied
content encryption key negotiated within the COSE Encrypt payload to
be reused for subsequent Encrypt0 message.  In this case, the Encrypt
can code a blank payload, and the NONCE does not need to be explicitly
handled.
