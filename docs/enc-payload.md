# Encrypted Payload

One aspect of Confidential AI has to do with getting the resulting
payload from the device in a manner that ensures both authentication
(we know the data is coming from an authorized device), and
confidentiality (observers of the protocol will be unable to determine
the contents).  This document will describe how this communication
happens.

# References

- CBOR: [RFC8949](https://datatracker.ietf.org/doc/html/rfc8949).
  Concise Binary Object Representation (CBOR).  CBOR is the encoding
  format used for most aspects of this protocol.
- CDDL: [RFC8610](https://datatracker.ietf.org/doc/html/rfc8610).
  Concise Data Definition Language (CDDL): A Notational Convention to
  Express Concise Binary Object Representation (CBOR) and JSON Data
  Structures.  This notation is used to describe data structures in
  both higher level protocols, as well as the wrapper protocol
  described in this document.
- COSE: [RFC8152](https://datatracker.ietf.org/doc/html/rfc8152).
  CBOR Object Signing and Encryption (COSE).  Defines a data format
  for encoding signatures, message authentication codes, and
  encryption using CBOR for serialization.
- [draft-ietf-cose-hpke-01](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/)
  Use of Hybrid Public-Key Encryption (HPKE) with CBOR Object Signing
  and Encryption (COSE).  Defines how to use HPKE within CBOR.

# Terminology

- CEK: Content Encryption Key
- HPKE: Hybrid Public Key Encryption
- pkR: Recipient's Public Key.  Held on device
- skR: Recipient's Private Key
- pkS: Sender's Public Key.  Held on device
- skR: Sender's Private Key

- `COSE_Sign`: A COSE Signed Data Object.  This message wraps an
  arbitrary block of data with a signature to ensure it was generated
  by a known sender.
- `COSE_Sign1`: A Single Signer Data Object.  Similar to `COSE_Sign`
  but optimized for the case where there is a single recipient.
- `COSE_Encrypt`: A COSE Encrypted Data Object.  Encrypts and possibly
  wraps a payload using a negotiated CEK.  The payload can either be
  internal, bundeled within the `COSE_Encrypt` message, or referenced
  externally.  The message will be both encrypted and authenticated,
  meaning as long as the CEK is kept between the two parties, only
  those parties will be able to decode the message, and those parties
  will also be able to determine the authenticity of the message.
- `COSE_Encrypt0`: A COSE Single Recipient Encrypted Data Object.
  This is a wrapper for a payload where the CEK has already been
  negotiated previously.

## Background

Devices supporting Confidential AI will generate various payload data.
This can be anything from raw sensor data to heavily processed output
data after Machine Learning algorithms have been used.  In either
case, it is desired to be able to transmit this data away from the
device in a way that ensures both authentication and confidentiality.
Authentication ensures that a given piece of payload data was indeed
generated by the specified device.  Confidentiality ensure that the
payload data cannot be decoded by other than the intended recipient.

These end devices are generally assumed to be microcontroller-type
devices, typically with flash memory sizes on the order of 1/2 to
several megabytes, and SRAM sizes on the order of hundreds of
kilobytes.  Confidential AI presumes that the microcontroller offers
some type of protected enclave so that the protected data and code can
be kept from the rest of the code running on the microcontroller.
However, this protocol is still useful, even with an ordinary simple
microcontroller, as it can prevent attacks against the communication
of the device.

We also assume that the device has been provisioned with a pair of
asymmetric keys to be used by this protocol:

- Device key: The device will have the private key for this key pair
  and the system that will be decoding the messages will have the
  public key.  Methods such as X.509 can be used to help with this
  provisioning process, but this is beyond the scope of this document.
- Service key: The device will have the public key for the intended
  recipient of these secured messages.

## Encoding

A simple way to encode messages meeting these requirements would be to
use

```
 COSE_Sign1(COSE_Encrypt(payload))
```

for each message.  The encryption ensures confidentiality and the
signature ensures authentication.  However, as both the key-exchange
aspect of the encrypt and the signature operation itself are
computationally expensive, this solution is unlikely to be practical
for the types of microcontroller devices we are targeting.

In order to reduce the number of key exchanges and signatures, it will
be necessary to separate these operations from the
authenticated-encryption for each payload message.  This can be done
via a manner similar to

```
  COSE_Sign1(COSE_Encrypt(CEK-1))
  COSE_Encrypt0(payload_1)    // implied using CEK-1
  COSE_Encrypt0(payload_2)    // implied using CEK-1
  ...
  COSE_Encrypt0(payload_n)    // implied using CEK-1
```

The initial message will negotiate a CEK that can be used by the
intended recipient.  This CEK will later be used by subsequent
messages to encrypt and authenticate the payloads.

However, there is a problem with this protocol in that if the initial
message isn't received, none of the remaining packets will be
decodable by the recipient.  Making this more robust will be a
tradeoff between message delivery reliability, and the need to
regenerate the sign/encrypt messages.  Another factor to consider is
how frequently the CEK needs to be renewed.

The sign/encrypt block can be resent periodically to handle the cases
where the message has simply been dropped.  It is also possible to
periodically generate a new CEK.

```
  COSE_Sign1(COSE_Encrypt(CEK-1))
  COSE_Encrypt0(payload_1)    // implied using CEK-1
  COSE_Encrypt0(payload_2)    // implied using CEK-1
  ...
  COSE_Encrypt0(payload_n)    // implied using CEK-1
  COSE_Sign1(COSE_Encrypt(CEK-1))
  COSE_Encrypt0(payload_n+1)  // implied using CEK-1
  COSE_Encrypt0(payload_n+2)  // implied using CEK-1
  ...
  COSE_Encrypt0(payload_m)    // implied using CEK-1
```

The frequency of sending the CEK is beyond the scope of this document.

When generating a new CEK, the use of the new CEK can be staggered and
only used after some number of times that the encoding payload has
been sent for it.  For example

```
  COSE_Sign1(COSE_Encrypt(CEK-1))
  COSE_Encrypt0(payload_n)    // implied using CEK-1
  COSE_Encrypt0(payload_n+1)  // implied using CEK-1
  COSE_Encrypt0(payload_n+2)  // implied using CEK-1
  ...
  COSE_Sign1(COSE_Encrypt(CEK-1))
  COSE_Sign1(COSE_Encrypt(CEK-2))
  COSE_Encrypt0(payload_m)    // implied using CEK-1 (still 1)
  COSE_Encrypt0(payload_m+1)  // implied using CEK-1 (still 1)
  COSE_Encrypt0(payload_m+2)  // implied using CEK-1 (still 1)
  ...
  COSE_Sign1(COSE_Encrypt(CEK-1))
  COSE_Sign1(COSE_Encrypt(CEK-2))
  COSE_Encrypt0(payload_k)    // implied using CEK-1 (still 1)
  COSE_Encrypt0(payload_k+1)  // implied using CEK-1 (still 1)
  COSE_Encrypt0(payload_k+2)  // implied using CEK-1 (still 1)
  ...
  COSE_Sign1(COSE_Encrypt(CEK-2))
  COSE_Encrypt0(payload_j)    // implied using CEK-2
  COSE_Encrypt0(payload_j+1)  // implied using CEK-2
  COSE_Encrypt0(payload_j+2)  // implied using CEK-2
  ...
```

Again the number of sends and frequency of them is beyond the scope of
this document.

If the underlying protocol can guarantee reliable delivery of the messages
containing the CEK-1, it will be unnecessary to use the staggered protocol.

## Wrappers

As can be seen from the above, the `COSE_Encrypt0` package makes an
assumption as to which CEK it uses.  In order to make it clearer, we
wrap all messages with some extra data to give this information.

```
  confidential_message = key_message / payload_message

  key_message = [
    KEY_TYPE,
    int,                      ; CEK identifier.
    COSE_Sign1 / COSE_Sign,   ; Wrapped key.
      ; consists of COSE_Sign1(COSE_Encrypt(CEK))
      ; for the desired recipients.
  ]

  Payload_message = [
    PAYLOAD_TYPE,
    int,                      ; CEK identifier.
    COSE_Encrypt0,            ; Encrypted payload
  ]

  KEY_TYPE = 1
  PAYLOAD_TYPE = 2
```

When the underlying transport is MQTT, these messages will be
contained as the payload of the MQTT publish message.