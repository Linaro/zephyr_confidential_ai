//! Key management

// TODO: Temporary until we use these methods in main.
#![allow(dead_code)]

use std::{collections::BTreeMap, path::Path};

use aes_gcm::{aead::generic_array::GenericArray, AeadInPlace, Aes128Gcm, KeyInit, Nonce};
use aes_kw::{Kek, KekAes128};
use base64::{engine::general_purpose, Engine};
use coset::{
    cbor::value::Value, iana, CborSerializable, CoseEncrypt0, CoseEncrypt0Builder,
    CoseEncryptBuilder, CoseKdfContextBuilder, CoseRecipientBuilder, CoseSign1, CoseSign1Builder,
    Header, HeaderBuilder, Label, ProtectedHeader, RegisteredLabelWithPrivate, SuppPubInfo,
};
// use ecdsa::signature::Verifier;
use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::DecodePrivateKey,
    PublicKey, SecretKey,
};
use rand_core::{CryptoRng, RngCore};
use x509_parser::{parse_x509_certificate, prelude::parse_x509_pem};

#[cfg(test)]
use rand_core::OsRng;

// This isn't right, but leave here to prevent this warning, until we do use
// this from main.
#[cfg(test)]
use coset::CoseEncrypt;

use crate::{data::Example, errors::FlowError, pdump::HexDump, Result};

#[derive(Debug)]
pub struct Key {
    info: KeyInfo,
    key_id: String,
}

/// Internal representation of a keypair. This can come from a certificate and
/// private key file, or can be extracted out of one of the example files.
#[derive(Debug)]
pub enum KeyInfo {
    Secret(SecretKey),
    Public(PublicKey),
}

impl Key {
    pub fn from_example(example: &Example) -> Result<Key> {
        let key = example.get_keys()[0];
        let secret = decode_key(key)?;
        let key_id = key
            .get("kid")
            .ok_or_else(|| FlowError::Flow("Key id (kid) not present"))?;
        Ok(Key {
            info: KeyInfo::Secret(secret),
            key_id: key_id.to_string(),
        })
    }

    /// Construct a fresh keypair, randomly.
    pub fn new(rng: impl CryptoRng + RngCore, key_id: &str) -> Result<Key> {
        Ok(Key {
            info: KeyInfo::Secret(SecretKey::random(rng)),
            key_id: key_id.to_string(),
        })
    }

    /// If there is a private key file adjacent to this file certificate, try
    /// reading a private key from it.
    fn read_private(path: &Path) -> Result<SecretKey> {
        // Look for a .pk8 file with the same name stem.
        let mut pk_file = path.to_path_buf();
        pk_file.set_extension("pk8");

        let pem = match std::fs::read_to_string(pk_file) {
            Ok(buf) => buf,
            Err(e) => return Err(e.into()),
        };
        let secret = SecretKey::from_pkcs8_pem(&pem).unwrap();
        Ok(secret)
    }

    /// Build a keypair (or possibly just a public key) out of a certificate
    /// file. If `with_private` is `true`, then there must be a `.pk8` file of
    /// the same base name as the certificate file containing the private key
    /// for this. In this case, the operations that require a private key will
    /// be available.
    pub fn from_cert_file<P: AsRef<Path>>(path: P, with_private: bool) -> Result<Key> {
        let path = path.as_ref();

        let secret = if with_private {
            Some(Self::read_private(path)?)
        } else {
            None
        };

        let cert = std::fs::read(path)?;
        let (rem, pem) = parse_x509_pem(&cert)?;
        if !rem.is_empty() {
            return Err(FlowError::Flow("Trailing garbage in certificate file"));
        }
        if pem.label != "CERTIFICATE" {
            return Err(FlowError::Flow(
                "Certificate file does not contain a CERTIFICATE",
            ));
        }
        let (rest, cert) = parse_x509_certificate(&pem.contents)?;
        if !rest.is_empty() {
            return Err(FlowError::Flow("Trailing der garbage in certificate file"));
        }
        // println!("cert: {:?}", cert);

        // For now, just use the textual version of the subject as the key-id,
        // we may want to only use some of the fields.
        let key_id = format!("{}", cert.subject());

        let pubkey = cert.public_key();

        // The raw key:
        let key = match pubkey.parsed()? {
            x509_parser::public_key::PublicKey::EC(pt) => PublicKey::from_sec1_bytes(pt.data())?,
            _ => return Err(FlowError::Flow("Cert public key is not EC key")),
        };

        // If we have a private key, ensure that it goes with the public key in
        // the certificate.
        match &secret {
            Some(sec) => {
                if sec.public_key() != key {
                    return Err(FlowError::Flow(
                        "pk8 key does not match public key in certificate",
                    ));
                }
            }
            None => (),
        }

        Ok(Key {
            info: secret.map_or_else(|| KeyInfo::Public(key), |s| KeyInfo::Secret(s)),
            key_id,
        })
    }

    /// Retrieve the public key associated with this Key.
    pub fn public_key(&self) -> PublicKey {
        match &self.info {
            KeyInfo::Secret(sec) => sec.public_key(),
            KeyInfo::Public(public) => public.clone(),
        }
    }

    /// Retrieve the secret key associated with this key. Fails if there is no
    /// associated secret key.
    pub fn secret_key(&self) -> Option<&SecretKey> {
        match &self.info {
            KeyInfo::Secret(sec) => Some(sec),
            KeyInfo::Public(_) => None,
        }
    }

    /// Decrypt a COSE_Encrypt packet that uses this particular key.
    pub fn decrypt_cose(&self, packet: &coset::CoseEncrypt) -> Result<Vec<u8>> {
        // For now, we only support a single recipient. Later, we can search
        // through the recipients to find the one that matches our current key.
        let recipient = match packet.recipients.as_slice() {
            [] => return Err(FlowError::Flow("No recipients")),
            [single] => single,
            _ => return Err(FlowError::Flow("Multiple recipients not yet supported")),
        };

        // Ensure that the correct algorithm is encoded.
        match recipient.protected.header.alg {
            Some(coset::RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ECDH_ES_A128KW)) => {
                ()
            }
            _ => return Err(FlowError::Flow("Unsupported algorithm in COSE packet")),
        }

        // The key ID of the sender is represented in the unprotected header.
        // TODO: actually compare this with the intended key id.
        let key_id = String::from_utf8_lossy(&recipient.unprotected.key_id).into_owned();
        println!("key id: {:?}", key_id);

        // Get the info about the key, for the most part, this match just match
        // specific values.
        let info = match cose_map_get(&recipient.unprotected.rest, &Label::Int(-1)) {
            None => {
                return Err(FlowError::Flow(
                    "No info entry -1 in recipient unprotected header",
                ))
            }
            Some(m) => m,
        };
        let info = info
            .as_map()
            .expect("Unexpected type of 'rest' field in map");

        // The key type must be a 2, for "EC2".
        match cbor_map_get(info, &Value::Integer(From::from(1i32))) {
            Some(v) if v == &Value::Integer(From::from(2i32)) => (),
            _ => return Err(FlowError::Flow("Expecting key to be EC2")),
        }

        // The curve must be P-256.
        match cbor_map_get(info, &Value::Integer(From::from(-1i32))) {
            Some(v) if v == &Value::Integer(From::from(1i32)) => (),
            _ => return Err(FlowError::Flow("Expecting curve to be P-256")),
        }

        // The other fields are then the x and y values.
        let x = cbor_map_get(info, &Value::Integer(From::from(-2)))
            .expect("x value of key not present")
            .as_bytes()
            .expect("x value of wrong type, expecting bstr");
        let y = cbor_map_get(info, &Value::Integer(From::from(-3)))
            .expect("y value of key not present")
            .as_bytes()
            .expect("y value of wrong type, expecting bstr");

        // Although there is a constructor for public keys that takes an affine
        // point, there doesn't seem to be any of deriving these directly from x
        // and y. Encode in sec1 as an uncompressed point.
        let mut sec1 = Vec::with_capacity(32 + 32 + 1);
        sec1.push(4);
        sec1.extend_from_slice(x.as_slice());
        sec1.extend_from_slice(y.as_slice());
        assert_eq!(sec1.len(), 65);

        let eph_pub = PublicKey::from_sec1_bytes(&sec1)?;

        // The algorithm for the context comes from the algorithm wrappin5 data,
        // but isn't the same, as it is only the keywrap algorithm.
        let alg = match recipient.protected.header.alg.as_ref() {
            Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ECDH_ES_A128KW)) => {
                iana::Algorithm::A128KW
            }
            alg => {
                let msg = format!("{:?}", alg);
                return Err(FlowError::UnexpectedKeyWrap(msg));
            }
        };

        // Construct the context for the HKDF.
        let ctxb = CoseKdfContextBuilder::new()
            .supp_pub_info(SuppPubInfo {
                key_data_length: 128,
                protected: recipient.protected.clone(),
                other: None,
            })
            .algorithm(alg)
            .build();
        let ctx = ctxb.to_vec()?;

        let secret = p256::ecdh::diffie_hellman(
            self.secret_key().unwrap().to_nonzero_scalar(),
            eph_pub.as_affine(),
        );
        let hkdf = secret.extract::<sha2::Sha256>(None);
        let mut hkey = vec![0u8; 16];
        hkdf.expand(&ctx, &mut hkey).unwrap();

        // Use AES-KW to unwrap the key.
        let unwr: KekAes128 = Kek::try_from(hkey.as_slice()).unwrap();
        let mut cek = vec![0u8; 16];
        unwr.unwrap(recipient.ciphertext.as_ref().unwrap().as_slice(), &mut cek)
            .unwrap();

        // Use this key to build the aead handler for this.
        let cipher = Aes128Gcm::new_from_slice(&cek)?;
        let nonce = Nonce::from_slice(&packet.unprotected.iv);

        let plain = packet
            .decrypt(&[], move |ciphertext: &[u8], aad: &[u8]| {
                let mut plaintext = ciphertext.to_owned();
                match cipher.decrypt_in_place(nonce, aad, &mut plaintext) {
                    Ok(()) => Ok(plaintext),
                    Err(e) => Err(e),
                }
            })
            .unwrap();

        Ok(plain)
    }

    /// Given some payload, and a recipient (where we know their public key), construct a cose packet.
    pub fn encrypt_cose(
        &self,
        plaintext: &[u8],
        recipient: &Self,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<Vec<u8>> {
        let mut cek = vec![0u8; 16];
        rng.fill_bytes(&mut cek);

        // The kek is the key encryption key, which is also just generated.
        let mut kek = vec![0u8; 16];
        rng.fill_bytes(&mut kek);

        // Generate an IV.
        let mut kw_iv = vec![0u8; 12];
        rng.fill_bytes(&mut kw_iv);

        // There is an ephemeral key as well that we use to derive the shared
        // key we wrap with.
        let eph_key = SecretKey::random(rng);

        // Extract the x and y values from this, as be_bytes.
        let eph_pub = eph_key.public_key();
        // Get the SEC1 encoded point out of this.
        let encoded = eph_pub.as_affine().to_encoded_point(false);
        let encoded = encoded.as_bytes();
        assert_eq!(encoded.len(), 65);
        assert_eq!(encoded[0], 4);
        let eph_x = &encoded[1..33];
        let eph_y = &encoded[33..65];

        // Build a protected header for the recipient as this is needed for the
        // key derivation context.
        let prot_hd = Header {
            alg: Some(RegisteredLabelWithPrivate::Assigned(
                iana::Algorithm::ECDH_ES_A128KW,
            )),
            ..Default::default()
        };
        // let prot = ProtectedHeader {
        //     original_data: None,
        //     header: prot_hd,
        // };
        let item_map = Value::Map(vec![
            (Value::Integer(From::from(1)), Value::Integer(From::from(2))),
            (
                Value::Integer(From::from(-1)),
                Value::Integer(From::from(1)),
            ),
            (Value::Integer(From::from(-2)), Value::Bytes(eph_x.to_vec())),
            (Value::Integer(From::from(-3)), Value::Bytes(eph_y.to_vec())),
        ]);
        let unprot_hd = HeaderBuilder::new()
            .key_id(recipient.key_id.clone().into_bytes())
            .value(-1, item_map)
            .build();

        // There is a bit of a catch-22 in building this. The API seems to
        // suggest using the recipient to build the protected header from the
        // header, but we need it to build the context before we can encrypt the
        // data. As such, we build a temporary one, even though there isn't a
        // builder for this.
        let prot_full_hd = ProtectedHeader {
            original_data: None,
            header: prot_hd.clone(),
        };

        // Use this to build the aead handler for this.
        let cipher = Aes128Gcm::new_from_slice(&cek)?;
        let nonce = Nonce::from_slice(&kw_iv);

        // Use HKDF to derive the secret from this. From our perspective, this
        // is based on the secret from the ephemeral key, and the public data of
        // the recipient.
        let alg = iana::Algorithm::A128KW;
        let ctxb = CoseKdfContextBuilder::new()
            .supp_pub_info(SuppPubInfo {
                key_data_length: 128,
                protected: prot_full_hd,
                other: None,
            })
            .algorithm(alg)
            .build();
        let ctx = ctxb.to_vec()?;

        let secret = p256::ecdh::diffie_hellman(
            eph_key.to_nonzero_scalar(),
            recipient.public_key().as_affine(),
        );
        let hkdf = secret.extract::<sha2::Sha256>(None);
        let mut hkey = vec![0u8; 16];
        hkdf.expand(&ctx, &mut hkey).unwrap();

        // Use AES-KW to wrap the cek.
        let wr: KekAes128 = Kek::try_from(hkey.as_slice()).unwrap();
        let mut ceke = vec![0u8; 24];
        wr.wrap(&cek, &mut ceke).unwrap();

        // Build the recipient.
        let recip = CoseRecipientBuilder::new()
            .protected(prot_hd)
            .unprotected(unprot_hd)
            .ciphertext(ceke)
            .build();

        // Build the cose header (the above was the recipient header).
        let cose_prot_hd = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ECDH_ES_A128KW)
            .build();
        let cose_unprot_hd = HeaderBuilder::new().iv(kw_iv.to_vec()).build();

        // Build all of it.
        let packet = CoseEncryptBuilder::new()
            .add_recipient(recip)
            .protected(cose_prot_hd)
            .unprotected(cose_unprot_hd)
            .create_ciphertext(plaintext, &[], move |plain, aad| {
                let mut result = plain.to_vec();
                cipher.encrypt_in_place(nonce, aad, &mut result).unwrap();
                result
            })
            .build();

        // println!("Packet: {:#?}", packet);

        Ok(packet.to_vec()?)
    }

    /// Sign this payload, using our key.
    pub fn sign_cose(
        &self,
        payload: &[u8],
        session_id: &[u8],
        content_type: &str,
        rng: impl CryptoRng + RngCore,
    ) -> Result<Vec<u8>> {
        // This signing algorithm doesn't need an rng.
        let _ = rng;

        let prot = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .content_type(content_type.to_string())
            .value(-65537, Value::Bytes(session_id.to_vec()))
            .build();
        let unprot = HeaderBuilder::new()
            .key_id(self.key_id.clone().into_bytes())
            .build();

        let signer = SigningKey::from(self.secret_key().unwrap());

        let packet = CoseSign1Builder::new()
            .protected(prot)
            .unprotected(unprot)
            .payload(payload.to_vec())
            .create_signature(&[], |message| {
                println!("Sign");
                message.dump();
                let sig: Signature = signer.sign(message);
                sig.to_vec()
            })
            .build();
        // println!("cose sign: {:#?}", packet);

        Ok(packet.to_vec()?)
    }

    /// Verify the signature on a Cose1 packet, using the current public key.
    pub fn verify<'a>(&self, packet: &'a CoseSign1) -> Result<&'a [u8]> {
        packet.verify_signature(&[], |sig, data| {
            println!("Sig: {:?}", sig);
            println!("Sig is {} bytes", sig.len());
            println!("Data: {:?}", data);

            let r = GenericArray::clone_from_slice(&sig[0..32]);
            let s = GenericArray::clone_from_slice(&sig[32..64]);
            let sig = Signature::from_scalars(r, s)?;

            let pub_key = self.public_key();
            let vkey = VerifyingKey::from(&pub_key);
            vkey.verify(data, &sig)
        })?;
        Ok(packet.payload.as_ref().unwrap())
    }
}

// An AES key.
pub struct ContentKey {
    cipher: Aes128Gcm,
    secret_bytes: Vec<u8>,
}

impl ContentKey {
    pub fn from_slice(data: &[u8]) -> Result<ContentKey> {
        Ok(ContentKey {
            secret_bytes: data.to_vec(),
            cipher: Aes128Gcm::new_from_slice(data)?,
        })
    }

    /// Construct a new content key, with random contents.
    pub fn new(mut rng: impl CryptoRng + RngCore) -> Result<ContentKey> {
        let mut key = vec![0u8; 16];
        rng.fill_bytes(&mut key);
        let cipher = Aes128Gcm::new_from_slice(&key)?;
        Ok(ContentKey {
            secret_bytes: key,
            cipher,
        })
    }

    pub fn decrypt(&self, packet: &CoseEncrypt0) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(&packet.unprotected.iv);
        packet.decrypt(&[], |ciphertext, aad| {
            let mut result = ciphertext.to_vec();
            self.cipher
                .decrypt_in_place(nonce, aad, &mut result)
                .unwrap();
            Ok(result)
        })
    }

    pub fn encrypt(
        &self,
        plain: &[u8],
        session_id: &[u8],
        mut rng: impl CryptoRng + RngCore,
    ) -> Result<Vec<u8>> {
        let mut iv = vec![0u8; 12];
        rng.fill_bytes(&mut iv);
        let nonce = Nonce::from_slice(&iv);
        let packet = CoseEncrypt0Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(iana::Algorithm::A128GCM)
                    .value(-65537, Value::Bytes(session_id.to_vec()))
                    .build(),
            )
            .unprotected(HeaderBuilder::new().iv(iv.clone()).build())
            .create_ciphertext(plain, &[], |plaintext, aad| {
                let mut result = plaintext.to_vec();
                self.cipher
                    .encrypt_in_place(nonce, aad, &mut result)
                    .unwrap();
                result
            })
            .build();
        Ok(packet.to_vec()?)
    }

    // Extract the bytes of the private key from this AES key.
    pub fn bytes(&self) -> &[u8] {
        &self.secret_bytes
    }
}

/// Decode an example P-256 key into a private key.
fn decode_key(src: &BTreeMap<String, String>) -> Result<SecretKey> {
    match src.get("crv") {
        None => panic!("Unknown key type, no 'crv' field"),
        Some(crv) if crv == "P-256" => (),
        Some(crv) => panic!("Unsupported curve: {:?}", crv),
    }

    let d = match src.get("d") {
        Some(text) => text.as_str(),
        None => panic!("No 'd' field in key"),
    };

    // The private key is build from the 'd' value.
    let d = general_purpose::URL_SAFE_NO_PAD.decode(d)?;

    let d = SecretKey::from_be_bytes(&d)?;
    // println!("d: {:?}", d);
    // println!("pub: {:?}", d.public_key());
    // println!("pub: {:?}", d.public_key().to_projective().to_affine());

    // TODO: Construct a public key from the x and y and ensure that is the same
    // public key we get from this private key.

    // Decode the public key from the output, and make sure we get the same value.
    // let x = general_purpose::URL_SAFE_NO_PAD.decode(&src["x"])?;
    // let x: ScalarCore<NistP256> = ScalarCore::from_be_slice(&x)?;
    // let _ = x;
    // let x = x.to_be_bytes();
    // assert_eq!(x_src, x.as_slice());

    Ok(d)
}

/// Scan through a 'rest' map, for a given key, and return it if present.
pub fn cose_map_get<'a>(map: &'a [(Label, Value)], key: &Label) -> Option<&'a Value> {
    for (k, v) in map {
        if k == key {
            return Some(v);
        }
    }
    None
}

/// Scan through a cbor "map" to find a given key.
pub fn cbor_map_get<'a>(map: &'a [(Value, Value)], key: &Value) -> Option<&'a Value> {
    for (k, v) in map {
        if k == key {
            return Some(v);
        }
    }
    None
}

#[test]
fn randomkey() {
    let sender = Key::new(OsRng, "sender").unwrap();
    let recip_priv = Key::new(OsRng, "recipient").unwrap();
    println!("sender: {:?}", sender);

    let plain = b"This is some plaintext.";

    let cblock = sender.encrypt_cose(plain, &recip_priv, OsRng).unwrap();

    // Decode. This will eventually need to be tagged, but shouldn't be yet.
    let packet = CoseEncrypt::from_slice(&cblock).unwrap();
    let plain2 = recip_priv.decrypt_cose(&packet).unwrap();
    assert_eq!(&plain[..], plain2);
}

#[test]
fn randomsign() {
    let signer = Key::new(OsRng, "signer").unwrap();

    let message = b"This is a simple message";

    let signed = signer
        .sign_cose(message, b"test messageid", "content-type/x-testcase", OsRng)
        .unwrap();

    // Now verify this signature.
    let packet = CoseSign1::from_slice(&signed).unwrap();
    let message2 = signer.verify(&packet).unwrap();
    assert_eq!(message2, message);
}

#[test]
fn encrypt0() {
    let secret = ContentKey::new(OsRng).unwrap();
    let message = b"This is a simple message";

    let encd = secret.encrypt(message, b"Test messageid", OsRng).unwrap();
    // println!("Encd: {:?}", encd);

    // Decode the (untagged) packet.
    let packet = CoseEncrypt0::from_slice(&encd).unwrap();
    let message2 = secret.decrypt(&packet).unwrap();
    assert_eq!(message2, message);
}

/// CBOR packets can be tagged. However, the ciborium and coset libraries make
/// using these tags a little awkward, as they need to be added at a lower level
/// than available. The solution of either converting the entire to/from a Value
/// is wasteful of memory. Fortunately, CBOR is fairly simple, and we can just
/// add and check these tags ourselves. This module provides some helpful
/// functions to make this easier.
pub mod tagging {
    use std::io::Write;

    use crate::{errors::FlowError, Result};

    pub const TAG_SIGN: usize = 98;
    pub const TAG_SIGN1: usize = 18;
    pub const TAG_ENCRYPT: usize = 96;
    pub const TAG_ENCRYPT0: usize = 16;

    const CBOR_TYPE_MASK: u8 = 0xe0;
    const CBOR_TYPE_TAG: u8 = 6 << 5;
    const CBOR_SIZE_MASK: u8 = 0x1f;

    /// Decode the CBOR tag at the start of a message, retuning a slice of the
    /// rest of the packet, and the tag type. If this is not a CBOR tag, will
    /// return an Error.
    pub fn decode(buf: &[u8]) -> Result<(usize, &[u8])> {
        if buf.len() < 1 {
            return Err(FlowError::CoseError("No packet to look for tag"));
        }

        let first = buf[0];
        if (first & CBOR_TYPE_MASK) != CBOR_TYPE_TAG {
            return Err(FlowError::CoseError("Packet does not start with CBOR tag"));
        }

        match first & CBOR_SIZE_MASK {
            v @ 0..=23 => Ok((v as usize, &buf[1..])),
            24 => {
                if buf.len() < 2 {
                    Err(FlowError::CoseError("Tag present, but insufficient data"))
                } else {
                    Ok((buf[1] as usize, &buf[2..]))
                }
            }
            _ => unimplemented!(),
        }
    }

    /// Add an encoded tag to the given writer.
    pub fn encode<W: Write>(writer: &mut W, tag: usize) -> Result<()> {
        match tag {
            tag @ 0..=23 => {
                let buf = [CBOR_TYPE_TAG | (tag as u8)];
                writer.write_all(&buf)?;
            }
            tag @ 24..=255 => {
                let buf = [CBOR_TYPE_TAG | 24, tag as u8];
                writer.write_all(&buf)?;
            }
            _ => unimplemented!(),
        }
        Ok(())
    }

    #[test]
    fn tagging() {
        struct Case {
            tag: usize,
            length: usize,
        }
        static CASES: [Case; 4] = [
            Case {
                tag: TAG_ENCRYPT,
                length: 2,
            },
            Case {
                tag: TAG_ENCRYPT0,
                length: 1,
            },
            Case {
                tag: TAG_SIGN,
                length: 2,
            },
            Case {
                tag: TAG_SIGN1,
                length: 1,
            },
        ];
        let mut buffer = Vec::new();

        for case in &CASES {
            buffer.clear();
            encode(&mut buffer, case.tag).unwrap();
            assert_eq!(buffer.len(), case.length);
            let (tag, rest) = decode(&buffer).unwrap();
            assert_eq!(tag, case.tag);
            assert!(rest.is_empty());
        }
    }
}
