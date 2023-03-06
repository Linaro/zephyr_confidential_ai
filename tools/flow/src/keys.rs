//! Key management

use std::collections::BTreeMap;

use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit, Nonce};
use aes_kw::{Kek, KekAes128};
use anyhow::anyhow;
use base64::{engine::general_purpose, Engine};
use coset::{
    cbor::value::Value, iana, CborSerializable, CoseEncrypt, CoseEncryptBuilder,
    CoseKdfContextBuilder, CoseRecipientBuilder, Header, HeaderBuilder, Label, ProtectedHeader,
    RegisteredLabelWithPrivate, SuppPubInfo,
};
use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use rand_core::{CryptoRng, OsRng, RngCore};

use crate::{data::Example, Result};

/// Internal representation of a keypair. This can come from a certificate and
/// private key file, or can be extracted out of one of the example files.
#[derive(Debug)]
pub struct Key {
    secret: SecretKey,
}

impl Key {
    pub fn from_example(example: &Example) -> Result<Key> {
        let secret = decode_key(example.get_keys()[0])?;
        Ok(Key { secret })
    }

    /// Construct a fresh keypair, randomly.
    pub fn new(rng: impl CryptoRng + RngCore) -> Result<Key> {
        Ok(Key {
            secret: SecretKey::random(rng),
        })
    }

    /// Retrieve the public key associated with this Key.
    pub fn public_key(&self) -> PublicKey {
        self.secret.public_key()
    }

    /// Decrypt a COSE_Encrypt packet that uses this particular key.
    pub fn decrypt_cose(&self, packet: &coset::CoseEncrypt) -> Result<Vec<u8>> {
        // For now, we only support a single recipient. Later, we can search
        // through the recipients to find the one that matches our current key.
        let recipient = match packet.recipients.as_slice() {
            [] => return Err(anyhow!("No recipients")),
            [single] => single,
            _ => return Err(anyhow!("Multiple recipients not yet supported")),
        };

        // Ensure that the correct algorithm is encoded.
        match recipient.protected.header.alg {
            Some(coset::RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ECDH_ES_A128KW)) => {
                ()
            }
            _ => return Err(anyhow!("Unsupported algorithm in COSE packet")),
        }

        // The key ID of the sender is represented in the unprotected header.
        // TODO: actually compare this with the intended key id.
        let key_id = String::from_utf8_lossy(&recipient.unprotected.key_id).into_owned();
        println!("key id: {:?}", key_id);

        // Get the info about the key, for the most part, this match just match
        // specific values.
        let info = match cose_map_get(&recipient.unprotected.rest, &Label::Int(-1)) {
            None => return Err(anyhow!("No info entry -1 in recipient unprotected header")),
            Some(m) => m,
        };
        let info = info
            .as_map()
            .expect("Unexpected type of 'rest' field in map");

        // The key type must be a 2, for "EC2".
        match cbor_map_get(info, &Value::Integer(From::from(1i32))) {
            Some(v) if v == &Value::Integer(From::from(2i32)) => (),
            _ => return Err(anyhow!("Expecting key to be EC2")),
        }

        // The curve must be P-256.
        match cbor_map_get(info, &Value::Integer(From::from(-1i32))) {
            Some(v) if v == &Value::Integer(From::from(1i32)) => (),
            _ => return Err(anyhow!("Expecting curve to be P-256")),
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

        let eph_pub = PublicKey::from_sec1_bytes(&sec1).unwrap();

        // The algorithm for the context comes from the algorithm wrappin5 data,
        // but isn't the same, as it is only the keywrap algorithm.
        let alg = match recipient.protected.header.alg.as_ref() {
            Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ECDH_ES_A128KW)) => {
                iana::Algorithm::A128KW
            }
            alg => return Err(anyhow!("Unexpected key wrap algorithm: {:?}", alg)),
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
        let ctx = ctxb.to_vec().unwrap();

        let secret =
            p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), eph_pub.as_affine());
        let hkdf = secret.extract::<sha2::Sha256>(None);
        let mut hkey = vec![0u8; 16];
        hkdf.expand(&ctx, &mut hkey).unwrap();

        // Use AES-KW to unwrap the key.
        let unwr: KekAes128 = Kek::try_from(hkey.as_slice()).unwrap();
        let mut cek = vec![0u8; 16];
        unwr.unwrap(recipient.ciphertext.as_ref().unwrap().as_slice(), &mut cek)
            .unwrap();

        // Use this key to build the aead handler for this.
        let cipher = Aes128Gcm::new_from_slice(&cek).unwrap();
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
        recipient: &PublicKey,
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
            .key_id(b"TODO use real key ID".to_vec())
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
        let cipher = Aes128Gcm::new_from_slice(&cek).unwrap();
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
        let ctx = ctxb.to_vec().unwrap();

        let secret = p256::ecdh::diffie_hellman(eph_key.to_nonzero_scalar(), recipient.as_affine());
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

        Ok(packet.to_vec().unwrap())
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
    let sender = Key::new(OsRng).unwrap();
    let recip_priv = Key::new(OsRng).unwrap();
    let recip_pub = recip_priv.public_key();
    println!("sender: {:?}", sender);
    println!("recip: {:?}", recip_pub);

    let plain = b"This is some plaintext.";

    let cblock = sender.encrypt_cose(plain, &recip_pub, OsRng).unwrap();

    // Decode. This will eventually need to be tagged, but shouldn't be yet.
    let packet = CoseEncrypt::from_slice(&cblock).unwrap();
    let plain2 = recip_priv.decrypt_cose(&packet).unwrap();
    assert_eq!(&plain[..], plain2);
}
