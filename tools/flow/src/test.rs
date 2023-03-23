//! COSE flow tests
//!
//! These tests use the sample data from the cose examples repo to ensure that we are producing
//! valid COSE packets.

use crate::data::Example;
use crate::keys::{tagging, ContentKey, Key};

use base64::{engine::general_purpose, Engine};
use coset::CborSerializable;

#[test]
fn check_ecdh_wrap() {
    let ex = Example::from_json_file("cose-examples/ecdh-wrap-examples/p256-wrap-128-01.json")
        .expect("Opening example file");

    let secret = Key::from_example(&ex).expect("Extract keypair from example");

    // Extract the CBOR payload from the example. This is tagged, so make sure
    // we see the right tag.
    // TODO: Try to do this using the cbor library directly, but for now, just check the bytes.
    let packet = &ex.output.cbor;
    let (tag, packet) = tagging::decode(packet).unwrap();
    if tag != tagging::TAG_ENCRYPT {
        panic!("CBOR packet is not properly tagged as COSE_Encrypt");
    }
    let packet = coset::CoseEncrypt::from_slice(packet).expect("Decoding cbor");

    let plain = secret.decrypt_cose(&packet).expect("Unable to decrypt");

    // println!("Plain: {:?}", plain);
    assert_eq!(&plain, ex.input.plaintext.as_bytes());
}

#[test]
fn check_ecdsa() {
    let ex = Example::from_json_file("cose-examples/ecdsa-examples/ecdsa-sig-01.json")
        .expect("Opening example file");
    // println!("Value: {:#?}", ex);

    let secret = Key::from_example(&ex).expect("Extract keypair from example");
    println!("Secret: {:?}", secret);

    // Extract the CBOR payload from the example. This is tagged, so make sure
    // we see the right tag.
    //
    // TODO: Try to do this using the cbor library directly, but for now, just
    // check the bytes.
    let packet = &ex.output.cbor;
    let (tag, packet) = tagging::decode(packet).unwrap();
    if tag != tagging::TAG_SIGN1 {
        panic!("CBOR packet is not properly tagged as COSE_Sign1");
    }
    let packet = coset::CoseSign1::from_slice(packet).expect("Decoding cbor");
    // println!("Packet: {:#?}", packet);

    secret.verify(&packet).unwrap();
}

#[test]
fn check_encrypt0() {
    let ex = Example::from_json_file("cose-examples/aes-gcm-examples/aes-gcm-enc-01.json")
        .expect("Opening example file");
    // println!("Value: {:#?}", ex);

    let recip = &ex.get_keys()[0];
    let key = match recip.get("k") {
        None => panic!("No decryption key present in encrypt0 example"),
        Some(text) => general_purpose::URL_SAFE_NO_PAD.decode(text).unwrap(),
    };
    let secret = ContentKey::from_slice(&key).unwrap();

    // TODO: Try to do this using the cbor library directly, but for now, just
    // check the bytes.
    let packet = &ex.output.cbor;
    let (tag, packet) = tagging::decode(packet).unwrap();
    if tag != tagging::TAG_ENCRYPT0 {
        panic!("CBOR packet is not properly tagged as COSE_Encrypt0");
    }
    let packet = coset::CoseEncrypt0::from_slice(packet).expect("Decoding cbor");
    // println!("Packet: {:#?}", packet);

    let plain2 = secret.decrypt(&packet).unwrap();
    // println!("Plaintext: {:?}", plain2);
    assert_eq!(ex.input.plaintext.as_bytes(), &plain2);
}
