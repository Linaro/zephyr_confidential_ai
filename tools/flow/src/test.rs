//! COSE flow tests
//!
//! These tests use the sample data from the cose examples repo to ensure that we are producing
//! valid COSE packets.

use crate::keys::Key;
use crate::data::Example;

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
    if packet.len() < 3 || packet[0] != 0xd8 || packet[1] != 0x60 {
        panic!("CBOR packet is not properly tagged as COSE_Encrypt");
    }
    let packet = &packet[2..];
    let packet = coset::CoseEncrypt::from_slice(packet).expect("Decoding cbor");

    let plain = secret.decrypt_cose(&packet).expect("Unable to decrypt");

    // println!("Plain: {:?}", plain);
    assert_eq!(&plain, ex.input.plaintext.as_bytes());
}
