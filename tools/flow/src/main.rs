//! Flow demo app.

use std::{fs::File, io::Write, path::Path};

use clap::{Parser, Subcommand};
use coset::{CborSerializable, CoseEncrypt, CoseEncrypt0, CoseSign1};
use keys::{tagging, ContentKey, Key};
// use pdump::HexDump;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::errors::FlowError;

#[cfg(test)]
mod test;

mod data;
mod errors;
mod keys;
mod pdump;

type Result<T> = std::result::Result<T, errors::FlowError>;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    name: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new session.
    NewSession {
        /// Device key to use, should be the name of a .crt file. Will look for
        /// a file with the same basename, and .key or .pk8 for the private key.
        #[arg(short, long)]
        device_key: String,

        /// Service certificate to send the message to. Should be the name of a
        /// .crt file.
        #[arg(short = 'c', long)]
        service_cert: String,

        /// File to store the session state in.
        #[arg(short, long)]
        state: String,

        /// File to write the session packet.
        #[arg(short, long)]
        output: String,
    },

    /// Encrypt.  Sign an encrypt a payload using a given session file.
    Encrypt {
        /// File to read the payload from. This is arbitrary data.
        #[arg(short, long)]
        input: String,

        /// File to write the generated message to.
        #[arg(short, long)]
        output: String,

        /// File containing the session state (previously written by new-session).
        #[arg(short, long)]
        state: String,
    },

    /// Decrypt a packet using the session information, and the data file.
    Decrypt {
        /// File containing the encrypted payload.
        #[arg(short, long)]
        input: String,

        /// File to write the plaintext to.
        #[arg(short, long)]
        output: String,

        /// File containing the session file written by the new-session command.
        #[arg(short, long)]
        session: String,

        /// File containing the device cert.
        #[arg(short, long)]
        device_cert: String,

        /// Certificate and key file for the service.
        #[arg(short = 'c', long)]
        service_cert: String,
    },

    /// A simple encrypt of a piece of payload.
    SimpleEncrypt {
        /// File to read the payload from. This is arbitrary data.
        #[arg(short, long)]
        input: String,

        /// File to write the generated message to.
        #[arg(short, long)]
        output: String,

        /// Device key to use, should be the name of a .crt file. Will look for
        /// a file with the same basename, and .key or .pk8 for the private key.
        #[arg(short, long)]
        device_key: String,

        /// Service certificate to send the message to. Should be the name of a
        /// .crt file.
        #[arg(short = 'c', long)]
        service_cert: String,
    },

    /// Decrypt a packet encoded with SimpleEncrypt.
    SimpleDecrypt {
        /// File containing the encrypted payload.
        #[arg(short, long)]
        input: String,

        /// File to write the plaintext to.
        #[arg(short, long)]
        output: String,

        /// File containing the device cert.
        #[arg(short, long)]
        device_cert: String,

        /// Certificate and key file for the service.
        #[arg(short = 'c', long)]
        service_cert: String,
    },
}

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    if let Some(name) = cli.name.as_deref() {
        println!("Value for name: {}", name);
    }

    match &cli.command {
        Some(Commands::NewSession {
            device_key,
            service_cert,
            state,
            output,
        }) => {
            println!(
                "dk {:?}, service {:?}, state {:?}, out {:?}",
                device_key, service_cert, state, output
            );
            new_session(device_key, service_cert, state, output)
        }
        Some(Commands::Encrypt {
            input,
            output,
            state,
        }) => encrypt(input, output, state),
        Some(Commands::Decrypt {
            input,
            output,
            session,
            device_cert,
            service_cert,
        }) => decrypt(input, output, session, device_cert, service_cert),
        Some(Commands::SimpleEncrypt {
            input,
            output,
            device_key,
            service_cert,
        }) => simple_encrypt(device_key, service_cert, input, output),
        Some(Commands::SimpleDecrypt {
            input,
            output,
            device_cert,
            service_cert,
        }) => simple_decrypt(input, output, device_cert, service_cert),
        None => {
            println!("Specify subcommand.  'help' to get list of commands");
            Ok(())
        }
    }
}

/// Create a new session.
fn new_session(
    device_key: &str,
    service_cert: &str,
    state_path: &str,
    output_path: &str,
) -> Result<()> {
    // From the service certificate file, we can load a public key (and associated key-id).
    let service = Key::from_cert_file(service_cert, false)?;
    let device = Key::from_cert_file(device_key, true)?;

    // Generate a session key, this should be a 16-byte AES key.
    let session = ContentKey::new(OsRng)?;

    // Generate a session ID.
    let mut session_id = vec![0u8; 16];
    OsRng.fill_bytes(&mut session_id);

    // Make the encrypt0 packet for the service containing this session key.
    let enc = device.encrypt_cose(session.bytes(), &service, OsRng)?;

    // Then wrap this with COSE_Sign1 for our integrity.
    let signed = device.sign_cose(
        &enc,
        &session_id,
        "application/x-linaro-secureai-session",
        OsRng,
    )?;

    // signed.dump();

    // Write the secret key to a state file. This will need to be encoded in
    // some manner, so we might as well use a COSE encoding, but just use Serde
    // to make it automatic.
    let state = SessionState {
        secret: session.bytes().to_vec(),
        session_id: session_id,
    };
    let stfile = File::options()
        .write(true)
        .create_new(true)
        .open(state_path)?;
    ciborium::ser::into_writer(&state, stfile)?;

    // Write the initial message to a file.
    // TODO: if this fails, it might make sense to delete the session file.
    let mut outfile = File::options()
        .write(true)
        .create_new(true)
        .open(output_path)?;
    tagging::encode(&mut outfile, tagging::TAG_SIGN1)?;
    outfile.write_all(&signed)?;

    Ok(())
}

/// Just sign/encrypt a single packet of data.
fn simple_encrypt(
    device_key: &str,
    service_cert: &str,
    input_path: &str,
    output_path: &str,
) -> Result<()> {
    let service = Key::from_cert_file(service_cert, false)?;
    let device = Key::from_cert_file(device_key, true)?;

    let plaintext = std::fs::read(input_path)?;

    // Make the encrypt0 packet containing the payload.
    let enc = device.encrypt_cose(&plaintext, &service, OsRng)?;

    // Wrap this with COSE_Sign1 for our integrity.
    let signed = device.sign_cose(
        &enc,
        b"single",
        "application/x-linaro-secureai-single",
        OsRng,
    )?;

    let mut outfile = File::options()
        .write(true)
        .create_new(true)
        .open(output_path)?;
    tagging::encode(&mut outfile, tagging::TAG_SIGN1)?;
    outfile.write_all(&signed)?;

    Ok(())
}

/// Encrypt payload.
fn encrypt(input: &str, output: &str, state_path: &str) -> Result<()> {
    let state = SessionState::load(state_path)?;
    println!("state: {:?}", state);

    let payload = std::fs::read(input)?;

    let key = state.content_key()?;

    let encd = key.encrypt(&payload, &state.session_id, OsRng)?;
    let mut outfile = File::options().write(true).create_new(true).open(output)?;
    tagging::encode(&mut outfile, tagging::TAG_ENCRYPT0)?;
    outfile.write_all(&encd)?;

    Ok(())
}

/// Decrypt payload.
fn decrypt(
    input: &str,
    output: &str,
    session_path: &str,
    device_path: &str,
    service_cert: &str,
) -> Result<()> {
    let service = Key::from_cert_file(service_cert, true)?;
    let device = Key::from_cert_file(device_path, false)?;

    // Read the session file, which should be a signed message wraping the
    // encrypted payload. TODO: Make these tagged.
    let sess = std::fs::read(session_path)?;
    let (tag, sess) = tagging::decode(&sess)?;
    if tag != tagging::TAG_SIGN1 {
        return Err(FlowError::IncorrectTag("COSE_Sign1"));
    }
    let packet = CoseSign1::from_slice(&sess)?;

    device.verify(&packet)?;

    // Get the session ID from this packet.
    let session_session_id =
        keys::cose_map_get(&packet.protected.header.rest, &coset::Label::Int(-65537))
            .expect("Packet should have a session_id header.");

    // The encrypted data is within this.
    let sess = packet.payload.as_ref().unwrap();
    let packet = CoseEncrypt::from_slice(&sess)?;

    let secret = service.decrypt_cose(&packet)?;
    println!("Secret {:?}", secret);
    let secret = ContentKey::from_slice(&secret)?;

    let ctext = std::fs::read(input)?;
    let (tag, ctext) = tagging::decode(&ctext)?;
    if tag != tagging::TAG_ENCRYPT0 {
        return Err(FlowError::IncorrectTag("COSE_Encrypt0"));
    }
    let ppacket = CoseEncrypt0::from_slice(&ctext)?;

    // Get the session id from the payload and make sure it matches the session packet.
    let packet_session_id =
        keys::cose_map_get(&ppacket.protected.header.rest, &coset::Label::Int(-65537))
            .expect("Encrypted payload should have a session_id header");

    if session_session_id != packet_session_id {
        return Err(errors::FlowError::SessionMismatch);
    }

    let plain = secret.decrypt(&ppacket)?;

    let mut outfile = File::options().write(true).create_new(true).open(output)?;
    outfile.write_all(&plain)?;

    Ok(())
}

/// Decrypt a simply-encrypted packet.
fn simple_decrypt(input: &str, output: &str, device_path: &str, service_cert: &str) -> Result<()> {
    let service = Key::from_cert_file(service_cert, true)?;
    let device = Key::from_cert_file(device_path, false)?;

    let outer = std::fs::read(input)?;
    let (tag, outer) = tagging::decode(&outer)?;
    if tag != tagging::TAG_SIGN1 {
        return Err(FlowError::IncorrectTag("COSE_Sign1"));
    }
    let packet = CoseSign1::from_slice(&outer)?;

    device.verify(&packet)?;

    // The encrypted data is within this.
    let inner = packet.payload.as_ref().unwrap();
    let packet = CoseEncrypt::from_slice(&inner)?;

    let plain = service.decrypt_cose(&packet)?;

    let mut outfile = File::options().write(true).create_new(true).open(output)?;
    outfile.write_all(&plain)?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionState {
    secret: Vec<u8>,
    session_id: Vec<u8>,
}

impl SessionState {
    pub fn load(path: impl AsRef<Path>) -> Result<SessionState> {
        let stfile = File::open(path)?;
        Ok(ciborium::de::from_reader(stfile)?)
    }

    pub fn content_key(&self) -> Result<ContentKey> {
        ContentKey::from_slice(&self.secret)
    }
}

mod config {
    use super::Result;
    use std::path::PathBuf;
    use temp_dir::TempDir;

    /// Config provides various path and other values. It is a trait to make it plugable, say to
    /// allow unit testing to work in a temp dir.
    pub trait Config {
        fn base(&self) -> PathBuf;

        // Default implementations that just buLd off of the base.

        /// Directory for storing certificates.
        fn cert_dir(&self) -> PathBuf {
            self.base()
        }

        /// Directory for storing device keys.
        fn key_dir(&self) -> PathBuf {
            self.base()
        }

        /// Pathname for the CA key file.
        fn ca_key(&self) -> PathBuf {
            let mut dir = self.cert_dir();
            dir.push("CA.key");
            dir
        }
    }

    /// Config handler that has hard-coded paths from the current directory.
    pub struct HardCodedConfig;

    impl Config for HardCodedConfig {
        fn base(&self) -> PathBuf {
            PathBuf::from("certs")
        }
    }

    /// Config handler that uses a temporary directory that will be cleaned up when dropped.
    pub struct TempDirConfig(TempDir);

    impl TempDirConfig {
        #[allow(dead_code)]
        pub fn new() -> Result<TempDirConfig> {
            Ok(TempDirConfig(TempDir::new()?))
        }
    }

    impl Config for TempDirConfig {
        fn base(&self) -> PathBuf {
            self.0.child("certs")
        }
    }
}

// Key generation.
// mod boguskeys {
//     use super::{
//         config::Config,
//         Result
//     };
//     use ring::{
//         pkcs8,
//         rand::SecureRandom,
//         signature::{
//             EcdsaKeyPair,
//             ECDSA_P256_SHA256_ASN1_SIGNING,
//         },
//     };
//     use std::{
//         fs::File,
//         io::{Read, Write},
//     };

//     pub struct Cert {
//         kp: EcdsaKeyPair,
//         kp8: Vec<u8>,
//     }

//     impl Cert {
//         /// Generate a new private key and certificate.
//         pub fn new(rng: &dyn SecureRandom) -> Result<Cert> {
//             // TODO: figure out how to deal with the error from ring. The docs say it's error type
//             // does implement Error, but I am not able to convert the error, with an error message
//             // that it doesn't implement Error.
//             let kp8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING,
//                 rng).unwrap();
//             let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, kp8.as_ref()).unwrap();
//             log::error!("Key: {:?}", kp);
//             Ok(Cert { kp, kp8: kp8.as_ref().to_owned() })
//         }

//         /// Load the keys from the saved file.
//         pub fn load(conf: &dyn Config) -> Result<Cert> {
//             let mut file = File::open(&conf.ca_key())?;
//             let mut kp8 = Vec::new();
//             file.read_to_end(&mut kp8)?;
//             let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &kp8).unwrap();
//             Ok(Cert { kp, kp8 })
//         }

//         /// Save the keypair and such.
//         pub fn save(&self, conf: &dyn Config) -> Result<()> {
//             let mut file = File::create(&conf.ca_key())?;
//             file.write_all(self.kp8.as_ref())?;
//             Ok(())
//         }
//     }

//     #[test]
//     fn test_save_load() {
//         use ring::rand::SystemRandom;
//         use crate::config::TempDirConfig;
//         use std::fs;

//         let rng = SystemRandom::new();
//         let conf = TempDirConfig::new().unwrap();

//         // Need to make the working directory.
//         fs::create_dir(conf.cert_dir()).unwrap();

//         let crt = Cert::new(&rng).unwrap();
//         crt.save(&conf).unwrap();
//         let crt2 = Cert::load(&conf).unwrap();

//         // The keys aren't directly comparable, but we can compare the pkcs8 version.
//         assert!(crt.kp8 == crt2.kp8);
//     }
// }
