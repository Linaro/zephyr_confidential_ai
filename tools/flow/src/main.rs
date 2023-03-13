//! Flow demo app.

use std::{fs::File, io::Write};

use clap::{Parser, Subcommand};
use keys::{Key, ContentKey};
use pdump::HexDump;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
// use log::error;
// use ring::rand::SystemRandom;
// use std::fs;
// use crate::config::Config;

#[cfg(test)]
mod test;

mod data;
mod keys;
mod pdump;

type Result<T> = anyhow::Result<T>;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    name: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// does testing things
    Test {
        /// lists test values
        #[arg(short, long)]
        list: bool,
    },

    /// Generate keys to use
    Gen,

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
}

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    if let Some(name) = cli.name.as_deref() {
        println!("Value for name: {}", name);
    }

    match &cli.command {
        Some(Commands::Test { list }) => {
            if *list {
                println!("Printing testing lists...");
            } else {
                println!("Not printing testing lists...");
            }
            Ok(())
        }
        Some(Commands::Gen) => gen(),
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
        None => {
            println!("Specify subcommand.  'help' to get list of commands");
            Ok(())
        }
    }
}

/// Generate a new set of keys.
fn gen() -> Result<()> {
    unimplemented!()
    // let conf = config::HardCodedConfig;

    // let certdir = conf.cert_dir();
    // if certdir.exists() {
    // error!("key directory {:?} alread exists, remove to create new", certdir);
    // return Err(anyhow!("Command error"));
    // }
    // fs::create_dir(&certdir)?;

    // let rng = SystemRandom::new();
    // let cert = keys::Cert::new(&rng)?;
    // cert.save(&conf)?;
    // Ok(())
}

/// Create a new session.
fn new_session(device_key: &str, service_cert: &str, state_path: &str, output_path: &str) -> Result<()> {
    // From the service certificate file, we can load a public key (and associated key-id).
    let service = Key::from_cert_file(service_cert)?;
    let device = Key::from_cert_file(device_key)?;

    // Generate a session key, this should be a 16-byte AES key.
    let session = ContentKey::new(OsRng)?;

    // Make the encrypt0 packet for the service containing this session key.
    let enc = device.encrypt_cose(session.bytes(), &service.public_key(), OsRng)?;

    // Then wrap this with COSE_Sign1 for our integrity.
    let signed = device.sign_cose(&enc, OsRng)?;

    signed.dump();

    // Write the secret key to a state file. This will need to be encoded in
    // some manner, so we might as well use a COSE encoding, but just use Serde
    // to make it automatic.
    let state = SessionState {
        secret: session.bytes().to_vec(),
        session_id: "session id placeholder".to_string(),
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
    outfile.write_all(&signed)?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionState {
    secret: Vec<u8>,
    session_id: String,
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
