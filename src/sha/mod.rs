//! Module for creating sha1, sha256 and sha512 hashes.
//!
//! ## Sha
//!
//! Example of computing a sha1, sha256 and sha512 hashes:
//!
//! ```no_run
//! use crypto_utils::sha::{Algorithm, CryptographicHash};
//!
//! // Sha1
//! let hash: Vec<u8> = CryptographicHash::hash(Algorithm::SHA1, b"input");
//!
//! // Sha256
//! let hash: Vec<u8> = CryptographicHash::hash(Algorithm::SHA256, b"input");
//!
//! // Sha512
//! let hash: Vec<u8> = CryptographicHash::hash(Algorithm::SHA512, b"input");
//! ```
//!
//! ## HMAC-Sha
//!
//! Read about HMAC in [wikipedia](https://en.wikipedia.org/wiki/HMAC)
//!
//! Example of computing a HMAC hashes (sha1, sha256 and sha512):
//!
//! ```no_run
//! use crypto_utils::sha::{AlgorithmMac, CryptographicMac};
//!
//! // secret value
//! const SECRET: &[u8] = b"secret";
//!
//! // HMAC Sha1
//! let hash: Vec<u8> = CryptographicMac::hash(AlgorithmMac::HmacSHA1, SECRET, b"input").unwrap();
//!
//! // HMAC Sha256
//! let hash: Vec<u8> = CryptographicMac::hash(AlgorithmMac::HmacSHA256, SECRET, b"input").unwrap();
//!
//! // HMAC Sha512
//! let hash: Vec<u8> = CryptographicMac::hash(AlgorithmMac::HmacSHA512, SECRET, b"input").unwrap();
//! ```

mod error;
mod mac;
#[allow(clippy::module_inception)]
mod sha;

pub use error::*;
pub use mac::*;
pub use sha::*;
