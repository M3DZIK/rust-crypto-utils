//! Module for creating sha1, sha256 and sha512 hashes.
//!
//! ```no_run
//! use crypto_utils::sha::{Algorithm, CryptographicHash};
//!
//! // sha1
//! CryptographicHash::hash(Algorithm::SHA1, b"P@ssw0rd");
//!
//! // sha256
//! CryptographicHash::hash(Algorithm::SHA256, b"P@ssw0rd");
//!
//! // sha512
//! CryptographicHash::hash(Algorithm::SHA512, b"P@ssw0rd");
//! ```

mod mac;
#[allow(clippy::module_inception)]
mod sha;

pub use mac::*;
pub use sha::*;
