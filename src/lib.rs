//! Cryptography Utils for Rust
//!
//! ## Importing
//! The driver is available on [crates.io](https://crates.io/crates/crypto-utils). To use the driver in
//! your application, simply add it to your project's `Cargo.toml`.
//!
//! ```toml
//! [dependencies]
//! crypto-utils = "0.1.0"
//! ```
//!
//! ## How to use?
//!
//! ### Compute a Sha hash
//!
//! Add `sha` features (is enabled by default)
//!
//! ```toml
//! [dependencies]
//! crypto-utils = { version = "...", features = ["sha"] }
//! ```
//!
//! Quick and easy Sha1, Sha256 and Sha512 hash computing.
//!
//! ```
//! use crypto_utils::sha::{Algorithm, CryptographicHash};
//!
//! // input data for a hasher
//! let input = "P@ssw0rd"; // &str
//!
//! // compute hash
//! let hash_bytes = CryptographicHash::hash(Algorithm::SHA1, input.as_bytes()); // Vec<u8>
//!
//! // decode hash to a String
//! let hash = hex::encode(hash_bytes); // String
//!
//! assert_eq!(hash, "21bd12dc183f740ee76f27b78eb39c8ad972a757".to_string())
//! ```

#[cfg(feature = "sha")]
pub mod sha;
