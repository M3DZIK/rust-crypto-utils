//! [![github]](https://github.com/MedzikUser/rust-crypto-utils)
//! [![crates-io]](https://crates.io/crates/crypto-utils)
//! [![docs-rs]](https://docs.rs/crypto-utils)
//! [![ci]](https://github.com/MedzikUser/rust-crypto-utils/actions/workflows/rust.yml)
//!
//! [github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//! [ci]: https://img.shields.io/github/workflow/status/MedzikUser/rust-crypto-utils/Rust/main?style=for-the-badge&logo=github
//!
//! Cryptography Utils for Rust
//!
//! ## Importing
//! The driver is available on [crates-io](https://crates.io/crates/crypto-utils). To use the driver in
//! your application, simply add it to your project's `Cargo.toml`.
//!
//! ```toml
//! [dependencies]
//! crypto-utils = "0.4.0"
//! ```
//!
//! ## How to use?
//!
//! Check [jsonwebtoken] and [sha] module
//!
//! ## All Feature flags
//!
//! | Feature  | Description                                                 | Dependencies                            | Default |
//! |:---------|:------------------------------------------------------------|:----------------------------------------|:--------|
//! | `sha`    | Enable support for the Sha1, Sha256 and Sha512 hasher       | `sha` and `sha2`                        | yes     |
//! | `jwt`    | Enable support for the Json Web Token utils                 | `chrono`, `serde` and `jsonwebtoken`    | yes     |

#![warn(missing_docs)]

#[cfg(feature = "jwt")]
pub mod jsonwebtoken;
#[cfg(feature = "sha")]
pub mod sha;
