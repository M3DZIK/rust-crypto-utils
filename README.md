# crypto-utils

[![github]](https://github.com/MedzikUser/rust-crypto-utils)
[![crates-io]](https://crates.io/crates/crypto-utils )
[![docs-rs]](https://docs.rs/crypto-utils )
[![CI]](https://github.com/MedzikUser/rust-crypto-utils/actions/workflows/rust.yml )

[github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
[crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
[docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
[CI]: https://img.shields.io/github/workflow/status/MedzikUser/rust-crypto-utils/Rust/main?style=for-the-badge

Cryptography Utils for Rust

### Importing
The driver is available on [crates-io]. To use the driver in
your application, simply add it to your project's `Cargo.toml`.

```toml
[dependencies]
crypto-utils = "0.1.0"
```

### How to use?

#### Compute a Sha hash

Add `sha` features (is enabled by default)

```toml
[dependencies]
crypto-utils = { version = "...", features = ["sha"] }
```

Quick and easy Sha1, Sha256 and Sha512 hash computing.

```rust
use crypto_utils::sha::{Algorithm, CryptographicHash};

// input data for a hasher
let input = "P@ssw0rd"; // &str

// compute hash
let hash_bytes = CryptographicHash::hash(Algorithm::SHA1, input.as_bytes()); // Vec<u8>

// decode hash to a String
let hash = hex::encode(hash_bytes); // String

assert_eq!(hash, "21bd12dc183f740ee76f27b78eb39c8ad972a757".to_string())
```

License: MIT
