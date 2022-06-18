# crypto-utils

[![github]](https://github.com/MedzikUser/rust-crypto-utils)
[![crates-io]](https://crates.io/crates/crypto-utils)
[![docs-rs]](https://docs.rs/crypto-utils)
[![ci]](https://github.com/MedzikUser/rust-crypto-utils/actions/workflows/rust.yml)

[github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
[crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
[docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
[ci]: https://img.shields.io/github/workflow/status/MedzikUser/rust-crypto-utils/Rust/main?style=for-the-badge&logo=github

Cryptography Utils for Rust

### Importing
The driver is available on [crates-io](https://crates.io/crates/crypto-utils). To use the driver in
your application, simply add it to your project's `Cargo.toml`.

```toml
[dependencies]
crypto-utils = "0.2.1"
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

#### Json Web Token

Add `jwt` features (is enabled by default)

```toml
[dependencies]
crypto-utils = { version = "...", features = ["jwt"] }
```

Create and decode a token

```rust
use crypto_utils::jsonwebtoken::{Claims, Token};

let secret = b"secret";
let user_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

// create claims
let claims = Claims::new(user_id, 24);

// create token
let token = Token::new(secret, claims).unwrap();

// decode token
let decoded = Token::decode(secret, token.encoded).unwrap();
```

### All Feature flags

| Feature    | Description                                                   | Dependencies                              | Default |
|:-----------|:-------------------------------------------------------------|:-------------------------------------------|:--------|
| `sha`      | Enable support for the Sha1, Sha256 and Sha512 hasher         | `sha` and `sha2`                          | yes     |
| `jwt`      | Enable support for the Json Web Token utils                   | `chrono`, `serde` and `jsonwebtoken`      | yes     |

License: MIT
