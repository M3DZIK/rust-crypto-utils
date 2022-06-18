//! Module for creating sha1, sha256 and sha512 hashes.
//!
//! **Required `sha` feature!**
//!
//! Examples:
//! ```
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

use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha512};

/// Hashing algorithms
#[derive(Debug)]
pub enum Algorithm {
    /// [SHA-1](https://en.wikipedia.org/wiki/SHA-1)
    SHA1,
    /// [SHA-256](https://en.wikipedia.org/wiki/SHA-2)
    SHA256,
    /// [SHA-512](https://en.wikipedia.org/wiki/SHA-2)
    SHA512,
}

/// Compute cryptographic hash from bytes (sha1, sha256, sha512).
///
/// Method 1
/// ```
/// use crypto_utils::sha::{Algorithm, CryptographicHash};
///
/// // compute hash
/// let hash_bytes = CryptographicHash::hash(Algorithm::SHA1, b"P@ssw0rd");
///
/// // decode hash to a String
/// let hash = hex::encode(hash_bytes);
///
/// assert_eq!(hash, "21bd12dc183f740ee76f27b78eb39c8ad972a757".to_string())
/// ```
///
/// Method 2
/// ```
/// use crypto_utils::sha::{Algorithm, CryptographicHash};
///
/// // create a new hasher
/// let mut sha1 = CryptographicHash::new(Algorithm::SHA1);
///
/// // set value in hasher
/// sha1.update(b"P@ssw0rd");
///
/// // compute hash
/// let hash_bytes = sha1.finalize();
///
/// // decode hash to a String
/// let hash = hex::encode(hash_bytes);
///
/// assert_eq!(hash, "21bd12dc183f740ee76f27b78eb39c8ad972a757".to_string())
/// ```
#[derive(Debug, Clone)]
pub enum CryptographicHash {
    /// Sha1 hasher
    Sha1(Sha1),
    /// Sha256 hasher
    Sha256(Sha256),
    /// Sha512 hasher
    Sha512(Sha512),
}

impl CryptographicHash {
    /// Create a new hasher
    pub fn new(algo: Algorithm) -> Self {
        match algo {
            // new Sha1 hasher
            Algorithm::SHA1 => Self::Sha1(Sha1::new()),
            // new Sha256 hasher
            Algorithm::SHA256 => Self::Sha256(Sha256::new()),
            // new Sha512 hasher
            Algorithm::SHA512 => Self::Sha512(Sha512::new()),
        }
    }

    /// Set value in hasher
    pub fn update(&mut self, input: &[u8]) {
        match self {
            // Sha1
            Self::Sha1(sha1) => sha1.update(input),
            // Sha256
            Self::Sha256(sha256) => sha256.update(input),
            // Sha512
            Self::Sha512(sha512) => sha512.update(input),
        }
    }

    /// Compute hash
    pub fn finalize(&mut self) -> Vec<u8> {
        match self {
            // Sha1
            Self::Sha1(sha1) => sha1.finalize_reset().to_vec(),
            // Sha256
            Self::Sha256(sha256) => sha256.finalize_reset().to_vec(),
            // Sha512
            Self::Sha512(sha512) => sha512.finalize_reset().to_vec(),
        }
    }

    /// Compute hash using a single function
    /// ```
    /// use crypto_utils::sha::{Algorithm, CryptographicHash};
    ///
    /// // compute hash
    /// let mut hash_bytes = CryptographicHash::hash(Algorithm::SHA1, b"P@ssw0rd");
    ///
    /// // decode hash to a String
    /// let hash = hex::encode(hash_bytes);
    ///
    /// assert_eq!(hash, "21bd12dc183f740ee76f27b78eb39c8ad972a757".to_string())
    /// ```
    pub fn hash(algo: Algorithm, input: &[u8]) -> Vec<u8> {
        // create hasher
        let mut hasher = Self::new(algo);

        // set value in hasher
        hasher.update(input);

        // compute hash
        hasher.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::{Algorithm, CryptographicHash};

    /// Test a Sha1 hasher
    #[test]
    fn sha1() {
        // expected hash
        let expected_hash = "7726bd9560e1ad4a1a4f056cae5c0c9ea8bacfc2".to_string();

        // compute hash
        let hash_bytes = CryptographicHash::hash(Algorithm::SHA1, b"test sha1 hash");

        // decode hash to a String
        let hash = hex::encode(hash_bytes);

        // validate hash
        assert_eq!(hash, expected_hash)
    }

    /// Test a Sha256 hasher
    #[test]
    fn sha256() {
        // expected hash
        let expected_hash =
            "eaf6e4198f39ccd63bc3e957d43bf4ef67f12c318c8e3cdc2567a37339902dac".to_string();

        // compute hash
        let hash_bytes = CryptographicHash::hash(Algorithm::SHA256, b"test sha256 hash");

        // decode hash to a String
        let hash = hex::encode(hash_bytes);

        // validate hash
        assert_eq!(hash, expected_hash)
    }

    /// Test a Sha512 hasher
    #[test]
    fn sha512() {
        // expected hash
        let expected_hash =
            "b43b4d7178014c92f55be828d66c9f98211fc67b385f7790a5b4b2fcb89fe1831645b5a4c17f3f7f11d8f34d2800a77a2b8faa5a0fb9d6b8f7befbc29a9ce795".to_string();

        // compute hash
        let hash_bytes = CryptographicHash::hash(Algorithm::SHA512, b"test sha512 hash");

        // decode hash to a String
        let hash = hex::encode(hash_bytes);

        // validate hash
        assert_eq!(hash, expected_hash)
    }
}
