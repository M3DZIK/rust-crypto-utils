use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha512};

/// Hashing algorithms
#[derive(Debug)]
pub enum Algorithm {
    /// Read about SHA-1 in [wikipedia](https://en.wikipedia.org/wiki/SHA-1)
    SHA1,
    /// Read about SHA-2 in [wikipedia](https://en.wikipedia.org/wiki/SHA-2)
    SHA256,
    /// Read about SHA-2 in [wikipedia](https://en.wikipedia.org/wiki/SHA-2)
    SHA512,
}

/// Compute cryptographic hash from bytes (sha1, sha256, sha512).
///
/// Method 1 (recommend)
/// ```
/// use crypto_utils::sha::{Algorithm, CryptographicHash};
///
/// // compute hash
/// let hash_bytes: Vec<u8> = CryptographicHash::hash(Algorithm::SHA1, b"P@ssw0rd");
///
/// // decode hash to a String
/// let hash: String = hex::encode(hash_bytes);
///
/// # assert_eq!(hash, "21bd12dc183f740ee76f27b78eb39c8ad972a757".to_string())
/// ```
///
/// Method 2
/// ```
/// use crypto_utils::sha::{Algorithm, CryptographicHash};
///
/// // create a new hasher
/// let mut hasher = CryptographicHash::new(Algorithm::SHA1);
///
/// // set value in hasher
/// hasher.update(b"P@ssw0rd");
///
/// // compute hash
/// let hash_bytes: Vec<u8> = hasher.finalize();
///
/// // decode hash to a String
/// let hash: String = hex::encode(hash_bytes);
///
/// # assert_eq!(hash, "21bd12dc183f740ee76f27b78eb39c8ad972a757".to_string())
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
    /// Create a new Sha hasher
    ///
    /// ```no_run
    /// use crypto_utils::sha::{Algorithm, CryptographicHash};
    ///
    /// // sha1 hasher
    /// let mut hasher = CryptographicHash::new(Algorithm::SHA1);
    ///
    /// // sha256 hasher
    /// let mut hasher = CryptographicHash::new(Algorithm::SHA256);
    ///
    /// // sha512 hasher
    /// let mut hasher = CryptographicHash::new(Algorithm::SHA512);
    /// ```
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

    /// Set value in the hasher
    ///
    /// ```no_run
    /// # use crypto_utils::sha::{Algorithm, CryptographicHash};
    /// #
    /// # let mut hasher = CryptographicHash::new(Algorithm::SHA1);
    /// #
    /// hasher.update(b"value");
    /// ```
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
    ///
    /// ```no_run
    /// # use crypto_utils::sha::{Algorithm, CryptographicHash};
    /// #
    /// # let mut hasher = CryptographicHash::new(Algorithm::SHA1);
    /// #
    /// # hasher.update(b"value");
    /// let hash: Vec<u8> = hasher.finalize();
    /// let hash_str: String = hex::encode(hash);
    /// ```
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
    ///
    /// ```
    /// use crypto_utils::sha::{Algorithm, CryptographicHash};
    ///
    /// // compute hash
    /// let hash_bytes: Vec<u8> = CryptographicHash::hash(Algorithm::SHA1, b"P@ssw0rd");
    ///
    /// // decode hash to a String
    /// let hash: String = hex::encode(hash_bytes);
    ///
    /// # assert_eq!(hash, "21bd12dc183f740ee76f27b78eb39c8ad972a757".to_string())
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

    const INPUT: &[u8] = b"input";

    // expected hashes
    const EXPECTED_SHA1: &str = "140f86aae51ab9e1cda9b4254fe98a74eb54c1a1";
    const EXPECTED_SHA256: &str =
        "c96c6d5be8d08a12e7b5cdc1b207fa6b2430974c86803d8891675e76fd992c20";
    const EXPECTED_SHA512: &str =
        "dc6d6c30f2be9c976d6318c9a534d85e9a1c3f3608321a04b4678ef408124d45d7164f3e562e68c6c0b6c077340a785824017032fddfa924f4cf400e6cbb6adc";

    /// Test a Sha1 hasher
    #[test]
    fn sha1() {
        // compute hash
        let hash_bytes = CryptographicHash::hash(Algorithm::SHA1, INPUT);

        // decode hash to a String
        let hash = hex::encode(hash_bytes);

        // validate hash
        assert_eq!(hash, EXPECTED_SHA1.to_string())
    }

    /// Test a Sha256 hasher
    #[test]
    fn sha256() {
        // compute hash
        let hash_bytes = CryptographicHash::hash(Algorithm::SHA256, INPUT);

        // decode hash to a String
        let hash = hex::encode(hash_bytes);

        // validate hash
        assert_eq!(hash, EXPECTED_SHA256.to_string())
    }

    /// Test a Sha512 hasher
    #[test]
    fn sha512() {
        // compute hash
        let hash_bytes = CryptographicHash::hash(Algorithm::SHA512, INPUT);

        // decode hash to a String
        let hash = hex::encode(hash_bytes);

        // validate hash
        assert_eq!(hash, EXPECTED_SHA512.to_string())
    }
}
