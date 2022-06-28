use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;

/// Custom error type
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid HMAC Key
    #[error("invalid key")]
    InvalidKey,
}

/// Alias to a `Resuly<T, Error>` with the cutom [Error].
pub type Result<T> = std::result::Result<T, Error>;

/// HMAC hashing algorithms
pub enum AlgorithmMac {
    /// Read about HMAC in [wikipedia](https://en.wikipedia.org/wiki/HMAC)
    HmacSHA1,
    /// Read about HMAC in [wikipedia](https://en.wikipedia.org/wiki/HMAC)
    HmacSHA256,
    /// Read about HMAC in [wikipedia](https://en.wikipedia.org/wiki/HMAC)
    HmacSHA512,
}

/// Compute cryptographic hash from bytes (HMAC Sha1, HMAC Sha256, HMAC Sha512).
pub enum CryptographicMac {
    /// HMAC Sha1 hasher
    HmacSha1(Hmac<Sha1>),
    /// HMAC Sha256 hasher
    HmacSha256(Hmac<Sha256>),
    /// HMAC Sha512 hasher
    HmacSha512(Hmac<Sha512>),
}

impl CryptographicMac {
    /// Create a new HMAC Sha hasher.
    ///
    /// ```no_run
    /// use crypto_utils::sha::{AlgorithmMac, CryptographicMac};
    ///
    /// // Hmac Sha1
    /// let mut hasher = CryptographicMac::new(AlgorithmMac::HmacSHA1, b"secret").unwrap();
    ///
    /// // Hmac Sha256
    /// let mut hasher = CryptographicMac::new(AlgorithmMac::HmacSHA256, b"secret").unwrap();
    ///
    /// // Hmac Sha512
    /// let mut hasher = CryptographicMac::new(AlgorithmMac::HmacSHA512, b"secret").unwrap();
    /// ```
    pub fn new(algo: AlgorithmMac, key: &[u8]) -> Result<Self> {
        Ok(match algo {
            AlgorithmMac::HmacSHA1 => {
                Self::HmacSha1(Hmac::<Sha1>::new_from_slice(key).map_err(|_| Error::InvalidKey)?)
            }
            AlgorithmMac::HmacSHA256 => Self::HmacSha256(
                Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::InvalidKey)?,
            ),
            AlgorithmMac::HmacSHA512 => Self::HmacSha512(
                Hmac::<Sha512>::new_from_slice(key).map_err(|_| Error::InvalidKey)?,
            ),
        })
    }

    /// Set value in the hasher
    ///
    /// ```no_run
    /// # use crypto_utils::sha::{AlgorithmMac, CryptographicMac};
    /// #
    /// # let mut hasher = CryptographicMac::new(AlgorithmMac::HmacSHA1, b"secret").unwrap();
    /// #
    /// hasher.update(b"value");
    /// ```
    pub fn update(&mut self, input: &[u8]) {
        match self {
            // Sha1
            Self::HmacSha1(sha1) => sha1.update(input),
            // Sha256
            Self::HmacSha256(sha256) => sha256.update(input),
            // Sha512
            Self::HmacSha512(sha512) => sha512.update(input),
        }
    }

    /// Compute hash
    ///
    /// ```no_run
    /// # use crypto_utils::sha::{AlgorithmMac, CryptographicMac};
    /// #
    /// # let mut hasher = CryptographicMac::new(AlgorithmMac::HmacSHA1, b"secret").unwrap();
    /// #
    /// # hasher.update(b"value");
    /// let hash: Vec<u8> = hasher.finalize();
    /// let hash_str: String = hex::encode(hash);
    /// ```
    pub fn finalize(self) -> Vec<u8> {
        match self {
            // Sha1
            Self::HmacSha1(sha1) => sha1.finalize().into_bytes().to_vec(),
            // Sha256
            Self::HmacSha256(sha256) => sha256.finalize().into_bytes().to_vec(),
            // Sha512
            Self::HmacSha512(sha512) => sha512.finalize().into_bytes().to_vec(),
        }
    }

    /// Compute hash using a single function
    ///
    /// ```
    /// use crypto_utils::sha::{AlgorithmMac, CryptographicMac};
    ///
    /// let hash_bytes: Vec<u8> = CryptographicMac::hash(AlgorithmMac::HmacSHA1, b"secret", b"P@ssw0rd").unwrap();
    ///
    /// // decode hash to a String
    /// let hash: String = hex::encode(hash_bytes);
    ///
    /// # assert_eq!(hash, "20bbb9ec2d4574845911b13695b776097bd46e41".to_string())
    /// ```
    pub fn hash(algo: AlgorithmMac, secret: &[u8], input: &[u8]) -> Result<Vec<u8>> {
        // create hasher
        let mut hasher = Self::new(algo, secret)?;

        // set value in hasher
        hasher.update(input);

        // compute hash
        Ok(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::{AlgorithmMac, CryptographicMac};

    const SECRET: &[u8] = b"secret";
    const INPUT: &[u8] = b"input";

    // expected hashes
    const EXPECTED_HMAC_SHA1: &str = "30440f36ddc2809bbd4c8b1f37a6e80d7588c303";
    const EXPECTED_HMAC_SHA256: &str =
        "8d8985d04b7abd32cbaa3779a3daa019e0d269a22aec15af8e7296f702cc68c6";
    const EXPECTED_HMAC_SHA512: &str =
        "2ac95ed3717e042c7064a5fa7c318230cd36d85e06f8ff8373d04ca17e361629e09f46b7f151ff382a3f48c5b19121446e45c2588f0ff1de9f74b0400daef81f";

    /// Test a HMAC Sha1 hasher
    #[test]
    fn hmac_sha1() {
        // compute hash
        let hash_bytes = CryptographicMac::hash(AlgorithmMac::HmacSHA1, SECRET, INPUT).unwrap();

        // decode hash to a String
        let hash = hex::encode(hash_bytes);

        // validate hash
        assert_eq!(hash, EXPECTED_HMAC_SHA1.to_string())
    }

    /// Test a HMAC Sha256 hasher
    #[test]
    fn hmac_sha256() {
        // compute hash
        let hash_bytes = CryptographicMac::hash(AlgorithmMac::HmacSHA256, SECRET, INPUT).unwrap();

        // decode hash to a String
        let hash = hex::encode(hash_bytes);

        // validate hash
        assert_eq!(hash, EXPECTED_HMAC_SHA256.to_string())
    }

    /// Test a HMAC Sha512 hasher
    #[test]
    fn hmac_sha512() {
        // compute hash
        let hash_bytes = CryptographicMac::hash(AlgorithmMac::HmacSHA512, SECRET, INPUT).unwrap();

        // decode hash to a String
        let hash = hex::encode(hash_bytes);

        // validate hash
        assert_eq!(hash, EXPECTED_HMAC_SHA512.to_string())
    }
}
