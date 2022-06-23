//! Module for creating and decoding json web token.
//!
//! ```
//! use crypto_utils::jsonwebtoken::{Claims, Token};
//!
//! let secret = b"secret";
//! let user_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
//!
//! // create claims
//! let claims = Claims::new(user_id, 24);
//!
//! // create token
//! let token = Token::new(secret, claims).unwrap();
//!
//! // decode token
//! let decoded = Token::decode(secret, token.encoded).unwrap();
//! ```

use chrono::{Duration, Utc};
use jsonwebtoken::{
    errors::Error, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

/// Token Claims
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Token value
    pub sub: String,
    /// Expire time of the token
    pub exp: i64,
    /// Token creation time
    pub iat: i64,
}

impl Claims {
    /// Create a new Json Web Token Claims.
    /// ```
    /// use crypto_utils::jsonwebtoken::Claims;
    ///
    /// let user_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
    ///
    /// Claims::new(user_id, 24);
    /// ```
    pub fn new(sub: &str, expire_hours: i64) -> Self {
        let iat = Utc::now();
        let exp = iat + Duration::hours(expire_hours);

        Self {
            sub: sub.to_string(),
            iat: iat.timestamp(),
            exp: exp.timestamp(),
        }
    }
}

/// The return type of a successful call to [decode](Token::decode).
pub type TokenData = jsonwebtoken::TokenData<Claims>;

/// Json Web Token
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Token {
    /// Token Header
    header: Header,
    /// Token claims
    pub claims: Claims,
    /// Encoded token to a String
    pub encoded: String,
}

impl Token {
    /// Create a new token
    /// ```
    /// use crypto_utils::jsonwebtoken::{Claims, Token};
    ///
    /// // jwt secret
    /// let secret = b"secret";
    ///
    /// // token claims
    /// let claims = Claims::new("user_id_1234", 24);
    ///
    /// // create token
    /// let token = Token::new(secret, claims).unwrap();
    /// ```
    pub fn new(key: &[u8], claims: Claims) -> Result<Self, Error> {
        // generate token header
        let header = Header::new(Algorithm::HS256);

        // encode token
        let encoded = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(key))?;

        Ok(Self {
            header,
            claims,
            encoded,
        })
    }

    /// Decode token
    /// ```
    /// use crypto_utils::jsonwebtoken::{Claims, Token};
    ///
    /// // jwt secret
    /// let secret = b"secret";
    ///
    /// // token claims
    /// let claims = Claims::new("user_id_1234", 24);
    ///
    /// // create token
    /// let token = Token::new(secret, claims).unwrap();
    ///
    /// // decode token
    /// let decoded = Token::decode(secret, token.encoded).unwrap();
    /// ```
    pub fn decode(key: &[u8], token: String) -> Result<TokenData, Error> {
        jsonwebtoken::decode::<Claims>(
            &token,
            &DecodingKey::from_secret(key),
            &Validation::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Claims, Token};

    /// Decode token with invalid secret
    #[test]
    fn decode_secret_invalid() {
        let secret = b"secret";

        // create claims
        let claims = Claims::new("user_id_1234", 24);

        // create token
        let token = Token::new(secret, claims).unwrap();

        // unwrap error when decoding token
        let err = Token::decode(b"other secret", token.encoded).unwrap_err();

        assert_eq!(err.to_string(), "InvalidSignature");
    }

    /// Decode expired token
    #[test]
    fn decode_expired() {
        let key = b"key";

        // create a token that expired an hour ago
        let token = Token::new(key, Claims::new("test", -1)).expect("generate token");

        // unwrap error when decoding token
        let err = Token::decode(key, token.encoded).unwrap_err();

        assert_eq!(err.to_string(), "ExpiredSignature");
    }
}
