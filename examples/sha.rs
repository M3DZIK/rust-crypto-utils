use crypto_utils::sha::{Algorithm, CryptographicHash, CryptographicMac, AlgorithmMac};

fn main() {
    let input = "This is a input text to be hashed";

    println!("==> Sha");

    println!("input       = `{input}`");

    let sha1 = CryptographicHash::hash(Algorithm::SHA1, input.as_bytes());

    println!("sha1        = `{}`", hex::encode(sha1));

    let sha256 = CryptographicHash::hash(Algorithm::SHA256, input.as_bytes());

    println!("sha256      = `{}`", hex::encode(sha256));

    let sha512 = CryptographicHash::hash(Algorithm::SHA512, input.as_bytes());

    println!("sha512      = `{}`", hex::encode(sha512));

    println!("==> HMAC-Sha");

    let secret = "secret";
    let input = "This is a input text to be hashed";

    println!("input       = `{input}`");
    println!("secret      = `{secret}`");

    let sha1 = CryptographicMac::hash(AlgorithmMac::HmacSHA1, secret.as_bytes(), input.as_bytes()).unwrap();

    println!("hmac sha1   = `{}`", hex::encode(sha1));

    let sha256 = CryptographicMac::hash(AlgorithmMac::HmacSHA256, secret.as_bytes(), input.as_bytes()).unwrap();

    println!("hmac sha256 = `{}`", hex::encode(sha256));

    let sha512 =CryptographicMac::hash(AlgorithmMac::HmacSHA512, secret.as_bytes(), input.as_bytes()).unwrap();

    println!("hmac sha512 = `{}`", hex::encode(sha512));
}
