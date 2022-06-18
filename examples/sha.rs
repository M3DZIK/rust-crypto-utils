use crypto_utils::sha::{CryptographicHash, Algorithm};

fn main() {
    let input = "This is a input text to be hashed";

    println!("input  = `{input}`");

    let sha1 = CryptographicHash::hash(Algorithm::SHA1, input.as_bytes());

    println!("sha1   = `{}`", hex::encode(sha1));

    let sha256 = CryptographicHash::hash(Algorithm::SHA256, input.as_bytes());

    println!("sha256 = `{}`",  hex::encode(sha256));

    let sha512 = CryptographicHash::hash(Algorithm::SHA512, input.as_bytes());

    println!("sha512 = `{}`",  hex::encode(sha512));
}
