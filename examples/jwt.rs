use crypto_utils::jsonwebtoken::{Claims, Token};

fn main() -> anyhow::Result<()> {
    let secret = b"secret";
    let user_id = "1234";

    // create claims
    let claims = Claims::new(user_id, 24);

    // create token
    let token = Token::new(secret, claims)?;

    println!("token   = `{}`", token.encoded);

    // decode token
    let decoded = Token::decode(secret, token.encoded)?;

    println!("user_id = `{}`", decoded.claims.sub);

    Ok(())
}
