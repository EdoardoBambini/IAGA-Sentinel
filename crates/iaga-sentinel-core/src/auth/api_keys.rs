use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::rngs::OsRng;
use uuid::Uuid;

/// Generate a new API key pair: (raw_key, key_hash)
/// The raw_key is returned to the user once; the Argon2id hash is stored.
pub fn generate_api_key() -> (String, String) {
    let raw = format!("iaga_{}", Uuid::new_v4().to_string().replace('-', ""));
    let hash = hash_key(&raw);
    (raw, hash)
}

/// Hash an API key with Argon2id for storage/lookup.
pub fn hash_key(raw_key: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(raw_key.as_bytes(), &salt)
        .expect("failed to hash API key")
        .to_string()
}

/// Verify a raw API key against a stored Argon2id hash.
pub fn verify_key(raw_key: &str, stored_hash: &str) -> bool {
    let parsed = match PasswordHash::new(stored_hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(raw_key.as_bytes(), &parsed)
        .is_ok()
}
