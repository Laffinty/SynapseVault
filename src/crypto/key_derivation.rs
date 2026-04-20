//! Per-secret 密钥派生
//!
//! 为每条密码条目独立派生加密密钥，确保单条密码泄露不影响其他密码。
//!
//! 派生路径：
//! ```text
//! Master Key
//!   └── HKDF-SHA256(info="secret:seed") → Secret Seed
//!         └── HKDF-SHA256(info="secret:{secret_id}") → Per-Secret Key
//! ```

use crate::crypto::kdf::hkdf_derive;

/// Per-secret 密钥派生错误
#[derive(Debug, thiserror::Error)]
pub enum KeyDerivationError {
    #[error("HKDF failed: {0}")]
    HkdfFailed(String),
}

/// 从 secret_seed 和 secret_id 派生独立的 32 字节密钥
///
/// # 参数
/// - `secret_seed`: 从 master_key 通过 HKDF 派生的种子
/// - `secret_id`: 密码条目的唯一标识（如 UUID）
///
/// # 返回
/// 32 字节 XChaCha20-Poly1305 密钥
pub fn derive_per_secret_key(
    secret_seed: &[u8; 32],
    secret_id: &str,
) -> Result<[u8; 32], KeyDerivationError> {
    let mut key = [0u8; 32];
    let info = format!("secret:{}", secret_id);
    hkdf_derive(secret_seed, info.as_bytes(), &mut key)
        .map_err(|e| KeyDerivationError::HkdfFailed(e.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_per_secret_key_deterministic() {
        let seed = [0x12u8; 32];
        let key1 = derive_per_secret_key(&seed, "uuid-1234").unwrap();
        let key2 = derive_per_secret_key(&seed, "uuid-1234").unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_different_secret_id() {
        let seed = [0x12u8; 32];
        let key1 = derive_per_secret_key(&seed, "uuid-1111").unwrap();
        let key2 = derive_per_secret_key(&seed, "uuid-2222").unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_different_seed() {
        let seed1 = [0x12u8; 32];
        let seed2 = [0x34u8; 32];
        let key1 = derive_per_secret_key(&seed1, "uuid-1234").unwrap();
        let key2 = derive_per_secret_key(&seed2, "uuid-1234").unwrap();
        assert_ne!(key1, key2);
    }
}
