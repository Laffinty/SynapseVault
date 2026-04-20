//! XChaCha20-Poly1305 对称加解密
//!
//! 提供基于 XChaCha20-Poly1305 的 AEAD 加解密，支持 192-bit nonce，
//! 适用于随机 nonce 场景（可安全随机生成，无需计数器管理）。

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

/// 对称加密错误
#[derive(Debug, thiserror::Error)]
pub enum SymmetricError {
    #[error("Invalid key length")]
    InvalidKey,
    #[error("Encryption failed")]
    EncryptFailed,
    #[error("Decryption failed")]
    DecryptFailed,
}

/// 生成随机 24 字节 nonce（XChaCha20-Poly1305 使用 192-bit nonce）
pub fn generate_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// 使用 XChaCha20-Poly1305 加密明文
///
/// # 参数
/// - `plaintext`: 待加密数据
/// - `key`: 32 字节密钥
/// - `nonce`: 24 字节 nonce（必须通过 [`generate_nonce`] 生成，且每次加密唯一）
///
/// # 返回
/// 密文（包含认证标签），失败返回 [`SymmetricError`]
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, SymmetricError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| SymmetricError::InvalidKey)?;
    let nonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| SymmetricError::EncryptFailed)
}

/// 使用 XChaCha20-Poly1305 解密密文
///
/// # 参数
/// - `ciphertext`: 密文（包含认证标签）
/// - `key`: 32 字节密钥
/// - `nonce`: 加密时使用的 24 字节 nonce
///
/// # 返回
/// 明文，失败返回 [`SymmetricError`]
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, SymmetricError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| SymmetricError::InvalidKey)?;
    let nonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SymmetricError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = generate_nonce();
        let plaintext = b"Hello, SynapseVault!";

        let ciphertext = encrypt(plaintext.as_slice(), &key, &nonce).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

        let decrypted = decrypt(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(decrypted, plaintext.as_slice());
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let nonce = generate_nonce();
        let plaintext = b"secret data";

        let ciphertext = encrypt(plaintext.as_slice(), &key, &nonce).unwrap();
        let result = decrypt(&ciphertext, &wrong_key, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let nonce = generate_nonce();
        let wrong_nonce = generate_nonce();
        let plaintext = b"secret data";

        let ciphertext = encrypt(plaintext.as_slice(), &key, &nonce).unwrap();
        let result = decrypt(&ciphertext, &key, &wrong_nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = generate_nonce();
        let plaintext = b"secret data";

        let mut ciphertext = encrypt(plaintext.as_slice(), &key, &nonce).unwrap();
        ciphertext[0] ^= 0xFF; // 篡改第一个字节

        let result = decrypt(&ciphertext, &key, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = generate_nonce();
        let plaintext = b"";

        let ciphertext = encrypt(plaintext.as_slice(), &key, &nonce).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(decrypted, plaintext.as_slice());
    }

    #[test]
    fn test_large_plaintext() {
        let key = [0x42u8; 32];
        let nonce = generate_nonce();
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1 MiB

        let ciphertext = encrypt(&plaintext, &key, &nonce).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
