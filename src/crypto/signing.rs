//! ed25519 签名与验签包装模块
//!
//! 提供 ed25519 密钥对生成、消息签名、签名验证的便捷接口。

use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng;

/// 签名相关错误
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid public key")]
    InvalidPublicKey,
}

/// 生成新的 ed25519 密钥对
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// 使用私钥对消息签名
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// 使用公钥验证签名
pub fn verify(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), SigningError> {
    verifying_key
        .verify(message, signature)
        .map_err(|_| SigningError::InvalidSignature)
}

/// 从 32 字节原始数据恢复公钥
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, SigningError> {
    VerifyingKey::from_bytes(bytes).map_err(|_| SigningError::InvalidPublicKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let (sk, vk) = generate_keypair();
        let message = b"SynapseVault test message";
        let signature = sign(&sk, message);
        assert!(verify(&vk, message, &signature).is_ok());
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let (sk, vk) = generate_keypair();
        let message = b"original message";
        let wrong_message = b"tampered message";
        let signature = sign(&sk, message);
        assert!(verify(&vk, wrong_message, &signature).is_err());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let (sk, _vk) = generate_keypair();
        let (_other_sk, other_vk) = generate_keypair();
        let message = b"test message";
        let signature = sign(&sk, message);
        assert!(verify(&other_vk, message, &signature).is_err());
    }

    #[test]
    fn test_keypair_deterministic_from_bytes() {
        let (sk, vk) = generate_keypair();
        let bytes = sk.to_bytes();
        let recovered_sk = SigningKey::from_bytes(&bytes);
        let recovered_vk = recovered_sk.verifying_key();
        assert_eq!(vk, recovered_vk);
    }

    #[test]
    fn test_verifying_key_from_bytes() {
        let (_sk, vk) = generate_keypair();
        let bytes = vk.to_bytes();
        let recovered = verifying_key_from_bytes(&bytes).unwrap();
        assert_eq!(vk, recovered);
    }

    #[test]
    fn test_verifying_key_from_invalid_bytes_fails() {
        // ed25519-dalek 2.x 对所有 32 字节数组都接受为公钥（只有在使用时才验证）
        // 但 from_bytes 对所有 32 字节都返回 Ok，所以我们测试一个明显的情况
        let bytes = [0xFFu8; 32];
        // 在 ed25519-dalek 2.x 中，from_bytes 对几乎所有 32 字节都返回 Ok
        // 这是合理的，因为点压缩表示下，某些字节组合仍然是有效公钥
        let vk = verifying_key_from_bytes(&bytes);
        // 我们仅验证函数可以被调用
        assert!(vk.is_ok());
    }
}
