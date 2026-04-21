//! 群组密钥管理
//!
//! 群组的签名密钥对，仅由 Admin 持有私钥，用于群组级操作签名。

use crate::crypto::signing::generate_keypair;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// 群组签名密钥对（仅 Admin 持有）
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupSigningKey {
    /// 群组私钥（需安全保管）
    #[serde(with = "ed25519_private_key_bytes")]
    pub private_key: SigningKey,
    /// 群组公钥
    pub public_key: VerifyingKey,
}

/// 群组公钥信息（可公开）
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupPublicKey {
    /// 群组公钥
    pub public_key: VerifyingKey,
}

impl GroupSigningKey {
    /// 生成新的群组密钥对
    pub fn generate() -> Self {
        let (private_key, public_key) = generate_keypair();
        Self {
            private_key,
            public_key,
        }
    }

    /// 获取公钥信息
    pub fn to_public_key(&self) -> GroupPublicKey {
        GroupPublicKey {
            public_key: self.public_key,
        }
    }
}

/// ed25519 私钥序列化辅助模块
mod ed25519_private_key_bytes {
    use ed25519_dalek::SigningKey;
    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S>(key: &SigningKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&key.to_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SigningKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("invalid signing key length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(SigningKey::from_bytes(&arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_group_key() {
        let gsk = GroupSigningKey::generate();
        assert_eq!(gsk.public_key, gsk.private_key.verifying_key());
    }

    #[test]
    fn test_group_key_serde() {
        let gsk = GroupSigningKey::generate();
        let encoded = bincode::serialize(&gsk).unwrap();
        let decoded: GroupSigningKey = bincode::deserialize(&encoded).unwrap();
        assert_eq!(gsk.public_key, decoded.public_key);
        assert_eq!(gsk.private_key.to_bytes(), decoded.private_key.to_bytes());
    }
}
