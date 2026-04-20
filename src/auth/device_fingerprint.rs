//! 设备指纹生成
//!
//! 结合机器唯一标识和公钥哈希生成设备指纹，用于密钥文件绑定。

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

/// 设备指纹结构
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceFingerprint {
    /// 机器唯一标识
    pub machine_uid: String,
    /// 公钥的 SHA-256 哈希（前 32 字节）
    pub pubkey_hash: [u8; 32],
    /// 组合字符串：`{machine_uid}:{hex(pubkey_hash)}`
    pub combined: String,
}

/// 生成设备指纹
///
/// # 参数
/// - `pubkey`: ed25519 公钥，用于绑定设备与密钥
///
/// # 返回
/// 包含机器 UID、公钥哈希和组合字符串的设备指纹
pub fn generate_device_fingerprint(pubkey: &VerifyingKey) -> DeviceFingerprint {
    let machine_uid = machine_uid::get().unwrap_or_else(|_| "unknown".to_string());

    let mut hasher = Sha256::new();
    hasher.update(pubkey.as_bytes());
    let pubkey_hash: [u8; 32] = hasher.finalize().into();

    let combined = format!("{}:{}", machine_uid, bytes_to_hex(&pubkey_hash));

    DeviceFingerprint {
        machine_uid,
        pubkey_hash,
        combined,
    }
}

/// 从已有组件重构设备指纹（用于验证时比对）
pub fn reconstruct_device_fingerprint(
    machine_uid: &str,
    pubkey: &VerifyingKey,
) -> DeviceFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(pubkey.as_bytes());
    let pubkey_hash: [u8; 32] = hasher.finalize().into();
    let combined = format!("{}:{}", machine_uid, bytes_to_hex(&pubkey_hash));

    DeviceFingerprint {
        machine_uid: machine_uid.to_string(),
        pubkey_hash,
        combined,
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::generate_keypair;

    #[test]
    fn test_fingerprint_deterministic() {
        let (_sk, vk) = generate_keypair();
        let fp1 = generate_device_fingerprint(&vk);
        let fp2 = generate_device_fingerprint(&vk);
        assert_eq!(fp1.combined, fp2.combined);
        assert_eq!(fp1.pubkey_hash, fp2.pubkey_hash);
    }

    #[test]
    fn test_fingerprint_different_pubkey() {
        let (_sk1, vk1) = generate_keypair();
        let (_sk2, vk2) = generate_keypair();
        let fp1 = generate_device_fingerprint(&vk1);
        let fp2 = generate_device_fingerprint(&vk2);
        assert_ne!(fp1.combined, fp2.combined);
        assert_ne!(fp1.pubkey_hash, fp2.pubkey_hash);
    }

    #[test]
    fn test_fingerprint_format() {
        let (_sk, vk) = generate_keypair();
        let fp = generate_device_fingerprint(&vk);
        // combined 格式应为 "machine_uid:hex_hash"
        let parts: Vec<&str> = fp.combined.split(':').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].len(), 64); // SHA-256 hex = 64 字符
    }

    #[test]
    fn test_reconstruct_matches_generate() {
        let (_sk, vk) = generate_keypair();
        let fp1 = generate_device_fingerprint(&vk);
        let fp2 = reconstruct_device_fingerprint(&fp1.machine_uid, &vk);
        assert_eq!(fp1.combined, fp2.combined);
        assert_eq!(fp1.pubkey_hash, fp2.pubkey_hash);
    }
}
