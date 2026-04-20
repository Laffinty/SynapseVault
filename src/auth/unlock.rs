//! 双认证解锁流程
//!
//! 提供从密钥文件 + 主密码解锁会话的完整流程，
//! 包含设备指纹验证、Argon2id 密钥派生、私钥解密。

use crate::auth::device_fingerprint::DeviceFingerprint;
use crate::auth::keyfile::{decode_key_file, KeyFileError};
use crate::crypto::kdf::{derive_keyfile_key, derive_master_key};
use crate::crypto::symmetric::decrypt;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use zeroize::Zeroize;

/// 解锁后会话（敏感数据在 Drop 时自动擦除）
pub struct UnlockedSession {
    /// ed25519 签名私钥（临时加载，退出即丢弃）
    pub private_key: SigningKey,
    /// 由 Argon2id 派生的 32 字节主密钥
    pub master_key: [u8; 32],
    /// 设备指纹组合字符串
    pub device_fingerprint: String,
    /// 解锁时间
    pub unlocked_at: DateTime<Utc>,
}

impl Zeroize for UnlockedSession {
    fn zeroize(&mut self) {
        // SigningKey 可以通过覆盖为零字节来擦除
        self.private_key = SigningKey::from_bytes(&[0u8; 32]);
        self.master_key.zeroize();
        self.device_fingerprint.zeroize();
    }
}

impl Drop for UnlockedSession {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for UnlockedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedSession")
            .field("device_fingerprint", &self.device_fingerprint)
            .field("unlocked_at", &self.unlocked_at)
            .field("public_key", &self.private_key.verifying_key())
            .finish_non_exhaustive()
    }
}

/// 解锁错误
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Key file error: {0}")]
    KeyFile(#[from] KeyFileError),
    #[error("KDF error")]
    KdfError,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Device fingerprint mismatch")]
    FingerprintMismatch,
    #[error("Public key mismatch — possible tampering")]
    PublicKeyMismatch,
}

/// 从密钥文件解锁（双认证：密钥文件 + 主密码）
///
/// # 流程
/// 1. 解码密钥文件并验证校验和
/// 2. 验证设备指纹匹配
/// 3. Argon2id 派生主密钥
/// 4. HKDF 派生密钥文件加密密钥
/// 5. XChaCha20-Poly1305 解密私钥
/// 6. 验证解密后的公钥与文件中的公钥一致
///
/// # 参数
/// - `key_file_data`: 密钥文件原始字节
/// - `master_password`: 用户输入的主密码
/// - `expected_fingerprint`: 当前设备的指纹（用于绑定验证）
///
/// # 安全注意
/// - 所有中间敏感数据在函数返回前被 zeroize
/// - `UnlockedSession` 的 `Drop` 会自动擦除 `private_key` 和 `master_key`
pub fn unlock_key_file(
    key_file_data: &[u8],
    master_password: &str,
    expected_fingerprint: &DeviceFingerprint,
) -> Result<UnlockedSession, UnlockError> {
    let key_file = decode_key_file(key_file_data)?;

    // 验证设备指纹
    if key_file.device_fingerprint != expected_fingerprint.combined {
        return Err(UnlockError::FingerprintMismatch);
    }

    // Argon2id 派生主密钥
    let master_key =
        derive_master_key(master_password, &key_file.salt, &key_file.argon2_params)
            .map_err(|_| UnlockError::KdfError)?;

    // HKDF 派生密钥文件加密密钥
    let keyfile_key = derive_keyfile_key(&master_key).map_err(|_| UnlockError::KdfError)?;

    // 解密私钥
    let decrypted_private_key =
        decrypt(&key_file.encrypted_private_key, &keyfile_key, &key_file.nonce)
            .map_err(|_| UnlockError::DecryptionFailed)?;

    if decrypted_private_key.len() != 32 {
        return Err(UnlockError::DecryptionFailed);
    }

    let mut private_key_bytes = [0u8; 32];
    private_key_bytes.copy_from_slice(&decrypted_private_key);

    let private_key = SigningKey::from_bytes(&private_key_bytes);
    let derived_public_key = private_key.verifying_key();

    // 验证公钥一致性（防篡改）
    if derived_public_key != key_file.public_key {
        return Err(UnlockError::PublicKeyMismatch);
    }

    // 安全擦除中间数据
    let mut decrypted_copy = decrypted_private_key;
    let mut keyfile_key_copy = keyfile_key;
    decrypted_copy.zeroize();
    keyfile_key_copy.zeroize();
    private_key_bytes.zeroize();

    Ok(UnlockedSession {
        private_key,
        master_key,
        device_fingerprint: expected_fingerprint.combined.clone(),
        unlocked_at: Utc::now(),
    })
}

/// 安全擦除字节数组（工具函数）
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::device_fingerprint::generate_device_fingerprint;
    use crate::auth::keyfile::generate_key_file;
    use crate::crypto::signing::generate_keypair;

    #[test]
    fn test_unlock_success() {
        let (_sk, vk) = generate_keypair();
        let fp = generate_device_fingerprint(&vk);
        let (key_file, _signing_key) = generate_key_file("correct_password", &fp).unwrap();
        let encoded = crate::auth::keyfile::encode_key_file(&key_file).unwrap();

        let session = unlock_key_file(&encoded, "correct_password", &fp).unwrap();
        assert_eq!(session.device_fingerprint, fp.combined);
        // 验证主密钥非全零
        assert_ne!(session.master_key, [0u8; 32]);
    }

    #[test]
    fn test_unlock_wrong_password_fails() {
        let (_sk, vk) = generate_keypair();
        let fp = generate_device_fingerprint(&vk);
        let (key_file, _signing_key) = generate_key_file("correct_password", &fp).unwrap();
        let encoded = crate::auth::keyfile::encode_key_file(&key_file).unwrap();

        let result = unlock_key_file(&encoded, "wrong_password", &fp);
        assert!(matches!(result, Err(UnlockError::DecryptionFailed | UnlockError::PublicKeyMismatch)));
    }

    #[test]
    fn test_unlock_wrong_fingerprint_fails() {
        let (_sk, vk) = generate_keypair();
        let fp = generate_device_fingerprint(&vk);
        let (key_file, _signing_key) = generate_key_file("password", &fp).unwrap();
        let encoded = crate::auth::keyfile::encode_key_file(&key_file).unwrap();

        let wrong_fp = DeviceFingerprint {
            machine_uid: "wrong".to_string(),
            pubkey_hash: [0u8; 32],
            combined: "wrong:0000".to_string(),
        };

        let result = unlock_key_file(&encoded, "password", &wrong_fp);
        assert!(matches!(result, Err(UnlockError::FingerprintMismatch)));
    }

    #[test]
    fn test_unlock_invalid_keyfile() {
        let fp = generate_device_fingerprint(&generate_keypair().1);
        let result = unlock_key_file(b"invalid_data", "password", &fp);
        assert!(matches!(result, Err(UnlockError::KeyFile(_))));
    }

    #[test]
    fn test_session_zeroize_on_drop() {
        let (_sk, vk) = generate_keypair();
        let fp = generate_device_fingerprint(&vk);
        let (key_file, _signing_key) = generate_key_file("password", &fp).unwrap();
        let encoded = crate::auth::keyfile::encode_key_file(&key_file).unwrap();

        let session = unlock_key_file(&encoded, "password", &fp).unwrap();
        // 这里 session 离开作用域时会自动 zeroize
        // 由于无法直接验证内存内容，此测试主要验证编译通过和正常运行
        assert_eq!(session.device_fingerprint, fp.combined);
    }
}
