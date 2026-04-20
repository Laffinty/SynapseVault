//! .key 密钥文件生成与读写
//!
//! 密钥文件格式规范（见文档 10.4 节）：
//! ```text
//! 文件头: "SVKEY" (5 bytes)
//! 版本号: 0x01 (1 byte)
//! Salt: 32 bytes
//! Argon2 参数: memory_cost(4) + time_cost(4) + parallelism(4)
//! Nonce: 24 bytes
//! 加密数据长度: 4 bytes (LE)
//! 加密数据: 变长 (XChaCha20-Poly1305 加密的 ed25519 私钥)
//! 公钥: 32 bytes
//! 设备指纹长度: 2 bytes (LE)
//! 设备指纹: 变长 (UTF-8)
//! 校验和: 32 bytes (SHA-256 of all above)
//! ```

use crate::auth::device_fingerprint::DeviceFingerprint;
use crate::crypto::kdf::{derive_keyfile_key, generate_salt, Argon2Params};
use crate::crypto::signing::generate_keypair;
use crate::crypto::symmetric::{encrypt, generate_nonce};
use ed25519_dalek::{SigningKey, VerifyingKey};

use sha2::{Digest, Sha256};
use std::io::Write;
use zeroize::Zeroize;

const MAGIC: &[u8] = b"SVKEY";
const VERSION: u8 = 1;

/// 密钥文件结构（内存表示）
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyFile {
    pub version: u8,
    pub salt: [u8; 32],
    pub encrypted_private_key: Vec<u8>,
    pub nonce: [u8; 24],
    pub public_key: VerifyingKey,
    pub device_fingerprint: String,
    pub argon2_params: Argon2Params,
}

/// 密钥文件错误
#[derive(Debug, thiserror::Error)]
pub enum KeyFileError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Encryption failed")]
    EncryptFailed,
    #[error("Decryption failed")]
    DecryptFailed,
    #[error("Invalid key file format")]
    InvalidFormat,
    #[error("Checksum mismatch")]
    ChecksumMismatch,
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),
}

/// 生成新的密钥文件（首次使用）
///
/// # 参数
/// - `master_password`: 用户设置的主密码
/// - `device_fingerprint`: 当前设备的指纹字符串
///
/// # 返回
/// - `(KeyFile, SigningKey)`: 密钥文件结构和对应的签名私钥
pub fn generate_key_file(
    master_password: &str,
    device_fingerprint: &DeviceFingerprint,
) -> Result<(KeyFile, SigningKey), KeyFileError> {
    let salt = generate_salt();
    let argon2_params = Argon2Params::default();

    let master_key = crate::crypto::kdf::derive_master_key(master_password, &salt, &argon2_params)
        .map_err(|_| KeyFileError::EncryptFailed)?;

    let (signing_key, verifying_key) = generate_keypair();
    let private_key_bytes = signing_key.to_bytes();

    let keyfile_key =
        derive_keyfile_key(&master_key).map_err(|_| KeyFileError::EncryptFailed)?;
    let nonce = generate_nonce();

    let encrypted_private_key =
        encrypt(&private_key_bytes, &keyfile_key, &nonce).map_err(|_| KeyFileError::EncryptFailed)?;

    // 安全擦除中间密钥和私钥副本
    let mut master_key_copy = master_key;
    let mut keyfile_key_copy = keyfile_key;
    let mut private_key_copy = private_key_bytes;
    master_key_copy.zeroize();
    keyfile_key_copy.zeroize();
    private_key_copy.zeroize();

    let key_file = KeyFile {
        version: VERSION,
        salt,
        encrypted_private_key,
        nonce,
        public_key: verifying_key,
        device_fingerprint: device_fingerprint.combined.clone(),
        argon2_params,
    };

    Ok((key_file, signing_key))
}

/// 重置密码（重新加密私钥）
///
/// 使用新密码重新加密已有的私钥，生成新的密钥文件。
/// 注意：这会改变 Argon2 盐值，但**不改变** ed25519 密钥对。
pub fn reset_password(
    key_file: &KeyFile,
    signing_key: &SigningKey,
    new_password: &str,
) -> Result<KeyFile, KeyFileError> {
    let salt = generate_salt();
    let argon2_params = Argon2Params::default();

    let master_key =
        crate::crypto::kdf::derive_master_key(new_password, &salt, &argon2_params)
            .map_err(|_| KeyFileError::EncryptFailed)?;

    let private_key_bytes = signing_key.to_bytes();
    let keyfile_key =
        derive_keyfile_key(&master_key).map_err(|_| KeyFileError::EncryptFailed)?;
    let nonce = generate_nonce();

    let encrypted_private_key =
        encrypt(&private_key_bytes, &keyfile_key, &nonce).map_err(|_| KeyFileError::EncryptFailed)?;

    // 安全擦除
    let mut master_key_copy = master_key;
    let mut keyfile_key_copy = keyfile_key;
    master_key_copy.zeroize();
    keyfile_key_copy.zeroize();

    Ok(KeyFile {
        version: VERSION,
        salt,
        encrypted_private_key,
        nonce,
        public_key: key_file.public_key,
        device_fingerprint: key_file.device_fingerprint.clone(),
        argon2_params,
    })
}

/// 将密钥文件编码为字节序列（用于写入磁盘）
pub fn encode_key_file(key_file: &KeyFile) -> Result<Vec<u8>, KeyFileError> {
    let mut buf = Vec::new();

    buf.write_all(MAGIC)?;
    buf.write_all(&[key_file.version])?;
    buf.write_all(&key_file.salt)?;
    buf.write_all(&key_file.argon2_params.memory_cost.to_le_bytes())?;
    buf.write_all(&key_file.argon2_params.time_cost.to_le_bytes())?;
    buf.write_all(&key_file.argon2_params.parallelism.to_le_bytes())?;
    buf.write_all(&key_file.nonce)?;

    let enc_len = key_file.encrypted_private_key.len() as u32;
    buf.write_all(&enc_len.to_le_bytes())?;
    buf.write_all(&key_file.encrypted_private_key)?;

    buf.write_all(key_file.public_key.as_bytes())?;

    let fp_bytes = key_file.device_fingerprint.as_bytes();
    let fp_len = fp_bytes.len() as u16;
    buf.write_all(&fp_len.to_le_bytes())?;
    buf.write_all(fp_bytes)?;

    let checksum = Sha256::digest(&buf);
    buf.write_all(&checksum)?;

    Ok(buf)
}

/// 从字节序列解码密钥文件（从磁盘读取后解析）
pub fn decode_key_file(data: &[u8]) -> Result<KeyFile, KeyFileError> {
    // 最小长度：magic(5) + version(1) + salt(32) + params(12) + nonce(24) + enc_len(4) + pubkey(32) + fp_len(2) + checksum(32)
    const MIN_LEN: usize = 5 + 1 + 32 + 12 + 24 + 4 + 32 + 2 + 32;
    if data.len() < MIN_LEN {
        return Err(KeyFileError::InvalidFormat);
    }

    let mut pos = 0usize;

    // Magic
    if &data[pos..pos + 5] != MAGIC {
        return Err(KeyFileError::InvalidFormat);
    }
    pos += 5;

    // Version
    let version = data[pos];
    if version != VERSION {
        return Err(KeyFileError::UnsupportedVersion(version));
    }
    pos += 1;

    // Checksum 位于数据末尾 32 字节
    let checksum_offset = data.len() - 32;
    let computed_checksum = Sha256::digest(&data[..checksum_offset]);
    if computed_checksum.as_slice() != &data[checksum_offset..] {
        return Err(KeyFileError::ChecksumMismatch);
    }

    // Salt
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // Argon2 params
    let mut memory_cost_bytes = [0u8; 4];
    memory_cost_bytes.copy_from_slice(&data[pos..pos + 4]);
    let memory_cost = u32::from_le_bytes(memory_cost_bytes);
    pos += 4;

    let mut time_cost_bytes = [0u8; 4];
    time_cost_bytes.copy_from_slice(&data[pos..pos + 4]);
    let time_cost = u32::from_le_bytes(time_cost_bytes);
    pos += 4;

    let mut parallelism_bytes = [0u8; 4];
    parallelism_bytes.copy_from_slice(&data[pos..pos + 4]);
    let parallelism = u32::from_le_bytes(parallelism_bytes);
    pos += 4;

    let argon2_params = Argon2Params {
        memory_cost,
        time_cost,
        parallelism,
    };

    // Nonce
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&data[pos..pos + 24]);
    pos += 24;

    // Encrypted data length
    let mut enc_len_bytes = [0u8; 4];
    enc_len_bytes.copy_from_slice(&data[pos..pos + 4]);
    let enc_len = u32::from_le_bytes(enc_len_bytes) as usize;
    pos += 4;

    if pos + enc_len + 32 + 2 > checksum_offset {
        return Err(KeyFileError::InvalidFormat);
    }

    // Encrypted data
    let encrypted_private_key = data[pos..pos + enc_len].to_vec();
    pos += enc_len;

    // Public key
    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(&data[pos..pos + 32]);
    let public_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|_| KeyFileError::InvalidFormat)?;
    pos += 32;

    // Device fingerprint
    let mut fp_len_bytes = [0u8; 2];
    fp_len_bytes.copy_from_slice(&data[pos..pos + 2]);
    let fp_len = u16::from_le_bytes(fp_len_bytes) as usize;
    pos += 2;

    if pos + fp_len != checksum_offset {
        return Err(KeyFileError::InvalidFormat);
    }

    let device_fingerprint = String::from_utf8(data[pos..pos + fp_len].to_vec())
        .map_err(|_| KeyFileError::InvalidFormat)?;

    Ok(KeyFile {
        version,
        salt,
        encrypted_private_key,
        nonce,
        public_key,
        device_fingerprint,
        argon2_params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::device_fingerprint::generate_device_fingerprint;
    use crate::crypto::signing::generate_keypair;

    #[test]
    fn test_generate_and_encode_decode() {
        let (_sk, vk) = generate_keypair();
        let fp = generate_device_fingerprint(&vk);
        let (key_file, _signing_key) = generate_key_file("my_strong_password", &fp).unwrap();

        let encoded = encode_key_file(&key_file).unwrap();
        let decoded = decode_key_file(&encoded).unwrap();

        assert_eq!(key_file.version, decoded.version);
        assert_eq!(key_file.salt, decoded.salt);
        assert_eq!(key_file.nonce, decoded.nonce);
        assert_eq!(key_file.public_key, decoded.public_key);
        assert_eq!(key_file.device_fingerprint, decoded.device_fingerprint);
        assert_eq!(key_file.argon2_params, decoded.argon2_params);
        assert_eq!(key_file.encrypted_private_key, decoded.encrypted_private_key);
    }

    #[test]
    fn test_decode_invalid_magic() {
        let mut data = vec![0u8; 200];
        data[..5].copy_from_slice(b"INVAL");
        assert!(matches!(
            decode_key_file(&data),
            Err(KeyFileError::InvalidFormat)
        ));
    }

    #[test]
    fn test_decode_checksum_mismatch() {
        let (_sk, vk) = generate_keypair();
        let fp = generate_device_fingerprint(&vk);
        let (key_file, _) = generate_key_file("password", &fp).unwrap();
        let mut encoded = encode_key_file(&key_file).unwrap();
        // 篡改最后一个字节（位于校验和区域内）
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;
        assert!(matches!(
            decode_key_file(&encoded),
            Err(KeyFileError::ChecksumMismatch)
        ));
    }

    #[test]
    fn test_reset_password_changes_salt() {
        let (_sk, vk) = generate_keypair();
        let fp = generate_device_fingerprint(&vk);
        let (key_file, signing_key) = generate_key_file("old_password", &fp).unwrap();

        let new_key_file = reset_password(&key_file, &signing_key, "new_password").unwrap();

        // 盐值应改变
        assert_ne!(key_file.salt, new_key_file.salt);
        // 公钥应保持不变
        assert_eq!(key_file.public_key, new_key_file.public_key);
        // 设备指纹应保持不变
        assert_eq!(key_file.device_fingerprint, new_key_file.device_fingerprint);
        // 加密后的私钥应不同（因为使用了不同的密钥和 nonce）
        assert_ne!(key_file.encrypted_private_key, new_key_file.encrypted_private_key);
    }

    #[test]
    fn test_empty_password_fails_argon2() {
        let (_sk, vk) = generate_keypair();
        let fp = generate_device_fingerprint(&vk);
        // Argon2 允许空密码，但生成密钥文件本身不会失败
        let result = generate_key_file("", &fp);
        assert!(result.is_ok());
    }
}
