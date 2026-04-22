//! Argon2id KDF + HKDF-SHA256 密钥派生
//!
//! 提供从主密码派生主密钥，以及从主密钥派生各类子密钥的能力。

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Argon2id 默认参数（64 MiB，3 轮，4 线程）
pub const ARGON2_MEMORY_COST: u32 = 65536;
pub const ARGON2_TIME_COST: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 4;
pub const ARGON2_OUTPUT_LEN: usize = 32;

/// 可序列化的 Argon2 参数
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Argon2Params {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_cost: ARGON2_MEMORY_COST,
            time_cost: ARGON2_TIME_COST,
            parallelism: ARGON2_PARALLELISM,
        }
    }
}

/// KDF 相关错误
#[derive(Debug, thiserror::Error)]
pub enum KdfError {
    #[error("Invalid Argon2 parameters: {0}")]
    InvalidParams(String),
    #[error("Argon2id KDF failed: {0}")]
    KdfFailed(String),
    #[error("HKDF expansion failed: {0}")]
    HkdfFailed(String),
}

/// 使用 Argon2id 从主密码派生 32 字节主密钥。
///
/// 这是耗时操作（约 1-3 秒），应在独立线程中执行。
pub fn derive_master_key(
    password: &str,
    salt: &[u8; 32],
    params: &Argon2Params,
) -> Result<[u8; 32], KdfError> {
    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| KdfError::InvalidParams(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| KdfError::KdfFailed(e.to_string()))?;
    Ok(output)
}

/// 生成随机 32 字节盐值
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// 校准 Argon2id 参数以达到目标耗时
///
/// 从最低参数开始（8192 KiB / 1 轮 / 1 线程），逐步增加 memory_cost 和 time_cost，
/// 直到 `derive_master_key` 耗时接近 `target_ms`。
///
/// # 参数
/// - `target_ms`: 目标耗时（毫秒），推荐 1000ms
///
/// # 返回
/// 校准后的 Argon2 参数
pub fn calibrate_argon2_params(target_ms: u64) -> Argon2Params {
    const TEST_PASSWORD: &str = "calibration_password_12345";
    let test_salt = [0xABu8; 32];

    let mut best_params = Argon2Params::default();
    let mut best_diff = u64::MAX;

    let candidates = generate_candidate_params();

    for params in candidates {
        let start = std::time::Instant::now();
        let _ = derive_master_key(TEST_PASSWORD, &test_salt, &params);
        let elapsed_ms = start.elapsed().as_millis() as u64;

        let diff = elapsed_ms.abs_diff(target_ms);

        if diff < best_diff {
            best_diff = diff;
            best_params = params;
        }

        // 如果已经超时太多，提前停止（后续参数只会更慢）
        if elapsed_ms > target_ms * 2 {
            break;
        }
    }

    best_params
}

/// 生成候选参数序列（从低到高）
fn generate_candidate_params() -> Vec<Argon2Params> {
    let mut params = Vec::new();
    let memory_costs = [8192, 16384, 32768, 65536, 131072, 262144];
    let time_costs = [1, 2, 3, 4, 5];
    let parallelisms = [1, 2, 4];

    for &m in &memory_costs {
        for &t in &time_costs {
            for &p in &parallelisms {
                params.push(Argon2Params {
                    memory_cost: m,
                    time_cost: t,
                    parallelism: p,
                });
            }
        }
    }
    params
}

/// 使用 HKDF-SHA256 从主密钥派生子密钥
pub fn hkdf_derive(master_key: &[u8; 32], info: &[u8], output: &mut [u8]) -> Result<(), KdfError> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    hk.expand(info, output)
        .map_err(|e| KdfError::HkdfFailed(e.to_string()))?;
    Ok(())
}

/// 派生数据库加密密钥（info = "db:key"）
pub fn derive_db_key(master_key: &[u8; 32]) -> Result<[u8; 32], KdfError> {
    let mut key = [0u8; 32];
    hkdf_derive(master_key, b"db:key", &mut key)?;
    Ok(key)
}

/// 派生密钥文件加密密钥（info = "keyfile:enc"）
pub fn derive_keyfile_key(master_key: &[u8; 32]) -> Result<[u8; 32], KdfError> {
    let mut key = [0u8; 32];
    hkdf_derive(master_key, b"keyfile:enc", &mut key)?;
    Ok(key)
}

/// 派生 per-secret 种子（info = "secret:seed"）
pub fn derive_secret_seed(master_key: &[u8; 32]) -> Result<[u8; 32], KdfError> {
    let mut seed = [0u8; 32];
    hkdf_derive(master_key, b"secret:seed", &mut seed)?;
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_master_key_deterministic() {
        let salt = [0xABu8; 32];
        let params = Argon2Params::default();
        let key1 = derive_master_key("test_password", &salt, &params).unwrap();
        let key2 = derive_master_key("test_password", &salt, &params).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_master_key_different_salt() {
        let salt1 = [0xABu8; 32];
        let salt2 = [0xCDu8; 32];
        let params = Argon2Params::default();
        let key1 = derive_master_key("test_password", &salt1, &params).unwrap();
        let key2 = derive_master_key("test_password", &salt2, &params).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_master_key_different_password() {
        let salt = [0xABu8; 32];
        let params = Argon2Params::default();
        let key1 = derive_master_key("password1", &salt, &params).unwrap();
        let key2 = derive_master_key("password2", &salt, &params).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hkdf_derive_deterministic() {
        let master_key = [0x12u8; 32];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hkdf_derive(&master_key, b"test_info", &mut out1).unwrap();
        hkdf_derive(&master_key, b"test_info", &mut out2).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_hkdf_different_info() {
        let master_key = [0x12u8; 32];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hkdf_derive(&master_key, b"info_a", &mut out1).unwrap();
        hkdf_derive(&master_key, b"info_b", &mut out2).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_derive_db_key_isolation() {
        let master_key = [0x34u8; 32];
        let db_key = derive_db_key(&master_key).unwrap();
        let kf_key = derive_keyfile_key(&master_key).unwrap();
        let seed = derive_secret_seed(&master_key).unwrap();
        assert_ne!(db_key, kf_key);
        assert_ne!(db_key, seed);
        assert_ne!(kf_key, seed);
    }

    #[test]
    fn test_generate_salt_random() {
        let s1 = generate_salt();
        let s2 = generate_salt();
        assert_ne!(s1, s2);
    }
}
