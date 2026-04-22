#![cfg(not(miri))]
//! 解锁流程集成测试
//!
//! 验证"生成密钥文件 → 保存 → 读取 → 解锁"的完整路径，
//! 模拟真实 App 的调用方式（BUG-P1-001 的回归测试）。

use std::io::Write;
use synapse_vault::auth::device_fingerprint::generate_device_fingerprint;
use synapse_vault::auth::keyfile::{decode_key_file, encode_key_file, generate_key_file};
use synapse_vault::auth::unlock::unlock_key_file;

#[test]
fn test_full_unlock_flow_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("synapsevault.key");

    // 1. 首次设置：生成密钥文件
    let (key_file, _signing_key, _master_key) = generate_key_file("my_secure_password").unwrap();
    let encoded = encode_key_file(&key_file).unwrap();

    // 2. 保存到磁盘
    let mut file = std::fs::File::create(&key_path).unwrap();
    file.write_all(&encoded).unwrap();
    drop(file);

    // 3. 下次启动：从磁盘读取
    let key_file_data = std::fs::read(&key_path).unwrap();
    let decoded = decode_key_file(&key_file_data).unwrap();

    // 4. 用公钥重新生成设备指纹（模拟 handle_unlock 的真实行为）
    let fp = generate_device_fingerprint(&decoded.public_key);

    // 5. 解锁
    let session = unlock_key_file(&key_file_data, "my_secure_password", &fp).unwrap();

    // 6. 验证
    assert_eq!(session.public_key, key_file.public_key);
    assert_eq!(session.device_fingerprint, key_file.device_fingerprint);
    assert_eq!(session.device_fingerprint, fp.combined);
    assert_ne!(session.master_key, [0u8; 32]);
}

#[test]
fn test_unlock_flow_wrong_password_fails() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("synapsevault.key");

    let (key_file, _signing_key, _) = generate_key_file("correct_password").unwrap();
    let encoded = encode_key_file(&key_file).unwrap();

    let mut file = std::fs::File::create(&key_path).unwrap();
    file.write_all(&encoded).unwrap();
    drop(file);

    let key_file_data = std::fs::read(&key_path).unwrap();
    let decoded = decode_key_file(&key_file_data).unwrap();
    let fp = generate_device_fingerprint(&decoded.public_key);

    let result = unlock_key_file(&key_file_data, "wrong_password", &fp);
    assert!(result.is_err());
}

#[test]
fn test_unlock_flow_fingerprint_mismatch_fails() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("synapsevault.key");

    let (key_file, _signing_key, _) = generate_key_file("password").unwrap();
    let encoded = encode_key_file(&key_file).unwrap();

    let mut file = std::fs::File::create(&key_path).unwrap();
    file.write_all(&encoded).unwrap();
    drop(file);

    let key_file_data = std::fs::read(&key_path).unwrap();

    // 使用错误的指纹
    let wrong_fp = synapse_vault::auth::device_fingerprint::DeviceFingerprint {
        machine_uid: "wrong".to_string(),
        pubkey_hash: [0u8; 32],
        combined: "wrong:0000".to_string(),
    };

    let result = unlock_key_file(&key_file_data, "password", &wrong_fp);
    assert!(result.is_err());
}
