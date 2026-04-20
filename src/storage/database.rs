//! SQLCipher 加密数据库连接管理
//!
//! 提供打开、关闭、配置 SQLCipher 加密数据库的能力。
//! 数据库密钥通过 HKDF 从 master_key 派生（info = "db:key"）。

use rusqlite::Connection;
use std::path::Path;

use crate::crypto::kdf::derive_db_key;
use crate::storage::schema::init_schema;

/// 存储错误
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("KDF error: {0}")]
    Kdf(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid path")]
    InvalidPath,
}

/// 打开 SQLCipher 加密数据库
///
/// # 参数
/// - `path`: 数据库文件路径
/// - `master_key`: 从 Argon2id 派生的 32 字节主密钥
///
/// # 返回
/// 已配置加密密钥并初始化 Schema 的数据库连接
pub fn open_database(path: &Path, master_key: &[u8; 32]) -> Result<Connection, StorageError> {
    // 确保父目录存在
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(path)?;

    // 派生数据库加密密钥
    let db_key = derive_db_key(master_key).map_err(|e| StorageError::Kdf(e.to_string()))?;
    let db_key_hex = bytes_to_hex(&db_key);

    // 配置 SQLCipher 密钥
    // 使用 pragma_update 以正确绑定值
    conn.pragma_update(None, "key", format!("x'{}'", db_key_hex))?;

    // 验证密钥是否正确（尝试读取）
    let _check: i64 =
        conn.query_row("SELECT count(*) FROM sqlite_master;", [], |row| row.get(0))?;

    // 初始化 Schema
    init_schema(&conn)?;

    Ok(conn)
}

/// 关闭数据库连接（显式关闭以便处理错误）
pub fn close_database(conn: Connection) -> Result<(), StorageError> {
    conn.close().map_err(|(_, e)| StorageError::Database(e))?;
    Ok(())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_database_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let master_key = [0x42u8; 32];

        let conn = open_database(&db_path, &master_key).unwrap();
        drop(conn);

        assert!(db_path.exists());
    }

    #[test]
    fn test_open_database_with_wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let master_key = [0x42u8; 32];

        // 首次打开创建数据库
        let conn = open_database(&db_path, &master_key).unwrap();
        drop(conn);

        // 用错误的密钥打开应失败
        let wrong_key = [0x43u8; 32];
        let result = open_database(&db_path, &wrong_key);
        // SQLCipher 在错误密钥下可能成功打开但后续读取失败
        // 具体行为取决于 SQLCipher 版本
        if let Ok(conn) = result {
            let check: Result<i64, _> =
                conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0));
            assert!(check.is_err(), "Wrong key should fail to read");
        }
    }

    #[test]
    fn test_open_database_initializes_schema() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let master_key = [0x42u8; 32];

        let conn = open_database(&db_path, &master_key).unwrap();

        // 验证 secrets 表存在
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='secrets'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}
