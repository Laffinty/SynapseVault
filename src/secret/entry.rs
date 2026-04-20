//! 密码条目数据结构
//!
//! 定义密码条目的内存表示、元信息、以及 CRDT 操作类型。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 密码条目唯一标识
pub type SecretId = String;

/// 组成员唯一标识
pub type MemberId = String;

/// 组唯一标识
pub type GroupId = String;

/// 密码条目（完整数据结构，含加密密码）
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretEntry {
    pub secret_id: SecretId,
    pub title: String,
    pub username: String,
    pub encrypted_password: Vec<u8>,
    pub nonce: [u8; 24],
    pub environment: String,
    pub tags: Vec<String>,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: MemberId,
    pub version: u64,
    pub expires_at: Option<DateTime<Utc>>,
}

/// 密码条目元信息（不含密码值，用于列表显示）
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretMeta {
    pub secret_id: SecretId,
    pub title: String,
    pub username: String,
    pub environment: String,
    pub tags: Vec<String>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl From<&SecretEntry> for SecretMeta {
    fn from(entry: &SecretEntry) -> Self {
        Self {
            secret_id: entry.secret_id.clone(),
            title: entry.title.clone(),
            username: entry.username.clone(),
            environment: entry.environment.clone(),
            tags: entry.tags.clone(),
            updated_at: entry.updated_at,
            expires_at: entry.expires_at,
        }
    }
}

/// 密码操作（CRDT 意图）
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecretOp {
    Create(SecretEntry),
    Update {
        secret_id: SecretId,
        encrypted_password: Vec<u8>,
        nonce: [u8; 24],
        updated_at: DateTime<Utc>,
        updated_by: MemberId,
    },
    Delete {
        secret_id: SecretId,
        deleted_by: MemberId,
        deleted_at: DateTime<Utc>,
    },
}

/// 密码条目错误
#[derive(Debug, thiserror::Error)]
pub enum SecretEntryError {
    #[error("Invalid secret data: {0}")]
    InvalidData(String),
    #[error("Secret not found: {0}")]
    NotFound(SecretId),
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Database error: {0}")]
    Database(String),
}

impl From<rusqlite::Error> for SecretEntryError {
    fn from(e: rusqlite::Error) -> Self {
        SecretEntryError::Database(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_meta_from_entry() {
        let entry = SecretEntry {
            secret_id: "uuid-1234".to_string(),
            title: "Test Secret".to_string(),
            username: "admin".to_string(),
            encrypted_password: vec![1, 2, 3],
            nonce: [0u8; 24],
            environment: "Production".to_string(),
            tags: vec!["ssh".to_string()],
            description: "Test desc".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "member-1".to_string(),
            version: 1,
            expires_at: None,
        };

        let meta: SecretMeta = (&entry).into();
        assert_eq!(meta.secret_id, entry.secret_id);
        assert_eq!(meta.title, entry.title);
        assert_eq!(meta.username, entry.username);
        assert_eq!(meta.environment, entry.environment);
        assert_eq!(meta.tags, entry.tags);
        // Meta 不应包含密码
    }

    #[test]
    fn test_secret_op_clone() {
        let op = SecretOp::Delete {
            secret_id: "id-1".to_string(),
            deleted_by: "member-1".to_string(),
            deleted_at: Utc::now(),
        };
        let cloned = op.clone();
        assert_eq!(op, cloned);
    }
}
