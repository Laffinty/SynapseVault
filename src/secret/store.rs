//! 密码 CRUD 操作
//!
//! 提供密码条目的创建、读取、更新、删除、搜索等操作，
//! 所有数据持久化到 SQLCipher 加密数据库中。

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use uuid::Uuid;

use crate::crypto::kdf::derive_secret_seed;
use crate::crypto::key_derivation::derive_per_secret_key;
use crate::crypto::symmetric::{decrypt, encrypt, generate_nonce};
use crate::secret::entry::{
    GroupId, MemberId, SecretEntry, SecretEntryError, SecretId, SecretMeta,
};

/// 密码存储
pub struct SecretStore<'a> {
    conn: &'a Connection,
}

impl<'a> SecretStore<'a> {
    /// 创建新的 SecretStore
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// 创建密码条目
    ///
    /// # 参数
    /// - `group_id`: 所属组 ID
    /// - `title`: 条目标题
    /// - `username`: 用户名
    /// - `password`: 明文密码
    /// - `environment`: 环境分组
    /// - `tags`: 标签列表
    /// - `description`: 描述
    /// - `expires_at`: 过期时间（可选）
    /// - `created_by`: 创建者 member_id
    /// - `master_key`: 主密钥（用于派生 per-secret 密钥）
    #[allow(clippy::too_many_arguments)]
    pub fn create_secret(
        &self,
        group_id: &GroupId,
        title: &str,
        username: &str,
        password: &str,
        environment: &str,
        tags: Vec<String>,
        description: &str,
        expires_at: Option<DateTime<Utc>>,
        created_by: &MemberId,
        master_key: &[u8; 32],
    ) -> Result<SecretEntry, SecretEntryError> {
        let secret_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // 派生 per-secret 密钥并加密密码
        let secret_seed =
            derive_secret_seed(master_key).map_err(|_| SecretEntryError::EncryptionFailed)?;
        let per_secret_key = derive_per_secret_key(&secret_seed, &secret_id)
            .map_err(|_| SecretEntryError::EncryptionFailed)?;
        let nonce = generate_nonce();
        let encrypted_password = encrypt(password.as_bytes(), &per_secret_key, &nonce)
            .map_err(|_| SecretEntryError::EncryptionFailed)?;

        let entry = SecretEntry {
            secret_id: secret_id.clone(),
            title: title.to_string(),
            username: username.to_string(),
            encrypted_password,
            nonce,
            environment: environment.to_string(),
            tags: tags.clone(),
            description: description.to_string(),
            created_at: now,
            updated_at: now,
            created_by: created_by.clone(),
            version: 1,
            expires_at,
        };

        let tags_json = serde_json::to_string(&tags)
            .map_err(|e| SecretEntryError::InvalidData(e.to_string()))?;

        self.conn.execute(
            "INSERT INTO secrets (
                secret_id, group_id, title, username, encrypted_password, nonce,
                environment, tags, description, created_at, updated_at, created_by, version, expires_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                &entry.secret_id,
                group_id,
                &entry.title,
                &entry.username,
                &entry.encrypted_password,
                &entry.nonce[..],
                &entry.environment,
                tags_json,
                &entry.description,
                entry.created_at.to_rfc3339(),
                entry.updated_at.to_rfc3339(),
                &entry.created_by,
                entry.version as i64,
                entry.expires_at.map(|t| t.to_rfc3339()),
            ],
        ).map_err(|e| SecretEntryError::InvalidData(e.to_string()))?;

        Ok(entry)
    }

    /// 获取密码条目（完整数据）
    pub fn get_secret(&self, secret_id: &SecretId) -> Result<SecretEntry, SecretEntryError> {
        self.conn.query_row(
            "SELECT secret_id, group_id, title, username, encrypted_password, nonce,
                    environment, tags, description, created_at, updated_at, created_by, version, expires_at
             FROM secrets WHERE secret_id = ?1",
            [secret_id],
            |row| {
                let tags_json: String = row.get(7)?;
                let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
                let mut nonce = [0u8; 24];
                let nonce_bytes: Vec<u8> = row.get(5)?;
                if nonce_bytes.len() == 24 {
                    nonce.copy_from_slice(&nonce_bytes);
                }

                Ok(SecretEntry {
                    secret_id: row.get(0)?,
                    title: row.get(2)?,
                    username: row.get(3)?,
                    encrypted_password: row.get(4)?,
                    nonce,
                    environment: row.get(6)?,
                    tags,
                    description: row.get(8)?,
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(10)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    created_by: row.get(11)?,
                    version: row.get::<_, i64>(12)? as u64,
                    expires_at: row.get::<_, Option<String>>(13)?.and_then(|s|
                        DateTime::parse_from_rfc3339(&s).map(|dt| dt.with_timezone(&Utc)).ok()
                    ),
                })
            },
        ).map_err(|_| SecretEntryError::NotFound(secret_id.clone()))
    }

    /// 获取密码条目元信息列表
    pub fn list_secrets(
        &self,
        group_id: Option<&GroupId>,
    ) -> Result<Vec<SecretMeta>, SecretEntryError> {
        let sql = if group_id.is_some() {
            "SELECT secret_id, title, username, environment, tags, updated_at, expires_at
             FROM secrets WHERE group_id = ?1 ORDER BY updated_at DESC"
        } else {
            "SELECT secret_id, title, username, environment, tags, updated_at, expires_at
             FROM secrets ORDER BY updated_at DESC"
        };

        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| SecretEntryError::InvalidData(e.to_string()))?;

        let rows: Result<Vec<SecretMeta>, SecretEntryError> = if let Some(gid) = group_id {
            stmt.query_map([gid], |row| {
                let tags_json: String = row.get(4)?;
                let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
                Ok(SecretMeta {
                    secret_id: row.get(0)?,
                    title: row.get(1)?,
                    username: row.get(2)?,
                    environment: row.get(3)?,
                    tags,
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    expires_at: row.get::<_, Option<String>>(6)?.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|dt| dt.with_timezone(&Utc))
                            .ok()
                    }),
                })
            })?
            .collect::<Result<Vec<_>, rusqlite::Error>>()
            .map_err(SecretEntryError::from)
        } else {
            stmt.query_map([], |row| {
                let tags_json: String = row.get(4)?;
                let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
                Ok(SecretMeta {
                    secret_id: row.get(0)?,
                    title: row.get(1)?,
                    username: row.get(2)?,
                    environment: row.get(3)?,
                    tags,
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    expires_at: row.get::<_, Option<String>>(6)?.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|dt| dt.with_timezone(&Utc))
                            .ok()
                    }),
                })
            })?
            .collect::<Result<Vec<_>, rusqlite::Error>>()
            .map_err(SecretEntryError::from)
        };

        rows
    }

    /// 更新密码条目
    #[allow(clippy::too_many_arguments)]
    pub fn update_secret(
        &self,
        secret_id: &SecretId,
        new_password: Option<&str>,
        new_title: Option<&str>,
        new_username: Option<&str>,
        new_environment: Option<&str>,
        new_tags: Option<Vec<String>>,
        new_description: Option<&str>,
        new_expires_at: Option<Option<DateTime<Utc>>>,
        master_key: &[u8; 32],
    ) -> Result<SecretEntry, SecretEntryError> {
        let mut entry = self.get_secret(secret_id)?;
        let now = Utc::now();

        if let Some(title) = new_title {
            entry.title = title.to_string();
        }
        if let Some(username) = new_username {
            entry.username = username.to_string();
        }
        if let Some(environment) = new_environment {
            entry.environment = environment.to_string();
        }
        if let Some(tags) = new_tags {
            entry.tags = tags;
        }
        if let Some(description) = new_description {
            entry.description = description.to_string();
        }
        if let Some(expires_at) = new_expires_at {
            entry.expires_at = expires_at;
        }

        if let Some(password) = new_password {
            let secret_seed =
                derive_secret_seed(master_key).map_err(|_| SecretEntryError::EncryptionFailed)?;
            let per_secret_key = derive_per_secret_key(&secret_seed, secret_id)
                .map_err(|_| SecretEntryError::EncryptionFailed)?;
            let nonce = generate_nonce();
            entry.encrypted_password = encrypt(password.as_bytes(), &per_secret_key, &nonce)
                .map_err(|_| SecretEntryError::EncryptionFailed)?;
            entry.nonce = nonce;
        }

        entry.updated_at = now;
        entry.version += 1;

        let tags_json = serde_json::to_string(&entry.tags)
            .map_err(|e| SecretEntryError::InvalidData(e.to_string()))?;

        self.conn
            .execute(
                "UPDATE secrets SET
                title = ?1, username = ?2, encrypted_password = ?3, nonce = ?4,
                environment = ?5, tags = ?6, description = ?7, updated_at = ?8,
                version = ?9, expires_at = ?10
             WHERE secret_id = ?11",
                params![
                    &entry.title,
                    &entry.username,
                    &entry.encrypted_password,
                    &entry.nonce[..],
                    &entry.environment,
                    tags_json,
                    &entry.description,
                    entry.updated_at.to_rfc3339(),
                    entry.version as i64,
                    entry.expires_at.map(|t| t.to_rfc3339()),
                    secret_id,
                ],
            )
            .map_err(|e| SecretEntryError::InvalidData(e.to_string()))?;

        Ok(entry)
    }

    /// 删除密码条目
    pub fn delete_secret(&self, secret_id: &SecretId) -> Result<(), SecretEntryError> {
        let rows = self
            .conn
            .execute("DELETE FROM secrets WHERE secret_id = ?1", [secret_id])
            .map_err(|e| SecretEntryError::InvalidData(e.to_string()))?;

        if rows == 0 {
            return Err(SecretEntryError::NotFound(secret_id.clone()));
        }
        Ok(())
    }

    /// 解密密码
    pub fn decrypt_password(
        &self,
        secret_id: &SecretId,
        master_key: &[u8; 32],
    ) -> Result<String, SecretEntryError> {
        let entry = self.get_secret(secret_id)?;
        let secret_seed =
            derive_secret_seed(master_key).map_err(|_| SecretEntryError::DecryptionFailed)?;
        let per_secret_key = derive_per_secret_key(&secret_seed, secret_id)
            .map_err(|_| SecretEntryError::DecryptionFailed)?;

        let plaintext = decrypt(&entry.encrypted_password, &per_secret_key, &entry.nonce)
            .map_err(|_| SecretEntryError::DecryptionFailed)?;

        String::from_utf8(plaintext).map_err(|_| SecretEntryError::DecryptionFailed)
    }

    /// 搜索密码条目
    pub fn search_secrets(
        &self,
        group_id: Option<&GroupId>,
        query: &str,
        environment: Option<&str>,
    ) -> Result<Vec<SecretMeta>, SecretEntryError> {
        let all = self.list_secrets(group_id)?;
        let query_lower = query.to_lowercase();

        let filtered: Vec<SecretMeta> = all
            .into_iter()
            .filter(|meta| {
                let matches_query = query.is_empty()
                    || meta.title.to_lowercase().contains(&query_lower)
                    || meta.username.to_lowercase().contains(&query_lower)
                    || meta
                        .tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(&query_lower));

                let matches_env = environment
                    .map(|env| meta.environment == env)
                    .unwrap_or(true);

                matches_query && matches_env
            })
            .collect();

        Ok(filtered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::schema::init_schema;
    use rusqlite::Connection;

    fn create_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        // 插入测试组，避免外键约束失败
        conn.execute(
            "INSERT INTO groups (group_id, name, group_public_key, admin_public_key, config, created_at, updated_at)
             VALUES ('group-1', 'Test Group', X'00', X'00', X'00', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')",
            [],
        ).unwrap();
        conn
    }

    #[test]
    fn test_create_and_get_secret() {
        let conn = create_test_db();
        let store = SecretStore::new(&conn);
        let master_key = [0x42u8; 32];

        let entry = store
            .create_secret(
                &"group-1".to_string(),
                "核心交换机",
                "admin",
                "secret_password_123",
                "生产环境",
                vec!["ssh".to_string(), "network".to_string()],
                "核心网络设备",
                None,
                &"member-1".to_string(),
                &master_key,
            )
            .unwrap();

        let fetched = store.get_secret(&entry.secret_id).unwrap();
        assert_eq!(fetched.title, "核心交换机");
        assert_eq!(fetched.username, "admin");
        assert_eq!(fetched.environment, "生产环境");
        assert_eq!(fetched.tags, vec!["ssh".to_string(), "network".to_string()]);
    }

    #[test]
    fn test_decrypt_password() {
        let conn = create_test_db();
        let store = SecretStore::new(&conn);
        let master_key = [0x42u8; 32];
        let original_password = "my_super_secret_password!@#";

        let entry = store
            .create_secret(
                &"group-1".to_string(),
                "Test",
                "user",
                original_password,
                "dev",
                vec![],
                "",
                None,
                &"member-1".to_string(),
                &master_key,
            )
            .unwrap();

        let decrypted = store
            .decrypt_password(&entry.secret_id, &master_key)
            .unwrap();
        assert_eq!(decrypted, original_password);
    }

    #[test]
    fn test_list_secrets() {
        let conn = create_test_db();
        let store = SecretStore::new(&conn);
        let master_key = [0x42u8; 32];

        store
            .create_secret(
                &"group-1".to_string(),
                "Secret A",
                "user1",
                "pass1",
                "prod",
                vec![],
                "",
                None,
                &"member-1".to_string(),
                &master_key,
            )
            .unwrap();

        store
            .create_secret(
                &"group-1".to_string(),
                "Secret B",
                "user2",
                "pass2",
                "dev",
                vec![],
                "",
                None,
                &"member-1".to_string(),
                &master_key,
            )
            .unwrap();

        let list = store.list_secrets(Some(&"group-1".to_string())).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_update_secret() {
        let conn = create_test_db();
        let store = SecretStore::new(&conn);
        let master_key = [0x42u8; 32];

        let entry = store
            .create_secret(
                &"group-1".to_string(),
                "Old Title",
                "old_user",
                "old_pass",
                "dev",
                vec!["tag1".to_string()],
                "old desc",
                None,
                &"member-1".to_string(),
                &master_key,
            )
            .unwrap();

        let updated = store
            .update_secret(
                &entry.secret_id,
                Some("new_pass"),
                Some("New Title"),
                Some("new_user"),
                Some("prod"),
                Some(vec!["tag2".to_string()]),
                Some("new desc"),
                None,
                &master_key,
            )
            .unwrap();

        assert_eq!(updated.title, "New Title");
        assert_eq!(updated.username, "new_user");
        assert_eq!(updated.environment, "prod");
        assert_eq!(updated.tags, vec!["tag2".to_string()]);
        assert_eq!(updated.version, 2);

        // 验证新密码可以解密
        let decrypted = store
            .decrypt_password(&entry.secret_id, &master_key)
            .unwrap();
        assert_eq!(decrypted, "new_pass");
    }

    #[test]
    fn test_delete_secret() {
        let conn = create_test_db();
        let store = SecretStore::new(&conn);
        let master_key = [0x42u8; 32];

        let entry = store
            .create_secret(
                &"group-1".to_string(),
                "ToDelete",
                "user",
                "pass",
                "dev",
                vec![],
                "",
                None,
                &"member-1".to_string(),
                &master_key,
            )
            .unwrap();

        store.delete_secret(&entry.secret_id).unwrap();
        assert!(store.get_secret(&entry.secret_id).is_err());
    }

    #[test]
    fn test_search_secrets() {
        let conn = create_test_db();
        let store = SecretStore::new(&conn);
        let master_key = [0x42u8; 32];

        store
            .create_secret(
                &"group-1".to_string(),
                "Production DB",
                "dbadmin",
                "pass1",
                "prod",
                vec!["database".to_string()],
                "",
                None,
                &"member-1".to_string(),
                &master_key,
            )
            .unwrap();

        store
            .create_secret(
                &"group-1".to_string(),
                "Dev Server",
                "devuser",
                "pass2",
                "dev",
                vec!["server".to_string()],
                "",
                None,
                &"member-1".to_string(),
                &master_key,
            )
            .unwrap();

        let results = store
            .search_secrets(Some(&"group-1".to_string()), "Production", None)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "Production DB");

        let results = store
            .search_secrets(Some(&"group-1".to_string()), "", Some("dev"))
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "Dev Server");
    }

    #[test]
    fn test_wrong_master_key_fails_decryption() {
        let conn = create_test_db();
        let store = SecretStore::new(&conn);
        let master_key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];

        let entry = store
            .create_secret(
                &"group-1".to_string(),
                "Test",
                "user",
                "secret",
                "dev",
                vec![],
                "",
                None,
                &"member-1".to_string(),
                &master_key,
            )
            .unwrap();

        let result = store.decrypt_password(&entry.secret_id, &wrong_key);
        assert!(result.is_err());
    }
}
