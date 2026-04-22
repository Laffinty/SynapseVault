//! 批量导入/导出功能
//!
//! 支持 JSON 格式导出（加密密码）和 CSV 格式导出（元信息），JSON 导入。

use crate::secret::entry::{GroupId, MemberId, SecretEntry, SecretEntryError, SecretId, SecretMeta};
use crate::secret::store::SecretStore;
use rusqlite::Connection;

/// 导出格式
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretExportFormat {
    Json,
    Csv,
}

/// 导出密码条目为 JSON（加密密码原样导出，不解密）
pub fn export_secrets_json(
    entries: &[SecretEntry],
    writer: &mut impl std::io::Write,
) -> Result<usize, SecretEntryError> {
    let json = serde_json::to_string_pretty(entries)
        .map_err(|e| SecretEntryError::InvalidData(e.to_string()))?;
    writer
        .write_all(json.as_bytes())
        .map_err(|e| SecretEntryError::InvalidData(e.to_string()))?;
    Ok(entries.len())
}

/// 导出密码元信息为 CSV
pub fn export_secrets_csv(
    metas: &[SecretMeta],
    writer: &mut impl std::io::Write,
) -> Result<usize, SecretEntryError> {
    writeln!(writer, "secret_id,title,username,environment,tags,updated_at,expires_at")
        .map_err(|e| SecretEntryError::InvalidData(e.to_string()))?;

    for meta in metas {
        let tags = meta.tags.join(";");
        let expires = meta
            .expires_at
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        writeln!(
            writer,
            "{},{},{},{},{},{},{}",
            escape_csv(&meta.secret_id),
            escape_csv(&meta.title),
            escape_csv(&meta.username),
            escape_csv(&meta.environment),
            escape_csv(&tags),
            meta.updated_at.to_rfc3339(),
            expires,
        )
        .map_err(|e| SecretEntryError::InvalidData(e.to_string()))?;
    }

    Ok(metas.len())
}

/// 从 JSON 导入密码条目（需要源 master_key 解密，目标 master_key 重新加密）
pub fn import_secrets_json(
    reader: &mut impl std::io::Read,
    conn: &Connection,
    group_id: &GroupId,
    created_by: &MemberId,
    source_master_key: &[u8; 32],
    target_master_key: &[u8; 32],
) -> Result<Vec<SecretId>, SecretEntryError> {
    let mut data = String::new();
    reader
        .read_to_string(&mut data)
        .map_err(|e| SecretEntryError::InvalidData(e.to_string()))?;

    let entries: Vec<SecretEntry> = serde_json::from_str(&data)
        .map_err(|e| SecretEntryError::InvalidData(e.to_string()))?;

    let store = SecretStore::new(conn);
    let mut imported = Vec::new();

    for entry in entries {
        match store.get_secret(&entry.secret_id) {
            Ok(_) => {
                tracing::debug!("跳过已存在的密码条目: {}", entry.secret_id);
            }
            Err(_) => {
                // 解密源密码，用目标密钥重新加密并创建
                match store.decrypt_password(&entry.secret_id, source_master_key) {
                    Ok(password) => {
                        match store.create_secret(
                            group_id,
                            &entry.title,
                            &entry.username,
                            &password,
                            &entry.environment,
                            entry.tags.clone(),
                            &entry.description,
                            entry.expires_at,
                            created_by,
                            target_master_key,
                        ) {
                            Ok(_) => {
                                imported.push(entry.secret_id.clone());
                            }
                            Err(e) => {
                                tracing::warn!("导入密码条目失败 {}: {}", entry.secret_id, e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("解密导入条目失败 {}: {}", entry.secret_id, e);
                    }
                }
            }
        }
    }

    Ok(imported)
}

/// CSV 字段转义（双引号、逗号、换行）
fn escape_csv(s: &str) -> String {
    if s.contains('"') || s.contains(',') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;

    #[test]
    fn test_export_csv() {
        let metas = vec![SecretMeta {
            secret_id: "s1".to_string(),
            title: "Test, Inc".to_string(),
            username: "admin".to_string(),
            environment: "prod".to_string(),
            tags: vec!["web".to_string()],
            updated_at: chrono::Utc::now(),
            expires_at: None,
        }];

        let mut buf = Vec::new();
        let count = export_secrets_csv(&metas, &mut buf).unwrap();
        assert_eq!(count, 1);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("secret_id,title"));
        assert!(output.contains("\"Test, Inc\""));
    }

    #[test]
    fn test_escape_csv() {
        assert_eq!(escape_csv("hello"), "hello");
        assert_eq!(escape_csv("hello, world"), "\"hello, world\"");
        assert_eq!(escape_csv("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn test_export_json() {
        let entries = vec![SecretEntry {
            secret_id: "s1".to_string(),
            title: "Test".to_string(),
            username: "user".to_string(),
            encrypted_password: vec![1, 2, 3],
            nonce: [0u8; 24],
            environment: "dev".to_string(),
            tags: vec![],
            description: String::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            created_by: "m1".to_string(),
            version: 1,
            expires_at: None,
        }];

        let mut buf = Vec::new();
        let count = export_secrets_json(&entries, &mut buf).unwrap();
        assert_eq!(count, 1);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("\"secret_id\": \"s1\""));
    }
}
