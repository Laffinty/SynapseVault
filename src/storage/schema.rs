//! 数据库 Schema 定义与迁移
//!
//! 定义 SynapseVault 所需的所有表结构，并提供初始化与迁移功能。

use rusqlite::Connection;

use crate::storage::database::StorageError;

/// 当前 Schema 版本
pub const SCHEMA_VERSION: u32 = 2;

/// 初始化数据库 Schema（首次运行）
pub fn init_schema(conn: &Connection) -> Result<(), StorageError> {
    // 创建 local_config 表（必须先于其他表，用于记录 schema 版本）
    conn.execute(
        "CREATE TABLE IF NOT EXISTS local_config (
            key     TEXT PRIMARY KEY,
            value   TEXT NOT NULL
        );",
        [],
    )?;

    // 组信息表
    conn.execute(
        "CREATE TABLE IF NOT EXISTS groups (
            group_id            TEXT PRIMARY KEY,
            name                TEXT NOT NULL,
            group_public_key    BLOB NOT NULL,
            admin_public_key    BLOB NOT NULL,
            config              BLOB NOT NULL,
            created_at          TEXT NOT NULL,
            updated_at          TEXT NOT NULL
        );",
        [],
    )?;

    // 成员表
    conn.execute(
        "CREATE TABLE IF NOT EXISTS members (
            member_id           TEXT PRIMARY KEY,
            group_id            TEXT NOT NULL,
            public_key          BLOB NOT NULL,
            role                TEXT NOT NULL,
            device_fingerprint  TEXT NOT NULL,
            status              TEXT NOT NULL,
            joined_at           TEXT NOT NULL,
            FOREIGN KEY (group_id) REFERENCES groups(group_id)
        );",
        [],
    )?;

    // 密码条目表
    conn.execute(
        "CREATE TABLE IF NOT EXISTS secrets (
            secret_id           TEXT PRIMARY KEY,
            group_id            TEXT NOT NULL DEFAULT '',
            title               TEXT NOT NULL,
            username            TEXT NOT NULL,
            encrypted_password  BLOB NOT NULL,
            nonce               BLOB NOT NULL,
            environment         TEXT NOT NULL DEFAULT '',
            tags                TEXT NOT NULL DEFAULT '[]',
            description         TEXT NOT NULL DEFAULT '',
            created_at          TEXT NOT NULL,
            updated_at          TEXT NOT NULL,
            created_by          TEXT NOT NULL,
            version             INTEGER NOT NULL DEFAULT 1,
            expires_at          TEXT,
            crdt_state          BLOB,
            FOREIGN KEY (group_id) REFERENCES groups(group_id)
        );",
        [],
    )?;

    // 密码条目索引
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_secrets_group ON secrets(group_id);",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_secrets_env ON secrets(environment);",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_secrets_expires ON secrets(expires_at);",
        [],
    )?;

    // 区块链表
    conn.execute(
        "CREATE TABLE IF NOT EXISTS blocks (
            height          INTEGER PRIMARY KEY,
            group_id        TEXT NOT NULL,
            prev_hash       BLOB NOT NULL,
            timestamp       TEXT NOT NULL,
            signer_pubkey   BLOB NOT NULL,
            signature       BLOB NOT NULL,
            merkle_root     BLOB NOT NULL,
            nonce           INTEGER NOT NULL,
            ops_data        BLOB NOT NULL,
            block_hash      BLOB NOT NULL,
            FOREIGN KEY (group_id) REFERENCES groups(group_id)
        );",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_blocks_group ON blocks(group_id);",
        [],
    )?;

    // 审计事件索引表
    conn.execute(
        "CREATE TABLE IF NOT EXISTS audit_index (
            event_id            TEXT PRIMARY KEY,
            block_height        INTEGER,
            operation_type      TEXT NOT NULL,
            actor_member_id     TEXT NOT NULL,
            target_secret_id    TEXT,
            device_fingerprint  TEXT NOT NULL,
            peer_id             TEXT NOT NULL,
            client_ip           TEXT,
            timestamp           TEXT NOT NULL,
            signature           BLOB NOT NULL DEFAULT X''
        );",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_index(operation_type);",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_index(actor_member_id);",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_index(timestamp);",
        [],
    )?;

    // CRDT 同步状态表
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sync_state (
            group_id        TEXT PRIMARY KEY,
            vector_clock    BLOB NOT NULL,
            last_sync_at    TEXT NOT NULL,
            pending_ops     BLOB NOT NULL
        );",
        [],
    )?;

    // 记录/更新 schema 版本
    conn.execute(
        "INSERT OR REPLACE INTO local_config (key, value) VALUES ('schema_version', ?1);",
        [SCHEMA_VERSION.to_string()],
    )?;

    Ok(())
}

/// 执行数据库迁移
///
/// 从当前版本迁移到目标版本。
pub fn migrate(conn: &Connection, target_version: u32) -> Result<(), StorageError> {
    let current_version: u32 = conn
        .query_row(
            "SELECT value FROM local_config WHERE key = 'schema_version'",
            [],
            |row| {
                let s: String = row.get(0)?;
                s.parse().map_err(|_| rusqlite::Error::InvalidQuery)
            },
        )
        .unwrap_or(0);

    if current_version >= target_version {
        return Ok(());
    }

    // 目前只有版本 1，后续迁移在这里添加
    if current_version < 1 && target_version >= 1 {
        init_schema(conn)?;
    }
    if current_version < 2 && target_version >= 2 {
        // 为 audit_index 添加 signature 列（如果不存在）
        let _ = conn.execute(
            "ALTER TABLE audit_index ADD COLUMN signature BLOB NOT NULL DEFAULT X''",
            [],
        );
    }

    conn.execute(
        "INSERT OR REPLACE INTO local_config (key, value) VALUES ('schema_version', ?1);",
        [target_version.to_string()],
    )?;

    Ok(())
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn test_init_schema_creates_tables() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        let tables = [
            "groups",
            "members",
            "secrets",
            "blocks",
            "audit_index",
            "sync_state",
            "local_config",
        ];
        for table in &tables {
            let count: i64 = conn
                .query_row(
                    &format!(
                        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{}'",
                        table
                    ),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "Table {} should exist", table);
        }
    }

    #[test]
    fn test_migrate_sets_version() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn, 1).unwrap();

        let version: String = conn
            .query_row(
                "SELECT value FROM local_config WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, "1");
    }

    #[test]
    fn test_migrate_no_downgrade() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        // 迁移到版本 1 不应失败（当前已经是 1）
        migrate(&conn, 1).unwrap();
    }
}
