//! 审计日志写入
//!
//! 将审计事件写入数据库，支持查询和分页。

use crate::audit::event::{AuditEvent, OperationType};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};

/// 审计日志错误
#[derive(Debug, thiserror::Error)]
pub enum AuditLogError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// 审计日志查询条件
#[derive(Clone, Debug, Default)]
pub struct AuditQuery {
    pub operation_type: Option<OperationType>,
    pub actor_member_id: Option<String>,
    pub target_secret_id: Option<String>,
    pub from_time: Option<DateTime<Utc>>,
    pub to_time: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// 写入审计事件到数据库
pub fn log_event(conn: &Connection, event: &AuditEvent, block_height: Option<i64>) -> Result<(), AuditLogError> {
    conn.execute(
        "INSERT OR REPLACE INTO audit_index (
            event_id, block_height, operation_type, actor_member_id,
            target_secret_id, device_fingerprint, peer_id, client_ip, timestamp
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            &event.event_id,
            block_height,
            event.operation_type.to_string(),
            &event.actor_member_id,
            event.target_secret_id.as_deref(),
            &event.device_fingerprint,
            &event.peer_id,
            event.client_ip.as_deref(),
            event.timestamp.to_rfc3339(),
        ],
    )?;
    Ok(())
}

/// 检查事件是否已存在（用于 P2P 同步去重）
pub fn event_exists(conn: &Connection, event_id: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM audit_index WHERE event_id = ?1",
        params![event_id],
        |row| row.get::<_, i64>(0),
    )
    .unwrap_or(0)
        > 0
}

/// 同步远程审计事件到本地数据库（去重）
pub fn sync_event(conn: &Connection, event: &AuditEvent, block_height: Option<i64>) -> Result<bool, AuditLogError> {
    if event_exists(conn, &event.event_id) {
        return Ok(false); // 已存在，跳过
    }
    log_event(conn, event, block_height)?;
    Ok(true)
}

/// 根据条件查询审计事件
pub fn query_events(conn: &Connection, query: &AuditQuery) -> Result<Vec<AuditEvent>, AuditLogError> {
    let mut sql = String::from(
        "SELECT event_id, operation_type, actor_member_id, target_secret_id,
                device_fingerprint, peer_id, client_ip, timestamp
         FROM audit_index WHERE 1=1"
    );
    let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(ref op) = query.operation_type {
        sql.push_str(" AND operation_type = ?");
        params_vec.push(Box::new(op.to_string()));
    }
    if let Some(ref actor) = query.actor_member_id {
        sql.push_str(" AND actor_member_id = ?");
        params_vec.push(Box::new(actor.clone()));
    }
    if let Some(ref secret_id) = query.target_secret_id {
        sql.push_str(" AND target_secret_id = ?");
        params_vec.push(Box::new(secret_id.clone()));
    }
    if let Some(ref from) = query.from_time {
        sql.push_str(" AND timestamp >= ?");
        params_vec.push(Box::new(from.to_rfc3339()));
    }
    if let Some(ref to) = query.to_time {
        sql.push_str(" AND timestamp <= ?");
        params_vec.push(Box::new(to.to_rfc3339()));
    }

    sql.push_str(" ORDER BY timestamp DESC");

    if let Some(limit) = query.limit {
        sql.push_str(&format!(" LIMIT {}", limit));
    }
    if let Some(offset) = query.offset {
        sql.push_str(&format!(" OFFSET {}", offset));
    }

    let param_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(&param_refs[..], |row| {
        let event_id: String = row.get(0)?;
        let op_str: String = row.get(1)?;
        let actor: String = row.get(2)?;
        let secret_id: Option<String> = row.get(3)?;
        let device_fp: String = row.get(4)?;
        let peer_id: String = row.get(5)?;
        let client_ip: Option<String> = row.get(6)?;
        let timestamp: String = row.get(7)?;

        let operation_type = parse_operation_type(&op_str);
        let timestamp = timestamp.parse().map_err(|e: chrono::ParseError| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
        })?;

        let mut event = AuditEvent {
            event_id,
            operation_type,
            actor_member_id: actor,
            target_secret_id: secret_id,
            device_fingerprint: device_fp,
            peer_id,
            client_ip,
            timestamp,
            summary: String::new(),
            event_hash: [0u8; 32],
        };
        event.update_hash();
        Ok(event)
    })?;

    let mut events = Vec::new();
    for row in rows {
        events.push(row?);
    }
    Ok(events)
}

/// 获取最近的审计事件
pub fn recent_events(conn: &Connection, limit: usize) -> Result<Vec<AuditEvent>, AuditLogError> {
    query_events(
        conn,
        &AuditQuery {
            limit: Some(limit),
            ..Default::default()
        },
    )
}

/// 获取事件总数
pub fn count_events(conn: &Connection) -> Result<usize, AuditLogError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM audit_index",
        [],
        |row| row.get(0),
    )?;
    Ok(count as usize)
}

pub fn parse_operation_type(s: &str) -> OperationType {
    match s {
        "解锁应用" => OperationType::Unlock,
        "查看密码" => OperationType::ViewSecret,
        "复制密码" => OperationType::CopySecret,
        "创建密码" => OperationType::CreateSecret,
        "更新密码" => OperationType::UpdateSecret,
        "删除密码" => OperationType::DeleteSecret,
        "申请加入" => OperationType::MemberJoin,
        "审批通过" => OperationType::MemberApprove,
        "拒绝加入" => OperationType::MemberReject,
        "移除成员" => OperationType::MemberRemove,
        "变更角色" => OperationType::RoleChange,
        "使用请求" => OperationType::UsageRequest,
        "使用审批" => OperationType::UsageApprove,
        "创建群组" => OperationType::GroupCreate,
        "生成区块" => OperationType::BlockProduced,
        _ => OperationType::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::event::AuditEvent;
    use rusqlite::Connection;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::storage::schema::init_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn test_log_and_query_event() {
        let conn = setup_db();
        let event = AuditEvent::new(
            "evt-1".to_string(),
            OperationType::ViewSecret,
            "member-1".to_string(),
            "fp-1".to_string(),
            "peer-1".to_string(),
        )
        .with_secret_id("secret-1".to_string());

        log_event(&conn, &event, Some(1)).unwrap();

        let events = query_events(&conn, &AuditQuery::default()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-1");
        assert_eq!(events[0].operation_type, OperationType::ViewSecret);
    }

    #[test]
    fn test_query_by_type() {
        let conn = setup_db();
        let e1 = AuditEvent::new(
            "evt-1".to_string(),
            OperationType::ViewSecret,
            "m1".to_string(),
            "fp".to_string(),
            "peer".to_string(),
        );
        let e2 = AuditEvent::new(
            "evt-2".to_string(),
            OperationType::CopySecret,
            "m1".to_string(),
            "fp".to_string(),
            "peer".to_string(),
        );
        log_event(&conn, &e1, None).unwrap();
        log_event(&conn, &e2, None).unwrap();

        let query = AuditQuery {
            operation_type: Some(OperationType::ViewSecret),
            ..Default::default()
        };
        let events = query_events(&conn, &query).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-1");
    }

    #[test]
    fn test_query_by_actor() {
        let conn = setup_db();
        let e1 = AuditEvent::new("evt-1".to_string(), OperationType::ViewSecret, "m1".to_string(), "fp".to_string(), "peer".to_string());
        let e2 = AuditEvent::new("evt-2".to_string(), OperationType::ViewSecret, "m2".to_string(), "fp".to_string(), "peer".to_string());
        log_event(&conn, &e1, None).unwrap();
        log_event(&conn, &e2, None).unwrap();

        let query = AuditQuery {
            actor_member_id: Some("m1".to_string()),
            ..Default::default()
        };
        let events = query_events(&conn, &query).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor_member_id, "m1");
    }

    #[test]
    fn test_recent_events_limit() {
        let conn = setup_db();
        for i in 0..10 {
            let event = AuditEvent::new(
                format!("evt-{}", i),
                OperationType::ViewSecret,
                "m1".to_string(),
                "fp".to_string(),
                "peer".to_string(),
            );
            log_event(&conn, &event, None).unwrap();
        }

        let events = recent_events(&conn, 5).unwrap();
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn test_count_events() {
        let conn = setup_db();
        assert_eq!(count_events(&conn).unwrap(), 0);

        let event = AuditEvent::new("evt-1".to_string(), OperationType::GroupCreate, "m1".to_string(), "fp".to_string(), "peer".to_string());
        log_event(&conn, &event, None).unwrap();
        assert_eq!(count_events(&conn).unwrap(), 1);
    }
}
