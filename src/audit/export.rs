//! 审计导出
//!
//! 将审计事件导出为 JSON 或 CSV 格式。

use crate::audit::event::AuditEvent;
use crate::audit::logger::{query_events, AuditLogError, AuditQuery};
use rusqlite::Connection;
use std::io::Write;

/// 导出格式
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ExportFormat {
    #[default]
    Json,
    Csv,
}

/// 导出审计事件
///
/// # 参数
/// - `conn`: 数据库连接
/// - `query`: 查询条件
/// - `format`: 导出格式
/// - `writer`: 输出写入器
pub fn export_events<W: Write>(
    conn: &Connection,
    query: &AuditQuery,
    format: ExportFormat,
    writer: &mut W,
) -> Result<usize, AuditLogError> {
    let events = query_events(conn, query)?;
    let count = events.len();

    match format {
        ExportFormat::Json => export_json(&events, writer)?,
        ExportFormat::Csv => export_csv(&events, writer)?,
    }

    Ok(count)
}

fn export_json<W: Write>(events: &[AuditEvent], writer: &mut W) -> Result<(), AuditLogError> {
    let json = serde_json::to_string_pretty(events)
        .map_err(|e| AuditLogError::Serialization(e.to_string()))?;
    writer
        .write_all(json.as_bytes())
        .map_err(|e| AuditLogError::Serialization(e.to_string()))?;
    Ok(())
}

fn export_csv<W: Write>(events: &[AuditEvent], writer: &mut W) -> Result<(), AuditLogError> {
    writeln!(writer, "event_id,operation_type,actor_member_id,target_secret_id,device_fingerprint,peer_id,client_ip,timestamp,summary")
        .map_err(|e| AuditLogError::Serialization(e.to_string()))?;

    for event in events {
        writeln!(
            writer,
            "{},{},{},{},{},{},{},{},{}",
            escape_csv(&event.event_id),
            escape_csv(&event.operation_type.to_string()),
            escape_csv(&event.actor_member_id),
            escape_csv(event.target_secret_id.as_deref().unwrap_or("")),
            escape_csv(&event.device_fingerprint),
            escape_csv(&event.peer_id),
            escape_csv(event.client_ip.as_deref().unwrap_or("")),
            escape_csv(&event.timestamp.to_rfc3339()),
            escape_csv(&event.summary),
        )
        .map_err(|e| AuditLogError::Serialization(e.to_string()))?;
    }

    Ok(())
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        let escaped = s.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        s.to_string()
    }
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use crate::audit::event::{AuditEvent, OperationType};
    use crate::audit::logger::log_event;

    fn setup_db_with_events() -> (Connection, Vec<AuditEvent>) {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::storage::schema::init_schema(&conn).unwrap();

        let mut events = Vec::new();
        for i in 0..3 {
            let event = AuditEvent::new(
                format!("evt-{}", i),
                OperationType::ViewSecret,
                format!("member-{}", i),
                "fp".to_string(),
                "peer".to_string(),
            )
            .with_secret_id(format!("secret-{}", i))
            .with_summary(format!("summary {}", i));
            log_event(&conn, &event, None).unwrap();
            events.push(event);
        }
        (conn, events)
    }

    #[test]
    fn test_export_json() {
        let (conn, _events) = setup_db_with_events();
        let mut buf = Vec::new();
        let count = export_events(&conn, &AuditQuery::default(), ExportFormat::Json, &mut buf).unwrap();
        assert_eq!(count, 3);

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("evt-0"));
        assert!(output.contains("evt-1"));
        assert!(output.contains("evt-2"));
    }

    #[test]
    fn test_export_csv() {
        let (conn, _events) = setup_db_with_events();
        let mut buf = Vec::new();
        let count = export_events(&conn, &AuditQuery::default(), ExportFormat::Csv, &mut buf).unwrap();
        assert_eq!(count, 3);

        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("event_id,operation_type"));
        assert!(output.contains("evt-0"));
        assert!(output.contains("member-1"));
        assert!(output.contains("secret-2"));
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(escape_csv("hello"), "hello");
        assert_eq!(escape_csv("hello,world"), "\"hello,world\"");
        assert_eq!(escape_csv("hello\"world"), "\"hello\"\"world\"");
        assert_eq!(escape_csv("hello\nworld"), "\"hello\nworld\"");
    }

    #[test]
    fn test_export_with_query() {
        let (conn, _events) = setup_db_with_events();
        let mut buf = Vec::new();
        let query = AuditQuery {
            actor_member_id: Some("member-1".to_string()),
            ..Default::default()
        };
        let count = export_events(&conn, &query, ExportFormat::Json, &mut buf).unwrap();
        assert_eq!(count, 1);

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("member-1"));
        assert!(!output.contains("member-0"));
    }
}
