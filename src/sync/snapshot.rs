//! 同步状态快照
//!
//! 保存和恢复 CRDT 同步状态，包括 vector clock 和待处理的操作。

use crate::group::manager::GroupId;
use crate::secret::entry::SecretOp;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 同步状态快照
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncSnapshot {
    /// 所属群组 ID
    pub group_id: GroupId,
    /// Vector clock：每个 actor 的最新版本号
    pub vector_clock: BTreeMap<String, u64>,
    /// 待处理的操作（尚未同步到数据库）
    pub pending_ops: Vec<PendingOp>,
    /// 最后同步时间（ISO 8601）
    pub last_sync_at: String,
}

/// 待处理操作（带序列号）
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingOp {
    /// 操作序号（单调递增）
    pub seq: u64,
    /// 操作内容
    pub op: SecretOp,
    /// 操作来源 actor
    pub actor: String,
}

impl SyncSnapshot {
    /// 创建空快照
    pub fn new(group_id: GroupId) -> Self {
        Self {
            group_id,
            vector_clock: BTreeMap::new(),
            pending_ops: Vec::new(),
            last_sync_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// 更新 vector clock
    pub fn update_clock(&mut self, actor: &str, seq: u64) {
        let entry = self.vector_clock.entry(actor.to_string()).or_insert(0);
        if seq > *entry {
            *entry = seq;
        }
    }

    /// 获取 actor 的当前序列号
    pub fn get_clock(&self, actor: &str) -> u64 {
        self.vector_clock.get(actor).copied().unwrap_or(0)
    }

    /// 添加待处理操作
    pub fn push_pending(&mut self, actor: String, op: SecretOp) {
        let seq = self.get_clock(&actor) + 1;
        self.update_clock(&actor, seq);
        self.pending_ops.push(PendingOp { seq, op, actor });
    }

    /// 清空已处理的操作
    pub fn clear_pending(&mut self) {
        self.pending_ops.clear();
        self.last_sync_at = chrono::Utc::now().to_rfc3339();
    }

    /// 序列化为 JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// 从 JSON 反序列化
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::entry::SecretEntry;
    use chrono::Utc;

    fn make_test_op(id: &str) -> SecretOp {
        SecretOp::Create(SecretEntry {
            secret_id: id.to_string(),
            title: "test".to_string(),
            username: "u".to_string(),
            encrypted_password: vec![1],
            nonce: [0u8; 24],
            environment: "dev".to_string(),
            tags: vec![],
            description: "".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "m1".to_string(),
            version: 1,
            expires_at: None,
        })
    }

    #[test]
    fn test_snapshot_clock() {
        let mut snap = SyncSnapshot::new("group-1".to_string());
        assert_eq!(snap.get_clock("node-a"), 0);
        snap.update_clock("node-a", 5);
        assert_eq!(snap.get_clock("node-a"), 5);
        snap.update_clock("node-a", 3); // 不应回退
        assert_eq!(snap.get_clock("node-a"), 5);
        snap.update_clock("node-a", 10);
        assert_eq!(snap.get_clock("node-a"), 10);
    }

    #[test]
    fn test_pending_ops() {
        let mut snap = SyncSnapshot::new("group-1".to_string());
        snap.push_pending("node-a".to_string(), make_test_op("s1"));
        snap.push_pending("node-a".to_string(), make_test_op("s2"));
        snap.push_pending("node-b".to_string(), make_test_op("s3"));

        assert_eq!(snap.pending_ops.len(), 3);
        assert_eq!(snap.get_clock("node-a"), 2);
        assert_eq!(snap.get_clock("node-b"), 1);

        snap.clear_pending();
        assert!(snap.pending_ops.is_empty());
    }

    #[test]
    fn test_snapshot_serde_roundtrip() {
        let mut snap = SyncSnapshot::new("group-1".to_string());
        snap.update_clock("node-a", 3);
        snap.push_pending("node-a".to_string(), make_test_op("s1"));

        let json = snap.to_json().unwrap();
        let restored = SyncSnapshot::from_json(&json).unwrap();
        assert_eq!(snap, restored);
    }
}
