//! CRDT 合并引擎
//!
//! 维护群组的 CRDT 状态，处理密码操作的合并与应用。

use crate::group::manager::GroupId;
use crate::secret::entry::{SecretEntry, SecretId, SecretOp};
use crate::sync::merge::merge_secret_entries;
use crate::sync::snapshot::{PendingOp, SyncSnapshot};
use std::collections::HashMap;

/// CRDT 引擎状态
#[derive(Clone, Debug, Default)]
pub struct CrdtEngine {
    /// 当前已知的所有密码条目（以 secret_id 为键）
    pub entries: HashMap<SecretId, SecretEntry>,
    /// 已删除的密码 ID（墓碑）
    pub tombstones: HashMap<SecretId, u64>, // secret_id -> deletion_version
    /// 同步快照
    pub snapshot: SyncSnapshot,
}

/// 操作应用结果
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyResult {
    /// 新操作被接受
    Applied,
    /// 操作已过时（已被更新的版本覆盖）
    Stale,
    /// 与本地状态冲突，已解决
    Merged,
    /// 条目已删除，拒绝更新
    RejectedDeleted,
}

/// 引擎错误
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("Entry not found: {0}")]
    NotFound(SecretId),
    #[error("Invalid operation sequence")]
    InvalidSequence,
}

impl CrdtEngine {
    /// 创建新的引擎实例
    pub fn new(group_id: GroupId) -> Self {
        Self {
            entries: HashMap::new(),
            tombstones: HashMap::new(),
            snapshot: SyncSnapshot::new(group_id),
        }
    }

    /// 应用单个 SecretOp
    pub fn apply_op(&mut self, actor: &str, op: &SecretOp) -> ApplyResult {
        match op {
            SecretOp::Create(entry) => {
                if self.tombstones.contains_key(&entry.secret_id) {
                    // 条目曾删除，但创建操作视为恢复（如果版本更高）
                    if entry.version > self.tombstones[&entry.secret_id] {
                        self.entries.insert(entry.secret_id.clone(), entry.clone());
                        self.tombstones.remove(&entry.secret_id);
                        self.snapshot.push_pending(actor.to_string(), op.clone());
                        ApplyResult::Applied
                    } else {
                        ApplyResult::Stale
                    }
                } else if self.entries.contains_key(&entry.secret_id) {
                    // 已存在，视为冲突合并
                    let existing = &self.entries[&entry.secret_id];
                    let merged = merge_secret_entries(
                        Some(existing),
                        Some(entry),
                        false,
                        false,
                    );
                    if let Some(m) = merged {
                        self.entries.insert(m.secret_id.clone(), m);
                        ApplyResult::Merged
                    } else {
                        ApplyResult::RejectedDeleted
                    }
                } else {
                    self.entries.insert(entry.secret_id.clone(), entry.clone());
                    self.snapshot.push_pending(actor.to_string(), op.clone());
                    ApplyResult::Applied
                }
            }
            SecretOp::Update {
                secret_id,
                encrypted_password,
                nonce,
                updated_at,
                updated_by,
            } => {
                if self.tombstones.contains_key(secret_id) {
                    return ApplyResult::RejectedDeleted;
                }

                if let Some(existing) = self.entries.get_mut(secret_id) {
                    // 简单 LWW：如果时间戳更新则应用
                    if *updated_at >= existing.updated_at {
                        existing.encrypted_password = encrypted_password.clone();
                        existing.nonce = *nonce;
                        existing.updated_at = *updated_at;
                        existing.version += 1;
                        existing.created_by = updated_by.clone();
                        self.snapshot.push_pending(actor.to_string(), op.clone());
                        ApplyResult::Applied
                    } else {
                        ApplyResult::Stale
                    }
                } else {
                    // 本地不存在此条目，可能是乱序到达，暂存为 pending
                    self.snapshot.push_pending(actor.to_string(), op.clone());
                    ApplyResult::Applied
                }
            }
            SecretOp::Delete {
                secret_id,
                deleted_by: _,
                deleted_at: _,
            } => {
                if let Some(entry) = self.entries.remove(secret_id) {
                    self.tombstones.insert(secret_id.clone(), entry.version);
                } else {
                    self.tombstones.insert(secret_id.clone(), 0);
                }
                self.snapshot.push_pending(actor.to_string(), op.clone());
                ApplyResult::Applied
            }
        }
    }

    /// 批量应用远程操作
    pub fn apply_remote_ops(&mut self, actor: &str, ops: &[SecretOp]) -> Vec<ApplyResult> {
        ops.iter()
            .map(|op| self.apply_op(actor, op))
            .collect()
    }

    /// 获取所有活跃条目
    pub fn active_entries(&self) -> Vec<&SecretEntry> {
        self.entries.values().collect()
    }

    /// 获取指定条目
    pub fn get_entry(&self, secret_id: &SecretId) -> Option<&SecretEntry> {
        self.entries.get(secret_id)
    }

    /// 检查条目是否已删除
    pub fn is_deleted(&self, secret_id: &SecretId) -> bool {
        self.tombstones.contains_key(secret_id)
    }

    /// 生成当前状态的快照
    pub fn to_snapshot(&self) -> SyncSnapshot {
        self.snapshot.clone()
    }

    /// 从快照恢复状态（仅恢复 metadata，entries 需外部填充）
    pub fn from_snapshot(snapshot: SyncSnapshot) -> Self {
        Self {
            entries: HashMap::new(),
            tombstones: HashMap::new(),
            snapshot,
        }
    }

    /// 获取自指定 vector clock 以来的新操作
    pub fn ops_since(&self, since_clock: &std::collections::BTreeMap<String, u64>) -> Vec<&PendingOp> {
        self.snapshot
            .pending_ops
            .iter()
            .filter(|op| {
                let current = self.snapshot.get_clock(&op.actor);
                let since = since_clock.get(&op.actor).copied().unwrap_or(0);
                current > since && op.seq > since
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::entry::SecretEntry;
    use chrono::Utc;

    fn make_entry(id: &str, version: u64, updated_at: chrono::DateTime<Utc>) -> SecretEntry {
        SecretEntry {
            secret_id: id.to_string(),
            title: "test".to_string(),
            username: "u".to_string(),
            encrypted_password: vec![1],
            nonce: [0u8; 24],
            environment: "dev".to_string(),
            tags: vec![],
            description: "".to_string(),
            created_at: updated_at,
            updated_at,
            created_by: "m1".to_string(),
            version,
            expires_at: None,
        }
    }

    #[test]
    fn test_apply_create() {
        let mut engine = CrdtEngine::new("g1".to_string());
        let entry = make_entry("s1", 1, Utc::now());
        let result = engine.apply_op("node-a", &SecretOp::Create(entry.clone()));
        assert_eq!(result, ApplyResult::Applied);
        assert!(engine.get_entry(&"s1".to_string()).is_some());
    }

    #[test]
    fn test_apply_duplicate_create_merges() {
        let mut engine = CrdtEngine::new("g1".to_string());
        let e1 = make_entry("s1", 1, Utc::now());
        let mut e2 = e1.clone();
        e2.title = "updated".to_string();
        e2.version = 2;

        engine.apply_op("node-a", &SecretOp::Create(e1));
        let result = engine.apply_op("node-b", &SecretOp::Create(e2.clone()));
        assert_eq!(result, ApplyResult::Merged);
        assert_eq!(engine.get_entry(&"s1".to_string()).unwrap().title, "updated");
    }

    #[test]
    fn test_apply_update() {
        let mut engine = CrdtEngine::new("g1".to_string());
        let entry = make_entry("s1", 1, Utc::now());
        engine.apply_op("node-a", &SecretOp::Create(entry));

        let now = Utc::now();
        let update = SecretOp::Update {
            secret_id: "s1".to_string(),
            encrypted_password: vec![9, 9, 9],
            nonce: [1u8; 24],
            updated_at: now,
            updated_by: "m2".to_string(),
        };
        let result = engine.apply_op("node-a", &update);
        assert_eq!(result, ApplyResult::Applied);
        assert_eq!(engine.get_entry(&"s1".to_string()).unwrap().encrypted_password, vec![9, 9, 9]);
        assert_eq!(engine.get_entry(&"s1".to_string()).unwrap().version, 2);
    }

    #[test]
    fn test_apply_delete() {
        let mut engine = CrdtEngine::new("g1".to_string());
        let entry = make_entry("s1", 1, Utc::now());
        engine.apply_op("node-a", &SecretOp::Create(entry));

        let delete = SecretOp::Delete {
            secret_id: "s1".to_string(),
            deleted_by: "m1".to_string(),
            deleted_at: Utc::now(),
        };
        let result = engine.apply_op("node-a", &delete);
        assert_eq!(result, ApplyResult::Applied);
        assert!(engine.get_entry(&"s1".to_string()).is_none());
        assert!(engine.is_deleted(&"s1".to_string()));
    }

    #[test]
    fn test_update_after_delete_rejected() {
        let mut engine = CrdtEngine::new("g1".to_string());
        let entry = make_entry("s1", 1, Utc::now());
        engine.apply_op("node-a", &SecretOp::Create(entry));
        engine.apply_op(
            "node-a",
            &SecretOp::Delete {
                secret_id: "s1".to_string(),
                deleted_by: "m1".to_string(),
                deleted_at: Utc::now(),
            },
        );

        let update = SecretOp::Update {
            secret_id: "s1".to_string(),
            encrypted_password: vec![9],
            nonce: [1u8; 24],
            updated_at: Utc::now(),
            updated_by: "m2".to_string(),
        };
        let result = engine.apply_op("node-a", &update);
        assert_eq!(result, ApplyResult::RejectedDeleted);
    }

    #[test]
    fn test_ops_since() {
        let mut engine = CrdtEngine::new("g1".to_string());
        engine.apply_op("node-a", &SecretOp::Create(make_entry("s1", 1, Utc::now())));
        engine.apply_op("node-a", &SecretOp::Create(make_entry("s2", 1, Utc::now())));
        engine.apply_op("node-b", &SecretOp::Create(make_entry("s3", 1, Utc::now())));

        let since = {
            let mut m = std::collections::BTreeMap::new();
            m.insert("node-a".to_string(), 1);
            m
        };
        let ops = engine.ops_since(&since);
        assert_eq!(ops.len(), 2); // node-a 的第2个 + node-b 的第1个
    }
}
