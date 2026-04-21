//! 冲突解决策略
//!
//! 提供 Last-Writer-Wins（LWW）等冲突解决机制，
//! 用于处理多节点同时修改同一密码条目时的冲突。

use crate::secret::entry::SecretEntry;

/// 冲突解决结果
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeResult {
    /// 本地版本胜出
    LocalWins,
    /// 远程版本胜出
    RemoteWins,
    /// 需要人工介入（理论上不应发生）
    Conflict,
}

/// 冲突解决器
pub struct ConflictResolver;

impl ConflictResolver {
    /// 比较两个密码条目，根据 LWW 策略决定哪个胜出
    ///
    /// 比较规则：
    /// 1. 先比较版本号（version），高的胜出
    /// 2. 版本号相同则比较时间戳（updated_at），新的胜出
    /// 3. 时间戳也相同则比较 member_id 字典序（确定性仲裁）
    pub fn resolve_secret_conflict(
        local: &SecretEntry,
        remote: &SecretEntry,
    ) -> MergeResult {
        assert_eq!(local.secret_id, remote.secret_id);

        if local.version > remote.version {
            MergeResult::LocalWins
        } else if local.version < remote.version {
            MergeResult::RemoteWins
        } else {
            // 版本号相同，比较时间戳
            match local.updated_at.cmp(&remote.updated_at) {
                std::cmp::Ordering::Greater => MergeResult::LocalWins,
                std::cmp::Ordering::Less => MergeResult::RemoteWins,
                std::cmp::Ordering::Equal => {
                    // 时间戳也相同，使用 member_id 字典序仲裁
                    if local.created_by >= remote.created_by {
                        MergeResult::LocalWins
                    } else {
                        MergeResult::RemoteWins
                    }
                }
            }
        }
    }

    /// 删除操作优先于任何修改
    pub fn resolve_with_delete_precedence(
        local_entry: Option<&SecretEntry>,
        remote_deleted: bool,
        local_deleted: bool,
    ) -> MergeResult {
        match (local_deleted, remote_deleted) {
            (true, true) => MergeResult::LocalWins, // 双方删除，无需操作
            (true, false) => MergeResult::LocalWins, // 本地已删除，保持删除
            (false, true) => MergeResult::RemoteWins, // 远程已删除，应用删除
            (false, false) => {
                // 双方都有条目，交给 LWW 处理
                if let Some(_local) = local_entry {
                    // 这种情况应由 resolve_secret_conflict 处理
                    MergeResult::Conflict
                } else {
                    MergeResult::RemoteWins
                }
            }
        }
    }
}

/// 合并两个密码条目，返回应该保留的版本
pub fn merge_secret_entries(
    local: Option<&SecretEntry>,
    remote: Option<&SecretEntry>,
    local_deleted: bool,
    remote_deleted: bool,
) -> Option<SecretEntry> {
    // 删除优先
    if local_deleted || remote_deleted {
        // 只要有一方删除，且另一方没有更新的修改，则删除
        // 但如果另一方版本号明显更高，则保留
        match (local, remote, local_deleted, remote_deleted) {
            (Some(l), Some(r), false, true) => {
                // 本地有更新，远程已删除：如果本地版本更高，保留本地
                if l.version > r.version {
                    Some(l.clone())
                } else {
                    None
                }
            }
            (Some(l), Some(r), true, false) => {
                // 本地已删除，远程有更新：如果远程版本更高，保留远程
                if r.version > l.version {
                    Some(r.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        // 双方都未删除，使用 LWW
        match (local, remote) {
            (Some(l), Some(r)) => {
                let result = ConflictResolver::resolve_secret_conflict(l, r);
                if result == MergeResult::RemoteWins {
                    Some(r.clone())
                } else {
                    Some(l.clone())
                }
            }
            (Some(l), None) => Some(l.clone()),
            (None, Some(r)) => Some(r.clone()),
            (None, None) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::entry::SecretEntry;
    use chrono::{DateTime, Utc};

    fn make_entry(secret_id: &str, version: u64, updated_at: DateTime<Utc>, created_by: &str) -> SecretEntry {
        SecretEntry {
            secret_id: secret_id.to_string(),
            title: "test".to_string(),
            username: "user".to_string(),
            encrypted_password: vec![1, 2, 3],
            nonce: [0u8; 24],
            environment: "dev".to_string(),
            tags: vec![],
            description: "".to_string(),
            created_at: updated_at,
            updated_at,
            created_by: created_by.to_string(),
            version,
            expires_at: None,
        }
    }

    #[test]
    fn test_local_version_higher() {
        let now = Utc::now();
        let local = make_entry("s1", 5, now, "a");
        let remote = make_entry("s1", 3, now, "b");
        assert_eq!(
            ConflictResolver::resolve_secret_conflict(&local, &remote),
            MergeResult::LocalWins
        );
    }

    #[test]
    fn test_remote_timestamp_newer() {
        let now = Utc::now();
        let local = make_entry("s1", 3, now, "a");
        let remote = make_entry("s1", 3, now + chrono::Duration::seconds(10), "b");
        assert_eq!(
            ConflictResolver::resolve_secret_conflict(&local, &remote),
            MergeResult::RemoteWins
        );
    }

    #[test]
    fn test_same_version_and_time_uses_member_id() {
        let now = Utc::now();
        let local = make_entry("s1", 3, now, "bob");
        let remote = make_entry("s1", 3, now, "alice");
        // "bob" > "alice"
        assert_eq!(
            ConflictResolver::resolve_secret_conflict(&local, &remote),
            MergeResult::LocalWins
        );
    }

    #[test]
    fn test_delete_precedence() {
        let now = Utc::now();
        let local = make_entry("s1", 3, now, "a");
        let remote = make_entry("s1", 3, now, "b");

        // 远程删除，本地版本不高
        assert_eq!(
            merge_secret_entries(Some(&local), Some(&remote), false, true),
            None
        );

        // 本地删除，远程版本更高
        let remote_newer = make_entry("s1", 5, now + chrono::Duration::seconds(10), "b");
        assert_eq!(
            merge_secret_entries(Some(&local), Some(&remote_newer), true, false),
            Some(remote_newer)
        );
    }

    #[test]
    fn test_merge_both_none() {
        assert_eq!(merge_secret_entries(None, None, false, false), None);
    }
}
