//! P2P 协议消息定义
//!
//! 定义所有通过 libp2p gossipsub 广播的消息类型。

use crate::group::manager::{DiscoveredGroup, GroupId, JoinApproval, JoinRequest};
use crate::rbac::role::Role;
use crate::secret::entry::{SecretEntry, SecretId, SecretOp};
use serde::{Deserialize, Serialize};

/// P2P 网络消息
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum P2pMessage {
    // === 群组发现 ===
    /// mDNS 等效广播：群组公告
    GroupAnnounce(DiscoveredGroup),
    /// 申请加入群组
    JoinRequest(JoinRequest),
    /// 加入审批通过
    JoinApproved(JoinApproval),
    /// 加入被拒绝
    JoinRejected {
        group_id: GroupId,
        requester: String, // MemberId
    },

    // === 密码同步 ===
    /// 密码操作广播
    SecretOp(SecretOp),
    /// 请求全量同步
    SecretSyncRequest {
        group_id: GroupId,
        from_version: u64,
    },
    /// 全量同步响应
    SecretSyncResponse {
        group_id: GroupId,
        entries: Vec<SecretEntry>,
        crdt_state: Vec<u8>, // bincode 序列化的 SyncSnapshot
    },

    // === 权限同步 ===
    /// 角色变更
    RoleChange {
        target_member: String,
        old_role: Role,
        new_role: Role,
        changed_by: String,
        timestamp: String,
    },

    // === 区块链同步 ===
    /// 新区块广播（简化版：直接广播审计事件列表）
    AuditEventsBatch {
        group_id: GroupId,
        events: Vec<AuditEventBrief>,
    },
    /// 链同步请求
    ChainSyncRequest {
        group_id: GroupId,
        from_height: u64,
    },
    /// 心跳/保活
    Heartbeat {
        group_id: GroupId,
        peer_id: String,
        timestamp: String,
    },
}

/// 简化的审计事件（用于 P2P 广播，避免依赖完整的 audit 模块）
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEventBrief {
    pub event_id: String,
    pub timestamp: String,
    pub operation_type: String,
    pub actor_member_id: String,
    pub target_secret_id: Option<SecretId>,
    pub signature: Vec<u8>,
}

/// 序列化 P2pMessage 为 bytes（使用 bincode）
pub fn serialize_message(msg: &P2pMessage) -> Result<Vec<u8>, ProtocolError> {
    bincode::serialize(msg).map_err(|e| ProtocolError::Serialize(e.to_string()))
}

/// 从 bytes 反序列化 P2pMessage
pub fn deserialize_message(data: &[u8]) -> Result<P2pMessage, ProtocolError> {
    bincode::deserialize(data).map_err(|e| ProtocolError::Deserialize(e.to_string()))
}

/// 协议错误
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Serialization failed: {0}")]
    Serialize(String),
    #[error("Deserialization failed: {0}")]
    Deserialize(String),
}

/// 生成 gossipsub topic 名称
pub fn topic_name(group_id: &str, category: &str) -> String {
    format!("synapsevault/{}/{}", group_id, category)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::generate_keypair;
    use chrono::Utc;

    #[test]
    fn test_serialize_deserialize_secret_op() {
        let (_sk, _vk) = generate_keypair();
        let entry = SecretEntry {
            secret_id: "s1".to_string(),
            title: "t".to_string(),
            username: "u".to_string(),
            encrypted_password: vec![1, 2, 3],
            nonce: [0u8; 24],
            environment: "dev".to_string(),
            tags: vec![],
            description: "".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "m1".to_string(),
            version: 1,
            expires_at: None,
        };
        let msg = P2pMessage::SecretOp(SecretOp::Create(entry));
        let bytes = serialize_message(&msg).unwrap();
        let decoded = deserialize_message(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_topic_name_format() {
        assert_eq!(
            topic_name("group-abc", "secrets"),
            "synapsevault/group-abc/secrets"
        );
    }

    #[test]
    fn test_heartbeat_serde() {
        let msg = P2pMessage::Heartbeat {
            group_id: "g1".to_string(),
            peer_id: "peer-1".to_string(),
            timestamp: Utc::now().to_rfc3339(),
        };
        let bytes = serialize_message(&msg).unwrap();
        let decoded = deserialize_message(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }
}
