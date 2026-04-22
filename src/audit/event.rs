//! 审计事件结构
//!
//! 定义所有可审计的操作事件类型。

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 审计事件唯一标识
pub type EventId = String;

/// 操作类型
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OperationType {
    /// 解锁应用
    Unlock,
    /// 查看密码明文
    ViewSecret,
    /// 复制密码到剪贴板
    CopySecret,
    /// 创建密码
    CreateSecret,
    /// 更新密码
    UpdateSecret,
    /// 删除密码
    DeleteSecret,
    /// 成员加入
    MemberJoin,
    /// 成员审批通过
    MemberApprove,
    /// 成员被拒绝
    MemberReject,
    /// 成员移除
    MemberRemove,
    /// 角色变更
    RoleChange,
    /// 使用请求
    UsageRequest,
    /// 使用审批
    UsageApprove,
    /// 群组创建
    GroupCreate,
    /// 区块生成
    BlockProduced,
    /// 其他
    Other,
}

impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            OperationType::Unlock => "解锁应用",
            OperationType::ViewSecret => "查看密码",
            OperationType::CopySecret => "复制密码",
            OperationType::CreateSecret => "创建密码",
            OperationType::UpdateSecret => "更新密码",
            OperationType::DeleteSecret => "删除密码",
            OperationType::MemberJoin => "申请加入",
            OperationType::MemberApprove => "审批通过",
            OperationType::MemberReject => "拒绝加入",
            OperationType::MemberRemove => "移除成员",
            OperationType::RoleChange => "变更角色",
            OperationType::UsageRequest => "使用请求",
            OperationType::UsageApprove => "使用审批",
            OperationType::GroupCreate => "创建群组",
            OperationType::BlockProduced => "生成区块",
            OperationType::Other => "其他",
        };
        write!(f, "{}", s)
    }
}

/// 审计事件
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    /// 事件唯一 ID
    pub event_id: EventId,
    /// 操作类型
    pub operation_type: OperationType,
    /// 执行者成员 ID
    pub actor_member_id: String,
    /// 目标密码 ID（可选）
    pub target_secret_id: Option<String>,
    /// 设备指纹
    pub device_fingerprint: String,
    /// 节点标识（PeerId 或 IP）
    pub peer_id: String,
    /// 客户端 IP（可选）
    pub client_ip: Option<String>,
    /// 事件发生时间
    pub timestamp: DateTime<Utc>,
    /// 事件摘要（额外描述）
    pub summary: String,
    /// 事件哈希（签名前计算）
    #[serde(skip)]
    pub event_hash: [u8; 32],
    /// ed25519 签名（对 event_hash 的签名）
    pub signature: Vec<u8>,
}

impl AuditEvent {
    /// 创建新审计事件
    pub fn new(
        event_id: EventId,
        operation_type: OperationType,
        actor_member_id: String,
        device_fingerprint: String,
        peer_id: String,
    ) -> Self {
        let mut event = Self {
            event_id,
            operation_type,
            actor_member_id,
            target_secret_id: None,
            device_fingerprint,
            peer_id,
            client_ip: None,
            timestamp: Utc::now(),
            summary: String::new(),
            event_hash: [0u8; 32],
            signature: Vec::new(),
        };
        event.update_hash();
        event
    }

    /// 设置目标密码 ID
    pub fn with_secret_id(mut self, secret_id: String) -> Self {
        self.target_secret_id = Some(secret_id);
        self.update_hash();
        self
    }

    /// 设置客户端 IP
    pub fn with_client_ip(mut self, ip: String) -> Self {
        self.client_ip = Some(ip);
        self.update_hash();
        self
    }

    /// 设置摘要
    pub fn with_summary(mut self, summary: String) -> Self {
        self.summary = summary;
        self.update_hash();
        self
    }

    /// 计算事件哈希
    pub fn compute_hash(&self) -> [u8; 32] {
        let data = bincode::serialize(&(
            &self.event_id,
            &self.operation_type,
            &self.actor_member_id,
            &self.target_secret_id,
            &self.device_fingerprint,
            &self.peer_id,
            &self.client_ip,
            &self.timestamp.to_rfc3339(),
            &self.summary,
        ))
        .expect("audit event serialization");
        let mut hasher = Sha256::new();
        hasher.update(&data);
        hasher.finalize().into()
    }

    /// 更新缓存哈希
    pub fn update_hash(&mut self) {
        self.event_hash = self.compute_hash();
    }

    /// 验证哈希
    pub fn verify_hash(&self) -> bool {
        self.event_hash == self.compute_hash()
    }

    /// 使用 ed25519 私钥对事件哈希签名
    pub fn sign(&mut self, signing_key: &SigningKey) {
        self.update_hash();
        self.signature = signing_key.sign(&self.event_hash).to_bytes().to_vec();
    }

    /// 验证签名
    pub fn verify_signature(&self, verifying_key: &ed25519_dalek::VerifyingKey) -> bool {
        if self.signature.len() != 64 {
            return false;
        }
        let sig_bytes: [u8; 64] = match self.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key.verify_strict(&self.event_hash, &signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            "evt-1".to_string(),
            OperationType::ViewSecret,
            "member-1".to_string(),
            "fp-1".to_string(),
            "peer-1".to_string(),
        );
        assert_eq!(event.operation_type, OperationType::ViewSecret);
        assert!(event.verify_hash());
    }

    #[test]
    fn test_audit_event_with_fields() {
        let event = AuditEvent::new(
            "evt-2".to_string(),
            OperationType::CopySecret,
            "member-2".to_string(),
            "fp-2".to_string(),
            "peer-2".to_string(),
        )
        .with_secret_id("secret-1".to_string())
        .with_client_ip("192.168.1.1".to_string())
        .with_summary("复制了生产环境密码".to_string());

        assert_eq!(event.target_secret_id, Some("secret-1".to_string()));
        assert_eq!(event.client_ip, Some("192.168.1.1".to_string()));
        assert_eq!(event.summary, "复制了生产环境密码");
        assert!(event.verify_hash());
    }

    #[test]
    fn test_event_hash_changes_with_content() {
        let mut event = AuditEvent::new(
            "evt-3".to_string(),
            OperationType::CreateSecret,
            "member-3".to_string(),
            "fp-3".to_string(),
            "peer-3".to_string(),
        );
        let hash1 = event.event_hash;
        event.summary = "modified".to_string();
        event.update_hash();
        let hash2 = event.event_hash;
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_operation_type_display() {
        assert_eq!(OperationType::ViewSecret.to_string(), "查看密码");
        assert_eq!(OperationType::MemberApprove.to_string(), "审批通过");
    }

    #[test]
    fn test_serde_roundtrip() {
        let event = AuditEvent::new(
            "evt-4".to_string(),
            OperationType::BlockProduced,
            "member-4".to_string(),
            "fp-4".to_string(),
            "peer-4".to_string(),
        )
        .with_summary("区块高度 42".to_string());

        let json = serde_json::to_string(&event).unwrap();
        let de: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.event_id, de.event_id);
        assert_eq!(event.operation_type, de.operation_type);
        assert_eq!(event.actor_member_id, de.actor_member_id);
    }
}
