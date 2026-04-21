//! 群组成员定义
//!
//! 定义成员数据结构、成员状态、以及成员身份标识。

use crate::rbac::role::Role;
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// 成员唯一标识（ed25519 公钥 hex）
pub type MemberId = String;

/// 成员状态
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MemberStatus {
    /// 已激活，可正常参与群组
    Active,
    /// 等待管理员审批
    PendingApproval,
    /// 已被撤销权限
    Revoked,
}

/// 群组成员
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Member {
    /// 成员 ID（公钥 hex）
    pub member_id: MemberId,
    /// ed25519 公钥
    pub public_key: VerifyingKey,
    /// 角色
    pub role: Role,
    /// 设备指纹
    pub device_fingerprint: String,
    /// 加入时间
    pub joined_at: DateTime<Utc>,
    /// 成员状态
    pub status: MemberStatus,
}

impl Member {
    /// 从公钥创建成员
    pub fn from_public_key(
        public_key: VerifyingKey,
        role: Role,
        device_fingerprint: String,
    ) -> Self {
        let member_id = hex::encode(public_key.as_bytes());
        Self {
            member_id,
            public_key,
            role,
            device_fingerprint,
            joined_at: Utc::now(),
            status: MemberStatus::PendingApproval,
        }
    }

    /// 激活成员
    pub fn activate(&mut self) {
        self.status = MemberStatus::Active;
    }

    /// 撤销成员
    pub fn revoke(&mut self) {
        self.status = MemberStatus::Revoked;
    }

    /// 检查成员是否有效（Active 状态）
    pub fn is_active(&self) -> bool {
        self.status == MemberStatus::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::generate_keypair;

    #[test]
    fn test_member_creation() {
        let (_sk, vk) = generate_keypair();
        let member = Member::from_public_key(vk, Role::FreeUser, "uid:hash".to_string());
        assert_eq!(member.role, Role::FreeUser);
        assert_eq!(member.status, MemberStatus::PendingApproval);
        assert!(!member.is_active());
    }

    #[test]
    fn test_member_activate_revoke() {
        let (_sk, vk) = generate_keypair();
        let mut member = Member::from_public_key(vk, Role::AuditUser, "uid:hash".to_string());
        member.activate();
        assert!(member.is_active());
        member.revoke();
        assert!(!member.is_active());
    }

    #[test]
    fn test_member_id_matches_pubkey() {
        let (_sk, vk) = generate_keypair();
        let member = Member::from_public_key(vk, Role::Admin, "uid:hash".to_string());
        assert_eq!(member.member_id, hex::encode(vk.as_bytes()));
    }
}
