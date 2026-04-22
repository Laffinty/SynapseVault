//! 群组管理器
//!
//! 提供创建群组、成员管理、加入审批等核心逻辑。

use crate::auth::device_fingerprint::DeviceFingerprint;
use crate::crypto::signing;
use crate::group::group_key::GroupSigningKey;
use crate::group::member::{Member, MemberId};
use crate::rbac::role::Role;
use chrono::{DateTime, Utc};
use crdts::{CmRDT, Orswot};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// 群组唯一标识（ed25519 公钥哈希前 16 字节 hex）
pub type GroupId = String;

/// 群组配置
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupConfig {
    /// gossip 端口，默认 42424
    pub gossip_port: u16,
    /// 最大成员数，默认 50
    pub max_members: u32,
    /// 新成员是否需要审批，默认 true
    pub require_approval: bool,
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            gossip_port: 42424,
            max_members: 50,
            require_approval: true,
        }
    }
}

/// 群组信息
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    /// 群组唯一 ID
    pub group_id: GroupId,
    /// 群组名称
    pub name: String,
    /// 群组公钥（用于验证群组级签名）
    pub group_public_key: VerifyingKey,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 管理员公钥
    pub admin_public_key: VerifyingKey,
    /// 成员集合（CRDT OR-Set，以 member_id 为元素）
    pub members: Orswot<MemberId, String>,
    /// 成员详细信息（以 member_id 为键）
    pub member_map: HashMap<MemberId, Member>,
    /// 群组配置
    pub config: GroupConfig,
}

/// 发现的群组（mDNS 广播信息）
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredGroup {
    /// 群组 ID
    pub group_id: GroupId,
    /// 群组名称
    pub name: String,
    /// 管理员公钥 SHA-256 前 8 字节 hex
    pub admin_pubkey_hash: String,
    /// gossip 端口
    pub port: u16,
    /// libp2p PeerId（字符串形式）
    pub peer_id: String,
    /// 发现时间
    pub discovered_at: DateTime<Utc>,
}

/// 加入请求
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinRequest {
    /// 目标群组 ID
    pub group_id: GroupId,
    /// 请求者公钥
    pub requester_public_key: VerifyingKey,
    /// 请求者设备指纹
    pub device_fingerprint: String,
    /// 请求时间
    pub timestamp: DateTime<Utc>,
    /// 请求者签名
    pub signature: Signature,
}

/// 加入审批结果
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinApproval {
    /// 群组 ID
    pub group_id: GroupId,
    /// 被批准的成员
    pub member: Member,
    /// 管理员审批签名
    pub approval_signature: Signature,
}

/// 群组操作错误
#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("Member not found: {0}")]
    MemberNotFound(MemberId),
    #[error("Member already exists: {0}")]
    MemberAlreadyExists(MemberId),
    #[error("Permission denied: Admin required")]
    NotAdmin,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Group is full (max {0})")]
    GroupFull(u32),
    #[error("Join request expired")]
    RequestExpired,
    #[error("Member not pending")]
    NotPending,
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// 生成群组 ID（基于公钥哈希前 16 字节 hex）
pub fn generate_group_id(public_key: &VerifyingKey) -> GroupId {
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    hex::encode(&hash[..16])
}

/// 计算管理员公钥短哈希（用于 mDNS 广播）
pub fn admin_pubkey_short_hash(public_key: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    hex::encode(&hash[..8])
}

/// 创建新群组（当前用户成为 Admin）
pub fn create_group(
    name: &str,
    admin_signing_key: &SigningKey,
    config: GroupConfig,
) -> Result<(Group, GroupSigningKey), GroupError> {
    if name.is_empty() || name.len() > 64 {
        return Err(GroupError::Serialization("组名长度必须在 1-64 字符之间".to_string()));
    }
    let admin_public_key = admin_signing_key.verifying_key();
    let group_signing_key = GroupSigningKey::generate();
    let group_id = generate_group_id(&group_signing_key.public_key);

    let mut group = Group {
        group_id: group_id.clone(),
        name: name.to_string(),
        group_public_key: group_signing_key.public_key,
        created_at: Utc::now(),
        admin_public_key,
        members: Orswot::new(),
        member_map: HashMap::new(),
        config,
    };

    // Admin 自动加入并激活
    let mut admin_member = Member::from_public_key(
        admin_public_key,
        Role::Admin,
        "admin_device".to_string(),
    );
    admin_member.activate();
    let actor = group_id.clone();
    let add_ctx = group.members.read_ctx().derive_add_ctx(actor);
    let op = group.members.add(admin_member.member_id.clone(), add_ctx);
    group.members.apply(op);
    group.member_map.insert(admin_member.member_id.clone(), admin_member);

    Ok((group, group_signing_key))
}

/// 构建加入请求
pub fn request_join(
    group: &DiscoveredGroup,
    my_signing_key: &SigningKey,
    device_fingerprint: &DeviceFingerprint,
) -> Result<JoinRequest, GroupError> {
    let requester_public_key = my_signing_key.verifying_key();
    let timestamp = Utc::now();

    // 签名内容：group_id || pubkey || timestamp || fingerprint
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(group.group_id.as_bytes());
    sign_data.extend_from_slice(requester_public_key.as_bytes());
    sign_data.extend_from_slice(timestamp.to_rfc3339().as_bytes());
    sign_data.extend_from_slice(device_fingerprint.combined.as_bytes());

    let signature = signing::sign(my_signing_key, &sign_data);

    Ok(JoinRequest {
        group_id: group.group_id.clone(),
        requester_public_key,
        device_fingerprint: device_fingerprint.combined.clone(),
        timestamp,
        signature,
    })
}

/// 验证加入请求签名
pub fn verify_join_request(request: &JoinRequest) -> Result<(), GroupError> {
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(request.group_id.as_bytes());
    sign_data.extend_from_slice(request.requester_public_key.as_bytes());
    sign_data.extend_from_slice(request.timestamp.to_rfc3339().as_bytes());
    sign_data.extend_from_slice(request.device_fingerprint.as_bytes());

    signing::verify(&request.requester_public_key, &sign_data, &request.signature)
        .map_err(|_| GroupError::InvalidSignature)
}

/// Admin 批准加入请求
pub fn approve_join(
    group: &mut Group,
    request: &JoinRequest,
    admin_signing_key: &SigningKey,
) -> Result<JoinApproval, GroupError> {
    // 验证请求者签名
    verify_join_request(request)?;

    // 检查是否为 Admin
    let admin_pubkey = admin_signing_key.verifying_key();
    let admin_id = hex::encode(admin_pubkey.as_bytes());
    if !group.member_map.contains_key(&admin_id) {
        return Err(GroupError::NotAdmin);
    }

    // 检查群组成员上限
    if group.member_map.len() >= group.config.max_members as usize {
        return Err(GroupError::GroupFull(group.config.max_members));
    }

    let member_id = hex::encode(request.requester_public_key.as_bytes());
    if group.member_map.contains_key(&member_id) {
        return Err(GroupError::MemberAlreadyExists(member_id));
    }

    // 创建新成员
    let mut member = Member::from_public_key(
        request.requester_public_key,
        Role::FreeUser,
        request.device_fingerprint.clone(),
    );
    member.activate();

    // 添加到 CRDT 集合
    let actor = group.group_id.clone();
    let add_ctx = group.members.read_ctx().derive_add_ctx(actor);
    let op = group.members.add(member_id.clone(), add_ctx);
    group.members.apply(op);
    group.member_map.insert(member_id.clone(), member.clone());

    // 生成审批签名
    let mut approval_data = Vec::new();
    approval_data.extend_from_slice(group.group_id.as_bytes());
    approval_data.extend_from_slice(member_id.as_bytes());
    approval_data.extend_from_slice(b"APPROVED");
    let approval_signature = signing::sign(admin_signing_key, &approval_data);

    Ok(JoinApproval {
        group_id: group.group_id.clone(),
        member,
        approval_signature,
    })
}

/// Admin 拒绝加入请求
pub fn reject_join(
    group: &mut Group,
    request: &JoinRequest,
    admin_signing_key: &SigningKey,
) -> Result<(), GroupError> {
    // 验证请求者签名
    verify_join_request(request)?;

    // 检查是否为 Admin
    let admin_pubkey = admin_signing_key.verifying_key();
    let admin_id = hex::encode(admin_pubkey.as_bytes());
    if !group.member_map.contains_key(&admin_id) {
        return Err(GroupError::NotAdmin);
    }

    // 拒绝无需修改群组状态，但已验证权限和请求真实性
    // 调用者应通过 P2P 向请求者发送拒绝通知
    Ok(())
}

/// Admin 移除成员
pub fn remove_member(
    group: &mut Group,
    member_id: &MemberId,
    admin_signing_key: &SigningKey,
) -> Result<(), GroupError> {
    let admin_pubkey = admin_signing_key.verifying_key();
    let admin_id = hex::encode(admin_pubkey.as_bytes());

    if !group.member_map.contains_key(&admin_id) {
        return Err(GroupError::NotAdmin);
    }

    if !group.member_map.contains_key(member_id) {
        return Err(GroupError::MemberNotFound(member_id.clone()));
    }

    // 不能移除自己（Admin 必须转移权限后才能离开）
    if member_id == &admin_id {
        return Err(GroupError::NotAdmin);
    }

    // 从 CRDT 中移除
    let _actor = group.group_id.clone();
    let read_ctx = group.members.read_ctx();
    let rm_ctx = read_ctx.derive_rm_ctx();
    let op = group.members.rm(member_id.clone(), rm_ctx);
    group.members.apply(op);

    // 标记为已撤销
    if let Some(member) = group.member_map.get_mut(member_id) {
        member.revoke();
    }

    Ok(())
}

/// 从成员列表中获取活跃成员
pub fn active_members(group: &Group) -> Vec<&Member> {
    group
        .member_map
        .values()
        .filter(|m| m.is_active())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::device_fingerprint::generate_device_fingerprint;

    #[test]
    fn test_create_group() {
        let (sk, _vk) = signing::generate_keypair();
        let (group, gsk) = create_group("TestGroup", &sk, GroupConfig::default()).unwrap();
        assert_eq!(group.name, "TestGroup");
        assert_eq!(group.group_public_key, gsk.public_key);
        assert_eq!(group.config.max_members, 50);
        assert_eq!(group.member_map.len(), 1);
    }

    #[test]
    fn test_group_id_deterministic() {
        let (_sk, vk) = signing::generate_keypair();
        let id1 = generate_group_id(&vk);
        let id2 = generate_group_id(&vk);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32); // 16 bytes hex = 32 chars
    }

    #[test]
    fn test_join_request_and_approve() {
        let (admin_sk, _admin_vk) = signing::generate_keypair();
        let (user_sk, user_vk) = signing::generate_keypair();
        let (mut group, _gsk) = create_group("TestGroup", &admin_sk, GroupConfig::default()).unwrap();

        let dg = DiscoveredGroup {
            group_id: group.group_id.clone(),
            name: group.name.clone(),
            admin_pubkey_hash: admin_pubkey_short_hash(&group.admin_public_key),
            port: group.config.gossip_port,
            peer_id: "peer-123".to_string(),
            discovered_at: Utc::now(),
        };

        let fp = generate_device_fingerprint(&user_vk);
        let request = request_join(&dg, &user_sk, &fp).unwrap();
        assert_eq!(request.group_id, group.group_id);

        // 验证请求签名
        assert!(verify_join_request(&request).is_ok());

        // Admin 审批
        let approval = approve_join(&mut group, &request, &admin_sk).unwrap();
        assert_eq!(approval.member.public_key, user_vk);
        assert!(group.member_map.contains_key(&approval.member.member_id));
        assert!(group.member_map[&approval.member.member_id].is_active());
    }

    #[test]
    fn test_remove_member() {
        let (admin_sk, _admin_vk) = signing::generate_keypair();
        let (user_sk, user_vk) = signing::generate_keypair();
        let (mut group, _gsk) = create_group("TestGroup", &admin_sk, GroupConfig::default()).unwrap();

        let dg = DiscoveredGroup {
            group_id: group.group_id.clone(),
            name: group.name.clone(),
            admin_pubkey_hash: admin_pubkey_short_hash(&group.admin_public_key),
            port: group.config.gossip_port,
            peer_id: "peer-123".to_string(),
            discovered_at: Utc::now(),
        };

        let fp = generate_device_fingerprint(&user_vk);
        let request = request_join(&dg, &user_sk, &fp).unwrap();
        let approval = approve_join(&mut group, &request, &admin_sk).unwrap();
        let member_id = approval.member.member_id;

        assert!(group.member_map[&member_id].is_active());

        // 移除成员
        remove_member(&mut group, &member_id, &admin_sk).unwrap();
        assert!(!group.member_map[&member_id].is_active());
    }

    #[test]
    fn test_admin_cannot_remove_self() {
        let (admin_sk, _admin_vk) = signing::generate_keypair();
        let (mut group, _gsk) = create_group("TestGroup", &admin_sk, GroupConfig::default()).unwrap();

        let admin_id = hex::encode(admin_sk.verifying_key().as_bytes());
        let result = remove_member(&mut group, &admin_id, &admin_sk);
        assert!(result.is_err());
    }

    #[test]
    fn test_group_full() {
        let (admin_sk, _admin_vk) = signing::generate_keypair();
        let config = GroupConfig {
            max_members: 2,
            ..Default::default()
        };
        let (mut group, _gsk) = create_group("TestGroup", &admin_sk, config).unwrap();

        let (user_sk, user_vk) = signing::generate_keypair();
        let dg = DiscoveredGroup {
            group_id: group.group_id.clone(),
            name: group.name.clone(),
            admin_pubkey_hash: admin_pubkey_short_hash(&group.admin_public_key),
            port: group.config.gossip_port,
            peer_id: "peer-123".to_string(),
            discovered_at: Utc::now(),
        };
        let fp = generate_device_fingerprint(&user_vk);
        let request = request_join(&dg, &user_sk, &fp).unwrap();
        let result = approve_join(&mut group, &request, &admin_sk);
        assert!(result.is_ok());

        // 再加一个就会满
        let (user2_sk, user2_vk) = signing::generate_keypair();
        let fp2 = generate_device_fingerprint(&user2_vk);
        let request2 = request_join(&dg, &user2_sk, &fp2).unwrap();
        let result2 = approve_join(&mut group, &request2, &admin_sk);
        assert!(result2.is_err());
        assert!(matches!(result2.unwrap_err(), GroupError::GroupFull(2)));
    }
}
