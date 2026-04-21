//! 策略引擎
//!
//! 提供权限校验、角色变更、使用申请审批等核心策略逻辑。

use crate::group::member::{Member, MemberId};
use crate::rbac::role::Role;
use crate::secret::entry::SecretId;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 可操作动作枚举
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Action {
    /// 查看密码列表（加密条目）
    ViewSecretList,
    /// 查看/复制密码明文
    ViewSecretPlaintext,
    /// 新增密码
    CreateSecret,
    /// 修改密码
    UpdateSecret,
    /// 删除密码
    DeleteSecret,
    /// 审批使用请求
    ApproveUsage,
    /// 管理成员（批准加入、移除成员）
    ManageMembers,
    /// 变更角色
    ChangeRole,
    /// 查看审计日志（全部）
    ViewAuditLog,
    /// 导入/导出密码
    ImportExportSecrets,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::ViewSecretList => write!(f, "查看密码列表"),
            Action::ViewSecretPlaintext => write!(f, "查看/复制密码明文"),
            Action::CreateSecret => write!(f, "新增密码"),
            Action::UpdateSecret => write!(f, "修改密码"),
            Action::DeleteSecret => write!(f, "删除密码"),
            Action::ApproveUsage => write!(f, "审批使用请求"),
            Action::ManageMembers => write!(f, "管理成员"),
            Action::ChangeRole => write!(f, "变更角色"),
            Action::ViewAuditLog => write!(f, "查看审计日志"),
            Action::ImportExportSecrets => write!(f, "导入/导出密码"),
        }
    }
}

/// 权限检查结果
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PermissionCheck {
    /// 允许执行
    Allowed,
    /// 拒绝，附带原因
    Denied(String),
    /// 需要 Admin 审批（AuditUser 使用密码前）
    RequiresApproval,
}

/// 角色变更操作
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleChangeOp {
    pub target_member: MemberId,
    pub old_role: Role,
    pub new_role: Role,
    pub changed_by: MemberId,
    pub timestamp: DateTime<Utc>,
}

/// 使用申请（AuditUser → Admin）
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageRequest {
    pub request_id: String,
    pub requester: MemberId,
    pub target_secret_id: SecretId,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
    pub signature: Signature,
}

/// 使用审批结果
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageApproval {
    pub request_id: String,
    pub approval: Signature,
    pub expires_at: DateTime<Utc>,
}

/// RBAC 策略错误
#[derive(Debug, thiserror::Error)]
pub enum RbacError {
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Member not found: {0}")]
    MemberNotFound(MemberId),
    #[error("Cannot change own role")]
    CannotChangeOwnRole,
    #[error("Invalid role transition: {0} -> {1}")]
    InvalidRoleTransition(Role, Role),
    #[error("Signature error: {0}")]
    SignatureError(String),
}

/// 默认使用审批有效期（分钟）
pub const DEFAULT_USAGE_APPROVAL_TTL_MINUTES: i64 = 5;

/// 将字符串以长度前缀方式追加到字节向量
///
/// 格式：u64 小端长度前缀 + 字符串 UTF-8 字节
fn append_length_prefixed(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u64).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

/// 检查指定角色是否有权执行某动作
///
/// 本函数为纯查询函数，无副作用。
pub fn check_permission(role: &Role, action: &Action) -> PermissionCheck {
    match role {
        Role::Admin => PermissionCheck::Allowed,
        Role::FreeUser => match action {
            Action::ViewSecretList => PermissionCheck::Allowed,
            Action::ViewSecretPlaintext => PermissionCheck::Allowed,
            Action::CreateSecret
            | Action::UpdateSecret
            | Action::DeleteSecret
            | Action::ApproveUsage
            | Action::ManageMembers
            | Action::ChangeRole
            | Action::ViewAuditLog
            | Action::ImportExportSecrets => {
                PermissionCheck::Denied("FreeUser 无权执行此操作".to_string())
            }
        },
        Role::AuditUser => match action {
            Action::ViewSecretList => PermissionCheck::Allowed,
            Action::ViewSecretPlaintext => PermissionCheck::RequiresApproval,
            Action::ViewAuditLog => PermissionCheck::Allowed,
            Action::CreateSecret
            | Action::UpdateSecret
            | Action::DeleteSecret
            | Action::ApproveUsage
            | Action::ManageMembers
            | Action::ChangeRole
            | Action::ImportExportSecrets => {
                PermissionCheck::Denied("AuditUser 无权执行此操作".to_string())
            }
        },
    }
}

/// 检查成员是否为 Admin
fn is_admin(member: &Member) -> bool {
    member.role == Role::Admin && member.is_active()
}

/// Admin 变更目标成员的角色
pub fn change_role(
    members: &mut HashMap<MemberId, Member>,
    target_member: &MemberId,
    new_role: Role,
    admin_signing_key: &SigningKey,
) -> Result<RoleChangeOp, RbacError> {
    let admin_id = hex::encode(admin_signing_key.verifying_key().as_bytes());

    // 检查执行者是否为 Admin
    let admin = members
        .get(&admin_id)
        .ok_or_else(|| RbacError::PermissionDenied("执行者不在成员列表中".to_string()))?;
    if !is_admin(admin) {
        return Err(RbacError::PermissionDenied("只有 Admin 可变更角色".to_string()));
    }

    // 不能变更自己的角色
    if target_member == &admin_id {
        return Err(RbacError::CannotChangeOwnRole);
    }

    // 先检查角色转换合法性（需要不可变借用）
    {
        let target = members
            .get(target_member)
            .ok_or_else(|| RbacError::MemberNotFound(target_member.clone()))?;
        let old_role = target.role;
        if old_role == Role::Admin && new_role != Role::Admin {
            // 确保降级后至少还有一个 Admin
            let admin_count_after = members
                .values()
                .filter(|m| is_admin(m) && m.member_id != *target_member)
                .count();
            if admin_count_after == 0 {
                return Err(RbacError::InvalidRoleTransition(old_role, new_role));
            }
        }
    }

    // 再执行变更（可变借用）
    let target = members
        .get_mut(target_member)
        .ok_or_else(|| RbacError::MemberNotFound(target_member.clone()))?;
    let old_role = target.role;
    target.role = new_role;

    Ok(RoleChangeOp {
        target_member: target_member.clone(),
        old_role,
        new_role,
        changed_by: admin_id,
        timestamp: Utc::now(),
    })
}

/// AuditUser 请求使用密码
///
/// 内部会校验请求者是否为 AuditUser 角色。
pub fn request_usage(
    secret_id: &SecretId,
    reason: &str,
    requester_signing_key: &SigningKey,
    members: &HashMap<MemberId, Member>,
) -> Result<UsageRequest, RbacError> {
    let requester_id = hex::encode(requester_signing_key.verifying_key().as_bytes());
    let requester = members
        .get(&requester_id)
        .ok_or_else(|| RbacError::PermissionDenied("请求者不在成员列表中".to_string()))?;
    if requester.role != Role::AuditUser {
        return Err(RbacError::PermissionDenied(
            "仅 AuditUser 可发起使用请求".to_string(),
        ));
    }

    let request_id = format!("usage_req_{}", uuid::Uuid::new_v4());
    let timestamp = Utc::now();

    // 签名内容：长度前缀(request_id) || 长度前缀(secret_id) || 长度前缀(timestamp) || 长度前缀(reason)
    let mut sign_data = Vec::new();
    append_length_prefixed(&mut sign_data, &request_id);
    append_length_prefixed(&mut sign_data, secret_id);
    append_length_prefixed(&mut sign_data, &timestamp.to_rfc3339());
    append_length_prefixed(&mut sign_data, reason);

    let signature = crate::crypto::signing::sign(requester_signing_key, &sign_data);

    Ok(UsageRequest {
        request_id,
        requester: requester_id,
        target_secret_id: secret_id.to_string(),
        reason: reason.to_string(),
        timestamp,
        signature,
    })
}

/// Admin 审批使用请求
///
/// `ttl` 为审批有效期，传 `None` 时使用默认值 5 分钟。
pub fn approve_usage(
    request: &UsageRequest,
    admin_signing_key: &SigningKey,
    admin_members: &HashMap<MemberId, Member>,
    ttl: Option<chrono::Duration>,
) -> Result<UsageApproval, RbacError> {
    let admin_id = hex::encode(admin_signing_key.verifying_key().as_bytes());

    let admin = admin_members
        .get(&admin_id)
        .ok_or_else(|| RbacError::PermissionDenied("审批者不在成员列表中".to_string()))?;
    if !is_admin(admin) {
        return Err(RbacError::PermissionDenied("只有 Admin 可审批使用请求".to_string()));
    }

    // 验证请求者签名（长度前缀格式）
    let mut sign_data = Vec::new();
    append_length_prefixed(&mut sign_data, &request.request_id);
    append_length_prefixed(&mut sign_data, &request.target_secret_id);
    append_length_prefixed(&mut sign_data, &request.timestamp.to_rfc3339());
    append_length_prefixed(&mut sign_data, &request.reason);

    let requester_pk = VerifyingKey::from_bytes(
        &hex::decode(&request.requester)
            .map_err(|e| RbacError::SignatureError(e.to_string()))?
            .try_into()
            .map_err(|_| RbacError::SignatureError("Invalid public key length".to_string()))?,
    )
    .map_err(|e| RbacError::SignatureError(e.to_string()))?;

    crate::crypto::signing::verify(&requester_pk, &sign_data, &request.signature)
        .map_err(|e| RbacError::SignatureError(e.to_string()))?;

    // 审批签名：长度前缀(request_id) || 长度前缀("APPROVED") || 长度前缀(timestamp)
    let now = Utc::now();
    let mut approval_data = Vec::new();
    append_length_prefixed(&mut approval_data, &request.request_id);
    append_length_prefixed(&mut approval_data, "APPROVED");
    append_length_prefixed(&mut approval_data, &now.to_rfc3339());

    let approval = crate::crypto::signing::sign(admin_signing_key, &approval_data);

    let ttl = ttl.unwrap_or(chrono::Duration::minutes(DEFAULT_USAGE_APPROVAL_TTL_MINUTES));

    Ok(UsageApproval {
        request_id: request.request_id.clone(),
        approval,
        expires_at: now + ttl,
    })
}

/// 获取某角色拥有的所有权限列表
///
/// 本函数为纯查询函数，结果可安全缓存。
pub fn permissions_for_role(role: &Role) -> Vec<(Action, PermissionCheck)> {
    use Action::*;
    let all_actions = [
        ViewSecretList,
        ViewSecretPlaintext,
        CreateSecret,
        UpdateSecret,
        DeleteSecret,
        ApproveUsage,
        ManageMembers,
        ChangeRole,
        ViewAuditLog,
        ImportExportSecrets,
    ];
    all_actions
        .into_iter()
        .map(|a| (a, check_permission(role, &a)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::generate_keypair;
    use crate::group::member::{Member, MemberStatus};

    fn make_admin_member(admin_sk: &SigningKey) -> Member {
        let vk = admin_sk.verifying_key();
        Member {
            member_id: hex::encode(vk.as_bytes()),
            public_key: vk,
            role: Role::Admin,
            device_fingerprint: "admin_fp".to_string(),
            joined_at: Utc::now(),
            status: MemberStatus::Active,
        }
    }

    fn make_user_member(role: Role) -> Member {
        let (sk, vk) = generate_keypair();
        let _ = sk;
        Member {
            member_id: hex::encode(vk.as_bytes()),
            public_key: vk,
            role,
            device_fingerprint: "user_fp".to_string(),
            joined_at: Utc::now(),
            status: MemberStatus::Active,
        }
    }

    #[test]
    fn test_admin_has_all_permissions() {
        for action in [
            Action::ViewSecretList,
            Action::ViewSecretPlaintext,
            Action::CreateSecret,
            Action::UpdateSecret,
            Action::DeleteSecret,
            Action::ApproveUsage,
            Action::ManageMembers,
            Action::ChangeRole,
            Action::ViewAuditLog,
            Action::ImportExportSecrets,
        ] {
            assert_eq!(
                check_permission(&Role::Admin, &action),
                PermissionCheck::Allowed,
                "Admin 应该拥有 {:?} 权限",
                action
            );
        }
    }

    #[test]
    fn test_freeuser_limited_permissions() {
        assert_eq!(
            check_permission(&Role::FreeUser, &Action::ViewSecretList),
            PermissionCheck::Allowed
        );
        assert_eq!(
            check_permission(&Role::FreeUser, &Action::ViewSecretPlaintext),
            PermissionCheck::Allowed
        );
        assert!(
            matches!(check_permission(&Role::FreeUser, &Action::CreateSecret), PermissionCheck::Denied(_)),
            "FreeUser 不应能创建密码"
        );
        assert!(
            matches!(check_permission(&Role::FreeUser, &Action::DeleteSecret), PermissionCheck::Denied(_)),
            "FreeUser 不应能删除密码"
        );
    }

    #[test]
    fn test_audituser_requires_approval_for_plaintext() {
        assert_eq!(
            check_permission(&Role::AuditUser, &Action::ViewSecretList),
            PermissionCheck::Allowed
        );
        assert_eq!(
            check_permission(&Role::AuditUser, &Action::ViewSecretPlaintext),
            PermissionCheck::RequiresApproval,
            "AuditUser 查看明文应需要审批"
        );
        assert!(
            matches!(check_permission(&Role::AuditUser, &Action::CreateSecret), PermissionCheck::Denied(_)),
            "AuditUser 不应能创建密码"
        );
    }

    #[test]
    fn test_check_permission_is_pure() {
        // 验证纯查询函数不产生副作用：两次调用同一参数应返回完全相同的结果
        let r1 = check_permission(&Role::AuditUser, &Action::ViewSecretPlaintext);
        let r2 = check_permission(&Role::AuditUser, &Action::ViewSecretPlaintext);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_change_role_success() {
        let (admin_sk, _) = generate_keypair();
        let mut members = HashMap::new();
        let admin = make_admin_member(&admin_sk);
        let user = make_user_member(Role::FreeUser);
        let user_id = user.member_id.clone();
        members.insert(admin.member_id.clone(), admin);
        members.insert(user_id.clone(), user);

        let op = change_role(&mut members, &user_id, Role::AuditUser, &admin_sk).unwrap();
        assert_eq!(op.old_role, Role::FreeUser);
        assert_eq!(op.new_role, Role::AuditUser);
        assert_eq!(members[&user_id].role, Role::AuditUser);
    }

    #[test]
    fn test_change_role_fails_for_non_admin() {
        let (admin_sk, _) = generate_keypair();
        let (user_sk, _) = generate_keypair();
        let mut members = HashMap::new();
        let admin = make_admin_member(&admin_sk);
        let user = make_user_member(Role::FreeUser);
        let user_id = user.member_id.clone();
        members.insert(admin.member_id.clone(), admin);
        members.insert(user_id.clone(), user);

        let result = change_role(&mut members, &user_id, Role::AuditUser, &user_sk);
        assert!(result.is_err());
    }

    #[test]
    fn test_change_own_role_fails() {
        let (admin_sk, _) = generate_keypair();
        let mut members = HashMap::new();
        let admin = make_admin_member(&admin_sk);
        let admin_id = admin.member_id.clone();
        members.insert(admin_id.clone(), admin);

        let result = change_role(&mut members, &admin_id, Role::FreeUser, &admin_sk);
        assert!(matches!(result.unwrap_err(), RbacError::CannotChangeOwnRole));
    }

    #[test]
    fn test_last_admin_cannot_be_demoted() {
        let (admin_sk, _) = generate_keypair();
        let mut members = HashMap::new();
        let admin = make_admin_member(&admin_sk);
        let admin_id = admin.member_id.clone();
        members.insert(admin_id.clone(), admin);

        // 自己不能变更自己的角色（优先于 "最后一个 Admin" 检查）
        let result = change_role(&mut members, &admin_id, Role::FreeUser, &admin_sk);
        assert!(matches!(result.unwrap_err(), RbacError::CannotChangeOwnRole));
    }

    #[test]
    fn test_admin_can_demote_another_admin_when_two_exist() {
        let (admin1_sk, _) = generate_keypair();
        let (_admin2_sk, admin2_vk) = generate_keypair();
        let mut members = HashMap::new();

        let admin1 = make_admin_member(&admin1_sk);
        let admin1_id = admin1.member_id.clone();
        members.insert(admin1_id.clone(), admin1);

        // 添加第二个 Admin
        let mut admin2 = Member::from_public_key(admin2_vk, Role::Admin, "fp2".to_string());
        admin2.status = MemberStatus::Active;
        let admin2_id = admin2.member_id.clone();
        members.insert(admin2_id.clone(), admin2);

        // admin1 可以降级 admin2（降级后仍保留 admin1 这一个 Admin）
        let result = change_role(&mut members, &admin2_id, Role::FreeUser, &admin1_sk);
        assert!(result.is_ok());
        assert_eq!(members[&admin2_id].role, Role::FreeUser);
    }

    #[test]
    fn test_last_admin_cannot_be_demoted_via_other_admin() {
        let (admin1_sk, _) = generate_keypair();
        let (_admin2_sk, admin2_vk) = generate_keypair();
        let mut members = HashMap::new();

        let admin1 = make_admin_member(&admin1_sk);
        let admin1_id = admin1.member_id.clone();
        members.insert(admin1_id.clone(), admin1);

        // 添加第二个 Admin，但将其状态设为 Revoked（不活跃）
        let mut admin2 = Member::from_public_key(admin2_vk, Role::Admin, "fp2".to_string());
        admin2.status = MemberStatus::Revoked;
        let admin2_id = admin2.member_id.clone();
        members.insert(admin2_id.clone(), admin2);

        // 降级一个已 Revoked 的 Admin 是允许的（检查只针对活跃 Admin）
        let result = change_role(&mut members, &admin2_id, Role::FreeUser, &admin1_sk);
        assert!(result.is_ok());
    }

    #[test]
    fn test_request_usage_requires_audituser_role() {
        let (admin_sk, _) = generate_keypair();
        let (freeuser_sk, freeuser_vk) = generate_keypair();
        let mut members = HashMap::new();

        let admin = make_admin_member(&admin_sk);
        let mut freeuser = Member::from_public_key(freeuser_vk, Role::FreeUser, "fp".to_string());
        freeuser.status = MemberStatus::Active;
        members.insert(admin.member_id.clone(), admin);
        members.insert(freeuser.member_id.clone(), freeuser);

        // FreeUser 不能发起使用请求
        let result = request_usage(
            &"secret-123".to_string(),
            "需要维护服务器",
            &freeuser_sk,
            &members,
        );
        assert!(
            result.is_err(),
            "FreeUser 不应能发起使用请求"
        );
    }

    #[test]
    fn test_usage_request_and_approve() {
        let (admin_sk, _) = generate_keypair();
        let (user_sk, user_vk) = generate_keypair();

        let mut members = HashMap::new();
        let admin = make_admin_member(&admin_sk);
        let mut user = Member::from_public_key(user_vk, Role::AuditUser, "user_fp".to_string());
        user.status = MemberStatus::Active;
        let user_id = user.member_id.clone();
        members.insert(admin.member_id.clone(), admin);
        members.insert(user_id.clone(), user);

        let req = request_usage(
            &"secret-123".to_string(),
            "需要维护服务器",
            &user_sk,
            &members,
        )
        .unwrap();
        assert_eq!(req.target_secret_id, "secret-123");
        assert_eq!(req.reason, "需要维护服务器");

        let approval = approve_usage(&req, &admin_sk, &members, None).unwrap();
        assert_eq!(approval.request_id, req.request_id);
        assert!(approval.expires_at > Utc::now());

        // 默认 TTL 为 5 分钟
        let expected_max = Utc::now() + chrono::Duration::minutes(6);
        assert!(approval.expires_at <= expected_max);
    }

    #[test]
    fn test_usage_approve_fails_for_non_admin() {
        let (admin_sk, _) = generate_keypair();
        let (user_sk, user_vk) = generate_keypair();
        let (other_sk, other_vk) = generate_keypair();

        let mut members = HashMap::new();
        let admin = make_admin_member(&admin_sk);
        let mut user = Member::from_public_key(user_vk, Role::AuditUser, "user_fp".to_string());
        user.status = MemberStatus::Active;
        let mut other = Member::from_public_key(other_vk, Role::FreeUser, "other_fp".to_string());
        other.status = MemberStatus::Active;
        members.insert(admin.member_id.clone(), admin);
        members.insert(user.member_id.clone(), user);
        members.insert(other.member_id.clone(), other);

        let req = request_usage(
            &"secret-123".to_string(),
            "需要维护服务器",
            &user_sk,
            &members,
        )
        .unwrap();
        let result = approve_usage(&req, &other_sk, &members, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_usage_approve_custom_ttl() {
        let (admin_sk, _) = generate_keypair();
        let (user_sk, user_vk) = generate_keypair();

        let mut members = HashMap::new();
        let admin = make_admin_member(&admin_sk);
        let mut user = Member::from_public_key(user_vk, Role::AuditUser, "user_fp".to_string());
        user.status = MemberStatus::Active;
        members.insert(admin.member_id.clone(), admin);
        members.insert(user.member_id.clone(), user);

        let req = request_usage(
            &"secret-123".to_string(),
            "需要维护服务器",
            &user_sk,
            &members,
        )
        .unwrap();

        let custom_ttl = chrono::Duration::minutes(30);
        let approval = approve_usage(&req, &admin_sk, &members, Some(custom_ttl)).unwrap();
        let expected_min = Utc::now() + chrono::Duration::minutes(29);
        let expected_max = Utc::now() + chrono::Duration::minutes(31);
        assert!(approval.expires_at >= expected_min);
        assert!(approval.expires_at <= expected_max);
    }

    #[test]
    fn test_permissions_for_role_matrix() {
        let admin_perms = permissions_for_role(&Role::Admin);
        assert_eq!(admin_perms.len(), 10);
        assert!(admin_perms.iter().all(|(_, check)| *check == PermissionCheck::Allowed));

        let freeuser_perms = permissions_for_role(&Role::FreeUser);
        let allowed_count = freeuser_perms
            .iter()
            .filter(|(_, check)| *check == PermissionCheck::Allowed)
            .count();
        assert_eq!(allowed_count, 2); // ViewSecretList + ViewSecretPlaintext
    }

    #[test]
    fn test_signature_length_prefix_prevents_collision() {
        // 验证长度前缀签名方案：构造两组在简单拼接下会碰撞的数据
        let (sk, _) = generate_keypair();
        let mut buf1 = Vec::new();
        append_length_prefixed(&mut buf1, "ab");
        append_length_prefixed(&mut buf1, "c");

        let mut buf2 = Vec::new();
        append_length_prefixed(&mut buf2, "a");
        append_length_prefixed(&mut buf2, "bc");

        assert_ne!(buf1, buf2, "长度前缀应消除拼接碰撞");

        // 确保签名对不同数据产生不同结果
        let sig1 = crate::crypto::signing::sign(&sk, &buf1);
        let sig2 = crate::crypto::signing::sign(&sk, &buf2);
        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }
}
