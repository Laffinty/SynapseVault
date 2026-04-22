#![cfg(not(miri))]
//! Phase 4 集成测试：RBAC 权限 + CRDT 同步
//!
//! 覆盖：
//! 1. 权限矩阵校验（Admin / FreeUser / AuditUser）
//! 2. 角色变更流程
//! 3. CRDT 引擎冲突合并
//! 4. 使用申请与审批签名验证

use synapse_vault::group::manager::{create_group, GroupConfig};
use synapse_vault::group::member::{Member, MemberStatus};
use synapse_vault::rbac::policy::{
    approve_usage, change_role, check_permission, request_usage, Action, PermissionCheck,
};
use synapse_vault::rbac::role::Role;
use synapse_vault::secret::entry::{SecretEntry, SecretOp};
use synapse_vault::sync::crdt_engine::{ApplyResult, CrdtEngine};
use synapse_vault::crypto::signing::generate_keypair;
use chrono::Utc;
use std::collections::HashMap;

#[test]
fn test_rbac_permission_matrix_boundaries() {
    // Admin: 全部允许
    assert!(matches!(
        check_permission(&Role::Admin, &Action::CreateSecret),
        PermissionCheck::Allowed
    ));
    assert!(matches!(
        check_permission(&Role::Admin, &Action::ChangeRole),
        PermissionCheck::Allowed
    ));

    // FreeUser: 仅查看相关
    assert!(matches!(
        check_permission(&Role::FreeUser, &Action::ViewSecretList),
        PermissionCheck::Allowed
    ));
    assert!(matches!(
        check_permission(&Role::FreeUser, &Action::ViewSecretPlaintext),
        PermissionCheck::Allowed
    ));
    assert!(
        matches!(check_permission(&Role::FreeUser, &Action::CreateSecret), PermissionCheck::Denied(_)),
        "FreeUser 不应能创建密码"
    );
    assert!(
        matches!(check_permission(&Role::FreeUser, &Action::ManageMembers), PermissionCheck::Denied(_)),
        "FreeUser 不应能管理成员"
    );

    // AuditUser: 查看列表允许，明文需审批，其他拒绝
    assert!(matches!(
        check_permission(&Role::AuditUser, &Action::ViewSecretList),
        PermissionCheck::Allowed
    ));
    assert!(
        matches!(
            check_permission(&Role::AuditUser, &Action::ViewSecretPlaintext),
            PermissionCheck::RequiresApproval
        ),
        "AuditUser 查看明文应需要审批"
    );
    assert!(
        matches!(check_permission(&Role::AuditUser, &Action::CreateSecret), PermissionCheck::Denied(_)),
        "AuditUser 不应能创建密码"
    );
}

#[test]
fn test_role_change_integration_flow() {
    let (admin_sk, _) = generate_keypair();
    let (user_sk, user_vk) = generate_keypair();

    let (mut group, _gsk) = create_group("运维组", &admin_sk, GroupConfig::default()).unwrap();

    // 添加一个 FreeUser
    let user = Member::from_public_key(user_vk, Role::FreeUser, "device:user".to_string());
    let user_id = user.member_id.clone();
    group.member_map.insert(user_id.clone(), user);

    // Admin 将 FreeUser 提升为 AuditUser
    let op = change_role(&mut group.member_map, &user_id, Role::AuditUser, &admin_sk).unwrap();
    assert_eq!(op.old_role, Role::FreeUser);
    assert_eq!(op.new_role, Role::AuditUser);
    assert_eq!(group.member_map[&user_id].role, Role::AuditUser);

    // 非 Admin 尝试变更角色应失败
    let result = change_role(&mut group.member_map, &user_id, Role::FreeUser, &user_sk);
    assert!(result.is_err(), "非 Admin 不应能变更角色");
}

#[test]
fn test_crdt_engine_conflict_resolution() {
    let mut engine_a = CrdtEngine::new("group-1".to_string());
    let mut engine_b = CrdtEngine::new("group-1".to_string());

    let now = Utc::now();
    let entry = SecretEntry {
        secret_id: "s1".to_string(),
        title: "核心交换机".to_string(),
        username: "admin".to_string(),
        encrypted_password: vec![1, 2, 3],
        nonce: [0u8; 24],
        environment: "生产".to_string(),
        tags: vec!["ssh".to_string()],
        description: "".to_string(),
        created_at: now,
        updated_at: now,
        created_by: "m1".to_string(),
        version: 1,
        expires_at: None,
    };

    // 双方同时创建同一密码（冲突场景）
    let result_a = engine_a.apply_op("node-a", &SecretOp::Create(entry.clone()));
    let result_b = engine_b.apply_op("node-b", &SecretOp::Create(entry.clone()));

    assert_eq!(result_a, ApplyResult::Applied);
    assert_eq!(result_b, ApplyResult::Applied);

    // 模拟同步：将 node-b 的操作应用到 node-a
    let sync_result = engine_a.apply_op("node-b", &SecretOp::Create(entry.clone()));
    assert_eq!(sync_result, ApplyResult::Merged, "重复创建应触发合并");

    // node-a 更新密码
    let update = SecretOp::Update {
        secret_id: "s1".to_string(),
        encrypted_password: vec![9, 9, 9],
        nonce: [1u8; 24],
        updated_at: now + chrono::Duration::seconds(10),
        updated_by: "m1".to_string(),
    };
    assert_eq!(engine_a.apply_op("node-a", &update), ApplyResult::Applied);

    // node-b 删除同一密码（删除 vs 修改冲突）
    let delete = SecretOp::Delete {
        secret_id: "s1".to_string(),
        deleted_by: "m2".to_string(),
        deleted_at: now + chrono::Duration::seconds(20),
    };
    assert_eq!(engine_b.apply_op("node-b", &delete), ApplyResult::Applied);

    // 将 node-b 的删除同步到 node-a
    // 当前 CrdtEngine 实现中，Delete 操作直接移除条目并记录墓碑，不比较版本
    assert_eq!(engine_a.apply_op("node-b", &delete), ApplyResult::Applied);
    assert!(engine_a.is_deleted(&"s1".to_string()));
}

#[test]
fn test_usage_request_and_approve_integration() {
    let (admin_sk, _) = generate_keypair();
    let (user_sk, user_vk) = generate_keypair();

    let mut members = HashMap::new();
    let mut admin = Member::from_public_key(admin_sk.verifying_key(), Role::Admin, "admin_fp".to_string());
    admin.status = MemberStatus::Active;
    let admin_id = admin.member_id.clone();
    members.insert(admin_id.clone(), admin);

    let mut user = Member::from_public_key(user_vk, Role::AuditUser, "user_fp".to_string());
    user.status = MemberStatus::Active;
    let user_id = user.member_id.clone();
    members.insert(user_id.clone(), user);

    // AuditUser 发起使用请求
    let req = request_usage(&"secret-123".to_string(), "维护服务器", &user_sk, &members).unwrap();
    assert_eq!(req.target_secret_id, "secret-123");
    assert_eq!(req.requester, user_id);

    // Admin 审批（默认 TTL 5 分钟）
    let approval = approve_usage(&req, &admin_sk, &members, None).unwrap();
    assert_eq!(approval.request_id, req.request_id);
    assert!(approval.expires_at > Utc::now());

    // 非 Admin 审批应失败
    let result = approve_usage(&req, &user_sk, &members, None);
    assert!(result.is_err(), "非 Admin 不应能审批使用请求");
}

#[test]
fn test_crdt_ops_since_vector_clock() {
    let mut engine = CrdtEngine::new("group-1".to_string());

    let now = Utc::now();
    let e1 = SecretEntry {
        secret_id: "s1".to_string(),
        title: "A".to_string(),
        username: "u1".to_string(),
        encrypted_password: vec![1],
        nonce: [0u8; 24],
        environment: "dev".to_string(),
        tags: vec![],
        description: "".to_string(),
        created_at: now,
        updated_at: now,
        created_by: "m1".to_string(),
        version: 1,
        expires_at: None,
    };

    engine.apply_op("node-a", &SecretOp::Create(e1.clone()));
    engine.apply_op("node-a", &SecretOp::Create(SecretEntry {
        secret_id: "s2".to_string(),
        title: "B".to_string(),
        ..e1.clone()
    }));
    engine.apply_op("node-b", &SecretOp::Create(SecretEntry {
        secret_id: "s3".to_string(),
        title: "C".to_string(),
        ..e1.clone()
    }));

    // 从 node-a seq=1 之后获取操作
    let since = {
        let mut m = std::collections::BTreeMap::new();
        m.insert("node-a".to_string(), 1);
        m
    };
    let ops = engine.ops_since(&since);
    assert_eq!(ops.len(), 2, "应包含 node-a 的第2个操作和 node-b 的第1个操作");
}
