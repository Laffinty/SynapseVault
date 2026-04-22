#![cfg(not(miri))]
//! Phase 5 集成测试：区块链 + 审计
//!
//! 验证区块链共识、审计日志记录、导出与持久化。

use synapse_vault::audit::event::{AuditEvent, OperationType};
use synapse_vault::audit::export::{export_events, ExportFormat};
use synapse_vault::audit::logger::{log_event, query_events, AuditQuery, recent_events};
use synapse_vault::blockchain::block::Block;
use synapse_vault::blockchain::chain::Blockchain;
use synapse_vault::blockchain::consensus::{create_block, BlockchainOp};
use synapse_vault::blockchain::validator::{is_validator_member, ValidatorSet};
use synapse_vault::crypto::signing::generate_keypair;
use synapse_vault::group::member::{Member, MemberStatus};
use synapse_vault::rbac::role::Role;

use std::collections::HashMap;

/// 创建带 Schema 的内存数据库
fn setup_db() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    synapse_vault::storage::schema::init_schema(&conn).unwrap();
    // 插入测试组
    conn.execute(
        "INSERT INTO groups (group_id, name, group_public_key, admin_public_key, config, created_at, updated_at)
         VALUES ('g1', 'Test', X'00', X'00', X'00', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')",
        [],
    ).unwrap();
    conn
}

/// 创建测试成员
fn make_member(role: Role, status: MemberStatus) -> Member {
    let (_sk, vk) = generate_keypair();
    let mut member = Member::from_public_key(vk, role, "fp".to_string());
    member.status = status;
    member
}

#[test]
fn test_blockchain_creation_and_append() {
    let (admin_sk, admin_vk) = generate_keypair();
    let mut chain = Blockchain::new("g1", admin_vk, vec![admin_vk]);

    assert_eq!(chain.height(), 0);
    assert!(chain.validate_chain().is_ok());

    // 追加新区块
    let ops = vec![BlockchainOp::MemberJoin {
        member_id: "user1".to_string(),
        public_key: vec![1, 2, 3],
        role: "FreeUser".to_string(),
        device_fingerprint: "fp1".to_string(),
    }];
    let block = create_block("g1", chain.latest_block().unwrap(), &ops, &admin_sk, &[admin_vk]).unwrap();
    chain.append_block(block).unwrap();

    assert_eq!(chain.height(), 1);
    assert!(chain.validate_chain().is_ok());
}

#[test]
fn test_blockchain_persistence_roundtrip() {
    let (admin_sk, admin_vk) = generate_keypair();
    let mut chain = Blockchain::new("g1", admin_vk, vec![admin_vk]);

    let ops = vec![BlockchainOp::AuditAnchor {
        event_id: "evt-1".to_string(),
        event_hash: [1u8; 32],
    }];
    let block = create_block("g1", chain.latest_block().unwrap(), &ops, &admin_sk, &[admin_vk]).unwrap();
    chain.append_block(block).unwrap();

    let conn = setup_db();
    chain.save_to_db(&conn).unwrap();

    let loaded = Blockchain::load_from_db(&conn, "g1").unwrap().unwrap();
    assert_eq!(loaded.height(), chain.height());
    assert_eq!(loaded.blocks[0].block_hash, chain.blocks[0].block_hash);
    assert_eq!(loaded.blocks[1].block_hash, chain.blocks[1].block_hash);
    assert!(loaded.validate_chain().is_ok());
}

#[test]
fn test_poa_consensus_rejects_non_validator() {
    let (_admin_sk, admin_vk) = generate_keypair();
    let (user_sk, _user_vk) = generate_keypair();
    let genesis = Block::genesis("g1", admin_vk);

    let ops = vec![];
    let result = create_block("g1", &genesis, &ops, &user_sk, &[admin_vk]);
    assert!(result.is_err(), "非验证者应无法创建区块");
}

#[test]
fn test_merkle_root_integrity() {
    let (admin_sk, admin_vk) = generate_keypair();
    let genesis = Block::genesis("g1", admin_vk);

    let ops = vec![
        BlockchainOp::MemberJoin {
            member_id: "u1".to_string(),
            public_key: vec![1],
            role: "FreeUser".to_string(),
            device_fingerprint: "fp1".to_string(),
        },
        BlockchainOp::SecretCreate {
            secret_id: "s1".to_string(),
            created_by: "u1".to_string(),
        },
    ];
    let block = create_block("g1", &genesis, &ops, &admin_sk, &[admin_vk]).unwrap();

    // 验证 Merkle 根与操作数量匹配
    assert_ne!(block.merkle_root, [0u8; 32]);
    assert!(block.verify_hash());
}

#[test]
fn test_validator_set_from_members() {
    let mut members = HashMap::new();
    let admin1 = make_member(Role::Admin, MemberStatus::Active);
    let admin2 = make_member(Role::Admin, MemberStatus::Active);
    let user = make_member(Role::FreeUser, MemberStatus::Active);
    let revoked_admin = make_member(Role::Admin, MemberStatus::Revoked);

    members.insert(admin1.member_id.clone(), admin1.clone());
    members.insert(admin2.member_id.clone(), admin2.clone());
    members.insert(user.member_id.clone(), user);
    members.insert(revoked_admin.member_id.clone(), revoked_admin);

    let set = ValidatorSet::from_members(&members);
    assert_eq!(set.len(), 2, "只有活跃 Admin 才是验证者");
    assert!(set.pubkeys().iter().any(|pk| *pk == admin1.public_key));
    assert!(set.pubkeys().iter().any(|pk| *pk == admin2.public_key));
}

#[test]
fn test_validator_rotation() {
    let mut members = HashMap::new();
    let admin1 = make_member(Role::Admin, MemberStatus::Active);
    let admin2 = make_member(Role::Admin, MemberStatus::Active);
    members.insert(admin1.member_id.clone(), admin1.clone());
    members.insert(admin2.member_id.clone(), admin2.clone());

    let mut set = ValidatorSet::from_members(&members);
    let first = set.current_validator().unwrap().member_id.clone();
    set.rotate();
    let second = set.current_validator().unwrap().member_id.clone();
    set.rotate();
    let third = set.current_validator().unwrap().member_id.clone();

    assert_ne!(first, second);
    assert_eq!(first, third);
}

#[test]
fn test_is_validator_member() {
    let admin = make_member(Role::Admin, MemberStatus::Active);
    let user = make_member(Role::FreeUser, MemberStatus::Active);
    let revoked = make_member(Role::Admin, MemberStatus::Revoked);

    assert!(is_validator_member(&admin));
    assert!(!is_validator_member(&user));
    assert!(!is_validator_member(&revoked));
}

#[test]
fn test_audit_event_logging_and_query() {
    let conn = setup_db();

    let event = AuditEvent::new(
        "evt-1".to_string(),
        OperationType::ViewSecret,
        "member-1".to_string(),
        "fp-1".to_string(),
        "peer-1".to_string(),
    )
    .with_secret_id("secret-1".to_string())
    .with_summary("查看了生产密码".to_string());

    log_event(&conn, &event, Some(1)).unwrap();

    let events = query_events(&conn, &AuditQuery::default()).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, "evt-1");
    assert_eq!(events[0].operation_type, OperationType::ViewSecret);

    // 按类型查询
    let query = AuditQuery {
        operation_type: Some(OperationType::ViewSecret),
        ..Default::default()
    };
    let filtered = query_events(&conn, &query).unwrap();
    assert_eq!(filtered.len(), 1);

    // 按不存在的类型查询
    let query = AuditQuery {
        operation_type: Some(OperationType::BlockProduced),
        ..Default::default()
    };
    let empty = query_events(&conn, &query).unwrap();
    assert!(empty.is_empty());
}

#[test]
fn test_audit_log_without_block_height() {
    let conn = setup_db();

    let event = AuditEvent::new(
        "evt-orphan".to_string(),
        OperationType::CopySecret,
        "member-2".to_string(),
        "fp-2".to_string(),
        "peer-2".to_string(),
    );

    // block_height 为 None 应允许（未上链的审计事件）
    log_event(&conn, &event, None).unwrap();

    let events = recent_events(&conn, 10).unwrap();
    assert_eq!(events.len(), 1);
}

#[test]
fn test_audit_export_json() {
    let conn = setup_db();

    for i in 0..3 {
        let event = AuditEvent::new(
            format!("evt-{}", i),
            OperationType::CreateSecret,
            format!("member-{}", i),
            "fp".to_string(),
            "peer".to_string(),
        );
        log_event(&conn, &event, None).unwrap();
    }

    let mut buf = Vec::new();
    let count = export_events(&conn, &AuditQuery::default(), ExportFormat::Json, &mut buf).unwrap();
    assert_eq!(count, 3);

    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("evt-0"));
    assert!(output.contains("evt-1"));
    assert!(output.contains("evt-2"));
}

#[test]
fn test_audit_export_csv() {
    let conn = setup_db();

    let event = AuditEvent::new(
        "evt-csv".to_string(),
        OperationType::UpdateSecret,
        "member-x".to_string(),
        "fp".to_string(),
        "peer".to_string(),
    )
    .with_secret_id("secret-x".to_string());
    log_event(&conn, &event, None).unwrap();

    let mut buf = Vec::new();
    let count = export_events(&conn, &AuditQuery::default(), ExportFormat::Csv, &mut buf).unwrap();
    assert_eq!(count, 1);

    let output = String::from_utf8(buf).unwrap();
    assert!(output.starts_with("event_id,operation_type"));
    assert!(output.contains("evt-csv"));
    assert!(output.contains("secret-x"));
}

#[test]
fn test_blockchain_and_audit_integration() {
    // 模拟一个完整场景：Admin 创建区块包含审计锚定，然后审计事件可查询
    let (admin_sk, admin_vk) = generate_keypair();
    let mut chain = Blockchain::new("g1", admin_vk, vec![admin_vk]);

    let conn = setup_db();

    // 记录审计事件
    let event = AuditEvent::new(
        "evt-anchor".to_string(),
        OperationType::BlockProduced,
        hex::encode(admin_vk.as_bytes()),
        "admin-fp".to_string(),
        "local".to_string(),
    )
    .with_summary("区块高度 1".to_string());
    log_event(&conn, &event, Some(1)).unwrap();

    // 创建包含 AuditAnchor 的区块
    let ops = vec![
        BlockchainOp::AuditAnchor {
            event_id: "evt-anchor".to_string(),
            event_hash: event.event_hash,
        },
        BlockchainOp::MemberJoin {
            member_id: "user1".to_string(),
            public_key: vec![1],
            role: "FreeUser".to_string(),
            device_fingerprint: "fp1".to_string(),
        },
    ];
    let block = create_block("g1", chain.latest_block().unwrap(), &ops, &admin_sk, &[admin_vk]).unwrap();
    chain.append_block(block).unwrap();
    chain.save_to_db(&conn).unwrap();

    // 验证链和审计都持久化
    let loaded_chain = Blockchain::load_from_db(&conn, "g1").unwrap().unwrap();
    assert_eq!(loaded_chain.height(), 1);

    let audit_events = query_events(&conn, &AuditQuery::default()).unwrap();
    assert_eq!(audit_events.len(), 1);
    assert_eq!(audit_events[0].event_id, "evt-anchor");

    // 验证区块操作可恢复
    let all_ops = loaded_chain.all_ops();
    assert_eq!(all_ops.len(), 2);
    assert!(matches!(all_ops[0].1, BlockchainOp::AuditAnchor { .. }));
    assert!(matches!(all_ops[1].1, BlockchainOp::MemberJoin { .. }));
}
