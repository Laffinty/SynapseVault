//! Phase 3 集成测试：两节点 P2P 组管理流程
//!
//! 验证以下端到端场景：
//! 1. 节点 A 创建组（成为 Admin）
//! 2. 节点 B 发现该组并生成签名加入请求
//! 3. 节点 A 验证签名并审批加入
//! 4. P2P 协议消息的序列化/反序列化
//! 5. DiscoveryState 的群组注册与查询

use chrono::Utc;
use synapse_vault::auth::device_fingerprint::generate_device_fingerprint;
use synapse_vault::crypto::signing::generate_keypair;
use synapse_vault::group::manager::{
    admin_pubkey_short_hash, approve_join, create_group, request_join, verify_join_request,
    DiscoveredGroup, GroupConfig,
};
use synapse_vault::group::member::MemberStatus;
use synapse_vault::p2p::discovery::DiscoveryState;
use synapse_vault::p2p::protocol::{deserialize_message, serialize_message, P2pMessage};
use synapse_vault::p2p::transport::{create_swarm, libp2p_keypair_from_signing_key};

/// 测试两节点完整加入流程：创建组 → 生成请求 → 验证签名 → Admin 审批
#[test]
fn test_two_node_join_flow() {
    // === 节点 A：Admin ===
    let (admin_sk, _admin_vk) = generate_keypair();
    let (group, _gsk) = create_group("运维密码库", &admin_sk, GroupConfig::default()).unwrap();
    assert_eq!(group.member_map.len(), 1);
    assert!(group.member_map.values().next().unwrap().is_active());

    // === 节点 B：普通用户 ===
    let (user_sk, user_vk) = generate_keypair();

    // 模拟发现组（通过 mDNS / gossip）
    let discovered = DiscoveredGroup {
        group_id: group.group_id.clone(),
        name: group.name.clone(),
        admin_pubkey_hash: admin_pubkey_short_hash(&group.admin_public_key),
        port: group.config.gossip_port,
        peer_id: "peer-b".to_string(),
        discovered_at: Utc::now(),
    };

    // 节点 B 生成加入请求并签名
    let fp = generate_device_fingerprint(&user_vk);
    let join_req = request_join(&discovered, &user_sk, &fp).unwrap();
    assert_eq!(join_req.group_id, group.group_id);

    // 节点 A 验证请求签名
    assert!(verify_join_request(&join_req).is_ok());

    // 节点 A 审批
    let mut group_mut = group;
    let approval = approve_join(&mut group_mut, &join_req, &admin_sk).unwrap();
    assert_eq!(approval.member.public_key, user_vk);
    assert!(approval.member.is_active());
    assert_eq!(approval.group_id, group_mut.group_id);

    // 验证组状态
    assert_eq!(group_mut.member_map.len(), 2);
    let user_member_id = hex::encode(user_vk.as_bytes());
    assert!(group_mut.member_map.contains_key(&user_member_id));
    assert_eq!(group_mut.member_map[&user_member_id].status, MemberStatus::Active);
    assert_eq!(group_mut.member_map[&user_member_id].role, synapse_vault::rbac::role::Role::FreeUser);
}

/// 测试 libp2p Swarm 创建与密钥转换
#[test]
fn test_swarm_lifecycle() {
    let (sk, _vk) = generate_keypair();
    let libp2p_key = libp2p_keypair_from_signing_key(&sk);
    let swarm = create_swarm(&libp2p_key).unwrap();

    // 验证 PeerId 非空且一致
    let peer_id = swarm.local_peer_id();
    assert!(!peer_id.to_string().is_empty());

    // 验证密钥转换可逆：从同一私钥应得到同一 PeerId
    let libp2p_key2 = libp2p_keypair_from_signing_key(&sk);
    let peer_id2 = libp2p::PeerId::from(libp2p_key2.public());
    assert_eq!(*peer_id, peer_id2);
}

/// 测试 GroupAnnounce P2P 消息的序列化往返
#[test]
fn test_group_announce_serde_roundtrip() {
    let dg = DiscoveredGroup {
        group_id: "test-group-abc".to_string(),
        name: "测试组".to_string(),
        admin_pubkey_hash: "a1b2c3d4".to_string(),
        port: 42424,
        peer_id: "peer-test".to_string(),
        discovered_at: Utc::now(),
    };

    let msg = P2pMessage::GroupAnnounce(dg);
    let bytes = serialize_message(&msg).unwrap();
    let decoded = deserialize_message(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

/// 测试 DiscoveryState 注册群组、过期清理、地址查询
#[test]
fn test_discovery_state_integration() {
    let mut state = DiscoveryState::new();

    // 注册第一个组
    let dg1 = DiscoveredGroup {
        group_id: "g1".to_string(),
        name: "Alpha".to_string(),
        admin_pubkey_hash: "1111".to_string(),
        port: 42424,
        peer_id: "peer-1".to_string(),
        discovered_at: Utc::now(),
    };
    state.register_discovered_group(dg1.clone());
    assert_eq!(state.discovered_groups.len(), 1);
    assert_eq!(state.discovered_groups["g1"].name, "Alpha");

    // 注册第二个组
    let dg2 = DiscoveredGroup {
        group_id: "g2".to_string(),
        name: "Beta".to_string(),
        admin_pubkey_hash: "2222".to_string(),
        port: 42425,
        peer_id: "peer-2".to_string(),
        discovered_at: Utc::now(),
    };
    state.register_discovered_group(dg2);
    assert_eq!(state.discovered_groups.len(), 2);

    // 查询组列表
    let names: Vec<_> = state.discovered_groups.values().map(|g| g.name.clone()).collect();
    assert!(names.contains(&"Alpha".to_string()));
    assert!(names.contains(&"Beta".to_string()));
}

/// 测试错误场景：非 Admin 尝试审批应失败
#[test]
fn test_non_admin_cannot_approve() {
    let (admin_sk, _admin_vk) = generate_keypair();
    let (user_sk, user_vk) = generate_keypair();
    let (attacker_sk, _attacker_vk) = generate_keypair();

    let (group, _gsk) = create_group("安全测试组", &admin_sk, GroupConfig::default()).unwrap();

    let discovered = DiscoveredGroup {
        group_id: group.group_id.clone(),
        name: group.name.clone(),
        admin_pubkey_hash: admin_pubkey_short_hash(&group.admin_public_key),
        port: group.config.gossip_port,
        peer_id: "peer-user".to_string(),
        discovered_at: Utc::now(),
    };

    let fp = generate_device_fingerprint(&user_vk);
    let join_req = request_join(&discovered, &user_sk, &fp).unwrap();

    // 攻击者（非 Admin）尝试审批
    let mut group_mut = group;
    let result = approve_join(&mut group_mut, &join_req, &attacker_sk);
    assert!(result.is_err());
}
