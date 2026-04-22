//! mDNS 局域网发现
//!
//! 处理 mDNS 发现事件，维护已发现的群组列表与 peer 地址映射。

use crate::group::manager::{DiscoveredGroup, GroupId};
use crate::p2p::protocol::{
    serialize_envelope, P2pMessage, P2pMessageEnvelope,
};
use libp2p::gossipsub::IdentTopic;
use libp2p::{mdns, Multiaddr, PeerId, Swarm};
use std::collections::HashMap;

use crate::p2p::transport::SynapseBehaviour;

/// 发现状态管理
#[derive(Clone, Debug, Default)]
pub struct DiscoveryState {
    /// 已发现的群组
    pub discovered_groups: HashMap<GroupId, DiscoveredGroup>,
    /// 已知 peer -> group_id 映射
    pub peer_to_group: HashMap<PeerId, GroupId>,
    /// peer 已知地址列表（由 mDNS 发现填充）
    pub peer_addresses: HashMap<PeerId, Vec<Multiaddr>>,
}

impl DiscoveryState {
    pub fn new() -> Self {
        Self::default()
    }

    /// 处理 mDNS 发现事件
    ///
    /// 对 `Discovered` 事件：保存 peer 地址，若该 peer 已通过 gossip 关联到某个
    /// group，则更新 `discovered_groups` 中的地址信息，并返回该群组。
    /// 对 `Expired` 事件：清理地址与映射。
    pub fn on_mdns_discovered(
        &mut self,
        discovered: &mdns::Event,
    ) -> Vec<DiscoveredGroup> {
        let mut updated_groups = Vec::new();

        match discovered {
            mdns::Event::Discovered(peers) => {
                for (peer, addr) in peers {
                    // 保存 peer 地址
                    let addrs = self.peer_addresses.entry(*peer).or_default();
                    if !addrs.contains(addr) {
                        addrs.push(addr.clone());
                    }

                    tracing::info!("mDNS discovered peer: {} at {}", peer, addr);

                    // 若该 peer 已与某个 group 关联（通过 gossip），更新地址信息
                    if let Some(group_id) = self.peer_to_group.get(peer) {
                        if let Some(group) = self.discovered_groups.get_mut(group_id) {
                            group.peer_id = peer.to_string();
                            updated_groups.push(group.clone());
                        }
                    }
                }
            }
            mdns::Event::Expired(peers) => {
                for (peer, _addr) in peers {
                    self.peer_addresses.remove(peer);
                    if let Some(group_id) = self.peer_to_group.remove(peer) {
                        // 只有该 group 没有其他已知 peer 时才移除
                        let has_other_peers = self.peer_to_group.values().any(|g| g == &group_id);
                        if !has_other_peers {
                            self.discovered_groups.remove(&group_id);
                            tracing::info!("mDNS peer expired: {} -> group {} removed", peer, group_id);
                        } else {
                            tracing::info!("mDNS peer expired: {} -> group {} still has other peers", peer, group_id);
                        }
                    }
                }
            }
        }

        updated_groups
    }

    /// 注册通过 gossip 等方式发现的群组
    pub fn register_discovered_group(&mut self, group: DiscoveredGroup) {
        // 尝试将 group 的 peer_id 与 group_id 关联
        if let Ok(peer_id) = group.peer_id.parse::<PeerId>() {
            self.peer_to_group
                .insert(peer_id, group.group_id.clone());
        }
        self.discovered_groups
            .insert(group.group_id.clone(), group);
    }

    /// 将已知 peer 与某个 group 关联（用于收到 gossip 消息后补全 mDNS 发现）
    pub fn associate_peer_with_group(&mut self, peer_id: PeerId, group_id: GroupId) {
        self.peer_to_group.insert(peer_id, group_id);
    }

    /// 获取某个群组已知 peer 的地址列表
    pub fn peer_addrs_for_group(&self, group_id: &GroupId) -> Vec<(PeerId, Vec<Multiaddr>)> {
        self.peer_to_group
            .iter()
            .filter(|(_, gid)| *gid == group_id)
            .filter_map(|(pid, _)| {
                self.peer_addresses
                    .get(pid)
                    .map(|addrs| (*pid, addrs.clone()))
            })
            .collect()
    }

    /// 通过 gossip 广播本地群组公告
    pub fn announce_group(
        swarm: &mut Swarm<SynapseBehaviour>,
        group: &DiscoveredGroup,
        topic: &IdentTopic,
    ) -> Result<(), DiscoveryError> {
        let envelope = P2pMessageEnvelope {
            nonce: rand::random(),
            payload: P2pMessage::GroupAnnounce(group.clone()),
        };
        let data = serialize_envelope(&envelope)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), data)
            .map_err(|e| DiscoveryError::Publish(e.to_string()))?;
        Ok(())
    }
}

/// 发现错误
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("Serialize error: {0}")]
    Serialize(#[from] crate::p2p::protocol::ProtocolError),
    #[error("Publish error: {0}")]
    Publish(String),
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_discovery_state_empty() {
        let state = DiscoveryState::new();
        assert!(state.discovered_groups.is_empty());
        assert!(state.peer_to_group.is_empty());
        assert!(state.peer_addresses.is_empty());
    }

    #[test]
    fn test_register_discovered_group() {
        let mut state = DiscoveryState::new();
        let valid_peer = PeerId::from_bytes(&[
            0, 36, 8, 1, 18, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
        .unwrap();
        let dg = DiscoveredGroup {
            group_id: "g1".to_string(),
            name: "Test".to_string(),
            admin_pubkey_hash: "abc123".to_string(),
            port: 42424,
            peer_id: valid_peer.to_string(),
            discovered_at: Utc::now(),
        };
        state.register_discovered_group(dg.clone());
        assert_eq!(state.discovered_groups.len(), 1);
        assert_eq!(state.discovered_groups["g1"].name, "Test");
        // peer_id 应被解析并关联
        assert_eq!(state.peer_to_group.len(), 1);
        assert!(state.peer_to_group.contains_key(&valid_peer));
    }

    #[test]
    fn test_associate_peer_with_group() {
        let mut state = DiscoveryState::new();
        let peer = PeerId::from_bytes(&[
            0, 36, 8, 1, 18, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
        .unwrap();
        state.associate_peer_with_group(peer, "group-a".to_string());
        assert_eq!(state.peer_to_group[&peer], "group-a");
    }

    #[test]
    fn test_peer_addrs_for_group() {
        let mut state = DiscoveryState::new();
        let peer = PeerId::from_bytes(&[
            0, 36, 8, 1, 18, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
        .unwrap();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/42424".parse().unwrap();

        state.associate_peer_with_group(peer, "g1".to_string());
        state.peer_addresses.insert(peer, vec![addr.clone()]);

        let addrs = state.peer_addrs_for_group(&"g1".to_string());
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].1, vec![addr]);
    }

    #[test]
    fn test_mdns_addr_deduplication() {
        let mut state = DiscoveryState::new();
        let peer = PeerId::from_bytes(&[
            0, 36, 8, 1, 18, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
        .unwrap();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/42424".parse().unwrap();

        // 同一 peer 同一地址重复发现不应累积
        let event = mdns::Event::Discovered(vec![(peer, addr.clone())]);
        state.on_mdns_discovered(&event);
        state.on_mdns_discovered(&event);
        state.on_mdns_discovered(&event);

        assert_eq!(state.peer_addresses.get(&peer).unwrap().len(), 1);
    }

    #[test]
    fn test_mdns_expire_keeps_group_with_other_peers() {
        let mut state = DiscoveryState::new();
        let peer1 = PeerId::from_bytes(&[
            0, 36, 8, 1, 18, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
        .unwrap();
        // peer2: 最后一个字节不同以生成不同 PeerId
        let peer2 = PeerId::from_bytes(&[
            0, 36, 8, 1, 18, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ])
        .unwrap();

        let addr1: Multiaddr = "/ip4/127.0.0.1/tcp/42424".parse().unwrap();
        let addr2: Multiaddr = "/ip4/192.168.1.2/tcp/42424".parse().unwrap();

        // 注册同一个 group 的两个不同 peer
        let dg1 = DiscoveredGroup {
            group_id: "group-a".to_string(),
            name: "Group A".to_string(),
            admin_pubkey_hash: "abc".to_string(),
            port: 42424,
            peer_id: peer1.to_string(),
            discovered_at: Utc::now(),
        };
        let dg2 = DiscoveredGroup {
            group_id: "group-a".to_string(),
            name: "Group A".to_string(),
            admin_pubkey_hash: "abc".to_string(),
            port: 42424,
            peer_id: peer2.to_string(),
            discovered_at: Utc::now(),
        };
        state.register_discovered_group(dg1);
        state.register_discovered_group(dg2);
        // 填充 mDNS 地址
        state.on_mdns_discovered(&mdns::Event::Discovered(vec![(peer1, addr1.clone())]));
        state.on_mdns_discovered(&mdns::Event::Discovered(vec![(peer2, addr2.clone())]));

        assert!(state.discovered_groups.contains_key("group-a"));
        assert_eq!(state.peer_to_group.len(), 2);

        // peer1 过期，group 应仍然保留（因为 peer2 还在）
        state.on_mdns_discovered(&mdns::Event::Expired(vec![(peer1, addr1)]));
        assert!(state.discovered_groups.contains_key("group-a"));
        assert!(!state.peer_to_group.contains_key(&peer1));
        assert!(state.peer_to_group.contains_key(&peer2));

        // peer2 也过期，group 应被移除
        state.on_mdns_discovered(&mdns::Event::Expired(vec![(peer2, addr2)]));
        assert!(!state.discovered_groups.contains_key("group-a"));
    }
}
