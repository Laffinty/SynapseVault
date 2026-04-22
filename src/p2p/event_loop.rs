//! P2P 事件循环与轮询
//!
//! 提供非阻塞的事件轮询接口，供 eframe::App::update 调用。

use crate::group::manager::{DiscoveredGroup, GroupId};
use crate::p2p::gossip::parse_gossip_message;
use crate::p2p::protocol::{AuditEventBrief, BlockBrief, P2pMessage};
use crate::p2p::transport::SynapseBehaviour;
use futures::StreamExt;
use libp2p::gossipsub::Event as GossipsubEvent;
use libp2p::swarm::SwarmEvent;
use libp2p::{mdns, PeerId, Swarm};
use std::collections::VecDeque;
use std::task::{Context, Poll, Wake};
use std::sync::Arc;

/// 可处理的 P2P 事件（已解析的高层事件）
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum P2pEvent {
    /// 发现新 peer
    PeerDiscovered { peer_id: String, group_id: Option<GroupId> },
    /// Peer 断开/过期
    PeerExpired { peer_id: String },
    /// 收到群组公告
    GroupAnnounced(DiscoveredGroup),
    /// 收到加入请求
    JoinRequestReceived { from_peer: String, request: crate::group::manager::JoinRequest },
    /// 收到密码操作
    SecretOpReceived { from_peer: String, op: crate::secret::entry::SecretOp },
    /// 收到同步请求
    SyncRequestReceived { from_peer: String, group_id: GroupId, from_version: u64 },
    /// 收到心跳
    HeartbeatReceived { peer_id: String, group_id: GroupId },
    /// 收到审计事件批次
    AuditEventsBatchReceived { from_peer: String, group_id: GroupId, events: Vec<AuditEventBrief> },
    /// 收到链同步请求
    ChainSyncRequested { from_peer: String, group_id: GroupId, from_height: u64 },
    /// 收到链同步响应
    ChainSyncResponseReceived { from_peer: String, group_id: GroupId, blocks: Vec<BlockBrief> },
    /// 连接已建立
    Connected { peer_id: String },
    /// 连接已关闭
    Disconnected { peer_id: String },
}

/// 轻量唤醒器（用于在同步代码中轮询 Swarm）
struct DummyWaker;

impl Wake for DummyWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}

/// 事件循环状态
pub struct EventLoop {
    /// 待处理的高层事件队列
    pub events: VecDeque<P2pEvent>,
    /// 本地 PeerId
    pub local_peer_id: PeerId,
}

impl EventLoop {
    pub fn new(local_peer_id: PeerId) -> Self {
        Self {
            events: VecDeque::new(),
            local_peer_id,
        }
    }

    /// 非阻塞地轮询 Swarm，将产生的事件转换为 P2pEvent
    pub fn poll(&mut self, swarm: &mut Swarm<SynapseBehaviour>) {
        let waker = Arc::new(DummyWaker).into();
        let mut cx = Context::from_waker(&waker);

        while let Poll::Ready(Some(event)) = swarm.poll_next_unpin(&mut cx) {
            match event {
                SwarmEvent::Behaviour(behaviour_event) => {
                    self.handle_behaviour_event(swarm, behaviour_event);
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    self.events.push_back(P2pEvent::Connected {
                        peer_id: peer_id.to_string(),
                    });
                }
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    tracing::debug!("Connection closed with {}: {:?}", peer_id, cause);
                    self.events.push_back(P2pEvent::Disconnected {
                        peer_id: peer_id.to_string(),
                    });
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    tracing::info!("Listening on {}", address);
                }
                SwarmEvent::ExpiredListenAddr { address, .. } => {
                    tracing::debug!("Expired listen address: {}", address);
                }
                _ => {}
            }
        }
    }

    /// 处理 Behaviour 级别事件
    fn handle_behaviour_event(
        &mut self,
        _swarm: &mut Swarm<SynapseBehaviour>,
        event: <SynapseBehaviour as libp2p::swarm::NetworkBehaviour>::ToSwarm,
    ) {
        match event {
            // Gossipsub 消息
            SynapseBehaviourToSwarm::Gossipsub(GossipsubEvent::Message {
                propagation_source,
                message_id: _,
                message,
            }) => {
                let peer_str = propagation_source.to_string();
                match parse_gossip_message(&message) {
                    Ok(p2p_msg) => self.handle_p2p_message(&peer_str, p2p_msg),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to parse gossip message from {}: {}",
                            peer_str,
                            e
                        );
                    }
                }
            }
            SynapseBehaviourToSwarm::Gossipsub(GossipsubEvent::Subscribed { peer_id, topic }) => {
                tracing::debug!("Peer {} subscribed to {}", peer_id, topic);
            }
            SynapseBehaviourToSwarm::Gossipsub(GossipsubEvent::Unsubscribed { peer_id, topic }) => {
                tracing::debug!("Peer {} unsubscribed from {}", peer_id, topic);
            }
            SynapseBehaviourToSwarm::Gossipsub(GossipsubEvent::GossipsubNotSupported { peer_id }) => {
                tracing::debug!("Peer {} does not support gossipsub", peer_id);
            }
            SynapseBehaviourToSwarm::Gossipsub(GossipsubEvent::SlowPeer { peer_id, .. }) => {
                tracing::debug!("Peer {} is slow", peer_id);
            }
            SynapseBehaviourToSwarm::Mdns(mdns_event) => {
                match mdns_event {
                    mdns::Event::Discovered(peers) => {
                        for (peer_id, addr) in peers {
                            tracing::debug!("mDNS discovered {} at {}", peer_id, addr);
                            self.events.push_back(P2pEvent::PeerDiscovered {
                                peer_id: peer_id.to_string(),
                                group_id: None,
                            });
                        }
                    }
                    mdns::Event::Expired(peers) => {
                        for (peer_id, _addr) in peers {
                            self.events.push_back(P2pEvent::PeerExpired {
                                peer_id: peer_id.to_string(),
                            });
                        }
                    }
                }
            }
            SynapseBehaviourToSwarm::Identify(identify_event) => {
                tracing::debug!("Identify event: {:?}", identify_event);
            }
        }
    }

    /// 将 P2pMessage 转换为 P2pEvent
    fn handle_p2p_message(&mut self, peer_id: &str, msg: P2pMessage) {
        match msg {
            P2pMessage::GroupAnnounce(dg) => {
                self.events.push_back(P2pEvent::GroupAnnounced(dg));
            }
            P2pMessage::JoinRequest(req) => {
                self.events.push_back(P2pEvent::JoinRequestReceived {
                    from_peer: peer_id.to_string(),
                    request: req,
                });
            }
            P2pMessage::JoinApproved(_) | P2pMessage::JoinRejected { .. } => {
                // 应用层直接处理
            }
            P2pMessage::SecretOp(op) => {
                self.events.push_back(P2pEvent::SecretOpReceived {
                    from_peer: peer_id.to_string(),
                    op,
                });
            }
            P2pMessage::SecretSyncRequest {
                group_id,
                from_version,
            } => {
                self.events.push_back(P2pEvent::SyncRequestReceived {
                    from_peer: peer_id.to_string(),
                    group_id,
                    from_version,
                });
            }
            P2pMessage::SecretSyncResponse { .. } => {}
            P2pMessage::RoleChange { .. } => {}
            P2pMessage::AuditEventsBatch { group_id, events } => {
                self.events.push_back(P2pEvent::AuditEventsBatchReceived {
                    from_peer: peer_id.to_string(),
                    group_id,
                    events,
                });
            }
            P2pMessage::ChainSyncRequest { group_id, from_height } => {
                self.events.push_back(P2pEvent::ChainSyncRequested {
                    from_peer: peer_id.to_string(),
                    group_id,
                    from_height,
                });
            }
            P2pMessage::ChainSyncResponse { group_id, blocks } => {
                self.events.push_back(P2pEvent::ChainSyncResponseReceived {
                    from_peer: peer_id.to_string(),
                    group_id,
                    blocks,
                });
            }
            P2pMessage::Heartbeat {
                group_id,
                peer_id: msg_peer_id,
                ..
            } => {
                self.events.push_back(P2pEvent::HeartbeatReceived {
                    peer_id: msg_peer_id,
                    group_id,
                });
            }
        }
    }

    /// 弹出下一个待处理事件
    pub fn next_event(&mut self) -> Option<P2pEvent> {
        self.events.pop_front()
    }
}

/// derive(NetworkBehaviour) 生成的事件类型别名
/// 注意：实际类型名由宏生成，通常为 `<BehaviourName>ToSwarm`
type SynapseBehaviourToSwarm = <SynapseBehaviour as libp2p::swarm::NetworkBehaviour>::ToSwarm;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::generate_keypair;
    use crate::p2p::transport::libp2p_keypair_from_signing_key;

    #[test]
    fn test_event_loop_new() {
        let (sk, _vk) = generate_keypair();
        let libp2p_key = libp2p_keypair_from_signing_key(&sk);
        let peer_id = PeerId::from(libp2p_key.public());
        let loop_state = EventLoop::new(peer_id);
        assert!(loop_state.events.is_empty());
    }
}
