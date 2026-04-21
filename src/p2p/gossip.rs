//! Gossipsub 消息广播与订阅
//!
//! 封装 topic 管理、消息发布、订阅逻辑。

use crate::p2p::protocol::{serialize_message, topic_name, P2pMessage};
use crate::p2p::transport::SynapseBehaviour;
use libp2p::gossipsub::{IdentTopic, Message};
use libp2p::Swarm;
use std::collections::HashSet;

/// Topic 分类
pub const TOPIC_SECRETS: &str = "secrets";
pub const TOPIC_CONTROL: &str = "control";
pub const TOPIC_CHAIN: &str = "chain";

/// Gossip 订阅管理
pub struct GossipManager {
    pub subscribed_topics: HashSet<String>,
}

impl GossipManager {
    pub fn new() -> Self {
        Self {
            subscribed_topics: HashSet::new(),
        }
    }

    /// 订阅指定群组的 topic
    pub fn subscribe_group(
        &mut self,
        swarm: &mut Swarm<SynapseBehaviour>,
        group_id: &str,
    ) -> Result<(), GossipError> {
        for category in [TOPIC_SECRETS, TOPIC_CONTROL, TOPIC_CHAIN] {
            let topic = IdentTopic::new(topic_name(group_id, category));
            swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
            self.subscribed_topics.insert(topic.hash().to_string());
        }
        Ok(())
    }

    /// 取消订阅群组的 topic
    pub fn unsubscribe_group(
        &mut self,
        swarm: &mut Swarm<SynapseBehaviour>,
        group_id: &str,
    ) {
        for category in [TOPIC_SECRETS, TOPIC_CONTROL, TOPIC_CHAIN] {
            let topic = IdentTopic::new(topic_name(group_id, category));
            let _ = swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
            self.subscribed_topics.remove(&topic.hash().to_string());
        }
    }

    /// 向指定 topic 发布消息
    pub fn broadcast(
        &self,
        swarm: &mut Swarm<SynapseBehaviour>,
        group_id: &str,
        category: &str,
        msg: &P2pMessage,
    ) -> Result<(), GossipError> {
        let topic = IdentTopic::new(topic_name(group_id, category));
        let data = serialize_message(msg)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, data)
            .map_err(|e| GossipError::Publish(e.to_string()))?;
        Ok(())
    }

    /// 广播密码操作到 secrets topic
    pub fn broadcast_secret_op(
        &self,
        swarm: &mut Swarm<SynapseBehaviour>,
        group_id: &str,
        msg: &P2pMessage,
    ) -> Result<(), GossipError> {
        self.broadcast(swarm, group_id, TOPIC_SECRETS, msg)
    }

    /// 广播控制消息到 control topic
    pub fn broadcast_control(
        &self,
        swarm: &mut Swarm<SynapseBehaviour>,
        group_id: &str,
        msg: &P2pMessage,
    ) -> Result<(), GossipError> {
        self.broadcast(swarm, group_id, TOPIC_CONTROL, msg)
    }
}

impl Default for GossipManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Gossip 错误
#[derive(Debug, thiserror::Error)]
pub enum GossipError {
    #[error("Protocol error: {0}")]
    Protocol(#[from] crate::p2p::protocol::ProtocolError),
    #[error("Subscription error: {0}")]
    Subscribe(String),
    #[error("Publish error: {0}")]
    Publish(String),
}

impl From<libp2p::gossipsub::SubscriptionError> for GossipError {
    fn from(e: libp2p::gossipsub::SubscriptionError) -> Self {
        GossipError::Subscribe(e.to_string())
    }
}

/// 解析收到的 gossipsub Message
pub fn parse_gossip_message(msg: &Message) -> Result<P2pMessage, GossipError> {
    crate::p2p::protocol::deserialize_message(&msg.data)
        .map_err(GossipError::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topic_name_constant() {
        assert_eq!(topic_name("g1", TOPIC_SECRETS), "synapsevault/g1/secrets");
        assert_eq!(topic_name("g1", TOPIC_CONTROL), "synapsevault/g1/control");
        assert_eq!(topic_name("g1", TOPIC_CHAIN), "synapsevault/g1/chain");
    }
}
