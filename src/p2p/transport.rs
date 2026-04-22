//! P2P 传输层与 Swarm 构建
//!
//! 封装 libp2p Swarm 创建：Noise + QUIC/TCP + yamux。

use ed25519_dalek::SigningKey;
use libp2p::{
    gossipsub, identify, mdns, noise, swarm::NetworkBehaviour, tcp, yamux, PeerId, Swarm,
};
use std::time::Duration;

/// SynapseVault 网络行为组合
#[derive(NetworkBehaviour)]
pub struct SynapseBehaviour {
    /// Gossipsub 消息广播
    pub gossipsub: gossipsub::Behaviour,
    /// mDNS 局域网发现
    pub mdns: mdns::tokio::Behaviour,
    /// 节点身份识别
    pub identify: identify::Behaviour,
}

/// 创建 libp2p 身份密钥对（从 ed25519-dalek 私钥转换）
pub fn libp2p_keypair_from_signing_key(signing_key: &SigningKey) -> libp2p::identity::Keypair {
    let bytes = signing_key.to_bytes();
    libp2p::identity::Keypair::ed25519_from_bytes(bytes)
        .expect("valid ed25519 key bytes")
}

/// 构建 SynapseBehaviour
pub fn build_behaviour(
    local_keypair: &libp2p::identity::Keypair,
) -> Result<SynapseBehaviour, TransportError> {
    let local_peer_id = PeerId::from(local_keypair.public());

    // Gossipsub 配置：针对 LAN 小团队优化
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .max_transmit_size(1_048_576)        // 1 MB，支持较大区块批次
        .heartbeat_interval(Duration::from_secs(5)) // 5s，小型网络更快收敛
        .validation_mode(gossipsub::ValidationMode::Strict)
        .mesh_n_high(6)
        .mesh_n_low(4)
        .mesh_outbound_min(2)
        .fanout_ttl(Duration::from_secs(30))
        .history_length(10)                  // 消息去重窗口
        .build()
        .map_err(|e| TransportError::Config(e.to_string()))?;

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_keypair.clone()),
        gossipsub_config,
    )
    .map_err(|e| TransportError::Config(e.to_string()))?;

    // mDNS 配置
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
        .map_err(|e| TransportError::Config(e.to_string()))?;

    // Identify 配置
    let identify = identify::Behaviour::new(identify::Config::new(
        "/synapsevault/1.0.0".to_string(),
        local_keypair.public(),
    ));

    Ok(SynapseBehaviour {
        gossipsub,
        mdns,
        identify,
    })
}

/// 创建 Swarm
pub fn create_swarm(
    local_keypair: &libp2p::identity::Keypair,
) -> Result<Swarm<SynapseBehaviour>, TransportError> {
    let behaviour = build_behaviour(local_keypair)?;

    let swarm = libp2p::SwarmBuilder::with_existing_identity(local_keypair.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| TransportError::Config(e.to_string()))?
        .with_quic()
        .with_behaviour(|_key| behaviour)
        .map_err(|e| TransportError::Config(format!("{:?}", e)))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    Ok(swarm)
}

/// 传输层错误
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Network error: {0}")]
    Network(String),
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use crate::crypto::signing::generate_keypair;

    #[test]
    fn test_keypair_conversion() {
        let (sk, _vk) = generate_keypair();
        let libp2p_key = libp2p_keypair_from_signing_key(&sk);
        // 验证可以生成 PeerId
        let peer_id = PeerId::from(libp2p_key.public());
        assert!(!peer_id.to_string().is_empty());
    }

    #[test]
    fn test_create_swarm() {
        let (sk, _vk) = generate_keypair();
        let libp2p_key = libp2p_keypair_from_signing_key(&sk);
        let swarm = create_swarm(&libp2p_key);
        assert!(swarm.is_ok());
    }
}
