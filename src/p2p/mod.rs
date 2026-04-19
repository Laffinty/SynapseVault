//! P2P 网络模块
//!
//! libp2p 封装：mDNS 发现、Noise 传输、gossipsub 广播、事件循环。

pub mod discovery;
pub mod event_loop;
pub mod gossip;
pub mod protocol;
pub mod transport;
