//! Block 结构与哈希
//!
//! 定义轻量 PoA 链的区块结构、哈希计算与序列化。

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 区块高度（从 0 开始）
pub type BlockHeight = u64;

/// 区块哈希（32 字节）
pub type BlockHash = [u8; 32];

/// 轻量 PoA 区块
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    /// 区块高度
    pub height: BlockHeight,
    /// 所属群组 ID
    pub group_id: String,
    /// 前一区块哈希
    pub prev_hash: BlockHash,
    /// 区块时间戳
    pub timestamp: DateTime<Utc>,
    /// 签名者公钥（Admin）
    pub signer_pubkey: VerifyingKey,
    /// 签名者对区块哈希的签名
    pub signature: Signature,
    /// Merkle 根哈希
    pub merkle_root: BlockHash,
    /// 随机数（用于未来扩展）
    pub nonce: u64,
    /// 区块包含的操作列表（bincode 序列化）
    pub ops_data: Vec<u8>,
    /// 区块哈希（缓存，不参与序列化哈希计算）
    #[serde(skip)]
    pub block_hash: BlockHash,
}

/// 区块头（用于哈希计算，不包含签名和缓存哈希）
#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlockHeader {
    height: BlockHeight,
    group_id: String,
    prev_hash: BlockHash,
    timestamp: DateTime<Utc>,
    signer_pubkey: VerifyingKey,
    merkle_root: BlockHash,
    nonce: u64,
    ops_data: Vec<u8>,
}

impl Block {
    /// 计算区块哈希（不含 signature 和 block_hash 字段）
    pub fn compute_hash(&self) -> BlockHash {
        let header = BlockHeader {
            height: self.height,
            group_id: self.group_id.clone(),
            prev_hash: self.prev_hash,
            timestamp: self.timestamp,
            signer_pubkey: self.signer_pubkey,
            merkle_root: self.merkle_root,
            nonce: self.nonce,
            ops_data: self.ops_data.clone(),
        };
        let encoded = bincode::serialize(&header).expect("block header serialization");
        let mut hasher = Sha256::new();
        hasher.update(&encoded);
        hasher.finalize().into()
    }

    /// 验证区块哈希是否正确
    pub fn verify_hash(&self) -> bool {
        self.block_hash == self.compute_hash()
    }

    /// 创建创世区块
    pub fn genesis(group_id: &str, signer_pubkey: VerifyingKey) -> Self {
        let timestamp = Utc::now();
        let ops_data = bincode::serialize(&Vec::<u8>::new()).expect("empty ops serialization");
        let mut block = Self {
            height: 0,
            group_id: group_id.to_string(),
            prev_hash: [0u8; 32],
            timestamp,
            signer_pubkey,
            signature: Signature::from_bytes(&[0u8; 64]),
            merkle_root: [0u8; 32],
            nonce: 0,
            ops_data,
            block_hash: [0u8; 32],
        };
        block.block_hash = block.compute_hash();
        block
    }

    /// 更新缓存的区块哈希
    pub fn update_hash(&mut self) {
        self.block_hash = self.compute_hash();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::generate_keypair;

    #[test]
    fn test_genesis_block() {
        let (_sk, vk) = generate_keypair();
        let block = Block::genesis("group-1", vk);
        assert_eq!(block.height, 0);
        assert_eq!(block.prev_hash, [0u8; 32]);
        assert!(block.verify_hash());
    }

    #[test]
    fn test_block_hash_deterministic() {
        let (_sk, vk) = generate_keypair();
        let block1 = Block::genesis("group-1", vk);
        let block2 = Block::genesis("group-1", vk);
        // 时间戳不同，哈希也不同；但我们验证同一对象哈希一致
        assert_eq!(block1.block_hash, block1.compute_hash());
        assert_eq!(block2.block_hash, block2.compute_hash());
    }

    #[test]
    fn test_block_hash_changes_with_content() {
        let (_sk, vk) = generate_keypair();
        let mut block = Block::genesis("group-1", vk);
        let hash1 = block.block_hash;
        block.nonce = 1;
        block.update_hash();
        let hash2 = block.block_hash;
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_block_serde_roundtrip() {
        let (_sk, vk) = generate_keypair();
        let block = Block::genesis("group-1", vk);
        let encoded = bincode::serialize(&block).unwrap();
        let decoded: Block = bincode::deserialize(&encoded).unwrap();
        assert_eq!(block.height, decoded.height);
        assert_eq!(block.group_id, decoded.group_id);
        assert_eq!(block.prev_hash, decoded.prev_hash);
    }
}
